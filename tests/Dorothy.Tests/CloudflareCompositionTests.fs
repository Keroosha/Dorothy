namespace Dorothy.Tests

open System
open System.Collections.Concurrent
open Dorothy.DSL
open NUnit.Framework
open Pulumi
open Pulumi.Testing
open Pulumi.Utilities

module private CloudflareQuickstart =
    open Dorothy.DSL.Cloudflare

    let records =
        cloudflare {
            domain "example.com" {
                dns {
                    a "edge-wildcard" {
                        name "*"
                        address "192.0.2.10"
                        proxy DnsOnly
                        Fields.comment "Edge wildcard"
                        Fields.tags [ "owner:dns" ]
                    }
                    cname "www" { name "www"; Fields.target "origin.example.net." }
                }
            }
        }

    type Stack() =
        inherit Pulumi.Stack()
        do deploy records |> ignore

module private HostQuickstart =
    open Dorothy.DSL
    open Dorothy.DSL.Firewalld

    let host =
        sshHost "mixed-host" {
            Address "192.0.2.2"
            User "root"
            debian {
                firewalld {
                    zone "external" {
                        services [ "ssh" ]
                        interfaces [ "eth0" ]
                        target FirewalldTarget.Drop
                    }
                }
            }
        }

[<Sealed>]
type private MixedStack() =
    inherit Pulumi.Stack()
    do Dorothy.DSL.Host.deploy HostQuickstart.host |> ignore
    do Dorothy.DSL.Cloudflare.deploy CloudflareQuickstart.records |> ignore

[<Sealed>]
type private EmptyProviderArgs() =
    inherit ResourceArgs()

module private CloudflareOptionsFixture =
    let captured = ConcurrentBag<ResourceTransformationArgs>()
    let mutable configure: unit -> unit = ignore
    let mutable providerResource: ProviderResource option = None
    let mutable sourceResource: Pulumi.Cloudflare.DnsRecord option = None

    let stackOptions () =
        let options = StackOptions()
        options.ResourceTransformations.Add(ResourceTransformation(fun args ->
            captured.Add args
            Nullable<ResourceTransformationResult>()))
        options

    type Stack() =
        inherit Pulumi.Stack(stackOptions())
        do configure()

[<TestFixture; NonParallelizable>]
type CloudflareCompositionTests() =
    [<Test>]
    member _.``Scoped quickstarts compose Cloudflare and Host DSLs without token collisions``() =
        let mocks = CloudflareMocks([ "example.com", "0123456789abcdef0123456789abcdef" ])
        Deployment.TestAsync<MixedStack>(mocks, TestOptions()).GetAwaiter().GetResult() |> ignore
        let cloudflareRecords =
            mocks.Resources.Values
            |> Seq.filter (fun resource -> resource.Type = "cloudflare:index/dnsRecord:DnsRecord")
            |> Seq.toArray
        Assert.That(cloudflareRecords, Has.Length.EqualTo 2)
        Assert.That(mocks.Resources.Values |> Seq.exists (fun resource -> resource.Type.StartsWith("keroosha:debian:", StringComparison.Ordinal)), Is.True)

    [<Test>]
    member _.``Protect aliases and explicit provider reach records and zone lookup``() =
        CloudflareOptionsFixture.captured.Clear()
        CloudflareOptionsFixture.configure <- fun () ->
            let provider = ProviderResource("cloudflare", "test-cloudflare-provider", EmptyProviderArgs(), CustomResourceOptions())
            CloudflareOptionsFixture.providerResource <- Some provider
            let alias = Alias()
            let previousUrn = "urn:pulumi:stack::project::cloudflare:index/dnsRecord:DnsRecord::legacy-edge"
            alias.Urn <- previousUrn
            let spec =
                Dorothy.DSL.Cloudflare.cloudflare {
                    Dorothy.DSL.Cloudflare.domain "example.test" {
                        Dorothy.DSL.Cloudflare.zoneProvider provider
                        Dorothy.DSL.Cloudflare.dns {
                            Dorothy.DSL.Cloudflare.a "edge" {
                                Dorothy.DSL.Cloudflare.name "@"
                                Dorothy.DSL.Cloudflare.address "192.0.2.1"
                                Dorothy.DSL.Cloudflare.Fields.protect true
                                Dorothy.DSL.Cloudflare.Fields.aliases [ alias ]
                            }
                        }
                    }
                }
            Dorothy.DSL.Cloudflare.deploy spec |> ignore
        let mocks = CloudflareMocks([ "example.test", "0123456789abcdef0123456789abcdef" ])
        Deployment.TestAsync<CloudflareOptionsFixture.Stack>(mocks, TestOptions()).GetAwaiter().GetResult() |> ignore
        let dnsTransform =
            CloudflareOptionsFixture.captured
            |> Seq.find (fun entry -> entry.Resource :? Pulumi.Cloudflare.DnsRecord)
        Assert.That(dnsTransform.Options.Protect.HasValue, Is.True)
        Assert.That(dnsTransform.Options.Protect.Value, Is.True)
        Assert.That(dnsTransform.Options.Provider, Is.SameAs CloudflareOptionsFixture.providerResource.Value)
        let aliases = dnsTransform.Options.Aliases
        let aliasUrns =
            aliases
            |> Seq.map (fun value ->
                InputExtensions.ToOutput<Alias>(value)
                |> OutputUtilities.GetValueAsync
                |> fun task -> task.GetAwaiter().GetResult().Urn)
            |> Seq.toArray
        Assert.That(aliasUrns, Does.Contain "urn:pulumi:stack::project::cloudflare:index/dnsRecord:DnsRecord::legacy-edge")
        let lookup = mocks.Calls |> Seq.exactlyOne
        Assert.That(lookup.Token, Is.EqualTo "cloudflare:index/getZones:getZones")
        Assert.That(lookup.Provider, Is.Not.Null)
        let dnsMock = mocks.Resources.Values |> Seq.find (fun resource -> resource.Type = "cloudflare:index/dnsRecord:DnsRecord")
        Assert.That(dnsMock.Provider, Is.EqualTo lookup.Provider)

    [<Test>]
    member _.``Unknown preview inputs register with their source dependency``() =
        CloudflareOptionsFixture.captured.Clear()
        CloudflareOptionsFixture.configure <- fun () ->
            let args = Pulumi.Cloudflare.DnsRecordArgs()
            args.ZoneId <- Input<string>.op_Implicit "0123456789abcdef0123456789abcdef"
            args.Name <- Input<string>.op_Implicit "unknown-source.example.test"
            args.Type <- Input<string>.op_Implicit "A"
            args.Ttl <- Input<double>.op_Implicit 1.0
            args.Content <- Input<string>.op_Implicit "192.0.2.99"
            let source = Pulumi.Cloudflare.DnsRecord("unknown-source", args)
            CloudflareOptionsFixture.sourceResource <- Some source
            let spec =
                Dorothy.DSL.Cloudflare.cloudflare {
                    Dorothy.DSL.Cloudflare.domain "example.test" {
                        Dorothy.DSL.Cloudflare.zoneId "0123456789abcdef0123456789abcdef"
                        Dorothy.DSL.Cloudflare.dns {
                            Dorothy.DSL.Cloudflare.a "from-unknown" {
                                Dorothy.DSL.Cloudflare.name "@"
                                Dorothy.DSL.Cloudflare.Fields.addressOutput source.Content
                            }
                        }
                    }
                }
            Dorothy.DSL.Cloudflare.deploy spec |> ignore
        let mocks = CloudflareMocks([])
        mocks.UnknownOutputFor <- Some "unknown-source"
        let options = TestOptions()
        options.IsPreview <- Nullable true
        Deployment.TestAsync<CloudflareOptionsFixture.Stack>(mocks, options).GetAwaiter().GetResult() |> ignore
        Assert.That(mocks.Resources.ContainsKey "cloudflare-dns-12-example.test-12-from-unknown", Is.True)
        let transformed =
            CloudflareOptionsFixture.captured
            |> Seq.find (fun entry ->
                match entry.Args with
                | :? Pulumi.Cloudflare.DnsRecordArgs as args ->
                    OutputUtilities.GetValueAsync(InputExtensions.ToOutput<string>(args.Name)).GetAwaiter().GetResult() = "example.test"
                | _ -> false)
        let args = transformed.Args :?> Pulumi.Cloudflare.DnsRecordArgs
        let content = InputExtensions.ToOutput<string>(args.Content)
        Assert.That(OutputUtilities.GetIsKnownAsync(content).GetAwaiter().GetResult(), Is.False)
        let dependencies = OutputUtilities.GetDependenciesAsync(content).GetAwaiter().GetResult()
        let dependencyNames = dependencies |> Seq.map (fun resource -> OutputUtilities.GetValueAsync(resource.Urn).GetAwaiter().GetResult().Split("::") |> Array.last) |> Set.ofSeq
        Assert.That(dependencyNames, Does.Contain "unknown-source")
