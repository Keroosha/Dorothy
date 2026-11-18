namespace Dorothy.Tests

open System
open System.Collections.Concurrent
open System.Collections.Immutable
open System.Globalization
open System.Threading.Tasks
open Dorothy.DSL.Cloudflare
open NUnit.Framework
open Pulumi
open Pulumi.Testing

module CF = Dorothy.DSL.Cloudflare


[<Sealed>]
type private CloudflareMocks(zones: (string * string) list) =
    let resources = ConcurrentDictionary<string, MockResourceArgs>()
    let calls = ConcurrentBag<MockCallArgs>()

    member _.Resources = resources
    member _.Calls = calls

    interface IMocks with
        member _.NewResourceAsync(args) =
            resources[args.Name] <- args
            let outputs =
                if args.Type = "test:index:AddressSeed" then
                    args.Inputs.SetItem("address", box "192.0.2.99")
                else
                    args.Inputs
            Task.FromResult(args.Name + "-id", box outputs)

        member _.CallAsync(args) =
            calls.Add args
            let results =
                zones
                |> Seq.map (fun (name, id) -> ImmutableDictionary<string, obj>.Empty.Add("name", box name).Add("id", box id))
                |> ImmutableArray.CreateRange
            let outputs = ImmutableDictionary<string, obj>.Empty.Add("results", box results)
            Task.FromResult(box outputs)

        member _.RegisterResourceOutputs(_) = Task.CompletedTask
        member _.RegisterTransform(_) = Task.CompletedTask
        member _.RegisterInvokeTransform(_) = Task.CompletedTask

[<TestFixture; NonParallelizable>]
type CloudflareTests() =
    let run (mocks: CloudflareMocks) (spec: CF.Spec) =
        Deployment.TestAsync(mocks, TestOptions(), Action(fun () -> CF.deploy spec |> ignore)).GetAwaiter().GetResult() |> ignore

    let dnsResources (mocks: CloudflareMocks) =
        mocks.Resources.Values
        |> Seq.filter (fun resource -> resource.Type = "cloudflare:index/dnsRecord:DnsRecord")
        |> Seq.toArray

    let stringInput (resource: MockResourceArgs) (name: string) = unbox<string> resource.Inputs.[name]
    let numberInput (resource: MockResourceArgs) (name: string) = Convert.ToDouble(resource.Inputs.[name], CultureInfo.InvariantCulture)
    let data (resource: MockResourceArgs) = resource.Inputs.["data"] :?> ImmutableDictionary<string, obj>
    let dataString (resource: MockResourceArgs) (name: string) =
        let values = data resource
        unbox<string> values.[name]
    let dataNumber (resource: MockResourceArgs) (name: string) =
        let values = data resource
        Convert.ToDouble(values.[name], CultureInfo.InvariantCulture)

    let allTypesSpec =
        cloudflare {
            domain "cybergulag.today" {
                zoneId "zone-explicit"
                dns {
                    a "edge-wildcard" { name "*"; address "192.0.2.10"; proxy DnsOnly }
                    aaaa "ipv6" { name "ipv6"; address "2001:db8::10" }
                    cname "alias" { name "alias"; target "origin.example.net."; proxy Proxied }
                    mx "null-mx" { name "@"; target "."; priority 0 }
                    ns "delegation" { name "delegated"; target "ns1.example.net" }
                    openpgpkey "openpgp" { name "openpgpkey"; content "AQID" }
                    ptr "reverse" { name "1"; target "host.example.net" }
                    txt "spf" { name "@"; text "v=spf1 include:example.net -all" }
                    caa "caa" { name "@"; flags 0; tag "issue"; value "letsencrypt.org" }
                    cert "cert" { name "cert"; algorithm 8; certificate "AQID"; keyTag 0; certificateType 1 }
                    dnskey "dnskey" { name "@"; flags 0; algorithm 8; protocol 3; publicKey "AQID" }
                    ds "ds" { name "@"; algorithm 8; digest "abcd"; digestType 2; keyTag 0 }
                    https "https" { name "@"; priority 1; target "."; value "alpn=h2" }
                    loc "loc" {
                        name "loc"
                        latitude (coordinate 37 46 49.0 North)
                        longitude (coordinate 122 25 9.0 West)
                        altitude 0.0
                        size 0.0
                        precisionHorz 10.0
                        precisionVert 0.0
                    }
                    naptr "naptr" {
                        name "_service._tcp"
                        naptrFlags "s"
                        order 0
                        preference 0
                        regex ""
                        replacement "."
                        service ""
                    }
                    smimea "smimea" { name "smimea"; certificate "abcd"; matchingType 0; selector 1; usage 3 }
                    srv "srv" { name "_sip._tcp"; port 5222; priority 5; target "talk.example.net"; weight 0 }
                    sshfp "sshfp" { name "sshfp"; algorithm 1; fingerprint "abcd"; fingerprintType 2 }
                    svcb "svcb" { name "@"; priority 0; target "."; value "alpn=h2" }
                    tlsa "tlsa" { name "_443._tcp"; certificate "abcd"; matchingType 1; selector 0; usage 3 }
                    uri "uri" { name "_service"; priority 0; target "https://example.net/path"; weight 0 }
                }
            }
        }

    [<Test>]
    member _.``All 21 record builders serialize provider inputs with typed data``() =
        let mocks = CloudflareMocks([])
        run mocks allTypesSpec
        let records = dnsResources mocks
        Assert.That(records, Has.Length.EqualTo 21)
        let byType = records |> Array.map (fun record -> stringInput record "type", record) |> Map.ofArray
        Assert.That(byType.Keys, Is.EquivalentTo [ "A"; "AAAA"; "CNAME"; "MX"; "NS"; "OPENPGPKEY"; "PTR"; "TXT"; "CAA"; "CERT"; "DNSKEY"; "DS"; "HTTPS"; "LOC"; "NAPTR"; "SMIMEA"; "SRV"; "SSHFP"; "SVCB"; "TLSA"; "URI" ])
        Assert.That(stringInput byType["A"] "name", Is.EqualTo "*.cybergulag.today")
        Assert.That(stringInput byType["A"] "content", Is.EqualTo "192.0.2.10")
        Assert.That(numberInput byType["A"] "ttl", Is.EqualTo 1.0)
        Assert.That(unbox<bool> byType["A"].Inputs["proxied"], Is.False)
        Assert.That(unbox<bool> byType["CNAME"].Inputs["proxied"], Is.True)
        Assert.That(stringInput byType["CNAME"] "content", Is.EqualTo "origin.example.net.")
        Assert.That(stringInput byType["MX"] "content", Is.EqualTo ".")
        Assert.That(numberInput byType["MX"] "priority", Is.EqualTo 0.0)
        Assert.That(stringInput byType["TXT"] "content", Is.EqualTo "\"v=spf1 include:example.net -all\"")
        Assert.That(dataNumber byType["CAA"] "flags", Is.EqualTo 0.0)
        Assert.That(dataString byType["CAA"] "tag", Is.EqualTo "issue")
        Assert.That(dataNumber byType["CERT"] "type", Is.EqualTo 1.0)
        Assert.That(dataNumber byType["DNSKEY"] "flags", Is.EqualTo 0.0)
        Assert.That(dataNumber byType["DS"] "keyTag", Is.EqualTo 0.0)
        Assert.That(dataNumber byType["HTTPS"] "priority", Is.EqualTo 1.0)
        Assert.That(dataString byType["HTTPS"] "target", Is.EqualTo ".")
        Assert.That(dataNumber byType["LOC"] "altitude", Is.EqualTo 0.0)
        Assert.That(dataNumber byType["LOC"] "size", Is.EqualTo 0.0)
        Assert.That(dataString byType["LOC"] "latDirection", Is.EqualTo "N")
        Assert.That(dataString byType["LOC"] "longDirection", Is.EqualTo "W")
        Assert.That(dataNumber byType["NAPTR"] "order", Is.EqualTo 0.0)
        Assert.That(dataNumber byType["NAPTR"] "preference", Is.EqualTo 0.0)
        Assert.That(dataString byType["NAPTR"] "flags", Is.EqualTo "s")
        Assert.That(dataString byType["NAPTR"] "replacement", Is.EqualTo ".")
        Assert.That(dataNumber byType["SMIMEA"] "usage", Is.EqualTo 3.0)
        Assert.That(dataNumber byType["SRV"] "priority", Is.EqualTo 5.0)
        Assert.That(numberInput byType["SRV"] "priority", Is.EqualTo 5.0)
        Assert.That(dataNumber byType["SRV"] "weight", Is.EqualTo 0.0)
        Assert.That(dataNumber byType["SSHFP"] "type", Is.EqualTo 2.0)
        Assert.That(dataNumber byType["SVCB"] "priority", Is.EqualTo 0.0)
        Assert.That(dataNumber byType["TLSA"] "matchingType", Is.EqualTo 1.0)
        Assert.That(numberInput byType["URI"] "priority", Is.EqualTo 0.0)
        Assert.That(dataString byType["URI"] "target", Is.EqualTo "https://example.net/path")
        Assert.That(mocks.Calls, Is.Empty)
        Assert.That(byType["A"].Name, Is.EqualTo "cloudflare-dns-16-cybergulag.today-13-edge-wildcard")

    [<Test>]
    member _.``IDN owners preserve underscores wildcards and avoid double zone suffixes``() =
        let spec =
            cloudflare {
                domain "münich.example" {
                    zoneId "zone-explicit"
                    dns {
                        a "underscore" { name "_sip._tcp"; address "192.0.2.1" }
                        a "wildcard" { name "*.bücher"; address "192.0.2.2" }
                        a "absolute" { name "www.xn--mnich-kva.example."; address "192.0.2.3" }
                        a "apex" { name "@"; address "192.0.2.4" }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks spec
        let byKey = dnsResources mocks |> Array.map (fun resource -> resource.Name, resource) |> Map.ofArray
        Assert.That(stringInput byKey["cloudflare-dns-21-xn--mnich-kva.example-10-underscore"] "name", Is.EqualTo "_sip._tcp.xn--mnich-kva.example")
        Assert.That(stringInput byKey["cloudflare-dns-21-xn--mnich-kva.example-8-wildcard"] "name", Is.EqualTo "*.xn--bcher-kva.xn--mnich-kva.example")
        Assert.That(stringInput byKey["cloudflare-dns-21-xn--mnich-kva.example-8-absolute"] "name", Is.EqualTo "www.xn--mnich-kva.example")
        Assert.That(stringInput byKey["cloudflare-dns-21-xn--mnich-kva.example-4-apex"] "name", Is.EqualTo "xn--mnich-kva.example")

    [<Test>]
    member _.``Zone lookup requires one exact normalized match and accepts an account filter``() =
        let spec =
            cloudflare {
                domain "CYBERGULAG.today." {
                    accountId "account-id"
                    dns { a "edge" { name "@"; address "192.0.2.1" } }
                }
            }
        let mocks = CloudflareMocks([ "other.example", "other-zone"; "CYBERGULAG.TODAY.", "exact-zone" ])
        run mocks spec
        Assert.That(mocks.Calls, Has.Count.EqualTo 1)
        let call = mocks.Calls |> Seq.exactlyOne
        Assert.That(call.Args["name"], Is.EqualTo "cybergulag.today")
        let account = call.Args["account"] :?> ImmutableDictionary<string, obj>
        Assert.That(account["id"], Is.EqualTo "account-id")
        Assert.That(stringInput (dnsResources mocks |> Array.exactlyOne) "zoneId", Is.EqualTo "exact-zone")

    [<TestCase(false)>]
    [<TestCase(true)>]
    member _.``Zone lookup rejects zero or multiple exact matches``(multiple: bool) =
        let spec = cloudflare { domain "example.test" { dns { a "edge" { name "@"; address "192.0.2.1" } } } }
        let zones = if multiple then [ "example.test", "one"; "EXAMPLE.TEST.", "two" ] else [ "other.test", "other" ]
        let failure = Assert.Catch<Exception>(TestDelegate(fun () -> run (CloudflareMocks(zones)) spec))
        Assert.That(failure, Is.Not.Null)
        Assert.That(failure.ToString(), Does.Contain(if multiple then "multiple" else "no exact match"))

    [<Test>]
    member _.``Same-owner RRset members stay separate while identical values are rejected``() =
        let spec =
            cloudflare {
                domain "example.test" {
                    zoneId "zone"
                    dns {
                        a "first" { name "@"; address "192.0.2.1" }
                        a "second" { name "@"; address "192.0.2.2" }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks spec
        Assert.That(dnsResources mocks, Has.Length.EqualTo 2)
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId "zone"
                    dns {
                        a "first" { name "@"; address "192.0.2.1" }
                        a "duplicate" { name "@"; address "192.0.2.1" }
                    }
                }
            } |> ignore) |> ignore

    [<Test>]
    member _.``TXT presentation quotes escapes and segments UTF-8 without changing payload``() =
        let longText = String.replicate 300 "x" + "\"\\\n"
        let spec =
            cloudflare {
                domain "example.test" {
                    zoneId "zone"
                    dns {
                        txt "long" { name "@"; text longText }
                        txt "spf" { name "_spf"; text "v=spf1 include:example.net -all" }
                        txt "segments" { name "_dkim"; segments [ String.replicate 255 "x"; "p=abc" ] }
                        txt "unicode" { name "unicode"; text (String.replicate 128 "é") }
                    }
                }
            }
        let mocks = CloudflareMocks([])
        run mocks spec
        let records = dnsResources mocks |> Array.map (fun resource -> resource.Name, resource) |> Map.ofArray
        let longContent = stringInput records["cloudflare-dns-12-example.test-4-long"] "content"
        Assert.That(longContent, Does.StartWith("\"" + String.replicate 255 "x" + "\" \""))
        Assert.That(longContent, Does.Contain("\\\""))
        Assert.That(longContent, Does.Contain("\\\\"))
        Assert.That(longContent, Does.Contain("\\010"))
        Assert.That(stringInput records["cloudflare-dns-12-example.test-3-spf"] "content", Is.EqualTo "\"v=spf1 include:example.net -all\"")
        Assert.That(stringInput records["cloudflare-dns-12-example.test-8-segments"] "content", Is.EqualTo("\"" + String.replicate 255 "x" + "\" \"p=abc\""))
        Assert.That(stringInput records["cloudflare-dns-12-example.test-7-unicode"] "content", Is.EqualTo("\"" + String.replicate 127 "\\195\\169" + "\" \"\\195\\169\""))
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId "zone"
                    dns { txt "too-long" { name "@"; segments [ String.replicate 256 "x" ] } }
                }
            } |> ignore) |> ignore

    [<Test>]
    member _.``Pulumi Output values flow into records without blocking``() =
        let mocks = CloudflareMocks([])
        Deployment.TestAsync(
            mocks,
            TestOptions(),
            Action(fun () ->
                let sourceArgs = Pulumi.Cloudflare.DnsRecordArgs()
                sourceArgs.ZoneId <- Input<string>.op_Implicit "zone"
                sourceArgs.Name <- Input<string>.op_Implicit "output-source.example.test"
                sourceArgs.Type <- Input<string>.op_Implicit "A"
                sourceArgs.Ttl <- Input<double>.op_Implicit 1.0
                sourceArgs.Content <- Input<string>.op_Implicit "192.0.2.99"
                let source = Pulumi.Cloudflare.DnsRecord("output-source", sourceArgs)
                let spec =
                    cloudflare {
                        domain "example.test" {
                            zoneId "zone"
                            dns { a "from-output" { name "@"; addressOutput source.Content } }
                        }
                    }
                CF.deploy spec |> ignore)
        ).GetAwaiter().GetResult() |> ignore
        let record = dnsResources mocks |> Array.find (fun resource -> resource.Name.Contains("cloudflare-dns-"))
        Assert.That(stringInput record "content", Is.EqualTo "192.0.2.99")
        Assert.That(mocks.Resources.ContainsKey "output-source", Is.True)

    [<Test>]
    member _.``Pulumi names stay stable across declaration reordering and record changes``() =
        let first =
            cloudflare {
                domain "example.test" {
                    zoneId "explicit-zone"
                    dns {
                        a "stable-key" { name "@"; address "192.0.2.1"; ttl Auto }
                        a "second-key" { name "second"; address "192.0.2.2" }
                    }
                }
            }
        let second =
            cloudflare {
                domain "example.test" {
                    dns {
                        aaaa "second-key" { name "changed"; address "2001:db8::2" }
                        aaaa "stable-key" { name "_changed"; address "2001:db8::1"; ttl (Fixed 300) }
                    }
                }
            }
        let firstMocks = CloudflareMocks([])
        let secondMocks = CloudflareMocks([ "example.test", "lookup-zone" ])
        run firstMocks first
        run secondMocks second
        let names mocks = dnsResources mocks |> Array.map (fun resource -> resource.Name) |> Set.ofArray
        Assert.That(names firstMocks, Is.EquivalentTo(names secondMocks))
        Assert.That(names firstMocks, Does.Contain "cloudflare-dns-12-example.test-10-stable-key")
        Assert.That(secondMocks.Calls, Has.Count.EqualTo 1)

    [<Test>]
    member _.``Absolute owners outside the zone and invalid proxy TTL combinations fail locally``() =
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId "zone"
                    dns { a "outside" { name "outside.other.test."; address "192.0.2.1" } }
                }
            } |> ignore) |> ignore
        Assert.Throws<ArgumentException>(fun () ->
            cloudflare {
                domain "example.test" {
                    zoneId "zone"
                    dns { a "proxied" { name "@"; address "192.0.2.1"; proxy Proxied; ttl (Fixed 300) } }
                }
            } |> ignore) |> ignore
