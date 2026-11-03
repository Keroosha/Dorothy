namespace Dorothy.Tests

open System
open System.Collections.Immutable
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open Dorothy.DSL.Provider
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

[<TestFixture>]
type DslTests() =
    [<Test>]
    member _.``APT declarations merge package sets and retain exact versions``() =
        // Arrange
        let declaration =
            debian {
                apt {
                    packageVersion "nginx" "1.24.0-2"
                    packageVersion "openssh-server" "1:9.2p1-2"
                }
                apt {
                    "ca-certificates"
                    packageVersion "nginx" "1.24.0-2"
                }
            }

        // Act
        let packages =
            match declaration with
            | HostDeclaration.Debian debianSpec -> debianSpec.Packages
            | _ -> invalidOp "Expected a Debian host declaration."

        // Assert
        Assert.That(packages["nginx"], Is.EqualTo(Some "1.24.0-2"))
        Assert.That(packages["openssh-server"], Is.EqualTo(Some "1:9.2p1-2"))
        Assert.That(Option.isNone (packages["ca-certificates"]), Is.True)

    [<Test>]
    member _.``APT declarations reject conflicting constraints and invalid Debian values``() =
        // Arrange
        let conflicting = fun () ->
            debian {
                apt { packageVersion "nginx" "1.24.0-1" }
                apt { packageVersion "nginx" "1.24.0-2" }
            }
        let invalidName = fun () -> packageVersion "Bad_Name" "1.0"
        let invalidVersion = fun () -> packageVersion "nginx" "latest"

        // Act
        let conflictAction = TestDelegate(fun () -> conflicting () |> ignore)
        let nameAction = TestDelegate(fun () -> invalidName () |> ignore)
        let versionAction = TestDelegate(fun () -> invalidVersion () |> ignore)

        // Assert
        Assert.Throws<ArgumentException>(conflictAction) |> ignore
        Assert.Throws<ArgumentException>(nameAction) |> ignore
        Assert.Throws<ArgumentException>(versionAction) |> ignore

    [<Test>]
    member _.``SSH host builder requires one complete Debian host declaration``() =
        // Arrange
        let missingUser = fun () -> sshHost "sandbox" { Address "192.0.2.10"; debian { apt { "nginx" } } }
        let duplicateAddress = fun () -> sshHost "sandbox" { Address "192.0.2.10"; Address "192.0.2.11"; User "root"; debian { apt { "nginx" } } }
        let invalidPort = fun () -> sshHost "sandbox" { Address "192.0.2.10"; User "root"; Port 65536; debian { apt { "nginx" } } }
        let unsafeFirewall = fun () ->
            let host =
                sshHost "sandbox" {
                    Address "192.0.2.10"
                    User "root"
                    debian {
                        ufw {
                            DefaultOut Deny
                            allow { toPort 22; proto Tcp }
                        }
                    }
                }
            Host.deploy host |> ignore
        // Act
        let missingUserAction = TestDelegate(fun () -> missingUser () |> ignore)
        let duplicateAddressAction = TestDelegate(fun () -> duplicateAddress () |> ignore)
        let invalidPortAction = TestDelegate(fun () -> invalidPort () |> ignore)
        let unsafeFirewallAction = TestDelegate(fun () -> unsafeFirewall () |> ignore)

        // Assert
        Assert.Throws<ArgumentException>(missingUserAction) |> ignore
        Assert.Throws<ArgumentException>(duplicateAddressAction) |> ignore
        Assert.Throws<ArgumentException>(invalidPortAction) |> ignore
        Assert.Throws<ArgumentException>(unsafeFirewallAction) |> ignore

    [<Test>]
    member _.``SSH host builder preserves defaults and optional identity``() =
        // Arrange
        let host =
            sshHost "sandbox" {
                Address "192.0.2.10"
                User "debian"
                IdentityFile "/home/debian/.ssh/id_ed25519"
                debian {
                    apt { "nginx" }
                }
            }

        // Act
        let port = host.Port
        let identity = host.IdentityFile

        // Assert
        Assert.That(port, Is.EqualTo(22))
        Assert.That(identity, Is.EqualTo(Some "/home/debian/.ssh/id_ed25519"))
        Assert.That(host.Packages.ContainsKey("nginx"), Is.True)

    [<Test>]
    member _.``Swapfile DSL requires one safe absolute path and positive measured size``() =
        let specification = swapfile { path "/swapfile"; size 64<MiB> }
        let missingPath = fun () -> swapfile { size 64<MiB> }
        let missingSize = fun () -> swapfile { path "/swapfile" }
        let duplicatePath = fun () -> swapfile { path "/swapfile"; path "/var/swap"; size 64<MiB> }
        let duplicateSize = fun () -> swapfile { path "/swapfile"; size 64<MiB>; size 128<MiB> }
        let relativePath = fun () -> swapfile { path "swapfile"; size 64<MiB> }
        let traversalPath = fun () -> swapfile { path "/tmp/../swapfile"; size 64<MiB> }

        Assert.That(specification.Path, Is.EqualTo("/swapfile"))
        Assert.That(specification.Size, Is.EqualTo(64<MiB>))
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> missingPath () |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> missingSize () |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> duplicatePath () |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> duplicateSize () |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> relativePath () |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> traversalPath () |> ignore)) |> ignore

    [<Test>]
    member _.``Swapfile is carried through one Debian host declaration``() =
        let host =
            sshHost "swap-host" {
                Address "192.0.2.10"
                User "debian"
                debian {
                    swapfile { path "/swapfile"; size 64<MiB> }
                }
            }

        Assert.That(host.Swapfile.IsSome, Is.True)
        Assert.That(host.Swapfile.Value.Path, Is.EqualTo("/swapfile"))
        Assert.That(host.Swapfile.Value.Size, Is.EqualTo(64<MiB>))
        Assert.Throws<ArgumentException>(TestDelegate(fun () ->
            debian {
                swapfile { path "/swapfile"; size 64<MiB> }
                swapfile { path "/var/swap"; size 128<MiB> }
            }
            |> ignore)) |> ignore

    [<Test>]
    member _.``UFW typed rules preserve ordered argv and expand TCP plus UDP``() =
        // Arrange
        let actual =
            ufw {
                allow {
                    toPort 22
                    proto Tcp
                }
                allow {
                    direction Incoming
                    inIface "eth0"
                    fromAddress "203.0.113.9"
                    fromPort 54321
                    toAddress "192.0.2.10"
                    toPort 8443
                    proto Tcp
                }
                deny {
                    direction Outgoing
                    outIface "eth1"
                    fromAddress "192.0.2.2"
                    fromPort 12345
                    toAddress "198.51.100.10"
                    toPort 53
                    proto Udp
                }
                allow {
                    direction Routed
                    inIface "wg0"
                    outIface "eth0"
                    fromAddress "10.0.0.0/8"
                    fromPort 51820
                    toAddress "203.0.113.7"
                    toPort 443
                    proto TcpAndUdp
                }
                reject {
                    direction Routed
                    inIface "wg1"
                    toPort 8000
                    proto Tcp
                }
                deny {
                    direction Routed
                    outIface "eth2"
                    toPort 8080
                }
                reject {
                    fromPort 49152
                    toPort 65535
                }
            }
        let expected: string list list = [
            [ "allow"; "in"; "proto"; "tcp"; "to"; "any"; "port"; "22" ]
            [ "allow"; "in"; "on"; "eth0"; "proto"; "tcp"; "from"; "203.0.113.9"; "port"; "54321"; "to"; "192.0.2.10"; "port"; "8443" ]
            [ "deny"; "out"; "on"; "eth1"; "proto"; "udp"; "from"; "192.0.2.2"; "port"; "12345"; "to"; "198.51.100.10"; "port"; "53" ]
            [ "route"; "allow"; "in"; "on"; "wg0"; "out"; "on"; "eth0"; "proto"; "tcp"; "from"; "10.0.0.0/8"; "port"; "51820"; "to"; "203.0.113.7"; "port"; "443" ]
            [ "route"; "allow"; "in"; "on"; "wg0"; "out"; "on"; "eth0"; "proto"; "udp"; "from"; "10.0.0.0/8"; "port"; "51820"; "to"; "203.0.113.7"; "port"; "443" ]
            [ "route"; "reject"; "in"; "on"; "wg1"; "proto"; "tcp"; "to"; "any"; "port"; "8000" ]
            [ "route"; "deny"; "out"; "on"; "eth2"; "to"; "any"; "port"; "8080" ]
            [ "reject"; "in"; "from"; "any"; "port"; "49152"; "to"; "any"; "port"; "65535" ]
        ]

        // Act
        let actualRules = actual.Rules

        // Assert
        Assert.That(actualRules, Is.EqualTo(box expected))

    [<Test>]
    member _.``UFW rule builder rejects duplicates and direction interface conflicts``() =
        // Arrange
        let invalidRules: (string * (unit -> UfwSpec)) list = [
            "duplicate direction", (fun () -> ufw { allow { direction Incoming; direction Outgoing } })
            "duplicate source address", (fun () -> ufw { allow { fromAddress "192.0.2.1"; fromAddress "192.0.2.2" } })
            "duplicate source port", (fun () -> ufw { allow { fromPort 1; fromPort 2 } })
            "duplicate destination address", (fun () -> ufw { allow { toAddress "192.0.2.1"; toAddress "192.0.2.2" } })
            "duplicate destination port", (fun () -> ufw { allow { toPort 1; toPort 2 } })
            "duplicate protocol", (fun () -> ufw { allow { proto Tcp; proto Udp } })
            "duplicate incoming interface", (fun () -> ufw { allow { inIface "eth0"; inIface "eth1" } })
            "duplicate outgoing interface", (fun () -> ufw { allow { outIface "eth0"; outIface "eth1" } })
            "incoming with outIface", (fun () -> ufw { allow { direction Incoming; outIface "eth0" } })
            "outgoing with inIface", (fun () -> ufw { allow { direction Outgoing; inIface "eth0" } })
        ]

        // Act
        let actions =
            invalidRules
            |> List.map (fun (_, build) -> TestDelegate(fun () -> build () |> ignore))

        // Assert
        for action in actions do Assert.Throws<ArgumentException>(action) |> ignore

    [<Test>]
    member _.``UFW raw rules tokenize safely and reject comments or shell syntax``() =
        // Arrange
        let valid = ufw { raw "allow in proto tcp to any port 443" }
        let comment = fun () -> ufw { raw "allow in 443/tcp comment injected" }
        let shell = fun () -> ufw { raw "allow in 443/tcp; reboot" }

        // Act
        let actualRules = valid.Rules
        let commentAction = TestDelegate(fun () -> comment () |> ignore)
        let shellAction = TestDelegate(fun () -> shell () |> ignore)

        // Assert
        Assert.That(actualRules, Is.EqualTo(box [ [ "allow"; "in"; "proto"; "tcp"; "to"; "any"; "port"; "443" ] ]))
        Assert.Throws<ArgumentException>(commentAction) |> ignore
        Assert.Throws<ArgumentException>(shellAction) |> ignore

    [<Test>]
    member _.``Traefik DSL builders retain typed entry point and router declarations``() =
        // Arrange
        let web = entryPoint "web" { listen 8080 }
        let websecure = entryPoint "websecure" { listen 8443 }
        let resolver = acmeResolver "letsencrypt" {
            email "ops@example.test"
            challenge (Http01 "web")
            caServer "https://acme.example.test/directory"
        }
        let certificate = pemCertificate "wildcard" {
            chain (Content.pem "deferred certificate")
            privateKey (Content.pem "deferred private key")
        }
        let plain =
            router "plain" {
                host "plain.example.test"
                entryPoint "web"
                backend "http://127.0.0.1:8080"
                tls noTls
            }
        let secure =
            router "secure" {
                host "api.example.test"
                entryPoint "websecure"
                backend "https://127.0.0.1:8443"
                tls (Provided certificate)
            }
        let acme =
            router "acme" {
                host "acme.example.test"
                entryPoint "websecure"
                backend "http://127.0.0.1:8081"
                tls (Acme resolver)
            }

        let redirected =
            router "redirected" {
                host "www.example.test"
                entryPoint "web"
                redirect (Redirect.permanentToOrigin "https://ovsianikov-history.ru")
                tls noTls
            }
        // Act
        let certificateName =
            match secure.Tls with
            | Provided providedCertificate -> providedCertificate.Name
            | _ -> String.Empty
        let acmeResolverName =
            match acme.Tls with
            | Acme acmeResolver -> acmeResolver.Name
            | _ -> String.Empty

        // Assert
        Assert.That(web.Name, Is.EqualTo("web"))
        Assert.That(web.Listen, Is.EqualTo(8080))
        Assert.That(websecure.Name, Is.EqualTo("websecure"))
        Assert.That(websecure.Listen, Is.EqualTo(8443))
        Assert.That(plain.Host, Is.EqualTo(LiteralString "plain.example.test"))
        Assert.That(plain.EntryPoint, Is.EqualTo(LiteralString "web"))
        Assert.That(plain.Target, Is.EqualTo(RouterTargetInput.Backend(LiteralString "http://127.0.0.1:8080")))
        Assert.That(plain.Tls, Is.EqualTo(NoTls))
        Assert.That(
            redirected.Target,
            Is.EqualTo(RouterTargetInput.PermanentToOrigin(LiteralString "https://ovsianikov-history.ru"))
        )
        Assert.That(certificateName, Is.EqualTo("wildcard"))
        Assert.That(acmeResolverName, Is.EqualTo(resolver.Name))

    [<Test>]
    member _.``Traefik redirect output origin retains canonical value and secrecy``() : Task =
        task {
            // Arrange
            let origin = Pulumi.Output.CreateSecret<string>("HTTPS://OVSIANIKOV-HISTORY.RU:443")
            let canonicalOrigin = Uri("HTTPS://OVSIANIKOV-HISTORY.RU:443").GetLeftPart(UriPartial.Authority)
            let specification =
                traefik {
                    entryPoint "web" { listen 8080 }
                    router "redirected" {
                        host "www.example.test"
                        entryPoint "web"
                        redirect (Redirect.permanentToOrigin origin)
                    }
                }

            // Act
            let resolved = specification.Resolve(System.Threading.CancellationToken.None)
            let! routers = Pulumi.Utilities.OutputUtilities.GetValueAsync(resolved.Routers)
            let! isSecret = Pulumi.Output.IsSecretAsync(resolved.Routers)

            // Assert
            Assert.That(routers["redirected"].Target, Is.EqualTo(TraefikRouterTarget.PermanentToOrigin canonicalOrigin))
            Assert.That(isSecret, Is.True)
        }

    [<Test>]
    member _.``Traefik builders reject duplicate declarations and invalid ports or names``() =
        // Arrange
        let duplicateListen = fun () -> entryPoint "web" { listen 8080; listen 8081 }
        let duplicateAdminPort = fun () -> traefik { entryPoint "web" { listen 8080 }; adminPort 19080; adminPort 19081 }
        let duplicateEntryPoint = fun () -> traefik { entryPoint "web" { listen 8080 }; entryPoint "web" { listen 8081 } }
        let reservedEntryPoint = fun () -> entryPoint "traefik" { listen 8080 }
        let invalidAdminPort = fun () -> traefik { entryPoint "web" { listen 19080 } }

        // Act
        let listenAction = TestDelegate(fun () -> duplicateListen () |> ignore)
        let adminAction = TestDelegate(fun () -> duplicateAdminPort () |> ignore)
        let entryAction = TestDelegate(fun () -> duplicateEntryPoint () |> ignore)
        let reservedAction = TestDelegate(fun () -> reservedEntryPoint () |> ignore)
        let portAction = TestDelegate(fun () -> invalidAdminPort () |> ignore)

        // Assert
        Assert.Throws<ArgumentException>(listenAction) |> ignore
        Assert.Throws<ArgumentException>(adminAction) |> ignore
        Assert.Throws<ArgumentException>(entryAction) |> ignore
        Assert.Throws<ArgumentException>(reservedAction) |> ignore
        Assert.Throws<ArgumentException>(portAction) |> ignore

    [<Test>]
    member _.``Traefik router builder requires host entry point and exactly one target``() =
        // Arrange
        let missingTarget = fun () -> traefik {
            entryPoint "web" { listen 8080 }
            router "incomplete" {
                host "example.test"
                entryPoint "web"
            }
        }
        let duplicateHost = fun () -> router "duplicate" {
            host "first.example.test"
            host "second.example.test"
            entryPoint "web"
            backend "http://127.0.0.1:8080"
        }
        let duplicateTarget = fun () -> router "duplicate-target" {
            host "example.test"
            entryPoint "web"
            backend "http://127.0.0.1:8080"
            redirect (Redirect.permanentToOrigin "https://example.test")
        }

        // Act
        let missingTargetAction = TestDelegate(fun () -> missingTarget () |> ignore)
        let duplicateHostAction = TestDelegate(fun () -> duplicateHost () |> ignore)
        let duplicateTargetAction = TestDelegate(fun () -> duplicateTarget () |> ignore)

        // Assert
        Assert.Throws<ArgumentException>(missingTargetAction) |> ignore
        Assert.Throws<ArgumentException>(duplicateHostAction) |> ignore
        Assert.Throws<ArgumentException>(duplicateTargetAction) |> ignore

[<RequireQualifiedAccess>]
module private TraefikRedirectProviderTestValues =
    let map (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do
            builder.Add(key, value)
        PropertyValue(builder.ToImmutable())

    let inputMap (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do
            builder.Add(key, value)
        builder.ToImmutable()

    let string (value: string) = PropertyValue(value)
    let number (value: int) = PropertyValue(float value)
    let boolean (value: bool) = PropertyValue(value)

    let mapContents (value: PropertyValue) =
        let mutable values = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&values) then values else failwith "Expected a map property value."

    let private connection =
        map [
            "address", string "192.0.2.1"
            "user", string "root"
        ]

    let traefikInputWithTarget (target: (string * PropertyValue) list) (adminPort: int) =
        let router =
            map (
                [
                    "host", string "example.org"
                    "entryPoint", string "websecure"
                ]
                @ target
                @ [
                    "tls", map [
                        "kind", string "none"
                        "name", string ""
                    ]
                ]
            )
        inputMap [
            "connection", connection
            "entryPoints", map [ "websecure", number 443 ]
            "resolvers", map Seq.empty
            "routers", map [ "example", router ]
            "certificates", map Seq.empty
            "adminPort", number adminPort
        ]

    let traefikBackendInput backend adminPort =
        traefikInputWithTarget [ "backend", string backend ] adminPort

    let traefikRedirectInput origin adminPort =
        traefikInputWithTarget [
            "redirect",
            map [
                "kind", string "permanentToOrigin"
                "origin", string origin
            ]
        ] adminPort

    let check (provider: DorothyProvider) (inputs: ImmutableDictionary<string, PropertyValue>) =
        let request =
            CheckRequest(
                Pulumi.Urn("urn:pulumi:unit::unit::keroosha:debian:Traefik::test-resource"),
                ImmutableDictionary<string, PropertyValue>.Empty,
                inputs,
                ImmutableArray<byte>.Empty
            )
        provider.Check(request, CancellationToken.None).GetAwaiter().GetResult()

    let diff
        (provider: DorothyProvider)
        (oldInputs: ImmutableDictionary<string, PropertyValue>)
        (oldOutputs: ImmutableDictionary<string, PropertyValue>)
        (newInputs: ImmutableDictionary<string, PropertyValue>)
        =
        let request =
            DiffRequest(
                Pulumi.Urn("urn:pulumi:unit::unit::keroosha:debian:Traefik::test-resource"),
                "owned-id",
                oldOutputs,
                newInputs,
                ImmutableArray<string>.Empty,
                oldInputs
            )
        provider.Diff(request, CancellationToken.None).GetAwaiter().GetResult()

[<TestFixture>]
type TraefikRedirectProviderTests() =
    [<Test>]
    member _.``Provider Check canonicalizes redirect origins and requires one target``() =
        // Arrange
        let provider = DorothyProvider()
        let canonicalOrigin = Uri("HTTPS://OVSIANIKOV-HISTORY.RU:443").GetLeftPart(UriPartial.Authority)
        let canonicalInput = TraefikRedirectProviderTestValues.traefikRedirectInput "HTTPS://OVSIANIKOV-HISTORY.RU:443" 19080
        let missingTarget = TraefikRedirectProviderTestValues.traefikInputWithTarget [] 19080
        let bothTargets =
            TraefikRedirectProviderTestValues.traefikInputWithTarget [
                "backend", TraefikRedirectProviderTestValues.string "http://127.0.0.1:8080"
                "redirect",
                TraefikRedirectProviderTestValues.map [
                    "kind", TraefikRedirectProviderTestValues.string "permanentToOrigin"
                    "origin", TraefikRedirectProviderTestValues.string "https://example.org"
                ]
            ] 19080

        // Act
        let canonicalResponse = TraefikRedirectProviderTestValues.check provider canonicalInput
        let missingResponse = TraefikRedirectProviderTestValues.check provider missingTarget
        let bothResponse = TraefikRedirectProviderTestValues.check provider bothTargets
        let routers = TraefikRedirectProviderTestValues.mapContents canonicalResponse.Inputs["routers"]
        let router = TraefikRedirectProviderTestValues.mapContents routers["example"]
        let redirect = TraefikRedirectProviderTestValues.mapContents router["redirect"]

        // Assert
        Assert.That(canonicalResponse.Failures, Is.Empty)
        Assert.That(
            redirect["origin"],
            Is.EqualTo(TraefikRedirectProviderTestValues.string canonicalOrigin)
        )
        Assert.That(missingResponse.Failures, Is.Not.Empty)
        Assert.That(bothResponse.Failures, Is.Not.Empty)

    [<Test>]
    member _.``Provider Check rejects raw redirect paths credentials markers and unsafe characters``() =
        // Arrange
        let provider = DorothyProvider()
        let invalidOrigins = [
            "https://"
            "https://example.org/"
            "https://example.org/a/../"
            "https://example.org?"
            "https://example.org#"
            "https://user:secret@example.org"
            "https://example.org\\path"
            "https://example.org "
            "https://example.org\u0009"
        ]

        // Act
        let responses =
            invalidOrigins
            |> List.map (fun origin ->
                origin,
                TraefikRedirectProviderTestValues.check
                    provider
                    (TraefikRedirectProviderTestValues.traefikRedirectInput origin 19080))

        // Assert
        for origin, response in responses do
            Assert.That(response.Failures, Is.Not.Empty, origin)

    [<Test>]
    member _.``Provider Create preview preserves unknown redirect origin``() =
        // Arrange
        let provider = DorothyProvider()
        let redirect =
            TraefikRedirectProviderTestValues.map [
                "kind", TraefikRedirectProviderTestValues.string "permanentToOrigin"
                "origin", PropertyValue.Computed
            ]
        let inputs = TraefikRedirectProviderTestValues.traefikInputWithTarget [ "redirect", redirect ] 19080
        let request =
            CreateRequest(
                Pulumi.Urn("urn:pulumi:unit::unit::keroosha:debian:Traefik::unknown-redirect"),
                inputs,
                TimeSpan.FromSeconds(1.0),
                true
            )

        // Act
        let preview = provider.Create(request, CancellationToken.None).GetAwaiter().GetResult()
        let routers = TraefikRedirectProviderTestValues.mapContents preview.Outputs["routers"]
        let router = TraefikRedirectProviderTestValues.mapContents routers["example"]
        let previewRedirect = TraefikRedirectProviderTestValues.mapContents router["redirect"]

        // Assert
        Assert.That(preview.Id, Is.Empty)
        Assert.That(previewRedirect["origin"].IsComputed, Is.True)

    [<Test>]
    member _.``Provider Diff reports transitions between backend and redirect targets``() =
        // Arrange
        let provider = DorothyProvider()
        let backend = TraefikRedirectProviderTestValues.traefikBackendInput "http://127.0.0.1:12345" 19080
        let redirect = TraefikRedirectProviderTestValues.traefikRedirectInput "https://ovsianikov-history.ru" 19080
        let oldOutputs =
            TraefikRedirectProviderTestValues.inputMap [
                "inSync", TraefikRedirectProviderTestValues.boolean true
            ]

        // Act
        let toRedirect = TraefikRedirectProviderTestValues.diff provider backend oldOutputs redirect
        let toBackend = TraefikRedirectProviderTestValues.diff provider redirect oldOutputs backend

        // Assert
        Assert.That(toRedirect.Changes.HasValue, Is.True)
        Assert.That(toRedirect.Changes.Value, Is.True)
        Assert.That(toRedirect.Diffs.Contains("routers"), Is.True)
        Assert.That(toRedirect.DetailedDiff["routers.example.backend"].Kind, Is.EqualTo(PropertyDiffKind.Delete))
        Assert.That(toRedirect.DetailedDiff["routers.example.redirect"].Kind, Is.EqualTo(PropertyDiffKind.Add))
        Assert.That(toBackend.Changes.HasValue, Is.True)
        Assert.That(toBackend.Changes.Value, Is.True)
        Assert.That(toBackend.DetailedDiff["routers.example.backend"].Kind, Is.EqualTo(PropertyDiffKind.Add))
        Assert.That(toBackend.DetailedDiff["routers.example.redirect"].Kind, Is.EqualTo(PropertyDiffKind.Delete))
