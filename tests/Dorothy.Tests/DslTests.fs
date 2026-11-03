namespace Dorothy.Tests

open System
open Dorothy.DSL
open NUnit.Framework

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
        Assert.That(plain.Backend, Is.EqualTo(LiteralString "http://127.0.0.1:8080"))
        Assert.That(plain.Tls, Is.EqualTo(NoTls))
        Assert.That(certificateName, Is.EqualTo("wildcard"))
        Assert.That(acmeResolverName, Is.EqualTo(resolver.Name))

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
    member _.``Traefik router builder requires host entry point and backend exactly once``() =
        // Arrange
        let missingBackend = fun () -> traefik {
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

        // Act
        let missingBackendAction = TestDelegate(fun () -> missingBackend () |> ignore)
        let duplicateHostAction = TestDelegate(fun () -> duplicateHost () |> ignore)

        // Assert
        Assert.Throws<ArgumentException>(missingBackendAction) |> ignore
        Assert.Throws<ArgumentException>(duplicateHostAction) |> ignore
