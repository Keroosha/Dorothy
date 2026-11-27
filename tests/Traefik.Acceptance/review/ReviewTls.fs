namespace Dorothy.Traefik.Acceptance.Review

open System
open System.IO
open Dorothy.DSL
open Pulumi

module ReviewTls =
    let private requiredFile name =
        match Environment.GetEnvironmentVariable(name) with
        | null -> invalidOp "A private TLS review fixture is missing."
        | path -> File.ReadAllText(path)

    let private requiredSecretFile name = requiredFile name |> fun value -> value.Trim()

    let private reviewConfiguration phase =
        let resolverName = "review-acme"
        let caServer =
            if phase = "review-tls-issuer-switch" then "https://localhost:14001/dir"
            else "https://localhost:14000/dir"
        let clientCa = requiredFile "CLIENT_CA_FILE"
        let secret = requiredSecretFile "DNS_TSIG_SECRET_FILE"
        let dnsChallenge =
            acmeDnsChallenge (nativeObject {
                acmeDnsProvider "dnsupdate"
                acmeDnsResolvers [ "127.0.0.1:1053" ]
                nativeField "propagation" (nativeObject {
                    nativeField "disableANSChecks" (nativeBoolean true)
                })
            })
        let acmeSettings =
            nativeObject {
                acmeEmail "ops@acceptance.test"
                acmeCaServer caServer
                acmeKeyType "EC256"
                dnsChallenge
                nativeField "certificatesDuration" (nativeInteger 1)
                nativeField "caSystemCertPool" (nativeBoolean true)
            }

        traefikConfiguration {
            staticConfiguration {
                staticEntryPoints {
                    staticEntryPoint "mtls" { entryPointAddress "127.0.0.1:18444/tcp" }
                }
                staticCertificatesResolvers {
                    staticCertificatesResolver resolverName {
                        yield acme acmeSettings
                    }
                }
            }
            dynamicConfiguration {
                httpConfiguration {
                    httpRouters {
                        httpRouter "review-mtls" {
                            httpRule (hostRule [ "mtls.acceptance.test" ])
                            httpRouterEntryPoints [ httpEntryPoint "mtls" ]
                            httpRouterService (httpServiceRef "catalog")
                            httpRouterTls (nativeObject {
                                httpTlsResolver (certificateResolverRef resolverName)
                                httpTlsOptions (tlsOptionsRef "mutual")
                            })
                        }
                    }
                    httpServices {
                        httpService "catalog" {
                            httpLoadBalancer (nativeObject {
                                httpServers [ "http://127.0.0.1:8080" ]
                            })
                        }
                    }
                }
                tlsConfiguration {
                    tlsOptions {
                        tlsOptionsSet "mutual" {
                            tlsClientAuth (nativeObject {
                                tlsClientAuthCaFiles [ clientCa ]
                                tlsClientAuthType "RequireAndVerifyClientCert"
                            })
                        }
                    }
                }
            }
            dnsCredentials {
                dnsupdateCredentials {
                    dnsupdateNameserver "127.0.0.1:1053"
                    dnsupdateZones "acceptance.test"
                    dnsupdateTsigKey "traefik-acceptance."
                    dnsupdateTsigAlgorithm "hmac-sha256."
                    dnsupdateTsigSecret (Output.CreateSecret<string>(secret))
                    dnsupdateTtl "30"
                    dnsupdatePropagationTimeout "30s"
                    dnsupdatePollingInterval "1s"
                    dnsupdateSequenceInterval "1s"
                }
            }
        }

    let createHost (phase: string) : HostSpec =
        if phase <> "review-tls-mtls"
           && phase <> "review-tls-incomplete"
           && phase <> "review-tls-issuer-switch" then
            invalidArg "phase" "Unsupported TLS review phase."

        sshHost "sandbox" {
            Address "192.0.2.1"
            User "root"
            Port 22
            debian {
                apt { "ca-certificates"; "openssl" }
                traefik {
                    adminPort 19080
                    reviewConfiguration phase
                }
            }
        }
