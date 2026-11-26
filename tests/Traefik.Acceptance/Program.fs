namespace Dorothy.Traefik.Acceptance

open System
open System.IO
open Dorothy.DSL
open Pulumi

module Program =
    let private environment name fallback =
        match Environment.GetEnvironmentVariable(name) with
        | null -> fallback
        | value -> value

    let private requiredEnvironment name =
        match Environment.GetEnvironmentVariable(name) with
        | null -> invalidOp "A private TLS fixture is missing."
        | value -> value
    let private configuredValue (config: Config) name fallback =
        match config.Get(name) with
        | null -> fallback
        | value -> value

    let private requiredFile name =
        match Environment.GetEnvironmentVariable(name) with
        | null -> invalidOp "A private acceptance fixture file is missing."
        | path -> File.ReadAllText(path)

    let private fullConfiguration (phase: string) =
        let upstreamCa = requiredFile "UPSTREAM_CA_FILE"
        let clientCa = requiredFile "CLIENT_CA_FILE"
        let secret =
            match Environment.GetEnvironmentVariable("DNS_TSIG_SECRET_FILE") with
            | null -> invalidOp "A private DNS credential fixture is missing."
            | path -> File.ReadAllText(path).Trim()

        let catalogRule = httpRule (hostRule [ "shop.acceptance.test" ] &&& pathPrefixRule "/items")
        let dnsChallenge =
            acmeDnsChallenge (nativeObject {
                acmeDnsProvider "dnsupdate"
                acmeDnsResolvers [ "127.0.0.1:1053" ]
                nativeField "propagation" (nativeObject {
                    nativeField "disableANSChecks" (nativeBoolean true)
                })
            })
        let acmeFields (caServer: string) (challenge: TraefikNativeField) =
            nativeObject {
                acmeEmail "ops@acceptance.test"
                acmeCaServer caServer
                acmeKeyType "EC256"
                challenge
                nativeField "certificatesDuration" (nativeInteger 1)
                nativeField "caSystemCertPool" (nativeBoolean true)
            }
        let resolverEpoch = environment "TRAEFIK_ACCEPTANCE_RESOLVER_EPOCH" "v2"
        let resolverName baseName = baseName + "-" + resolverEpoch
        let activeDnsResolver =
            if phase = "rotate" || phase = "rollback" || phase = "withdraw-udp" || phase = "rollback-udp" then
                resolverName "acceptance-rotated"
            else
                resolverName "acceptance"

        traefikConfiguration {
            staticConfiguration {
                staticEntryPoints {
                    staticEntryPoint "front" { entryPointAddress "127.0.0.1:18081/tcp" }
                    staticEntryPoint "secure" {
                        entryPointAddress "127.0.0.1:18443/tcp"
                        entryPointHttp3 18443
                    }
                    staticEntryPoint "mtls" { entryPointAddress "127.0.0.1:18444/tcp" }
                    staticEntryPoint "tcp" { entryPointAddress "127.0.0.1:19000/tcp" }
                    staticEntryPoint "udp" { entryPointAddress "127.0.0.1:19000/udp" }
                    staticEntryPoint "udp-other" { entryPointAddress "127.0.0.1:19003/udp" }
                    staticEntryPoint "http01" { entryPointAddress "127.0.0.1:5002/tcp" }
                    staticEntryPoint "tlsalpn" { entryPointAddress "127.0.0.1:5001/tcp" }
                    staticEntryPoint "proxy-front" {
                        entryPointAddress "127.0.0.1:18082/tcp"
                        entryPointProxyProtocol (nativeObject {
                            nativeField "trustedIPs" (nativeArray [ nativeString "127.0.0.1/32" ])
                        })
                    }
                    staticEntryPoint "sni-proof" { entryPointAddress "127.0.0.2:18449/tcp" }
                    if phase = "rollback" then
                        staticEntryPoint "rollback-collision" { entryPointAddress "127.0.0.1:8080/tcp" }
                }
                staticCertificatesResolvers {
                    if phase = "rotate" || phase = "rollback" || phase = "withdraw-udp" || phase = "rollback-udp" then
                        staticCertificatesResolver (resolverName "acceptance-rotated") {
                            yield acme (acmeFields "https://localhost:14001/dir" dnsChallenge)
                        }
                    else
                        staticCertificatesResolver (resolverName "acceptance") {
                            yield acme (acmeFields "https://localhost:14000/dir" dnsChallenge)
                        }
                        staticCertificatesResolver (resolverName "acceptance-rotated") {
                            yield acme (acmeFields "https://localhost:14001/dir" dnsChallenge)
                        }
                    staticCertificatesResolver (resolverName "http01") {
                        yield acme (acmeFields "https://localhost:14000/dir" (acmeHttpChallengeStatic "http01"))
                    }
                    staticCertificatesResolver (resolverName "tlsalpn") {
                        yield acme (acmeFields "https://localhost:14000/dir" acmeTlsChallenge)
                    }
                }
                staticLog (nativeObject {
                    logLevel "DEBUG"
                    logFormat "json"
                })
                staticAccessLog (nativeObject {
                    accessLogFormat "json"
                })
                staticMetrics (nativeObject {
                    nativeField "prometheus" (nativeObject {
                        nativeField "entryPoint" (nativeString "keroosha-admin")
                        nativeField "addEntryPointsLabels" (nativeBoolean true)
                        nativeField "addRoutersLabels" (nativeBoolean true)
                        nativeField "addServicesLabels" (nativeBoolean true)
                    })
                    nativeField "otlp" (nativeObject {
                        nativeField "http" (nativeObject {
                            nativeField "endpoint" (nativeString "http://127.0.0.1:4318/v1/metrics")
                        })
                        nativeField "serviceName" (nativeString "dorothy-traefik-acceptance")
                        nativeField "pushInterval" (nativeString "5s")
                    })
                })
                nativeField "ping" (nativeObject {
                    nativeField "entryPoint" (nativeString "keroosha-admin")
                })
                staticTracing (nativeObject {
                    nativeField "serviceName" (nativeString "dorothy-traefik-acceptance")
                    nativeField "sampleRate" (nativeNumber 1.0M)
                    nativeField "otlp" (nativeObject {
                        nativeField "http" (nativeObject {
                            nativeField "endpoint" (nativeString "http://127.0.0.1:4318/v1/traces")
                        })
                    })
                })
            }
            dynamicConfiguration {
                httpConfiguration {
                    httpRouters {
                        httpRouter "catalog" {
                            catalogRule
                            httpRouterEntryPoints [ httpEntryPoint "front" ]
                            httpRouterService (httpServiceRef "catalog")
                            httpRouterMiddlewares [
                                httpMiddlewareRef "add-prefix"
                                httpMiddlewareRef "strip-prefix"
                                httpMiddlewareRef "compress"
                            ]
                            nativeField "observability" (nativeObject {
                                nativeField "tracing" (nativeBoolean true)
                            })
                        }
                        httpRouter "catalog-status" {
                            httpRule (hostRule [ "shop.acceptance.test" ] &&& pathPrefixRule "/status")
                            httpRouterEntryPoints [ httpEntryPoint "front" ]
                            httpRouterService (httpServiceRef "catalog")
                        }
                        httpRouter "catalog-other-backend" {
                            httpRule (hostRule [ "shop.acceptance.test" ] &&& pathPrefixRule "/other")
                            httpRouterEntryPoints [ httpEntryPoint "front" ]
                            httpRouterService (httpServiceRef "other")
                        }
                        httpRouter "multi-upstream" {
                            httpRule (andRule
                                (hostRule [ "shop.acceptance.test" ])
                                (andRule (pathPrefixRule "/multi") (notRule (pathPrefixRule "/multi/private"))))
                            httpRouterEntryPoints [ httpEntryPoint "front" ]
                            httpRouterService (httpServiceRef "multi")
                        }
                        httpRouter "proxy-trusted" {
                            httpRule (hostRule [ "shop.acceptance.test" ] &&& pathPrefixRule "/proxy")
                            httpRouterEntryPoints [ httpEntryPoint "proxy-front" ]
                            httpRouterService (httpServiceRef "catalog")
                        }
                        httpRouter "secure-catalog" {
                            httpRule (hostRule [ "shop.acceptance.test" ] &&& pathPrefixRule "/secure")
                            httpRouterEntryPoints [ httpEntryPoint "secure" ]
                            httpRouterService (httpServiceRef "secure-catalog")
                            httpRouterTls (nativeObject {
                                httpTlsResolver (certificateResolverRef activeDnsResolver)
                            })
                        }
                        httpRouter "mutual-catalog" {
                            httpRule (hostRule [ "mtls.acceptance.test" ] &&& pathPrefixRule "/mtls")
                            httpRouterEntryPoints [ httpEntryPoint "mtls" ]
                            httpRouterService (httpServiceRef "catalog")
                            httpRouterTls (nativeObject {
                                httpTlsResolver (certificateResolverRef activeDnsResolver)
                                httpTlsOptions (tlsOptionsRef "mutual")
                            })
                        }
                        httpRouter "http01-proof" {
                            httpRule (hostRule [ "http01.acceptance.test" ] &&& pathPrefixRule "/http01")
                            httpRouterEntryPoints [ httpEntryPoint "secure" ]
                            httpRouterService (httpServiceRef "catalog")
                            httpRouterTls (nativeObject {
                                httpTlsResolver (certificateResolverRef (resolverName "http01"))
                            })
                        }
                        httpRouter "tlsalpn-proof" {
                            httpRule (hostRule [ "tlsalpn.acceptance.test" ] &&& pathPrefixRule "/tlsalpn")
                            httpRouterEntryPoints [ httpEntryPoint "tlsalpn" ]
                            httpRouterService (httpServiceRef "catalog")
                            httpRouterTls (nativeObject {
                                httpTlsResolver (certificateResolverRef (resolverName "tlsalpn"))
                            })
                        }
                        httpRouter "sni-proof" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ])
                            httpRouterEntryPoints [ httpEntryPoint "sni-proof" ]
                            httpRouterService (httpServiceRef "catalog")
                            httpRouterTls (nativeObject {})
                        }
                        if phase = "route-update" then
                            httpRouter "catalog-extra" {
                                httpRule (hostRule [ "shop.acceptance.test" ] &&& pathPrefixRule "/extra")
                                httpRouterEntryPoints [ httpEntryPoint "front" ]
                                httpRouterService (httpServiceRef "catalog")
                            }
                        if phase = "rollback-udp" then
                            httpRouter "rollback-udp-invalid" {
                                nativeField "rule" (nativeString "NotATraefikMatcher(\"x\")")
                                httpRouterEntryPoints [ httpEntryPoint "front" ]
                                httpRouterService (httpServiceRef "catalog")
                            }
                    }
                    httpServices {
                        httpService "catalog" {
                            httpLoadBalancer (nativeObject {
                                httpServers [ "http://127.0.0.1:8080" ]
                                httpHealthCheck (nativeObject {
                                    httpHealthCheckPath "/health"
                                    httpHealthCheckInterval "5s"
                                    httpHealthCheckTimeout "2s"
                                })
                            })
                        }
                        httpService "secure-catalog" {
                            httpLoadBalancer (nativeObject {
                                httpServers [ "https://127.0.0.1:8081" ]
                                httpServiceServersTransport (httpServersTransportRef "upstream")
                            })
                        }
                        httpService "other" {
                            httpLoadBalancer (nativeObject { httpServers [ "http://127.0.0.1:8082" ] })
                        }
                        httpService "multi" {
                            httpLoadBalancer (nativeObject {
                                httpServers [ "http://127.0.0.1:8080"; "http://127.0.0.1:8082"; "http://127.0.0.1:18099" ]
                                httpHealthCheck (nativeObject {
                                    httpHealthCheckPath "/health"
                                    httpHealthCheckInterval "1s"
                                    httpHealthCheckTimeout "500ms"
                                })
                            })
                        }
                    }
                    httpMiddlewares {
                        httpMiddleware "compress" {
                            nativeField "compress" (nativeObject {
                                nativeField "minResponseBodyBytes" (nativeInteger 1)
                                nativeField "encodings" (nativeArray [ nativeString "gzip" ])
                            })
                        }
                        httpMiddleware "add-prefix" { httpMiddlewareAddPrefix "/proxied" }
                        httpMiddleware "strip-prefix" { httpMiddlewareStripPrefix [ "/proxied" ] }
                    }
                    httpServersTransports {
                        httpServersTransport "upstream" {
                            nativeField "serverName" (nativeString "backend.acceptance.test")
                            nativeField "rootCAs" (nativeArray [ nativeString upstreamCa ])
                        }
                    }
                }
                tcpConfiguration {
                    tcpRouters {
                        tcpRouter "raw-echo" {
                            tcpRule (tcpHostSniRule "*")
                            tcpRouterEntryPoints [ tcpEntryPoint "tcp" ]
                            tcpRouterService (tcpServiceRef "echo")
                        }
                        tcpRouter "tls-terminated-echo" {
                            tcpRule (tcpHostSniRule "sni-proof.acceptance.test")
                            tcpRouterEntryPoints [ tcpEntryPoint "tcp" ]
                            tcpRouterService (tcpServiceRef "echo")
                            tcpRouterTls (nativeObject {})
                        }
                        tcpRouter "tls-passthrough" {
                            tcpRule (tcpHostSniRule "backend.acceptance.test")
                            tcpRouterEntryPoints [ tcpEntryPoint "tcp" ]
                            tcpRouterService (tcpServiceRef "tls-passthrough")
                            tcpRouterTls (nativeObject { tcpTlsPassthrough true })
                        }
                    }
                    tcpServices {
                        tcpService "echo" {
                            tcpLoadBalancer (nativeObject {
                                tcpServers [ "127.0.0.1:19001" ]
                                tcpProxyProtocol (nativeObject { tcpProxyProtocolVersion 2 })
                            })
                        }
                        tcpService "tls-passthrough" {
                            tcpLoadBalancer (nativeObject { tcpServers [ "127.0.0.1:8081" ] })
                        }
                    }
                }
                udpConfiguration {
                    udpRouters {
                        if phase <> "withdraw-udp" then
                            udpRouter "echo" {
                                udpRouterEntryPoints [ udpEntryPoint "udp" ]
                                udpRouterService (udpServiceRef "echo")
                            }
                        udpRouter "echo-other" {
                            udpRouterEntryPoints [ udpEntryPoint "udp-other" ]
                            udpRouterService (udpServiceRef "echo")
                        }
                    }
                    udpServices {
                        udpService "echo" {
                            udpLoadBalancer (nativeObject { udpServers [ "127.0.0.1:19002" ] })
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

    let private sniProofConfiguration () =
        traefikConfiguration {
            staticConfiguration {
                staticEntryPoints {
                    staticEntryPoint "sni-proof" { entryPointAddress "127.0.0.2:18449/tcp" }
                }
            }
            dynamicConfiguration {
                httpConfiguration {
                    httpRouters {
                        httpRouter "sni-proof" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ])
                            httpRouterEntryPoints [ httpEntryPoint "sni-proof" ]
                            httpRouterService (httpServiceRef "catalog")
                            httpRouterTls (nativeObject {})
                        }
                    }
                    httpServices {
                        httpService "catalog" {
                            httpLoadBalancer (nativeObject {
                                httpServers [ "http://127.0.0.1:8080" ]
                                httpHealthCheck (nativeObject {
                                    httpHealthCheckPath "/health"
                                    httpHealthCheckInterval "5s"
                                    httpHealthCheckTimeout "2s"
                                })
                            })
                        }
                    }
                }
            }
        }

    let private configuration (phase: string) =
        if phase = "sni-proof-only" then sniProofConfiguration ()
        else fullConfiguration phase

    let private createHost (phase: string) =
        let config = Config()
        let backendUrl = configuredValue config "backend" "http://127.0.0.1:8080"
        let certificate =
            pemCertificate "example" {
                chain (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_LEGACY_CERT_FILE"))
                privateKey (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_LEGACY_KEY_FILE"))
            }
        let sniCertificate =
            pemCertificate "sni-proof" {
                chain (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_SNI_CERT_FILE"))
                privateKey (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_SNI_KEY_FILE"))
            }
        let host =
            sshHost "sandbox" {
                Address "192.0.2.1"
                User "root"
                Port 22
                debian {
                    apt { "ca-certificates"; "openssl" }
                    if phase <> "delete" then
                        traefik {
                            entryPoint "websecure" { listen 443 }
                            certificate
                            if phase = "structured" || phase = "route-update" || phase = "rotate" || phase = "rollback" || phase = "withdraw-udp" || phase = "rollback-udp" || phase = "sni-proof-only" then
                                sniCertificate
                            router "example" {
                                host "example.org"
                                entryPoint "websecure"
                                backend backendUrl
                                tls (Provided certificate)
                            }
                            if phase = "structured" || phase = "route-update" || phase = "rotate" || phase = "rollback" || phase = "withdraw-udp" || phase = "rollback-udp" then
                                router "legacy-redirect" {
                                    host "redirect.acceptance.test"
                                    entryPoint "websecure"
                                    redirect (Redirect.permanentToOrigin "https://target.acceptance.test")
                                    excludePathSubtree "/private"
                                }
                            adminPort 19080
                            if phase = "structured" || phase = "route-update" || phase = "rotate" || phase = "rollback" || phase = "withdraw-udp" || phase = "rollback-udp" || phase = "sni-proof-only" then
                                configuration phase
                        }
                }
            }
        Host.deploy host |> ignore

    type InfrastructureStack() =
        inherit Stack()
        do createHost (environment "TRAEFIK_ACCEPTANCE_PHASE" "legacy")

    [<EntryPoint>]
    let main _ =
        Deployment.RunAsync<InfrastructureStack>()
        |> fun run -> run.GetAwaiter().GetResult()
