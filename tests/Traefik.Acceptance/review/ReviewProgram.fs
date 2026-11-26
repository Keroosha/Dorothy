namespace Dorothy.Traefik.Acceptance.Review

open System
open System.IO
open Dorothy.DSL
open Pulumi

module ReviewProgram =
    let private environment name fallback =
        match Environment.GetEnvironmentVariable(name) with
        | null -> fallback
        | value -> value

    let private requiredEnvironment name =
        match Environment.GetEnvironmentVariable(name) with
        | null -> invalidOp "A required review acceptance fixture is missing."
        | value -> value

    let private requiredFile name =
        Environment.GetEnvironmentVariable(name)
        |> function
            | null -> invalidOp "A required review acceptance fixture file is missing."
            | path -> File.ReadAllText(path)

    let private trustedProxy =
        nativeObject {
            nativeField "trustedIPs" (nativeArray [ nativeString "127.0.0.1/32" ])
        }

    let private forwardedHeaders =
        nativeObject {
            nativeField "trustedIPs" (nativeArray [ nativeString "127.0.0.1/32" ])
        }

    let private entryPointHttpDefaults middleware tls =
        nativeObject {
            nativeField "middlewares" (nativeArray [ nativeString middleware ])
            if tls then nativeField "tls" (nativeObject {})
        }


    let private tcpHealthCheck () =
        nativeObject {
            nativeField "port" (nativeInteger 19001)
            nativeField "send" (nativeString "dorothy-health-probe")
            nativeField "expect" (nativeString "dorothy-health-probe")
            nativeField "interval" (nativeString "2s")
            nativeField "unhealthyInterval" (nativeString "3s")
            nativeField "timeout" (nativeString "1s")
        }

    let private proxyVersion version =
        nativeObject {
            nativeField "version" (nativeInteger version)
        }

    let private makeTcpLoadBalancer server transport proxyProtocol =
        nativeObject {
            tcpServers [ server ]
            tcpServiceServersTransport (tcpServersTransportRef transport)
            nativeField "healthCheck" (tcpHealthCheck ())
            match proxyProtocol with
            | Some version -> tcpProxyProtocol (proxyVersion version)
            | None -> ()
        }

    let private reviewConfiguration phase =
        let ipv6 = environment "TRAEFIK_ACCEPTANCE_REVIEW_IPV6" "0" = "1"
        let includeTcp = phase <> "review-no-tcp"
        let includeProxyPlacement = phase = "review-proxy-placement-control" || phase = "review-proxy-misplaced"
        let misplacedProxy = phase = "review-proxy-misplaced"
        let includeUdpConflict = phase = "review-udp-conflict-control" || phase = "review-udp-conflict"
        let metricsInterval = "5s"
        let upstreamCa = requiredFile "UPSTREAM_CA_FILE"

        traefikConfiguration {
            staticConfiguration {
                staticEntryPoints {
                    staticEntryPoint "review-front" {
                        entryPointAddress "127.0.0.1:18445/tcp"
                        entryPointForwardedHeaders forwardedHeaders
                        entryPointHttp (entryPointHttpDefaults "review-front-default" false)
                    }
                    staticEntryPoint "review-secure" {
                        entryPointAddress "127.0.0.1:18451/tcp"
                        entryPointHttp (entryPointHttpDefaults "review-secure-default" true)
                    }
                    staticEntryPoint "review-proxy-v1" {
                        entryPointAddress "127.0.0.1:19010/tcp"
                        entryPointProxyProtocol trustedProxy
                    }
                    staticEntryPoint "review-proxy-v2" {
                        entryPointAddress "127.0.0.1:19011/tcp"
                        entryPointProxyProtocol trustedProxy
                    }
                    if includeTcp then
                        staticEntryPoint "review-tcp" { entryPointAddress "127.0.0.1:19012/tcp" }
                    staticEntryPoint "review-udp-a" { entryPointAddress "127.0.0.1:19013/udp" }
                    staticEntryPoint "review-udp-b" { entryPointAddress "127.0.0.1:19014/udp" }
                    if includeUdpConflict then
                        staticEntryPoint "review-udp-shared" { entryPointAddress "127.0.0.1:19015/udp" }
                    if includeProxyPlacement then
                        staticEntryPoint "review-proxy-placement" { entryPointAddress "127.0.0.1:19016/tcp" }
                    if ipv6 then
                        staticEntryPoint "review-v6" {
                            entryPointAddress "[::1]:18182/tcp"
                            entryPointForwardedHeaders (nativeObject {
                                nativeField "trustedIPs" (nativeArray [ nativeString "::1/128" ])
                            })
                        }
                }
                staticLog (nativeObject {
                    logLevel "INFO"
                    logFormat "json"
                    nativeField "otlp" (nativeObject {
                        nativeField "serviceName" (nativeString "dorothy-review-acceptance")
                        nativeField "http" (nativeObject {
                            nativeField "endpoint" (nativeString "http://127.0.0.1:4318/v1/logs")
                        })
                    })
                })
                staticAccessLog (nativeObject {
                    accessLogFormat "json"
                    nativeField "otlp" (nativeObject {
                        nativeField "serviceName" (nativeString "dorothy-review-access")
                        nativeField "http" (nativeObject {
                            nativeField "endpoint" (nativeString "http://127.0.0.1:4318/v1/logs")
                        })
                    })
                })
                staticMetrics (nativeObject {
                    nativeField "otlp" (nativeObject {
                        nativeField "http" (nativeObject {
                            nativeField "endpoint" (nativeString "http://127.0.0.1:4318/v1/metrics")
                        })
                        nativeField "serviceName" (nativeString "dorothy-review-acceptance")
                        nativeField "pushInterval" (nativeString metricsInterval)
                    })
                })
            }
            dynamicConfiguration {
                httpConfiguration {
                    httpRouters {
                        httpRouter "review-multi-entrypoint" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/multi-entry")
                            httpRouterEntryPoints [ httpEntryPoint "review-front"; httpEntryPoint "review-secure" ]
                            httpRouterService (httpServiceRef "review-main")
                        }
                        httpRouter "review-method-get" {
                            httpRule (andRule (hostRule [ "sni-proof.acceptance.test" ]) (andRule (pathPrefixRule "/method") (methodRule "GET")))
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-main")
                        }
                        httpRouter "review-method-post" {
                            httpRule (andRule (hostRule [ "sni-proof.acceptance.test" ]) (andRule (pathPrefixRule "/method") (methodRule "POST")))
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-other")
                        }
                        httpRouter "review-header-target" {
                            httpRule (andRule (hostRule [ "sni-proof.acceptance.test" ]) (andRule (pathPrefixRule "/header") (headerRule "X-Dorothy-Target" "other")))
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-other")
                        }
                        httpRouter "review-header-default" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/header")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-main")
                        }
                        httpRouter "review-priority-default" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/priority")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterPriority 0
                            httpRouterService (httpServiceRef "review-main")
                        }
                        httpRouter "review-priority-long" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/priority/long")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterPriority 0
                            httpRouterService (httpServiceRef "review-other")
                        }
                        httpRouter "review-priority-explicit" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/priority/explicit")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterPriority 1000
                            httpRouterService (httpServiceRef "review-other")
                        }
                        httpRouter "review-chain-one" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/base/chain-one")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-main")
                            httpRouterMiddlewares [ httpMiddlewareRef "review-chain-strip-then-add" ]
                        }
                        httpRouter "review-chain-two" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/base/chain-two")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-main")
                            httpRouterMiddlewares [ httpMiddlewareRef "review-chain-add-then-strip" ]
                        }
                        httpRouter "review-layer-parent" {
                            httpRule (hostRule [ "multi.example.test" ] &&& pathPrefixRule "/multilayer")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-main")
                            httpRouterMiddlewares [ httpMiddlewareRef "review-layer-request-header" ]
                        }
                        httpRouter "review-layer-child" {
                            httpRule (andRule (hostRule [ "multi.example.test" ]) (andRule (pathPrefixRule "/multilayer") (headerRule "X-Dorothy-Layer" "admin")))
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-other")
                            httpRouterParentRefs [ httpRouterRef "review-layer-parent" ]
                        }
                        httpRouter "review-forwarded" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/forwarded")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-main")
                        }
                        httpRouter "review-otlp-event" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/otlp-event")
                            httpRouterEntryPoints [ httpEntryPoint "review-front" ]
                            httpRouterService (httpServiceRef "review-main")
                        }
                        httpRouter "review-client-auth" {
                            httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/client-auth")
                            httpRouterEntryPoints [ httpEntryPoint "review-front"; httpEntryPoint "review-secure" ]
                            httpRouterService (httpServiceRef "review-client-auth")
                        }
                        if ipv6 then
                            httpRouter "review-v6-forwarded" {
                                httpRule (hostRule [ "sni-proof.acceptance.test" ] &&& pathPrefixRule "/v6-forwarded")
                                httpRouterEntryPoints [ httpEntryPoint "review-v6" ]
                                httpRouterService (httpServiceRef "review-main")
                            }
                    }
                    httpServices {
                        httpService "review-main" {
                            httpLoadBalancer (nativeObject { httpServers [ "http://127.0.0.1:8080" ] })
                        }
                        httpService "review-other" {
                            httpLoadBalancer (nativeObject { httpServers [ "http://127.0.0.1:8082" ] })
                            httpServiceMiddlewares [ httpMiddlewareRef "review-service-response-header" ]
                        }
                        httpService "review-client-auth" {
                            httpLoadBalancer (nativeObject {
                                httpServers [ "https://127.0.0.1:18123" ]
                                httpServiceServersTransport (httpServersTransportRef "review-client-auth")
                            })
                        }
                    }
                    httpMiddlewares {
                        httpMiddleware "review-front-default" {
                            nativeField "headers" (nativeObject {
                                nativeField "customResponseHeaders" (nativeObject {
                                    nativeField "X-Dorothy-EntryPoint" (nativeString "front")
                                })
                            })
                        }
                        httpMiddleware "review-secure-default" {
                            nativeField "headers" (nativeObject {
                                nativeField "customResponseHeaders" (nativeObject {
                                    nativeField "X-Dorothy-EntryPoint" (nativeString "secure")
                                })
                            })
                        }
                        httpMiddleware "review-service-response-header" {
                            nativeField "headers" (nativeObject {
                                nativeField "customResponseHeaders" (nativeObject {
                                    nativeField "X-Dorothy-Service" (nativeString "native")
                                })
                            })
                        }
                        httpMiddleware "review-layer-request-header" {
                            nativeField "headers" (nativeObject {
                                nativeField "customRequestHeaders" (nativeObject {
                                    nativeField "X-Dorothy-Layer" (nativeString "admin")
                                })
                            })
                        }
                        httpMiddleware "review-strip-base" { httpMiddlewareStripPrefix [ "/base" ] }
                        httpMiddleware "review-add-from-chain" { httpMiddlewareAddPrefix "/from-chain" }
                        httpMiddleware "review-chain-strip-then-add" {
                            nativeField "chain" (nativeObject {
                                nativeField "middlewares" (nativeArray [ nativeString "review-strip-base"; nativeString "review-add-from-chain" ])
                            })
                        }
                        httpMiddleware "review-chain-add-then-strip" {
                            nativeField "chain" (nativeObject {
                                nativeField "middlewares" (nativeArray [ nativeString "review-add-from-chain"; nativeString "review-strip-base" ])
                            })
                        }
                    }
                    httpServersTransports {
                        httpServersTransport "review-client-auth" {
                            nativeField "serverName" (nativeString "backend.acceptance.test")
                            nativeField "rootCAs" (nativeArray [ nativeString upstreamCa ])
                            if phase <> "review-client-auth-absent" then
                                httpServersTransportCertificates [ certificateRef "review-client" ]
                        }
                    }
                }
                tcpConfiguration {
                    tcpRouters {
                        if includeTcp then
                            tcpRouter "review-filtered-tcp" {
                                tcpRule (tcpHostSniRule "*")
                                tcpRouterEntryPoints [ tcpEntryPoint "review-tcp" ]
                                tcpRouterService (tcpServiceRef "review-tcp-filtered")
                                tcpRouterMiddlewares [ tcpMiddlewareRef "review-tcp-loopback-only" ]
                            }
                        tcpRouter "review-proxy-v1" {
                            tcpRule (tcpHostSniRule "*")
                            tcpRouterEntryPoints [ tcpEntryPoint "review-proxy-v1" ]
                            tcpRouterService (tcpServiceRef "review-proxy-v1")
                        }
                        tcpRouter "review-proxy-v2" {
                            tcpRule (tcpHostSniRule "*")
                            tcpRouterEntryPoints [ tcpEntryPoint "review-proxy-v2" ]
                            tcpRouterService (tcpServiceRef "review-proxy-v2")
                        }
                        if includeProxyPlacement then
                            tcpRouter "review-proxy-placement" {
                                tcpRule (tcpHostSniRule "*")
                                tcpRouterEntryPoints [ tcpEntryPoint "review-proxy-placement" ]
                                tcpRouterService (tcpServiceRef "review-proxy-placement")
                            }
                    }
                    tcpServices {
                        if includeTcp then
                            tcpService "review-tcp-filtered" {
                                tcpLoadBalancer (makeTcpLoadBalancer "127.0.0.1:19001" "review-timeout-only" None)
                            }
                        tcpService "review-proxy-v1" {
                            tcpLoadBalancer (makeTcpLoadBalancer "127.0.0.1:19001" "review-out-proxy-v1" None)
                        }
                        tcpService "review-proxy-v2" {
                            tcpLoadBalancer (makeTcpLoadBalancer "127.0.0.1:19001" "review-out-proxy-v2" None)
                        }
                        if includeProxyPlacement then
                            tcpService "review-proxy-placement" {
                                let misplaced = if misplacedProxy then Some 2 else None
                                tcpLoadBalancer (makeTcpLoadBalancer "127.0.0.1:19001" "review-proxy-placement" misplaced)
                            }
                    }
                    tcpMiddlewares {
                        if includeTcp then
                            tcpMiddleware "review-tcp-loopback-only" {
                                nativeField "ipAllowList" (nativeObject {
                                    nativeField "sourceRange" (nativeArray [ nativeString "127.0.0.1/32" ])
                                })
                            }
                    }
                    tcpServersTransports {
                        tcpServersTransport "review-timeout-only" {
                            nativeField "dialTimeout" (nativeString "5s")
                        }
                        tcpServersTransport "review-out-proxy-v1" {
                            nativeField "dialTimeout" (nativeString "5s")
                            nativeField "proxyProtocol" (proxyVersion 1)
                        }
                        tcpServersTransport "review-out-proxy-v2" {
                            nativeField "dialTimeout" (nativeString "5s")
                            nativeField "proxyProtocol" (proxyVersion 2)
                        }
                        tcpServersTransport "review-proxy-placement" {
                            nativeField "dialTimeout" (nativeString "5s")
                            if not misplacedProxy then nativeField "proxyProtocol" (proxyVersion 2)
                        }
                    }
                }
                udpConfiguration {
                    udpRouters {
                        udpRouter "review-udp-a" {
                            udpRouterEntryPoints [ udpEntryPoint "review-udp-a" ]
                            udpRouterService (udpServiceRef "review-udp-a")
                        }
                        udpRouter "review-udp-b" {
                            udpRouterEntryPoints [ udpEntryPoint "review-udp-b" ]
                            udpRouterService (udpServiceRef "review-udp-b")
                        }
                        if includeUdpConflict then
                            udpRouter "review-udp-conflict-a" {
                                udpRouterEntryPoints [ udpEntryPoint "review-udp-shared" ]
                                udpRouterService (udpServiceRef "review-udp-a")
                            }
                        if phase = "review-udp-conflict" then
                            udpRouter "review-udp-conflict-b" {
                                udpRouterEntryPoints [ udpEntryPoint "review-udp-shared" ]
                                udpRouterService (udpServiceRef "review-udp-b")
                            }
                    }
                    udpServices {
                        udpService "review-udp-a" {
                            udpLoadBalancer (nativeObject { udpServers [ "127.0.0.1:19002" ] })
                        }
                        udpService "review-udp-b" {
                            udpLoadBalancer (nativeObject { udpServers [ "127.0.0.1:19004" ] })
                        }
                    }
                }
            }
        }

    let private createReviewHost phase =
        let exampleCertificate =
            pemCertificate "example" {
                chain (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_LEGACY_CERT_FILE"))
                privateKey (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_LEGACY_KEY_FILE"))
            }
        let sniCertificate =
            pemCertificate "sni-proof" {
                chain (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_SNI_CERT_FILE"))
                privateKey (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_SNI_KEY_FILE"))
            }
        let clientCertificate =
            match phase with
            | "review-client-auth-absent" -> None
            | "review-client-auth-wrong" ->
                Some(
                    pemClientCertificate "review-client" {
                        chain (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_REVIEW_WRONG_CLIENT_CERT_FILE"))
                        privateKey (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_REVIEW_WRONG_CLIENT_KEY_FILE"))
                    }
                )
            | _ ->
                Some(
                    pemClientCertificate "review-client" {
                        chain (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_REVIEW_CLIENT_CERT_FILE"))
                        privateKey (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_REVIEW_CLIENT_KEY_FILE"))
                    }
                )

        sshHost "sandbox" {
            Address "192.0.2.1"
            User "root"
            Port 22
            debian {
                apt { "ca-certificates"; "openssl" }
                traefik {
                    entryPoint "websecure" { listen 443 }
                    exampleCertificate
                    sniCertificate
                    for identity in clientCertificate |> Option.toList do identity

                    router "example" {
                        host "example.org"
                        entryPoint "websecure"
                        backend "http://127.0.0.1:8080"
                        tls (TraefikTlsMode.Provided exampleCertificate)
                    }
                    adminPort 19080
                    reviewConfiguration phase
                }
            }
        }

    type ReviewStack() =
        inherit Stack()
        do
            let phase = environment "TRAEFIK_ACCEPTANCE_REVIEW_PHASE" "structured"
            let host =
                if phase = "review-tls-incomplete" || phase = "review-tls-mtls" || phase = "review-tls-issuer-switch" then
                    ReviewTls.createHost phase
                else
                    createReviewHost phase
            Host.deploy host |> ignore

    [<EntryPoint>]
    let main _ =
        Deployment.RunAsync<ReviewStack>()
        |> fun run -> run.GetAwaiter().GetResult()
