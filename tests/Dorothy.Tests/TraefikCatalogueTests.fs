namespace Dorothy.Tests

open System
open System.Collections.Concurrent
open System.Collections.Immutable
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open NUnit.Framework
open Pulumi
open Pulumi.Testing
open Pulumi.Utilities
open System.Text.Json.Nodes

module private TraefikCatalogueFixture =
    let specification (credential: Output<string>) =
        let _credentialBuilders =
            [ dnsupdateCredentials {
                  dnsupdateNameserver "127.0.0.1:53"
                  dnsupdateTsigKey "acme"
                  dnsupdateTsigSecret credential
                  dnsupdateTsigAlgorithm "hmac-sha256"
                  dnsupdateDnsTimeout "10s"
                  dnsupdateZones "example.test"
                  dnsupdateTtl "60"
                  dnsupdatePropagationTimeout "2m"
                  dnsupdatePollingInterval "2s"
                  dnsupdateSequenceInterval "2s"
              }
              cloudflareCredentials { cloudflareDnsApiToken credential; cloudflareZoneApiToken credential }
              digitalOceanCredentials { digitalOceanAuthToken credential }
              linodeCredentials { linodeToken credential }
              vultrCredentials { vultrApiKey credential } ]
        ignore _credentialBuilders

        traefik {
            entryPoint "legacy-web" { listen 8080 }

            traefikConfiguration {
                staticConfiguration {
                    staticEntryPoints {
                        staticEntryPoint "front" {
                            entryPointAddress "127.0.0.1:18443/tcp"
                            entryPointReusePort false
                            entryPointHttp3 18443
                            entryPointForwardedHeaders (
                                nativeObject {
                                    nativeField "trustedIPs" (nativeArray [ nativeString "127.0.0.1/32" ])
                                    nativeField "insecure" (nativeBoolean false)
                                }
                            )
                            entryPointProxyProtocol (
                                nativeObject {
                                    nativeField "trustedIPs" (nativeArray [ nativeString "127.0.0.1/32" ])
                                }
                            )
                            entryPointTransport (
                                nativeObject {
                                    nativeField "lifeCycle" (nativeObject { nativeField "graceTimeOut" (nativeString "30s") })
                                }
                            )
                        }
                        staticEntryPoint "tls" { entryPointAddress "127.0.0.1:18444/tcp" }
                        staticEntryPoint "dns-udp" { entryPointAddress "127.0.0.1:15353/udp" }
                    }

                    staticCertificatesResolvers {
                        staticCertificatesResolver "dns01" {
                            acme (
                                nativeObject {
                                    acmeEmail "ops@example.test"
                                    acmeDnsChallenge (
                                        nativeObject {
                                            acmeDnsProvider "cloudflare"
                                            acmeDnsResolvers [ "127.0.0.1:53" ]
                                        }
                                    )
                                }
                            )
                        }
                    }

                    staticLog (nativeObject { logLevel "INFO"; logFormat "json" })
                    staticAccessLog (nativeObject { accessLogFormat "json" })
                    staticMetrics (nativeObject { nativeField "addInternals" (nativeBoolean false) })
                    staticTracing (nativeObject { nativeField "sampleRate" (nativeNumber 0.25M) })
                }

                dynamicConfiguration {
                    httpConfiguration {
                        httpRouters {
                            httpRouter "catalog" {
                                httpRule (
                                    (hostRule [ "shop.example.test"; "store.example.test" ] &&& pathPrefixRule "/items")
                                    ||| (hostRule [ "admin.example.test" ] &&& pathPrefixRule "/admin")
                                )
                                httpRouterEntryPoints [ httpEntryPoint "front" ]
                                httpRouterService (httpServiceRef "catalog")
                                httpRouterMiddlewares [ httpMiddlewareRef "compress"; httpMiddlewareRef "strip-items" ]
                                httpRouterPriority 10
                                httpRouterTls (
                                    nativeObject {
                                        httpTlsResolver (certificateResolverRef "dns01")
                                        httpTlsOptions (tlsOptionsRef "modern")
                                    }
                                )
                            }
                            httpRouter "api-parent" {
                                httpRule (pathPrefixRule "/multilayer")
                                httpRouterEntryPoints [ httpEntryPoint "front" ]
                                httpRouterMiddlewares [ httpMiddlewareRef "layer-mark" ]
                            }
                            httpRouter "api-child" {
                                httpRule (headerRule "X-Route-Layer" "admin")
                                httpRouterParentRefs [ httpRouterRef "api-parent" ]
                                httpRouterService (httpServiceRef "catalog")
                            }
                        }

                        httpServices {
                            httpService "catalog" {
                                httpServiceMiddlewares [ httpMiddlewareRef "service-mark" ]
                                httpLoadBalancer (
                                    nativeObject {
                                        httpServers [ "http://127.0.0.1:18080"; "http://127.0.0.1:18081" ]
                                        httpPassHostHeader true
                                        httpServiceServersTransport (httpServersTransportRef "upstream")
                                        httpHealthCheck (
                                            nativeObject {
                                                httpHealthCheckPath "/health"
                                                httpHealthCheckInterval "10s"
                                                httpHealthCheckTimeout "2s"
                                                httpHealthCheckFollowRedirects false
                                            }
                                        )
                                    }
                                )
                            }
                        }

                        httpMiddlewares {
                            httpMiddleware "layer-mark" {
                                httpMiddlewareHeaders (
                                    nativeObject {
                                        nativeField "customRequestHeaders" (
                                            nativeObject { nativeField "X-Route-Layer" (nativeString "admin") }
                                        )
                                    }
                                )
                            }
                            httpMiddleware "service-mark" {
                                httpMiddlewareHeaders (
                                    nativeObject {
                                        nativeField "customResponseHeaders" (
                                            nativeObject { nativeField "X-Dorothy-Service" (nativeString "native") }
                                        )
                                    }
                                )
                            }
                            httpMiddleware "compress" { httpMiddlewareCompress }
                            httpMiddleware "strip-items" { httpMiddlewareStripPrefix [ "/items" ] }
                            httpMiddleware "redirect" { httpMiddlewareRedirectScheme "https" true }
                            httpMiddleware "auth" { httpMiddlewareBasicAuth [ "catalog:hash" ] }
                        }

                        httpServersTransports {
                            httpServersTransport "upstream" {
                                nativeField "forwardingTimeouts" (
                                    nativeObject {
                                        nativeField "dialTimeout" (nativeString "3s")
                                        nativeField "readTimeout" (nativeString "2s")
                                        nativeField "writeTimeout" (nativeString "4s")
                                    }
                                )
                            }
                        }
                    }

                    tcpConfiguration {
                        tcpRouters {
                            tcpRouter "database" {
                                tcpRule (tcpHostSniRule "db.example.test")
                                tcpRouterEntryPoints [ tcpEntryPoint "tls" ]
                                tcpRouterService (tcpServiceRef "database")
                                tcpRouterMiddlewares [ tcpMiddlewareRef "audit" ]
                                tcpRouterTls (nativeObject { tcpTlsPassthrough true })
                            }
                        }
                        tcpServices {
                            tcpService "database" {
                                tcpLoadBalancer (
                                    nativeObject {
                                        tcpServers [ "127.0.0.1:15432" ]
                                        tcpServiceServersTransport (tcpServersTransportRef "database-upstream")
                                        tcpHealthCheck (
                                            nativeObject {
                                                tcpHealthCheckPort 15432
                                                tcpHealthCheckSend "PING"
                                                tcpHealthCheckExpect "PONG"
                                                tcpHealthCheckInterval "10s"
                                                tcpHealthCheckTimeout "2s"
                                            }
                                        )
                                    }
                                )
                            }
                        }
                        tcpMiddlewares {
                            tcpMiddleware "audit" {
                                nativeField "inFlightConn" (nativeObject { nativeField "amount" (nativeInteger 10) })
                            }
                        }
                        tcpServersTransports {
                            tcpServersTransport "database-upstream" {
                                nativeField "dialTimeout" (nativeString "5s")
                                tcpProxyProtocol (nativeObject { tcpProxyProtocolVersion 2 })
                            }
                        }
                    }

                    udpConfiguration {
                        udpRouters {
                            udpRouter "dns" {
                                udpRouterEntryPoints [ udpEntryPoint "dns-udp" ]
                                udpRouterService (udpServiceRef "dns")
                            }
                        }
                        udpServices {
                            udpService "dns" {
                                udpLoadBalancer (nativeObject { udpServers [ "127.0.0.1:15354" ] })
                            }
                        }
                    }

                    tlsConfiguration {
                        tlsOptions {
                            tlsOptionsSet "modern" {
                                tlsMinVersion "VersionTLS12"
                                tlsMaxVersion "VersionTLS13"
                                tlsCipherSuites [ "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" ]
                                tlsCurvePreferences [ "CurveP256"; "CurveP384" ]
                                tlsSniStrict true
                                tlsClientAuth (nativeObject { tlsClientAuthType "RequestClientCert" })
                            }
                        }
                    }
                }

                dnsCredentials {
                    cloudflareCredentials { cloudflareDnsApiToken credential }
                }
            }
        }

    let outputStackOptions (captured: ConcurrentBag<TraefikArgs>) =
        let options = StackOptions()
        options.ResourceTransformations.Add(ResourceTransformation(fun args ->
            match args.Args with
            | :? TraefikArgs as traefikArgs -> captured.Add(traefikArgs)
            | _ -> ()
            Nullable<ResourceTransformationResult>()))
        options


    type Mocks() =
        let resources = ConcurrentDictionary<string, MockResourceArgs>()

        member _.Resources = resources

        interface IMocks with
            member _.NewResourceAsync(args: MockResourceArgs) =
                resources[args.Name] <- args
                let outputs = args.Inputs
                Task.FromResult(args.Name + "-id", box outputs)

            member _.CallAsync(_args: MockCallArgs) =
                Task.FromResult(box ImmutableDictionary<string, obj>.Empty)

            member _.RegisterResourceOutputs(_args: MockRegisterResourceOutputsRequest) = Task.CompletedTask
            member _.RegisterTransform(_transform: ResourceTransform) = Task.CompletedTask
            member _.RegisterInvokeTransform(_transform: InvokeTransform) = Task.CompletedTask
    let private sourceRecord () =
        let args = Pulumi.Cloudflare.DnsRecordArgs()
        args.ZoneId <- Input<string>.op_Implicit "test-zone"
        args.Name <- Input<string>.op_Implicit "traefik-output.example.test"
        args.Type <- Input<string>.op_Implicit "TXT"
        args.Ttl <- Input<double>.op_Implicit 1.0
        args.Content <- Input<string>.op_Implicit(Output.CreateSecret<string>("INFO"))
        Pulumi.Cloudflare.DnsRecord("traefik-config-source", args)

    type OutputStack(captured: ConcurrentBag<TraefikArgs>) =
        inherit Stack(outputStackOptions captured)

        let source = sourceRecord ()

        let host =
            sshHost "traefik-output" {
                Address "192.0.2.10"
                User "root"
                debian {
                    traefik {
                        entryPoint "web" { listen 8080 }
                        traefikConfiguration {
                            staticConfiguration {
                                staticLog (nativeObject { logLevel source.Content })
                                staticTracing (
                                    nativeObject {
                                        nativeField "serviceName" (nativeString source.Content)
                                    }
                                )
                            }
                        }
                    }
                }
            }

        do Host.deploy host |> ignore

        new() = OutputStack(ConcurrentBag<TraefikArgs>())

        member _.Captured = captured


[<TestFixture>]
type TraefikCatalogueTests() =
    [<Test>]
    member _.``Native Traefik catalogue serializes and validates all protocol families``() : Task =
        task {
            let composedRule =
                (hostRule [ "shop.example.test"; "store.example.test" ] &&& pathPrefixRule "/items")
                ||| (hostRule [ "admin.example.test" ] &&& pathPrefixRule "/admin")
            let injectedRule = hostRule [ "shop.example.test\") || PathPrefix(\"/admin"; "shop😀.example.test" ]
            Assert.That(injectedRule.Expression, Does.Contain("\\\""))
            Assert.That(injectedRule.Expression, Does.Contain("\\U0001F600"))
            Assert.That(injectedRule.Expression, Does.Not.Contain("\\uD83D"))

            let specification = TraefikCatalogueFixture.specification (Output.Create("test-cloudflare-token"))
            let resolved = specification.Resolve(CancellationToken.None)
            let configuration = resolved.Configuration |> Option.get
            let! configurationJson = OutputUtilities.GetValueAsync(configuration)
            let root = Dorothy.HostHelper.TraefikSettings.parse configurationJson
            Dorothy.HostHelper.TraefikSettings.validate
                (Map.ofList [ "legacy-web", 8080 ]) 19080 Set.empty Set.empty Set.empty root
            let objectProperty (node: JsonNode) (name: string) = node[name]
            let dynamic = objectProperty root "dynamic"
            let http = objectProperty dynamic "http"
            let router = objectProperty (objectProperty http "routers") "catalog"
            Assert.That((objectProperty router "rule").GetValue<string>(), Does.Contain("Host("))
            Assert.That((objectProperty router "rule").GetValue<string>(), Does.Contain("store.example.test"))
            Assert.That((objectProperty router "rule").GetValue<string>(), Does.Contain(" || "))
            Assert.That(
                (objectProperty router "middlewares").AsArray()
                |> Seq.map (fun value -> value.GetValue<string>())
                |> Seq.toList,
                Is.EqualTo<string list>([ "compress"; "strip-items" ])
            )

            let apiChild = objectProperty (objectProperty http "routers") "api-child"
            Assert.That((objectProperty apiChild "parentRefs").ToJsonString(), Is.EqualTo("[\"api-parent\"]"))
            Assert.That((objectProperty apiChild "rule").GetValue<string>(), Does.Contain("Header("))
            let apiParent = objectProperty (objectProperty http "routers") "api-parent"
            Assert.That((objectProperty apiParent "middlewares").ToJsonString(), Is.EqualTo("[\"layer-mark\"]"))
            Assert.That((objectProperty apiParent "rule").GetValue<string>(), Does.Contain("PathPrefix("))
            let catalogService = objectProperty (objectProperty http "services") "catalog"
            Assert.That((objectProperty catalogService "middlewares").ToJsonString(), Is.EqualTo("[\"service-mark\"]"))
            let httpLoadBalancer = objectProperty catalogService "loadBalancer"
            Assert.That((httpLoadBalancer.AsObject().ContainsKey("middlewares")), Is.False)
            Assert.That((objectProperty httpLoadBalancer "serversTransport").GetValue<string>(), Is.EqualTo("upstream"))
            Assert.That((objectProperty http "serversTransports").AsObject().ContainsKey("upstream"), Is.True)
            let upstream = objectProperty (objectProperty http "serversTransports") "upstream"
            let upstreamTimeouts = objectProperty upstream "forwardingTimeouts"
            Assert.That((objectProperty upstreamTimeouts "readTimeout").GetValue<string>(), Is.EqualTo("2s"))
            Assert.That((objectProperty upstreamTimeouts "writeTimeout").GetValue<string>(), Is.EqualTo("4s"))

            let tcp = objectProperty dynamic "tcp"
            let tcpLoadBalancer =
                objectProperty (objectProperty (objectProperty tcp "services") "database") "loadBalancer"
            Assert.That((objectProperty tcpLoadBalancer "serversTransport").GetValue<string>(), Is.EqualTo("database-upstream"))
            Assert.That((tcpLoadBalancer.AsObject().ContainsKey("proxyProtocol")), Is.False)
            let tcpHealthCheck = objectProperty tcpLoadBalancer "healthCheck"
            Assert.That((objectProperty tcpHealthCheck "port").GetValue<int>(), Is.EqualTo(15432))
            Assert.That((objectProperty tcpHealthCheck "send").GetValue<string>(), Is.EqualTo("PING"))
            let namedTcpTransport = objectProperty (objectProperty tcp "serversTransports") "database-upstream"
            Assert.That((objectProperty (objectProperty namedTcpTransport "proxyProtocol") "version").GetValue<int>(), Is.EqualTo(2))
            Assert.That((objectProperty tcp "serversTransports").AsObject().ContainsKey("database-upstream"), Is.True)
            Assert.That(composedRule.Expression, Does.Contain("&&"))
            Assert.That(composedRule.Expression, Does.Contain(" || "))
            let! outputIsSecret = Output.IsSecretAsync(configuration)
            Assert.That(outputIsSecret, Is.True)
        }

    [<Test>]
    [<NonParallelizable>]
    member _.``Native configuration retains Output dependency and secrecy through ResourceArgs``() =
        let mocks = TraefikCatalogueFixture.Mocks()
        let resources =
            Deployment.TestAsync<TraefikCatalogueFixture.OutputStack>(mocks, TestOptions())
                .GetAwaiter()
                .GetResult()

        let stack = resources |> Seq.pick (function :? TraefikCatalogueFixture.OutputStack as value -> Some value | _ -> None)
        let configurationArgs = stack.Captured |> Seq.exactlyOne
        let configuration = InputExtensions.ToOutput<string>(configurationArgs.Configuration)
        let configurationJson = OutputUtilities.GetValueAsync(configuration).GetAwaiter().GetResult()
        let secret = Output.IsSecretAsync(configuration).GetAwaiter().GetResult()
        let dependencies = OutputUtilities.GetDependenciesAsync(configuration).GetAwaiter().GetResult()
        let dependencyNames =
            dependencies
            |> Seq.map (fun resource ->
                OutputUtilities.GetValueAsync(resource.Urn).GetAwaiter().GetResult().Split("::")
                |> Array.last)
            |> Set.ofSeq

        Assert.That(secret, Is.True)
        Assert.That(dependencyNames, Does.Contain("traefik-config-source"))
        let root = Dorothy.HostHelper.TraefikSettings.parse configurationJson
        let legacyListeners = Map.ofList [ "web", 8080 ]
        Dorothy.HostHelper.TraefikSettings.validate legacyListeners 19080 Set.empty Set.empty Set.empty root
        |> ignore

    [<Test>]
    member _.``Native extension objects reject duplicate fields and named objects``() =
        let duplicateField () =
            nativeObject {
                entryPointAddress "127.0.0.1:8443/tcp"
                entryPointAddress "127.0.0.1:9443/tcp"
            }

        let duplicateObject () =
            staticEntryPoints {
                staticEntryPoint "front" { entryPointAddress "127.0.0.1:8443/tcp" }
                staticEntryPoint "front" { entryPointAddress "127.0.0.1:9443/tcp" }
            }

        Assert.Throws<ArgumentException>(TestDelegate(fun () -> duplicateField () |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> duplicateObject () |> ignore)) |> ignore

    [<Test>]
    member _.``HTTP rule builder preserves exact matcher and composition grammar``() =
        let singleHost = hostRule [ "shop.example.test" ]
        let multipleHosts = hostRule [ "one.example.test"; "two.example.test" ]
        let composed =
            (hostRule [ "shop.example.test" ] &&& pathPrefixRule "/items")
            ||| notRule (pathRegexpRule "^/private($|/)")

        Assert.That(singleHost.Expression, Is.EqualTo("Host(\"shop.example.test\")"))
        Assert.That(
            multipleHosts.Expression,
            Is.EqualTo("(Host(\"one.example.test\") || Host(\"two.example.test\"))")
        )
        Assert.That(
            composed.Expression,
            Is.EqualTo("((Host(\"shop.example.test\")) && (PathPrefix(\"/items\"))) || (!(PathRegexp(\"^/private($|/)\")))")
        )

    [<Test>]
    member _.``Typed listener constructors render numeric IPv4 and IPv6 addresses``() =
        let specification =
            traefikConfiguration {
                staticConfiguration {
                    staticEntryPoints {
                        staticEntryPoint "front" {
                            entryPointListenerAddress "192.0.2.10" 8080 TraefikListenerTransport.Tcp
                        }
                        staticEntryPoint "dns" {
                            entryPointListener (System.Net.IPAddress.Parse("2001:db8::1")) 5353 TraefikListenerTransport.Udp
                        }
                    }
                }
            }
        let output = TraefikConfiguration.resolve specification
        let json = OutputUtilities.GetValueAsync(output).GetAwaiter().GetResult()
        use document = System.Text.Json.JsonDocument.Parse(json)
        let configurationRoot = Dorothy.HostHelper.TraefikSettings.parse json
        Dorothy.HostHelper.TraefikSettings.validate
            (Map.empty: Map<string, int>) 19080 Set.empty Set.empty Set.empty configurationRoot
        |> ignore
        let entryPoints = document.RootElement.GetProperty("static").GetProperty("entryPoints")
        let front = entryPoints.GetProperty("front")
        let dns = entryPoints.GetProperty("dns")
        Assert.That(front.GetProperty("address").GetString(), Is.EqualTo("192.0.2.10:8080/tcp"))
        Assert.That(dns.GetProperty("address").GetString(), Is.EqualTo("[2001:db8::1]:5353/udp"))
        Assert.That(front.EnumerateObject() |> Seq.exists (fun field -> field.Name = "tcp"), Is.False)
        let invalidAddress =
            TestDelegate(fun () ->
                entryPointListenerAddress "listener.example.test" 8080 TraefikListenerTransport.Tcp
                |> ignore)
        let invalidPort =
            TestDelegate(fun () ->
                entryPointListener (System.Net.IPAddress.Parse("192.0.2.10")) 0 TraefikListenerTransport.Tcp
                |> ignore)
        let addressError = Assert.Throws<ArgumentException>(invalidAddress)
        let portError = Assert.Throws<ArgumentException>(invalidPort)
        Assert.That(addressError.Message, Does.Contain("Invalid, unsafe or unsupported Traefik listener socket binding."))
        Assert.That(addressError.Message, Does.Not.Contain("listener.example.test"))
        Assert.That(portError.Message, Does.Contain("Invalid, unsafe or unsupported Traefik listener socket binding."))
        let mappedAddressFailure =
            TestDelegate(fun () ->
                entryPointListener (System.Net.IPAddress.Parse("::ffff:192.0.2.10")) 8080 TraefikListenerTransport.Tcp
                |> ignore)
        let mappedAddressError = Assert.Throws<ArgumentException>(mappedAddressFailure)
        Assert.That(mappedAddressError.Message, Does.Contain("Invalid, unsafe or unsupported Traefik listener socket binding."))
        Assert.That(mappedAddressError.Message, Does.Not.Contain("192.0.2.10"))
