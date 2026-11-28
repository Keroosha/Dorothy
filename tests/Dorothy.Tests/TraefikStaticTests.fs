namespace Dorothy.Tests

open System
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text.Json.Nodes
open Dorothy.DSL
open Dorothy.Tests.TestSupport
open NUnit.Framework

[<TestFixture>]
type TraefikStaticTests() =
    let adminPort = 6060

    let parse (text: string) =
        match JsonNode.Parse(text) with
        | :? JsonObject as value -> value
        | _ -> invalidOp "Test input must be a JSON object."

    let validate legacy text = TraefikStatic.validate legacy adminPort (parse text)

    let assertInvalid (action: unit -> unit) =
        let error = Assert.Catch<Exception>(TestDelegate(action))
        match error with
        | TraefikStatic.ValidationError _ -> ()
        | :? InvalidOperationException as invalid ->
            Assert.That(invalid.Message, Is.EqualTo("Static Traefik configuration is invalid."))
        | _ -> Assert.Fail("Unexpected static validation failure.")

    let assertCategory (category: TraefikStatic.ValidationFailure) (action: unit -> unit) =
        let error: exn = Assert.Throws<TraefikStatic.ValidationError>(TestDelegate(action)) :> exn
        match error with
        | TraefikStatic.ValidationError actual -> Assert.That(actual, Is.EqualTo(category))
        | _ -> Assert.Fail("Expected the requested Traefik static validation category.")
    [<Test>]
    member _.``entrypoint protocols include legacy TCP and default TCP and normalize UDP``() =
        let actual =
            validate (Map.ofList [ "legacy", 8080 ])
                """{
                    "entryPoints": {
                        "web": { "address": "127.0.0.1:8081" },
                        "dns": { "address": "127.0.0.1:8081/UDP" }
                    }
                }"""

        Assert.That(
            actual,
            Is.EqualTo<Map<string,string>>(Map.ofList [ "legacy", "tcp"; "web", "tcp"; "dns", "udp" ])
        )

    [<Test>]
    member _.``bind validation rejects overlaps and the private admin port``() =
        assertCategory TraefikStatic.ValidationFailure.SocketBind (fun () ->
            validate Map.empty
                """{"entryPoints":{"all":{"address":":8081"},"loopback":{"address":"127.0.0.1:8081/tcp"}}}"""
            |> ignore)
        assertCategory TraefikStatic.ValidationFailure.SocketBind (fun () ->
            validate Map.empty """{"entryPoints":{"admin":{"address":"127.0.0.1:6060"}}}"""
            |> ignore)
        assertCategory TraefikStatic.ValidationFailure.SocketBind (fun () ->
            validate (Map.ofList [ "legacy", adminPort ]) "{}" |> ignore)

    [<Test>]
    member _.``mapped IPv4 binds overlap and cannot claim the private admin socket``() =
        assertCategory TraefikStatic.ValidationFailure.SocketBind (fun () ->
            validate Map.empty """{"entryPoints":{"mapped":{"address":"[::ffff:127.0.0.1]:8081"},"ipv4":{"address":"127.0.0.1:8081"}}}"""
            |> ignore)
        assertCategory TraefikStatic.ValidationFailure.SocketBind (fun () ->
            validate Map.empty (sprintf """{"entryPoints":{"mapped":{"address":"[::ffff:127.0.0.1]:%d"}}}""" adminPort)
            |> ignore)

    [<Test>]
    member _.``mapped IPv4 CIDRs and empty secure PROXY trust are rejected``() =
        for network in [ "::ffff:0.0.0.0/96"; "::ffff:0.0.0.0/1" ] do
            let invalid =
                sprintf """{"entryPoints":{"front":{"address":":8081","proxyProtocol":{"trustedIPs":["%s"]}}}}""" network
            assertCategory TraefikStatic.ValidationFailure.TrustNetwork (fun () -> validate Map.empty invalid |> ignore)
        assertCategory TraefikStatic.ValidationFailure.TrustNetwork (fun () ->
            validate Map.empty """{"entryPoints":{"front":{"address":":8081","proxyProtocol":{}}}}"""
            |> ignore)
        assertCategory TraefikStatic.ValidationFailure.TrustNetwork (fun () ->
            validate Map.empty """{"entryPoints":{"front":{"address":":8081","proxyProtocol":{"trustedIPs":[]}}}}"""
            |> ignore)
        let mappedSubnet =
            validate Map.empty """{"entryPoints":{"front":{"address":":8081","proxyProtocol":{"trustedIPs":["::ffff:10.0.0.0/104"]}}}}"""
        Assert.That(mappedSubnet, Is.EqualTo<Map<string,string>>(Map.ofList [ "front", "tcp" ]))

    [<Test>]
    member _.``exporter push intervals must be positive``() =
        let invalid =
            [ """{"metrics":{"datadog":{"address":"127.0.0.1:8125","pushInterval":"0s"}}}"""
              """{"metrics":{"statsD":{"pushInterval":"-1s"}}}"""
              """{"metrics":{"influxDB2":{"pushInterval":"0"}}}"""
              """{"metrics":{"otlp":{"http":{"endpoint":"http://localhost:4318/v1/metrics"},"pushInterval":"0s"}}}""" ]
        for settings in invalid do
            assertInvalid (fun () -> validate Map.empty settings |> ignore)

        validate Map.empty """{"metrics":{"datadog":{"address":"127.0.0.1:8125","pushInterval":"250ms"}}}"""
        |> ignore
        validate Map.empty """{"metrics":{"statsD":{"pushInterval":"1s"}}}""" |> ignore
        validate Map.empty """{"metrics":{"influxDB2":{"pushInterval":"2s"}}}""" |> ignore
        validate Map.empty """{"metrics":{"otlp":{"http":{"endpoint":"http://localhost:4318/v1/metrics"},"pushInterval":"3s"}}}"""
        |> ignore

    [<Test>]
    member _.``Read accepts expired inline CAs but still enforces CA constraints``() =
        use key = RSA.Create(2048)
        let request = CertificateRequest("CN=expired static root", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        request.CertificateExtensions.Add(X509BasicConstraintsExtension(true, true, 1, true)) |> ignore
        use expiredRoot =
            request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2.0), DateTimeOffset.UtcNow.AddDays(-1.0))
        let settings = parse """{"serversTransport":{"rootCAs":[]}}"""
        settings.["serversTransport"].["rootCAs"].AsArray().Add(JsonValue.Create(expiredRoot.ExportCertificatePem()) :> JsonNode)

        assertInvalid (fun () -> TraefikStatic.validate Map.empty adminPort settings |> ignore)
        TraefikStatic.validateForRead Map.empty adminPort settings |> ignore

        let leaf = createValidCertificateFixture "static leaf" [ "leaf.example.test" ]
        let leafSettings = parse """{"serversTransport":{"rootCAs":[]}}"""
        leafSettings.["serversTransport"].["rootCAs"].AsArray().Add(JsonValue.Create(leaf.LeafCertificatePem) :> JsonNode)
        assertInvalid (fun () -> TraefikStatic.validateForRead Map.empty adminPort leafSettings |> ignore)

    [<Test>]
    member _.``TCP and UDP may share a port but HTTP3 reserves its implied UDP socket``() =
        let valid =
            validate Map.empty
                """{"entryPoints":{"tcp":{"address":":8443/tcp"},"udp":{"address":":8443/udp"}}}"""
        Assert.That(valid, Is.EqualTo<Map<string,string>>(Map.ofList [ "tcp", "tcp"; "udp", "udp" ]))

        let withHttp3 =
            """{"entryPoints":{"quic":{"address":"127.0.0.1:8444","http3":{}},"udp":{"address":"127.0.0.1:8444/udp"}}}"""
        assertInvalid (fun () -> validate Map.empty withHttp3 |> ignore)

        let h3Only = validate Map.empty """{"entryPoints":{"quic":{"address":"127.0.0.1:8445","http3":{}}}}"""
        Assert.That(h3Only, Is.EqualTo<Map<string,string>>(Map.ofList [ "quic", "tcp" ]))
        let advertisedPortDoesNotChangeTheUdpBind =
            """{"entryPoints":{"quic":{"address":"127.0.0.1:8446","http3":{"advertisedPort":9446}},"udp":{"address":"127.0.0.1:8446/udp"}}}"""
        assertInvalid (fun () -> validate Map.empty advertisedPortDoesNotChangeTheUdpBind |> ignore)

        let separateAdvertisedPort =
            validate Map.empty
                """{"entryPoints":{"quic":{"address":"127.0.0.1:8447","http3":{"advertisedPort":9447}},"udp":{"address":"127.0.0.1:9447/udp"}}}"""
        Assert.That(separateAdvertisedPort, Is.EqualTo<Map<string,string>>(Map.ofList [ "quic", "tcp"; "udp", "udp" ]))


    [<Test>]
    member _.``safe static operations and bounded entrypoint fields are accepted``() =
        let settings =
            parse
                """{
                    "entryPoints": {
                        "front": {
                            "address": "127.0.0.1:8443/tcp",
                            "allowACMEByPass": false,
                            "reusePort": false,
                            "asDefault": true,
                            "forwardedHeaders": { "insecure": false, "trustedIPs": ["127.0.0.1/32", "10.0.0.0/8"], "connection": ["X-Forwarded-For"], "notAppendXForwardedFor": true },
                            "proxyProtocol": { "insecure": false, "trustedIPs": ["10.0.0.2"] },
                            "transport": {
                                "lifeCycle": { "requestAcceptGraceTimeout": "2s", "graceTimeOut": "5s" },
                                "respondingTimeouts": { "readTimeout": "10s", "writeTimeout": "0", "idleTimeout": "1m" },
                                "keepAliveMaxTime": "2m",
                                "keepAliveMaxRequests": 1000
                            },
                            "http": {
                                "redirections": { "entryPoint": { "to": "secure", "scheme": "https", "permanent": true, "priority": 100 } },
                                "middlewares": ["edge-auth@file"],
                                "tls": { "options": "modern@file", "certResolver": "le", "domains": [{"main":"example.test","sans":["shop.example.test"]}] },
                                "encodedCharacters": {
                                    "allowEncodedSlash": false,
                                    "allowEncodedBackSlash": false,
                                    "allowEncodedNullCharacter": false,
                                    "allowEncodedSemicolon": false,
                                    "allowEncodedPercent": false,
                                    "allowEncodedQuestionMark": false,
                                    "allowEncodedHash": false
                                },
                                "encodeQuerySemicolons": true,
                                "sanitizePath": true,
                                "maxHeaderBytes": 16384,
                                "aliasHeadersStrategy": "reject"
                            },
                            "http2": { "maxConcurrentStreams": 100, "maxDecoderHeaderTableSize": 4096, "maxEncoderHeaderTableSize": 4096 },
                            "http3": { "advertisedPort": 8443 },
                            "udp": { "timeout": "3s" },
                            "observability": { "accessLogs": true, "metrics": true, "tracing": true, "traceVerbosity": "detailed" }
                        },
                        "secure": {
                            "address": "127.0.0.1:9443/tcp",
                            "asDefault": false,
                            "http": { "tls": { "options": "default" } }
                        }
                    },
                    "certificatesResolvers": { "le": {} },
                    "global": { "checkNewVersion": false, "sendAnonymousUsage": false, "notAppendXForwardedFor": true },
                    "core": { "defaultRuleSyntax": "v3", "strictTLSOptions": true },
                    "hostResolver": { "cnameFlattening": true, "resolvDepth": 8 },
                    "log": {
                        "level": "INFO",
                        "format": "json",
                        "noColor": true,
                        "otlp": { "http": { "endpoint": "http://localhost:4318/v1/logs", "headers": { "X-API-Key": "redacted" } } }
                    },
                    "accessLog": {
                        "format": "json",
                        "filters": { "statusCodes": ["200", "400-499"], "retryAttempts": true, "minDuration": "1.5s" },
                        "fields": {
                            "defaultMode": "drop",
                            "names": { "StartUTC": "keep" },
                            "headers": { "defaultMode": "redact", "names": { "Authorization": "redact" } },
                            "queryParameters": { "defaultMode": "drop" }
                        },
                        "bufferingSize": 100,
                        "addInternals": false,
                        "dualOutput": true,
                        "otlp": { "http": { "endpoint": "http://127.0.0.1:4318/v1/logs" } }
                    },
                    "metrics": {
                        "addInternals": false,
                        "prometheus": {
                            "buckets": [0.1, 1.0],
                            "addEntryPointsLabels": true,
                            "addRoutersLabels": false,
                            "addServicesLabels": true,
                            "entryPoint": "keroosha-admin",
                            "manualRouting": false,
                            "headerLabels": { "client": "X-Client" }
                        },
                        "datadog": { "address": "127.0.0.1:8125", "pushInterval": "10s", "prefix": "traefik" },
                        "statsD": { "address": "localhost:8125", "pushInterval": "10s", "prefix": "traefik" },
                        "influxDB2": { "address": "http://127.0.0.1:8086", "pushInterval": "10s", "org": "local", "bucket": "metrics", "additionalLabels": { "site": "test" } },
                        "otlp": {
                            "http": { "endpoint": "http://127.0.0.1:4318/v1/metrics", "headers": { "X-API-Key": "redacted" } },
                            "explicitBoundaries": [0.05, 0.1],
                            "pushInterval": "10s",
                            "serviceName": "traefik",
                            "resourceAttributes": { "deployment.environment": "test" }
                        }
                    },
                    "tracing": {
                        "serviceName": "traefik",
                        "globalAttributes": { "deployment.environment": "test" },
                        "capturedRequestHeaders": ["X-Request-ID"],
                        "capturedResponseHeaders": ["X-Trace-ID"],
                        "safeQueryParams": ["page"],
                        "sampleRate": 0.25,
                        "addInternals": false,
                        "otlp": { "grpc": { "endpoint": "localhost:4317", "insecure": true, "headers": { "X-API-Key": "redacted" } } }
                    },
                    "serversTransport": {
                        "insecureSkipVerify": false,
                        "rootCAs": [],
                        "maxIdleConnsPerHost": 128,
                        "forwardingTimeouts": { "dialTimeout": "3s", "responseHeaderTimeout": "5s", "idleConnTimeout": "90s" }
                    },
                    "tcpServersTransport": {
                        "dialKeepAlive": "15s",
                        "dialTimeout": "3s",
                        "terminationDelay": "100ms",
                        "tls": { "insecureSkipVerify": false, "rootCAs": [] }
                    },
                    "ping": { "entryPoint": "keroosha-admin", "manualRouting": false, "terminatingStatusCode": 200 }
                }"""

        let rootCertificate =
            createValidCertificateFixture "static transport root" [ "collector.example.test" ]
        settings.["serversTransport"].["rootCAs"].AsArray().Add(JsonValue.Create(rootCertificate.RootCertificatePem) :> JsonNode)
        settings.["tcpServersTransport"].["tls"].["rootCAs"].AsArray().Add(JsonValue.Create(rootCertificate.RootCertificatePem) :> JsonNode)
        let listeners = TraefikStatic.validate Map.empty adminPort settings
        Assert.That(listeners, Is.EqualTo<Map<string,string>>(Map.ofList [ "front", "tcp"; "secure", "tcp" ]))

        let dynamic =
            parse
                """{
                    "http": { "middlewares": { "edge-auth": { "headers": { "frameDeny": true } } } },
                    "tls": { "options": { "modern": { "minVersion": "VersionTLS13" } } }
                }"""
        TraefikStatic.validateReferences settings dynamic (Set.singleton "le")
    [<Test>]
    member _.``only fixed local exporter defaults are implicit``() =
        let localDefaults = parse """{"metrics":{"statsD":{},"influxDB2":{}}}"""
        TraefikStatic.validate Map.empty adminPort localDefaults |> ignore
        assertInvalid (fun () -> validate Map.empty """{"metrics":{"datadog":{}}}""" |> ignore)

    [<Test>]
    member _.``the built-in default TLS option needs no dynamic declaration``() =
        let settings = parse """{"entryPoints":{"front":{"address":":8443","http":{"tls":{"options":"default"}}}}}"""
        TraefikStatic.validateReferences settings (parse "{}") Set.empty

    [<Test>]
    member _.``static references require file namespace and resolve to the dynamic graph``() =
        let invalidSettings =
            [ """{"entryPoints":{"front":{"address":":8443","http":{"middlewares":["edge-auth"]}}}}"""
              """{"entryPoints":{"front":{"address":":8443","http":{"middlewares":["edge-auth@internal"]}}}}"""
              """{"entryPoints":{"front":{"address":":8443","http":{"middlewares":["missing@file"]}}}}"""
              """{"entryPoints":{"front":{"address":":8443","http":{"tls":{"options":"missing@file"}}}}}"""
              """{"entryPoints":{"front":{"address":":8443","http":{"tls":{"certResolver":"missing"}}}}}""" ]

        let dynamic = parse """{"http":{"middlewares":{"edge-auth":{}}},"tls":{"options":{"modern":{}}}}"""
        for text in invalidSettings do
            let settings = parse text
            assertInvalid (fun () -> TraefikStatic.validateReferences settings dynamic Set.empty)

        let badDefaultResolver = parse """{"entryPoints":{"front":{"address":":8443","http":{"tls":{"certResolver":"le"}}}}}"""
        assertInvalid (fun () -> TraefikStatic.validateReferences badDefaultResolver dynamic Set.empty)

    [<Test>]
    member _.``health and Prometheus entrypoints require the generated private endpoint``() =
        let privateMetrics = parse """{"metrics":{"prometheus":{"entryPoint":"keroosha-admin"}}}"""
        TraefikStatic.validate Map.empty adminPort privateMetrics |> ignore
        let privatePing = parse """{"ping":{"entryPoint":"keroosha-admin"}}"""
        TraefikStatic.validate Map.empty adminPort privatePing |> ignore
        TraefikStatic.validateReferences privateMetrics (parse "{}") Set.empty
        TraefikStatic.validateReferences privatePing (parse "{}") Set.empty

        for invalid in
            [ """{"ping":{"entryPoint":"public"}}"""
              """{"metrics":{"prometheus":{"entryPoint":"public"}}}"""
              """{"ping":{}}"""
              """{"metrics":{"prometheus":{}}}"""
              """{"ping":{"entryPoint":"traefik"}}"""
              """{"metrics":{"prometheus":{"entryPoint":"traefik"}}}"""
              """{"entryPoints":{"keroosha-admin":{"address":":8081"}}}"""
              """{"entryPoints":{"traefik":{"address":":8081"}}}""" ] do
            assertInvalid (fun () -> validate Map.empty invalid |> ignore)

        for destination in [ "traefik"; "keroosha-admin" ] do
            let redirection =
                sprintf
                    """{"entryPoints":{"front":{"address":":8081","http":{"redirections":{"entryPoint":{"to":"%s"}}}}}}"""
                    destination
            assertInvalid (fun () -> validate Map.empty redirection |> ignore)

        assertInvalid (fun () ->
            validate Map.empty
                """{"entryPoints":{"front":{"address":":8081","http":{"redirections":{"entryPoint":{"to":"udp"}}}},"udp":{"address":":9000/udp"}}}"""
            |> ignore)

    [<Test>]
    member _.``unknown aliases APIs providers paths and nested fields are rejected``() =
        let invalidSettings =
            [ """{"api":{"insecure":true}}"""
              """{"providers":{"file":{"directory":"/tmp"}}}"""
              """{"entrypoints":{"front":{"address":":8081"}}}"""
              """{"entryPoints":{"front":{"address":":8081","HTTP":{"tls":{}}}}}"""
              """{"entryPoints":{"front":{"address":"unix:///tmp/traefik.sock"}}}"""
              """{"entryPoints":{"front":{"address":":8081","transport":{"respondingTimeouts":{"api":true}}}}}"""
              """{"log":{"filePath":"/tmp/traefik.log"}}"""
              """{"accessLog":{"filePath":"/tmp/access.log"}}"""
              """{"serversTransport":{"rootCAs":["/etc/ssl/private.pem"]}}"""
              """{"tracing":{"otlp":{"http":{"tls":{"cert":"/tmp/client.pem"}}}}}"""
              """{"entryPoints":{"front":{"address":":8081","http":{"aliasHeadersStrategy":"reject","underscoreHeadersStrategy":"keep"}}}}"""
              """{"entryPoints":{"front":{"address":":8081","http":{"middlewares":["{{ .Host }}@file"]}}}}"""
              """{"entryPoints":{"web":{"address":":8081"},"WEB":{"address":":8082"}}}"""
              """{"entryPoints":{"front":{"address":":8081","command":"id"}}}"""
              """{"experimental":{"plugins":{"x":{"moduleName":"x"}}}}"""
              """{"experimental":{"otlpLogs":true}}"""
              """{"tcpServersTransport":{"tls":{"rootCAs":["/etc/ssl/private.pem"]}}}"""
              """{"serversTransport":{"insecureSkipVerify":true}}"""
              """{"tcpServersTransport":{"tls":{"insecureSkipVerify":true}}}"""
              """{"tracing":{"globalAttributes":{},"resourceAttributes":{}}}"""
              """{"metrics":{"datadog":{"address":"collector.example:8125"}}}"""
              """{"metrics":{"influxDB2":{"address":"http://localhost:8086","token":"/etc/influx/token"}}}"""
              """{"tracing":{"otlp":{"http":{"endpoint":"https://collector.example:4318/v1/traces"}}}}"""
              """{"hostResolver":{"resolvConfig":"/tmp/resolv.conf"}}"""
              """{"metrics":{"statsD":{"address":"metrics.example:8125"}}}"""
              """{"metrics":{"otlp":{"http":{"endpoint":"http://localhost:4318/custom"}}}}"""
              """{"accessLog":{"otlp":{"grpc":{"endpoint":"collector.example:4317"}}}}"""
              """{"log":{"otlp":{"http":{"endpoint":"http://localhost:4318/v1/traces"}}}}""" ]
        for text in invalidSettings do
            assertInvalid (fun () -> validate Map.empty text |> ignore)
    [<Test>]
    member _.``deprecated static aliases are accepted alone and rejected when ambiguous``() =
        let legacyAliases =
            parse
                """{
                    "entryPoints": { "front": { "address": ":8081", "http": { "underscoreHeadersStrategy": "reject" } } },
                    "tracing": { "globalAttributes": { "deployment.environment": "test" } }
                }"""
        TraefikStatic.validate Map.empty adminPort legacyAliases |> ignore
        assertInvalid (fun () ->
            validate Map.empty
                """{"entryPoints":{"front":{"address":":8081","http":{"aliasHeadersStrategy":"reject","underscoreHeadersStrategy":"reject"}}}}"""
            |> ignore)
        TraefikStatic.validate Map.empty adminPort (parse """{"core":{"defaultRuleSyntax":"v2"}}""") |> ignore

    [<Test>]
    member _.``static transport trust accepts inline CA PEM and rejects a leaf certificate``() =
        let leaf = createValidCertificateFixture "static leaf" [ "leaf.example.test" ]
        let settings = parse """{"serversTransport":{"rootCAs":[]}}"""
        settings.["serversTransport"].["rootCAs"].AsArray().Add(JsonValue.Create(leaf.LeafCertificatePem) :> JsonNode)
        assertInvalid (fun () -> TraefikStatic.validate Map.empty adminPort settings |> ignore)


    [<Test>]
    member _.``trust all and malformed duration or telemetry endpoints are rejected``() =
        assertCategory TraefikStatic.ValidationFailure.TrustNetwork (fun () ->
            validate Map.empty """{"entryPoints":{"front":{"address":":8081","forwardedHeaders":{"insecure":true}}}}"""
            |> ignore)
        assertCategory TraefikStatic.ValidationFailure.TrustNetwork (fun () ->
            validate Map.empty """{"entryPoints":{"front":{"address":":8081","proxyProtocol":{"trustedIPs":["0.0.0.0/0"]}}}}"""
            |> ignore)
        assertInvalid (fun () ->
            validate Map.empty """{"entryPoints":{"front":{"address":":8081","transport":{"keepAliveMaxTime":"1week"}}}}"""
            |> ignore)
        assertInvalid (fun () ->
            validate Map.empty """{"tracing":{"otlp":{"http":{"endpoint":"file:///tmp/collector"}}}}"""
            |> ignore)
