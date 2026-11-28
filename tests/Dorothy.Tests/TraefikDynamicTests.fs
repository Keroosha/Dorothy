namespace Dorothy.Tests

open System
open System.Text.Json.Nodes
open Dorothy.DSL
open NUnit.Framework
open Dorothy.Tests.TestSupport

[<TestFixture>]
type TraefikDynamicTests() =
    let entryPoints = Map.ofList [ "web", "tcp"; "dns", "udp" ]
    let resolvers = Set.ofList [ "le" ]
    let tlsOptions = Set.ofList [ "strict" ]
    let legacyRouters = Set.ofList [ "legacy" ]

    let parse (json: string) = JsonNode.Parse(json) :?> JsonObject

    let validate (root: JsonObject) =
        TraefikDynamic.validate entryPoints resolvers tlsOptions legacyRouters root

    let validateJson json = parse json |> validate

    let assertInvalidRoot (root: JsonObject) =
        try
            validate root
            Assert.Fail("Expected invalid Traefik dynamic configuration.")
        with
        | TraefikDynamic.ValidationError _ -> ()
        | :? InvalidOperationException as invalid ->
            Assert.That(invalid.Message, Is.EqualTo("Traefik dynamic configuration is invalid."))

    let assertValidationFailure (expected: TraefikDynamic.ValidationFailure) (action: unit -> unit) =
        let error: exn =
            Assert.Throws<TraefikDynamic.ValidationError>(TestDelegate(fun () -> action ()))
            :> exn
        match error with
        | TraefikDynamic.ValidationError actual -> Assert.That(actual, Is.EqualTo(expected))
        | _ -> Assert.Fail("Expected the requested Traefik validation failure category.")

    let assertFailure (expected: TraefikDynamic.ValidationFailure) json =
        assertValidationFailure expected (fun () -> validateJson json)

    let assertInvalid json = parse json |> assertInvalidRoot

    let addRootCa (transports: JsonObject) (name: string) (pem: string) =
        let transport = transports[name] :?> JsonObject
        let certificates = JsonArray()
        certificates.Add(JsonValue.Create(pem))
        transport["rootCAs"] <- certificates

    [<Test>]
    member _.``Pinned HTTP TCP and UDP graphs retain typed edges chain order TLS roots and upstream PROXY SNI``() =
        let fixture = createValidCertificateFixture "backend.example.test" [ "backend.example.test" ]
        let root =
            parse
                """{
                  "http": {
                    "routers": {
                      "catalog": {
                        "entryPoints": ["web"],
                        "middlewares": ["ordered@file"],
                        "service": "weighted@file",
                        "rule": "Host(`catalog.example.test`)",
                        "tls": {"options": "strict@file", "certResolver": "le"}
                      }
                    },
                    "services": {
                      "weighted": {"weighted": {"services": [{"name": "secure@file", "weight": 2}, {"name": "local", "weight": 1}]}},
                      "secure": {"loadBalancer": {"servers": [{"url": "https://backend.example.test:8443"}], "serversTransport": "strict@file"}},
                      "local": {"loadBalancer": {"servers": [{"url": "h2c://127.0.0.1:9000"}]}}
                    },
                    "middlewares": {
                      "ordered": {"chain": {"middlewares": ["auth@file", "prefix"]}},
                      "auth": {"basicAuth": {"users": ["alice:$2y$hash"]}},
                      "prefix": {"addPrefix": {"prefix": "/v1"}},
                      "auth-proxy": {"forwardAuth": {"address": "https://auth.example.test", "tls": {"caCertificate": "auth-root", "clientCertificate": "auth-client", "insecureSkipVerify": false, "caOptional": false}}}
                    },
                    "serversTransports": {
                      "strict": {"serverName": "backend.example.test", "minVersion": "VersionTLS12", "maxVersion": "VersionTLS13", "certificates": [{"certificate": "http-client"}]}
                    }
                  },
                  "tcp": {
                    "routers": {
                      "echo": {
                        "entryPoints": ["web"],
                        "middlewares": ["allow-local"],
                        "service": "echo@file",
                        "rule": "HostSNI(`echo.example.test`)",
                        "tls": {"passthrough": false, "options": "strict@file"}
                      }
                    },
                    "services": {
                      "echo": {
                        "loadBalancer": {
                          "servers": [{"address": "127.0.0.1:9443", "tls": true}],
                          "serversTransport": "sni@file"
                        }
                      }
                    },
                    "middlewares": {"allow-local": {"ipAllowList": {"sourceRange": ["127.0.0.1/32"]}}},
                    "serversTransports": {"sni": {"proxyProtocol": {"version": 2}, "tls": {"serverName": "origin.example.test", "certificates": [{"certificate": "tcp-client"}]}}}
                  },
                  "udp": {
                    "routers": {"dns-query": {"entryPoints": ["dns"], "service": "dns-pool@file"}},
                    "services": {"dns-pool": {"weighted": {"services": [{"name": "dns-a@file", "weight": 3}, {"name": "dns-b", "weight": 1}]}},
                      "dns-a": {"loadBalancer": {"servers": [{"address": "127.0.0.1:5301"}]}},
                      "dns-b": {"loadBalancer": {"servers": [{"address": "127.0.0.1:5302"}]}}
                    }
                  },
                  "tls": {"options": {"strict": {}}}
                }"""

        let http = root["http"] :?> JsonObject
        let httpTransports = http["serversTransports"] :?> JsonObject
        addRootCa httpTransports "strict" fixture.RootCertificatePem
        let strict = httpTransports["strict"] :?> JsonObject
        (strict["rootCAs"] :?> JsonArray).Add(JsonValue.Create("legacy-root"))
        let tcp = root["tcp"] :?> JsonObject
        let tcpTransports = tcp["serversTransports"] :?> JsonObject
        let sni = tcpTransports["sni"] :?> JsonObject
        let sniTls = sni["tls"] :?> JsonObject
        let tcpRootCAs = JsonArray()
        tcpRootCAs.Add(JsonValue.Create(fixture.RootCertificatePem))
        tcpRootCAs.Add(JsonValue.Create("tcp-root"))
        sniTls["rootCAs"] <- tcpRootCAs
        validate root

        let middlewares = http["middlewares"] :?> JsonObject
        let ordered = middlewares["ordered"] :?> JsonObject
        let chainConfig = ordered["chain"] :?> JsonObject
        let chain = chainConfig["middlewares"] :?> JsonArray
        Assert.That(chain.ToJsonString(), Is.EqualTo("[\"auth@file\",\"prefix\"]"))
        let serverName = sniTls["serverName"]
        if isNull serverName then invalidOp "Expected an upstream SNI value."
        Assert.That(serverName.GetValue<string>(), Is.EqualTo("origin.example.test"))

    [<Test>]
    member _.``HTTP services require typed references and reject cycles``() =
        assertInvalid """{"http":{"routers":{"r":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"api@internal"}}}}"""
        assertInvalid """{"http":{"routers":{"r":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"tcp-only"}},"services":{}}} """
        assertInvalid """{"http":{"routers":{"r":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"s@docker"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"routers":{"r":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"s","tls":{"options":"strict@docker"}}},"services":{"s":{"loadBalancer":{"servers":[{"url":"https://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"routers":{"r":{"entryPoints":["web"],"middlewares":["missing"],"rule":"Host(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}],"serversTransport":"missing"}}}}}"""
        assertInvalid """{"http":{"routers":{"r":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"s","tls":{"certResolver":"missing"}}},"services":{"s":{"loadBalancer":{"servers":[{"url":"https://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"routers":{"r":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"s","tls":{"options":"missing"}}},"services":{"s":{"loadBalancer":{"servers":[{"url":"https://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"services":{"a":{"weighted":{"services":[{"name":"b"}]}},"b":{"weighted":{"services":[{"name":"a"}]}}}}}"""

    [<Test>]
    member _.``Middleware chains preserve their order and reject missing or cyclic middleware references``() =
        assertInvalid """{"http":{"middlewares":{"a":{"chain":{"middlewares":["missing"]}}}}}"""
        assertInvalid """{"http":{"middlewares":{"a":{"chain":{"middlewares":["b"]}},"b":{"chain":{"middlewares":["a"]}}}}}"""

    [<Test>]
    member _.``Regex replacement capture groups are not templates``() =
        validateJson """{"http":{"middlewares":{"canonical":{"redirectRegex":{"regex":"^https?://[^/]+/(.*)$","replacement":"https://shop.test/${1}","permanent":true}}}}}"""

    [<Test>]
    member _.``Unknown plugin file and template settings fail closed``() =
        assertInvalid """{"http":{"models":{}}}"""
        assertInvalid """{"http":{"middlewares":{"m":{"plugin":{"arbitrary":{}}}}}}"""
        assertInvalid """{"http":{"middlewares":{"auth":{"basicAuth":{"usersFile":"/etc/passwd"}}}}}"""
        assertInvalid """{"http":{"middlewares":{"forward":{"forwardAuth":{"address":"http://auth.example.test/{{.Host}}"}}}}}"""
        assertInvalid """{"http":{"middlewares":{"allow":{"ipWhiteList":{"sourceRange":["127.0.0.1/32"],"rejectStatusCode":401}}}}}"""

    [<Test>]
    member _.``HTTPS transports accept inline certificate roots and reject paths and insecure verification``() =
        let fixture = createValidCertificateFixture "backend.example.test" [ "backend.example.test" ]
        let accepted = parse """{"http":{"serversTransports":{"strict":{"rootCAs":[]}}}}"""
        let transports = (accepted["http"] :?> JsonObject)["serversTransports"] :?> JsonObject
        addRootCa transports "strict" fixture.RootCertificatePem
        let strict = transports["strict"] :?> JsonObject
        let rootCAs = strict["rootCAs"] :?> JsonArray
        rootCAs.Add(JsonValue.Create("legacy-root"))
        let certificates = JsonArray()
        let certificate = JsonObject()
        certificate["certificate"] <- JsonValue.Create("legacy-client")
        certificates.Add(certificate)
        strict["certificates"] <- certificates
        validate accepted

        let forwardAuth = parse """{"http":{"middlewares":{"auth":{"forwardAuth":{"address":"https://auth.example.test","tls":{"caCertificate":"legacy-root","clientCertificate":"legacy-client"}}}}}}"""
        let forwardHttp = forwardAuth["http"] :?> JsonObject
        let forwardMiddlewares = forwardHttp["middlewares"] :?> JsonObject
        let forward = forwardMiddlewares["auth"] :?> JsonObject
        let forwardConfig = forward["forwardAuth"] :?> JsonObject
        let forwardTls = forwardConfig["tls"] :?> JsonObject
        forwardTls["caCertificate"] <- JsonValue.Create(fixture.RootCertificatePem)
        validate forwardAuth

        let privateKeyRoot = parse """{"http":{"serversTransports":{"strict":{"rootCAs":[]}}}}"""
        let privateKeyTransports = (privateKeyRoot["http"] :?> JsonObject)["serversTransports"] :?> JsonObject
        addRootCa privateKeyTransports "strict" fixture.PrivateKeyPem
        assertInvalidRoot privateKeyRoot

        assertInvalid """{"http":{"serversTransports":{"strict":{"rootCAs":["/etc/ssl/private/ca.pem"]}}}}"""
        assertInvalid """{"http":{"serversTransports":{"strict":{"insecureSkipVerify":true}}}}"""
        assertInvalid """{"http":{"serversTransports":{"strict":{"certificates":[{"certFile":"/tmp/client.crt","keyFile":"/tmp/client.key"}]}}}}"""
        assertInvalid """{"http":{"serversTransports":{"strict":{"certificates":[{"certificate":"../client"}]}}}}"""
        assertInvalid """{"http":{"serversTransports":{"strict":{"rootCAs":["not a PEM certificate"]}}}}"""
        assertInvalid """{"http":{"middlewares":{"auth":{"forwardAuth":{"address":"https://auth.example.test","tls":{"caCertificate":"/etc/ssl/ca.pem"}}}}}}"""
        assertInvalid """{"http":{"middlewares":{"auth":{"forwardAuth":{"address":"https://auth.example.test","tls":{"clientCertificate":"/etc/ssl/client.pem"}}}}}}"""
        assertInvalid """{"http":{"middlewares":{"auth":{"forwardAuth":{"address":"https://auth.example.test","tls":{"insecureSkipVerify":true}}}}}}"""
        assertInvalid """{"http":{"middlewares":{"auth":{"forwardAuth":{"address":"https://auth.example.test","tls":{"caOptional":true}}}}}}"""

    [<Test>]
    member _.``Routers require explicit protocol-compatible entry points and unique legacy-safe names``() =
        assertInvalid """{"http":{"routers":{"r":{"rule":"Host(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"routers":{"r":{"entryPoints":["dns"],"rule":"Host(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"udp":{"routers":{"r":{"entryPoints":["web"],"service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:5300"}]}}}}}"""
        assertInvalid """{"http":{"routers":{"legacy":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"routers":{"keroosha-admin":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"services":{"keroosha-backend-generated":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"middlewares":{"keroosha-redirect-generated":{"addPrefix":{"prefix":"/"}}}}}"""

    [<Test>]
    member _.``TCP proxy references validate PROXY versions SNI and transport identity``() =
        assertInvalid """{"tcp":{"routers":{"r":{"entryPoints":["web"],"rule":"HostSNI(`x.test`)","service":"s","tls":{}}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"serversTransport":"missing"}}}}}"""
        assertInvalid """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"proxyProtocol":{"version":3}}}}}}"""
        assertInvalid """{"tcp":{"services":{"a":{"weighted":{"services":[{"name":"b"}]}},"b":{"weighted":{"services":[{"name":"a"}]}}}}}"""
        assertInvalid """{"tcp":{"routers":{"r":{"entryPoints":["web"],"middlewares":["missing"],"rule":"HostSNI(`x.test`)","service":"s","tls":{}}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"udp":{"services":{"a":{"weighted":{"services":[{"name":"b"}]}},"b":{"weighted":{"services":[{"name":"a"}]}}}}}"""
        assertInvalid """{"tcp":{"serversTransports":{"sni":{"tls":{"rootCAs":["/tmp/ca.pem"]}}}}}"""
    [<Test>]
    member _.``UDP routers cannot compete for one entry point``() =
        assertInvalid """{"udp":{"routers":{"first":{"entryPoints":["dns"],"service":"s"},"second":{"entryPoints":["dns"],"service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:5300"}]}}}}}"""

        let entryPointsWithSecondUdp = Map.add "dns-alt" "udp" entryPoints
        let distinct =
            parse
                """{"udp":{"routers":{"first":{"entryPoints":["dns"],"service":"s"},"second":{"entryPoints":["dns-alt"],"service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:5300"}]}}}}}"""
        TraefikDynamic.validate entryPointsWithSecondUdp resolvers tlsOptions legacyRouters distinct

        let overlap =
            parse
                """{"udp":{"routers":{"first":{"entryPoints":["dns","dns-alt"],"service":"s"},"second":{"entryPoints":["dns-alt"],"service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:5300"}]}}}}}"""
        assertValidationFailure TraefikDynamic.ValidationFailure.UdpListenerOverlap (fun () ->
            TraefikDynamic.validate entryPointsWithSecondUdp resolvers tlsOptions legacyRouters overlap)

    [<Test>]
    member _.``HTTP parentRefs retain multi-layer edges and service middleware order``() =
        let root =
            parse
                """{"http":{
                  "routers":{
                    "root":{"entryPoints":["web"],"rule":"PathPrefix(`/multi`)","middlewares":["enrich"]},
                    "middle":{"parentRefs":["root@file"],"rule":"Header(`X-Role`,`admin`)","middlewares":["child-chain"]},
                    "leaf":{"parentRefs":["middle@file","root"],"rule":"PathPrefix(`/multi/admin`)","service":"admin"}
                  },
                  "services":{
                    "admin":{"middlewares":["service-tag","prefix"],"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}
                  },
                  "middlewares":{
                    "enrich":{"headers":{"customRequestHeaders":{"X-Role":"admin"}}},
                    "child-chain":{"chain":{"middlewares":["normalize"]}},
                    "normalize":{"stripPrefix":{"prefixes":["/multi"]}},
                    "service-tag":{"headers":{"customResponseHeaders":{"X-Dorothy-Service":"native"}}},
                    "prefix":{"addPrefix":{"prefix":"/from-service"}}
                  }
                }}"""
        validate root

        let http = root["http"] :?> JsonObject
        let routers = http["routers"] :?> JsonObject
        Assert.That(routers["middle"].["parentRefs"].ToJsonString(), Is.EqualTo("[\"root@file\"]"))
        Assert.That(routers["leaf"].["parentRefs"].ToJsonString(), Is.EqualTo("[\"middle@file\",\"root\"]"))
        Assert.That(routers["root"].["middlewares"].ToJsonString(), Is.EqualTo("[\"enrich\"]"))
        Assert.That(routers["middle"].["middlewares"].ToJsonString(), Is.EqualTo("[\"child-chain\"]"))
        let services = http["services"] :?> JsonObject
        Assert.That(services["admin"].["middlewares"].ToJsonString(), Is.EqualTo("[\"service-tag\",\"prefix\"]"))

    [<Test>]
    member _.``HTTP parent graphs reject missing edges cycles and child root-only fields``() =
        assertInvalid """{"http":{"routers":{"child":{"parentRefs":["missing"],"rule":"Host(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"routers":{"a":{"parentRefs":["b"],"rule":"Host(`x.test`)"},"b":{"parentRefs":["a"],"rule":"Host(`x.test`)"} }}}"""
        assertInvalid
            """{
              "http": {
                "routers": {
                  "root": {
                    "entryPoints": ["web"],
                    "rule": "PathPrefix(`/`)",
                    "service": "s"
                  },
                  "child": {
                    "parentRefs": ["root"],
                    "rule": "Host(`x.test`)",
                    "service": "s"
                  }
                },
                "services": {
                  "s": {
                    "loadBalancer": {
                      "servers": [{"url": "http://127.0.0.1:9000"}]
                    }
                  }
                }
              }
            }"""
        assertInvalid """{"http":{"routers":{"root":{"entryPoints":["web"],"rule":"PathPrefix(`/`)"},"child":{"parentRefs":["root"],"entryPoints":["web"],"rule":"Host(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"routers":{"root":{"entryPoints":["web"],"rule":"PathPrefix(`/`)"},"child":{"parentRefs":["root"],"rule":"Host(`x.test`)","service":"s","tls":{}}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""

    [<Test>]
    member _.``HTTP service middleware references participate in typed cycles``() =
        assertInvalid """{"http":{"services":{"s":{"middlewares":["missing"],"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"http":{"services":{"s":{"middlewares":["errors"],"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}},"middlewares":{"errors":{"errors":{"service":"s"}}}}}"""

    [<Test>]
    member _.``Named TCP transports own outgoing PROXY and termination delay``() =
        validateJson """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"serversTransport":"upstream"}}},"serversTransports":{"upstream":{"proxyProtocol":{"version":2},"terminationDelay":"100ms"}}}}"""
        validateJson """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"proxyProtocol":{"version":1}}}}}}"""
        assertFailure TraefikDynamic.ValidationFailure.ProxyProtocolPlacement """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"serversTransport":"upstream","proxyProtocol":{"version":2}}}},"serversTransports":{"upstream":{"dialTimeout":"5s"}}}}"""
        assertFailure TraefikDynamic.ValidationFailure.ProxyProtocolPlacement """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"serversTransport":"upstream","terminationDelay":100}}},"serversTransports":{"upstream":{"dialTimeout":"5s"}}}}"""

    [<Test>]
    member _.``TCP passthrough cannot claim ignored TLS policy and literal SNI needs TLS``() =
        assertInvalid """{"tcp":{"routers":{"r":{"entryPoints":["web"],"rule":"HostSNI(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"tcp":{"routers":{"r":{"entryPoints":["web"],"rule":"HostSNI(`x.test`)","service":"s","tls":{"passthrough":true,"options":"strict"}}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"tcp":{"routers":{"r":{"entryPoints":["web"],"rule":"HostSNI(`x.test`)","service":"s","tls":{"passthrough":true,"certResolver":"le"}}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"tcp":{"routers":{"r":{"entryPoints":["web"],"rule":"HostSNI(`x.test`)","service":"s","tls":{"passthrough":true,"domains":[{"main":"x.test"}]}}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}"""
        validateJson """{"tcp":{"routers":{"r":{"entryPoints":["web"],"rule":"HostSNI(`*`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}"""

    [<Test>]
    member _.``TCP native health checks validate all load-balancer and weighted fields``() =
        validateJson """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"healthCheck":{"port":9001,"send":"PING","expect":"PONG","interval":"5s","unhealthyInterval":"10s","timeout":"2s"}}}}}}"""
        validateJson """{"tcp":{"services":{"parent":{"weighted":{"services":[{"name":"child"}],"healthCheck":{}}},"child":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"healthCheck":{"port":65536}}}}}}"""
        assertInvalid """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"healthCheck":{"unexpected":true}}}}}}"""

    [<Test>]
    member _.``File-exposed HTTP middleware and transport fields are admitted exactly``() =
        let root =
            parse
                """{"http":{
                  "middlewares":{
                    "retry":{"retry":{"attempts":3,"timeout":"10s","initialInterval":"100ms","maxRequestBodyBytes":4096,"status":["500-599"],"disableRetryOnNetworkError":true,"retryNonIdempotentMethod":true}},
                    "signin":{"forwardAuth":{"address":"https://auth.example.test/check","authSigninURL":"https://login.example.test/sign-in"}},
                    "path":{"encodedCharacters":{"allowEncodedSlash":true,"allowEncodedBackSlash":false,"allowEncodedNullCharacter":false,"allowEncodedSemicolon":false,"allowEncodedPercent":true,"allowEncodedQuestionMark":false,"allowEncodedHash":false}},
                    "cert-info":{"passTLSClientCert":{"info":{"subject":{"organizationalUnit":true},"issuer":{"commonName":true}}}}
                  },
                  "serversTransports":{"timeouts":{"forwardingTimeouts":{"readTimeout":"2s","writeTimeout":"3s"}}}
                }}"""
        validate root

        assertInvalid """{"http":{"middlewares":{"path":{"encodedCharacters":{"allowEncodedSlash":true,"allowEncodedNewline":true}}}}}"""
        assertInvalid """{"http":{"middlewares":{"retry":{"retry":{"attempts":2,"futureOption":true}}}}}"""
        assertInvalid """{"http":{"middlewares":{"cert-info":{"passTLSClientCert":{"info":{"issuer":{"organizationalUnit":true}}}}}}}"""
        assertInvalid """{"http":{"models":{"front":{"middlewares":[],"tls":{},"observability":{"accessLogs":true}}}}}"""
        assertInvalid """{"tcp":{"models":{"front":{}}}}"""
        assertInvalid """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000","port":"9000"}]}}}}}"""

        assertInvalid """{"http":{"serversTransports":{"workload":{"spiffe":{"trustDomain":"example.test"}}}}}"""
        assertInvalid """{"tcp":{"serversTransports":{"workload":{"spiffe":{"trustDomain":"example.test"}}}}}"""
        assertInvalid """{"tcp":{"serversTransports":{"workload":{"tls":{"spiffe":{"trustDomain":"example.test"}}}}}}"""
    [<Test>]
    member _.``Graph admission failures carry safe non-identifying categories``() =
        assertFailure TraefikDynamic.ValidationFailure.UnresolvedReference """{"http":{"routers":{"r":{"entryPoints":["web"],"rule":"Host(`x.test`)","service":"missing"}}}}"""
        assertFailure TraefikDynamic.ValidationFailure.ListenerProtocolMismatch """{"udp":{"routers":{"r":{"entryPoints":["web"],"service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:5300"}]}}}}}"""
        assertFailure TraefikDynamic.ValidationFailure.UdpListenerOverlap """{"udp":{"routers":{"a":{"entryPoints":["dns"],"service":"s"},"b":{"entryPoints":["dns"],"service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:5300"}]}}}}}"""
        assertFailure TraefikDynamic.ValidationFailure.ProxyProtocolPlacement """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"serversTransport":"upstream","proxyProtocol":{"version":2}}}},"serversTransports":{"upstream":{"dialTimeout":"5s"}}}}"""

    [<Test>]
    member _.``Trusted legacy lowering resolves native references but rejects user internal spoofing``() =
        let backend = "http://127.0.0.1:9000"
        let redirectOrigin = "https://redirect.example.test"
        let hash (value: string) =
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))
            |> Convert.ToHexStringLower
        let backendService = "keroosha-backend-" + hash backend
        let redirectMiddleware = "keroosha-redirect-" + hash ("legacy-redirect\n" + redirectOrigin)
        let routes: TraefikHttpGraphModel.LegacyRouter list =
            [ { Name = "legacy-backend"
                Host = "legacy.example.test"
                EntryPoint = "legacy-web"
                ExcludedPathSubtree = None
                Target = TraefikHttpGraphModel.LegacyTarget.Backend backend
                Tls = TraefikHttpGraphModel.LegacyTls.None }
              { Name = "legacy-redirect"
                Host = "redirect.example.test"
                EntryPoint = "legacy-web"
                ExcludedPathSubtree = None
                Target = TraefikHttpGraphModel.LegacyTarget.Redirect redirectOrigin
                Tls = TraefikHttpGraphModel.LegacyTls.None } ]
        let makeRoot (service: string) =
            let root =
                parse
                    """{"static":{},"dynamic":{"http":{"routers":{"native-share":{"entryPoints":["legacy-web"],"rule":"Host(`native.example.test`)","service":"placeholder","middlewares":["placeholder"]}}}}}"""
            let http = (root["dynamic"] :?> JsonObject)["http"] :?> JsonObject
            let routers = http["routers"] :?> JsonObject
            let native = routers["native-share"] :?> JsonObject
            native["service"] <- JsonValue.Create(service)
            let middlewares = JsonArray()
            middlewares.Add(JsonValue.Create(redirectMiddleware))
            native["middlewares"] <- middlewares
            root
        let validateLegacy root =
            TraefikSettings.validateWithLegacyRoutes
                (Map.ofList [ "legacy-web", 8080 ])
                19080
                Set.empty
                Set.empty
                Set.empty
                routes
                root

        let _, mergedDynamic = validateLegacy (makeRoot backendService)
        let mergedHttp = mergedDynamic["http"] :?> JsonObject
        Assert.That((mergedHttp["services"] :?> JsonObject).ContainsKey(backendService), Is.True)
        Assert.That((mergedHttp["middlewares"] :?> JsonObject).ContainsKey(redirectMiddleware), Is.True)

        for internalTarget in [ "api@internal"; "noop@internal" ] do
            let error =
                Assert.Throws<TraefikSettings.InvalidConfiguration>(
                    TestDelegate(fun () -> validateLegacy (makeRoot internalTarget) |> ignore)
                )
            Assert.That(error.Message, Does.Not.Contain(internalTarget))

        let adminSpoof =
            parse
                """{"static":{},"dynamic":{"http":{"routers":{"keroosha-admin":{"entryPoints":["legacy-web"],"rule":"Host(`attacker.example.test`)","service":"api@internal"}}}}}"""
        let adminError =
            Assert.Throws<TraefikSettings.InvalidConfiguration>(
                TestDelegate(fun () -> validateLegacy adminSpoof |> ignore)
            )
        Assert.That(adminError.Message, Does.Not.Contain("keroosha-admin"))
