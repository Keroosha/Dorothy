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
        let error =
            Assert.Throws<InvalidOperationException>(TestDelegate(fun () -> validate root))
        Assert.That(error.Message, Is.EqualTo("Traefik dynamic configuration is invalid."))

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
                          "serversTransport": "sni@file",
                          "proxyProtocol": {"version": 2}
                        }
                      }
                    },
                    "middlewares": {"allow-local": {"ipAllowList": {"sourceRange": ["127.0.0.1/32"]}}},
                    "serversTransports": {"sni": {"tls": {"serverName": "origin.example.test", "certificates": [{"certificate": "tcp-client"}]}}}
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
        assertInvalid """{"tcp":{"routers":{"r":{"entryPoints":["web"],"rule":"HostSNI(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"serversTransport":"missing"}}}}}"""
        assertInvalid """{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}],"proxyProtocol":{"version":3}}}}}}"""
        assertInvalid """{"tcp":{"services":{"a":{"weighted":{"services":[{"name":"b"}]}},"b":{"weighted":{"services":[{"name":"a"}]}}}}}"""
        assertInvalid """{"tcp":{"routers":{"r":{"entryPoints":["web"],"middlewares":["missing"],"rule":"HostSNI(`x.test`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}"""
        assertInvalid """{"udp":{"services":{"a":{"weighted":{"services":[{"name":"b"}]}},"b":{"weighted":{"services":[{"name":"a"}]}}}}}"""
        assertInvalid """{"tcp":{"serversTransports":{"sni":{"tls":{"rootCAs":["/tmp/ca.pem"]}}}}}"""
