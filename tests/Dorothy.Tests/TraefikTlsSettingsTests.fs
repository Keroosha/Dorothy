namespace Dorothy.Tests

open System
open System.IO
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Net
open System.Text.Json.Nodes
open Dorothy.DSL
open NUnit.Framework
open Dorothy.HostHelper

[<TestFixture>]
type TraefikTlsSettingsTests() =
    let parse (json: string) = JsonNode.Parse(json) :?> JsonObject
    let entryPoints = Map.ofList [ "web", "80" ]

    let validate (legacyResolvers: Set<string>) (legacyCertificates: Set<string>) (configuration: JsonObject) =
        TraefikTlsSettings.validate entryPoints legacyResolvers legacyCertificates configuration

    let assertInvalid (legacyResolvers: Set<string>) (legacyCertificates: Set<string>) (configuration: JsonObject) =
        let error =
            Assert.Throws<InvalidOperationException>(
                TestDelegate(fun () -> validate legacyResolvers legacyCertificates configuration)
            )
        Assert.That(error.Message, Is.EqualTo("Traefik TLS or ACME configuration is invalid."))

    let digest (value: string) =
        SHA256.HashData(Encoding.UTF8.GetBytes(value))
        |> Convert.ToHexString
        |> fun hash -> hash.ToLowerInvariant()

    let publicCertificatePem () =
        use rsa = RSA.Create(2048)
        let request = CertificateRequest("CN=ca.example.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        use certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddDays(30.0))
        certificate.ExportCertificatePem()

    [<Test>]
    member _.``ACME storage is injected as a stable helper-owned path without mutating input``() =
        let configuration =
            parse """{
              "static":{"certificatesResolvers":{"le":{"acme":{"email":"ops@example.test","httpChallenge":{"entryPoint":"web"}}}}},
              "dynamic":{"tls":{"options":{"default":{"minVersion":"VersionTLS12","sniStrict":true}},"stores":{"default":{"defaultGeneratedCert":{"resolver":"le","domain":{"main":"shop.example.test","sans":["www.example.test"]}}}}}}
            }"""

        validate Set.empty Set.empty configuration
        let staticRoot = configuration["static"] :?> JsonObject
        let transformed = TraefikTlsSettings.staticSettings "/var/lib/traefik" staticRoot
        let resolvers = transformed["certificatesResolvers"] :?> JsonObject
        let resolver = resolvers["le"] :?> JsonObject
        let acme = resolver["acme"] :?> JsonObject
        let storage = acme["storage"].GetValue<string>()
        let originalResolvers = staticRoot["certificatesResolvers"] :?> JsonObject
        let originalResolver = originalResolvers["le"] :?> JsonObject
        let originalAcme = originalResolver["acme"] :?> JsonObject

        let defaultIssuer = "https://acme-v02.api.letsencrypt.org/directory"
        Assert.That(storage, Is.EqualTo(TraefikTlsSettings.acmeStoragePath "/var/lib/traefik" "le" defaultIssuer))
        Assert.That(storage, Is.Not.EqualTo(TraefikTlsSettings.legacyAcmeStoragePath "/var/lib/traefik" "le"))
        Assert.That(
            TraefikTlsSettings.acmeStoragePath "/var/lib/traefik" "le" "https://ca.example.test/directory",
            Is.Not.EqualTo(storage)
        )
        Assert.That(originalAcme.ContainsKey("storage"), Is.False)
        Assert.That(transformed, Is.Not.SameAs(staticRoot))

    [<Test>]
    member _.``Dynamic TLS resolves only named protected certificate material``() =
        let configuration =
            parse """{
              "dynamic":{
                "tls":{
                  "certificates":[{"certificate":"identity","stores":["default"]}],
                  "options":{"client":{"minVersion":"VersionTLS12","clientAuth":{"clientAuthType":"RequireAndVerifyClientCert","caFiles":["identity"]},"sniStrict":true}},
                  "stores":{"default":{"defaultCertificate":{"certificate":"identity"}}}
                },
                "http":{
                  "serversTransports":{"origin":{"serverName":"api.example.test","rootCAs":["ca-root"],"certificates":[{"certificate":"identity"}]}},
                  "middlewares":{"auth":{"forwardAuth":{"address":"https://auth.example.test","tls":{"caCertificate":"ca-root","clientCertificate":"identity","insecureSkipVerify":false}}}}
                },
                "tcp":{"serversTransports":{"database":{"tls":{"serverName":"db.example.test","rootCAs":["ca-root"],"certificates":[{"certificate":"identity"}],"insecureSkipVerify":false}}}}
              }
            }"""
        let certificatePaths =
            Map.ofList [
                "identity", ("/protected/identity.crt", "/protected/identity.key")
                "ca-root", ("/protected/ca-root.crt", "/protected/ca-root.key")
            ]
        let expectedCertificates = set [ "identity"; "ca-root" ]

        validate Set.empty expectedCertificates configuration
        let dynamicRoot = configuration["dynamic"] :?> JsonObject
        let transformed = TraefikTlsSettings.dynamicSettings certificatePaths dynamicRoot
        let tls = transformed["tls"] :?> JsonObject
        let certificates = tls["certificates"] :?> JsonArray
        let certificate = certificates[0] :?> JsonObject
        let options = tls["options"] :?> JsonObject
        let option = options["client"] :?> JsonObject
        let clientAuth = option["clientAuth"] :?> JsonObject
        let caFiles = clientAuth["caFiles"] :?> JsonArray
        let stores = tls["stores"] :?> JsonObject
        let defaultStore = stores["default"] :?> JsonObject
        let storeCertificate = defaultStore["defaultCertificate"] :?> JsonObject
        let sourceTls = dynamicRoot["tls"] :?> JsonObject
        let sourceCertificates = sourceTls["certificates"] :?> JsonArray
        let sourceCertificate = sourceCertificates[0] :?> JsonObject
        let http = transformed["http"] :?> JsonObject
        let httpTransports = http["serversTransports"] :?> JsonObject
        let httpTransport = httpTransports["origin"] :?> JsonObject
        let httpRootCAs = httpTransport["rootCAs"] :?> JsonArray
        let httpClientCertificates = httpTransport["certificates"] :?> JsonArray
        let httpClientCertificate = httpClientCertificates[0] :?> JsonObject
        let middlewares = http["middlewares"] :?> JsonObject
        let authMiddleware = middlewares["auth"] :?> JsonObject
        let forwardAuth = authMiddleware["forwardAuth"] :?> JsonObject
        let forwardAuthTls = forwardAuth["tls"] :?> JsonObject
        let tcp = transformed["tcp"] :?> JsonObject
        let tcpTransports = tcp["serversTransports"] :?> JsonObject
        let tcpTransport = tcpTransports["database"] :?> JsonObject
        let tcpTls = tcpTransport["tls"] :?> JsonObject
        let tcpRootCAs = tcpTls["rootCAs"] :?> JsonArray
        let tcpCertificates = tcpTls["certificates"] :?> JsonArray
        let tcpCertificate = tcpCertificates[0] :?> JsonObject

        let certificateStores = certificate["stores"] :?> JsonArray
        Assert.That(certificate["certFile"].GetValue<string>(), Is.EqualTo("/protected/identity.crt"))
        Assert.That(certificate["keyFile"].GetValue<string>(), Is.EqualTo("/protected/identity.key"))
        Assert.That(certificateStores[0].GetValue<string>(), Is.EqualTo("default"))
        Assert.That(caFiles[0].GetValue<string>(), Is.EqualTo("/protected/identity.crt"))
        Assert.That(storeCertificate["certFile"].GetValue<string>(), Is.EqualTo("/protected/identity.crt"))
        Assert.That(storeCertificate["keyFile"].GetValue<string>(), Is.EqualTo("/protected/identity.key"))
        Assert.That(sourceCertificate["certificate"].GetValue<string>(), Is.EqualTo("identity"))
        Assert.That(httpRootCAs[0].GetValue<string>(), Is.EqualTo("/protected/ca-root.crt"))
        Assert.That(httpClientCertificate["certFile"].GetValue<string>(), Is.EqualTo("/protected/identity.crt"))
        Assert.That(forwardAuthTls["ca"].GetValue<string>(), Is.EqualTo("/protected/ca-root.crt"))
        Assert.That(forwardAuthTls["cert"].GetValue<string>(), Is.EqualTo("/protected/identity.crt"))
        Assert.That(forwardAuthTls["key"].GetValue<string>(), Is.EqualTo("/protected/identity.key"))
        Assert.That(tcpRootCAs[0].GetValue<string>(), Is.EqualTo("/protected/ca-root.crt"))
        Assert.That(tcpCertificate["keyFile"].GetValue<string>(), Is.EqualTo("/protected/identity.key"))

    [<Test>]
    member _.``Inline CA PEM is accepted without private key or filesystem fallback``() =
        let pem = publicCertificatePem ()
        let configuration = JsonObject()
        let dynamic = JsonObject()
        let tls = JsonObject()
        let options = JsonObject()
        let mtls = JsonObject()
        let clientAuth = JsonObject()
        let caFiles = JsonArray()
        caFiles.Add(JsonValue.Create(pem))
        clientAuth["clientAuthType"] <- JsonValue.Create("RequireAndVerifyClientCert")
        clientAuth["caFiles"] <- caFiles
        mtls["clientAuth"] <- clientAuth
        options["mtls"] <- mtls
        tls["options"] <- options
        dynamic["tls"] <- tls
        let http = JsonObject()
        let transports = JsonObject()
        let transport = JsonObject()
        let rootCAs = JsonArray()
        rootCAs.Add(JsonValue.Create(pem))
        transport["rootCAs"] <- rootCAs
        transports["upstream"] <- transport
        http["serversTransports"] <- transports
        let middlewares = JsonObject()
        let auth = JsonObject()
        let forwardAuth = JsonObject()
        let forwardAuthTls = JsonObject()
        forwardAuthTls["caCertificate"] <- JsonValue.Create(pem)
        forwardAuth["tls"] <- forwardAuthTls
        auth["forwardAuth"] <- forwardAuth
        middlewares["auth"] <- auth
        http["middlewares"] <- middlewares
        dynamic["http"] <- http
        configuration["dynamic"] <- dynamic

        validate Set.empty Set.empty configuration
        let transformed = TraefikTlsSettings.dynamicSettings Map.empty dynamic
        let transformedHttp = transformed["http"] :?> JsonObject
        let transformedTransports = transformedHttp["serversTransports"] :?> JsonObject
        let transformedTransport = transformedTransports["upstream"] :?> JsonObject
        let transformedRoots = transformedTransport["rootCAs"] :?> JsonArray
        let transformedMiddlewares = transformedHttp["middlewares"] :?> JsonObject
        let transformedAuth = transformedMiddlewares["auth"] :?> JsonObject
        let transformedForwardAuth = transformedAuth["forwardAuth"] :?> JsonObject
        let transformedForwardAuthTls = transformedForwardAuth["tls"] :?> JsonObject

        Assert.That(transformedRoots[0].GetValue<string>(), Is.EqualTo(pem))
        Assert.That(transformedForwardAuthTls["ca"].GetValue<string>(), Is.EqualTo(pem))

        use rsa = RSA.Create(2048)
        let request = CertificateRequest("CN=ca.example.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        use certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddDays(30.0))
        let privatePem = certificate.ExportCertificatePem() + "\n" + rsa.ExportPkcs8PrivateKeyPem()
        let invalid = JsonObject()
        let invalidDynamic = JsonObject()
        let invalidHttp = JsonObject()
        let invalidTransports = JsonObject()
        let invalidTransport = JsonObject()
        let invalidRoots = JsonArray()
        invalidRoots.Add(JsonValue.Create(privatePem))
        invalidTransport["rootCAs"] <- invalidRoots
        invalidTransports["upstream"] <- invalidTransport
        invalidHttp["serversTransports"] <- invalidTransports
        invalidDynamic["http"] <- invalidHttp
        invalid["dynamic"] <- invalidDynamic
        assertInvalid Set.empty Set.empty invalid

    [<Test>]
    member _.``DNS challenge credentials use the pinned dnsupdate contract``() =
        let configuration =
            parse """{
              "static":{"certificatesResolvers":{"le":{"acme":{"dnsChallenge":{"provider":"dnsupdate"}}}}},
              "dnsCredentials":{"dnsupdate":{"DNSUPDATE_NAMESERVER":"127.0.0.1:5300","DNSUPDATE_TSIG_KEY":"acme-key.","DNSUPDATE_TSIG_SECRET":"opaque-secret","DNSUPDATE_TSIG_ALGORITHM":"hmac-sha256."}}
            }"""

        validate Set.empty Set.empty configuration
        let entries = TraefikTlsSettings.dnsEnvironment (Some configuration)
        Assert.That(entries |> List.map fst, Is.EqualTo<string list>([ "DNSUPDATE_NAMESERVER"; "DNSUPDATE_TSIG_ALGORITHM"; "DNSUPDATE_TSIG_KEY"; "DNSUPDATE_TSIG_SECRET" ]))
        Assert.That(entries |> List.tryFind (fun (key, _) -> key = "DNSUPDATE_TSIG_SECRET") |> Option.map snd, Is.EqualTo(Some "opaque-secret"))

    [<Test>]
    member _.``Provider credential allowlists reject file hooks and redact values``() =
        let secret = "credential-that-must-not-appear"
        let configuration =
            parse """{
              "static":{"certificatesResolvers":{"le":{"acme":{"dnsChallenge":{"provider":"dnsupdate"}}}}},
              "dnsCredentials":{"dnsupdate":{"DNSUPDATE_NAMESERVER":"127.0.0.1:5300","DNSUPDATE_TSIG_SECRET":"credential-that-must-not-appear","DNSUPDATE_TSIG_FILE":"/tmp/credential-that-must-not-appear"}}
            }"""
        let error =
            Assert.Throws<InvalidOperationException>(
                TestDelegate(fun () -> validate Set.empty Set.empty configuration)
            )
        Assert.That(error.Message, Does.Not.Contain(secret))
        Assert.That(error.Message, Is.EqualTo("Traefik TLS or ACME configuration is invalid."))

    [<Test>]
    member _.``DNS provider names and tokens must match the vetted provider environment``() =
        let providerConfiguration =
            parse """{
              "static":{"certificatesResolvers":{"le":{"acme":{"dnsChallenge":{"provider":"digitalocean"}}}}},
              "dnsCredentials":{"digitalocean":{"DO_AUTH_TOKEN":"token"}}
            }"""
        validate Set.empty Set.empty providerConfiguration

        let badConfiguration =
            parse """{
              "static":{"certificatesResolvers":{"le":{"acme":{"dnsChallenge":{"provider":"digitalocean"}}}}},
              "dnsCredentials":{"digitalocean":{"DO_AUTH_TOKEN":"token","DO_API_URL":"https://attacker.invalid"}}
            }"""
        assertInvalid Set.empty Set.empty badConfiguration

    [<Test>]
    member _.``TLS validation rejects duplicate and undeclared certificate references``() =
        let duplicate =
            parse """{"dynamic":{"tls":{"certificates":[{"certificate":"identity"},{"certificate":"identity"}]}}}"""
        assertInvalid Set.empty (set [ "identity" ]) duplicate

        let undeclared =
            parse """{"dynamic":{"tls":{"stores":{"default":{"defaultCertificate":{"certificate":"missing"}}}}}}"""
        assertInvalid Set.empty Set.empty undeclared

    [<Test>]
    member _.``Caller-selected ACME storage and unknown TLS fields are rejected``() =
        let storage =
            parse """{"static":{"certificatesResolvers":{"le":{"acme":{"storage":"/tmp/secret.json","httpChallenge":{"entryPoint":"web"}}}}}}"""
        assertInvalid Set.empty Set.empty storage

        let unknown = parse """{"dynamic":{"tls":{"options":{"default":{"allowInsecure":true}}}}}"""
        assertInvalid Set.empty Set.empty unknown

    [<Test>]
    member _.``TLS probe bind selection is numeric local and preserves address family``() =
        let localAddress, localPort =
            Traefik.resolveProbeBind "192.0.2.44:9443/tcp" (set [ "192.0.2.44" ])
            |> Option.defaultWith (fun () -> failwith "Expected the explicitly local address to resolve.")
        let wildcardV4, wildcardV4Port =
            Traefik.resolveProbeBind ":8443/tcp" Set.empty
            |> Option.defaultWith (fun () -> failwith "Expected the IPv4 wildcard to resolve to loopback.")
        let wildcardV6, wildcardV6Port =
            Traefik.resolveProbeBind "[::]:8443/tcp" Set.empty
            |> Option.defaultWith (fun () -> failwith "Expected the IPv6 wildcard to resolve to loopback.")

        Assert.That(localAddress.ToString(), Is.EqualTo("192.0.2.44"))
        Assert.That(localPort, Is.EqualTo(9443))
        Assert.That(wildcardV4.ToString(), Is.EqualTo(IPAddress.Loopback.ToString()))
        Assert.That(wildcardV6.ToString(), Is.EqualTo(IPAddress.IPv6Loopback.ToString()))
        Assert.That(wildcardV4Port, Is.EqualTo(8443))
        Assert.That(wildcardV6Port, Is.EqualTo(8443))
        let nonLocal = Traefik.resolveProbeBind "192.0.2.45:9443/tcp" (set [ "192.0.2.44" ])
        let hostname = Traefik.resolveProbeBind "proxy.example.test:9443/tcp" (set [ "proxy.example.test" ])
        Assert.That(Option.isNone nonLocal, Is.True)
        Assert.That(Option.isNone hostname, Is.True)

    [<Test>]
    member _.``SNI host extraction accepts only unambiguous positive literal matchers``() =
        Assert.That(
            Traefik.probeHostsFromRule false """(Host("shop.example.test")) && (PathPrefix("/catalog"))""",
            Is.EqualTo<string list>([ "shop.example.test" ])
        )
        Assert.That(
            Traefik.probeHostsFromRule true "HostSNI(`db.example.test`)",
            Is.EqualTo<string list>([ "db.example.test" ])
        )
        Assert.That(Traefik.probeHostsFromRule false "HostRegexp(`{subdomain:[a-z]+}.example.test`)", Is.Empty)
        Assert.That(Traefik.probeHostsFromRule false "!Host(`negated.example.test`)", Is.Empty)
        Assert.That(Traefik.probeHostsFromRule false "Host(`one.example.test`) || Host(`two.example.test`)", Is.Empty)
        Assert.That(Traefik.probeHostsFromRule false "PathPrefix(`/catalog`) && Host(`shop.example.test`)", Is.Empty)

    [<Test>]
    member _.``EAB HMAC accepts only the pinned Lego URL-safe base64 encodings``() =
        let makeConfiguration (encoded: string) =
            let configuration =
                parse """{"static":{"certificatesResolvers":{"le":{"acme":{"eab":{"kid":"account","hmacEncoded":"__8"},"httpChallenge":{"entryPoint":"web"}}}}}}"""
            let staticRoot = configuration["static"] :?> JsonObject
            let resolvers = staticRoot["certificatesResolvers"] :?> JsonObject
            let resolver = resolvers["le"] :?> JsonObject
            let acme = resolver["acme"] :?> JsonObject
            let eab = acme["eab"] :?> JsonObject
            eab["hmacEncoded"] <- JsonValue.Create(encoded)
            configuration

        for encoded in [ "__8"; "__8=" ] do
            validate Set.empty Set.empty (makeConfiguration encoded)
        for encoded in [ "+/8="; "__8=="; "__=8"; "A"; "" ] do
            assertInvalid Set.empty Set.empty (makeConfiguration encoded)

    [<Test>]
    member _.``TLS options accept pinned TLS 1.3 suites and ML-KEM groups``() =
        let supported =
            parse """{
              "dynamic":{"tls":{"options":{"post-quantum":{
                "minVersion":"VersionTLS13",
                "cipherSuites":["TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"],
                "curvePreferences":["X25519MLKEM768","SecP256r1MLKEM768","SecP384r1MLKEM1024"]
              }}}}
            }"""
        validate Set.empty Set.empty supported

        let unsupportedSuite =
            parse """{"dynamic":{"tls":{"options":{"default":{"cipherSuites":["TLS_UNSUPPORTED"]}}}}}"""
        let unsupportedCurve =
            parse """{"dynamic":{"tls":{"options":{"default":{"curvePreferences":["MLKEM_UNKNOWN"]}}}}}"""
        assertInvalid Set.empty Set.empty unsupportedSuite
        assertInvalid Set.empty Set.empty unsupportedCurve
