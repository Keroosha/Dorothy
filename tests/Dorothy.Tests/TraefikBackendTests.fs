namespace Dorothy.Tests

open System
open System.IO
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.IO.Compression
open Dorothy.HostHelper
open NUnit.Framework
open System.Diagnostics
open System.Threading
open Dorothy.DSL.Provider

[<RequireQualifiedAccess>]
module private TraefikArchiveTestData =
    let private writeText (header: byte[]) offset (value: string) =
        let bytes = Encoding.ASCII.GetBytes(value)
        Array.Copy(bytes, 0, header, offset, bytes.Length)

    let private writeOctal (header: byte[]) offset width (value: int64) =
        let encoded = Convert.ToString(value, 8).PadLeft(width - 1, '0') + "\000"
        writeText header offset encoded

    let private header (name: string) (length: int64) =
        let result = Array.zeroCreate<byte> 512
        writeText result 0 name
        writeOctal result 100 8 0o755L
        writeOctal result 108 8 0L
        writeOctal result 116 8 0L
        writeOctal result 124 12 length
        writeOctal result 136 12 0L
        Array.fill result 148 8 (byte ' ')
        result[156] <- byte '0'
        writeText result 257 "ustar\000"
        writeText result 263 "00"
        let checksum = result |> Array.sumBy int
        writeText result 148 (Convert.ToString(checksum, 8).PadLeft(6, '0') + "\000 ")
        result

    let private compress (tar: MemoryStream) =
        use compressed = new MemoryStream()
        do
            use gzip = new GZipStream(compressed, CompressionLevel.Optimal, true)
            tar.Position <- 0L
            tar.CopyTo(gzip)
        compressed.ToArray()

    let archive (entries: (string * byte[]) list) =
        use tar = new MemoryStream()

        for name, payload in entries do
            let entryHeader = header name (int64 payload.Length)
            tar.Write(entryHeader, 0, entryHeader.Length)
            tar.Write(payload, 0, payload.Length)
            let padding = (512 - payload.Length % 512) % 512
            if padding > 0 then
                let zeroes = Array.zeroCreate<byte> padding
                tar.Write(zeroes, 0, zeroes.Length)

        let terminator = Array.zeroCreate<byte> 1024
        tar.Write(terminator, 0, terminator.Length)
        compress tar

    let archiveWithDeclaredBinaryLength (length: int64) =
        use tar = new MemoryStream()
        let entryHeader = header "traefik" length
        tar.Write(entryHeader, 0, entryHeader.Length)
        let terminator = Array.zeroCreate<byte> 1024
        tar.Write(terminator, 0, terminator.Length)
        compress tar

    let checksum (bytes: byte[]) =
        SHA256.HashData(bytes)
        |> Convert.ToHexString
        |> fun value -> value.ToLowerInvariant()

    let extract (archiveBytes: byte[]) =
        use archive = new MemoryStream(archiveBytes, false)
        use binary = new MemoryStream()
        let length, checksum = Traefik.extractBinary archive binary
        length, checksum, binary.ToArray()

    let assertInvalidArchive (archiveBytes: byte[]) =
        let failure =
            TestDelegate(fun () ->
                extract archiveBytes |> ignore)
        Assert.Throws<Traefik.BackendError>(failure) |> ignore

[<TestFixture>]
type TraefikBackendTests() =
    let paths: Traefik.RuntimePaths =
        { ConfigDir = "/tmp/traefik/config"
          StateDir = "/tmp/traefik/state"
          InstallDir = "/tmp/traefik/bin"
          UnitPath = "/tmp/traefik/keroosha-traefik.service" }

    let digest (value: string) =
        SHA256.HashData(Encoding.UTF8.GetBytes(value))
        |> Convert.ToHexString
        |> fun result -> result.ToLowerInvariant()
    let apiConfigurationFromJson adminPort (rawDataText: string) (entryPointsText: string) (versionText: string) : Traefik.ApiConfiguration =
        use rawData = JsonDocument.Parse(rawDataText)
        use entryPoints = JsonDocument.Parse(entryPointsText)
        use version = JsonDocument.Parse(versionText)
        { RawData = rawData.RootElement.Clone()
          EntryPoints = entryPoints.RootElement.Clone()
          Version = version.RootElement.Clone()
          AdminPort = adminPort }

    let apiConfigurationFromArrays (routers: JsonElement) (services: JsonElement) (middlewares: JsonElement) =
        let resources (items: JsonElement) =
            let result = JsonObject()
            for item in items.EnumerateArray() do
                let name = item.GetProperty("name").GetString()
                match JsonNode.Parse(item.GetRawText()) with
                | :? JsonObject as value ->
                    value.Remove("name") |> ignore
                    value.Remove("provider") |> ignore
                    value.Remove("type") |> ignore
                    result[name] <- value
                | _ -> invalidOp "API fixture resource must be an object."
            result
        let rawData = JsonObject()
        rawData["routers"] <- resources routers
        rawData["services"] <- resources services
        rawData["middlewares"] <- resources middlewares
        rawData["tcpRouters"] <- JsonObject()
        rawData["tcpServices"] <- JsonObject()
        rawData["tcpMiddlewares"] <- JsonObject()
        rawData["udpRouters"] <- JsonObject()
        rawData["udpServices"] <- JsonObject()
        apiConfigurationFromJson
            19080
            (rawData.ToJsonString())
            "[]"
            """{"Version":"3.7.16"}"""

    let sandboxConnection () =
        let address = Environment.GetEnvironmentVariable("KEROOSHA_TRAEFIK_SANDBOX_ADDRESS")
        if String.IsNullOrWhiteSpace(address) then
            invalidOp "Set KEROOSHA_TRAEFIK_SANDBOX_ADDRESS to a dedicated disposable host before running the Sandbox integration test."
        let identityFile =
            match Environment.GetEnvironmentVariable("KEROOSHA_TRAEFIK_SANDBOX_IDENTITY") with
            | null
            | "" -> None
            | value -> Some value
        { Address = address
          User = "root"
          Port = 22
          IdentityFile = identityFile }

    let runSandboxSsh (connection: SshConnection) (remoteCommand: string) (input: string option) =
        let startInfo = ProcessStartInfo("ssh")
        startInfo.UseShellExecute <- false
        startInfo.RedirectStandardInput <- true
        startInfo.RedirectStandardOutput <- true
        startInfo.RedirectStandardError <- true
        startInfo.CreateNoWindow <- true
        for argument in [ "-T"; "-o"; "BatchMode=yes"; "-o"; "StrictHostKeyChecking=yes"; "-o"; "ConnectTimeout=15"; "-p"; string connection.Port ] do
            startInfo.ArgumentList.Add(argument)
        match connection.IdentityFile with
        | Some path ->
            startInfo.ArgumentList.Add("-i")
            startInfo.ArgumentList.Add(path)
        | None -> ()
        startInfo.ArgumentList.Add(connection.User + "@" + connection.Address)
        startInfo.ArgumentList.Add(remoteCommand)
        use childProcess = new Process(StartInfo = startInfo)
        if not (childProcess.Start()) then invalidOp "Unable to start the SSH client for the Sandbox Traefik test."
        let stdout = childProcess.StandardOutput.ReadToEndAsync()
        let stderr = childProcess.StandardError.ReadToEndAsync()
        match input with
        | Some value -> childProcess.StandardInput.Write(value); childProcess.StandardInput.Flush()
        | None -> ()
        childProcess.StandardInput.Close()
        if not (childProcess.WaitForExit(60000)) then
            childProcess.Kill(true)
            childProcess.WaitForExit()
            invalidOp "Sandbox SSH command timed out."
        let output = stdout.GetAwaiter().GetResult()
        let error = stderr.GetAwaiter().GetResult()
        if childProcess.ExitCode <> 0 then
            invalidOp ("Sandbox SSH command failed: " + error.Trim())
        output

    let sandboxHelper (connection: SshConnection) (request: JsonObject) =
        SshTransport.runHelper
            connection
            "traefik"
            "Sandbox Traefik lifecycle test"
            (request.ToJsonString())
            CancellationToken.None
        |> fun operation -> operation.GetAwaiter().GetResult()

    [<Test>]
    member _.``Traefik archive extraction streams the exact binary and rejects unsafe or malformed members``() =
        // Arrange
        let payload = Encoding.UTF8.GetBytes("traefik-binary-payload")
        let archiveBytes = TraefikArchiveTestData.archive [ "traefik", payload ]

        // Act
        let length, binaryHash, extracted = TraefikArchiveTestData.extract archiveBytes

        // Assert
        Assert.That(length, Is.EqualTo(int64 payload.Length))
        Assert.That(binaryHash, Is.EqualTo(TraefikArchiveTestData.checksum payload))
        Assert.That(extracted, Is.EqualTo(payload :> obj))

        TraefikArchiveTestData.assertInvalidArchive (Encoding.UTF8.GetBytes("not a gzip tar archive"))
        TraefikArchiveTestData.assertInvalidArchive (TraefikArchiveTestData.archive [ "traefik", payload; "traefik", payload ])
        TraefikArchiveTestData.assertInvalidArchive (TraefikArchiveTestData.archive [ "../escape", payload; "traefik", payload ])

    [<Test>]
    member _.``Traefik archive extraction rejects an oversized declared binary before reading it``() =
        // Arrange
        let archiveBytes =
            TraefikArchiveTestData.archiveWithDeclaredBinaryLength (512L * 1024L * 1024L + 1L)

        // Act and Assert
        TraefikArchiveTestData.assertInvalidArchive archiveBytes

    [<Test>]
    member _.``Traefik archive streaming enforces compressed size and checksum including truncation``() =
        // Arrange
        let archiveBytes = TraefikArchiveTestData.archive [ "traefik", Encoding.UTF8.GetBytes("binary") ]
        let expected = TraefikArchiveTestData.checksum archiveBytes
        let truncated = Array.take (archiveBytes.Length - 4) archiveBytes
        let tooLarge = Array.init 9 (fun index -> byte index)

        let copyFailure (bytes: byte[]) (limit: int64) (checksum: string) =
            TestDelegate(fun () ->
                use source = new MemoryStream(bytes, false)
                use destination = new MemoryStream()
                use timeout = new CancellationTokenSource()
                Traefik.copyVerifiedArchive source destination limit checksum timeout
                |> fun operation -> operation.GetAwaiter().GetResult()
                |> ignore)

        // Act
        let truncatedFailure = copyFailure truncated (int64 archiveBytes.Length) expected
        let oversizedFailure = copyFailure tooLarge 8L (TraefikArchiveTestData.checksum tooLarge)
        let checksumFailure = copyFailure archiveBytes (int64 archiveBytes.Length) (String.replicate 64 "0")

        // Assert
        Assert.Throws<Traefik.BackendError>(truncatedFailure) |> ignore
        Assert.Throws<Traefik.BackendError>(oversizedFailure) |> ignore
        Assert.Throws<Traefik.BackendError>(checksumFailure) |> ignore

    [<Test>]
    member _.``Rendering keeps the admin API loopback and ACME state persistent``() =
        // Arrange
        use request = JsonDocument.Parse("""{
          "operation":"apply",
          "ownerId":"unit-test-traefik",
          "entryPoints":{"web":80},
          "resolvers":{"le":{"email":"ops@example.test","httpChallengeEntryPoint":"web","caServer":"http://localhost:14000/dir"}},
          "routers":{"site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"acme","name":"le"}}},
          "certificates":{},
          "adminPort":19080
        }""")

        // Act
        let staticText = Traefik.renderStaticConfig request.RootElement paths "127.0.0.1"
        let dynamicText = Traefik.renderDynamicConfig request.RootElement paths
        use staticConfig = JsonDocument.Parse(staticText)
        use dynamicConfig = JsonDocument.Parse(dynamicText)

        // Assert
        Assert.That(staticConfig.RootElement.GetProperty("entryPoints").GetProperty("web").GetProperty("address").GetString(), Is.EqualTo("127.0.0.1:80"))
        Assert.That(staticConfig.RootElement.GetProperty("entryPoints").GetProperty("keroosha-admin").GetProperty("address").GetString(), Is.EqualTo("127.0.0.1:19080"))
        Assert.That(staticConfig.RootElement.GetProperty("api").GetProperty("dashboard").GetBoolean(), Is.True)
        Assert.That(staticConfig.RootElement.GetProperty("providers").GetProperty("file").GetProperty("directory").GetString(), Is.EqualTo(paths.DynamicDir))
        let acme = staticConfig.RootElement.GetProperty("certificatesResolvers").GetProperty("le").GetProperty("acme")
        Assert.That(acme.GetProperty("caServer").GetString(), Is.EqualTo("http://localhost:14000/dir"))
        Assert.That(acme.GetProperty("httpChallenge").GetProperty("entryPoint").GetString(), Is.EqualTo("web"))
        Assert.That(acme.GetProperty("storage").GetString(), Does.StartWith(paths.StateDir + string Path.DirectorySeparatorChar))
        let router = dynamicConfig.RootElement.GetProperty("http").GetProperty("routers").GetProperty("site")
        Assert.That(router.GetProperty("tls").GetProperty("certResolver").GetString(), Is.EqualTo("le"))
        let serviceName = "keroosha-backend-" + digest "http://127.0.0.1:9000"
        Assert.That(router.GetProperty("service").GetString(), Is.EqualTo(serviceName))
        let services = dynamicConfig.RootElement.GetProperty("http").GetProperty("services")
        let service = services.GetProperty(serviceName)
        let loadBalancer = service.GetProperty("loadBalancer")
        let servers = loadBalancer.GetProperty("servers")
        let firstServer = servers[0]
        let actualUrl = firstServer.GetProperty("url").GetString()
        Assert.That(actualUrl, Is.EqualTo("http://127.0.0.1:9000"))


    [<Test>]
    member _.``ACME resolver omits an unset contact email``() =
        use request =
            JsonDocument.Parse("""{
              "operation":"apply",
              "ownerId":"unit-test-traefik",
              "entryPoints":{"web":80},
              "resolvers":{"le":{"httpChallengeEntryPoint":"web","caServer":"http://localhost:14000/dir"}},
              "routers":{},
              "certificates":{},
              "adminPort":19080
            }""")
        use staticConfig = JsonDocument.Parse(Traefik.renderStaticConfig request.RootElement paths "127.0.0.1")
        let acme = staticConfig.RootElement.GetProperty("certificatesResolvers").GetProperty("le").GetProperty("acme")
        Assert.That(acme.EnumerateObject() |> Seq.exists (fun property -> property.Name = "email"), Is.False)
        Assert.That(acme.GetProperty("httpChallenge").GetProperty("entryPoint").GetString(), Is.EqualTo "web")
    [<Test>]
    member _.``Host rules canonicalize IPv6 and IDN names``() =
        // Arrange
        use ipv6Request = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},
          "routers":{"ipv6":{"host":"2001:0db8:0:0:0:0:0:1","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"none","name":""}}},
          "certificates":{},"adminPort":19080
        }""")
        use idnRequest = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},
          "routers":{"idn":{"host":"пример.рф","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"none","name":""}}},
          "certificates":{},"adminPort":19080
        }""")

        // Act
        use ipv6Dynamic = JsonDocument.Parse(Traefik.renderDynamicConfig ipv6Request.RootElement paths)
        use idnDynamic = JsonDocument.Parse(Traefik.renderDynamicConfig idnRequest.RootElement paths)

        // Assert
        Assert.That(ipv6Dynamic.RootElement.GetProperty("http").GetProperty("routers").GetProperty("ipv6").GetProperty("rule").GetString(), Is.EqualTo("Host(`[2001:db8::1]`)"))
        Assert.That(idnDynamic.RootElement.GetProperty("http").GetProperty("routers").GetProperty("idn").GetProperty("rule").GetString(), Is.EqualTo("Host(`xn--e1afmkfd.xn--p1ai`)"))

    [<Test>]
    member _.``Native excluded path subtree rules separate exact and descendant paths and reject invalid request values``() =
        let requestJson (excludedPathSubtree: string option) =
            let subtreeProperty =
                match excludedPathSubtree with
                | Some rawJson -> ",\"excludedPathSubtree\":" + rawJson
                | None -> ""
            """{"operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},"routers":{"site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"none","name":""}"""
            + subtreeProperty
            + """}},"certificates":{},"adminPort":19080}"""

        let renderRule excludedPathSubtree =
            use request = JsonDocument.Parse(requestJson excludedPathSubtree)
            use dynamicConfig = JsonDocument.Parse(Traefik.renderDynamicConfig request.RootElement paths)
            dynamicConfig.RootElement.GetProperty("http").GetProperty("routers").GetProperty("site").GetProperty("rule").GetString()

        Assert.That(renderRule None, Is.EqualTo("Host(`site.example.test`)"))
        Assert.That(
            renderRule (Some "\"/admin\""),
            Is.EqualTo("Host(`site.example.test`) && !PathRegexp(`^(/|%2[fF])+admin($|/|%2[fF])`)"))

        for invalidValue in
            [ "17"; "true"; "null"; "[]"; "\"admin\""; "\"/\""; "\"/admin/\""; "\"/admin//\"";
              "\"/admin/../secret\""; "\"/admin?x\""; "\"/admin`\"" ] do
            let failure = TestDelegate(fun () -> renderRule (Some invalidValue) |> ignore)
            Assert.Throws<Traefik.BackendError>(failure) |> ignore

    [<Test>]
    member _.``Validation rejects unsafe names and admin port collisions``() =
        // Arrange
        use unsafeName = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},
          "routers":{"../site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"none","name":""}}},
          "certificates":{},"adminPort":19080
        }""")
        use collision = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},"routers":{},"certificates":{},"adminPort":31080
        }""")
        let proxyDestinationFailure (backend: string) =
            let requestNode =
                JsonNode.Parse("""{
                  "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},
                  "routers":{"site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"none","name":""}}},
                  "certificates":{},"adminPort":19080
                }""") :?> JsonObject
            let router = (requestNode["routers"] :?> JsonObject)["site"] :?> JsonObject
            router["backend"] <- JsonValue.Create(backend)
            use request = JsonDocument.Parse(requestNode.ToJsonString())
            Traefik.renderDynamicConfig request.RootElement paths |> ignore
        let proxyFailures =
            [ "http://admin-alias.example.test:19080"; "https://127.0.0.1:19080" ]
            |> List.map (fun backend -> TestDelegate(fun () -> proxyDestinationFailure backend))

        // Act
        let unsafeFailure = TestDelegate(fun () -> Traefik.renderDynamicConfig unsafeName.RootElement paths |> ignore)
        let collisionFailure = TestDelegate(fun () -> Traefik.renderDynamicConfig collision.RootElement paths |> ignore)

        // Assert
        Assert.Throws<Traefik.BackendError>(unsafeFailure) |> ignore
        Assert.Throws<Traefik.BackendError>(collisionFailure) |> ignore
        for proxyFailure in proxyFailures do
            Assert.Throws<Traefik.BackendError>(proxyFailure) |> ignore

    [<Test>]
    member _.``Dynamic configuration contains versioned certificate paths but never key material``() =
        // Arrange
        let certificate = TestSupport.createValidCertificateFixture "site.example.test" [ "site.example.test" ]
        let certificateNode = JsonObject()
        certificateNode["certificatePem"] <- JsonValue.Create(certificate.LeafCertificatePem)
        certificateNode["privateKeyPem"] <- JsonValue.Create(certificate.PrivateKeyPem)
        certificateNode["fingerprint"] <- JsonValue.Create(certificate.Fingerprint)
        let certificates = JsonObject()
        certificates["site-cert"] <- certificateNode
        let tls = JsonObject()
        tls["kind"] <- JsonValue.Create("provided")
        tls["name"] <- JsonValue.Create("site-cert")
        let router = JsonObject()
        router["host"] <- JsonValue.Create("site.example.test")
        router["entryPoint"] <- JsonValue.Create("web")
        router["backend"] <- JsonValue.Create("http://127.0.0.1:9000")
        router["tls"] <- tls
        let routers = JsonObject()
        routers["site"] <- router
        let entryPoints = JsonObject()
        entryPoints["web"] <- JsonValue.Create(443)
        let requestNode = JsonObject()
        requestNode["operation"] <- JsonValue.Create("apply")
        requestNode["ownerId"] <- JsonValue.Create("unit-test-traefik")
        requestNode["entryPoints"] <- entryPoints
        requestNode["resolvers"] <- JsonObject()
        requestNode["routers"] <- routers
        requestNode["certificates"] <- certificates
        requestNode["adminPort"] <- JsonValue.Create(19080)
        use request = JsonDocument.Parse(requestNode.ToJsonString())

        // Act
        let dynamicText = Traefik.renderDynamicConfig request.RootElement paths
        use dynamicConfig = JsonDocument.Parse(dynamicText)
        let material = dynamicConfig.RootElement.GetProperty("tls").GetProperty("certificates")[0]

        // Assert
        Assert.That(material.GetProperty("certFile").GetString(), Does.EndWith(".crt"))
        Assert.That(material.GetProperty("keyFile").GetString(), Does.EndWith(".key"))
        Assert.That(dynamicText, Does.Not.Contain(certificate.PrivateKeyPem))
        Assert.That(Traefik.renderSystemdUnit paths, Does.Contain("User=keroosha-traefik\nGroup=keroosha-traefik"))

    [<Test>]
    member _.``API comparison accepts Traefik provider suffixes and default TLS normalization``() =
        // Arrange
        use request = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},
          "resolvers":{"le":{"email":"ops@example.test","httpChallengeEntryPoint":"web"}},
          "routers":{"site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","excludedPathSubtree":"/admin","tls":{"kind":"acme","name":"le"}}},
          "certificates":{},"adminPort":19080
        }""")
        let dynamicBytes = Encoding.UTF8.GetBytes(Traefik.renderDynamicConfig request.RootElement paths)
        let serviceName = "keroosha-backend-" + digest "http://127.0.0.1:9000"
        use routers = JsonDocument.Parse($"""[
          {{"name":"keroosha-admin@file","provider":"file","rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000,"status":"enabled","middlewares":[]}},
          {{"name":"site@file","provider":"file","rule":"Host(`site.example.test`) && !PathRegexp(`^(/|%%2[fF])+admin($|/|%%2[fF])`)","entryPoints":["web"],"service":"{serviceName}","status":"enabled","middlewares":[],"tls":{{"certResolver":"le","options":"default"}}}}
        ]""")
        use services = JsonDocument.Parse($"""[
          {{"name":"{serviceName}@file","provider":"file","status":"enabled","type":"loadbalancer","loadBalancer":{{"servers":[{{"url":"http://127.0.0.1:9000"}}]}}}}
        ]""")
        use middlewares = JsonDocument.Parse("[]")
        let api = apiConfigurationFromArrays routers.RootElement services.RootElement middlewares.RootElement

        // Act
        let matches = Traefik.apiMatchesDynamic (Some api) (Some dynamicBytes)

        // Assert
        Assert.That(matches, Is.True)

        use wrongPassHostService = JsonDocument.Parse($"""[{{"name":"{serviceName}@file","status":"enabled","type":"loadbalancer","loadBalancer":{{"servers":[{{"url":"http://127.0.0.1:9000"}}],"passHostHeader":false}}}}]""")
        let wrongPassHost = apiConfigurationFromArrays routers.RootElement wrongPassHostService.RootElement middlewares.RootElement
        Assert.That(Traefik.apiMatchesDynamic (Some wrongPassHost) (Some dynamicBytes), Is.False)

    [<Test>]
    member _.``API comparison matches HTTP TCP and UDP rawdata resources and verifies static binds``() =
        let dynamic = """{
          "http":{"routers":{"keroosha-admin":{"rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000}}},
          "tcp":{"routers":{"stream":{"rule":"HostSNI(`*`)","entryPoints":["tcp"],"service":"stream","tls":{"passthrough":true}}},"services":{"stream":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9001"}]}}}},
          "udp":{"routers":{"datagrams":{"entryPoints":["udp"],"service":"datagrams"}},"services":{"datagrams":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9002"}]}}}},
          "tls":{"certificates":[]}
        }"""
        let rawData = """{
          "routers":{"keroosha-admin@file":{"rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000,"status":"enabled"}},
          "services":{},"middlewares":{},
          "tcpRouters":{"stream@file":{"rule":"HostSNI(`*`)","entryPoints":["tcp"],"service":"stream","tls":{"passthrough":true,"options":"default"},"status":"enabled"}},
          "tcpServices":{"stream@file":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9001"}]},"status":"enabled"}},
          "tcpMiddlewares":{},
          "udpRouters":{"datagrams@file":{"entryPoints":["udp"],"service":"datagrams","status":"enabled"}},
          "udpServices":{"datagrams@file":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9002"}]},"status":"enabled"}}
        }"""
        let endpoints = """[
          {"name":"keroosha-admin","address":"127.0.0.1:19080"},
          {"name":"tcp","address":"127.0.0.1:43001"},
          {"name":"udp","address":"127.0.0.1:43002/udp"}
        ]"""
        let api = apiConfigurationFromJson 19080 rawData endpoints """{"Version":"3.7.16"}"""
        let staticData = Encoding.UTF8.GetBytes("""{"entryPoints":{"keroosha-admin":{"address":"127.0.0.1:19080"},"tcp":{"address":"127.0.0.1:43001"},"udp":{"address":"127.0.0.1:43002/udp"}}}""")

        Assert.That(Traefik.apiMatchesRuntime (Some api) (Some staticData) (Some(Encoding.UTF8.GetBytes(dynamic))), Is.True)

        let driftedRawData = rawData.Replace("127.0.0.1:9002", "127.0.0.1:9003", StringComparison.Ordinal)
        let drifted = apiConfigurationFromJson 19080 driftedRawData endpoints """{"Version":"3.7.16"}"""
        Assert.That(Traefik.apiMatchesDynamic (Some drifted) (Some(Encoding.UTF8.GetBytes(dynamic))), Is.False)

        let driftedEndpoints = endpoints.Replace("127.0.0.1:43002/udp", "127.0.0.1:43003/udp", StringComparison.Ordinal)
        let wrongBind = apiConfigurationFromJson 19080 rawData driftedEndpoints """{"Version":"3.7.16"}"""
        Assert.That(Traefik.apiMatchesStatic (Some wrongBind) (Some staticData), Is.False)

        let wrongVersion = apiConfigurationFromJson 19080 rawData endpoints """{"Version":"3.7.15"}"""
        Assert.That(Traefik.apiMatchesRuntime (Some wrongVersion) (Some staticData) (Some(Encoding.UTF8.GetBytes(dynamic))), Is.False)

    [<Test>]
    member _.``UDP withdrawal restarts only when a bound listener loses its final router``() =
        let staticData =
            Encoding.UTF8.GetBytes(
                """{"entryPoints":{"udp-a":{"address":"127.0.0.1:43001/udp"},"udp-b":{"address":"127.0.0.1:43002/udp"}}}""")
        let dynamic (routes: (string * string list) list) (destination: string) (httpRule: string option) =
            let root = JsonObject()
            let udp = JsonObject()
            let routers = JsonObject()
            for name, entryPoints in routes do
                let router = JsonObject()
                let values = JsonArray()
                for entryPoint in entryPoints do values.Add(JsonValue.Create(entryPoint))
                router["entryPoints"] <- values
                router["service"] <- JsonValue.Create("echo")
                routers[name] <- router
            udp["routers"] <- routers
            let services = JsonObject()
            let service = JsonObject()
            let loadBalancer = JsonObject()
            let servers = JsonArray()
            let server = JsonObject()
            server["address"] <- JsonValue.Create(destination)
            servers.Add(server)
            loadBalancer["servers"] <- servers
            service["loadBalancer"] <- loadBalancer
            services["echo"] <- service
            udp["services"] <- services
            root["udp"] <- udp
            match httpRule with
            | Some rule ->
                let http = JsonObject()
                let httpRouters = JsonObject()
                let httpRouter = JsonObject()
                httpRouter["rule"] <- JsonValue.Create(rule)
                httpRouters["site"] <- httpRouter
                http["routers"] <- httpRouters
                root["http"] <- http
            | None -> ()
            Encoding.UTF8.GetBytes(root.ToJsonString())
        let requires previous next =
            Traefik.udpWithdrawalRequiresRestart (Some previous) (Some next) (Some staticData)
        let shared = dynamic [ "first", [ "udp-a" ]; "second", [ "udp-a" ] ] "127.0.0.1:9000" None
        let oneReferenceRemains = dynamic [ "second", [ "udp-a" ] ] "127.0.0.1:9000" None
        let noRoutes = dynamic [] "127.0.0.1:9000" None
        let routeA = dynamic [ "stream", [ "udp-a" ] ] "127.0.0.1:9000" None
        let routeB = dynamic [ "stream", [ "udp-b" ] ] "127.0.0.1:9000" None
        let tcpOnlyStatic =
            Encoding.UTF8.GetBytes("""{"entryPoints":{"web":{"address":"127.0.0.1:8080"}}}""")

        let multipleEndpoints = dynamic [ "stream", [ "udp-a"; "udp-b" ] ] "127.0.0.1:9000" None
        let remainingEndpoint = dynamic [ "stream", [ "udp-b" ] ] "127.0.0.1:9000" None
        Assert.That(
            requires multipleEndpoints remainingEndpoint,
            Is.True,
            "A router leaving one of its entrypoints must clear the old listener handler.")
        Assert.That(requires shared oneReferenceRemains, Is.False, "Removing one of multiple routers must preserve the listener handler.")
        Assert.That(requires shared noRoutes, Is.True, "Removing the final router must restart the still-bound listener.")
        Assert.That(requires routeA routeB, Is.True, "Moving a router must clear the old listener handler.")
        Assert.That(requires routeB routeA, Is.True, "Rollback of a move must clear the candidate listener handler.")
        Assert.That(requires noRoutes routeA, Is.False, "Adding a UDP route must not restart the service.")
        Assert.That(requires routeA noRoutes, Is.True, "Rollback that removes an added route must restart the service.")
        Assert.That(
            requires routeA (dynamic [ "stream", [ "udp-a" ] ] "127.0.0.1:9001" None),
            Is.False,
            "Changing only the UDP service must not restart the service.")
        Assert.That(
            requires
                (dynamic [ "stream", [ "udp-a" ] ] "127.0.0.1:9000" (Some "Host(`old.example.test`)"))
                (dynamic [ "stream", [ "udp-a" ] ] "127.0.0.1:9000" (Some "Host(`new.example.test`)")),
            Is.False,
            "An unrelated HTTP-only route change must not restart the service.")
        Assert.That(requires noRoutes noRoutes, Is.False, "An already-unrouted UDP listener is idle.")
        Assert.That(
            Traefik.udpWithdrawalRequiresRestart (Some routeA) (Some noRoutes) (Some tcpOnlyStatic),
            Is.False,
            "A withdrawn route must not restart Traefik when its listener is no longer bound.")

        let malformedPrevious =
            Encoding.UTF8.GetBytes(
                """{"udp":{"routers":{"broken":{"entryPoints":"udp-a","service":"echo"}},"services":{"echo":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9000"}]}}}}}""")
        Assert.That(
            Traefik.udpWithdrawalRequiresRestart (Some malformedPrevious) (Some noRoutes) (Some staticData),
            Is.True,
            "An ambiguous prior UDP graph must conservatively restart bound UDP listeners.")

    [<Test>]
    member _.``API comparison requires the generation marker for API-masked TLS options``() =
        use request = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},
          "resolvers":{},"routers":{},"certificates":{},"adminPort":19080,
          "configuration":{"dynamic":{"tls":{"options":{"custom":{"minVersion":"VersionTLS13","sniStrict":true}}}}}
        }""")
        let dynamicBytes = Encoding.UTF8.GetBytes(Traefik.renderDynamicConfig request.RootElement paths)
        use dynamic = JsonDocument.Parse(dynamicBytes)
        let admin = dynamic.RootElement.GetProperty("http").GetProperty("routers").GetProperty("keroosha-admin")
        let adminNode = JsonNode.Parse(admin.GetRawText()) :?> JsonObject
        adminNode["status"] <- JsonValue.Create("enabled")
        let routers = JsonObject()
        routers["keroosha-admin@file"] <- adminNode
        let rawData = JsonObject()
        rawData["routers"] <- routers
        rawData["services"] <- JsonObject()
        rawData["middlewares"] <- JsonObject()
        rawData["tcpRouters"] <- JsonObject()
        rawData["tcpServices"] <- JsonObject()
        rawData["tcpMiddlewares"] <- JsonObject()
        rawData["udpRouters"] <- JsonObject()
        rawData["udpServices"] <- JsonObject()
        let api = apiConfigurationFromJson 19080 (rawData.ToJsonString()) "[]" """{"Version":"3.7.16"}"""

        Assert.That(Traefik.apiMatchesDynamic (Some api) (Some dynamicBytes), Is.True)

        let changedBytes =
            Encoding.UTF8.GetString(dynamicBytes)
                .Replace("VersionTLS13", "VersionTLS12", StringComparison.Ordinal)
                |> Encoding.UTF8.GetBytes
        Assert.That(Traefik.apiMatchesDynamic (Some api) (Some changedBytes), Is.False)

    [<Test>]
    member _.``API comparison rejects a suffixed router service identifier``() =
        // Arrange
        use request = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},
          "routers":{"site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"none","name":""}}},
          "certificates":{},"adminPort":19080
        }""")
        let dynamicBytes = Encoding.UTF8.GetBytes(Traefik.renderDynamicConfig request.RootElement paths)
        let serviceName = "keroosha-backend-" + digest "http://127.0.0.1:9000"
        use routers = JsonDocument.Parse($"""[
          {{"name":"keroosha-admin@file","rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000,"status":"enabled","middlewares":[]}},
          {{"name":"site@file","rule":"Host(`site.example.test`)","entryPoints":["web"],"service":"{serviceName}@file","status":"enabled","middlewares":[]}}
        ]""")
        use services = JsonDocument.Parse($"""[{{"name":"{serviceName}@file","status":"enabled","type":"loadbalancer","loadBalancer":{{"servers":[{{"url":"http://127.0.0.1:9000"}}]}}}}]""")
        use middlewares = JsonDocument.Parse("[]")
        let api = apiConfigurationFromArrays routers.RootElement services.RootElement middlewares.RootElement

        // Act
        let matches = Traefik.apiMatchesDynamic (Some api) (Some dynamicBytes)

        // Assert
        Assert.That(matches, Is.False)

    [<Test>]
    member _.``Redirect renderer uses a deterministic noop route and preserves raw path and query``() =
        // Arrange
        let origin = "HTTPS://DESTINATION.TEST:443"
        let route = JsonObject()
        route["host"] <- JsonValue.Create("redirect.example.test")
        route["entryPoint"] <- JsonValue.Create("web")
        let redirect = JsonObject()
        redirect["kind"] <- JsonValue.Create("permanentToOrigin")
        redirect["origin"] <- JsonValue.Create(origin)
        route["redirect"] <- redirect
        let tls = JsonObject()
        tls["kind"] <- JsonValue.Create("acme")
        tls["name"] <- JsonValue.Create("le")
        route["tls"] <- tls
        let routers = JsonObject()
        routers["site"] <- route
        let request = JsonObject()
        request["operation"] <- JsonValue.Create("apply")
        request["ownerId"] <- JsonValue.Create("unit-test-traefik")
        let entryPoints = JsonObject()
        entryPoints["web"] <- JsonValue.Create(31080)
        request["entryPoints"] <- entryPoints
        let resolver = JsonObject()
        resolver["email"] <- JsonValue.Create("ops@example.test")
        resolver["httpChallengeEntryPoint"] <- JsonValue.Create("web")
        let resolvers = JsonObject()
        resolvers["le"] <- resolver
        request["resolvers"] <- resolvers
        request["routers"] <- routers
        request["certificates"] <- JsonObject()
        request["adminPort"] <- JsonValue.Create(19080)
        use requestDocument = JsonDocument.Parse(request.ToJsonString())
        let dynamicText = Traefik.renderDynamicConfig requestDocument.RootElement paths
        use dynamic = JsonDocument.Parse(dynamicText)
        let http = dynamic.RootElement.GetProperty("http")
        let renderedRoute = http.GetProperty("routers").GetProperty("site")
        let middlewareNames = renderedRoute.GetProperty("middlewares")
        let middlewareName = middlewareNames[0].GetString()
        let middleware = http.GetProperty("middlewares").GetProperty(middlewareName).GetProperty("redirectRegex")
        let regex = middleware.GetProperty("regex").GetString()
        let replacement = middleware.GetProperty("replacement").GetString()
        let canonicalOrigin = Uri(origin, UriKind.Absolute).GetLeftPart(UriPartial.Authority)

        // Act
        let renderedAgain = Traefik.renderDynamicConfig requestDocument.RootElement paths
        let preservedSuffixes =
            [ "/a%2Fb/%25?empty=&repeat=a+b&repeat=two%2Fwords"
              "/?next=https%3A%2F%2Felsewhere.test%2Fa%3Fx%3D1" ]
            |> List.map (fun suffix ->
                let requestUrl = "http://redirect.example.test" + suffix
                System.Text.RegularExpressions.Regex.Replace(requestUrl, regex, replacement), canonicalOrigin + suffix)

        // Assert
        Assert.That(renderedAgain, Is.EqualTo(dynamicText))
        Assert.That(renderedRoute.GetProperty("service").GetString(), Is.EqualTo("noop@internal"))
        Assert.That(renderedRoute.GetProperty("tls").GetProperty("certResolver").GetString(), Is.EqualTo("le"))
        Assert.That(http.EnumerateObject() |> Seq.exists (fun property -> property.Name = "services"), Is.False)
        Assert.That(middlewareNames.GetArrayLength(), Is.EqualTo(1))
        Assert.That(System.Text.RegularExpressions.Regex.IsMatch(middlewareNames[0].GetString(), "^keroosha-redirect-[0-9a-f]{64}$"), Is.True)
        Assert.That(middleware.GetProperty("permanent").GetBoolean(), Is.True)
        Assert.That(replacement, Is.EqualTo(canonicalOrigin + "${1}"))
        for actual, expected in preservedSuffixes do
            Assert.That(actual, Is.EqualTo(expected))

    [<Test>]
    member _.``Redirect validation rejects non-origin values and requires exactly one target``() =
        // Arrange
        let renderTarget (backend: string option) (redirectOrigin: string option) =
            let route = JsonObject()
            route["host"] <- JsonValue.Create("redirect.example.test")
            route["entryPoint"] <- JsonValue.Create("web")
            let tls = JsonObject()
            tls["kind"] <- JsonValue.Create("none")
            tls["name"] <- JsonValue.Create("")
            route["tls"] <- tls
            match backend with
            | Some value -> route["backend"] <- JsonValue.Create(value)
            | None -> ()
            match redirectOrigin with
            | Some value ->
                let redirect = JsonObject()
                redirect["kind"] <- JsonValue.Create("permanentToOrigin")
                redirect["origin"] <- JsonValue.Create(value)
                route["redirect"] <- redirect
            | None -> ()
            let routers = JsonObject()
            routers["site"] <- route
            let request = JsonObject()
            request["operation"] <- JsonValue.Create("apply")
            request["ownerId"] <- JsonValue.Create("unit-test-traefik")
            let entryPoints = JsonObject()
            entryPoints["web"] <- JsonValue.Create(31080)
            request["entryPoints"] <- entryPoints
            request["resolvers"] <- JsonObject()
            request["routers"] <- routers
            request["certificates"] <- JsonObject()
            request["adminPort"] <- JsonValue.Create(19080)
            use document = JsonDocument.Parse(request.ToJsonString())
            Traefik.renderDynamicConfig document.RootElement paths |> ignore
        let invalidOrigins =
            [ ""; "ftp://target.example.test"; "https://"; "https://target.example.test/path"
              "https://target.example.test/"; "https://user@target.example.test"
              "https://target.example.test?"; "https://target.example.test#"
              "https://target.example.test?x=1"; "https://target.example.test#fragment"
              "https://target.example.test\\path"; "https://target.example.test "
              "https://target.example.test\t" ]

        // Act
        let invalidFailures =
            invalidOrigins
            |> List.map (fun origin -> TestDelegate(fun () -> renderTarget None (Some origin)))
        let bothTargetsFailure = TestDelegate(fun () -> renderTarget (Some "http://127.0.0.1:9000") (Some "https://target.example.test"))
        let noTargetFailure = TestDelegate(fun () -> renderTarget None None)

        // Assert
        for failure in invalidFailures do
            Assert.Throws<Traefik.BackendError>(failure) |> ignore
        Assert.Throws<Traefik.BackendError>(bothTargetsFailure) |> ignore
        Assert.Throws<Traefik.BackendError>(noTargetFailure) |> ignore

    [<Test>]
    member _.``API comparison detects redirect middleware config and route association drift``() =
        // Arrange
        use request = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},
          "routers":{"site":{"host":"redirect.example.test","entryPoint":"web","redirect":{"kind":"permanentToOrigin","origin":"https://destination.example.test"},"tls":{"kind":"none","name":""}}},
          "certificates":{},"adminPort":19080
        }""")
        let dynamicBytes = Encoding.UTF8.GetBytes(Traefik.renderDynamicConfig request.RootElement paths)
        let middlewareName = "keroosha-redirect-" + digest "site\nhttps://destination.example.test"
        let regex = "^https?://[^/?#]+(.*)$"
        let replacement = "https://destination.example.test${1}"
        let makeRouter (name: string) (rule: string) (entryPoint: string) (service: string) (middlewareNames: string list) =
            let router = JsonObject()
            router["name"] <- JsonValue.Create(name)
            router["provider"] <- JsonValue.Create("file")
            router["status"] <- JsonValue.Create("enabled")
            router["rule"] <- JsonValue.Create(rule)
            let entryPoints = JsonArray()
            entryPoints.Add(JsonValue.Create(entryPoint))
            router["entryPoints"] <- entryPoints
            router["service"] <- JsonValue.Create(service)
            let middlewares = JsonArray()
            for middlewareName in middlewareNames do middlewares.Add(JsonValue.Create(middlewareName))
            router["middlewares"] <- middlewares
            router
        let buildApi (includeMiddleware: bool) (actualReplacement: string) (actualPermanent: bool option) (routeAssociation: bool) (middlewareUsers: string[]) : Traefik.ApiConfiguration =
            let routers = JsonArray()
            let adminRouter = makeRouter "keroosha-admin@file" "PathPrefix(`/api`) || PathPrefix(`/dashboard`)" "keroosha-admin" "api@internal" []
            adminRouter["priority"] <- JsonValue.Create(1000000)
            routers.Add(adminRouter)
            let routeMiddlewares = if routeAssociation then [ middlewareName + "@file" ] else []
            routers.Add(makeRouter "site@file" "Host(`redirect.example.test`)" "web" "noop@internal" routeMiddlewares)
            let middlewares = JsonArray()
            if includeMiddleware then
                let middleware = JsonObject()
                middleware["name"] <- JsonValue.Create(middlewareName + "@file")
                middleware["provider"] <- JsonValue.Create("file")
                middleware["status"] <- JsonValue.Create("enabled")
                middleware["type"] <- JsonValue.Create("RedirectRegex")
                let usedBy = JsonArray()
                for user in middlewareUsers do usedBy.Add(JsonValue.Create(user))
                middleware["usedBy"] <- usedBy
                let redirectRegex = JsonObject()
                redirectRegex["regex"] <- JsonValue.Create(regex)
                redirectRegex["replacement"] <- JsonValue.Create(actualReplacement)
                match actualPermanent with
                | Some value -> redirectRegex["permanent"] <- JsonValue.Create(value)
                | None -> ()
                middleware["redirectRegex"] <- redirectRegex
                middlewares.Add(middleware)
            use routerDocument = JsonDocument.Parse(routers.ToJsonString())
            use serviceDocument = JsonDocument.Parse("[]")
            use middlewareDocument = JsonDocument.Parse(middlewares.ToJsonString())
            apiConfigurationFromArrays routerDocument.RootElement serviceDocument.RootElement middlewareDocument.RootElement

        // Act
        let correct = buildApi true replacement (Some true) true [| "site@file" |]
        let missingMiddleware = buildApi false replacement (Some true) true [| "site@file" |]
        let tamperedMiddleware = buildApi true (replacement + "/tampered") (Some true) true [| "site@file" |]
        let falsePermanent = buildApi true replacement (Some false) true [| "site@file" |]
        let missingPermanent = buildApi true replacement None true [| "site@file" |]
        let missingRouteAssociation = buildApi true replacement (Some true) false [| "site@file" |]
        let wrongMiddlewareUser = buildApi true replacement (Some true) true [| "other@file" |]

        // Assert
        Assert.That(Traefik.apiMatchesDynamic (Some correct) (Some dynamicBytes), Is.True)
        for drifted in [ missingMiddleware; tamperedMiddleware; falsePermanent; missingPermanent; missingRouteAssociation; wrongMiddlewareUser ] do
            Assert.That(Traefik.apiMatchesDynamic (Some drifted) (Some dynamicBytes), Is.False)

    [<Test>]
    member _.``ACME certificate lookup is resolver-keyed and honors the host clock``() =
        // Arrange
        use temporary = new TemporaryDirectory("traefik-acme-")
        let now = DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero)
        let valid = TestSupport.createCertificateFixture "site.example.test" [ "site.example.test" ] (now.AddDays(-1.0)) (now.AddDays(30.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let expired = TestSupport.createCertificateFixture "site.example.test" [ "site.example.test" ] (now.AddDays(-30.0)) (now.AddDays(-1.0)) [ "1.3.6.1.5.5.7.3.1" ]
        Directory.CreateDirectory(temporary.Path) |> ignore
        let storagePath = Path.Combine(temporary.Path, "acme-" + digest "le" + ".json")
        let writeStorage (certificatePem: string) =
            let encoded = Convert.ToBase64String(Encoding.ASCII.GetBytes(certificatePem))
            let domain = JsonObject()
            domain["main"] <- JsonValue.Create("site.example.test")
            domain["sans"] <- JsonArray()
            let entry = JsonObject()
            entry["domain"] <- domain
            entry["certificate"] <- JsonValue.Create(encoded)
            let certificates = JsonArray()
            certificates.Add(entry)
            let resolver = JsonObject()
            resolver["Certificates"] <- certificates
            let storage = JsonObject()
            storage["le"] <- resolver
            File.WriteAllText(storagePath, storage.ToJsonString())
        let paths = { paths with StateDir = temporary.Path }
        let environment = TestSupport.fakeHostEnvironment "/" (fun _ _ _ -> { ExitCode = 0; Stdout = ""; Stderr = "" }) (fun () -> now)
        writeStorage valid.LeafCertificatePem

        // Act
        let validFingerprint = Traefik.acmeCertificateFingerprint environment paths "le" "site.example.test"
        let wrongResolver = Traefik.acmeCertificateFingerprint environment paths "other" "site.example.test"
        writeStorage expired.LeafCertificatePem
        let expiredFingerprint = Traefik.acmeCertificateFingerprint environment paths "le" "site.example.test"

        // Assert
        Assert.That(validFingerprint, Is.EqualTo(Some valid.Fingerprint))
        Assert.That(wrongResolver, Is.EqualTo(None))
        Assert.That(expiredFingerprint, Is.EqualTo(None))

    [<Test>]
    member _.``Protected material rejects permission drift``() =
        // Arrange
        use temporary = new TemporaryDirectory("traefik-protected-")
        let environment = TestSupport.fakeHostEnvironment "/" (fun _ _ _ -> { ExitCode = 0; Stdout = ""; Stderr = "" }) (fun () -> DateTimeOffset.UtcNow)
        let uid = HostEnvironment.system.Run "id" [ "-u" ] None |> fun result -> Int32.Parse(result.Stdout.Trim())
        let gid = HostEnvironment.system.Run "id" [ "-g" ] None |> fun result -> Int32.Parse(result.Stdout.Trim())
        let path = Path.Combine(temporary.Path, "key.pem")
        File.WriteAllText(path, "private material")
        File.SetUnixFileMode(path, enum<UnixFileMode>(0o640))

        // Act
        let material = Traefik.readProtectedMaterial environment path uid gid
        File.SetUnixFileMode(path, enum<UnixFileMode>(0o644))
        let drift = TestDelegate(fun () -> Traefik.readProtectedMaterial environment path uid gid |> ignore)

        // Assert
        Assert.That(material.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes("private material").AsSpan()), Is.True)
        Assert.Throws<Traefik.BackendError>(drift) |> ignore

    [<Test>]
    member _.``Owned directory metadata observation detects mode drift``() =
        // Arrange
        use temporary = new TemporaryDirectory("traefik-mode-")
        let environment = TestSupport.fakeHostEnvironment "/" (fun _ _ _ -> { ExitCode = 0; Stdout = ""; Stderr = "" }) (fun () -> DateTimeOffset.UtcNow)
        let uid = HostEnvironment.system.Run "id" [ "-u" ] None |> fun result -> Int32.Parse(result.Stdout.Trim())
        let gid = HostEnvironment.system.Run "id" [ "-g" ] None |> fun result -> Int32.Parse(result.Stdout.Trim())
        let path = Path.Combine(temporary.Path, "dynamic")
        Directory.CreateDirectory(path) |> ignore
        File.SetUnixFileMode(path, enum<UnixFileMode>(0o750))

        // Act
        let correctlySecured = Traefik.metadataMatches environment path "directory" 0o750 uid gid
        File.SetUnixFileMode(path, enum<UnixFileMode>(0o777))
        let drifted = Traefik.metadataMatches environment path "directory" 0o750 uid gid

        // Assert
        Assert.That(correctlySecured, Is.True)
        Assert.That(drifted, Is.False)

    [<Test>]
    member _.``Unmarked configuration directory is an ownership collision``() =
        // Arrange
        use temporary = new TemporaryDirectory("traefik-unowned-")
        let testPaths: Traefik.RuntimePaths =
            { ConfigDir = Path.Combine(temporary.Path, "config")
              StateDir = Path.Combine(temporary.Path, "state")
              InstallDir = Path.Combine(temporary.Path, "install")
              UnitPath = Path.Combine(temporary.Path, "systemd", "keroosha-traefik.service") }
        Directory.CreateDirectory(testPaths.ConfigDir) |> ignore
        File.WriteAllText(Path.Combine(testPaths.ConfigDir, "unrelated.yml"), "unmanaged")
        let environment = TestSupport.fakeHostEnvironment "/" (fun _ _ _ -> { ExitCode = 0; Stdout = ""; Stderr = "" }) (fun () -> DateTimeOffset.UtcNow)

        // Act
        let failure =
            TestDelegate(fun () -> Traefik.checkLayoutCollisions environment testPaths "unit-test-traefik" |> ignore)

        // Assert
        Assert.Throws<Traefik.BackendError>(failure) |> ignore

    [<Test; Explicit("Runs a real Traefik lifecycle only on the dedicated Sandbox host."); Category("Sandbox")>]
    member _.``Sandbox apply redirect-only transition rollback read and Delete retain ACME storage and prove SNI``() =
        // Arrange
        if Environment.GetEnvironmentVariable("KEROOSHA_RUN_SANDBOX_TRAEFIK_TESTS") <> "1" then
            Assert.Ignore("Set KEROOSHA_RUN_SANDBOX_TRAEFIK_TESTS=1 to run the explicit Sandbox integration test.")
        let connection = sandboxConnection ()
        let ownerId = "keroosha-iac-nunit-traefik-" + Guid.NewGuid().ToString("N")
        TestContext.Progress.WriteLine("Sandbox Traefik test ownerId: " + ownerId)
        let adminPort = RandomNumberGenerator.GetInt32(45000, 50000)
        let webPort = RandomNumberGenerator.GetInt32(30000, 38000)
        let nextWebPort = RandomNumberGenerator.GetInt32(38001, 44000)
        let securePort = RandomNumberGenerator.GetInt32(50001, 60000)
        let certificate = TestSupport.createValidCertificateFixture "sandbox.example.test" [ "sandbox.example.test" ]
        let makeRequest (operation: string) (httpPort: int) (tlsPort: int) (backend: string option) (redirectOrigin: string option) : JsonObject =
            let entryPoints = JsonObject()
            entryPoints["web"] <- JsonValue.Create(httpPort)
            entryPoints["websecure"] <- JsonValue.Create(tlsPort)
            let tls = JsonObject()
            tls["kind"] <- JsonValue.Create("provided")
            tls["name"] <- JsonValue.Create("sandbox-cert")
            let router = JsonObject()
            router["host"] <- JsonValue.Create("sandbox.example.test")
            router["entryPoint"] <- JsonValue.Create("websecure")
            match backend, redirectOrigin with
            | Some value, None -> router["backend"] <- JsonValue.Create(value)
            | None, Some origin ->
                let redirect = JsonObject()
                redirect["kind"] <- JsonValue.Create("permanentToOrigin")
                redirect["origin"] <- JsonValue.Create(origin)
                router["redirect"] <- redirect
            | _ -> invalidOp "Sandbox Traefik route must have exactly one target."
            router["tls"] <- tls
            let routers = JsonObject()
            routers["site"] <- router
            let certificateValue = JsonObject()
            certificateValue["certificatePem"] <- JsonValue.Create(certificate.LeafCertificatePem)
            certificateValue["privateKeyPem"] <- JsonValue.Create(certificate.PrivateKeyPem)
            certificateValue["fingerprint"] <- JsonValue.Create(certificate.Fingerprint)
            let certificates = JsonObject()
            certificates["sandbox-cert"] <- certificateValue
            let request = JsonObject()
            request["operation"] <- JsonValue.Create(operation)
            request["ownerId"] <- JsonValue.Create(ownerId)
            request["entryPoints"] <- entryPoints
            request["resolvers"] <- JsonObject()
            request["routers"] <- routers
            request["certificates"] <- certificates
            request["adminPort"] <- JsonValue.Create(adminPort)
            request
        let applyRequest = makeRequest "apply" webPort securePort (Some "http://127.0.0.1:1") None
        let redirectRequest = makeRequest "apply" webPort securePort None (Some "https://destination.example.test")
        let dynamicUpdate = makeRequest "apply" webPort securePort (Some "http://127.0.0.1:2") None
        let startupUpdate = makeRequest "apply" nextWebPort securePort (Some "http://127.0.0.1:2") None
        let readRequest = makeRequest "read" nextWebPort securePort (Some "http://127.0.0.1:2") None
        let failedUpdate = makeRequest "apply" nextWebPort 22 (Some "http://127.0.0.1:2") None
        let deleteRequest = JsonObject()
        deleteRequest["operation"] <- JsonValue.Create("delete")
        deleteRequest["ownerId"] <- JsonValue.Create(ownerId)
        let resolverName = "sandbox-nunit-" + Guid.NewGuid().ToString("N")
        let resolverHash = digest resolverName
        let acmeName = "acme-" + resolverHash + ".json"
        let acmePath = "/var/lib/keroosha-traefik/" + acmeName
        let acmeResolver = JsonObject()
        acmeResolver["Certificates"] <- JsonArray()
        let acmeStorage = JsonObject()
        acmeStorage[resolverName] <- acmeResolver
        let acmeContents = acmeStorage.ToJsonString()
        let ownerHash = digest ownerId
        let ownershipGuard =
            String.concat "\n" [
                "set -eu"
                "for path in /etc/keroosha-iac/traefik /var/lib/keroosha-traefik /usr/local/libexec/keroosha-iac/traefik /etc/systemd/system/keroosha-traefik.service; do"
                "  if [ -e \"$path\" ] || [ -L \"$path\" ]; then exit 73; fi"
                "done"
                "if getent passwd keroosha-traefik >/dev/null 2>&1 || getent group keroosha-traefik >/dev/null 2>&1; then exit 73; fi"
                "if systemctl is-active --quiet keroosha-traefik.service || systemctl is-enabled --quiet keroosha-traefik.service; then exit 73; fi"
                "echo safe"
            ]
        let cleanupOwnedSandbox =
            String.concat "\n" [
                "set -eu"
                "owner='" + ownerHash + "'"
                "state=/var/lib/keroosha-traefik"
                "acme='" + acmePath + "'"
                "expected='" + acmeContents + "'"
                "for path in /etc/keroosha-iac/traefik /usr/local/libexec/keroosha-iac/traefik /etc/systemd/system/keroosha-traefik.service; do"
                "  if [ -e \"$path\" ] || [ -L \"$path\" ]; then exit 73; fi"
                "done"
                "if systemctl is-active --quiet keroosha-traefik.service || systemctl is-enabled --quiet keroosha-traefik.service; then exit 73; fi"
                "if [ -e \"$state\" ] || [ -L \"$state\" ]; then"
                "  [ -d \"$state\" ] && [ ! -L \"$state\" ] || exit 73"
                "  marker=\"$state/.keroosha-owner\""
                "  [ -f \"$marker\" ] && [ ! -L \"$marker\" ] && [ \"$(cat -- \"$marker\")\" = \"$owner\" ] || exit 73"
                "  if [ -e \"$acme\" ] || [ -L \"$acme\" ]; then"
                "    [ -f \"$acme\" ] && [ ! -L \"$acme\" ] && [ \"$(cat -- \"$acme\")\" = \"$expected\" ] || exit 73"
                "    rm -- \"$acme\""
                "  fi"
                "  [ \"$(find \"$state\" -mindepth 1 -maxdepth 1 -printf '%f\\n')\" = .keroosha-owner ] || exit 73"
                "  rm -- \"$marker\""
                "  rmdir -- \"$state\""
                "fi"
                "account=$(getent passwd keroosha-traefik || true)"
                "group=$(getent group keroosha-traefik || true)"
                "if [ -n \"$account\" ]; then"
                "  uid=$(printf '%s\\n' \"$account\" | cut -d: -f3)"
                "  primary_gid=$(printf '%s\\n' \"$account\" | cut -d: -f4)"
                "  home=$(printf '%s\\n' \"$account\" | cut -d: -f6)"
                "  shell=$(printf '%s\\n' \"$account\" | cut -d: -f7)"
                "  group_gid=$(printf '%s\\n' \"$group\" | cut -d: -f3)"
                "  [ \"$uid\" -ne 0 ] && [ \"$primary_gid\" = \"$group_gid\" ] && [ \"$home\" = /var/lib/keroosha-traefik ] && [ \"$shell\" = /usr/sbin/nologin ] || exit 73"
                "  userdel keroosha-traefik"
                "  if getent group keroosha-traefik >/dev/null 2>&1; then groupdel keroosha-traefik; fi"
                "elif [ -n \"$group\" ]; then"
                "  [ -z \"$(printf '%s\\n' \"$group\" | cut -d: -f4)\" ] || exit 73"
                "  groupdel keroosha-traefik"
                "fi"
                ":"
            ]

        let invoke request =
            let response = sandboxHelper connection request
            use document = JsonDocument.Parse(response)
            document.RootElement.Clone()
        let mainPid () =
            runSandboxSsh connection "systemctl show keroosha-traefik.service --property=MainPID --value" None |> fun value -> value.Trim()

        let guardStatus = runSandboxSsh connection ownershipGuard None
        Assert.That(guardStatus.Trim(), Is.EqualTo("safe"))
        // Act
        let sshListeners = runSandboxSsh connection "ss -H -ltn 'sport = :22'" None
        if String.IsNullOrWhiteSpace(sshListeners) then
            Assert.Ignore("The rollback scenario requires the Sandbox SSH daemon to retain port 22.")
        let mutable cleanupCompleted = false
        try
            let applied = invoke applyRequest
            let initialPid = mainPid ()

            // Assert
            Assert.That(applied.GetProperty("inSync").GetBoolean(), Is.True)
            Assert.That(applied.GetProperty("certificateFingerprints").GetProperty("sandbox-cert").GetString(), Is.EqualTo(certificate.Fingerprint))

            let writeAcme =
                "set -eu; umask 077; temporary=$(mktemp /var/lib/keroosha-traefik/.acme.XXXXXX); trap 'rm -f -- \"$temporary\"' EXIT; cat > \"$temporary\"; chown keroosha-traefik:keroosha-traefik -- \"$temporary\"; chmod 0600 -- \"$temporary\"; mv -f -- \"$temporary\" '" + acmePath + "'; trap - EXIT"
            runSandboxSsh connection writeAcme (Some acmeContents) |> ignore
            let redirectResult = invoke redirectRequest
            Assert.That(redirectResult.GetProperty("inSync").GetBoolean(), Is.True)
            Assert.That(redirectResult.GetProperty("actualConfigHash").GetString(), Is.Not.EqualTo(applied.GetProperty("actualConfigHash").GetString()))
            Assert.That(mainPid (), Is.EqualTo(initialPid), "A redirect-only dynamic update must not restart Traefik.")


            let dynamicResult = invoke dynamicUpdate
            Assert.That(dynamicResult.GetProperty("inSync").GetBoolean(), Is.True)
            Assert.That(dynamicResult.GetProperty("actualConfigHash").GetString(), Is.Not.EqualTo(applied.GetProperty("actualConfigHash").GetString()))
            Assert.That(mainPid (), Is.EqualTo(initialPid), "A dynamic-only update must not restart Traefik.")

            let startupResult = invoke startupUpdate
            Assert.That(startupResult.GetProperty("inSync").GetBoolean(), Is.True)
            Assert.That(startupResult.GetProperty("certificateFingerprints").GetProperty("sandbox-cert").GetString(), Is.EqualTo(certificate.Fingerprint))
            Assert.That(mainPid (), Is.Not.EqualTo(initialPid), "An entry-point change must restart Traefik.")
            let stablePid = mainPid ()
            let staticDriftPort = RandomNumberGenerator.GetInt32(60001, 65000)
            let driftStaticConfiguration =
                String.concat "\n" [
                    "set -eu"
                    "static=/etc/keroosha-iac/traefik/static.yml"
                    "backup=$(mktemp /tmp/keroosha-traefik-static.XXXXXX)"
                    "cp -- \"$static\" \"$backup\""
                    "restore() { install -o root -g keroosha-traefik -m 0640 -- \"$backup\" \"$static\"; rm -f -- \"$backup\"; systemctl restart keroosha-traefik.service || true; }"
                    "trap restore EXIT"
                    "temporary=$(mktemp /tmp/keroosha-traefik-static.XXXXXX)"
                    "sed 's/:" + string nextWebPort + "/:" + string staticDriftPort + "/g' \"$backup\" > \"$temporary\""
                    "chown root:keroosha-traefik -- \"$temporary\""
                    "chmod 0640 -- \"$temporary\""
                    "mv -f -- \"$temporary\" \"$static\""
                    "grep -Fq ':" + string staticDriftPort + "' \"$static\""
                    "systemctl restart keroosha-traefik.service"
                    "install -o root -g keroosha-traefik -m 0640 -- \"$backup\" \"$static\""
                    "rm -- \"$backup\""
                    "trap - EXIT"
                ]
            runSandboxSsh connection driftStaticConfiguration None |> ignore
            let driftedPid = mainPid ()
            Assert.That(driftedPid, Is.Not.EqualTo(stablePid), "The external static drift restart should have changed the process.")
            let repairedStatic = invoke startupUpdate
            Assert.That(repairedStatic.GetProperty("inSync").GetBoolean(), Is.True)
            Assert.That(mainPid (), Is.Not.EqualTo(driftedPid), "Apply must restart when live entrypoint binds drift despite matching static file bytes.")

            // Act
            let rollbackAction = TestDelegate(fun () -> sandboxHelper connection failedUpdate |> ignore)

            // Assert
            Assert.Throws<NativeHelperBackendException>(rollbackAction) |> ignore
            let restored = invoke readRequest
            Assert.That(restored.GetProperty("inSync").GetBoolean(), Is.True)
            Assert.That(restored.GetProperty("certificateFingerprints").GetProperty("sandbox-cert").GetString(), Is.EqualTo(certificate.Fingerprint))

            let deletion = invoke deleteRequest
            Assert.That(deletion.ValueKind, Is.EqualTo(JsonValueKind.Object))
            let retained =
                runSandboxSsh
                    connection
                    ("test -f /var/lib/keroosha-traefik/.keroosha-owner && [ \"$(cat -- /var/lib/keroosha-traefik/.keroosha-owner)\" = '" + ownerHash + "' ] && cat -- '" + acmePath + "'")
                    None

            // Assert
            Assert.That(retained, Is.EqualTo(acmeContents))
            runSandboxSsh connection cleanupOwnedSandbox None |> ignore
            let postCleanupGuard = runSandboxSsh connection ownershipGuard None
            Assert.That(postCleanupGuard.Trim(), Is.EqualTo("safe"))
            cleanupCompleted <- true
        finally
            if not cleanupCompleted then
                try
                    sandboxHelper connection deleteRequest |> ignore
                    runSandboxSsh connection cleanupOwnedSandbox None |> ignore
                    runSandboxSsh connection ownershipGuard None |> ignore
                    cleanupCompleted <- true
                with error ->
                    let detail =
                        match error with
                        | :? NativeHelperBackendException -> error.Message
                        | _ -> error.GetType().Name
                    let diagnostic =
                        "Sandbox Traefik cleanup failed for ownerId "
                        + ownerId
                        + " ("
                        + detail
                        + ")."
                    TestContext.Progress.WriteLine(diagnostic)
