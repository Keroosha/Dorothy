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
        let resources isRouter (items: JsonElement) =
            let result = JsonObject()
            for item in items.EnumerateArray() do
                let name = item.GetProperty("name").GetString()
                match JsonNode.Parse(item.GetRawText()) with
                | :? JsonObject as value ->
                    let mutable parentRefs = Unchecked.defaultof<JsonElement>
                    let rootRouter =
                        not (item.TryGetProperty("parentRefs", &parentRefs))
                        || parentRefs.ValueKind = JsonValueKind.Null
                    if isRouter && rootRouter && not (value.ContainsKey("observability")) then
                        let observability = JsonObject()
                        observability["accessLogs"] <- JsonValue.Create(true)
                        observability["metrics"] <- JsonValue.Create(true)
                        observability["tracing"] <- JsonValue.Create(true)
                        observability["traceVerbosity"] <- JsonValue.Create("minimal")
                        value["observability"] <- observability
                    value.Remove("name") |> ignore
                    value.Remove("provider") |> ignore
                    value.Remove("type") |> ignore
                    result[name] <- value
                | _ -> invalidOp "API fixture resource must be an object."
            result
        let rawData = JsonObject()
        rawData["routers"] <- resources true routers
        rawData["services"] <- resources false services
        rawData["middlewares"] <- resources false middlewares
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

    let acceptanceFile path =
        let file = FileInfo(path)
        if not file.Exists || not (String.IsNullOrEmpty(file.LinkTarget)) then
            invalidOp "The sealed acceptance state contains a missing or linked file."
        path

    let verifiedAcceptanceStateDirectory () =
        let stateValue =
            match Environment.GetEnvironmentVariable("DOROTHY_TRAEFIK_ACCEPTANCE_STATE_DIR") with
            | null
            | "" -> invalidOp "Set DOROTHY_TRAEFIK_ACCEPTANCE_STATE_DIR to a fresh prepare.sh state directory."
            | value -> value
        let stateDirectory = Path.GetFullPath(stateValue)
        let tempRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd([| Path.DirectorySeparatorChar |])
        let directoryName = Path.GetFileName(stateDirectory)
        let prefix = "dorothy-traefik-acceptance."
        let suffix = if directoryName.StartsWith(prefix, StringComparison.Ordinal) then directoryName.Substring(prefix.Length) else ""
        let directory = DirectoryInfo(stateDirectory)
        if Path.GetDirectoryName(stateDirectory) <> tempRoot
           || suffix.Length = 0
           || not (suffix |> Seq.forall (fun character -> Char.IsAsciiLetterOrDigit(character)))
           || not directory.Exists
           || not (String.IsNullOrEmpty(directory.LinkTarget)) then
            invalidOp "Refusing to run outside the private sealed acceptance state root."
        if (int (File.GetUnixFileMode(stateDirectory)) &&& 0o077) <> 0 then
            invalidOp "The sealed acceptance state directory is not private."
        let owner = acceptanceFile (Path.Combine(stateDirectory, ".owner"))
        if (FileInfo(owner)).Length > 128L
           || File.ReadAllText(owner).Trim() <> "dorothy-traefik-acceptance-owned-state-v1" then
            invalidOp "The sealed acceptance ownership marker is invalid."
        for filename in [ "handle.env"; "legacy-checkpoint.json"; "legacy-resource-id.txt" ] do
            acceptanceFile (Path.Combine(stateDirectory, filename)) |> ignore
        if Directory.EnumerateFiles(stateDirectory, "candidate-helper-*.sha256", SearchOption.TopDirectoryOnly) |> Seq.isEmpty |> not then
            invalidOp "Refusing to repeat the sealed full acceptance run in a used per-run state directory."
        stateDirectory

    let verifiedCandidateProviderDirectory () =
        let providerValue =
            match Environment.GetEnvironmentVariable("DOROTHY_TRAEFIK_ACCEPTANCE_PROVIDER_DIR") with
            | null
            | "" -> invalidOp "Set DOROTHY_TRAEFIK_ACCEPTANCE_PROVIDER_DIR to the candidate provider directory."
            | value -> value
        let providerDirectory = Path.GetFullPath(providerValue)
        let directory = DirectoryInfo(providerDirectory)
        if not directory.Exists || not (String.IsNullOrEmpty(directory.LinkTarget)) then
            invalidOp "The candidate provider directory is missing or linked."
        for filename in [ "pulumi-resource-keroosha"; "helper/linux-x64/keroosha-iac-helper" ] do
            acceptanceFile (Path.Combine(providerDirectory, filename)) |> ignore
        providerDirectory

    let publicAcceptanceRunner () =
        let rec find (directory: DirectoryInfo) =
            if isNull directory then invalidOp "The public sealed acceptance runner was not found in the source tree."
            let candidate = Path.Combine(directory.FullName, "tests", "Traefik.Acceptance", "run.sh")
            if File.Exists(candidate) then
                acceptanceFile candidate
            else
                match directory.Parent with
                | null -> invalidOp "The public sealed acceptance runner was not found in the source tree."
                | parent -> find parent
        find (DirectoryInfo(AppContext.BaseDirectory))

    let runPublicAcceptance (stateDirectory: string) (providerDirectory: string) =
        let runner = publicAcceptanceRunner ()
        let startInfo = ProcessStartInfo("/usr/bin/bash")
        startInfo.UseShellExecute <- false
        startInfo.RedirectStandardOutput <- true
        startInfo.RedirectStandardError <- true
        startInfo.CreateNoWindow <- true
        startInfo.WorkingDirectory <- Path.GetDirectoryName(runner)
        for name in
            [ "SSH_CONFIG"; "SSH_HOST"; "SSH_PORT"; "SSH_USER"; "GUEST_ROOT"
              "DOROTHY_ACCEPTANCE_SSH_CONFIG"; "DOROTHY_ACCEPTANCE_SSH_PORT"
              "UPSTREAM_CA_FILE"; "CLIENT_CA_FILE"; "DNS_TSIG_SECRET_FILE"; "PULUMI_PASSPHRASE_FILE"
              "PULUMI_CONFIG_PASSPHRASE"; "PULUMI_ACCESS_TOKEN"; "BASH_ENV"; "ENV"
              "HTTP_PROXY"; "HTTPS_PROXY"; "ALL_PROXY"; "http_proxy"; "https_proxy"; "all_proxy" ] do
            startInfo.Environment.Remove(name) |> ignore
        for argument in [ runner; stateDirectory; providerDirectory; "full" ] do
            startInfo.ArgumentList.Add(argument)
        use child = new Process(StartInfo = startInfo)
        if not (child.Start()) then invalidOp "Could not start the public sealed QEMU acceptance runner."
        let standardOutput = child.StandardOutput.BaseStream.CopyToAsync(Stream.Null)
        let standardError = child.StandardError.BaseStream.CopyToAsync(Stream.Null)
        child.WaitForExit()
        standardOutput.GetAwaiter().GetResult()
        standardError.GetAwaiter().GetResult()
        if child.ExitCode <> 0 then
            invalidOp "The sealed Traefik acceptance runner failed; inspect its private per-run logs."
        for filename in [ "candidate-helper-full.sha256"; "deleted-checkpoint.json"; "secret-hygiene-metrics.json" ] do
            acceptanceFile (Path.Combine(stateDirectory, filename)) |> ignore

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
        Assert.That(
            acme.GetProperty("storage").GetString(),
            Is.EqualTo(TraefikTlsSettings.acmeStoragePath paths.StateDir "le" "http://localhost:14000/dir")
        )
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
    member _.``OTLP application and access logs derive only the OTLPLogs experimental gate``() =
        let requestFor settings =
            sprintf
                """{"operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},"routers":{},"certificates":{},"adminPort":19080,"configuration":{"static":%s}}"""
                settings
        let render settings =
            use request = JsonDocument.Parse(requestFor settings)
            JsonDocument.Parse(Traefik.renderStaticConfig request.RootElement paths "127.0.0.1")
        let log = """{"log":{"otlp":{"http":{"endpoint":"http://127.0.0.1:4318/v1/logs"}}}}"""
        let accessLog = """{"accessLog":{"otlp":{"http":{"endpoint":"http://127.0.0.1:4318/v1/logs"}}}}"""

        for settings in [ log; accessLog; """{"log":{"otlp":{"http":{"endpoint":"http://127.0.0.1:4318/v1/logs"}}},"accessLog":{"otlp":{"http":{"endpoint":"http://127.0.0.1:4318/v1/logs"}}}}""" ] do
            use rendered = render settings
            let experimental = rendered.RootElement.GetProperty("experimental")
            Assert.That(experimental.GetProperty("otlpLogs").GetBoolean(), Is.True)
            let experimentalNames: string[] =
                experimental.EnumerateObject() |> Seq.map (fun field -> field.Name) |> Seq.toArray
            Assert.That(experimentalNames, Is.EquivalentTo([| "otlpLogs" |]))

        use unrelatedSignals =
            render """{"metrics":{"otlp":{"http":{"endpoint":"http://127.0.0.1:4318/v1/metrics"}}},"tracing":{"otlp":{"http":{"endpoint":"http://127.0.0.1:4318/v1/traces"}}}}"""
        Assert.That(
            unrelatedSignals.RootElement.EnumerateObject() |> Seq.exists (fun field -> field.Name = "experimental"),
            Is.False
        )
    [<Test>]
    member _.``Read renders expired inline CA state but Apply still rejects it``() =
        use key = RSA.Create(2048)
        let request = System.Security.Cryptography.X509Certificates.CertificateRequest("CN=expired read root", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        request.CertificateExtensions.Add(System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, true, 1, true)) |> ignore
        use expiredRoot = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2.0), DateTimeOffset.UtcNow.AddDays(-1.0))
        let configuration = JsonObject()
        let settings = JsonObject()
        let transport = JsonObject()
        let rootCAs = JsonArray()
        rootCAs.Add(JsonValue.Create(expiredRoot.ExportCertificatePem()))
        transport["rootCAs"] <- rootCAs
        settings["serversTransport"] <- transport
        configuration["static"] <- settings
        let makeRequest (operation: string) =
            let request = JsonObject()
            request["operation"] <- JsonValue.Create(operation)
            request["ownerId"] <- JsonValue.Create("unit-test-traefik")
            let entryPoints = JsonObject()
            entryPoints["web"] <- JsonValue.Create(31080)
            request["entryPoints"] <- entryPoints
            request["resolvers"] <- JsonObject()
            request["routers"] <- JsonObject()
            request["certificates"] <- JsonObject()
            request["adminPort"] <- JsonValue.Create(19080)
            request["configuration"] <- configuration.DeepClone()
            request

        use readRequest = JsonDocument.Parse((makeRequest "read").ToJsonString())
        use readStatic = JsonDocument.Parse(Traefik.renderStaticConfig readRequest.RootElement paths "127.0.0.1")
        Assert.That(
            readStatic.RootElement.GetProperty("serversTransport").GetProperty("rootCAs").[0].GetString(),
            Is.EqualTo(expiredRoot.ExportCertificatePem())
        )

        let applyFailure =
            TestDelegate(fun () ->
                use applyRequest = JsonDocument.Parse((makeRequest "apply").ToJsonString())
                Traefik.renderStaticConfig applyRequest.RootElement paths "127.0.0.1" |> ignore)
        Assert.Catch<Exception>(applyFailure) |> ignore

    [<Test>]
    member _.``Legacy HTTP graph lowering preserves exact generated config bytes``() =
        use request =
            JsonDocument.Parse("""{
              "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},"resolvers":{},
              "routers":{"site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"none","name":""}}},
              "certificates":{},"adminPort":19080
            }""")
        let serviceName = "keroosha-backend-" + digest "http://127.0.0.1:9000"
        let expectedTemplate =
            """{
  "http": {
    "routers": {
      "keroosha-admin": {
        "entryPoints": [
          "keroosha-admin"
        ],
        "priority": 1000000,
        "rule": "PathPrefix(`/api`) || PathPrefix(`/dashboard`)",
        "service": "api@internal"
      },
      "site": {
        "entryPoints": [
          "web"
        ],
        "rule": "Host(`site.example.test`)",
        "service": "@SERVICE@"
      }
    },
    "services": {
      "@SERVICE@": {
        "loadBalancer": {
          "servers": [
            {
              "url": "http://127.0.0.1:9000"
            }
          ]
        }
      }
    }
  },
  "tls": {
    "certificates": []
  }
}"""
        let expected = expectedTemplate.Replace("@SERVICE@", serviceName, StringComparison.Ordinal) + "\n"
        let actual = Traefik.renderHistoricalDynamicConfig request.RootElement paths
        let actualBytes = Encoding.UTF8.GetBytes(actual)
        let expectedBytes = Encoding.UTF8.GetBytes(expected)
        Assert.That(actualBytes, Is.EqualTo(expectedBytes :> obj))


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
    member _.``Client-only identities are protected outbound material and never inbound registrations``() =
        let now = DateTimeOffset.UtcNow
        let client =
            TestSupport.createCertificateFixture
                "review-client"
                [ "review-client.example.test" ]
                (now.AddDays(-1.0))
                (now.AddDays(30.0))
                [ "1.3.6.1.5.5.7.3.2" ]

        let certificateNode = JsonObject()
        certificateNode["certificatePem"] <- JsonValue.Create(client.ChainPem)
        certificateNode["privateKeyPem"] <- JsonValue.Create(client.PrivateKeyPem)
        certificateNode["fingerprint"] <- JsonValue.Create(client.Fingerprint)
        certificateNode["usage"] <- JsonValue.Create("client")
        let certificates = JsonObject()
        certificates["review-client"] <- certificateNode

        let certificateReference = JsonObject()
        certificateReference["certificate"] <- JsonValue.Create("review-client")
        let transportCertificates = JsonArray()
        transportCertificates.Add(certificateReference)
        let rootCAs = JsonArray()
        rootCAs.Add(JsonValue.Create(client.RootCertificatePem))
        let transport = JsonObject()
        transport["rootCAs"] <- rootCAs
        transport["certificates"] <- transportCertificates
        let transports = JsonObject()
        transports["verified-upstream"] <- transport
        let http = JsonObject()
        http["serversTransports"] <- transports
        let dynamic = JsonObject()
        dynamic["http"] <- http
        let configuration = JsonObject()
        configuration["dynamic"] <- dynamic

        let requestFor (nativeConfiguration: JsonObject) =
            let requestNode = JsonObject()
            requestNode["operation"] <- JsonValue.Create("apply")
            requestNode["ownerId"] <- JsonValue.Create("unit-test-traefik")
            let entryPoints = JsonObject()
            entryPoints["web"] <- JsonValue.Create(31080)
            requestNode["entryPoints"] <- entryPoints
            requestNode["resolvers"] <- JsonObject()
            requestNode["routers"] <- JsonObject()
            requestNode["certificates"] <- certificates.DeepClone()
            requestNode["adminPort"] <- JsonValue.Create(19080)
            requestNode["configuration"] <- nativeConfiguration.DeepClone()
            JsonDocument.Parse(requestNode.ToJsonString())

        use request = requestFor configuration
        let dynamicText = Traefik.renderDynamicConfig request.RootElement paths
        use dynamicConfig = JsonDocument.Parse(dynamicText)
        let tlsCertificates = dynamicConfig.RootElement.GetProperty("tls").GetProperty("certificates")
        let outbound = dynamicConfig.RootElement.GetProperty("http").GetProperty("serversTransports").GetProperty("verified-upstream").GetProperty("certificates")[0]
        let inboundConfiguration = JsonObject()
        let inboundDynamic = JsonObject()
        let inboundTls = JsonObject()
        let inboundReferences = JsonArray()
        inboundReferences.Add(certificateReference.DeepClone())
        inboundTls["certificates"] <- inboundReferences
        inboundDynamic["tls"] <- inboundTls
        inboundConfiguration["dynamic"] <- inboundDynamic
        use inboundRequest = requestFor inboundConfiguration
        let inboundFailure =
            TestDelegate(fun () -> Traefik.renderDynamicConfig inboundRequest.RootElement paths |> ignore)

        Assert.That(tlsCertificates.GetArrayLength(), Is.EqualTo(0))
        Assert.That(outbound.GetProperty("certFile").GetString(), Does.EndWith(".crt"))
        Assert.That(outbound.GetProperty("keyFile").GetString(), Does.EndWith(".key"))
        Assert.That(dynamicText, Does.Not.Contain(client.PrivateKeyPem))
        Assert.Throws<Traefik.BackendError>(inboundFailure) |> ignore

    [<Test>]
    member _.``API comparison accepts Traefik provider suffixes and default TLS normalization``() =
        // Arrange
        use request = JsonDocument.Parse("""{
          "operation":"apply","ownerId":"unit-test-traefik","entryPoints":{"web":31080},
          "resolvers":{"le":{"email":"ops@example.test","httpChallengeEntryPoint":"web"}},
          "routers":{"site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","excludedPathSubtree":"/admin","tls":{"kind":"acme","name":"le"}}},
          "certificates":{},"adminPort":19080
        }""")
        let dynamicBytes = Encoding.UTF8.GetBytes(Traefik.renderHistoricalDynamicConfig request.RootElement paths)
        let serviceName = "keroosha-backend-" + digest "http://127.0.0.1:9000"
        let siteRule = "Host(`site.example.test`) && !PathRegexp(`^(/|%2[fF])+admin($|/|%2[fF])`)"
        use routers = JsonDocument.Parse($"""[
          {{"name":"keroosha-admin@file","provider":"file","rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000,"status":"enabled","middlewares":[]}},
          {{"name":"site@file","provider":"file","rule":"{siteRule}","entryPoints":["web"],"service":"{serviceName}","priority":{Encoding.UTF8.GetByteCount(siteRule)},"status":"enabled","middlewares":[],"tls":{{"certResolver":"le","options":"default"}}}}
        ]""")
        use services = JsonDocument.Parse($"""[
          {{"name":"{serviceName}@file","provider":"file","status":"enabled","type":"loadbalancer","loadBalancer":{{"servers":[{{"url":"http://127.0.0.1:9000"}}]}},"usedBy":["site@file"]}}
        ]""")
        use middlewares = JsonDocument.Parse("[]")
        let api = apiConfigurationFromArrays routers.RootElement services.RootElement middlewares.RootElement

        // Act
        let matches = Traefik.apiMatchesDynamic (Some api) (Some dynamicBytes)

        // Assert
        Assert.That(matches, Is.True)

        use wrongPassHostService = JsonDocument.Parse($"""[{{"name":"{serviceName}@file","status":"enabled","type":"loadbalancer","loadBalancer":{{"servers":[{{"url":"http://127.0.0.1:9000"}}],"passHostHeader":false}},"usedBy":["site@file"]}}]""")
        let wrongPassHost = apiConfigurationFromArrays routers.RootElement wrongPassHostService.RootElement middlewares.RootElement
        Assert.That(Traefik.apiMatchesDynamic (Some wrongPassHost) (Some dynamicBytes), Is.False)

    [<Test>]
    member _.``API comparison matches HTTP TCP and UDP rawdata resources and verifies static binds``() =
        let dynamic =
            """{
              "http":{
                "routers":{
                  "keroosha-admin":{"rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000},
                  "healthy":{"rule":"Host(`healthy.test`)","entryPoints":["web"],"middlewares":["observe"],"service":"healthy-service"}
                },
                "services":{"healthy-service":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}},
                "middlewares":{"observe":{"addPrefix":{"prefix":"/check"}}}
              },
              "tcp":{
                "routers":{"stream":{"rule":"HostSNI(`*`)","entryPoints":["tcp"],"service":"stream","tls":{"passthrough":true}}},
                "services":{"stream":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9001"}]}}}
              },
              "udp":{
                "routers":{"datagrams":{"entryPoints":["udp"],"service":"datagrams"}},
                "services":{"datagrams":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9002"}]}}}
              },
              "tls":{"certificates":[]}
            }"""
        let rawData =
            """{
              "routers":{
                "keroosha-admin@file":{"rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000,"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled"},
                "healthy@file":{"entryPoints":["web"],"middlewares":["observe@file"],"service":"healthy-service","rule":"Host(`healthy.test`)","priority":20,"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["web"]}
              },
              "services":{
                "api@internal":{"status":"enabled","usedBy":["keroosha-admin@file"]},
                "healthy-service@file":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}],"strategy":"wrr","passHostHeader":true,"responseForwarding":{"flushInterval":"100ms"}},"status":"enabled","type":"loadbalancer","usedBy":["healthy@file"],"serverStatus":{"http://127.0.0.1:9000":"UP"}},
                "dashboard@internal":{"status":"enabled"},
                "noop@internal":{"status":"enabled"}
              },
              "middlewares":{"observe@file":{"addPrefix":{"prefix":"/check"},"status":"enabled","usedBy":["healthy@file"]}},
              "tcpRouters":{"stream@file":{"rule":"HostSNI(`*`)","entryPoints":["tcp"],"service":"stream","priority":-1,"tls":{"passthrough":true,"options":"default"},"status":"enabled","using":["tcp"]}},
              "tcpServices":{"stream@file":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9001"}]},"status":"enabled","usedBy":["stream@file"]}},
              "tcpMiddlewares":{},
              "udpRouters":{"datagrams@file":{"entryPoints":["udp"],"service":"datagrams","status":"enabled","using":["udp"]}},
              "udpServices":{"datagrams@file":{"loadBalancer":{"servers":[{"address":"127.0.0.1:9002"}]},"status":"enabled","usedBy":["datagrams@file"]}}
            }"""
        let apiEntryPoint name address =
            sprintf
                """{"name":"%s","address":"%s","transport":{"lifeCycle":{"graceTimeOut":"10s"},"respondingTimeouts":{"readTimeout":"1m0s","idleTimeout":"3m0s"}},"forwardedHeaders":{},"http":{"sanitizePath":true,"maxHeaderBytes":1048576},"http2":{"maxConcurrentStreams":250,"maxDecoderHeaderTableSize":4096,"maxEncoderHeaderTableSize":4096},"udp":{"timeout":"3s"}}"""
                name
                address
        let endpoints =
            "["
            + String.concat ","
                [ apiEntryPoint "keroosha-admin" "127.0.0.1:19080"
                  apiEntryPoint "web" "127.0.0.1:43000"
                  apiEntryPoint "tcp" "127.0.0.1:43001"
                  apiEntryPoint "udp" "127.0.0.1:43002/udp" ]
            + "]"
        let staticData =
            Encoding.UTF8.GetBytes(
                """{"entryPoints":{"keroosha-admin":{"address":"127.0.0.1:19080"},"web":{"address":"127.0.0.1:43000"},"tcp":{"address":"127.0.0.1:43001"},"udp":{"address":"127.0.0.1:43002/udp"}}}""")
        let dynamicBytes = Encoding.UTF8.GetBytes(dynamic)
        let matchesRawData candidate =
            let api = apiConfigurationFromJson 19080 candidate endpoints """{"Version":"3.7.16"}"""
            Traefik.apiMatchesRuntime (Some api) (Some staticData) (Some dynamicBytes)
        let mutateRawData (update: JsonObject -> unit) =
            let candidate = JsonNode.Parse(rawData) :?> JsonObject
            update candidate
            matchesRawData (candidate.ToJsonString())

        Assert.That(matchesRawData rawData, Is.True)

        let driftedRawData = rawData.Replace("127.0.0.1:9002", "127.0.0.1:9003", StringComparison.Ordinal)
        Assert.That(matchesRawData driftedRawData, Is.False)

        let driftedEndpoints = endpoints.Replace("127.0.0.1:43002/udp", "127.0.0.1:43003/udp", StringComparison.Ordinal)
        let wrongBind =
            apiConfigurationFromJson 19080 rawData driftedEndpoints """{"Version":"3.7.16"}"""
        Assert.That(Traefik.apiMatchesStatic (Some wrongBind) (Some staticData), Is.False)

        let wrongVersion =
            apiConfigurationFromJson 19080 rawData endpoints """{"Version":"3.7.15"}"""
        Assert.That(
            Traefik.apiMatchesRuntime (Some wrongVersion) (Some staticData) (Some dynamicBytes),
            Is.False)

        let setRouterStatus (section: string) (name: string) (status: string) =
            mutateRawData (fun root ->
                let routers = root[section] :?> JsonObject
                let router = routers[name] :?> JsonObject
                router["status"] <- JsonValue.Create(status))
        let omitRouter (section: string) (name: string) =
            mutateRawData (fun root ->
                let routers = root[section] :?> JsonObject
                routers.Remove(name) |> ignore)

        Assert.That(setRouterStatus "tcpRouters" "stream@file" "disabled", Is.False)
        Assert.That(omitRouter "tcpRouters" "stream@file", Is.False)
        Assert.That(setRouterStatus "udpRouters" "datagrams@file" "disabled", Is.False)
        Assert.That(omitRouter "udpRouters" "datagrams@file", Is.False)

        let setUdpServiceUsers (users: string list) =
            mutateRawData (fun root ->
                let services = root["udpServices"] :?> JsonObject
                let service = services["datagrams@file"] :?> JsonObject
                let usedBy = JsonArray()
                for user in users do usedBy.Add(JsonValue.Create(user))
                service["usedBy"] <- usedBy)
        Assert.That(setUdpServiceUsers [ "other@file" ], Is.False)
        Assert.That(setUdpServiceUsers [ "datagrams@file"; "stale@file" ], Is.False)
        let omitServiceUsers (section: string) (name: string) =
            mutateRawData (fun root ->
                let services = root[section] :?> JsonObject
                let service = services[name] :?> JsonObject
                service.Remove("usedBy") |> ignore)
        Assert.That(omitServiceUsers "services" "healthy-service@file", Is.False)
        Assert.That(omitServiceUsers "tcpServices" "stream@file", Is.False)
        Assert.That(omitServiceUsers "udpServices" "datagrams@file", Is.False)


    [<Test>]
    member _.``static API comparison checks effective listener policy and defaults``() =
        let staticText =
            """{"entryPoints":{"keroosha-admin":{"address":"127.0.0.1:19080"},"front":{"address":"127.0.0.1:43001","asDefault":true,"proxyProtocol":{"trustedIPs":["192.0.2.4/32"]},"forwardedHeaders":{"trustedIPs":["127.0.0.1/32"]},"transport":{"lifeCycle":{"graceTimeOut":"10s"},"respondingTimeouts":{"readTimeout":"1m"}},"http2":{"maxConcurrentStreams":512},"http3":{"advertisedPort":43001},"udp":{"timeout":"3s"}}}}"""
        let apiEndpoints =
            """[{"name":"keroosha-admin","address":"127.0.0.1:19080","transport":{"lifeCycle":{"graceTimeOut":"10s"},"respondingTimeouts":{"readTimeout":"1m0s","idleTimeout":"3m0s"}},"forwardedHeaders":{},"http":{"sanitizePath":true,"maxHeaderBytes":1048576},"http2":{"maxConcurrentStreams":250,"maxDecoderHeaderTableSize":4096,"maxEncoderHeaderTableSize":4096},"udp":{"timeout":"3s"}},{"name":"front","address":"127.0.0.1:43001","asDefault":true,"proxyProtocol":{"trustedIPs":["192.0.2.4/32"]},"forwardedHeaders":{"trustedIPs":["127.0.0.1/32"]},"transport":{"lifeCycle":{"graceTimeOut":"10s"},"respondingTimeouts":{"readTimeout":"1m0s","idleTimeout":"3m0s"}},"http":{"sanitizePath":true,"maxHeaderBytes":1048576},"http2":{"maxConcurrentStreams":512,"maxDecoderHeaderTableSize":4096,"maxEncoderHeaderTableSize":4096},"http3":{"advertisedPort":43001},"udp":{"timeout":"3s"}}]"""
        let api =
            apiConfigurationFromJson 19080 "{}" apiEndpoints """{"Version":"3.7.16"}"""
        let matches (configuration: string) =
            Traefik.apiMatchesStatic (Some api) (Some(Encoding.UTF8.GetBytes(configuration)))

        Assert.That(matches staticText, Is.True)
        let driftedSettings =
            [ staticText.Replace("127.0.0.1/32", "127.0.0.2/32", StringComparison.Ordinal)
              staticText.Replace("192.0.2.4/32", "192.0.2.5/32", StringComparison.Ordinal)
              staticText.Replace("\"readTimeout\":\"1m\"", "\"readTimeout\":\"30s\"", StringComparison.Ordinal)
              staticText.Replace("\"maxConcurrentStreams\":512", "\"maxConcurrentStreams\":1024", StringComparison.Ordinal)
              staticText.Replace("\"advertisedPort\":43001", "\"advertisedPort\":43002", StringComparison.Ordinal)
              staticText.Replace("\"asDefault\":true", "\"asDefault\":false", StringComparison.Ordinal) ]
        for settings in driftedSettings do
            Assert.That(matches settings, Is.False)

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
        Assert.That(
            requires routeB routeB,
            Is.False,
            "Comparing only drifted disk state to the requested graph cannot detect the accepted router's withdrawal.")
        Assert.That(
            Traefik.udpWithdrawalRequiresRestartForAcceptedEntryPoints
                (Set.ofList [ "udp-a"; "udp-b" ])
                (Some routeB)
                (Some staticData),
            Is.True,
            "The prior accepted entrypoint set must detect withdrawal after the on-disk graph drifted.")
        let managed accepted disk desired =
            Traefik.udpUpdateRequiresRestart accepted (Some disk) (Some desired) (Some staticData)
        Assert.That(managed (Some (set ["udp-a"; "udp-b"])) routeB routeB, Is.True,
            "Drift already removed the checkpoint's handler from disk, not necessarily from the daemon.")
        Assert.That(managed (Some (set ["udp-b"])) multipleEndpoints routeB, Is.True,
            "An extra handler loaded from external drift must not survive restoration of the checkpoint.")
        Assert.That(managed None routeB routeB, Is.True,
            "Missing prior inputs leave an idle listener's previous handler indeterminate.")
        Assert.That(managed (Some (set ["udp-b"])) routeB routeB, Is.False,
            "A known idle listener does not force a restart on an unrelated update.")

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
        adminNode["observability"] <- JsonNode.Parse("""{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"}""")
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
        Assert.That(Traefik.loadedRollbackGraph (Some api) (Some dynamicBytes), Is.True)
        Assert.That(Traefik.loadedRollbackGraph (Some api) (Some changedBytes), Is.False, "Matching routers do not attest modified TLS options.")

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
        use services = JsonDocument.Parse($"""[{{"name":"{serviceName}@file","status":"enabled","type":"loadbalancer","loadBalancer":{{"servers":[{{"url":"http://127.0.0.1:9000"}}]}},"usedBy":["site@file"]}}]""")
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
        let dynamicBytes = Encoding.UTF8.GetBytes(Traefik.renderHistoricalDynamicConfig request.RootElement paths)
        let middlewareName = "keroosha-redirect-" + digest "site\nhttps://destination.example.test"
        let regex = "^https?://[^/?#]+(.*)$"
        let replacement = "https://destination.example.test${1}"
        let makeRouter (name: string) (rule: string) (entryPoint: string) (service: string) (middlewareNames: string list) =
            let router = JsonObject()
            router["name"] <- JsonValue.Create(name)
            router["provider"] <- JsonValue.Create("file")
            router["status"] <- JsonValue.Create("enabled")
            router["rule"] <- JsonValue.Create(rule)
            router["priority"] <- JsonValue.Create(Encoding.UTF8.GetByteCount(rule))
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
    member _.``ACME certificate lookup validates issuer account leaf key and storage metadata``() =
        use temporary = new TemporaryDirectory("traefik-acme-")
        let now = DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero)
        let valid = TestSupport.createCertificateFixture "site.example.test" [ "site.example.test" ] (now.AddDays(-1.0)) (now.AddDays(30.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let expired = TestSupport.createCertificateFixture "site.example.test" [ "site.example.test" ] (now.AddDays(-30.0)) (now.AddDays(-1.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let resolverName = "le"
        let resolverEmail = "ops@example.test"
        let caServer = "https://ca.example.test/directory"
        let storagePath = TraefikTlsSettings.acmeStoragePath temporary.Path resolverName caServer
        use accountKey = RSA.Create(2048)
        let accountKeyBase64 = Convert.ToBase64String(accountKey.ExportRSAPrivateKey())
        let writeStorage (certificatePem: string) (privateKeyPem: string) (registrationUri: string) =
            let domain = JsonObject()
            domain["main"] <- JsonValue.Create("site.example.test")
            domain["sans"] <- JsonArray()
            let entry = JsonObject()
            entry["domain"] <- domain
            entry["certificate"] <- JsonValue.Create(Convert.ToBase64String(Encoding.ASCII.GetBytes(certificatePem)))
            entry["key"] <- JsonValue.Create(Convert.ToBase64String(Encoding.ASCII.GetBytes(privateKeyPem)))
            let certificates = JsonArray()
            certificates.Add(entry)
            let registration = JsonObject()
            registration["body"] <- JsonObject()
            registration["uri"] <- JsonValue.Create(registrationUri)
            let account = JsonObject()
            account["Email"] <- JsonValue.Create(resolverEmail)
            account["Registration"] <- registration
            account["PrivateKey"] <- JsonValue.Create(accountKeyBase64)
            let resolver = JsonObject()
            resolver["Account"] <- account
            resolver["Certificates"] <- certificates
            let storage = JsonObject()
            storage[resolverName] <- resolver
            File.WriteAllText(storagePath, storage.ToJsonString())
            File.SetUnixFileMode(storagePath, enum<UnixFileMode>(0o600))

        let run (command: string) (arguments: string list) (stdin: string option) =
            if command = "getent" then { ExitCode = 2; Stdout = ""; Stderr = "" }
            elif command = "id" then HostEnvironment.system.Run command arguments stdin
            else { ExitCode = 2; Stdout = ""; Stderr = "" }
        let paths = { paths with StateDir = temporary.Path }
        let environment = TestSupport.fakeHostEnvironment "/" run (fun () -> now)
        let validRegistration = "https://ca.example.test/acme/account/1"
        writeStorage valid.LeafCertificatePem valid.PrivateKeyPem validRegistration

        let validFingerprint =
            Traefik.acmeCertificateFingerprint environment paths resolverName resolverEmail caServer "site.example.test"
        let wrongResolver =
            Traefik.acmeCertificateFingerprint environment paths "other" resolverEmail caServer "site.example.test"
        let wrongDirectory =
            Traefik.acmeCertificateFingerprint environment paths resolverName resolverEmail "https://ca.example.test/other-directory" "site.example.test"
        writeStorage expired.LeafCertificatePem expired.PrivateKeyPem validRegistration
        let expiredFingerprint =
            Traefik.acmeCertificateFingerprint environment paths resolverName resolverEmail caServer "site.example.test"
        writeStorage valid.LeafCertificatePem expired.PrivateKeyPem validRegistration
        let mismatchedKey =
            Traefik.acmeCertificateFingerprint environment paths resolverName resolverEmail caServer "site.example.test"
        writeStorage valid.LeafCertificatePem valid.PrivateKeyPem "https://other.example.test/acme/account/1"
        let wrongAccount =
            Traefik.acmeCertificateFingerprint environment paths resolverName resolverEmail caServer "site.example.test"
        writeStorage valid.LeafCertificatePem valid.PrivateKeyPem validRegistration
        File.SetUnixFileMode(storagePath, enum<UnixFileMode>(0o644))
        let unsafeMetadata =
            Traefik.acmeCertificateFingerprint environment paths resolverName resolverEmail caServer "site.example.test"

        Assert.That(validFingerprint, Is.EqualTo(Some valid.Fingerprint))
        Assert.That(wrongResolver, Is.EqualTo(None))
        Assert.That(wrongDirectory, Is.EqualTo(None))
        Assert.That(expiredFingerprint, Is.EqualTo(None))
        Assert.That(mismatchedKey, Is.EqualTo(None))
        Assert.That(wrongAccount, Is.EqualTo(None))
        Assert.That(unsafeMetadata, Is.EqualTo(None))

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

    [<Test; Explicit("Invokes only the public sealed QEMU acceptance harness."); Category("Sandbox")>]
    member _.``Sandbox lifecycle delegates to the sealed full acceptance runner``() =
        if Environment.GetEnvironmentVariable("DOROTHY_RUN_SEALED_TRAEFIK_ACCEPTANCE") <> "1" then
            Assert.Ignore("Set DOROTHY_RUN_SEALED_TRAEFIK_ACCEPTANCE=1 to invoke the explicit sealed acceptance harness.")
        let stateDirectory = verifiedAcceptanceStateDirectory ()
        let providerDirectory = verifiedCandidateProviderDirectory ()
        runPublicAcceptance stateDirectory providerDirectory
    [<Test>]
    member _.``API comparison projects effective entrypoint routes and native middleware references``() =
        let dynamic =
            """{
              "http":{
                "routers":{
                  "keroosha-admin":{"rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000},
                  "app":{"rule":"Host(`app.test`)","entryPoints":["a","b"],"middlewares":["chain"],"service":"app","priority":0},
                  "parent":{"rule":"Host(`parent.test`)","entryPoints":["a","b"],"middlewares":["mark"]},
                  "child":{"rule":"Header(`middlewares`,`literal-value`)","parentRefs":["parent"],"service":"app"}
                },
                "services":{
                  "app":{"middlewares":["mark"],"loadBalancer":{"servers":[{"url":"http://127.0.0.1:8080"}]}}
                },
                "middlewares":{
                  "mark":{"headers":{"customRequestHeaders":{"middlewares":"literal-value"}}},
                  "prefix":{"addPrefix":{"prefix":"/first"}},
                  "chain":{"chain":{"middlewares":["prefix","mark"]}}
                }
              },
              "tcp":{
                "routers":{"echo":{"entryPoints":["t"],"rule":"HostSNI(\"*\")","middlewares":["one"],"service":"echo","priority":0,"tls":{"passthrough":false}}},
                "middlewares":{"one":{"ipAllowList":{"sourceRange":["127.0.0.1/32"]}}},
                "services":{"echo":{"loadBalancer":{"servers":[{"address":"127.0.0.1:19001"}]}}}
              }
            }"""
        let rawData =
            """{
              "routers":{
                "a-app@file":{"entryPoints":["a"],"middlewares":["mark@file","chain@file"],"service":"app","rule":"Host(`app.test`)","priority":16,"tls":{"options":"default"},"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["a"]},
                "a-parent@file":{"entryPoints":["a"],"middlewares":["mark@file","mark@file"],"rule":"Host(`parent.test`)","priority":19,"tls":{"options":"default"},"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["a"]},
                "b-app@file":{"entryPoints":["b"],"middlewares":["mark@file","chain@file"],"service":"app","rule":"Host(`app.test`)","priority":16,"tls":{"options":"default"},"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["b"]},
                "b-parent@file":{"entryPoints":["b"],"middlewares":["mark@file","mark@file"],"rule":"Host(`parent.test`)","priority":19,"tls":{"options":"default"},"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["b"]},
                "child@file":{"service":"app","rule":"Header(`middlewares`,`literal-value`)","parentRefs":["a-parent@file","b-parent@file"],"priority":37,"status":"enabled"},
                "keroosha-admin@file":{"entryPoints":["keroosha-admin"],"service":"api@internal","rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","priority":1000000,"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["keroosha-admin"]}
              },
              "middlewares":{
                "chain@file":{"chain":{"middlewares":["prefix@file","mark@file"]},"status":"enabled","usedBy":["a-app@file","b-app@file"]},
                "mark@file":{"headers":{"customRequestHeaders":{"middlewares":"literal-value"}},"status":"enabled","usedBy":["a-app@file","a-parent@file","a-parent@file","b-app@file","b-parent@file","b-parent@file"]},
                "prefix@file":{"addPrefix":{"prefix":"/first"},"status":"enabled"}
              },
              "services":{
                "api@internal":{"status":"enabled","usedBy":["keroosha-admin@file"]},
                "app@file":{"middlewares":["mark@file"],"loadBalancer":{"servers":[{"url":"http://127.0.0.1:8080"}],"strategy":"wrr","passHostHeader":true,"responseForwarding":{"flushInterval":"100ms"}},"status":"enabled","type":"loadbalancer","usedBy":["a-app@file","b-app@file","child@file"],"serverStatus":{"http://127.0.0.1:8080":"UP"}},
                "dashboard@internal":{"status":"enabled"},
                "noop@internal":{"status":"enabled"}
              },
              "tcpRouters":{"echo@file":{"entryPoints":["t"],"middlewares":["one@file"],"service":"echo","rule":"HostSNI(\"*\")","priority":-1,"tls":{"options":"default"},"status":"enabled","using":["t"]}},
              "tcpMiddlewares":{"one@file":{"ipAllowList":{"sourceRange":["127.0.0.1/32"]},"status":"enabled"}},
              "tcpServices":{"echo@file":{"loadBalancer":{"servers":[{"address":"127.0.0.1:19001"}]},"status":"enabled","usedBy":["echo@file"]}}
            }"""
        let entryPoints =
            """[
              {"name":"a","address":"127.0.0.1:38308","http":{"middlewares":["mark@file"],"tls":{"options":"default"}}},
              {"name":"b","address":"127.0.0.1:38309","http":{"middlewares":["mark@file"],"tls":{"options":"default"}}},
              {"name":"keroosha-admin","address":"127.0.0.1:38307"},
              {"name":"t","address":"127.0.0.1:38310"}
            ]"""
        let apiFor raw =
            apiConfigurationFromJson 19080 raw entryPoints """{"Version":"3.7.16"}"""
        Assert.That(Traefik.loadedRollbackGraph (Some(apiFor rawData)) (Some(Encoding.UTF8.GetBytes(dynamic))), Is.False,
                    "An unmarked file without TLS cannot attest that the running process has no certificate registrations.")
        let marked = JsonNode.Parse(dynamic).AsObject()
        marked["http"].["middlewares"].["mark"].["headers"].["frameDeny"] <- JsonValue.Create(false)
        let rule = Traefik.stampDynamicGeneration marked
        let dynamic = marked.ToJsonString()
        let api = JsonNode.Parse(rawData)
        api["routers"].["keroosha-admin@file"].["rule"] <- JsonValue.Create(rule)
        let rawData = api.ToJsonString()
        let matches raw =
            Traefik.apiMatchesDynamic
                (Some(apiFor raw))
                (Some(Encoding.UTF8.GetBytes(dynamic)))

        Assert.That(matches rawData, Is.True)
        let recoverable (disk: string) =
            Traefik.loadedRollbackGraph (Some(apiFor rawData)) (Some(Encoding.UTF8.GetBytes(disk)))
        Assert.That(recoverable dynamic, Is.True)
        Assert.That(recoverable "{\"http\":[", Is.False, "Serving a good graph cannot make malformed disk bytes recoverable.")
        Assert.That(recoverable (dynamic.Replace("127.0.0.1:19001", "127.0.0.1:19002")), Is.False, "A different live backend is not the disk preimage.")
        for value in [ "false"; "null" ] do
            let changed = JsonNode.Parse(dynamic)
            changed["http"].["services"].["app"].["loadBalancer"].AsObject().Add("unknownNativeKey", JsonNode.Parse(value))
            Assert.That(recoverable (changed.ToJsonString()), Is.False, $"Unobserved field {value} must not attribute the file.")
            changed["http"].["services"].["app"].["loadBalancer"].AsObject().Remove("unknownNativeKey") |> ignore
            changed["http"].["middlewares"].["mark"].["headers"].AsObject().Add("removeHeader", JsonNode.Parse(value))
            Assert.That(recoverable (changed.ToJsonString()), Is.False, "A known auth boolean is not a headers default.")
        for status in [ "warning"; "disabled" ] do
            let live = JsonNode.Parse(rawData)
            let route = live["routers"].["a-app@file"]
            route["status"] <- JsonValue.Create(status)
            route["error"] <- JsonNode.Parse("""["router configuration error"]""")
            let raw = live.ToJsonString()
            Assert.That(matches raw, Is.False, "Unhealthy is never successful activation.")
            Assert.That(Traefik.loadedRollbackGraph (Some(apiFor raw)) (Some(Encoding.UTF8.GetBytes(dynamic))), Is.True)
            let services = JsonNode.Parse(rawData)
            let service = services["services"].["app@file"]
            service["status"] <- JsonValue.Create(status)
            service["error"] <- JsonNode.Parse("""["service middleware unavailable"]""")
            let serviceRaw = services.ToJsonString()
            Assert.That(matches serviceRaw, Is.False)
            Assert.That(Traefik.loadedRollbackGraph (Some(apiFor serviceRaw)) (Some(Encoding.UTF8.GetBytes(dynamic))), Is.True)

        let priorityDrift = JsonNode.Parse(rawData) :?> JsonObject
        let routers = priorityDrift["routers"] :?> JsonObject
        let app = routers["a-app@file"] :?> JsonObject
        app["priority"] <- JsonValue.Create(15)
        Assert.That(matches (priorityDrift.ToJsonString()), Is.False)

        let extraHeader = JsonNode.Parse(rawData) :?> JsonObject
        let resources = extraHeader["middlewares"] :?> JsonObject
        let mark = resources["mark@file"] :?> JsonObject
        let headers = mark["headers"] :?> JsonObject
        let customRequestHeaders = headers["customRequestHeaders"] :?> JsonObject
        customRequestHeaders["x-review-extra"] <- JsonValue.Create("literal")
        Assert.That(matches (extraHeader.ToJsonString()), Is.False)

        let extraService = JsonNode.Parse(rawData) :?> JsonObject
        let services = extraService["services"] :?> JsonObject
        services["unexpected@file"] <- JsonObject()
        Assert.That(matches (extraService.ToJsonString()), Is.False)

    [<Test>]
    member _.``API comparison treats equivalent Go durations as the same effective load balancer value``() =
        let dynamic =
            """{
              "http":{
                "routers":{"keroosha-admin":{"rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000}},
                "services":{"timed":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}],"responseForwarding":{"flushInterval":"60s"}}}}
              }
            }"""
        let rawData =
            """{
              "routers":{"keroosha-admin@file":{"entryPoints":["keroosha-admin"],"service":"api@internal","rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","priority":1000000,"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled"}},
              "services":{"timed@file":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}],"strategy":"wrr","passHostHeader":true,"responseForwarding":{"flushInterval":"1m0s"}},"status":"enabled","type":"loadbalancer"}},
              "middlewares":{}
            }"""
        let api =
            apiConfigurationFromJson 19080 rawData "[]" """{"Version":"3.7.16"}"""
        Assert.That(
            Traefik.apiMatchesDynamic (Some api) (Some(Encoding.UTF8.GetBytes(dynamic))),
            Is.True)
        let explicitEmptyUsers = JsonNode.Parse(rawData) :?> JsonObject
        let timedServices = explicitEmptyUsers["services"] :?> JsonObject
        let timed = timedServices["timed@file"] :?> JsonObject
        timed["usedBy"] <- JsonArray()
        let apiWithEmptyUsers =
            apiConfigurationFromJson 19080 (explicitEmptyUsers.ToJsonString()) "[]" """{"Version":"3.7.16"}"""
        Assert.That(
            Traefik.apiMatchesDynamic (Some apiWithEmptyUsers) (Some(Encoding.UTF8.GetBytes(dynamic))),
            Is.True)
    [<Test>]
    member _.``API comparison applies root observability precedence and observation-only listener splitting``() =
        let dynamic =
            """{
              "http":{
                "routers":{
                  "keroosha-admin":{"rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","priority":1000000},
                  "site":{"entryPoints":["front","other"],"rule":"Host(`obs.test`)","service":"app","observability":{"tracing":true}},
                  "parent":{"entryPoints":["front","other"],"rule":"Host(`parent.test`)"},
                  "child":{"parentRefs":["parent"],"rule":"Header(`x`,`child`)","service":"app"}
                },
                "services":{"app":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}]}}}
              }
            }"""
        let rawData =
            """{
              "routers":{
                "keroosha-admin@file":{"entryPoints":["keroosha-admin"],"service":"api@internal","rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","priority":1000000,"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["keroosha-admin"]},
                "front-site@file":{"entryPoints":["front"],"service":"app","rule":"Host(`obs.test`)","priority":16,"observability":{"accessLogs":false,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["front"]},
                "site@file":{"entryPoints":["other"],"service":"app","rule":"Host(`obs.test`)","priority":16,"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["other"]},
                "front-parent@file":{"entryPoints":["front"],"rule":"Host(`parent.test`)","priority":19,"observability":{"accessLogs":false,"metrics":true,"tracing":false,"traceVerbosity":"minimal"},"status":"enabled","using":["front"]},
                "parent@file":{"entryPoints":["other"],"rule":"Host(`parent.test`)","priority":19,"observability":{"accessLogs":true,"metrics":true,"tracing":true,"traceVerbosity":"minimal"},"status":"enabled","using":["other"]},
                "child@file":{"service":"app","rule":"Header(`x`,`child`)","parentRefs":["front-parent@file","parent@file"],"priority":19,"status":"enabled"}
              },
              "services":{
                "app@file":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:9000"}],"strategy":"wrr","passHostHeader":true,"responseForwarding":{"flushInterval":"100ms"}},"status":"enabled","type":"loadbalancer","usedBy":["child@file","front-site@file","site@file"]}
              },
              "middlewares":{}
            }"""
        let entryPoints =
            """[
              {"name":"keroosha-admin","address":"127.0.0.1:19080"},
              {"name":"front","address":"127.0.0.1:18081","observability":{"accessLogs":false,"tracing":false}},
              {"name":"other","address":"127.0.0.1:18082"}
            ]"""
        let matches (raw: string) =
            let api = apiConfigurationFromJson 19080 raw entryPoints """{"Version":"3.7.16"}"""
            Traefik.apiMatchesDynamic (Some api) (Some(Encoding.UTF8.GetBytes(dynamic)))
        let mutate (update: JsonObject -> unit) =
            let candidate = JsonNode.Parse(rawData) :?> JsonObject
            update candidate
            matches (candidate.ToJsonString())
        let mutateObservability (routerName: string) (update: JsonObject -> unit) =
            mutate (fun root ->
                let routers = root["routers"] :?> JsonObject
                let route = routers[routerName] :?> JsonObject
                let observability = route["observability"] :?> JsonObject
                update observability)

        Assert.That(matches rawData, Is.True)
        Assert.That(
            mutateObservability "front-site@file" (fun observability ->
                observability["accessLogs"] <- JsonValue.Create(true)),
            Is.False,
            "The router inherits listener values where it has no explicit override.")
        Assert.That(
            mutateObservability "front-site@file" (fun observability ->
                observability["tracing"] <- JsonValue.Create(false)),
            Is.False,
            "An explicit router value takes precedence over the listener model.")
        Assert.That(
            mutateObservability "site@file" (fun observability ->
                observability["metrics"] <- JsonValue.Create(false)),
            Is.False,
            "Unmodeled root routers retain native observability defaults.")
        Assert.That(
            mutateObservability "site@file" (fun observability ->
                observability["stale"] <- JsonValue.Create(false)),
            Is.False,
            "Unknown observability fields remain drift.")

        let missingNativeDefaultBlock =
            mutate (fun root ->
                let routers = root["routers"] :?> JsonObject
                let route = routers["parent@file"] :?> JsonObject
                route.Remove("observability") |> ignore)
        Assert.That(missingNativeDefaultBlock, Is.False, "Root routers must expose the complete native observability block.")

        let missingListenerModel =
            mutate (fun root ->
                let routers = root["routers"] :?> JsonObject
                let route = routers["front-site@file"] :?> JsonObject
                route.Remove("observability") |> ignore)
        Assert.That(missingListenerModel, Is.False, "A configured non-default model cannot be omitted.")

        let childWithObservability =
            mutate (fun root ->
                let routers = root["routers"] :?> JsonObject
                let child = routers["child@file"] :?> JsonObject
                let observability = JsonObject()
                observability["accessLogs"] <- JsonValue.Create(true)
                observability["metrics"] <- JsonValue.Create(true)
                observability["tracing"] <- JsonValue.Create(true)
                observability["traceVerbosity"] <- JsonValue.Create("minimal")
                child["observability"] <- observability)
        Assert.That(childWithObservability, Is.False, "Child routers do not inherit root defaults.")

    [<Test>]
    member _.``Only the identical bound dynamic step can resume across rename``() =
        let accepts bound before after = Traefik.recoveryDiskAccepted bound "candidate" before after
        Assert.That(accepts None true false, Is.True)
        Assert.That(accepts None false true, Is.False, "An unbound journal cannot adopt an already installed candidate.")
        Assert.That(accepts (Some "different") true false, Is.False, "The preimage must not reopen target selection.")
        Assert.That(accepts (Some "candidate") true false, Is.True, "Interrupted before rename.")
        Assert.That(accepts (Some "candidate") false true, Is.True, "Interrupted after rename.")
        Assert.That(accepts (Some "candidate") false false, Is.False, "Foreign bytes after binding.")

    [<Test>]
    member _.``Pending start is not failed by an empty PID but a recorded exit belongs to its exact invocation``() =
        let id = String('a',32)
        let mutable completed = false
        let mutable exited = false
        let env = TestSupport.fakeHostEnvironment "/" (fun cmd args _ ->
            let text =
                if cmd = "systemctl" then "InvocationID=" + id + "\nMainPID=0"
                elif List.contains "JOB_ID=123" args then
                    if completed then "{\"MESSAGE_ID\":\"39f53479d3a045ac8e11786248231fbf\",\"JOB_RESULT\":\"done\",\"JOB_TYPE\":\"start\",\"INVOCATION_ID\":\"" + id + "\"}"
                    else "{\"MESSAGE_ID\":\"9d1aaa27d60140bd96365438aad20286\",\"JOB_RESULT\":\"done\",\"JOB_TYPE\":\"restart\",\"INVOCATION_ID\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}"
                elif List.contains ("INVOCATION_ID=" + id) args && exited then "{\"UNIT_RESULT\":\"exit-code\"}"
                else ""
            { ExitCode=0; Stdout=text; Stderr="" }) (fun () -> DateTimeOffset.UtcNow)
        Assert.That(Traefik.checkActivationJob env "123" None, Is.EqualTo(None:string option))
        completed <- true
        Assert.That(Traefik.checkActivationJob env "123" None, Is.EqualTo(Some id))
        exited <- true
        let error = Assert.Throws<Traefik.BackendError>(fun () -> Traefik.checkActivationJob env "123" (Some id) |> ignore)
        Assert.That(error.Message, Does.Contain(id + " failed: exit-code"))
