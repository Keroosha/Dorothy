namespace Dorothy.Tests

open System
open System.IO
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper
open NUnit.Framework
open System.Diagnostics
open System.Threading
open Dorothy.DSL.Provider

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

        // Act
        let unsafeFailure = TestDelegate(fun () -> Traefik.renderDynamicConfig unsafeName.RootElement paths |> ignore)
        let collisionFailure = TestDelegate(fun () -> Traefik.renderDynamicConfig collision.RootElement paths |> ignore)

        // Assert
        Assert.Throws<Traefik.BackendError>(unsafeFailure) |> ignore
        Assert.Throws<Traefik.BackendError>(collisionFailure) |> ignore

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
          "routers":{"site":{"host":"site.example.test","entryPoint":"web","backend":"http://127.0.0.1:9000","tls":{"kind":"acme","name":"le"}}},
          "certificates":{},"adminPort":19080
        }""")
        let dynamicBytes = Encoding.UTF8.GetBytes(Traefik.renderDynamicConfig request.RootElement paths)
        let serviceName = "keroosha-backend-" + digest "http://127.0.0.1:9000"
        use routers = JsonDocument.Parse($"""[
          {{"name":"keroosha-admin@file","provider":"file","rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","status":"enabled","middlewares":[]}},
          {{"name":"site@file","provider":"file","rule":"Host(`site.example.test`)","entryPoints":["web"],"service":"{serviceName}","status":"enabled","middlewares":[],"tls":{{"certResolver":"le","options":"default"}}}}
        ]""")
        use services = JsonDocument.Parse($"""[
          {{"name":"{serviceName}@file","provider":"file","status":"enabled","type":"loadbalancer","loadBalancer":{{"servers":[{{"url":"http://127.0.0.1:9000"}}]}}}}
        ]""")
        let api: Traefik.ApiConfiguration =
            { Routers = routers.RootElement.Clone()
              Services = services.RootElement.Clone() }

        // Act
        let matches = Traefik.apiMatchesDynamic (Some api) (Some dynamicBytes)

        // Assert
        Assert.That(matches, Is.True)

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
          {{"name":"keroosha-admin@file","rule":"PathPrefix(`/api`) || PathPrefix(`/dashboard`)","entryPoints":["keroosha-admin"],"service":"api@internal","status":"enabled","middlewares":[]}},
          {{"name":"site@file","rule":"Host(`site.example.test`)","entryPoints":["web"],"service":"{serviceName}@file","status":"enabled","middlewares":[]}}
        ]""")
        use services = JsonDocument.Parse($"""[{{"name":"{serviceName}@file","status":"enabled","type":"loadbalancer","loadBalancer":{{"servers":[{{"url":"http://127.0.0.1:9000"}}]}}}}]""")
        let api: Traefik.ApiConfiguration =
            { Routers = routers.RootElement.Clone()
              Services = services.RootElement.Clone() }

        // Act
        let matches = Traefik.apiMatchesDynamic (Some api) (Some dynamicBytes)

        // Assert
        Assert.That(matches, Is.False)

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
    member _.``Sandbox apply rollback read and Delete retain ACME storage and prove SNI``() =
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
        let makeRequest (operation: string) (httpPort: int) (tlsPort: int) (backend: string) : JsonObject =
            let entryPoints = JsonObject()
            entryPoints["web"] <- JsonValue.Create(httpPort)
            entryPoints["websecure"] <- JsonValue.Create(tlsPort)
            let tls = JsonObject()
            tls["kind"] <- JsonValue.Create("provided")
            tls["name"] <- JsonValue.Create("sandbox-cert")
            let router = JsonObject()
            router["host"] <- JsonValue.Create("sandbox.example.test")
            router["entryPoint"] <- JsonValue.Create("websecure")
            router["backend"] <- JsonValue.Create(backend)
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
        let applyRequest = makeRequest "apply" webPort securePort "http://127.0.0.1:1"
        let dynamicUpdate = makeRequest "apply" webPort securePort "http://127.0.0.1:2"
        let startupUpdate = makeRequest "apply" nextWebPort securePort "http://127.0.0.1:2"
        let readRequest = makeRequest "read" nextWebPort securePort "http://127.0.0.1:2"
        let failedUpdate = makeRequest "apply" nextWebPort 22 "http://127.0.0.1:2"
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

            let dynamicResult = invoke dynamicUpdate
            Assert.That(dynamicResult.GetProperty("inSync").GetBoolean(), Is.True)
            Assert.That(dynamicResult.GetProperty("actualConfigHash").GetString(), Is.Not.EqualTo(applied.GetProperty("actualConfigHash").GetString()))
            Assert.That(mainPid (), Is.EqualTo(initialPid), "A dynamic-only update must not restart Traefik.")

            let startupResult = invoke startupUpdate
            Assert.That(startupResult.GetProperty("inSync").GetBoolean(), Is.True)
            Assert.That(startupResult.GetProperty("certificateFingerprints").GetProperty("sandbox-cert").GetString(), Is.EqualTo(certificate.Fingerprint))
            Assert.That(mainPid (), Is.Not.EqualTo(initialPid), "An entry-point change must restart Traefik.")

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
