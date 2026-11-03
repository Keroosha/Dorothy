namespace Dorothy.Tests

open System
open System.Diagnostics
open System.IO
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper
open NUnit.Framework

type TemporaryDirectory(prefix: string) =
    let path = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"))

    do
        Directory.CreateDirectory(path) |> ignore
        if OperatingSystem.IsLinux() then
            File.SetUnixFileMode(path, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)

    member _.Path = path

    interface IDisposable with
        member _.Dispose() =
            if Directory.Exists(path) then
                Directory.Delete(path, true)

module TestSupport =
    let fakeHostEnvironment root run utcNow : HostEnvironment =
        { Root = root
          Run = run
          UtcNow = utcNow }

    let private serialNumber () =
        let bytes = RandomNumberGenerator.GetBytes(16)
        bytes[0] <- bytes[0] &&& 0x7fuy
        if bytes |> Array.forall ((=) 0uy) then bytes[0] <- 1uy
        bytes

    type CertificateFixture =
        { LeafCertificatePem: string
          ChainPem: string
          PrivateKeyPem: string
          EncryptedPrivateKeyPem: string
          Fingerprint: string
          PfxBytes: byte array
          PfxPassword: string
          RootCertificatePem: string
          IntermediateCertificatePem: string }

    let createCertificateFixture
        (subject: string)
        (dnsNames: string list)
        (notBefore: DateTimeOffset)
        (notAfter: DateTimeOffset)
        (extendedKeyUsage: string list)
        =
        let now = DateTimeOffset.UtcNow
        let issuerNotBefore = min (now.AddDays(-10.0)) (notBefore.AddDays(-1.0))
        let issuerNotAfter = max (now.AddDays(180.0)) (notAfter.AddDays(1.0))
        let rootNotBefore = issuerNotBefore.AddDays(-1.0)
        let rootNotAfter = issuerNotAfter.AddDays(1.0)
        use rootKey = RSA.Create(2048)
        let rootRequest = CertificateRequest("CN=" + subject + " Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        rootRequest.CertificateExtensions.Add(X509BasicConstraintsExtension(true, true, 1, true)) |> ignore
        rootRequest.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign ||| X509KeyUsageFlags.CrlSign, true)) |> ignore
        rootRequest.CertificateExtensions.Add(X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false)) |> ignore
        use rootCertificate = rootRequest.CreateSelfSigned(rootNotBefore, rootNotAfter)
        use rootPublicCertificate = X509CertificateLoader.LoadCertificate(rootCertificate.RawData)

        use intermediateKey = RSA.Create(2048)
        let intermediateRequest = CertificateRequest("CN=" + subject + " Intermediate", intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        intermediateRequest.CertificateExtensions.Add(X509BasicConstraintsExtension(true, true, 0, true)) |> ignore
        intermediateRequest.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign ||| X509KeyUsageFlags.CrlSign, true)) |> ignore
        intermediateRequest.CertificateExtensions.Add(X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false)) |> ignore
        intermediateRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(rootCertificate, true, true)) |> ignore
        use intermediateCertificate = intermediateRequest.Create(rootCertificate, issuerNotBefore, issuerNotAfter, serialNumber())
        use intermediateSigner = intermediateCertificate.CopyWithPrivateKey(intermediateKey)

        use leafKey = RSA.Create(2048)
        let leafRequest = CertificateRequest("CN=" + subject, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        leafRequest.CertificateExtensions.Add(X509BasicConstraintsExtension(false, false, 0, true)) |> ignore
        leafRequest.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature ||| X509KeyUsageFlags.KeyEncipherment, true)) |> ignore
        if not extendedKeyUsage.IsEmpty then
            let usages = OidCollection()
            for oid in extendedKeyUsage do usages.Add(Oid(oid)) |> ignore
            leafRequest.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(usages, true)) |> ignore
        let san = SubjectAlternativeNameBuilder()
        for dnsName in dnsNames do san.AddDnsName(dnsName)
        leafRequest.CertificateExtensions.Add(san.Build()) |> ignore
        leafRequest.CertificateExtensions.Add(X509SubjectKeyIdentifierExtension(leafRequest.PublicKey, false)) |> ignore
        leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(intermediateSigner, true, true)) |> ignore
        use issuedLeaf = leafRequest.Create(intermediateSigner, notBefore, notAfter, serialNumber())
        use leafCertificate = issuedLeaf.CopyWithPrivateKey(leafKey)

        let password = "test-pfx-password"
        let pfxCertificates = X509Certificate2Collection()
        pfxCertificates.Add(leafCertificate) |> ignore
        pfxCertificates.Add(intermediateCertificate) |> ignore
        pfxCertificates.Add(rootPublicCertificate) |> ignore
        let pfxBytes = pfxCertificates.Export(X509ContentType.Pkcs12, password)
        let encryptedPrivateKeyPem =
            leafKey.ExportEncryptedPkcs8PrivateKeyPem(
                password.AsSpan(),
                PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100000)
            )

        let leafPem = leafCertificate.ExportCertificatePem()
        let intermediatePem = intermediateCertificate.ExportCertificatePem()
        let rootPem = rootCertificate.ExportCertificatePem()

        { LeafCertificatePem = leafPem
          ChainPem = String.concat "\n" [ leafPem; intermediatePem; rootPem ] + "\n"
          PrivateKeyPem = leafKey.ExportPkcs8PrivateKeyPem()
          EncryptedPrivateKeyPem = encryptedPrivateKeyPem
          Fingerprint = SHA256.HashData(leafCertificate.RawData) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
          PfxBytes = pfxBytes
          PfxPassword = password
          RootCertificatePem = rootPem
          IntermediateCertificatePem = intermediatePem }

    let createValidCertificateFixture subject dnsNames =
        createCertificateFixture
            subject
            dnsNames
            (DateTimeOffset.UtcNow.AddDays(-1.0))
            (DateTimeOffset.UtcNow.AddDays(30.0))
            [ "1.3.6.1.5.5.7.3.1" ]

    let createMultiKeyPfx password =
        let certificates = X509Certificate2Collection()
        let createOne subject host =
            let key = RSA.Create(2048)
            let request = CertificateRequest("CN=" + subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            request.CertificateExtensions.Add(X509BasicConstraintsExtension(false, false, 0, true)) |> ignore
            request.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature ||| X509KeyUsageFlags.KeyEncipherment, true)) |> ignore
            let usages = OidCollection()
            usages.Add(Oid("1.3.6.1.5.5.7.3.1")) |> ignore
            request.CertificateExtensions.Add(X509EnhancedKeyUsageExtension(usages, true)) |> ignore
            let san = SubjectAlternativeNameBuilder()
            san.AddDnsName(host)
            request.CertificateExtensions.Add(san.Build()) |> ignore
            let certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddDays(30.0))
            key, certificate

        let key1, cert1 = createOne "first multikey" "first.multikey.example.test"
        use key1 = key1
        use cert1 = cert1
        let key2, cert2 = createOne "second multikey" "second.multikey.example.test"
        use key2 = key2
        use cert2 = cert2
        certificates.Add(cert1) |> ignore
        certificates.Add(cert2) |> ignore
        certificates.Export(X509ContentType.Pkcs12, password)

    type PulumiProcessResult =
        { ExitCode: int
          StandardOutput: string
          StandardError: string }

    let private findExecutable executableName =
        let pathValue = Environment.GetEnvironmentVariable("PATH")
        let extensions = if OperatingSystem.IsWindows() then [ ".exe"; ".cmd"; ".bat"; "" ] else [ "" ]
        pathValue.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
        |> Seq.collect (fun directory -> extensions |> Seq.map (fun extension -> Path.Combine(directory, executableName + extension)))
        |> Seq.tryFind File.Exists

    let private findRepositoryRoot () =
        let rec walk (directory: DirectoryInfo) =
            if isNull directory then
                invalidOp "Unable to locate Dorothy.slnx from the NUnit test output directory."
            let solution = Path.Combine(directory.FullName, "Dorothy.slnx")
            if File.Exists(solution) then directory.FullName else walk directory.Parent
        walk (DirectoryInfo(AppContext.BaseDirectory))

    let private copyDirectory source destination =
        Directory.CreateDirectory(destination) |> ignore
        for sourceDirectory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories) do
            let relative = Path.GetRelativePath(source, sourceDirectory)
            Directory.CreateDirectory(Path.Combine(destination, relative)) |> ignore
        for sourceFile in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories) do
            let relative = Path.GetRelativePath(source, sourceFile)
            let destinationFile = Path.Combine(destination, relative)
            File.Copy(sourceFile, destinationFile, true)
            if OperatingSystem.IsLinux() then
                File.SetUnixFileMode(destinationFile, File.GetUnixFileMode(sourceFile))

    [<Sealed>]
    type PulumiCliProject() =
        let pulumiPath =
            match findExecutable "pulumi" with
            | Some value -> value
            | None -> Assert.Ignore("The isolated Pulumi CLI tests require the pulumi command."); ""
        let temporary = new TemporaryDirectory("keroosha-nunit-pulumi-")
        let root = temporary.Path
        let projectDirectory = Path.Combine(root, "project")
        let pulumiHome = Path.Combine(root, "pulumi-home")
        let backendDirectory = Path.Combine(root, "backend")
        let backendUrl = Uri(Path.GetFullPath(backendDirectory), UriKind.Absolute).AbsoluteUri
        let stackName = "integration"
        let projectName = "keroosha-nunit-" + Guid.NewGuid().ToString("N")


        let runWith (arguments: string list) (overrides: Map<string, string>) =
            let startInfo = ProcessStartInfo(pulumiPath)
            startInfo.WorkingDirectory <- projectDirectory
            startInfo.UseShellExecute <- false
            startInfo.RedirectStandardOutput <- true
            startInfo.RedirectStandardError <- true
            startInfo.CreateNoWindow <- true
            startInfo.Environment["PULUMI_HOME"] <- pulumiHome
            startInfo.Environment["PULUMI_BACKEND_URL"] <- backendUrl
            startInfo.Environment["PULUMI_CONFIG_PASSPHRASE"] <- "keroosha-test-passphrase"
            startInfo.Environment["PULUMI_SKIP_UPDATE_CHECK"] <- "1"
            startInfo.Environment["PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION"] <- "1"
            startInfo.Environment["PULUMI_EXPERIMENTAL"] <- "false"
            startInfo.Environment.Remove("PULUMI_ENABLE_STREAMING_JSON_PREVIEW") |> ignore
            for KeyValue(key, value) in overrides do startInfo.Environment[key] <- value
            for argument in arguments do startInfo.ArgumentList.Add(argument)
            use childProcess = new Process(StartInfo = startInfo)
            if not (childProcess.Start()) then invalidOp "Unable to start Pulumi CLI."
            let standardOutput = childProcess.StandardOutput.ReadToEndAsync()
            let standardError = childProcess.StandardError.ReadToEndAsync()
            if not (childProcess.WaitForExit(240000)) then
                childProcess.Kill(true)
                childProcess.WaitForExit()
                let stdout = standardOutput.GetAwaiter().GetResult()
                let stderr = standardError.GetAwaiter().GetResult()
                raise (TimeoutException(sprintf "Pulumi CLI command timed out: %s\nstdout:\n%s\nstderr:\n%s" (String.concat " " arguments) stdout stderr))
            { ExitCode = childProcess.ExitCode
              StandardOutput = standardOutput.GetAwaiter().GetResult()
              StandardError = standardError.GetAwaiter().GetResult() }

        do
            Directory.CreateDirectory(projectDirectory) |> ignore
            Directory.CreateDirectory(pulumiHome) |> ignore
            Directory.CreateDirectory(backendDirectory) |> ignore
            let repositoryRoot = findRepositoryRoot ()
            let configuration = DirectoryInfo(AppContext.BaseDirectory).Parent.Name
            let fixtureAssembly =
                Path.Combine(repositoryRoot, "tests", "Dorothy.TestFixture", "bin", configuration, "net10.0", "Dorothy.TestFixture.dll")
            if not (File.Exists(fixtureAssembly)) then
                Assert.Fail("The compiled Pulumi test fixture is missing: " + fixtureAssembly)
            let providerDirectory = Path.Combine(repositoryRoot, "src", "Dorothy.DSL.Providers", "bin", configuration, "net10.0")
            let providerExecutableName = if OperatingSystem.IsWindows() then "pulumi-resource-keroosha.exe" else "pulumi-resource-keroosha"
            let providerExecutable = Path.Combine(providerDirectory, providerExecutableName)
            if not (File.Exists(providerExecutable)) then
                Assert.Fail("The compiled Dorothy provider executable is missing: " + providerExecutable)
            let pluginDirectory = Path.Combine(pulumiHome, "plugins", "resource-keroosha-v0.1.0")
            copyDirectory providerDirectory pluginDirectory

            let yaml =
                String.concat "\n" [
                    "name: " + projectName
                    "runtime:"
                    "  name: dotnet"
                    "  options:"
                    "    binary: " + JsonSerializer.Serialize(fixtureAssembly)
                    ""
                ]
            File.WriteAllText(Path.Combine(projectDirectory, "Pulumi.yaml"), yaml)
            let init = runWith [ "stack"; "init"; stackName; "--secrets-provider"; "passphrase"; "--non-interactive" ] Map.empty
            if init.ExitCode <> 0 then
                Assert.Fail("Unable to initialize the temporary Pulumi stack.\n" + init.StandardOutput + init.StandardError)
            let setScenario = runWith [ "config"; "set"; "scenario"; "empty"; "--stack"; stackName; "--non-interactive" ] Map.empty
            if setScenario.ExitCode <> 0 then
                Assert.Fail("Unable to configure the temporary Pulumi stack.\n" + setScenario.StandardOutput + setScenario.StandardError)
            let baseline = runWith [ "up"; "--stack"; stackName; "--yes"; "--non-interactive"; "--color=never" ] Map.empty
            if baseline.ExitCode <> 0 then
                Assert.Fail("Unable to create the isolated Pulumi stack baseline.\n" + baseline.StandardOutput + baseline.StandardError)

        member _.Root = root
        member _.ProjectDirectory = projectDirectory
        member _.PulumiHome = pulumiHome
        member _.BackendDirectory = backendDirectory
        member _.StackName = stackName
        member _.ProjectName = projectName

        member _.RunWith(arguments: string list, overrides: Map<string, string>) = runWith arguments overrides

        member _.Run(arguments: string list) = runWith arguments Map.empty

        member this.RunSuccess(arguments: string list) =
            let result = this.Run(arguments)
            if result.ExitCode <> 0 then
                Assert.Fail(sprintf "Command failed (%d): pulumi %s\nstdout:\n%s\nstderr:\n%s" result.ExitCode (String.concat " " arguments) result.StandardOutput result.StandardError)
            result.StandardOutput

        member this.SetConfig(name: string, value: string) =
            this.RunSuccess([ "config"; "set"; name; value; "--stack"; stackName; "--non-interactive" ]) |> ignore


        member this.ExportCheckpoint() =
            let path = Path.Combine(root, "checkpoint.json")
            this.RunSuccess([ "stack"; "export"; "--stack"; stackName; "--file"; path ]) |> ignore
            JsonNode.Parse(File.ReadAllText(path)).AsObject()

        member this.ExportResources() =
            let checkpoint = this.ExportCheckpoint()
            let deploymentNode = checkpoint["deployment"]
            let deployment = deploymentNode.AsObject()
            let resourcesNode = deployment["resources"]
            resourcesNode.AsArray()

        member this.ImportCheckpoint(checkpoint: JsonObject) =
            let path = Path.Combine(root, "synthetic-checkpoint.json")
            let options = JsonSerializerOptions()
            options.WriteIndented <- true
            File.WriteAllText(path, checkpoint.ToJsonString(options))
            this.RunSuccess([ "stack"; "import"; "--stack"; stackName; "--file"; path ]) |> ignore

        member this.ReplaceResources(resources: JsonArray) =
            let checkpoint = this.ExportCheckpoint()
            checkpoint["version"] <- JsonValue.Create(3)
            let deploymentNode = checkpoint["deployment"]
            let deployment = deploymentNode.AsObject()
            deployment["resources"] <- resources
            this.ImportCheckpoint(checkpoint)


        interface IDisposable with
            member _.Dispose() = (temporary :> IDisposable).Dispose()
