namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.IO
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Text.RegularExpressions
open Dorothy.Tests.TestSupport
open NUnit.Framework

[<RequireQualifiedAccess>]
module private PulumiCliTestData =
    let private textValue (value: string) : JsonNode = JsonValue.Create(value) :> JsonNode
    let private boolValue (value: bool) : JsonNode = JsonValue.Create(value) :> JsonNode
    let private intValue (value: int) : JsonNode = JsonValue.Create(value) :> JsonNode

    let objectValue (entries: (string * JsonNode) list) =
        let value = JsonObject()
        for key, node in entries do value[key] <- node
        value

    let stringArray (values: seq<string>) =
        let value = JsonArray()
        for item in values do value.Add(textValue item)
        value

    let connection (address: string) (user: string) =
        objectValue [
            "address", textValue address
            "user", textValue user
            "port", intValue 22
        ]

    let private stackUrn (project: PulumiCliProject) =
        sprintf "urn:pulumi:%s::%s::pulumi:pulumi:Stack::%s-%s" project.StackName project.ProjectName project.ProjectName project.StackName

    let private providerUrn (project: PulumiCliProject) =
        sprintf "urn:pulumi:%s::%s::pulumi:providers:keroosha::default_0_1_0" project.StackName project.ProjectName

    let private resource
        (urn: string)
        (resourceType: string)
        (resourceId: string option)
        (parent: string option)
        (provider: string option)
        (dependencies: string list)
        (inputs: JsonObject)
        (outputs: JsonObject)
        =
        let value = JsonObject()
        value["urn"] <- textValue urn
        value["type"] <- textValue resourceType
        value["custom"] <- boolValue (resourceType <> "pulumi:pulumi:Stack")
        resourceId |> Option.iter (fun id -> value["id"] <- textValue id)
        parent |> Option.iter (fun item -> value["parent"] <- textValue item)
        provider |> Option.iter (fun item -> value["provider"] <- textValue item)
        if not dependencies.IsEmpty then value["dependencies"] <- stringArray dependencies
        value["inputs"] <- inputs
        value["outputs"] <- outputs
        value

    let private providerResource (project: PulumiCliProject) =
        let inputs = objectValue [ "version", textValue "0.1.0" ]
        let outputs = objectValue [ "version", textValue "0.1.0" ]
        resource (providerUrn project) "pulumi:providers:keroosha" (Some "00000000-0000-0000-0000-000000000001") None None [] inputs outputs

    let private packageMap (packages: Map<string, string option>) =
        let result = JsonObject()
        for KeyValue(name, version) in packages do
            let properties = JsonObject()
            version |> Option.iter (fun value -> properties["version"] <- textValue value)
            result[name] <- properties
        result

    let private installedVersions (packages: Map<string, string option>) =
        let result = JsonObject()
        for KeyValue(name, version) in packages do
            result[name] <- textValue (defaultArg version "1.0-1")
        result

    let private aptInputs (packages: Map<string, string option>) =
        objectValue [
            "connection", connection "192.0.2.1" "root"
            "packages", packageMap packages
        ]

    let private aptOutputs (packages: Map<string, string option>) =
        objectValue [
            "connection", connection "192.0.2.1" "root"
            "packages", packageMap packages
            "installedVersions", installedVersions packages
            "managedPackages", stringArray (packages |> Map.toList |> List.map fst)
        ]

    let private packageResource
        (project: PulumiCliProject)
        (parent: string)
        (provider: string)
        (id: string)
        (name: string)
        (packages: Map<string, string option>)
        (dependencies: string list)
        =
        let urn = sprintf "urn:pulumi:%s::%s::keroosha:debian:AptPackageSet::%s" project.StackName project.ProjectName name
        resource urn "keroosha:debian:AptPackageSet" (Some id) (Some parent) (Some provider) dependencies (aptInputs packages) (aptOutputs packages), urn

    let private initialResources (project: PulumiCliProject) =
        let checkpoint = project.ExportCheckpoint()
        let deploymentNode = checkpoint["deployment"]
        let deployment = deploymentNode.AsObject()
        let previousNode = deployment["resources"]
        let previous = previousNode.AsArray()
        if previous.Count = 0 then invalidOp "The initialized Pulumi stack checkpoint is missing its stack resource."
        let resources = JsonArray()
        let stackResourceNode = previous[0]
        resources.Add(stackResourceNode.DeepClone())
        resources.Add(providerResource project)
        resources

    let seedAptState (project: PulumiCliProject) (packages: Map<string, string option>) =
        let resources = initialResources project
        let stack = stackUrn project
        let provider = providerUrn project + "::00000000-0000-0000-0000-000000000001"
        let inputs = aptInputs packages
        let outputs = aptOutputs packages
        let urn = sprintf "urn:pulumi:%s::%s::keroosha:debian:AptPackageSet::sandbox" project.StackName project.ProjectName
        resources.Add(resource urn "keroosha:debian:AptPackageSet" (Some "synthetic-apt-fixture") (Some stack) (Some provider) [] inputs outputs)
        project.ReplaceResources(resources)

    let private ufwRules (port: int) =
        let rule (values: seq<string>) = stringArray values
        let result = JsonArray()
        result.Add(rule [ "allow"; "in"; "proto"; "tcp"; "to"; "any"; "port"; "22" ])
        result.Add(rule [ "allow"; "in"; "proto"; "tcp"; "to"; "any"; "port"; string port ])
        result

    let private ufwInputs (port: int) =
        objectValue [
            "connection", connection "192.0.2.1" "root"
            "rules", ufwRules port
            "enabled", boolValue true
            "defaultIn", textValue "deny"
            "defaultOut", textValue "allow"
        ]

    let private ufwOutputs (port: int) =
        objectValue [
            "connection", connection "192.0.2.1" "root"
            "rules", ufwRules port
            "enabled", boolValue true
            "defaultIn", textValue "deny"
            "defaultOut", textValue "allow"
            "actualRules", stringArray [ "22/tcp ALLOW IN Anywhere"; sprintf "%d/tcp ALLOW IN Anywhere" port ]
            "actualEnabled", boolValue true
            "actualDefaultIn", textValue "deny"
            "actualDefaultOut", textValue "allow"
            "inSync", boolValue true
        ]

    let seedUfwState (project: PulumiCliProject) (oldRulePort: int) =
        let resources = initialResources project
        let stack = stackUrn project
        let provider = providerUrn project + "::00000000-0000-0000-0000-000000000001"
        let emptyPackages: Map<string, string option> = Map.empty
        let mainPackage, mainUrn = packageResource project stack provider "synthetic-main-apt-fixture" "sandbox" emptyPackages []
        let firewallPackages = Map.ofList [ "ufw", None ]
        let firewallPackage, firewallPackageUrn =
            packageResource project stack provider "synthetic-ufw-package-fixture" "sandbox-ufw-package" firewallPackages [ mainUrn ]
        let firewallOutputsNode = firewallPackage["outputs"]
        let firewallOutputs = firewallOutputsNode.AsObject()
        let installedVersionsNode = firewallOutputs["installedVersions"]
        let installedVersions = installedVersionsNode.AsObject()
        installedVersions["ufw"] <- textValue "0.36.2-9"
        let firewallUrn = sprintf "urn:pulumi:%s::%s::keroosha:debian:Ufw::sandbox" project.StackName project.ProjectName
        let firewall =
            resource
                firewallUrn
                "keroosha:debian:Ufw"
                (Some "synthetic-ufw-fixture")
                (Some stack)
                (Some provider)
                [ mainUrn; firewallPackageUrn ]
                (ufwInputs oldRulePort)
                (ufwOutputs oldRulePort)
        resources.Add(mainPackage)
        resources.Add(firewallPackage)
        resources.Add(firewall)
        project.ReplaceResources(resources)


    let private traefikInputs (backend: string) (adminPort: int) (certificateMap: JsonNode) =
        let router =
            objectValue [
                "host", textValue "example.org"
                "entryPoint", textValue "websecure"
                "backend", textValue backend
                "tls", objectValue [ "kind", textValue "provided"; "name", textValue "example" ]
            ]
        objectValue [
            "connection", connection "192.0.2.1" "root"
            "entryPoints", objectValue [ "websecure", intValue 443 ]
            "resolvers", JsonObject()
            "routers", objectValue [ "example", router ]
            "certificates", certificateMap
            "adminPort", intValue adminPort
        ]

    let seedTraefikState (project: PulumiCliProject) (fixture: CertificateFixture) =
        let resources = initialResources project
        let stackResourceNode = resources[0]
        let previousStack = stackResourceNode.AsObject()
        let stackOutputsNode = previousStack["outputs"]
        let stackOutputs = stackOutputsNode.AsObject()
        let secretMapNode = stackOutputs["certificateMap"]
        let secretMap = secretMapNode.DeepClone()
        let stack = stackUrn project
        let provider = providerUrn project + "::00000000-0000-0000-0000-000000000001"
        let inputs = traefikInputs "http://127.0.0.1:12345" 19080 secretMap
        let outputsSecretMap = secretMapNode.DeepClone()
        let outputs = traefikInputs "http://127.0.0.1:12345" 19080 outputsSecretMap
        outputs["inSync"] <- boolValue true
        outputs["actualConfigHash"] <- textValue (String.replicate 64 "0")
        outputs["certificateFingerprints"] <- objectValue [ "example", textValue fixture.Fingerprint ]
        let urn = sprintf "urn:pulumi:%s::%s::keroosha:debian:Traefik::sandbox" project.StackName project.ProjectName
        resources.Add(resource urn "keroosha:debian:Traefik" (Some "synthetic-traefik-fixture") (Some stack) (Some provider) [] inputs outputs)
        project.ReplaceResources(resources)

    let base64Text (value: string) = Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
    let base64Bytes (value: byte array) = Convert.ToBase64String(value)

    let pemPayload (pem: string) =
        pem.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)[1]

    let tlsEnvironment (project: PulumiCliProject) =
        let inlineCert = TestSupport.createValidCertificateFixture "inline.example.test" [ "inline.example.test" ]
        let pem = TestSupport.createValidCertificateFixture "pem.example.test" [ "pem.example.test" ]
        let stream = TestSupport.createValidCertificateFixture "stream.example.test" [ "stream.example.test" ]
        let base64 = TestSupport.createValidCertificateFixture "base64.example.test" [ "base64.example.test" ]
        let wildcard = TestSupport.createValidCertificateFixture "wildcard.example.test" [ "*.wildcard.example.test" ]
        let wrongKey = TestSupport.createValidCertificateFixture "wrong.example.test" [ "wrong.example.test" ]
        let expired = TestSupport.createCertificateFixture "expired.example.test" [ "expired.example.test" ] (DateTimeOffset.UtcNow.AddDays(-60.0)) (DateTimeOffset.UtcNow.AddDays(-30.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let future = TestSupport.createCertificateFixture "future.example.test" [ "future.example.test" ] (DateTimeOffset.UtcNow.AddDays(30.0)) (DateTimeOffset.UtcNow.AddDays(60.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let clientAuth = TestSupport.createCertificateFixture "client.example.test" [ "client.example.test" ] (DateTimeOffset.UtcNow.AddDays(-1.0)) (DateTimeOffset.UtcNow.AddDays(30.0)) [ "1.3.6.1.5.5.7.3.2" ]
        let malformed = TestSupport.createValidCertificateFixture "malformed.example.test" [ "malformed.example.test" ]
        let multiKey = TestSupport.createMultiKeyPfx "multi-key-test-password"
        let environment =
            [
                "INLINE_CHAIN_B64", base64Text inlineCert.ChainPem
                "INLINE_KEY_B64", base64Text inlineCert.PrivateKeyPem
                "PEM_CHAIN_B64", base64Text pem.ChainPem
                "PEM_ENCRYPTED_KEY_B64", base64Text pem.EncryptedPrivateKeyPem
                "PEM_WRONG_KEY_B64", base64Text wrongKey.PrivateKeyPem
                "PEM_PASSWORD", pem.PfxPassword
                "PEM_HOST", "pem.example.test"
                "PEM_CERT_PATH", Path.Combine(project.Root, "lazy-certificate.pem")
                "PEM_EXPIRED_CHAIN_B64", base64Text expired.ChainPem
                "PEM_EXPIRED_KEY_B64", base64Text expired.PrivateKeyPem
                "PEM_FUTURE_CHAIN_B64", base64Text future.ChainPem
                "PEM_FUTURE_KEY_B64", base64Text future.PrivateKeyPem
                "PEM_CLIENT_AUTH_CHAIN_B64", base64Text clientAuth.ChainPem
                "PEM_CLIENT_AUTH_KEY_B64", base64Text clientAuth.PrivateKeyPem
                "MALFORMED_PEM_CHAIN_B64", base64Text (pem.ChainPem + malformed.LeafCertificatePem)
                "PEM_CHAIN_OVERRIDE_B64", ""
                "PFX_STREAM_B64", base64Bytes stream.PfxBytes
                "PFX_PASSWORD", stream.PfxPassword
                "PFX_BASE64_B64", base64Bytes base64.PfxBytes
                "PFX_BASE64_PASSWORD", base64.PfxPassword
                "PFX_WILDCARD_B64", base64Bytes wildcard.PfxBytes
                "PFX_WILDCARD_PASSWORD", wildcard.PfxPassword
                "PFX_MULTIPLE_B64", base64Bytes multiKey
                "STATUS_PATH", Path.Combine(project.Root, "tls-status.txt")
                "STREAM_MARKER_PATH", Path.Combine(project.Root, "stream-marker.txt")
                "CONFLICT_MODE", "off"
                "UNKNOWN_MODE", "off"
                "PEM_KEY_MODE", "encrypted"
                "PEM_PASSWORD_MODE", "valid"
                "PFX_PASSWORD_MODE", "valid"
            ]
            |> Map.ofList
        let fingerprints =
            [ "base64", base64.Fingerprint; "encrypted", pem.Fingerprint; "inline", inlineCert.Fingerprint; "stream", stream.Fingerprint; "wildcard", wildcard.Fingerprint ]
        environment, fingerprints

    let prepareTlsProject (project: PulumiCliProject) =
        project.SetConfig("scenario", "tls")
        let environment, fingerprints = tlsEnvironment project
        environment, fingerprints

    let previewArguments = [ "preview"; "--stack"; "integration"; "--diff"; "--refresh=false"; "--color=never"; "--non-interactive" ]

    let resourceOfType (resources: JsonArray) resourceType =
        resources
        |> Seq.cast<JsonObject>
        |> Seq.tryFind (fun value -> value["type"].GetValue<string>() = resourceType)

[<TestFixture>]
type PulumiCliTests() =
    [<Test>]
    member _.``Pulumi CLI preview shows package removals additions versions and punctuation``() =
        // Arrange
        use project = new PulumiCliProject()
        project.SetConfig("scenario", "apt")
        project.SetConfig("packages", "mc")
        PulumiCliTestData.seedAptState project (Map.ofList [ "htop", None; "mc", None ])

        // Act
        let removed = project.RunSuccess(PulumiCliTestData.previewArguments)
        project.SetConfig("packages", "htop,mc,jq")
        let added = project.RunSuccess(PulumiCliTestData.previewArguments)
        project.SetConfig("packages", "mc=4.8.34")
        PulumiCliTestData.seedAptState project (Map.ofList [ "mc", Some "4.8.33" ])
        let version = project.RunSuccess(PulumiCliTestData.previewArguments)
        project.SetConfig("packages", "mc,libfoo1.2")
        PulumiCliTestData.seedAptState project (Map.ofList [ "mc", None ])
        let punctuation = project.RunSuccess(PulumiCliTestData.previewArguments)

        // Assert
        Assert.That(Regex.IsMatch(removed, "(?m)^\\s*-\\s+htop\\s*:"), Is.True, removed)
        Assert.That(Regex.IsMatch(added, "(?m)^\\s*\\+\\s+jq\\s*:"), Is.True, added)
        Assert.That(Regex.IsMatch(version, "(?m)^\\s*~\\s+version\\s*:\\s*\"?4\\.8\\.33\"?\\s*=>\\s*\"?4\\.8\\.34\"?\\s*$"), Is.True, version)
        Assert.That(Regex.IsMatch(punctuation, "(?m)^\\s*\\+\\s+libfoo1\\.2\\s*:"), Is.True, punctuation)

    [<Test>]
    member _.``Pulumi CLI preview accepts an identical package set without changes``() =
        // Arrange
        use project = new PulumiCliProject()
        project.SetConfig("scenario", "apt")
        project.SetConfig("packages", "htop,mc")
        PulumiCliTestData.seedAptState project (Map.ofList [ "htop", None; "mc", None ])

        // Act
        let result = project.Run([ "preview"; "--stack"; project.StackName; "--expect-no-changes"; "--refresh=false"; "--color=never"; "--non-interactive" ])

        // Assert
        Assert.That(result.ExitCode, Is.EqualTo(0), result.StandardOutput + result.StandardError)

    [<Test>]
    member _.``Pulumi CLI preview shows UFW rule changes and identical policy is unchanged``() =
        // Arrange
        use project = new PulumiCliProject()
        project.SetConfig("scenario", "ufw")
        project.SetConfig("rulePort", "443")
        PulumiCliTestData.seedUfwState project 80

        // Act
        let changed = project.RunSuccess(PulumiCliTestData.previewArguments)
        PulumiCliTestData.seedUfwState project 443
        let unchanged = project.Run([ "preview"; "--stack"; project.StackName; "--expect-no-changes"; "--refresh=false"; "--color=never"; "--non-interactive" ])

        // Assert
        Assert.That(Regex.IsMatch(changed, "(?s)~\\s+rules(?:\\[\\d+\\])*\\s*:.*?\"?80\"?\\s*=>\\s*\"?443\"?"), Is.True, changed)
        Assert.That(unchanged.ExitCode, Is.EqualTo(0), unchanged.StandardOutput + unchanged.StandardError)

    [<Test>]
    member _.``Pulumi CLI rejects raw UFW comment rule without changing checkpoint``() =
        // Arrange
        use project = new PulumiCliProject()
        project.SetConfig("scenario", "ufw")
        project.SetConfig("rulePort", "443")
        PulumiCliTestData.seedUfwState project 80
        let before = project.ExportResources().ToJsonString()
        project.SetConfig("scenario", "ufw-raw")

        // Act
        let result = project.Run(PulumiCliTestData.previewArguments)
        let after = project.ExportResources().ToJsonString()

        // Assert
        Assert.That(result.ExitCode, Is.Not.EqualTo(0), result.StandardOutput + result.StandardError)
        Assert.That(after, Is.EqualTo(before))

    [<Test>]
    member _.``Pulumi CLI preview redacts TLS inputs and checkpoints their encrypted values``() =
        // Arrange
        use project = new PulumiCliProject()
        project.SetConfig("scenario", "seed-secret")
        let certificate = TestSupport.createValidCertificateFixture "example.org" [ "example.org" ]
        let certificatePayload = PulumiCliTestData.pemPayload certificate.LeafCertificatePem
        let privateKeyPayload = PulumiCliTestData.pemPayload certificate.PrivateKeyPem
        let secretEnvironment =
            Map.ofList [
                "TRAEFIK_CERTIFICATE_PEM_B64", PulumiCliTestData.base64Text certificate.ChainPem
                "TRAEFIK_PRIVATE_KEY_PEM_B64", PulumiCliTestData.base64Text certificate.PrivateKeyPem
                "TRAEFIK_CERTIFICATE_FINGERPRINT", certificate.Fingerprint
            ]
        project.RunWith([ "up"; "--stack"; project.StackName; "--yes"; "--non-interactive"; "--color=never" ], secretEnvironment)
        |> fun result -> Assert.That(result.ExitCode, Is.EqualTo(0), result.StandardOutput + result.StandardError)
        project.SetConfig("scenario", "traefik")
        project.SetConfig("backend", "http://127.0.0.1:12346")
        project.SetConfig("adminPort", "19081")
        PulumiCliTestData.seedTraefikState project certificate

        // Act
        let previewResult = project.RunWith(PulumiCliTestData.previewArguments, secretEnvironment)
        let output = previewResult.StandardOutput
        let resources = project.ExportResources()
        let traefikOption = PulumiCliTestData.resourceOfType resources "keroosha:debian:Traefik"
        Assert.That(Option.isSome traefikOption, Is.True)
        let traefik = Option.get traefikOption
        let serialized = resources.ToJsonString()

        // Assert
        Assert.That(previewResult.ExitCode, Is.EqualTo(0), previewResult.StandardOutput + previewResult.StandardError)
        Assert.That(output, Does.Contain("adminPort"))
        Assert.That(output, Does.Contain("routers"))
        Assert.That(output, Does.Contain("backend"))
        Assert.That(output, Does.Contain("19080"))
        Assert.That(output, Does.Contain("19081"))
        Assert.That(output, Does.Not.Contain(certificate.PrivateKeyPem))
        Assert.That(output, Does.Not.Contain(certificate.ChainPem))
        Assert.That(output, Does.Not.Contain(certificatePayload))
        Assert.That(output, Does.Not.Contain(privateKeyPayload))
        let traefikInputs = traefik["inputs"].AsObject()
        let certificateInputs = traefikInputs["certificates"]
        Assert.That(certificateInputs.ToJsonString(), Does.Contain("ciphertext"))
        Assert.That(serialized, Does.Not.Contain(certificate.PrivateKeyPem))
        Assert.That(serialized, Does.Not.Contain(certificate.ChainPem))
        Assert.That(serialized, Does.Not.Contain(certificatePayload))
        Assert.That(serialized, Does.Not.Contain(privateKeyPayload))

    [<Test>]
    member _.``Pulumi CLI preview of a new Traefik resource commits no state and discloses no TLS``() =
        // Arrange
        use project = new PulumiCliProject()
        project.SetConfig("scenario", "traefik")
        let certificate = TestSupport.createValidCertificateFixture "example.org" [ "example.org" ]
        let certificatePayload = PulumiCliTestData.pemPayload certificate.LeafCertificatePem
        let privateKeyPayload = PulumiCliTestData.pemPayload certificate.PrivateKeyPem
        let environment =
            Map.ofList [
                "TRAEFIK_CERTIFICATE_PEM_B64", PulumiCliTestData.base64Text certificate.ChainPem
                "TRAEFIK_PRIVATE_KEY_PEM_B64", PulumiCliTestData.base64Text certificate.PrivateKeyPem
                "TRAEFIK_CERTIFICATE_FINGERPRINT", certificate.Fingerprint
            ]

        // Act
        let result = project.RunWith(PulumiCliTestData.previewArguments, environment)
        let resources = project.ExportResources()

        // Assert
        Assert.That(result.ExitCode, Is.EqualTo(0), result.StandardOutput + result.StandardError)
        Assert.That(result.StandardOutput, Does.Contain("sandbox"))
        Assert.That(result.StandardOutput, Does.Not.Contain(certificate.PrivateKeyPem))
        Assert.That(result.StandardOutput, Does.Not.Contain(certificate.ChainPem))
        Assert.That(result.StandardOutput, Does.Not.Contain(certificatePayload))
        Assert.That(result.StandardOutput, Does.Not.Contain(privateKeyPayload))
        Assert.That(Option.isNone (PulumiCliTestData.resourceOfType resources "keroosha:debian:Traefik"), Is.True)

    [<Test>]
    member _.``Pulumi CLI preview preserves an unknown nested Traefik input``() =
        // Arrange
        use project = new PulumiCliProject()
        project.SetConfig("scenario", "traefik")
        let certificate = TestSupport.createValidCertificateFixture "example.org" [ "example.org" ]
        let certificatePayload = PulumiCliTestData.pemPayload certificate.LeafCertificatePem
        let privateKeyPayload = PulumiCliTestData.pemPayload certificate.PrivateKeyPem
        let environment =
            Map.ofList [
                "TRAEFIK_CERTIFICATE_PEM_B64", PulumiCliTestData.base64Text certificate.ChainPem
                "TRAEFIK_PRIVATE_KEY_PEM_B64", PulumiCliTestData.base64Text certificate.PrivateKeyPem
                "TRAEFIK_CERTIFICATE_FINGERPRINT", certificate.Fingerprint
                "UNKNOWN_ENTRYPOINT_MODE", "on"
            ]

        // Act
        let result = project.RunWith(PulumiCliTestData.previewArguments, environment)
        let resources = project.ExportResources()

        // Assert
        Assert.That(result.ExitCode, Is.EqualTo(0), result.StandardOutput + result.StandardError)
        Assert.That(result.StandardOutput, Does.Contain("sandbox"))
        Assert.That(result.StandardOutput, Does.Contain("unknown-entrypoint-source"))
        Assert.That(result.StandardOutput, Does.Not.Contain(certificate.PrivateKeyPem))
        Assert.That(result.StandardOutput, Does.Not.Contain(certificate.ChainPem))
        Assert.That(result.StandardOutput, Does.Not.Contain(certificatePayload))
        Assert.That(result.StandardOutput, Does.Not.Contain(privateKeyPayload))
        Assert.That(Option.isNone (PulumiCliTestData.resourceOfType resources "keroosha:debian:Traefik"), Is.True)

    [<Test>]
    member _.``Pulumi apply reaches the transport sentinel for valid TLS but not invalid TLS``() =
        // Arrange
        use project = new PulumiCliProject()
        project.SetConfig("scenario", "traefik")
        let certificate = TestSupport.createValidCertificateFixture "example.org" [ "example.org" ]
        let certificatePayload = PulumiCliTestData.pemPayload certificate.LeafCertificatePem
        let privateKeyPayload = PulumiCliTestData.pemPayload certificate.PrivateKeyPem
        let shimDirectory = Path.Combine(project.Root, "transport-sentinel")
        Directory.CreateDirectory(shimDirectory) |> ignore
        let marker = Path.Combine(project.Root, "ssh-invoked")
        let sshShim = Path.Combine(shimDirectory, "ssh")
        File.WriteAllText(sshShim, "#!/bin/sh\nprintf 'invoked\\n' > \"$KEROOSHA_TEST_SSH_MARKER\"\nexit 91\n")
        File.SetUnixFileMode(sshShim, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
        let baseEnvironment =
            Map.ofList [
                "TRAEFIK_CERTIFICATE_PEM_B64", PulumiCliTestData.base64Text certificate.ChainPem
                "TRAEFIK_PRIVATE_KEY_PEM_B64", PulumiCliTestData.base64Text certificate.PrivateKeyPem
                "TRAEFIK_CERTIFICATE_FINGERPRINT", certificate.Fingerprint
                "PATH", shimDirectory + string Path.PathSeparator + Environment.GetEnvironmentVariable("PATH")
                "KEROOSHA_TEST_SSH_MARKER", marker
            ]
        let applyArguments = [ "up"; "--stack"; project.StackName; "--yes"; "--skip-preview"; "--non-interactive"; "--color=never" ]

        // Act
        let validAttempt = project.RunWith(applyArguments, baseEnvironment)
        let validReachedTransport = File.Exists(marker)
        let validMarkerText = if File.Exists(marker) then File.ReadAllText(marker) else ""
        if File.Exists(marker) then File.Delete(marker)
        let invalidEnvironment = Map.add "TRAEFIK_PRIVATE_KEY_PEM_B64" (PulumiCliTestData.base64Text "invalid-test-private-key") baseEnvironment
        let invalidAttempt = project.RunWith(applyArguments, invalidEnvironment)
        let invalidReachedTransport = File.Exists(marker)
        let resources = project.ExportResources()
        let validText = validAttempt.StandardOutput + validAttempt.StandardError
        let invalidText = invalidAttempt.StandardOutput + invalidAttempt.StandardError

        // Assert
        Assert.That(validAttempt.ExitCode, Is.Not.EqualTo(0), validText)
        Assert.That(validMarkerText, Is.EqualTo("invoked\n"))
        Assert.That(validReachedTransport, Is.True, validText)
        Assert.That(invalidAttempt.ExitCode, Is.Not.EqualTo(0), invalidText)
        Assert.That(invalidReachedTransport, Is.False, "Invalid TLS reached the SSH transport sentinel.")
        Assert.That(validText, Does.Not.Contain(certificate.PrivateKeyPem))
        Assert.That(validText, Does.Not.Contain(certificate.ChainPem))
        Assert.That(invalidText, Does.Not.Contain("invalid-test-private-key"))
        Assert.That(validText, Does.Not.Contain(certificatePayload))
        Assert.That(validText, Does.Not.Contain(privateKeyPayload))
        Assert.That(invalidText, Does.Not.Contain(certificatePayload))
        Assert.That(Option.isNone (PulumiCliTestData.resourceOfType resources "keroosha:debian:Traefik"), Is.True)

    [<Test>]
    member _.``Pulumi TLS preview resolves deferred sources and disposes its stream``() =
        // Arrange
        use project = new PulumiCliProject()
        let environment, fingerprints = PulumiCliTestData.prepareTlsProject project
        let statusPath = environment["STATUS_PATH"]
        let streamMarkerPath = environment["STREAM_MARKER_PATH"]
        let pemChain = Encoding.UTF8.GetString(Convert.FromBase64String(environment["PEM_CHAIN_B64"]))
        let encryptedPrivateKey = Encoding.UTF8.GetString(Convert.FromBase64String(environment["PEM_ENCRYPTED_KEY_B64"]))
        let certificatePayload = PulumiCliTestData.pemPayload pemChain
        let privateKeyPayload = PulumiCliTestData.pemPayload encryptedPrivateKey

        // Act
        let result = project.RunWith([ "preview"; "--stack"; project.StackName; "--refresh=false"; "--color=never"; "--non-interactive" ], environment)
        let status = if File.Exists(statusPath) then File.ReadAllText(statusPath) else ""
        let streamMarker = if File.Exists(streamMarkerPath) then File.ReadAllText(streamMarkerPath) else ""
        let expectedStatus = "1|1|" + (fingerprints |> List.map (fun (name, fingerprint) -> name + "=" + fingerprint) |> String.concat ",")

        // Assert
        Assert.That(result.ExitCode, Is.EqualTo(0), result.StandardOutput + result.StandardError)
        Assert.That(File.Exists(environment["PEM_CERT_PATH"]), Is.True)
        Assert.That(status, Is.EqualTo(expectedStatus))
        Assert.That(streamMarker, Is.EqualTo("opened;disposed;"))
        Assert.That(result.StandardOutput + result.StandardError, Does.Not.Contain("BEGIN PRIVATE KEY"))
        Assert.That(result.StandardOutput + result.StandardError, Does.Not.Contain(certificatePayload))
        Assert.That(result.StandardOutput + result.StandardError, Does.Not.Contain(privateKeyPayload))

    [<Test>]
    member _.``Pulumi TLS preview rejects bad passwords and ambiguous PKCS12 keys without leaking secrets``() =
        // Arrange
        use project = new PulumiCliProject()
        let environment, _ = PulumiCliTestData.prepareTlsProject project
        let scenarios = [
            Map.ofList [ "PEM_PASSWORD_MODE", "wrong"; "PEM_PASSWORD", "not-the-password" ]
            Map.ofList [ "PEM_PASSWORD_MODE", "missing" ]
            Map.ofList [ "PFX_PASSWORD_MODE", "wrong"; "PFX_PASSWORD", "not-the-password" ]
            Map.ofList [ "PFX_PASSWORD_MODE", "missing" ]
            Map.ofList [ "PFX_PASSWORD_MODE", "multiple" ]
        ]

        // Act
        let results =
            scenarios
            |> List.map (fun overrides ->
                let statusPath = environment["STATUS_PATH"]
                let pemPath = environment["PEM_CERT_PATH"]
                let streamMarkerPath = environment["STREAM_MARKER_PATH"]
                if File.Exists(statusPath) then File.Delete(statusPath)
                if File.Exists(pemPath) then File.Delete(pemPath)
                if File.Exists(streamMarkerPath) then File.Delete(streamMarkerPath)
                let settings = Map.fold (fun state key value -> Map.add key value state) environment overrides
                let result = project.RunWith([ "preview"; "--stack"; project.StackName; "--refresh=false"; "--color=never"; "--non-interactive" ], settings)
                result, File.Exists(pemPath), File.Exists(statusPath), overrides)

        // Assert
        for result, reachedCertificateResolution, wroteStatus, overrides in results do
            let output = result.StandardOutput + result.StandardError
            Assert.That(result.ExitCode, Is.Not.EqualTo(0), output)
            Assert.That(reachedCertificateResolution, Is.True, "The program did not reach local certificate resolution.")
            Assert.That(wroteStatus, Is.False, "Failed certificate preflight wrote a successful status marker.")
            Assert.That(output, Does.Not.Contain("BEGIN PRIVATE KEY"))
            Assert.That(output, Does.Not.Contain(environment["PEM_PASSWORD"]))
            match Map.tryFind "PEM_PASSWORD" overrides, Map.tryFind "PFX_PASSWORD" overrides with
            | Some secret, _ -> Assert.That(output, Does.Not.Contain(secret))
            | _, Some secret -> Assert.That(output, Does.Not.Contain(secret))
            | _ when Map.tryFind "PFX_PASSWORD_MODE" overrides = Some "multiple" ->
                Assert.That(output, Does.Not.Contain("multi-key-test-password"))
            | _ -> ()

    [<Test>]
    member _.``Pulumi TLS preview rejects key host domain validity EKU and chain mismatches``() =
        // Arrange
        use project = new PulumiCliProject()
        let environment, _ = PulumiCliTestData.prepareTlsProject project
        let scenarios = [
            Map.ofList [ "PEM_KEY_MODE", "wrong" ]
            Map.ofList [ "PEM_HOST", "other.example.test" ]
            Map.ofList [ "CONFLICT_MODE", "on" ]
            Map.ofList [ "PEM_KEY_MODE", "expired" ]
            Map.ofList [ "PEM_KEY_MODE", "future" ]
            Map.ofList [ "PEM_KEY_MODE", "client-auth" ]
            Map.empty |> Map.add "PEM_CHAIN_OVERRIDE_B64" environment["MALFORMED_PEM_CHAIN_B64"]
        ]

        // Act
        let results =
            scenarios
            |> List.map (fun overrides ->
                let statusPath = environment["STATUS_PATH"]
                let pemPath = environment["PEM_CERT_PATH"]
                let streamMarkerPath = environment["STREAM_MARKER_PATH"]
                if File.Exists(statusPath) then File.Delete(statusPath)
                if File.Exists(pemPath) then File.Delete(pemPath)
                if File.Exists(streamMarkerPath) then File.Delete(streamMarkerPath)
                let settings = Map.fold (fun state key value -> Map.add key value state) environment overrides
                let result = project.RunWith([ "preview"; "--stack"; project.StackName; "--refresh=false"; "--color=never"; "--non-interactive" ], settings)
                result, File.Exists(pemPath), File.Exists(statusPath))

        // Assert
        for result, reachedCertificateResolution, wroteStatus in results do
            let output = result.StandardOutput + result.StandardError
            Assert.That(result.ExitCode, Is.Not.EqualTo(0), output)
            Assert.That(reachedCertificateResolution, Is.True, "The program did not reach local certificate resolution.")
            Assert.That(wroteStatus, Is.False, "Failed certificate preflight wrote a successful status marker.")
            Assert.That(output, Does.Not.Contain("BEGIN PRIVATE KEY"))
            Assert.That(output, Does.Not.Contain(environment["PEM_PASSWORD"]))

    [<Test>]
    member _.``Pulumi TLS preview defers unknown secret output and never opens its stream``() =
        // Arrange
        use project = new PulumiCliProject()
        let environment, _ = PulumiCliTestData.prepareTlsProject project
        let statusPath = environment["STATUS_PATH"]
        let streamMarkerPath = environment["STREAM_MARKER_PATH"]
        let unknownEnvironment = environment |> Map.add "UNKNOWN_MODE" "on"

        // Act
        let result = project.RunWith([ "preview"; "--stack"; project.StackName; "--refresh=false"; "--color=never"; "--non-interactive" ], unknownEnvironment)

        // Assert
        Assert.That(result.ExitCode, Is.EqualTo(0), result.StandardOutput + result.StandardError)
        Assert.That(File.Exists(environment["PEM_CERT_PATH"]), Is.True)
        Assert.That(File.Exists(streamMarkerPath), Is.False)
        Assert.That(File.Exists(statusPath), Is.False)
