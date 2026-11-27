namespace Dorothy.Tests

open System
open System.Collections.Immutable
open System.Threading
open System.IO
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.DSL.Provider
open Dorothy.HostHelper
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private AptTestHelpers =
    let packageState status version essential protectedPackage =
        let record =
            { BinaryName = "hello"
              Name = "hello"
              Architecture = "amd64"
              Status = status
              Version = version
              Essential = essential
              Protected = protectedPackage }

        { NativeArchitecture = "amd64"
          Records = Map.ofList [ record.BinaryName, record ]
          ByName = Map.ofList [ record.Name, [ record ] ] }

    let parseRequest (requestText: string) : JsonDocument =
        JsonDocument.Parse(requestText)

    let readManagedPackages (response: JsonNode) =
        response["managedPackages"].AsArray()
        |> Seq.map (fun item -> item.GetValue<string>())
        |> Seq.toArray

    let createRecoveryEnvironment () =
        let root = Path.Combine(Path.GetTempPath(), "keroosha-apt-test-" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory(root) |> ignore

        let pathEnvironment =
            { Root = root
              Run = (fun _ _ _ -> { ExitCode = 0; Stdout = ""; Stderr = "" })
              UtcNow = fun () -> DateTimeOffset.UtcNow }

        let mapped logicalPath = HostEnvironment.path pathEnvironment logicalPath
        let osRelease = mapped "/etc/os-release"
        Directory.CreateDirectory(Path.GetDirectoryName(osRelease)) |> ignore
        File.WriteAllText(osRelease, "ID=debian\n")
        Directory.CreateDirectory(mapped "/run/lock") |> ignore

        let success stdout =
            { ExitCode = 0
              Stdout = stdout
              Stderr = "" }

        let failure stderr =
            { ExitCode = 42
              Stdout = ""
              Stderr = stderr }

        let run executable arguments _stdin =
            match executable, arguments with
            | "dpkg", [ "--print-architecture" ] -> success "amd64\n"
            | "dpkg-query", _ -> success ""
            | "apt-get", args when List.contains "update" args -> success ""
            | "apt-cache", [ "show"; "hello" ] -> success "Package: hello\nVersion: 2.10-5\n"
            | "apt-get", args when List.contains "-s" args -> success "Inst hello (2.10-5 Debian:13 [amd64])\n"
            | "apt-get", args when List.contains "-y" args -> failure "simulated interruption after durable ownership journal"
            | _ -> failure (sprintf "unexpected test command: %s %s" executable (String.concat " " arguments))

        let environment =
            { Root = root
              Run = run
              UtcNow = fun () -> DateTimeOffset.UtcNow }

        root, environment

    let dockerBootstrapVersion = "26.1.5+dfsg1-9+deb13u1+b1"

    let dockerApplyRequest (desiredVersion: string option) (strictFlag: bool option) =
        let versionJson =
            match desiredVersion with
            | Some version -> JsonSerializer.Serialize(version)
            | None -> "null"

        let strictJson =
            match strictFlag with
            | Some value -> ",\"strictDockerBootstrap\":" + value.ToString().ToLowerInvariant()
            | None -> ""

        parseRequest
            (sprintf
                """{"operation":"apply","ownerId":"owner","previousNames":[],"desiredVersions":{"docker.io":%s}%s}"""
                versionJson
                strictJson)

    let private createDockerEnvironment (simulationBeforeUpdate: string) (simulationAfterUpdate: string) =
        let root = Path.Combine(Path.GetTempPath(), "keroosha-apt-docker-test-" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory(root) |> ignore
        let osRelease = Path.Combine(root, "etc", "os-release")
        Directory.CreateDirectory(Path.GetDirectoryName(osRelease)) |> ignore
        File.WriteAllText(osRelease, "ID=debian\n")
        Directory.CreateDirectory(Path.Combine(root, "run", "lock")) |> ignore
        let commands = ResizeArray<string * string list>()
        let mutable indexesUpdated = false
        let mutable dockerInstalled = false
        let success stdout =
            { ExitCode = 0
              Stdout = stdout
              Stderr = "" }
        let failure stderr =
            { ExitCode = 42
              Stdout = ""
              Stderr = stderr }
        let run executable arguments _stdin =
            commands.Add((executable, arguments))
            match executable, arguments with
            | "dpkg", [ "--print-architecture" ] -> success "amd64\n"
            | "dpkg", [ "--compare-versions"; _; "lt"; _ ] -> { ExitCode = 1; Stdout = ""; Stderr = "" }
            | "dpkg-query", _ ->
                if dockerInstalled then
                    success ("docker.io\tamd64\tii \t" + dockerBootstrapVersion + "\tno\tno\n")
                else
                    success ""
            | "apt-get", args when List.contains "update" args ->
                indexesUpdated <- true
                success ""
            | "apt-cache", [ "show"; name ] ->
                let versions =
                    if name = "docker.io" then
                        if indexesUpdated then [ dockerBootstrapVersion; "26.1.5+dfsg1-9" ]
                        else [ "26.1.5+dfsg1-9" ]
                    else
                        [ "1.0-1" ]

                versions
                |> List.map (fun version -> "Package: " + name + "\nVersion: " + version)
                |> String.concat "\n\n"
                |> success
            | "apt-get", args when List.contains "-s" args ->
                success (if indexesUpdated then simulationAfterUpdate else simulationBeforeUpdate)
            | "apt-get", args when List.contains "-y" args ->
                dockerInstalled <-
                    args
                    |> List.exists (fun argument ->
                        argument = "docker.io"
                        || argument.StartsWith("docker.io=", StringComparison.Ordinal))
                success ""
            | _ -> failure (sprintf "unexpected test command: %s %s" executable (String.concat " " arguments))
        let environment =
            { Root = root
              Run = run
              UtcNow = fun () -> DateTimeOffset.UtcNow }
        root, environment, commands

    let withDockerEnvironment simulationBeforeUpdate simulationAfterUpdate action =
        let root, environment, commands =
            createDockerEnvironment simulationBeforeUpdate simulationAfterUpdate

        try
            action environment commands
        finally
            if Directory.Exists(root) then
                Directory.Delete(root, true)

[<RequireQualifiedAccess>]
module private AptProviderTestValues =
    let map (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do
            builder.Add(key, value)
        PropertyValue(builder.ToImmutable())

    let inputMap (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do
            builder.Add(key, value)
        builder.ToImmutable()

    let array (values: seq<PropertyValue>) = PropertyValue(ImmutableArray.CreateRange(values))
    let text (value: string) = PropertyValue(value)
    let boolean (value: bool) = PropertyValue(value)
    let emptyMap = map Seq.empty

    let connection address =
        map [
            "address", text address
            "user", text "root"
        ]

    let inputs (strictDockerBootstrap: bool option) =
        let entries = [
            "connection", connection "192.0.2.10"
            "packages", map [ "nginx", emptyMap ]
        ]
        let entries =
            match strictDockerBootstrap with
            | Some value -> ("strictDockerBootstrap", boolean value) :: entries
            | None -> entries
        inputMap entries

    let urn = Pulumi.Urn("urn:pulumi:unit::unit::keroosha:debian:AptPackageSet::apt-provider-test")

    let check (provider: DorothyProvider) inputs =
        let request =
            CheckRequest(
                urn,
                ImmutableDictionary<string, PropertyValue>.Empty,
                inputs,
                ImmutableArray<byte>.Empty
            )
        provider.Check(request, CancellationToken.None).GetAwaiter().GetResult()

    let diff (provider: DorothyProvider) oldInputs newInputs =
        let oldOutputs =
            inputMap [
                "installedVersions", emptyMap
                "managedPackages", array [ text "nginx" ]
            ]
        let request =
            DiffRequest(
                urn,
                "apt-provider-test",
                oldOutputs,
                newInputs,
                ImmutableArray<string>.Empty,
                oldInputs
            )
        provider.Diff(request, CancellationToken.None).GetAwaiter().GetResult()


[<TestFixture>]
type AptTests() =
    [<Test>]
    member _.``Held installed packages remain present``() =
        // Arrange
        let state = AptTestHelpers.packageState "hi " "2.10-5" false false
        let expected: Map<string, string> = Map.ofList [ "hello", "2.10-5" ]

        // Act
        let installed = Apt.installedMap state [ "hello" ]

        // Assert
        Assert.That(installed, Is.EqualTo(box expected))

    [<Test>]
    member _.``Reinstallation-required package is not healthy``() =
        // Arrange
        let state = AptTestHelpers.packageState "iiR" "2.10-5" false false

        // Act
        let action = TestDelegate(fun () -> Apt.installedMap state [ "hello" ] |> ignore)

        // Assert
        Assert.Throws<BackendError>(action) |> ignore

    [<Test>]
    member _.``Residual configuration is not installed``() =
        // Arrange
        let state = AptTestHelpers.packageState "rc " "2.10-5" false false

        // Act
        let installed = Apt.installedMap state [ "hello" ]

        // Assert
        Assert.That(installed, Is.Empty)

    [<Test>]
    member _.``Keeping an unpinned installed package does not request an upgrade``() =
        // Arrange
        let state = AptTestHelpers.packageState "ii " "2.10-5" false false
        let desired = Map.ofList [ "hello", None ]

        // Act
        let plan = Apt.planTransaction [ "hello" ] desired state

        // Assert
        Assert.That(plan.Installs, Is.Empty)
        Assert.That(plan.Removals, Is.Empty)
        Assert.That(plan.Arguments, Is.Empty)

    [<Test>]
    member _.``Only previously owned installed packages are removed``() =
        // Arrange
        let state = AptTestHelpers.packageState "ii " "2.10-5" false false
        let expectedRemovals: string list = [ "hello" ]
        let expectedArguments: string list = [ "hello-" ]

        // Act
        let unmanagedPlan = Apt.planTransaction [] Map.empty state
        let ownedPlan = Apt.planTransaction [ "hello" ] Map.empty state

        // Assert
        Assert.That(unmanagedPlan.Arguments, Is.Empty)
        Assert.That(ownedPlan.Removals, Is.EqualTo(box expectedRemovals))
        Assert.That(ownedPlan.Arguments, Is.EqualTo(box expectedArguments))

    [<Test>]
    member _.``Reverse dependency removal outside ownership is rejected``() =
        // Arrange
        let desired = Map.empty<string, string option>
        let output = "Remv hello [2.10-5]\nRemv sl [5.02-1]\n"

        // Act
        let action =
            TestDelegate(fun () ->
                Apt.validateSimulation (fun _ _ -> false) output [ "hello" ] desired |> ignore)

        // Assert
        Assert.Throws<BackendError>(action) |> ignore

    [<Test>]
    member _.``Unrequested package upgrade is rejected``() =
        // Arrange
        let desired = Map.ofList [ "hello", None ]
        let output = "Inst hello [2.10-4] (2.10-5 Debian:13 [amd64])\n"

        // Act
        let action =
            TestDelegate(fun () ->
                Apt.validateSimulation (fun _ _ -> false) output [] desired |> ignore)

        // Assert
        Assert.Throws<BackendError>(action) |> ignore

    [<Test>]
    member _.``Exact version change is expressed as an install``() =
        // Arrange
        let state = AptTestHelpers.packageState "ii " "2.10-5" false false
        let desired = Map.ofList [ "hello", Some "2.10-4" ]
        let expectedInstalls: (string * string option) list = [ "hello", Some "2.10-4" ]
        let expectedArguments: string list = [ "hello=2.10-4" ]

        // Act
        let plan = Apt.planTransaction [ "hello" ] desired state

        // Assert
        Assert.That(plan.Installs, Is.EqualTo(box expectedInstalls))
        Assert.That(plan.Removals, Is.Empty)
        Assert.That(plan.Arguments, Is.EqualTo(box expectedArguments))

    [<Test>]
    member _.``Essential package cannot be removed``() =
        // Arrange
        let state = AptTestHelpers.packageState "ii " "2.10-5" true false

        // Act
        let action = TestDelegate(fun () -> Apt.planTransaction [ "hello" ] Map.empty state |> ignore)

        // Assert
        Assert.Throws<BackendError>(action) |> ignore

    [<Test>]
    member _.``Protected package cannot be removed``() =
        // Arrange
        let state = AptTestHelpers.packageState "ii " "2.10-5" false true

        // Act
        let action = TestDelegate(fun () -> Apt.planTransaction [ "hello" ] Map.empty state |> ignore)

        // Assert
        Assert.Throws<BackendError>(action) |> ignore

    [<Test>]
    member _.``Simulation refuses to remove an essential package``() =
        // Arrange
        let state = AptTestHelpers.packageState "ii " "2.10-5" true false
        let output = "Remv hello [2.10-5]\n"

        // Act
        let action = TestDelegate(fun () -> Apt.validateSimulatedProtection output state)

        // Assert
        Assert.Throws<BackendError>(action) |> ignore

    [<Test>]
    member _.``Transaction verification rejects an unmanaged removal``() =
        // Arrange
        let before = AptTestHelpers.packageState "ii " "2.10-5" false false

        let after =
            { NativeArchitecture = "amd64"
              Records = Map.empty
              ByName = Map.empty }

        // Act
        let action = TestDelegate(fun () -> Apt.verifyTransaction before after Map.empty [])

        // Assert
        Assert.Throws<BackendError>(action) |> ignore

    [<Test>]
    member _.``Exact requested downgrade is enabled in the transaction``() =
        // Arrange
        let desired = Map.ofList [ "hello", Some "2.10-4" ]
        let output = "Inst hello [2.10-5] (2.10-4 Debian:13 [amd64])\n"

        // Act
        let allowDowngrades = Apt.validateSimulation (fun _ _ -> true) output [] desired

        // Assert
        Assert.That(allowDowngrades, Is.True)

    [<TestCase("a")>]
    [<TestCase("Hello")>]
    [<TestCase("hello:amd64")>]
    [<TestCase("hello/unsafe")>]
    member _.``Invalid package names are rejected``(name: string) =
        // Arrange
        let packageName = name
        // Act
        let action = TestDelegate(fun () -> Apt.validatePackageName packageName |> ignore)

        // Assert
        Assert.Throws<BackendError>(action) |> ignore

    [<Test>]
    member _.``Unsafe exact Debian versions are rejected before host access``() =
        // Arrange
        let commandCalls = ResizeArray<string>()

        let environment =
            { Root = "/"
              Run = (fun executable _ _ ->
                  commandCalls.Add(executable)
                  { ExitCode = 0; Stdout = ""; Stderr = "" })
              UtcNow = fun () -> DateTimeOffset.UtcNow }

        let request =
            AptTestHelpers.parseRequest
                """{"operation":"apply","ownerId":"owner","previousNames":[],"desiredVersions":{"hello":"1;touch /tmp/unexpected"}}"""

        // Act
        let action = TestDelegate(fun () -> Apt.handle environment request.RootElement |> ignore)

        // Assert
        Assert.Throws<BackendError>(action) |> ignore
        Assert.That(commandCalls, Is.Empty)


    [<Test>]
    member _.``Failed install retains attempted ownership for the next read``() =
        // Arrange
        let root, environment = AptTestHelpers.createRecoveryEnvironment ()

        try
            let applyRequest =
                AptTestHelpers.parseRequest
                    """{"operation":"apply","ownerId":"owner","previousNames":[],"desiredVersions":{"hello":null}}"""

            let readRequest =
                AptTestHelpers.parseRequest
                    """{"operation":"read","ownerId":"owner","names":[]}"""
            let expectedManagedPackages: string array = [| "hello" |]
            let recoveredResponses = ResizeArray<JsonNode>()

            // Act
            let action =
                TestDelegate(fun () ->
                    try
                        Apt.handle environment applyRequest.RootElement |> ignore
                    with :? BackendError ->
                        recoveredResponses.Add(Apt.handle environment readRequest.RootElement)
                        reraise ())

            // Assert
            Assert.Throws<BackendError>(action) |> ignore
            Assert.That(recoveredResponses.Count, Is.EqualTo(1))
            let recovered = recoveredResponses[0]
            let managedPackages = AptTestHelpers.readManagedPackages recovered
            Assert.That(managedPackages, Is.EqualTo(box expectedManagedPackages))
            Assert.That(recovered["installedVersions"].AsObject(), Is.Empty)
        finally
            Directory.Delete(root, true)

    [<Test>]
    member _.``Strict cold Docker bootstrap pins the post-update solver selection``() =
        let beforeUpdate = "Inst docker.io (26.1.5+dfsg1-9 Debian:12 [amd64])\n"
        let afterUpdate = "Inst docker.io (26.1.5+dfsg1-9+deb13u1+b1 Debian:13 [amd64])\n"

        AptTestHelpers.withDockerEnvironment beforeUpdate afterUpdate (fun environment commands ->
            use request = AptTestHelpers.dockerApplyRequest None (Some true)
            Apt.handle environment request.RootElement |> ignore

            let entries = commands |> Seq.toArray
            let updateIndex =
                entries
                |> Array.findIndex (fun (executable, arguments) ->
                    executable = "apt-get" && List.contains "update" arguments)
            let simulationIndex =
                entries
                |> Array.findIndex (fun (executable, arguments) ->
                    executable = "apt-get" && List.contains "-s" arguments)
            let installArguments =
                entries
                |> Array.find (fun (executable, arguments) ->
                    executable = "apt-get" && List.contains "-y" arguments)
                |> snd
            let qualifiedArgument = "docker.io=" + AptTestHelpers.dockerBootstrapVersion

            Assert.That(updateIndex < simulationIndex, Is.True)
            Assert.That(installArguments |> List.contains qualifiedArgument, Is.True)
            Assert.That(installArguments |> List.contains "docker.io", Is.False)
            Assert.That(installArguments |> List.contains "--no-remove", Is.True))

    [<Test>]
    member _.``Strict cold Docker bootstrap preserves a matching explicit version``() =
        let selected = "Inst docker.io (26.1.5+dfsg1-9+deb13u1+b1 Debian:13 [amd64])\n"

        AptTestHelpers.withDockerEnvironment selected selected (fun environment commands ->
            use request =
                AptTestHelpers.dockerApplyRequest (Some AptTestHelpers.dockerBootstrapVersion) (Some true)
            Apt.handle environment request.RootElement |> ignore

            let installArguments =
                commands
                |> Seq.find (fun (executable, arguments) ->
                    executable = "apt-get" && List.contains "-y" arguments)
                |> snd
            Assert.That(installArguments |> List.contains ("docker.io=" + AptTestHelpers.dockerBootstrapVersion), Is.True))

    [<Test>]
    member _.``Strict cold Docker bootstrap rejects unsupported or mismatched simulation selections before writes``() =
        let unsupported =
            "Inst docker.io (28.0.0-1 Debian:13 [amd64])\n"
        let wrongArchitecture =
            "Inst docker.io (26.1.5+dfsg1-9+deb13u1+b1 Debian:13 [arm64])\n"
        let missing = "Inst unrelated-package (1.0-1 Debian:13 [amd64])\n"

        for simulation in [ unsupported; wrongArchitecture; missing ] do
            AptTestHelpers.withDockerEnvironment simulation simulation (fun environment commands ->
                use request = AptTestHelpers.dockerApplyRequest None (Some true)
                Assert.Throws<BackendError>(TestDelegate(fun () -> Apt.handle environment request.RootElement |> ignore))
                |> ignore

                Assert.That(
                    commands
                    |> Seq.exists (fun (executable, arguments) ->
                        executable = "apt-get" && List.contains "-y" arguments),
                    Is.False)
                let journalDirectory = HostEnvironment.path environment "/var/lib/keroosha-iac/apt"
                Assert.That(Directory.Exists(journalDirectory), Is.False))

    [<Test>]
    member _.``Strict cold Docker bootstrap refuses a solver version different from an explicit pin``() =
        let selected = "Inst docker.io (26.1.5+dfsg1-9+deb13u1+b1 Debian:13 [amd64])\n"

        AptTestHelpers.withDockerEnvironment selected selected (fun environment commands ->
            use request = AptTestHelpers.dockerApplyRequest (Some "26.1.5+dfsg1-9") (Some true)
            Assert.Throws<BackendError>(TestDelegate(fun () -> Apt.handle environment request.RootElement |> ignore))
            |> ignore

            Assert.That(
                commands
                |> Seq.exists (fun (executable, arguments) ->
                    executable = "apt-get" && List.contains "-y" arguments),
                Is.False)
            let journalDirectory = HostEnvironment.path environment "/var/lib/keroosha-iac/apt"
            Assert.That(Directory.Exists(journalDirectory), Is.False))

    [<Test>]
    member _.``Strict cold Docker bootstrap refuses indirect installation without direct ownership``() =
        let simulation =
            "Inst hello (1.0-1 Debian:13 [amd64])\n"
            + "Inst docker.io (26.1.5+dfsg1-9+deb13u1+b1 Debian:13 [amd64])\n"

        AptTestHelpers.withDockerEnvironment simulation simulation (fun environment commands ->
            use request =
                AptTestHelpers.parseRequest
                    """{"operation":"apply","ownerId":"owner","previousNames":[],"desiredVersions":{"hello":null},"strictDockerBootstrap":true}"""
            Assert.Throws<BackendError>(TestDelegate(fun () -> Apt.handle environment request.RootElement |> ignore))
            |> ignore

            Assert.That(
                commands
                |> Seq.exists (fun (executable, arguments) ->
                    executable = "apt-get" && List.contains "-y" arguments),
                Is.False)
            let journalDirectory = HostEnvironment.path environment "/var/lib/keroosha-iac/apt"
            Assert.That(Directory.Exists(journalDirectory), Is.False))

    [<Test>]
    member _.``Absent strict Docker bootstrap flag keeps unqualified APT install semantics``() =
        let selected = "Inst docker.io (26.1.5+dfsg1-9+deb13u1+b1 Debian:13 [amd64])\n"

        AptTestHelpers.withDockerEnvironment selected selected (fun environment commands ->
            use request = AptTestHelpers.dockerApplyRequest None None
            Apt.handle environment request.RootElement |> ignore

            let installArguments =
                commands
                |> Seq.find (fun (executable, arguments) ->
                    executable = "apt-get" && List.contains "-y" arguments)
                |> snd
            Assert.That(installArguments |> List.contains "docker.io", Is.True)
            Assert.That(
                installArguments
                |> List.exists (fun argument -> argument.StartsWith("docker.io=", StringComparison.Ordinal)),
                Is.False))

[<TestFixture>]
type AptProviderTests() =
    [<Test>]
    member _.``Combined provider schema exposes optional strict Docker bootstrap inputs and outputs``() =
        let response =
            DorothyProvider().GetSchema(GetSchemaRequest(0, "", ""), CancellationToken.None).GetAwaiter().GetResult()
        use schema = JsonDocument.Parse(response.Schema)
        let resources = schema.RootElement.GetProperty("resources")
        let aptPackageSet = resources.GetProperty("keroosha:debian:AptPackageSet")
        let inputFlag = aptPackageSet.GetProperty("inputProperties").GetProperty("strictDockerBootstrap")
        let outputFlag = aptPackageSet.GetProperty("properties").GetProperty("strictDockerBootstrap")
        let requiredInputs = aptPackageSet.GetProperty("requiredInputs")
        let required = aptPackageSet.GetProperty("required")
        let names (values: JsonElement) =
            values.EnumerateArray() |> Seq.map _.GetString() |> Seq.toArray

        Assert.That(inputFlag.GetProperty("type").ValueEquals("boolean"), Is.True)
        Assert.That(outputFlag.GetProperty("type").ValueEquals("boolean"), Is.True)
        Assert.That(names requiredInputs, Is.EquivalentTo([| "connection"; "packages" |]))
        Assert.That(names required, Is.EquivalentTo([| "connection"; "packages"; "installedVersions"; "managedPackages" |]))
        Assert.That(resources.GetProperty("keroosha:debian:Ufw").ValueKind, Is.EqualTo(JsonValueKind.Object))

    [<Test>]
    member _.``Combined provider Check accepts optional strict Docker bootstrap without host access``() =
        let provider = DorothyProvider()
        let absent = AptProviderTestValues.check provider (AptProviderTestValues.inputs None)
        let disabled = AptProviderTestValues.check provider (AptProviderTestValues.inputs (Some false))
        let enabled = AptProviderTestValues.check provider (AptProviderTestValues.inputs (Some true))
        let unknownInputs =
            (AptProviderTestValues.inputs None).SetItem("strictDockerBootstrap", PropertyValue.Computed)
        let unknown = AptProviderTestValues.check provider unknownInputs
        let invalidInputs =
            (AptProviderTestValues.inputs None).SetItem("strictDockerBootstrap", AptProviderTestValues.text "true")
        let invalid = AptProviderTestValues.check provider invalidInputs
        let mutable enabledFlag = false

        Assert.That(absent.Failures, Is.Empty)
        Assert.That(absent.Inputs.ContainsKey("strictDockerBootstrap"), Is.False)
        Assert.That(disabled.Failures, Is.Empty)
        Assert.That(disabled.Inputs.ContainsKey("strictDockerBootstrap"), Is.False)
        Assert.That(enabled.Failures, Is.Empty)
        Assert.That(enabled.Inputs["strictDockerBootstrap"].TryGetBool(&enabledFlag), Is.True)
        Assert.That(enabledFlag, Is.True)
        Assert.That(unknown.Failures, Is.Empty)
        Assert.That(unknown.Inputs["strictDockerBootstrap"].IsComputed, Is.True)
        Assert.That(invalid.Failures |> Seq.exists (fun failure -> failure.Property = "strictDockerBootstrap"), Is.True)

    [<Test>]
    member _.``Combined provider Diff reports strict Docker bootstrap input changes without host access``() =
        let provider = DorothyProvider()

        let changes =
            [ None; Some false ]
            |> List.map (fun oldStrict ->
                AptProviderTestValues.diff
                    provider
                    (AptProviderTestValues.inputs oldStrict)
                    (AptProviderTestValues.inputs (Some true)))

        for response in changes do
            Assert.That(response.Changes.HasValue, Is.True)
            Assert.That(response.Changes.Value, Is.True)
            Assert.That(response.Diffs.Contains("strictDockerBootstrap"), Is.True)
            Assert.That(response.DetailedDiff.ContainsKey("strictDockerBootstrap"), Is.True)
