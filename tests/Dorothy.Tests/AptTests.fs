namespace Dorothy.Tests

open System
open System.IO
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper
open NUnit.Framework

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
