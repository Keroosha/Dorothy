namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Text.Json
open System.Threading
open Dorothy.DSL.Provider
open Dorothy.HostHelper
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

[<RequireQualifiedAccess>]
module private DockerEngineTestValues =
    let map (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do builder.Add(key, value)
        PropertyValue(builder.ToImmutable())

    let inputMap (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do builder.Add(key, value)
        builder.ToImmutable()

    let string (value: string) = PropertyValue(value)
    let boolean (value: bool) = PropertyValue(value)

    let connection address user =
        map [ "address", string address; "user", string user ]

    let inputs address user =
        inputMap [ "connection", connection address user ]

    let urn = Pulumi.Urn("urn:pulumi:unit::unit::keroosha:debian:DockerEngine::dockerEngine-test")

    let runCheck (provider: DockerEngineProvider) (inputs: ImmutableDictionary<string, PropertyValue>) =
        let request =
            CheckRequest(
                urn,
                ImmutableDictionary<string, PropertyValue>.Empty,
                inputs,
                ImmutableArray<byte>.Empty
            )
        provider.Check(request, CancellationToken.None).GetAwaiter().GetResult()

    let runDiff
        (provider: DockerEngineProvider)
        (oldInputs: ImmutableDictionary<string, PropertyValue>)
        (oldOutputs: ImmutableDictionary<string, PropertyValue>)
        (newInputs: ImmutableDictionary<string, PropertyValue>)
        =
        let request =
            DiffRequest(
                urn,
                "existing-docker-engine",
                oldOutputs,
                newInputs,
                ImmutableArray<string>.Empty,
                oldInputs
            )
        provider.Diff(request, CancellationToken.None).GetAwaiter().GetResult()

    let helperRequest (environment: HostEnvironment) (json: string) =
        use document = JsonDocument.Parse(json)
        DockerEngine.handle environment document.RootElement

    let systemctlSnapshot loadState unitFileState activeState =
        sprintf "LoadState=%s\nUnitFileState=%s\nActiveState=%s\n" loadState unitFileState activeState

[<TestFixture>]
type DockerEngineTests() =
    [<Test>]
    member _.``Docker Engine Check Diff and Create preview do not contact the host``() =
        let provider = DockerEngineProvider()
        let inputs = DockerEngineTestValues.inputs "127.0.0.1" "root"

        let check = DockerEngineTestValues.runCheck provider inputs

        Assert.That(check.Failures, Is.Empty)

        let oldOutputs =
            DockerEngineTestValues.inputMap [
                "serviceEnabled", DockerEngineTestValues.boolean true
                "serviceActive", DockerEngineTestValues.boolean true
                "dockerGroupMembership", DockerEngineTestValues.boolean true
                "inSync", DockerEngineTestValues.boolean true
            ]

        let diff = DockerEngineTestValues.runDiff provider inputs oldOutputs inputs

        Assert.That(diff.Changes.HasValue, Is.True)
        Assert.That(diff.Changes.Value, Is.False)

        let createRequest = CreateRequest(DockerEngineTestValues.urn, inputs, TimeSpan.FromSeconds(1.0), true)
        let preview = provider.Create(createRequest, CancellationToken.None).GetAwaiter().GetResult()

        Assert.That(preview.Id, Is.Empty)
        Assert.That(preview.Outputs["serviceEnabled"].IsComputed, Is.True)
        Assert.That(preview.Outputs["serviceActive"].IsComputed, Is.True)
        Assert.That(preview.Outputs["dockerGroupMembership"].IsComputed, Is.True)
        Assert.That(preview.Outputs["inSync"].IsComputed, Is.True)

    [<Test>]
    member _.``Missing Docker service and group membership read as drift and Diff requests repair``() =
        let calls = ResizeArray<string * string list>()
        let run executable arguments _ =
            calls.Add((executable, arguments))
            match executable, arguments with
            | "systemctl", [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; "docker.service" ] ->
                { ExitCode = 0
                  Stdout = DockerEngineTestValues.systemctlSnapshot "not-found" "disabled" "inactive"
                  Stderr = "" }
            | "id", [ "-nG"; "--"; "debian" ] ->
                { ExitCode = 0; Stdout = "debian users\n"; Stderr = "" }
            | _ -> { ExitCode = 99; Stdout = ""; Stderr = "unexpected helper command" }

        let environment = TestSupport.fakeHostEnvironment "/" run (fun () -> DateTimeOffset.UnixEpoch)
        let snapshot = DockerEngineTestValues.helperRequest environment "{\"operation\":\"read\",\"user\":\"debian\"}"

        Assert.That(snapshot["serviceEnabled"].GetValue<bool>(), Is.False)
        Assert.That(snapshot["serviceActive"].GetValue<bool>(), Is.False)
        Assert.That(snapshot["dockerGroupMembership"].GetValue<bool>(), Is.False)

        let inputs = DockerEngineTestValues.inputs "192.0.2.8" "debian"
        let oldOutputs =
            DockerEngineTestValues.inputMap [
                "serviceEnabled", DockerEngineTestValues.boolean(snapshot["serviceEnabled"].GetValue<bool>())
                "serviceActive", DockerEngineTestValues.boolean(snapshot["serviceActive"].GetValue<bool>())
                "dockerGroupMembership", DockerEngineTestValues.boolean(snapshot["dockerGroupMembership"].GetValue<bool>())
                "inSync", DockerEngineTestValues.boolean false
            ]

        let provider = DockerEngineProvider()
        let diff = DockerEngineTestValues.runDiff provider inputs oldOutputs inputs

        Assert.That(diff.Changes.HasValue, Is.True)
        Assert.That(diff.Changes.Value, Is.True)
        Assert.That(diff.Diffs.Contains("serviceEnabled"), Is.True)
        Assert.That(diff.Diffs.Contains("serviceActive"), Is.True)
        Assert.That(diff.Diffs.Contains("dockerGroupMembership"), Is.True)
        Assert.That(calls.Count, Is.EqualTo(2))

    [<Test>]
    member _.``Root is exempt from Docker group membership checks``() =
        let calls = ResizeArray<string * string list>()
        let run executable arguments _ =
            calls.Add((executable, arguments))
            match executable, arguments with
            | "systemctl", [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; "docker.service" ] ->
                { ExitCode = 0
                  Stdout = DockerEngineTestValues.systemctlSnapshot "loaded" "enabled" "active"
                  Stderr = "" }
            | _ -> { ExitCode = 99; Stdout = ""; Stderr = "unexpected helper command" }

        let environment = TestSupport.fakeHostEnvironment "/" run (fun () -> DateTimeOffset.UnixEpoch)
        let snapshot = DockerEngineTestValues.helperRequest environment "{\"operation\":\"read\",\"user\":\"root\"}"

        Assert.That(snapshot["dockerGroupMembership"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["serviceEnabled"].GetValue<bool>(), Is.True)
        Assert.That(snapshot["serviceActive"].GetValue<bool>(), Is.True)
        Assert.That(calls.Count, Is.EqualTo(1))

    [<Test>]
    member _.``Apply adds a non-root user to docker group only when absent``() =
        let calls = ResizeArray<string * string list>()
        let mutable membershipAdded = false
        let run executable arguments _ =
            calls.Add((executable, arguments))
            match executable, arguments with
            | "systemctl", [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; "docker.service" ] ->
                { ExitCode = 0
                  Stdout = DockerEngineTestValues.systemctlSnapshot "loaded" "enabled" "active"
                  Stderr = "" }
            | "systemctl", [ "unmask"; "docker.service" ]
            | "systemctl", [ "enable"; "docker.service" ]
            | "systemctl", [ "start"; "docker.service" ] ->
                { ExitCode = 0; Stdout = ""; Stderr = "" }
            | "id", [ "-nG"; "--"; "debian" ] ->
                { ExitCode = 0
                  Stdout = if membershipAdded then "debian docker\n" else "debian users\n"
                  Stderr = "" }
            | "gpasswd", [ "-a"; "debian"; "docker" ] ->
                membershipAdded <- true
                { ExitCode = 0; Stdout = ""; Stderr = "" }
            | _ -> { ExitCode = 99; Stdout = ""; Stderr = "unexpected helper command" }

        let environment = TestSupport.fakeHostEnvironment "/" run (fun () -> DateTimeOffset.UnixEpoch)
        let snapshot = DockerEngineTestValues.helperRequest environment "{\"operation\":\"apply\",\"user\":\"debian\"}"
        let addCalls = calls |> Seq.filter (fun (executable, _) -> executable = "gpasswd") |> Seq.toArray

        Assert.That(snapshot["dockerGroupMembership"].GetValue<bool>(), Is.True)
        Assert.That(addCalls.Length, Is.EqualTo(1))
        let expectedAddArguments: string list = [ "-a"; "debian"; "docker" ]
        Assert.That(snd (addCalls[0]), Is.EqualTo(box expectedAddArguments))

        let existingMemberCalls = ResizeArray<string * string list>()
        let runExisting executable arguments _ =
            existingMemberCalls.Add((executable, arguments))
            match executable, arguments with
            | "systemctl", [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; "docker.service" ] ->
                { ExitCode = 0
                  Stdout = DockerEngineTestValues.systemctlSnapshot "loaded" "enabled" "active"
                  Stderr = "" }
            | "systemctl", [ "unmask"; "docker.service" ]
            | "systemctl", [ "enable"; "docker.service" ]
            | "systemctl", [ "start"; "docker.service" ] ->
                { ExitCode = 0; Stdout = ""; Stderr = "" }
            | "id", [ "-nG"; "--"; "debian" ] ->
                { ExitCode = 0; Stdout = "debian docker\n"; Stderr = "" }
            | _ -> { ExitCode = 99; Stdout = ""; Stderr = "unexpected helper command" }

        let existingEnvironment = TestSupport.fakeHostEnvironment "/" runExisting (fun () -> DateTimeOffset.UnixEpoch)
        let _ = DockerEngineTestValues.helperRequest existingEnvironment "{\"operation\":\"apply\",\"user\":\"debian\"}"
        Assert.That(existingMemberCalls |> Seq.exists (fun (executable, _) -> executable = "gpasswd"), Is.False)

    [<Test>]
    member _.``Invalid SSH usernames are rejected before helper commands``() =
        let calls = ResizeArray<string * string list>()
        let run executable arguments _ =
            calls.Add((executable, arguments))
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        let environment = TestSupport.fakeHostEnvironment "/" run (fun () -> DateTimeOffset.UnixEpoch)
        use document = JsonDocument.Parse("{\"operation\":\"read\",\"user\":\"-root\"}")

        let action = TestDelegate(fun () -> DockerEngine.handle environment document.RootElement |> ignore)

        Assert.Throws<ArgumentException>(action) |> ignore
        Assert.That(calls, Is.Empty)
