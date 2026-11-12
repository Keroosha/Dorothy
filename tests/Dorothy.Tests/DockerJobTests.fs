namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading
open Dorothy.DSL
open Dorothy.DSL.Provider
open Dorothy.HostHelper
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private DockerJobTestValues =
    let id = String('a', 64)
    let map entries =
        entries |> Seq.map (fun (key, value) -> KeyValuePair(key, value)) |> ImmutableDictionary.CreateRange
    let inputs containerId =
        map [
            "connection", PropertyValue(map [ "address", PropertyValue("192.0.2.1"); "user", PropertyValue("root") ])
            "containerId", PropertyValue(containerId: string)
            "timeoutSeconds", PropertyValue(1.0)
        ]
    let urn = Pulumi.Urn("urn:pulumi:unit::unit::keroosha:debian:DockerJob::migrator")
    let diff oldInputs outputs newInputs =
        DockerJobProvider().Diff(DiffRequest(urn, "existing-job", outputs, newInputs, ImmutableArray<string>.Empty, oldInputs), CancellationToken.None).GetAwaiter().GetResult()

    type Fixture(initialStatus: string, exitCode: int, waitTimeout: bool) =
        let temporary = new TemporaryDirectory("dorothy-docker-job-")
        let calls = ResizeArray<string * string list * string option>()
        let mutable state = initialStatus
        let mutable actualExitCode = exitCode
        let mutable nextExitCode = exitCode
        let mutable waitTimeout = waitTimeout
        let mutable timeoutSeconds = 1
        let mutable secretEnvironmentKeys = []
        let mutable exists = true
        let mutable restart = "no"
        let mutable daemonFailure = false
        let mutable malformedEnvironment = false
        let mutable logFailure = false
        let mutable logs = "migration failed: fixture-password\nsecond-secret\nuseful diagnostic"
        let inspect () =
            let stateNode = JsonObject()
            stateNode["Status"] <- JsonValue.Create(state)
            stateNode["ExitCode"] <- JsonValue.Create(actualExitCode)
            let env = JsonArray()
            env.Add(JsonValue.Create("PASSWORD=fixture-password"))
            env.Add(JsonValue.Create("MULTILINE=first-secret\nsecond-secret"))
            env.Add(JsonValue.Create("DOTNET_NOLOGO=1"))
            env.Add(JsonValue.Create("PORT=8080"))
            env.Add(JsonValue.Create("ENABLED=true"))
            env.Add(JsonValue.Create("SHORT_PIN=s7"))
            env.Add(JsonValue.Create("SHORT_LINES=x1\nq2"))
            let config = JsonObject()
            config["Env"] <- if malformedEnvironment then null else env
            let restartNode = JsonObject()
            restartNode["Name"] <- JsonValue.Create(restart)
            let host = JsonObject()
            host["RestartPolicy"] <- restartNode
            let container = JsonObject()
            container["Id"] <- JsonValue.Create(id)
            container["Config"] <- config
            container["State"] <- stateNode
            container["HostConfig"] <- host
            let array = JsonArray()
            array.Add container
            array.ToJsonString()
        let ok stdout : CommandResult = { ExitCode = 0; Stdout = stdout; Stderr = "" }
        let run executable arguments stdin =
            calls.Add(executable, arguments, stdin)
            if executable <> "timeout" || stdin.IsSome then failwith "Unexpected command transport."
            match arguments with
            | [ "--signal=KILL"; "30s"; "docker"; "container"; "ls"; "--all"; "--no-trunc"; "--quiet"; "--filter"; filter ] when filter = "id=" + id ->
                if daemonFailure then { ExitCode = 1; Stdout = ""; Stderr = "fixture-password daemon failure" }
                else ok (if exists then id + "\n" else "")
            | [ "--signal=KILL"; "30s"; "docker"; "container"; "inspect"; containerId ] when containerId = id -> ok (inspect())
            | [ "--signal=KILL"; "30s"; "docker"; "container"; "start"; containerId ] when containerId = id -> state <- "running"; ok (id + "\n")
            | [ "--signal=KILL"; "1s"; "docker"; "container"; "wait"; containerId ] when containerId = id ->
                if waitTimeout then { ExitCode = 137; Stdout = ""; Stderr = "" }
                else
                    state <- "exited"
                    actualExitCode <- nextExitCode
                    ok (string actualExitCode + "\n")
            | [ "--signal=KILL"; "30s"; "docker"; "container"; "kill"; containerId ] when containerId = id ->
                state <- "exited"
                actualExitCode <- 137
                ok (id + "\n")
            | [ "--signal=KILL"; "10s"; "docker"; "container"; "logs"; "--tail"; "50"; containerId ] when containerId = id ->
                if logFailure then { ExitCode = 1; Stdout = logs; Stderr = "fixture-password" } else ok logs
            | _ -> failwithf "Unexpected fixture command %A" arguments
        let environment = TestSupport.fakeHostEnvironment temporary.Path run (fun () -> DateTimeOffset.UnixEpoch)
        member _.Calls = calls
        member _.Status = state
        member _.Exists with set value = exists <- value
        member _.Restart with set value = restart <- value
        member _.DaemonFailure with set value = daemonFailure <- value
        member _.MalformedEnvironment with set value = malformedEnvironment <- value
        member _.LogFailure with set value = logFailure <- value
        member _.Logs with set value = logs <- value
        member _.NextExitCode with set value = nextExitCode <- value
        member _.WaitTimeout with set value = waitTimeout <- value
        member _.TimeoutSeconds with set value = timeoutSeconds <- value
        member _.SecretEnvironmentKeys with set value = secretEnvironmentKeys <- value
        member _.Run(operation) =
            use request = JsonDocument.Parse(DockerJobBackend.serializeRequest operation id timeoutSeconds secretEnvironmentKeys)
            DockerJob.handle environment request.RootElement
        member _.RunRaw(json: string) =
            use request = JsonDocument.Parse(json)
            DockerJob.handle environment request.RootElement
        interface IDisposable with member _.Dispose() = (temporary :> IDisposable).Dispose()

[<TestFixture>]
type DockerJobTests() =
    [<Test>]
    member _.``RunOnce replaces restart and supports dependency ordering by declaration identity``() =
        let database = container "z-db" { image "mariadb@sha256:abc"; restart unlessStopped; healthcheck { healthExec [ "healthcheck.sh"; "--connect" ] }; waitHealthy (TimeSpan.FromMinutes 1.) }
        let migrator = container "m-migrator" { image "web@sha256:def"; runOnce (TimeSpan.FromMinutes 5.); command [ "--migrator" ]; dependsOn database }
        let web = container "a-web" { image "web@sha256:def"; restart unlessStopped; dependsOn migrator }
        let spec = docker { web; migrator; database }
        Assert.That(spec.Containers |> List.map (fun c -> c.Name), Is.EqualTo(box [ "z-db"; "m-migrator"; "a-web" ]))
        Assert.That(migrator.Restart, Is.EqualTo(NoRestart))
        Assert.That(migrator.Command, Is.EqualTo(Some [ "--migrator" ]))
        Assert.That(migrator.Dependencies[0], Is.SameAs(database))
        let impostor = container "z-db" { image "db"; restart noRestart }
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> docker { impostor; migrator } |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> docker { migrator } |> ignore)) |> ignore

    [<Test>]
    member _.``RunOnce rejects ambiguous lifecycle and invalid timeout declarations``() =
        let invalid = [
            fun () -> container "job" { image "image"; runOnce TimeSpan.Zero } |> ignore
            fun () -> container "job" { image "image"; runOnce (TimeSpan.FromDays 2.) } |> ignore
            fun () -> container "job" { image "image"; runOnce (TimeSpan.FromSeconds 1.); restart noRestart } |> ignore
            fun () -> container "job" { image "image"; runOnce (TimeSpan.FromSeconds 1.); waitHealthy (TimeSpan.FromSeconds 1.) } |> ignore
            fun () -> container "job" { image "image"; runOnce (TimeSpan.FromSeconds 1.); healthcheck { healthExec [ "true" ] } } |> ignore
            fun () -> container "job" { image "image"; runOnce (TimeSpan.FromSeconds 1.); runOnce (TimeSpan.FromSeconds 2.) } |> ignore
        ]
        for action in invalid do Assert.Throws<ArgumentException>(TestDelegate(action)) |> ignore

    [<Test>]
    member _.``Successful job refresh and repeated apply never restart completed work``() =
        use fixture = new DockerJobTestValues.Fixture("created", 0, false)
        let applied = fixture.Run("apply")
        let refreshed = fixture.Run("read")
        fixture.Run("apply") |> ignore
        Assert.That(applied["completed"].GetValue<bool>(), Is.True)
        Assert.That(refreshed["completed"].GetValue<bool>(), Is.True)
        let starts = fixture.Calls |> Seq.filter (fun (_, args, _) -> List.contains "start" args) |> Seq.length
        Assert.That(starts, Is.EqualTo(1))
        Assert.That(fixture.Status, Is.EqualTo("exited"))
        let inputs = DockerJobTestValues.inputs DockerJobTestValues.id
        let outputs = inputs.SetItem("completed", PropertyValue(true)).SetItem("exists", PropertyValue(true))
        Assert.That((DockerJobTestValues.diff inputs outputs inputs).Changes.Value, Is.False)
        let changed = DockerJobTestValues.diff inputs outputs (DockerJobTestValues.inputs (String('b', 64)))
        Assert.That(changed.Changes.Value, Is.True)
        Assert.That(changed.Diffs, Does.Contain("containerId"))

    [<Test>]
    member _.``Failed jobs redact diagnostics and retry once on the next apply but never after success``() =
        use fixture = new DockerJobTestValues.Fixture("created", 42, false)
        let failed = Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("apply") |> ignore))
        Assert.That(failed.Message, Does.Contain("code 42"))
        Assert.That(failed.Message, Does.Contain("useful diagnostic"))
        Assert.That(failed.Message, Does.Not.Contain("fixture-password"))
        Assert.That(failed.Message, Does.Not.Contain("second-secret"))
        let refreshed = fixture.Run("read")
        Assert.That(refreshed["completed"].GetValue<bool>(), Is.False)
        Assert.That(fixture.Calls |> Seq.filter (fun (_, args, _) -> List.contains "start" args) |> Seq.length, Is.EqualTo(1))
        fixture.NextExitCode <- 0
        let retried = fixture.Run("apply")
        Assert.That(retried["completed"].GetValue<bool>(), Is.True)
        fixture.Run("apply") |> ignore
        Assert.That(fixture.Calls |> Seq.filter (fun (_, args, _) -> List.contains "start" args) |> Seq.length, Is.EqualTo(2))
        for _, args, stdin in fixture.Calls do
            Assert.That(String.concat " " args, Does.Not.Contain("fixture-password"))
            Assert.That(stdin, Is.EqualTo(None))

    [<Test>]
    member _.``Timeout kills job and a later apply retries it without input replacement``() =
        use fixture = new DockerJobTestValues.Fixture("created", 0, true)
        let failed = Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("apply") |> ignore))
        Assert.That(failed.Message, Does.Contain("timed out"))
        Assert.That(failed.Message, Does.Contain("useful diagnostic"))
        Assert.That(failed.Message, Does.Not.Contain("fixture-password"))
        Assert.That(fixture.Status, Is.EqualTo("exited"))
        Assert.That(fixture.Calls |> Seq.exists (fun (_, args, _) -> List.contains "kill" args), Is.True)
        let refreshed = fixture.Run("read")
        Assert.That(refreshed["completed"].GetValue<bool>(), Is.False)
        Assert.That(fixture.Calls |> Seq.filter (fun (_, args, _) -> List.contains "start" args) |> Seq.length, Is.EqualTo(1))
        fixture.WaitTimeout <- false
        fixture.NextExitCode <- 0
        let retried = fixture.Run("apply")
        Assert.That(retried["completed"].GetValue<bool>(), Is.True)
        fixture.Run("apply") |> ignore
        Assert.That(fixture.Calls |> Seq.filter (fun (_, args, _) -> List.contains "start" args) |> Seq.length, Is.EqualTo(2))

    [<Test>]
    member _.``Recovery waits for an already started job rather than starting it twice``() =
        use fixture = new DockerJobTestValues.Fixture("running", 0, false)
        let result = fixture.Run("apply")
        Assert.That(result["completed"].GetValue<bool>(), Is.True)
        Assert.That(fixture.Calls |> Seq.exists (fun (_, args, _) -> List.contains "start" args), Is.False)

    [<Test>]
    member _.``Delete releases running jobs and preserves sole Docker resource removal ownership``() =
        use fixture = new DockerJobTestValues.Fixture("running", 0, false)
        let released = fixture.Run("delete")
        Assert.That(released["exists"].GetValue<bool>(), Is.True)
        Assert.That(fixture.Status, Is.EqualTo("exited"))
        Assert.That(fixture.Calls |> Seq.exists (fun (_, args, _) -> List.contains "rm" args), Is.False)
        fixture.Exists <- false
        let absent = fixture.Run("delete")
        let refreshed = fixture.Run("read")
        Assert.That(absent["exists"].GetValue<bool>(), Is.False)
        Assert.That(refreshed["completed"].GetValue<bool>(), Is.False)
        Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("apply") |> ignore)) |> ignore

    [<Test>]
    member _.``Daemon failures are errors rather than absent jobs and do not leak daemon diagnostics``() =
        use fixture = new DockerJobTestValues.Fixture("created", 0, false)
        fixture.DaemonFailure <- true
        let failed = Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("read") |> ignore))
        Assert.That(failed.Message, Does.Not.Contain("fixture-password"))

    [<Test>]
    member _.``Logs fail closed when redaction or logging is unavailable and redact before truncation``() =
        use fixture = new DockerJobTestValues.Fixture("exited", 1, false)
        fixture.MalformedEnvironment <- true
        let failed = Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("apply") |> ignore))
        Assert.That(failed.Message, Does.Contain("logs withheld"))
        Assert.That(failed.Message, Does.Not.Contain("fixture-password"))
        fixture.MalformedEnvironment <- false
        fixture.LogFailure <- true
        let failed = Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("apply") |> ignore))
        Assert.That(failed.Message, Does.Contain("logs unavailable"))
        Assert.That(failed.Message, Does.Not.Contain("fixture-password"))
        fixture.LogFailure <- false
        fixture.Logs <- String('x', 5000) + "fixture-password" + String('y', 4090)
        let failed = Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("apply") |> ignore))
        Assert.That(failed.Message, Does.Not.Contain("password"))
        Assert.That(failed.Message.Length, Is.LessThan(4300))

    [<Test>]
    member _.``Helper refuses unsafe identity restart and invalid timeout before mutations``() =
        use fixture = new DockerJobTestValues.Fixture("created", 0, false)
        let invalid = DockerJobBackend.serializeRequest "apply" "--all" 1 []
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> fixture.RunRaw invalid |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> fixture.RunRaw (DockerJobBackend.serializeRequest "apply" DockerJobTestValues.id 0 []) |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> fixture.RunRaw (DockerJobBackend.serializeRequest "apply" DockerJobTestValues.id 1 [ "bad=key" ]) |> ignore)) |> ignore
        Assert.That(fixture.Calls, Is.Empty)
        fixture.Restart <- "always"
        Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("apply") |> ignore)) |> ignore
        Assert.That(fixture.Calls |> Seq.exists (fun (_, args, _) -> List.contains "start" args), Is.False)

    [<Test>]
    member _.``Provider check and previews preserve unknowns and do not connect``() =
        let provider = DorothyProvider()
        let inputs = (DockerJobTestValues.inputs DockerJobTestValues.id).SetItem("containerId", PropertyValue.Computed)
        let check = provider.Check(CheckRequest(DockerJobTestValues.urn, ImmutableDictionary<string, PropertyValue>.Empty, inputs, ImmutableArray<byte>.Empty), CancellationToken.None).GetAwaiter().GetResult()
        Assert.That(check.Failures, Is.Empty)
        Assert.That(check.Inputs["containerId"].IsComputed, Is.True)
        let preview = provider.Create(CreateRequest(DockerJobTestValues.urn, inputs, TimeSpan.FromSeconds 1., true), CancellationToken.None).GetAwaiter().GetResult()
        Assert.That(preview.Outputs["completed"].IsComputed, Is.True)
        Assert.That((DockerJobTestValues.diff inputs ImmutableDictionary<string, PropertyValue>.Empty inputs).Changes.HasValue, Is.False)
        let invalid = (DockerJobTestValues.inputs "short").SetItem("timeoutSeconds", PropertyValue(0.0))
        let rejected = provider.Check(CheckRequest(DockerJobTestValues.urn, inputs, invalid, ImmutableArray<byte>.Empty), CancellationToken.None).GetAwaiter().GetResult()
        Assert.That(rejected.Failures |> Seq.map (fun f -> f.Property), Is.EquivalentTo([ "containerId"; "timeoutSeconds" ]))

    [<Test>]
    member _.``Backend rejects inconsistent duplicate or malformed completion snapshots``() =
        let valid = DockerJobBackend.parseSnapshot "{\"exists\":true,\"completed\":true}"
        Assert.That(valid.Completed, Is.True)
        for invalid in [ "{}"; "not json"; "{\"exists\":false,\"completed\":true}"; "{\"exists\":true,\"completed\":\"true\"}"; "{\"exists\":true,\"exists\":true,\"completed\":true}" ] do
            Assert.Throws<InvalidOperationException>(TestDelegate(fun () -> DockerJobBackend.parseSnapshot invalid |> ignore)) |> ignore

    [<Test>]
    member _.``Short public environment values preserve diagnostics while short explicit secrets are always redacted``() =
        use fixture = new DockerJobTestValues.Fixture("created", 1, false)
        fixture.SecretEnvironmentKeys <- [ "SHORT_PIN"; "SHORT_LINES" ]
        fixture.Logs <- "status 1, port 8080, enabled true, pin s7, lines x1 and q2, password fixture-password"
        let error = Assert.Throws<DockerJob.BackendError>(TestDelegate(fun () -> fixture.Run("apply") |> ignore))
        Assert.That(error.Message, Does.Contain("status 1, port 8080, enabled true"))
        Assert.That(error.Message, Does.Contain("pin [redacted], lines [redacted] and [redacted]"))
        for secret in [ "s7"; "x1"; "q2"; "fixture-password" ] do
            Assert.That(error.Message, Does.Not.Contain(secret))

    [<Test>]
    member _.``Diff schedules incomplete jobs for update and does not mutate helper state``() =
        let inputs = DockerJobTestValues.inputs DockerJobTestValues.id
        for outputs in [ inputs.SetItem("completed", PropertyValue(false)); inputs ] do
            let diff = DockerJobTestValues.diff inputs outputs inputs
            Assert.That(diff.Changes.Value, Is.True)
            Assert.That(diff.Diffs, Is.EquivalentTo([ "completed" ]))
            Assert.That(diff.Replaces, Is.Empty)
            Assert.That(diff.DeleteBeforeReplace, Is.False)
            Assert.That(diff.DetailedDiff["completed"].Kind, Is.EqualTo(PropertyDiffKind.Update))
            Assert.That(diff.DetailedDiff["completed"].InputDiff, Is.False)

    [<Test>]
    member _.``Diff replaces a changed connection before create and updates only the timeout without rerunning success``() =
        let inputs = DockerJobTestValues.inputs DockerJobTestValues.id
        let outputs = inputs.SetItem("completed", PropertyValue(true))
        let moved = inputs.SetItem("connection", PropertyValue(DockerJobTestValues.map [ "address", PropertyValue("192.0.2.2"); "user", PropertyValue("root") ]))
        let replacement = DockerJobTestValues.diff inputs outputs moved
        Assert.That(replacement.Replaces, Is.EquivalentTo([ "connection" ]))
        Assert.That(replacement.DeleteBeforeReplace, Is.True)
        Assert.That(replacement.DetailedDiff["connection"].Kind, Is.EqualTo(PropertyDiffKind.UpdateReplace))
        Assert.That(replacement.DetailedDiff["connection"].InputDiff, Is.True)

        let timeoutChange = DockerJobTestValues.diff inputs outputs (inputs.SetItem("timeoutSeconds", PropertyValue(2.0)))
        Assert.That(timeoutChange.Diffs, Is.EquivalentTo([ "timeoutSeconds" ]))
        Assert.That(timeoutChange.Replaces, Is.Empty)
        Assert.That(timeoutChange.DeleteBeforeReplace, Is.False)
        Assert.That(timeoutChange.DetailedDiff["timeoutSeconds"].Kind, Is.EqualTo(PropertyDiffKind.Update))
        Assert.That(timeoutChange.DetailedDiff["timeoutSeconds"].InputDiff, Is.True)
        use fixture = new DockerJobTestValues.Fixture("exited", 0, false)
        fixture.TimeoutSeconds <- 2
        let unchanged = fixture.Run("apply")
        Assert.That(unchanged["completed"].GetValue<bool>(), Is.True)
        Assert.That(fixture.Calls |> Seq.exists (fun (_, args, _) -> List.contains "start" args || List.contains "wait" args), Is.False)

    [<Test>]
    member _.``Diff uses stored output inputs and preserves unknown input decisions``() =
        let inputs = DockerJobTestValues.inputs DockerJobTestValues.id
        let outputs = inputs.SetItem("completed", PropertyValue(true))
        let fallback = DockerJobTestValues.diff ImmutableDictionary<string, PropertyValue>.Empty outputs inputs
        Assert.That(fallback.Changes.Value, Is.False)
        for oldInputs, newInputs in [
            inputs.SetItem("containerId", PropertyValue.Computed), inputs
            inputs, inputs.SetItem("timeoutSeconds", PropertyValue.Computed)
            inputs, inputs.SetItem("secretEnvironmentKeys", PropertyValue(ImmutableArray.Create(PropertyValue.Computed)))
        ] do
            Assert.That((DockerJobTestValues.diff oldInputs outputs newInputs).Changes.HasValue, Is.False)

    [<Test>]
    member _.``Provider validates secret environment names without exposing their values``() =
        let provider = DockerJobProvider()
        let inputs = DockerJobTestValues.inputs DockerJobTestValues.id
        for invalid in [ PropertyValue("not an array"); PropertyValue(ImmutableArray.Create(PropertyValue("bad=key"))) ] do
            let request = CheckRequest(DockerJobTestValues.urn, inputs, inputs.SetItem("secretEnvironmentKeys", invalid), ImmutableArray<byte>.Empty)
            let response = provider.Check(request, CancellationToken.None).GetAwaiter().GetResult()
            Assert.That(response.Failures |> Seq.map (fun failure -> failure.Property), Is.EquivalentTo([ "secretEnvironmentKeys" ]))
