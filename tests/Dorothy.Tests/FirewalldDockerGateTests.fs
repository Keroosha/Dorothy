namespace Dorothy.Tests

open System
open Dorothy.HostHelper
open System.IO
open System.Text.Json.Nodes
open NUnit.Framework

[<TestFixture>]
type FirewalldDockerGateTests() =
    let withReadinessHost (action: HostEnvironment -> (CommandResult -> unit) -> (string -> string -> string -> string -> unit) -> (string -> unit) -> (CommandResult -> unit) -> unit) =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-gate-" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory root |> ignore
        let mutable panicResult = { ExitCode = 1; Stdout = "no\n"; Stderr = "" }
        let mutable firewalldStateResult = { ExitCode = 0; Stdout = "running\n"; Stderr = "" }
        let mutable firewalldActiveState = "active"
        let recoveryUnits =
            FirewalldLifecycle.dockerBootDecisionUnits
            @ [ FirewalldLifecycle.dockerRollbackServiceName ]
        let preboot = List.head FirewalldLifecycle.dockerBootDecisionUnits
        let recoveryResults = Collections.Generic.Dictionary<string, CommandResult>(StringComparer.Ordinal)
        let recoveryResult active result status =
            { ExitCode = 0
              Stdout = String.concat "\n" [ "LoadState=loaded"; "ActiveState=" + active; "Result=" + result; "ExecMainStatus=" + status ] + "\n"
              Stderr = "" }
        for unitName in recoveryUnits do
            let active = if unitName = preboot then "active" else "inactive"
            recoveryResults[unitName] <- recoveryResult active "success" "0"
        let run executable arguments _ =
            match executable, arguments with
            | "firewall-cmd", [ "--state" ] -> firewalldStateResult
            | "firewall-cmd", [ "--query-panic" ] -> panicResult
            | "/usr/bin/systemctl", [ "show"; "--no-pager"; "--property=LoadState,ActiveState,SubState"; "--"; "firewalld.service" ] ->
                { ExitCode = 0
                  Stdout = String.concat "\n" [ "LoadState=loaded"; "ActiveState=" + firewalldActiveState; "SubState=running" ] + "\n"
                  Stderr = "" }
            | "/usr/bin/systemctl", [ "show"; "--no-pager"; "--property=LoadState,ActiveState,Result,ExecMainStatus"; "--"; unitName ] ->
                recoveryResults[unitName]
            | "stat", [ "-c"; "%u:%a"; "--"; path ] ->
                { ExitCode = 0
                  Stdout = if path.EndsWith("pending-transaction.json", StringComparison.Ordinal) then "0:600" else "0:700"
                  Stderr = "" }
            | _ -> invalidOp ("Unexpected gate admission command: " + executable + " " + String.concat " " arguments)
        let environment: HostEnvironment =
            { Root = root
              Run = run
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        let setRecovery unitName active result status =
            recoveryResults[unitName] <- recoveryResult active result status
        let setDaemonActive state = firewalldActiveState <- state
        let setDaemonStateResult result = firewalldStateResult <- result
        try action environment (fun result -> panicResult <- result) setRecovery setDaemonActive setDaemonStateResult
        finally
            if Directory.Exists root then Directory.Delete(root, true)

    let pendingTransaction () =
        let transaction = JsonObject()
        transaction["version"] <- JsonValue.Create 2
        transaction["nonce"] <- JsonValue.Create "00000000000000000000000000000000"
        transaction["ownerId"] <- JsonValue.Create "test-owner"
        transaction["configuration"] <- JsonValue.Create(FirewalldModel.toJson (FirewalldModel.empty "zone" "gatepending"))
        transaction["path"] <- JsonValue.Create "/etc/firewalld/zones/gatepending.xml"
        transaction["scope"] <- null
        transaction["before"] <- null
        transaction["beforeMode"] <- JsonValue.Create 0o644
        transaction["after"] <- null
        transaction["afterMode"] <- JsonValue.Create 0o644
        transaction["managedBefore"] <- null
        transaction["managedAfter"] <- null
        transaction["rollbackProof"] <- JsonNode.Parse("{\"strategy\":\"object-delta\"}")
        transaction["activationStarted"] <- JsonValue.Create true
        transaction["awaitingPostBoot"] <- JsonValue.Create false
        transaction["releaseOnRollback"] <- JsonValue.Create false
        transaction["deleteOnConfirm"] <- JsonValue.Create false
        transaction["status"] <- JsonValue.Create "pending"
        transaction.ToJsonString()


    let setPrivateDirectory path =
        Directory.CreateDirectory path |> ignore
        File.SetUnixFileMode(path, enum<UnixFileMode> 0o700)

    // A policy can be quiet until Docker binds its bridge. Query named loaded policies,
    // not just the active list. Input shape is firewall-cmd 2.3.1 --policy=NAME --list-all.
    let observe name ingress egress target priority ports =
        let text =
            String.concat "\n"
                [ name; "  priority: " + string priority; "  target: " + target; "  ingress-zones: " + ingress; "  egress-zones: " + egress
                  "  services:"; "  ports: " + ports; "  protocols:"; "  masquerade: no"; "  forward-ports:"; "  source-ports:"; "  icmp-blocks:"; "  rich rules:" ]
        let env = { HostEnvironment.system with
                        Run = fun exe args _ ->
                            if exe <> "firewall-cmd" || args <> ["--policy=" + name; "--list-all"] then invalidOp "Unexpected runtime query."
                            { ExitCode = 0; Stdout = text; Stderr = "" } }
        FirewalldRuntime.inspectRuntime env "policy" name |> Option.get

    [<Test>]
    member _.``External policy cannot precede a Docker DROP while HOST authorization remains unrelated``() =
        let fence = FirewalldGateModel.parseArguments "dockerguard" "-10" "public" "docker"
        let guard = observe "dockerguard" "public" "docker" "DROP" -10 ""
        let verify other = FirewalldDockerGate.verifyPolicies [guard; other] [fence]
        verify (observe "hostapi" "public" "HOST" "ACCEPT" -20 "")
        verify (observe "defaultallow" "ANY" "docker" "ACCEPT" 32767 "")
        for priority in [-20; -10] do
            let overlapping = observe "external" "ANY" "docker" "CONTINUE" priority "8443/tcp"
            Assert.Throws<Firewalld.BackendError>(fun () -> verify overlapping) |> ignore
        let permeable = {guard with Ports=["8443/tcp"]}
        Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyPolicies [permeable] [fence]) |> ignore

    [<Test>]
    member _.``Readiness accepts only the exact normal no-panic response``() =
        withReadinessHost (fun environment setPanic _ _ _ ->
            FirewalldDockerGate.verifyReadiness environment
            let cases =
                [ { ExitCode = 0; Stdout = "yes\n"; Stderr = "" }, "panic mode is enabled"
                  { ExitCode = 0; Stdout = "unknown\n"; Stderr = "" }, "ambiguous successful response"
                  { ExitCode = 124; Stdout = ""; Stderr = "" }, "Timed out"
                  { ExitCode = 0; Stdout = "no\n"; Stderr = "" }, "conflicting status and reply"
                  { ExitCode = 1; Stdout = "yes\n"; Stderr = "" }, "conflicting status and reply"
                  { ExitCode = 1; Stdout = "no\nextra"; Stderr = "" }, "ambiguous negative response"
                  { ExitCode = 1; Stdout = "no\n"; Stderr = "warning\n" }, "stderr diagnostics" ]
            for response, expectedMessage in cases do
                setPanic response
                let error = Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyReadiness environment)
                Assert.That(error.Message, Does.Contain expectedMessage))

    [<Test>]
    member _.``Recovery must be settled and have no pending transaction``() =
        withReadinessHost (fun environment _ setRecovery _ _ ->
            // The preboot hook is intentionally latched active after success.
            FirewalldDockerGate.verifyReadiness environment
            let preboot = List.head FirewalldLifecycle.dockerBootDecisionUnits
            let postboot = FirewalldLifecycle.dockerBootDecisionUnits[1]
            let containment = List.last FirewalldLifecycle.dockerBootDecisionUnits
            setRecovery preboot "inactive" "success" "0"
            Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyReadiness environment) |> ignore
            setRecovery preboot "active" "success" "0"
            setRecovery postboot "inactive" "success" "0"
            setRecovery containment "inactive" "condition" "0"
            Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyReadiness environment) |> ignore
            setRecovery containment "inactive" "exec-condition" "1"
            FirewalldDockerGate.verifyReadiness environment
            setRecovery preboot "failed" "exit-code" "1"
            let failed = Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyReadiness environment)
            Assert.That(failed.Message, Does.Contain "recovery unit is failed")
            setRecovery preboot "active" "success" "0"
            let markerPath = HostEnvironment.path environment "/var/lib/keroosha-iac/firewalld/pending-transaction.json"
            Directory.CreateDirectory(Path.GetDirectoryName markerPath) |> ignore
            File.WriteAllText(markerPath, pendingTransaction())
            File.SetUnixFileMode(markerPath, enum<UnixFileMode> 0o600)
            let pending = Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyReadiness environment)
            Assert.That(pending.Message, Does.Contain "pending, orphaned"))

    [<Test>]
    member _.``Orphan owner intent and nonrunning or suspended firewalld reject readiness``() =
        withReadinessHost (fun environment _ _ setDaemonActive setDaemonStateResult ->
            let ownerDirectory = HostEnvironment.path environment "/var/lib/keroosha-iac"
            let journalDirectory = HostEnvironment.path environment "/var/lib/keroosha-iac/firewalld"
            setPrivateDirectory ownerDirectory
            setPrivateDirectory journalDirectory
            File.WriteAllText(Path.Combine(journalDirectory, "zone-owner.json"), "{\"pending\":{}}")
            let orphan = Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyReadiness environment)
            Assert.That(orphan.Message, Does.Contain "pending, orphaned")
            Directory.Delete(HostEnvironment.path environment "/var/lib", true)
            setDaemonActive "inactive"
            let stopped = Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyReadiness environment)
            Assert.That(stopped.Message, Does.Contain "not running")
            setDaemonActive "active"
            setDaemonStateResult { ExitCode = 124; Stdout = ""; Stderr = "" }
            let suspended = Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyReadiness environment)
            Assert.That(suspended.Message, Does.Contain "may be suspended"))

    [<TestCase("required", true); TestCase("cleared", false); TestCase("opaque", false)>]
    [<TestCase("unrelated-error", false); TestCase("timeout", false); TestCase("unknown-search", false)>]
    member _.``Cold admission needs a distinguishable native required-command witness``(observation: string, expected: bool) =
        let root = Directory.CreateTempSubdirectory("dorothy-test-unit-path-")
        try
            let ownerDir = root.CreateSubdirectory("etc").FullName
            let higher = root.CreateSubdirectory("control").FullName
            let vendor = root.CreateSubdirectory("vendor").FullName
            let reply = JsonObject()
            reply["type"] <- JsonValue.Create "as"
            let paths = JsonArray()
            for path in [higher; ownerDir; vendor] do paths.Add(JsonValue.Create path)
            reply["data"] <- paths
            let ok text = { ExitCode = 0; Stdout = text; Stderr = "" }
            let hook = Path.Combine(ownerDir, "docker.service.d", "90-dorothy-test.conf")
            let bytes = System.Text.Encoding.UTF8.GetBytes("[Service]\nExecStartPre=/usr/bin/true\n")
            let env =
                { HostEnvironment.system with
                    Run = fun exe args _ ->
                        if exe = "/usr/bin/busctl" then
                            ok (if observation = "unknown-search" then "{}" else reply.ToJsonString())
                        elif exe = "/usr/bin/env" then
                            let dirs =
                                args |> List.find (fun s -> s.StartsWith("SYSTEMD_UNIT_PATH=", StringComparison.Ordinal))
                                |> fun s -> s.Substring("SYSTEMD_UNIT_PATH=".Length).Split(':')
                            // A stronger site directory must never be put behind our shadow.
                            if dirs.Length <> 4 || dirs[0] <> higher || dirs[2] <> ownerDir || dirs[3] <> vendor then
                                invalidOp "Incorrect unit search precedence."
                            let probe = Path.Combine(dirs[1], "docker.service.d", Path.GetFileName hook)
                            let text = File.ReadAllText probe
                            if observation = "opaque" then { ExitCode = 1; Stdout = ""; Stderr = "unit cannot be checked" }
                            elif not (text.Contains("must-not-exist", StringComparison.Ordinal)) || observation = "cleared" then ok ""
                            elif observation = "timeout" then { ExitCode = 124; Stdout = ""; Stderr = "" }
                            else
                                let witness = text.TrimEnd('\n').Split('\n') |> Array.last |> fun line -> line.Substring("ExecStartPre=".Length)
                                let reason = if observation = "required" then witness else "/unrelated"
                                { ExitCode = 1; Stdout = ""; Stderr = "docker.service: Command " + reason + " is not executable: No such file or directory\n" }
                        else invalidOp "No live systemd operation is allowed." }
            Assert.That(Services.coldHookEffective env hook bytes, Is.EqualTo expected)
            Assert.That(File.Exists hook, Is.False)
        finally
            root.Delete(true)
