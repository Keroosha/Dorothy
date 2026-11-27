namespace Dorothy.Tests

open System
open Dorothy.HostHelper
open System.IO
open System.Text.Json
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

    let generatorDirectories =
        [ "/etc/systemd/system-generators"
          "/run/systemd/system-generators"
          "/usr/local/lib/systemd/system-generators"
          "/usr/lib/systemd/system-generators"
          "/etc/systemd/system-environment-generators"
          "/run/systemd/system-environment-generators"
          "/usr/local/lib/systemd/system-environment-generators"
          "/usr/lib/systemd/system-environment-generators" ]

    let stockManagerConfiguration =
        "# /etc/systemd/system.conf\n\n# /usr/lib/systemd/system.conf.d/10-coredump-debian.conf\n[Manager]\nDefaultLimitCORE=0:infinity\n"

    let withGeneratorHost (action: HostEnvironment -> (string -> byte[] -> string) -> (CommandResult -> unit) -> (CommandResult -> unit) -> unit) =
        let root = Directory.CreateTempSubdirectory("dorothy-generator-profile-")
        let mutable managerEnvironment =
            { ExitCode = 0
              Stdout = "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
              Stderr = "" }
        let mutable managerConfiguration =
            { ExitCode = 0
              Stdout = stockManagerConfiguration
              Stderr = "" }
        let procExePath = Path.Combine(root.FullName, "proc", "1", "exe")
        let run executable arguments _ =
            match executable, arguments with
            | "/usr/bin/systemctl", [ "show-environment" ] -> managerEnvironment
            | "/usr/bin/sha256sum", [ "--"; path ] when path = procExePath ->
                { ExitCode = 0
                  Stdout = "799fd89964a716fb5f26c4506047190b6e842ac2745b473bd45351c4d8cbd929  " + path + "\n"
                  Stderr = "" }
            | "/usr/bin/systemd-analyze", [ "--no-pager"; "--tldr"; "cat-config"; "systemd/system.conf" ] -> managerConfiguration
            | "/usr/bin/stat", [ "-L"; "-c"; "%f"; "--"; path ] when File.Exists path ->
                { ExitCode = 0; Stdout = "81ed\n"; Stderr = "" }
            | "/usr/bin/stat", [ "-L"; "-c"; "%f"; "--"; _ ] ->
                { ExitCode = 1; Stdout = ""; Stderr = "cannot stat file" }
            | _ -> invalidOp ("Unexpected generator-profile command: " + executable + " " + String.concat " " arguments)
        let environment: HostEnvironment = { HostEnvironment.system with Root = root.FullName; Run = run }
        let writeHostFile (logicalPath: string) (body: byte[]) =
            let path = HostEnvironment.path environment logicalPath
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            File.WriteAllBytes(path, body)
            path
        let encode (value: string) = System.Text.Encoding.UTF8.GetBytes value
        try
            writeHostFile "/etc/debian_version" (encode "13.8\n") |> ignore
            writeHostFile "/proc/1/environ" (encode "HOME=/\000PATH=/usr/sbin:/usr/bin:/sbin:/bin\000") |> ignore
            writeHostFile "/proc/1/exe" (encode "mock systemd executable") |> ignore
            action environment writeHostFile (fun result -> managerEnvironment <- result) (fun result -> managerConfiguration <- result)
        finally
            if Directory.Exists root.FullName then root.Delete(true)

    let bootstrapUnitName = "dorothy-docker-firewall-bootstrap.service"
    let bootstrapHelperPath = "/var/cache/keroosha-iac/helper/linux-x64/" + String.replicate 64 "a"

    let withBootstrapServiceHost (dockerResult: CommandResult) (packageResult: CommandResult) (action: HostEnvironment -> ResizeArray<string * string list> -> unit) =
        let root = Directory.CreateTempSubdirectory("dorothy-bootstrap-preflight-")
        let calls = ResizeArray<string * string list>()
        let ok stdout = { ExitCode = 0; Stdout = stdout; Stderr = "" }
        let run executable arguments _ =
            calls.Add((executable, arguments))
            match executable, arguments with
            | "/usr/bin/systemctl", [ "show"; "--property=LoadState,ActiveState,UnitFileState"; "--"; name ] when name = bootstrapUnitName ->
                ok "LoadState=not-found\nActiveState=inactive\nUnitFileState=disabled\n"
            | "/usr/bin/systemctl", [ "show"; "--property=LoadState,ExecStartPre,NeedDaemonReload"; "--"; "docker.service" ] ->
                dockerResult
            | "/usr/bin/dpkg-query", [ "--show"; "--showformat=${Status}\\n"; "docker.io" ] -> packageResult
            | "/usr/bin/systemctl", [ "show"; "--no-pager"; "--property=LoadState,ActiveState,SubState"; "--"; "firewalld.service" ] ->
                ok "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            | _ -> invalidOp ("Unexpected bootstrap preflight command: " + executable + " " + String.concat " " arguments)
        let environment: HostEnvironment = { HostEnvironment.system with Root = root.FullName; Run = run }
        try action environment calls
        finally
            if Directory.Exists root.FullName then root.Delete(true)

    let applyBootstrapGate (environment: HostEnvironment) =
        use request =
            JsonDocument.Parse(
                """{"operation":"apply","name":"dorothy-docker-firewall-bootstrap.service","managed":true,"configuration":"","restart":false,"dockerFence":[]}""")
        Services.handleWithExecutable bootstrapHelperPath environment request.RootElement |> ignore

    let assertNoBootstrapPublication (environment: HostEnvironment) (calls: ResizeArray<string * string list>) =
        let unitPath = HostEnvironment.path environment ("/etc/systemd/system/" + bootstrapUnitName)
        let hookPath =
            HostEnvironment.path environment
                ("/etc/systemd/system/docker.service.d/90-dorothy-" + bootstrapUnitName + ".conf")
        Assert.That(File.Exists unitPath, Is.False)
        Assert.That(File.Exists hookPath, Is.False)
        Assert.That(calls |> Seq.exists (fun (_, arguments) -> arguments = [ "daemon-reload" ]), Is.False)
        Assert.That(
            calls |> Seq.exists (fun (_, arguments) ->
                not arguments.IsEmpty && List.contains arguments.Head [ "start"; "enable"; "reenable"; "restart" ]),
            Is.False)

    let assertRejectedFromEmptyInventory (environment: HostEnvironment) (addUnsafeItem: unit -> unit) =
        Assert.That(Services.coldGeneratorProfile environment, Is.True, "The empty generator inventory must be a passing baseline.")
        addUnsafeItem ()
        Assert.That(Services.coldGeneratorProfile environment, Is.False)

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
    [<Test>]
    member _.``Cold generator profile permits missing and empty generator directories``() =
        withGeneratorHost (fun environment _ _ _ ->
            Assert.That(Services.coldGeneratorProfile environment, Is.True)
            for directory in generatorDirectories do
                Directory.CreateDirectory(HostEnvironment.path environment directory) |> ignore
            Assert.That(Services.coldGeneratorProfile environment, Is.True))

    [<TestCase("/etc/systemd/system-generators/untrusted")>]
    [<TestCase("/run/systemd/system-generators/untrusted")>]
    [<TestCase("/usr/local/lib/systemd/system-generators/untrusted")>]
    [<TestCase("/etc/systemd/system-environment-generators/untrusted")>]
    [<TestCase("/run/systemd/system-environment-generators/untrusted")>]
    [<TestCase("/usr/local/lib/systemd/system-environment-generators/untrusted")>]
    member _.``Cold generator profile rejects site executables``(logicalPath: string) =
        withGeneratorHost (fun environment writeHostFile _ _ ->
            assertRejectedFromEmptyInventory environment (fun () ->
                let path = writeHostFile logicalPath (System.Text.Encoding.UTF8.GetBytes "#!/bin/sh\n")
                File.SetUnixFileMode(path, enum<UnixFileMode> 0o755)))

    [<TestCase("/etc/systemd/system-generators")>]
    [<TestCase("/run/systemd/system-generators")>]
    [<TestCase("/usr/local/lib/systemd/system-generators")>]
    [<TestCase("/etc/systemd/system-environment-generators")>]
    [<TestCase("/run/systemd/system-environment-generators")>]
    [<TestCase("/usr/local/lib/systemd/system-environment-generators")>]
    member _.``Cold generator profile rejects unknown site symlinks``(logicalDirectory: string) =
        withGeneratorHost (fun environment _ _ _ ->
            assertRejectedFromEmptyInventory environment (fun () ->
                let path = HostEnvironment.path environment (logicalDirectory + "/unknown-generator")
                Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
                File.CreateSymbolicLink(path, Path.Combine(environment.Root, "unknown-generator-target")) |> ignore))

    [<Test>]
    member _.``Cold generator profile rejects a vendor executable masquerading as a stock generator``() =
        withGeneratorHost (fun environment writeHostFile _ _ ->
            assertRejectedFromEmptyInventory environment (fun () ->
                let path =
                    writeHostFile
                        "/usr/lib/systemd/system-generators/systemd-fstab-generator"
                        (System.Text.Encoding.UTF8.GetBytes "not the Debian stock generator")
                File.SetUnixFileMode(path, enum<UnixFileMode> 0o755)))

    [<Test>]
    member _.``Cold generator profile rejects vendor environment generators``() =
        withGeneratorHost (fun environment writeHostFile _ _ ->
            assertRejectedFromEmptyInventory environment (fun () ->
                let path =
                    writeHostFile
                        "/usr/lib/systemd/system-environment-generators/vendor-generator"
                        (System.Text.Encoding.UTF8.GetBytes "#!/bin/sh\n")
                File.SetUnixFileMode(path, enum<UnixFileMode> 0o755)))

    [<TestCase("SYSTEMD_GENERATOR_PATH")>]
    [<TestCase("SYSTEMD_ENVIRONMENT_GENERATOR_PATH")>]
    member _.``Cold generator profile rejects PID1 generator path overrides``(variable: string) =
        withGeneratorHost (fun environment writeHostFile _ _ ->
            assertRejectedFromEmptyInventory environment (fun () ->
                let pid1Environment =
                    "HOME=/\000PATH=/usr/sbin:/usr/bin:/sbin:/bin\000"
                    + variable + "=/opt/unapproved\000"
                writeHostFile "/proc/1/environ" (System.Text.Encoding.UTF8.GetBytes pid1Environment) |> ignore))

    [<TestCase("SYSTEMD_GENERATOR_PATH")>]
    [<TestCase("SYSTEMD_ENVIRONMENT_GENERATOR_PATH")>]
    member _.``Cold generator profile rejects manager generator path overrides``(variable: string) =
        withGeneratorHost (fun environment _ setManagerEnvironment _ ->
            assertRejectedFromEmptyInventory environment (fun () ->
                setManagerEnvironment
                    { ExitCode = 0
                      Stdout = "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n" + variable + "=/opt/unapproved\n"
                      Stderr = "" }))


    [<TestCase("ManagerEnvironment=")>]
    [<TestCase("ManagerEnvironment=PATH=/usr/local/bin")>]
    [<TestCase("UnknownManagerDirective=value")>]
    member _.``Cold generator profile rejects manager environment and unknown active settings``(directive: string) =
        withGeneratorHost (fun environment _ _ setManagerConfiguration ->
            assertRejectedFromEmptyInventory environment (fun () ->
                setManagerConfiguration
                    { ExitCode = 0
                      Stdout = stockManagerConfiguration + directive + "\n"
                      Stderr = "" }))

    [<Test>]
    member _.``Cold generator profile rejects unavailable manager configuration``() =
        withGeneratorHost (fun environment _ _ setManagerConfiguration ->
            assertRejectedFromEmptyInventory environment (fun () ->
                setManagerConfiguration { ExitCode = 1; Stdout = ""; Stderr = "systemd-analyze failed" }))

    [<TestCase("masked")>]
    [<TestCase("unrecognized")>]
    [<TestCase("opaque")>]
    [<TestCase("query-failure")>]
    member _.``Bootstrap refuses unclassifiable Docker state before publishing its gate``(observation: string) =
        let dockerResult =
            match observation with
            | "masked" ->
                { ExitCode = 0; Stdout = "LoadState=masked\nExecStartPre=\nNeedDaemonReload=no\n"; Stderr = "" }
            | "unrecognized" ->
                { ExitCode = 0; Stdout = "LoadState=alien\nExecStartPre=\nNeedDaemonReload=no\n"; Stderr = "" }
            | "opaque" ->
                { ExitCode = 0; Stdout = "LoadState=loaded\nExecStartPre=\nNeedDaemonReload=no\nUnknown=value\n"; Stderr = "" }
            | _ -> { ExitCode = 1; Stdout = ""; Stderr = "systemctl failed" }
        withBootstrapServiceHost dockerResult { ExitCode = 1; Stdout = ""; Stderr = "package absent" } (fun environment calls ->
            let error = Assert.Throws<Services.BackendError>(fun () -> applyBootstrapGate environment)
            Assert.That(error.Message, Does.Contain "classify Docker")
            Assert.That(calls |> Seq.exists (fun (executable, _) -> executable = "/usr/bin/dpkg-query"), Is.False)
            assertNoBootstrapPublication environment calls)

    [<Test>]
    member _.``Bootstrap refuses a loaded site unit without installed docker.io before publishing``() =
        let dockerResult =
            { ExitCode = 0; Stdout = "LoadState=loaded\nExecStartPre=\nNeedDaemonReload=no\n"; Stderr = "" }
        let packageResult = { ExitCode = 1; Stdout = ""; Stderr = "package absent" }
        withBootstrapServiceHost dockerResult packageResult (fun environment calls ->
            let error = Assert.Throws<Services.BackendError>(fun () -> applyBootstrapGate environment)
            Assert.That(error.Message, Does.Contain "classify Docker")
            Assert.That(calls |> Seq.exists (fun (executable, _) -> executable = "/usr/bin/dpkg-query"), Is.True)
            assertNoBootstrapPublication environment calls)

    [<Test>]
    member _.``Healthy installed Docker reaches admission checks while its future hook is absent``() =
        let dockerResult =
            { ExitCode = 0; Stdout = "LoadState=loaded\nExecStartPre=\nNeedDaemonReload=no\n"; Stderr = "" }
        let packageResult = { ExitCode = 0; Stdout = "install ok installed\n"; Stderr = "" }
        withBootstrapServiceHost dockerResult packageResult (fun environment calls ->
            let error = Assert.Throws<Firewalld.BackendError>(fun () -> applyBootstrapGate environment)
            Assert.That(error.Message, Does.Contain "native firewalld systemd unit is not loaded")
            Assert.That(calls |> Seq.exists (fun (executable, _) -> executable = "/usr/bin/dpkg-query"), Is.True)
            assertNoBootstrapPublication environment calls)
    [<Test>]
    member _.``Cold generator profile requires explicit PID1 and manager environment data``() =
        withGeneratorHost (fun environment writeHostFile setManagerEnvironment _ ->
            assertRejectedFromEmptyInventory environment (fun () ->
                File.Delete(HostEnvironment.path environment "/proc/1/environ"))
            // Restore PID1's environment before checking systemctl's independent evidence.
            writeHostFile
                "/proc/1/environ"
                (System.Text.Encoding.UTF8.GetBytes "HOME=/\000PATH=/usr/sbin:/usr/bin:/sbin:/bin\000")
            |> ignore
            assertRejectedFromEmptyInventory environment (fun () ->
                setManagerEnvironment { ExitCode = 1; Stdout = ""; Stderr = "systemctl failed" }))
