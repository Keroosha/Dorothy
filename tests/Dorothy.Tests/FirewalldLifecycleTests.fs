namespace Dorothy.Tests

open System
open System.IO
open System.Text
open System.Text.Json.Nodes
open System.Text.Json
open Dorothy.DSL
open Dorothy.HostHelper
open NUnit.Framework

[<TestFixture; NonParallelizable>]
type FirewalldLifecycleTests() =

    let physical (root: string) (logical: string) =
        Path.Combine(root, logical.TrimStart('/').Replace('/', Path.DirectorySeparatorChar))

    let writeFile (root: string) (logical: string) (text: string) (mode: int) =
        let target = physical root logical
        Directory.CreateDirectory(Path.GetDirectoryName target) |> ignore
        if logical.StartsWith("/var/lib/keroosha-iac/firewalld/", StringComparison.Ordinal) then
            File.SetUnixFileMode(Path.GetDirectoryName target, enum<UnixFileMode> 0o700)
        HostFiles.atomicWrite target (Encoding.UTF8.GetBytes text) (enum<UnixFileMode> mode)

    let journal (owner: string) (baseline: string option) (managed: string option) =
        let value = JsonObject()
        value["version"] <- JsonValue.Create 1
        value["ownerId"] <- JsonValue.Create owner
        value["baseline"] <- match baseline with None -> null | Some text -> JsonValue.Create text :> JsonNode
        value["managed"] <- match managed with None -> null | Some text -> JsonValue.Create text :> JsonNode
        value["pending"] <- null
        value["baselineMode"] <- JsonValue.Create 0o644
        value["managedMode"] <- JsonValue.Create 0o644
        value

    let recoveryUnitNames = FirewalldCommandFixture.recoveryUnitNames
    let dependencyQueryArguments = FirewalldCommandFixture.dependencyQueryArguments
    let unitPathArguments = FirewalldCommandFixture.unitPathArguments

    let withHostForNativeCommands
        (systemctlState: CommandResult option)
        (initialBootState: string)
        (dependencyOverrides: Map<string, Map<string, string>>)
        (action: HostEnvironment -> string -> ResizeArray<string list> -> ResizeArray<string list> -> unit)
        =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-lifecycle-" + Guid.NewGuid().ToString("N"))
        for directory in [ "etc/firewalld/zones"; "etc/systemd/system"; "run/lock"; "var/lib" ] do
            Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
        let systemctlCommands = ResizeArray<string list>()
        let busctlCommands = ResizeArray<string list>()
        let mutable bootState = initialBootState
        let unitRelativePath name =
            match name with
            | "keroosha-iac-firewalld-rollback.service" -> "etc/systemd/system/keroosha-iac-firewalld-rollback.service"
            | "keroosha-iac-firewalld-rollback.timer" -> "etc/systemd/system/keroosha-iac-firewalld-rollback.timer"
            | "keroosha-iac-firewalld-boot-recovery.service" -> "etc/systemd/system/keroosha-iac-firewalld-boot-recovery.service"
            | "keroosha-iac-firewalld-postboot-recovery.service" -> "etc/systemd/system/keroosha-iac-firewalld-postboot-recovery.service"
            | "keroosha-iac-firewalld-boot-containment.service" -> "etc/systemd/system/keroosha-iac-firewalld-boot-containment.service"
            | _ -> invalidArg (nameof name) "Unexpected recovery fixture unit."
        let unitPhysicalPath name = Path.Combine(root, unitRelativePath name)
        let run (executable: string) (arguments: string list) (_input: string option) : CommandResult =
            if executable = "stat" then
                if List.contains "%u:%g" arguments then
                    { ExitCode = 0; Stdout = "0:0"; Stderr = "" }
                else
                    let target = List.last arguments
                    let mode = File.GetUnixFileMode target |> int |> fun value -> Convert.ToString(value, 8)
                    { ExitCode = 0; Stdout = "0:" + mode; Stderr = "" }
            elif executable = "/usr/bin/busctl" then
                busctlCommands.Add arguments
                if arguments = unitPathArguments then
                    { ExitCode = 0; Stderr = ""; Stdout = FirewalldCommandFixture.unitPathResponse }
                else
                    invalidOp ("Unexpected busctl command: " + String.concat " " arguments)
            elif executable = "/usr/bin/systemctl" then
                systemctlCommands.Add arguments
                let mutable response: CommandResult = { ExitCode = 0; Stdout = "success"; Stderr = "" }
                let createLink directory name target =
                    Directory.CreateDirectory(directory) |> ignore
                    let link = Path.Combine(directory, name)
                    if isNull (FileInfo(link).LinkTarget) && not (File.Exists link || Directory.Exists link) then
                        File.CreateSymbolicLink(link, target) |> ignore
                match arguments with
                | [ "show"; "--property=ActiveState"; "--value"; "firewalld.service" ] ->
                    response <- systemctlState |> Option.defaultValue response
                | args when args = dependencyQueryArguments ->
                    response <-
                        { ExitCode = 0
                          Stdout = FirewalldCommandFixture.systemdDependencyOutput root dependencyOverrides
                          Stderr = "" }
                | [ "show"; "--all"; "-p"; _; "--"; name ] ->
                    let path = unitPhysicalPath name
                    let loaded = File.Exists path
                    let state = if name.EndsWith("-boot-recovery.service") then bootState else "inactive"
                    let load = if state = "load-error" then "error" elif loaded then "loaded" else "not-found"
                    let sub = match state with "inactive" -> "dead" | "active" -> "exited" | _ -> state
                    response <-
                        { ExitCode = if state = "error" then 1 elif loaded then 0 else 4
                          Stderr = ""
                          Stdout = String.concat "\n" [
                              "Id=" + name; "LoadState=" + load; "ActiveState=" + state; "SubState=" + sub
                              "Result=success"; "Job="; "DropInPaths="; "NeedDaemonReload=no"
                              "FragmentPath=" + (if loaded then path else "") ] }
                | [ "enable"; "keroosha-iac-firewalld-boot-recovery.service" ] ->
                    createLink (Path.Combine(root, "etc/systemd/system/multi-user.target.wants")) "keroosha-iac-firewalld-boot-recovery.service" "../keroosha-iac-firewalld-boot-recovery.service"
                    createLink (Path.Combine(root, "etc/systemd/system/firewalld.service.wants")) "keroosha-iac-firewalld-boot-recovery.service" "../keroosha-iac-firewalld-boot-recovery.service"
                | [ "start"; "keroosha-iac-firewalld-boot-recovery.service" ] ->
                    if bootState = "failed" then
                        response <- { ExitCode = 1; Stdout = ""; Stderr = "unit is failed" }
                    else bootState <- "active"
                | [ "enable"; "keroosha-iac-firewalld-postboot-recovery.service" ] ->
                    createLink (Path.Combine(root, "etc/systemd/system/multi-user.target.wants")) "keroosha-iac-firewalld-postboot-recovery.service" "../keroosha-iac-firewalld-postboot-recovery.service"
                | [ "enable"; "keroosha-iac-firewalld-boot-containment.service" ] ->
                    createLink (Path.Combine(root, "etc/systemd/system/multi-user.target.wants")) "keroosha-iac-firewalld-boot-containment.service" "../keroosha-iac-firewalld-boot-containment.service"
                | [ "enable"; "keroosha-iac-firewalld-rollback.timer" ] ->
                    createLink (Path.Combine(root, "etc/systemd/system/timers.target.wants")) "keroosha-iac-firewalld-rollback.timer" (Path.Combine(root, "etc/systemd/system/keroosha-iac-firewalld-rollback.timer"))
                | [ "start"; "keroosha-iac-firewalld-rollback.timer" ]
                | [ "restart"; "keroosha-iac-firewalld-rollback.timer" ]
                | [ "stop"; "keroosha-iac-firewalld-rollback.timer" ]
                | [ "stop"; "keroosha-iac-firewalld-rollback.service" ] -> ()
                | _ -> ()
                response
            else
                invalidOp ("Unexpected lifecycle command: " + executable + " " + String.concat " " arguments)
        let environment: HostEnvironment =
            { Root = root
              Run = run
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        try action environment root systemctlCommands busctlCommands
        finally
            if Directory.Exists root then Directory.Delete(root, true)
    let withHostForSystemctlStateAndCommands
        (systemctlState: CommandResult option)
        (initialBootState: string)
        (action: HostEnvironment -> string -> ResizeArray<string list> -> unit)
        =
        withHostForNativeCommands systemctlState initialBootState Map.empty (fun environment root systemctl _ ->
            action environment root systemctl)
    let withHostForDependencyOverrides
        (dependencyOverrides: Map<string, Map<string, string>>)
        (action: HostEnvironment -> string -> ResizeArray<string list> -> ResizeArray<string list> -> unit)
        =
        withHostForNativeCommands None "inactive" dependencyOverrides action
    let withHostForSystemctlState (systemctlState: CommandResult option) (action: HostEnvironment -> string -> unit) =
        withHostForSystemctlStateAndCommands systemctlState "inactive" (fun environment root _ -> action environment root)
    let withHost (action: HostEnvironment -> string -> unit) =
        withHostForSystemctlState None action

    let saveBootstrapSettingsOwner (root: string) (settingsOwner: string) =
        let baseline = JsonObject()
        baseline["etcExists"] <- JsonValue.Create true
        baseline["etcStrictValue"] <- JsonValue.Create "no"
        baseline["etcMode"] <- JsonValue.Create 0o644
        let value = JsonObject()
        value["version"] <- JsonValue.Create 1
        value["ownerId"] <- JsonValue.Create settingsOwner
        value["baseline"] <- JsonValue.Create(baseline.ToJsonString())
        value["managed"] <- JsonValue.Create "StrictForwardPorts=yes\n"
        value["pending"] <- null
        let text = value.ToJsonString()
        let path = "/var/lib/keroosha-iac/firewalld/settings-strict-forward-ports.json"
        writeFile root path text 0o600
        path, text

    let configuration = FirewalldModel.empty "zone" "lifecycle"
    let logicalPath = "/etc/firewalld/zones/lifecycle.xml"
    let owner = "test-owner"
    let before = "<zone><service name=\"ssh\"/></zone>\n"
    let after = "<zone><service name=\"ssh\"/><port port=\"443\" protocol=\"tcp\"/></zone>\n"

    let readState (_scope: JsonObject option) (contents: string option) = contents

    let writeState (root: string) (logical: string) (scope: JsonObject option) (expected: string option) (contents: string option) (mode: int) =
        if scope.IsSome then invalidOp "The lifecycle test writer only supports whole-file scope."
        let target = physical root logical
        let current = if File.Exists target then Some(File.ReadAllText target) else None
        if current <> expected then invalidOp "The test file changed before scoped write."
        match contents with
        | Some text -> writeFile root logical text mode
        | None ->
            if File.Exists target then
                File.Delete target
                HostFiles.syncDirectory (Path.GetDirectoryName target)

    let rollbackProof () =
        let proof = JsonObject()
        proof["version"] <- JsonValue.Create 1
        proof["kind"] <- JsonValue.Create "test"
        proof

    let transactWithMode
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (logical: string)
        (before: string option)
        (beforeMode: int)
        (after: string option)
        (afterMode: int)
        (managedBefore: string option)
        (managedAfter: string option)
        (releaseOnRollback: bool)
        (deleteOnConfirm: bool)
        =
        FirewalldLifecycle.transact environment c journal releaseOnRollback deleteOnConfirm logical None
            before beforeMode after afterMode managedBefore managedAfter (Some(rollbackProof()))
            readState (writeState environment.Root logical) (fun _ _ -> ()) (fun _ -> ()) (fun _ _ -> ())

    let transact
        (environment: HostEnvironment)
        (journal: JsonObject)
        (before: string option)
        (after: string option)
        (releaseOnRollback: bool)
        (deleteOnConfirm: bool)
        =
        transactWithMode environment configuration journal logicalPath before 0o644 after 0o644 before after releaseOnRollback deleteOnConfirm

    let recoverTransaction
        (environment: HostEnvironment)
        (phase: FirewalldLifecycle.RecoveryPhase)
        (transaction: FirewalldLifecycle.PendingTransaction)
        (journal: JsonObject)
        =
        FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration journal transaction.Path phase
            readState (writeState environment.Root transaction.Path) (fun _ _ -> ())

    let pendingRecord (version: int) (activationStarted: bool) (awaitingPostBoot: bool) =
        let value = JsonObject()
        value["version"] <- JsonValue.Create version
        value["nonce"] <- JsonValue.Create(String.replicate 32 "a")
        value["ownerId"] <- JsonValue.Create owner
        value["configuration"] <- JsonValue.Create(FirewalldModel.toJson configuration)
        value["path"] <- JsonValue.Create logicalPath
        let optionalString (key: string) (text: string option) =
            value[key] <- match text with None -> null | Some contents -> JsonValue.Create contents :> JsonNode
        optionalString "before" (Some before)
        value["beforeMode"] <- JsonValue.Create 0o644
        optionalString "after" (Some after)
        value["afterMode"] <- JsonValue.Create 0o644
        optionalString "managedBefore" (Some before)
        optionalString "managedAfter" (Some after)
        if version = 2 then
            value["scope"] <- null
            value["rollbackProof"] <- rollbackProof()
            value["activationStarted"] <- JsonValue.Create activationStarted
            value["awaitingPostBoot"] <- JsonValue.Create awaitingPostBoot
        value["releaseOnRollback"] <- JsonValue.Create false
        value["deleteOnConfirm"] <- JsonValue.Create false
        value["status"] <- JsonValue.Create "pending"
        value
    let nativeProgressRecord (strategy: string) (completedSteps: int) (awaitingPostBoot: bool) =
        let value = pendingRecord 2 true awaitingPostBoot
        value["version"] <- JsonValue.Create 3
        value["rollbackProof"].AsObject()["strategy"] <- JsonValue.Create strategy
        value["nativeProgress"] <-
            JsonNode.Parse(sprintf """{"completedSteps":%d,"inFlightStep":null}""" completedSteps)
        value

    let savePendingRecord (root: string) (record: JsonObject) =
        writeFile root "/var/lib/keroosha-iac/firewalld/pending-transaction.json" (record.ToJsonString()) 0o600

    let awaitingFixture root (beforeState: string option) (afterState: string option) includeUndo =
        let record = nativeProgressRecord "object-delta" 1 true
        let generation = Guid.NewGuid().ToString("D")
        writeFile root "/proc/sys/kernel/random/boot_id" generation 0o644
        record["version"] <- JsonValue.Create 5
        record["before"] <- beforeState |> Option.map (fun s -> JsonValue.Create(s) :> JsonNode) |> Option.toObj
        record["after"] <- afterState |> Option.map (fun s -> JsonValue.Create(s) :> JsonNode) |> Option.toObj
        record["deleteOnConfirm"] <- JsonValue.Create afterState.IsNone
        record["releaseOnRollback"] <- JsonValue.Create beforeState.IsNone
        record["nativeUndo"] <-
            if includeUndo then
                JsonNode.Parse(sprintf """{"bootId":"%s","remainingSteps":0,"inFlightStep":null,"preimageVerified":false}""" generation)
            else null
        let stored = journal owner beforeState beforeState
        stored["pending"] <- record.DeepClone()
        writeFile root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json" (stored.ToJsonString()) 0o600
        savePendingRecord root record
        stored

    let probeAwaiting environment phase restoreRuntime =
        let recover (t: FirewalldLifecycle.PendingTransaction) stored =
            FirewalldLifecycle.recoverPendingTransaction environment t.Configuration (Option.get stored) t.Path phase
                readState (fun _ _ _ _ -> Assert.Fail "Preboot already consumed disk-write authority.") restoreRuntime
        match phase with
        | FirewalldLifecycle.ActiveDaemon -> FirewalldLifecycle.recoverPending environment recover
        | FirewalldLifecycle.BootAfterFirewalld -> FirewalldLifecycle.recoverPendingPostBoot environment recover
        | _ -> invalidArg (nameof phase) "Expected a retry or ordered postboot."

    let fileSnapshot path =
        if File.Exists path then Some(File.ReadAllBytes path, File.GetUnixFileMode path) else None

    let reservationSnapshot root =
        [ "pending-transaction.json"; "zone-lifecycle.json" ]
        |> List.map (fun name -> fileSnapshot (physical root ("/var/lib/keroosha-iac/firewalld/" + name)))

    let setTarget root contents mode =
        match contents with
        | Some text -> writeFile root logicalPath text mode
        | None -> File.Delete(physical root logicalPath)

    [<Test>]
    member _.``Reverse receipts survive reload and cannot grow or be confirmed``() =
        withHost (fun env root ->
            let generation = Guid.NewGuid()
            writeFile root "/proc/sys/kernel/random/boot_id" (string generation) 0o644
            let record = pendingRecord 2 true false
            record["version"] <- JsonValue.Create 4
            record["nativeProgress"] <- JsonNode.Parse("""{"completedSteps":2,"inFlightStep":null}""")
            record["nativeUndo"] <- null
            savePendingRecord root record
            let load () =
                let reservation = FirewalldLifecycle.pending env |> Option.get
                FirewalldLifecycle.undoJournal env reservation |> Option.get
            let first = load ()
            first.Persist { RemainingSteps = 2; InFlightStep = Some 1; PreimageVerified = false }
            use migrated = JsonDocument.Parse(File.ReadAllText(physical root "/var/lib/keroosha-iac/firewalld/pending-transaction.json"))
            Assert.That(migrated.RootElement.GetProperty("version").GetInt32(), Is.EqualTo 5)
            Assert.That(migrated.RootElement.GetProperty("nativeUndo").GetProperty("preimageVerified").GetBoolean(), Is.False)
            let interrupted = load ()
            Assert.That(interrupted.Previous.Value.InFlightStep, Is.EqualTo(Some 1))
            Assert.That(interrupted.Previous.Value.PreimageVerified, Is.False)
            Assert.Throws<InvalidOperationException>(fun () ->
                interrupted.Persist { RemainingSteps = 2; InFlightStep = Some 1; PreimageVerified = false }) |> ignore
            first.Persist { RemainingSteps = 1; InFlightStep = None; PreimageVerified = false }
            let resumed = load ()
            Assert.That(resumed.Previous.Value.RemainingSteps, Is.EqualTo 1)
            Assert.That(resumed.Previous.Value.PreimageVerified, Is.False)
            Assert.Throws<InvalidOperationException>(fun () ->
                resumed.Persist { RemainingSteps = 2; InFlightStep = Some 1; PreimageVerified = false }) |> ignore
            let stored = journal owner (Some before) (Some after)
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldLifecycle.confirm env configuration stored (String.replicate 32 "a") readState) |> ignore
            writeFile root "/proc/sys/kernel/random/boot_id" (string (Guid.NewGuid())) 0o644
            Assert.Throws<InvalidOperationException>(fun () -> load () |> ignore) |> ignore)

    [<Test>]
    member _.``Legacy terminal inverse is unverified and migrates without changing its generation``() =
        withHost (fun env root ->
            let generation = Guid.NewGuid()
            writeFile root "/proc/sys/kernel/random/boot_id" (string generation) 0o644
            let record = pendingRecord 2 true false
            record["version"] <- JsonValue.Create 4
            record["nativeProgress"] <- JsonNode.Parse("""{"completedSteps":2,"inFlightStep":null}""")
            let undo = JsonObject()
            undo["bootId"] <- JsonValue.Create(generation.ToString("D"))
            undo["remainingSteps"] <- JsonValue.Create 0
            undo["inFlightStep"] <- null
            record["nativeUndo"] <- undo
            savePendingRecord root record
            let load () =
                let reservation = FirewalldLifecycle.pending env |> Option.get
                FirewalldLifecycle.undoJournal env reservation |> Option.get
            let terminal = load ()
            Assert.That(terminal.Previous.Value.RemainingSteps, Is.Zero)
            Assert.That(terminal.Previous.Value.PreimageVerified, Is.False)
            terminal.Persist { RemainingSteps = 0; InFlightStep = None; PreimageVerified = true }
            use stored = JsonDocument.Parse(File.ReadAllText(physical root "/var/lib/keroosha-iac/firewalld/pending-transaction.json"))
            let serialized = stored.RootElement
            Assert.That(serialized.GetProperty("version").GetInt32(), Is.EqualTo 5)
            Assert.That(serialized.GetProperty("ownerId").GetString(), Is.EqualTo owner)
            Assert.That(serialized.GetProperty("nativeUndo").GetProperty("bootId").GetString(), Is.EqualTo(generation.ToString("D")))
            Assert.That(serialized.GetProperty("nativeUndo").GetProperty("remainingSteps").GetInt32(), Is.Zero)
            Assert.That(serialized.GetProperty("nativeUndo").GetProperty("preimageVerified").GetBoolean(), Is.True)
            let verified = load ()
            Assert.That(verified.Previous.Value.PreimageVerified, Is.True)
            Assert.Throws<InvalidOperationException>(fun () ->
                verified.Persist { RemainingSteps = 1; InFlightStep = Some 0; PreimageVerified = false }) |> ignore
            Assert.Throws<InvalidOperationException>(fun () ->
                verified.Persist { RemainingSteps = 0; InFlightStep = None; PreimageVerified = true }) |> ignore
            Assert.Throws<InvalidOperationException>(fun () ->
                verified.Persist { RemainingSteps = 0; InFlightStep = None; PreimageVerified = false }) |> ignore
            let pristineRecord = pendingRecord 2 true false
            pristineRecord["version"] <- JsonValue.Create 4
            pristineRecord["nativeProgress"] <- JsonNode.Parse("""{"completedSteps":0,"inFlightStep":null}""")
            pristineRecord["nativeUndo"] <- null
            savePendingRecord root pristineRecord
            Assert.Throws<InvalidOperationException>(fun () ->
                (load ()).Persist { RemainingSteps = 0; InFlightStep = None; PreimageVerified = false }) |> ignore)

    [<Test>]
    member _.``Ordered pristine postboot receipt is unverified and only global state advances``() =
        withHost (fun env root ->
            let generation = Guid.NewGuid()
            writeFile root "/proc/sys/kernel/random/boot_id" (string generation) 0o644
            let record = pendingRecord 2 true true
            record["version"] <- JsonValue.Create 4
            record["nativeProgress"] <- JsonNode.Parse("""{"completedSteps":0,"inFlightStep":null}""")
            record["nativeUndo"] <- null
            savePendingRecord root record
            let ownerRecord = journal owner (Some before) (Some after)
            ownerRecord["pending"] <- record.DeepClone()
            let ownerPath = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            let ownerText = ownerRecord.ToJsonString()
            writeFile root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json" ownerText 0o600
            let load () =
                let reservation = FirewalldLifecycle.pending env |> Option.get
                FirewalldLifecycle.undoJournal env reservation |> Option.get
            let inverse = load ()
            Assert.Throws<InvalidOperationException>(fun () ->
                inverse.Persist { RemainingSteps = 0; InFlightStep = None; PreimageVerified = true }) |> ignore

            inverse.Persist { RemainingSteps = 0; InFlightStep = None; PreimageVerified = false }
            use unverified = JsonDocument.Parse(File.ReadAllText(physical root "/var/lib/keroosha-iac/firewalld/pending-transaction.json"))
            Assert.That(unverified.RootElement.GetProperty("version").GetInt32(), Is.EqualTo 5)
            Assert.That(unverified.RootElement.GetProperty("nativeUndo").GetProperty("remainingSteps").GetInt32(), Is.Zero)
            Assert.That(unverified.RootElement.GetProperty("nativeUndo").GetProperty("preimageVerified").GetBoolean(), Is.False)
            Assert.That(File.ReadAllText ownerPath, Is.EqualTo ownerText)
            let pendingPath = physical root "/var/lib/keroosha-iac/firewalld/pending-transaction.json"
            let backupPath = pendingPath + ".saved"
            File.Move(pendingPath, backupPath)
            File.CreateSymbolicLink(pendingPath, Path.GetFileName backupPath) |> ignore
            Assert.Throws<InvalidOperationException>(fun () ->
                inverse.Persist { RemainingSteps = 0; InFlightStep = None; PreimageVerified = true }) |> ignore
            File.Delete pendingPath
            File.Move(backupPath, pendingPath)
            Assert.That((load ()).Previous.Value.PreimageVerified, Is.False)
            inverse.Persist { RemainingSteps = 0; InFlightStep = None; PreimageVerified = true }
            Assert.That((load ()).Previous.Value.PreimageVerified, Is.True)
            Assert.That(File.ReadAllText ownerPath, Is.EqualTo ownerText))

    [<Test>]
    member _.``Version five rejects a verified nonterminal inverse receipt``() =
        withHost (fun env root ->
            let record = pendingRecord 2 true false
            record["version"] <- JsonValue.Create 5
            record["nativeProgress"] <- JsonNode.Parse("""{"completedSteps":2,"inFlightStep":null}""")
            let undo = JsonObject()
            undo["bootId"] <- JsonValue.Create(Guid.NewGuid().ToString("D"))
            undo["remainingSteps"] <- JsonValue.Create 1
            undo["inFlightStep"] <- null
            undo["preimageVerified"] <- JsonValue.Create true
            record["nativeUndo"] <- undo
            savePendingRecord root record
            Assert.Throws<InvalidOperationException>(fun () -> FirewalldLifecycle.pending env |> ignore) |> ignore)

    [<Test>]
    member _.``Apply failure diagnostic describes rollback without assuming native work``() =
        withHost (fun env root ->
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            let failure =
                Assert.Throws<InvalidOperationException>(fun () ->
                    FirewalldLifecycle.transact env configuration value false false logicalPath None
                        (Some before) 0o644 (Some after) 0o644 (Some before) (Some after) (Some(rollbackProof()))
                        readState (writeState env.Root logicalPath) (fun _ _ -> ())
                        (fun _ -> invalidOp "simulated apply failure") (fun _ _ -> ()) |> ignore)
            Assert.That(failure.Message, Does.Contain "rollback completed for this transaction")
            Assert.That(failure.Message, Does.Not.Contain "recorded working runtime")
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
            Assert.That(FirewalldLifecycle.pending env, Is.EqualTo None))

    [<Test>]
    member _.``Fresh confirmation commits the journaled candidate``() =
        withHost (fun environment root ->
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            let nonce = transact environment value (Some before) (Some after) false false
            Assert.That(nonce.Length, Is.EqualTo 32)
            use marker = JsonDocument.Parse(File.ReadAllText(physical root "/var/lib/keroosha-iac/firewalld/pending-transaction.json"))
            Assert.That(marker.RootElement.GetProperty("version").GetInt32(), Is.EqualTo 5)
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo after)
            let journalPath = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            FirewalldLifecycle.confirm environment configuration value nonce readState
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None)
            use stored = JsonDocument.Parse(File.ReadAllText journalPath)
            Assert.That(stored.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Null)
            Assert.That(stored.RootElement.GetProperty("managed").GetString(), Is.EqualTo after)
            let next = "<zone><service name=\"ssh\"/><port port=\"443\" protocol=\"tcp\"/><port port=\"8443\" protocol=\"tcp\"/></zone>\n"
            let nextNonce = transact environment value (Some after) (Some next) false false
            FirewalldLifecycle.confirm environment configuration value nextNonce readState
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo next))

    [<Test>]
    member _.``Host-global pending transaction rejects a competing resource``() =
        withHost (fun environment root ->
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            transact environment value (Some before) (Some after) false false |> ignore
            let otherConfiguration = FirewalldModel.empty "zone" "other"
            let otherPath = "/etc/firewalld/zones/other.xml"
            let otherValue = journal "other-owner" None None
            let failure =
                Assert.Throws<InvalidOperationException>(fun () ->
                    transactWithMode environment otherConfiguration otherValue otherPath None 0o644 (Some "<zone/>\n") 0o644 None (Some "<zone/>\n") true false |> ignore)
            Assert.That(failure.Message, Does.Contain "Another firewalld transaction"))

    [<TestCase(0o600)>]
    [<TestCase(0o640)>]
    [<TestCase(0o644)>]
    member _.``Safe override modes survive apply and watchdog rollback``(mode: int) =
        withHost (fun environment root ->
            let target = physical root logicalPath
            writeFile root logicalPath before mode
            let value = journal owner (Some before) (Some before)
            value["baselineMode"] <- JsonValue.Create mode
            value["managedMode"] <- JsonValue.Create mode
            let nonce =
                transactWithMode environment configuration value logicalPath (Some before) mode (Some after) mode
                    (Some before) (Some after) false false
            Assert.That(nonce, Is.Not.Empty)
            Assert.That(int (File.GetUnixFileMode target), Is.EqualTo mode)
            FirewalldLifecycle.recoverPending environment (fun transaction storedJournal ->
                let journal = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                recoverTransaction environment FirewalldLifecycle.ActiveDaemon transaction journal)
            Assert.That(File.ReadAllText target, Is.EqualTo before)
            Assert.That(int (File.GetUnixFileMode target), Is.EqualTo mode))

    [<Test>]
    member _.``Independent recovery restores exact pre-delete bytes after confirmation is lost``() =
        withHost (fun environment root ->
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            let nonce = transact environment value (Some before) (Some after) false false
            Assert.That(nonce, Is.Not.Empty)
            let journalPath = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            FirewalldLifecycle.recoverPending environment (fun transaction storedJournal ->
                let journal = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                recoverTransaction environment FirewalldLifecycle.ActiveDaemon transaction journal)
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None)
            use recovered = JsonDocument.Parse(File.ReadAllText journalPath)
            Assert.That(recovered.RootElement.GetProperty("managed").GetString(), Is.EqualTo before)
            Assert.That(recovered.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Null))

    [<Test>]
    member _.``Delete confirmation releases only its own journal after exact baseline restore``() =
        withHost (fun environment root ->
            let target = physical root logicalPath
            let baseline = "<zone target=\"DROP\"><interface name=\"eth0\"/></zone>\n"
            let managed = "<zone target=\"DROP\"/>\n"
            writeFile root logicalPath managed 0o644
            let value = journal owner (Some baseline) (Some managed)
            value["baselineMode"] <- JsonValue.Create 0o644
            let journalPath = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            let nonce = transact environment value (Some managed) (Some baseline) false true
            Assert.That(nonce, Is.Not.Empty)
            Assert.That(File.ReadAllText target, Is.EqualTo baseline)
            FirewalldLifecycle.confirm environment configuration value nonce readState
            Assert.That(File.Exists journalPath, Is.False)
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None)
            Assert.That(File.ReadAllText target, Is.EqualTo baseline))

    [<Test>]
    member _.``Global marker recovers a first-create crash before the owner journal exists``() =
        withHost (fun environment root ->
            let marker = pendingRecord 2 false false
            marker["releaseOnRollback"] <- JsonValue.Create true
            writeFile root logicalPath after 0o644
            savePendingRecord root marker
            FirewalldLifecycle.recoverPending environment (fun transaction storedJournal ->
                let stored =
                    storedJournal
                    |> Option.defaultWith (fun () ->
                        let value = JsonObject()
                        value["ownerId"] <- JsonValue.Create owner
                        value)
                recoverTransaction environment FirewalldLifecycle.ActiveDaemon transaction stored)
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None)
            Assert.That(File.Exists(physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"), Is.False))

    [<Test>]
    member _.``Empty boot latch fast path does not wait for the active transaction lock``() =
        withHost (fun environment _ ->
            let held = HostFiles.lockFile (physical environment.Root "/run/lock/keroosha-firewalld-backend.lock")
            let recovery =
                System.Threading.Tasks.Task.Run(fun () ->
                    FirewalldLifecycle.recoverPendingBoot environment (fun _ _ -> invalidOp "No transaction should be dispatched."))
            let finishedWhileLocked = recovery.Wait(TimeSpan.FromSeconds 2.0)
            held.Dispose()
            recovery.GetAwaiter().GetResult()
            Assert.That(finishedWhileLocked, Is.True))

    [<TestCase(true); TestCase(false)>]
    member _.``Boot rollback retains preexisting runtime divergence from the first durable intent``(started: bool) =
        withHost (fun environment root ->
            let journalPath = "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            let record = pendingRecord 2 started false
            record["rollbackProof"].AsObject().["strategy"] <- JsonValue.Create "runtime-delta"
            if not started then record["after"] <- JsonValue.Create before
            let value = journal owner (Some before) (Some before)
            value["pending"] <- record.DeepClone()
            writeFile root journalPath (value.ToJsonString()) 0o600
            writeFile root logicalPath (if started then after else before) 0o644
            savePendingRecord root record
            let restored = ResizeArray<FirewalldLifecycle.RecoveryPhase>()
            let recover phase (transaction: FirewalldLifecycle.PendingTransaction) storedJournal =
                let stored = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration stored transaction.Path phase
                    readState (writeState root transaction.Path) (fun _ actualPhase -> restored.Add actualPhase)
            FirewalldLifecycle.recoverPendingBoot environment (recover FirewalldLifecycle.BootBeforeFirewalld)
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
            Assert.That(restored, Is.Empty)
            let awaiting = FirewalldLifecycle.pending environment |> Option.defaultWith (fun () -> failwith "Expected post-boot continuation")
            Assert.That(awaiting.AwaitingPostBoot, Is.True)
            use staged = JsonDocument.Parse(File.ReadAllText(physical root journalPath))
            Assert.That(staged.RootElement.GetProperty("pending").GetProperty("awaitingPostBoot").GetBoolean(), Is.True)
            FirewalldLifecycle.recoverPendingPostBoot environment (recover FirewalldLifecycle.BootAfterFirewalld)
            Assert.That(restored.ToArray(), Is.EquivalentTo [| FirewalldLifecycle.BootAfterFirewalld |])
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None)
            use finished = JsonDocument.Parse(File.ReadAllText(physical root journalPath))
            Assert.That(finished.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Null))

    [<TestCase("inactive", 0, true)>]
    [<TestCase("active", 0, false)>]
    [<TestCase("activating", 0, false)>]
    [<TestCase("inactive", 1, false)>]
    member _.``Legacy object repair upgrades only after an inactive daemon observation``(state: string, exitCode: int, shouldMigrate: bool) =
        let observation = { ExitCode = exitCode; Stdout = state; Stderr = "" }
        withHostForSystemctlState (Some observation) (fun environment root ->
            let generation = Guid.NewGuid()
            writeFile root "/proc/sys/kernel/random/boot_id" (string generation) 0o644
            let record = nativeProgressRecord "object-delta" 3 false
            let markerText = record.ToJsonString()
            let value = journal owner (Some before) (Some after)
            value["pending"] <- record.DeepClone()
            let ownerPath = "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            let ownerText = value.ToJsonString()
            writeFile root ownerPath ownerText 0o600
            writeFile root logicalPath before 0o644
            savePendingRecord root record
            let recover phase (transaction: FirewalldLifecycle.PendingTransaction) storedJournal =
                let stored = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration stored transaction.Path phase
                    readState (writeState root transaction.Path) (fun _ _ -> invalidOp "Boot-before recovery must not invoke native repair.")
            if shouldMigrate then
                FirewalldLifecycle.recoverPendingBoot environment (recover FirewalldLifecycle.BootBeforeFirewalld)
                let migrated = FirewalldLifecycle.pending environment |> Option.defaultWith (fun () -> failwith "Expected post-boot continuation")
                Assert.That(migrated.SchemaVersion, Is.EqualTo 4)
                Assert.That(migrated.OwnerId, Is.EqualTo owner)
                Assert.That(migrated.ActivationStarted, Is.True)
                Assert.That(migrated.AwaitingPostBoot, Is.True)
                Assert.That(migrated.NativeProgress.Value.CompletedSteps, Is.EqualTo 3)
                Assert.That(migrated.NativeUndo.IsNone, Is.True)
                Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
                use storedOwner = JsonDocument.Parse(File.ReadAllText(physical root ownerPath))
                let ownerPending = storedOwner.RootElement.GetProperty("pending")
                Assert.That(ownerPending.GetProperty("version").GetInt32(), Is.EqualTo 4)
                Assert.That(ownerPending.GetProperty("ownerId").GetString(), Is.EqualTo owner)
                Assert.That(ownerPending.GetProperty("activationStarted").GetBoolean(), Is.True)
                Assert.That(ownerPending.GetProperty("awaitingPostBoot").GetBoolean(), Is.True)
                Assert.That(ownerPending.GetProperty("nativeProgress").GetProperty("completedSteps").GetInt32(), Is.EqualTo 3)
                Assert.That(ownerPending.GetProperty("nativeUndo").ValueKind, Is.EqualTo JsonValueKind.Null)
                let inverse = FirewalldLifecycle.undoJournal environment migrated |> Option.get
                Assert.That(inverse.Previous.IsNone, Is.True)

                let mutable activeCallback = false
                let blocked =
                    Assert.Throws<InvalidOperationException>(fun () ->
                        FirewalldLifecycle.recoverPending environment (fun transaction storedJournal ->
                            let stored = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                            FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration stored transaction.Path
                                FirewalldLifecycle.ActiveDaemon readState (writeState root transaction.Path)
                                (fun _ _ -> activeCallback <- true)))
                Assert.That(blocked.Message, Does.Contain "Ordered post-boot recovery")
                Assert.That(activeCallback, Is.False)
                Assert.That((FirewalldLifecycle.pending environment).Value.AwaitingPostBoot, Is.True)
                Assert.That((FirewalldLifecycle.pending environment).Value.NativeUndo.IsNone, Is.True)
            else
                let blocked =
                    Assert.Throws<InvalidOperationException>(fun () ->
                        FirewalldLifecycle.recoverPendingBoot environment (recover FirewalldLifecycle.BootBeforeFirewalld))
                Assert.That(blocked.Message, Does.Contain "stopped firewalld")
                Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
                Assert.That(File.ReadAllText(physical root ownerPath), Is.EqualTo ownerText)
                Assert.That(File.ReadAllText(physical root "/var/lib/keroosha-iac/firewalld/pending-transaction.json"), Is.EqualTo markerText)
                let unchanged = FirewalldLifecycle.pending environment |> Option.defaultWith (fun () -> failwith "Expected unchanged intent")
                Assert.That(unchanged.SchemaVersion, Is.EqualTo 3)
                Assert.That(unchanged.OwnerId, Is.EqualTo owner)
                Assert.That(unchanged.NativeProgress.Value.CompletedSteps, Is.EqualTo 3)
                Assert.That(unchanged.AwaitingPostBoot, Is.False))

    [<Test>]
    member _.``Same-boot active retry delegates an awaiting object receipt as postboot recovery``() =
        withHost (fun environment root ->
            let generation = Guid.NewGuid()
            writeFile root "/proc/sys/kernel/random/boot_id" (string generation) 0o644
            let record = nativeProgressRecord "object-delta" 3 true
            record["version"] <- JsonValue.Create 4
            record["nativeUndo"] <- null
            let value = journal owner (Some before) (Some after)
            value["pending"] <- record.DeepClone()
            let ownerPath = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            let ownerText = value.ToJsonString()
            writeFile root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json" ownerText 0o600
            writeFile root logicalPath before 0o644
            savePendingRecord root record
            let waiting = FirewalldLifecycle.pending environment |> Option.get
            (FirewalldLifecycle.undoJournal environment waiting |> Option.get).Persist
                { RemainingSteps = 0; InFlightStep = None; PreimageVerified = false }
            let mutable observedPhase = None
            let failure =
                Assert.Throws<InvalidOperationException>(fun () ->
                    FirewalldLifecycle.recoverPending environment (fun transaction storedJournal ->
                        let stored = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                        FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration stored transaction.Path
                            FirewalldLifecycle.ActiveDaemon readState (writeState root transaction.Path)
                            (fun _ phase ->
                                observedPhase <- Some phase
                                invalidOp "ordered postboot verifier remains pending")))
            Assert.That(failure.Message, Does.Contain "ordered postboot verifier remains pending")
            Assert.That(observedPhase, Is.EqualTo(Some FirewalldLifecycle.BootAfterFirewalld))
            Assert.That(File.ReadAllText ownerPath, Is.EqualTo ownerText)
            let retained = FirewalldLifecycle.pending environment |> Option.get
            Assert.That(retained.AwaitingPostBoot, Is.True)
            let receipt = (FirewalldLifecycle.undoJournal environment retained |> Option.get).Previous.Value
            Assert.That(receipt.RemainingSteps, Is.Zero)
            Assert.That(receipt.PreimageVerified, Is.False))

    [<TestCase(false, "old-after"); TestCase(true, "old-after")>]
    [<TestCase(false, "later-delete"); TestCase(true, "later-delete")>]
    [<TestCase(false, "reintroduced-override"); TestCase(true, "reintroduced-override")>]
    [<TestCase(false, "wrong-mode"); TestCase(true, "wrong-mode")>]
    member _.``Awaiting recovery preserves later disk state until independent reconciliation``(postboot: bool, change: string) =
        let phase = if postboot then FirewalldLifecycle.BootAfterFirewalld else FirewalldLifecycle.ActiveDaemon
        let expected, staged, later, laterMode =
            match change with
            | "old-after" -> Some before, Some after, Some after, 0o644
            | "later-delete" -> Some before, None, None, 0o644
            | "reintroduced-override" -> None, Some after, Some after, 0o644
            | "wrong-mode" -> Some before, Some after, Some before, 0o600
            | _ -> invalidArg (nameof change) "Unexpected disk state."
        withHost (fun env root ->
            awaitingFixture root expected staged true |> ignore
            setTarget root later laterMode
            let path = physical root logicalPath
            let reservation = reservationSnapshot root
            let foreign = fileSnapshot path
            let mutable runtimeChecks = 0
            let retry () = probeAwaiting env phase (fun _ _ -> runtimeChecks <- runtimeChecks + 1)
            for _ in 1..2 do
                Assert.Throws<InvalidOperationException>(TestDelegate retry) |> ignore
                Assert.That(fileSnapshot path, Is.EqualTo(box foreign))
                Assert.That(reservationSnapshot root, Is.EqualTo(box reservation))
                Assert.That(runtimeChecks, Is.Zero)
            setTarget root expected 0o644
            let reconciled = fileSnapshot path
            retry ()
            Assert.That(fileSnapshot path, Is.EqualTo(box reconciled))
            Assert.That(runtimeChecks, Is.EqualTo 1)
            Assert.That(FirewalldLifecycle.pending env, Is.EqualTo None))

    [<Test>]
    member _.``Cleanup rechecks the preboot disk state after runtime verification``() =
        withHost (fun env root ->
            awaitingFixture root (Some before) (Some after) true |> ignore
            setTarget root (Some before) 0o644
            let prior = reservationSnapshot root
            Assert.Throws<InvalidOperationException>(fun () ->
                probeAwaiting env FirewalldLifecycle.BootAfterFirewalld (fun _ _ -> setTarget root (Some after) 0o644)) |> ignore
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo after)
            Assert.That(reservationSnapshot root, Is.EqualTo(box prior)))

    [<Test>]
    member _.``Confirmation cannot commit an awaiting transaction even before its first reverse receipt``() =
        withHost (fun env root ->
            let stored = awaitingFixture root (Some before) (Some after) false
            setTarget root (Some after) 0o644
            let prior = reservationSnapshot root
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldLifecycle.confirm env configuration stored (String.replicate 32 "a") readState) |> ignore
            Assert.That(reservationSnapshot root, Is.EqualTo(box prior)))


    [<TestCase(false, 0); TestCase(false, 2); TestCase(false, 4096); TestCase(true, 0)>]
    member _.``Active recovery requires a same-boot postboot receipt at every forward count``(hasRetryReceipt: bool, completedSteps: int) =
        withHost (fun environment root ->
            let journalPath = "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            let generation = Guid.NewGuid()
            writeFile root "/proc/sys/kernel/random/boot_id" (string generation) 0o644
            let record = pendingRecord 2 true true
            record["version"] <- JsonValue.Create 4
            record["rollbackProof"].AsObject()["strategy"] <- JsonValue.Create "runtime-delta"
            record["nativeProgress"] <- JsonNode.Parse(sprintf """{"completedSteps":%d,"inFlightStep":null}""" completedSteps)
            if hasRetryReceipt then
                let undo = JsonObject()
                undo["bootId"] <- JsonValue.Create(generation.ToString("D"))
                undo["remainingSteps"] <- JsonValue.Create 1
                undo["inFlightStep"] <- null
                record["nativeUndo"] <- undo
            else record["nativeUndo"] <- null
            let value = journal owner (Some before) (Some after)
            value["pending"] <- record.DeepClone()
            writeFile root journalPath (value.ToJsonString()) 0o600
            writeFile root logicalPath before 0o644
            savePendingRecord root record
            let mutable observedPhase = None
            let mutable observedRemaining = None
            let mutable observedVerified = None
            let recover (transaction: FirewalldLifecycle.PendingTransaction) storedJournal =
                let stored = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration stored transaction.Path
                    FirewalldLifecycle.ActiveDaemon readState (writeState root transaction.Path) (fun _ runtimePhase ->
                        observedPhase <- Some runtimePhase
                        if hasRetryReceipt then
                            let inverse = FirewalldLifecycle.undoJournal environment transaction |> Option.get
                            observedRemaining <- inverse.Previous |> Option.map (fun receipt -> receipt.RemainingSteps)
                            observedVerified <- inverse.Previous |> Option.map (fun receipt -> receipt.PreimageVerified)
                        invalidOp "postboot native repair remains pending")
            Assert.Throws<InvalidOperationException>(fun () -> FirewalldLifecycle.recoverPending environment recover) |> ignore
            if hasRetryReceipt then
                Assert.That(observedPhase, Is.EqualTo(Some FirewalldLifecycle.BootAfterFirewalld))
                Assert.That(observedRemaining, Is.EqualTo(Some 1))
                Assert.That(observedVerified, Is.EqualTo(Some false))
            else
                Assert.That(observedPhase, Is.EqualTo None)
            let waiting = FirewalldLifecycle.pending environment |> Option.defaultWith (fun () -> failwith "Expected retained native repair")
            Assert.That(waiting.AwaitingPostBoot, Is.True))

    [<TestCase("runtime-delta", true); TestCase("reload-before", false)>]
    member _.``Active postboot receipt gate applies only to native scoped repairs``(strategy: string, shouldBlock: bool) =
        withHost (fun environment root ->
            let generation = Guid.NewGuid()
            writeFile root "/proc/sys/kernel/random/boot_id" (string generation) 0o644
            let record = pendingRecord 2 true true
            record["rollbackProof"].AsObject()["strategy"] <- JsonValue.Create strategy
            let value = journal owner (Some before) (Some after)
            value["pending"] <- record.DeepClone()
            writeFile root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json" (value.ToJsonString()) 0o600
            writeFile root logicalPath before 0o644
            savePendingRecord root record
            let mutable observedPhase = None
            let recover (transaction: FirewalldLifecycle.PendingTransaction) storedJournal =
                let stored = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration stored transaction.Path
                    FirewalldLifecycle.ActiveDaemon readState (writeState root transaction.Path) (fun _ phase ->
                        observedPhase <- Some phase)
            if shouldBlock then
                Assert.Throws<InvalidOperationException>(fun () -> FirewalldLifecycle.recoverPending environment recover) |> ignore
                Assert.That(observedPhase, Is.EqualTo None)
                Assert.That((FirewalldLifecycle.pending environment).IsSome, Is.True)
            else
                FirewalldLifecycle.recoverPending environment recover
                Assert.That(observedPhase, Is.EqualTo(Some FirewalldLifecycle.ActiveDaemon))
                Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None))

    [<Test>]
    member _.``Legacy pending host records fail closed without changing disk or journal``() =
        withHost (fun environment root ->
            let marker = "/var/lib/keroosha-iac/firewalld/pending-transaction.json"
            let record = pendingRecord 1 false false
            writeFile root logicalPath after 0o644
            savePendingRecord root record
            let failure =
                Assert.Throws<InvalidOperationException>(fun () ->
                    FirewalldLifecycle.recoverPending environment (fun _ _ -> failwith "Legacy transaction must not be recovered") )
            Assert.That(failure.Message, Does.Contain "rollback proof")
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo after)
            Assert.That(File.Exists(physical root marker), Is.True))

    [<Test>]
    member _.``Unpaired owner pending record blocks new mutation``() =
        withHost (fun environment root ->
            let orphan = journal "stale-owner" None None
            orphan["pending"] <- JsonObject()
            writeFile root "/var/lib/keroosha-iac/firewalld/zone-orphan.json" (orphan.ToJsonString()) 0o600
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            let failure =
                Assert.Throws<InvalidOperationException>(fun () ->
                    transact environment value (Some before) (Some after) false false |> ignore)
            Assert.That(failure.Message, Does.Contain "unpaired")
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None))

    [<Test>]
    member _.``Independent watchdog invocation retries after a transient runtime restore failure``() =
        withHost (fun environment root ->
            let journalPath = "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            let record = pendingRecord 2 true false
            let value = journal owner (Some before) (Some before)
            value["pending"] <- record.DeepClone()
            writeFile root journalPath (value.ToJsonString()) 0o600
            writeFile root logicalPath after 0o644
            savePendingRecord root record
            let mutable attempts = 0
            let recover (transaction: FirewalldLifecycle.PendingTransaction) storedJournal =
                let stored = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration stored transaction.Path
                    FirewalldLifecycle.ActiveDaemon readState (writeState root transaction.Path) (fun _ _ ->
                        attempts <- attempts + 1
                        if attempts = 1 then invalidOp "simulated transient restore failure")
            Assert.Throws<InvalidOperationException>(fun () -> FirewalldLifecycle.recoverPending environment recover) |> ignore
            Assert.That(FirewalldLifecycle.pending environment |> Option.isSome, Is.True)
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
            FirewalldLifecycle.recoverPending environment recover
            Assert.That(attempts, Is.EqualTo 2)
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None))

    [<Test>]
    member _.``Foreign recovery enable link collision preserves all unit files and links``() =
        withHost (fun environment root ->
            let baseline = "<zone target=\"DROP\"><interface name=\"eth0\"/></zone>\n"
            let managed = "<zone target=\"DROP\"/>\n"
            writeFile root logicalPath managed 0o644
            let value = journal owner (Some baseline) (Some managed)
            let nonce = transact environment value (Some managed) (Some baseline) false true
            let foreignUnit = physical root "/etc/systemd/system/foreign.service"
            File.WriteAllText(foreignUnit, "[Unit]\nDescription=Unowned test unit\n")
            let requiresLink = physical root "/etc/systemd/system/firewalld.service.wants/keroosha-iac-firewalld-boot-recovery.service"
            let original = FileInfo(requiresLink).LinkTarget
            File.Delete requiresLink
            File.CreateSymbolicLink(requiresLink, "../foreign.service") |> ignore
            let failure = Assert.Throws<InvalidOperationException>(fun () -> FirewalldLifecycle.confirm environment configuration value nonce readState)
            Assert.That(failure.Message, Does.Contain "unowned unit")
            Assert.That(File.Exists foreignUnit, Is.True)
            Assert.That(FileInfo(requiresLink).LinkTarget, Is.EqualTo "../foreign.service")
            Assert.That(File.Exists(physical root "/etc/systemd/system/keroosha-iac-firewalld-boot-recovery.service"), Is.True)
            Assert.That(File.Exists(physical root "/etc/systemd/system/keroosha-iac-firewalld-postboot-recovery.service"), Is.True)
            Assert.That(FileInfo(physical root "/etc/systemd/system/multi-user.target.wants/keroosha-iac-firewalld-boot-recovery.service").LinkTarget, Is.Not.Null)
            Assert.That(FileInfo(physical root "/etc/systemd/system/timers.target.wants/keroosha-iac-firewalld-rollback.timer").LinkTarget, Is.Not.Null)
            Assert.That((FirewalldLifecycle.pending environment).Value.Status, Is.EqualTo "confirmed")
            let owned = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            Assert.That(File.Exists owned, Is.True)
            File.Delete requiresLink
            File.CreateSymbolicLink(requiresLink, original) |> ignore
            FirewalldLifecycle.confirm environment configuration value nonce readState
            Assert.That(File.Exists owned, Is.False)
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None))

    [<Test>]
    member _.``Populated split zones are refused before mutation``() =
        withHost (fun environment root ->
            let directory = physical root "/usr/lib/firewalld/zones/public"
            Directory.CreateDirectory directory |> ignore
            File.WriteAllText(Path.Combine(directory, "20-local.xml"), "<zone><service name=\"ssh\"/></zone>")
            Assert.Throws<Dorothy.HostHelper.Firewalld.BackendError>(fun () ->
                Dorothy.HostHelper.Firewalld.ensureNoSplitZones environment) |> ignore)
    [<Test>]
    member _.``Bootstrap recovery provisions owned units without arming a transaction watchdog``() =
        withHostForDependencyOverrides Map.empty (fun environment root commands _ ->
            let journalPath, journalText = saveBootstrapSettingsOwner root owner
            Firewalld.ensureBootstrapRecovery environment owner
            Assert.That(File.ReadAllText(physical root journalPath), Is.EqualTo journalText)
            let unitPaths =
                [ "/etc/systemd/system/keroosha-iac-firewalld-rollback.service"
                  "/etc/systemd/system/keroosha-iac-firewalld-rollback.timer"
                  "/etc/systemd/system/keroosha-iac-firewalld-boot-recovery.service"
                  "/etc/systemd/system/keroosha-iac-firewalld-postboot-recovery.service"
                  "/etc/systemd/system/keroosha-iac-firewalld-boot-containment.service" ]
            for path in unitPaths do Assert.That(File.Exists(physical root path), Is.True, path)
            let firstPass = commands |> Seq.toList
            Assert.That(firstPass |> List.exists (fun args -> args = [ "start"; "keroosha-iac-firewalld-boot-recovery.service" ]), Is.True)
            Assert.That(firstPass |> List.exists (fun args -> args = [ "enable"; "keroosha-iac-firewalld-rollback.timer" ]), Is.False)
            Assert.That(firstPass |> List.exists (fun args ->
                args = [ "start"; "keroosha-iac-firewalld-rollback.timer" ]
                || args = [ "restart"; "keroosha-iac-firewalld-rollback.timer" ]
                || args = [ "stop"; "keroosha-iac-firewalld-rollback.timer" ]
                || args = [ "start"; "keroosha-iac-firewalld-rollback.service" ]
                || args = [ "stop"; "keroosha-iac-firewalld-rollback.service" ]
                || args = [ "reset-failed"; "keroosha-iac-firewalld-boot-recovery.service" ]), Is.False)
            Assert.That(File.Exists(physical root "/etc/systemd/system/timers.target.wants/keroosha-iac-firewalld-rollback.timer"), Is.False)
            let beforeRetry = commands.Count
            Firewalld.ensureBootstrapRecovery environment owner
            let retryCommands = commands |> Seq.skip beforeRetry |> Seq.toList
            Assert.That(retryCommands |> List.exists (fun args -> List.contains (List.head args) [ "daemon-reload"; "enable"; "start"; "stop"; "restart"; "reset-failed" ]), Is.False))

    [<Test>]
    member _.``Bootstrap recovery preflights late link collisions before writing units``() =
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root commands ->
            let journalPath, journalText = saveBootstrapSettingsOwner root owner
            let collision = "/etc/systemd/system/timers.target.wants/keroosha-iac-firewalld-rollback.timer"
            writeFile root collision "foreign timer link target\n" 0o644
            let originalCollision = fileSnapshot (physical root collision)
            let failure =
                Assert.Throws<HostPrerequisiteError>(fun () -> Firewalld.ensureBootstrapRecovery environment owner)
            Assert.That(failure.Message, Does.Contain "keroosha-iac-firewalld-rollback.timer")
            Assert.That(File.ReadAllText(physical root journalPath), Is.EqualTo journalText)
            Assert.That(fileSnapshot (physical root collision), Is.EqualTo(box originalCollision))
            for path in
                [ "/etc/systemd/system/keroosha-iac-firewalld-rollback.service"
                  "/etc/systemd/system/keroosha-iac-firewalld-rollback.timer"
                  "/etc/systemd/system/keroosha-iac-firewalld-boot-recovery.service"
                  "/etc/systemd/system/keroosha-iac-firewalld-postboot-recovery.service"
                  "/etc/systemd/system/keroosha-iac-firewalld-boot-containment.service"
                  "/etc/systemd/system/multi-user.target.wants/keroosha-iac-firewalld-boot-recovery.service"
                  "/etc/systemd/system/firewalld.service.wants/keroosha-iac-firewalld-boot-recovery.service"
                  "/etc/systemd/system/multi-user.target.wants/keroosha-iac-firewalld-postboot-recovery.service"
                  "/etc/systemd/system/multi-user.target.wants/keroosha-iac-firewalld-boot-containment.service" ] do
                Assert.That(File.Exists(physical root path), Is.False, path)
            Assert.That(commands |> Seq.exists (fun args -> List.contains (List.head args) [ "daemon-reload"; "enable"; "start"; "stop"; "restart"; "reset-failed" ]), Is.False))

    [<TestCase("/usr/lib/systemd/system/keroosha-iac-firewalld-rollback.service")>]
    [<TestCase("/run/systemd/system/keroosha-iac-firewalld-rollback.service")>]
    [<TestCase("/etc/systemd/system/keroosha-iac-firewalld-rollback.service")>]
    [<TestCase("/etc/systemd/system/keroosha-iac-firewalld-boot-recovery.service.d/90-admin.conf")>]
    [<TestCase("/etc/systemd/system.control/keroosha-iac-firewalld-boot-recovery.service.d/90-admin.conf")>]
    [<TestCase("/run/systemd/system.attached/service.d/90-admin.conf")>]
    [<TestCase("/usr/lib/systemd/system/keroosha-iac-.service.d/90-admin.conf")>]
    member _.``Bootstrap recovery refuses unowned effective fragments and drop-ins``(logicalCollision: string) =
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root commands ->
            let journalPath, journalText = saveBootstrapSettingsOwner root owner
            writeFile root logicalCollision "unowned systemd customization\n" 0o644
            let collisionPath = physical root logicalCollision
            let collisionText = File.ReadAllText collisionPath
            Assert.Throws<HostPrerequisiteError>(fun () ->
                Firewalld.ensureBootstrapRecovery environment owner) |> ignore
            Assert.That(File.ReadAllText(physical root journalPath), Is.EqualTo journalText)
            Assert.That(File.ReadAllText collisionPath, Is.EqualTo collisionText)
            Assert.That(File.Exists(physical root "/etc/systemd/system/keroosha-iac-firewalld-rollback.timer"), Is.False)
            Assert.That(commands |> Seq.exists (fun args -> List.contains (List.head args) [ "daemon-reload"; "enable"; "start"; "stop"; "restart"; "reset-failed" ]), Is.False))

    [<TestCase("load-error")>]
    [<TestCase("failed")>]
    [<TestCase("activating")>]
    [<TestCase("error")>]
    member _.``Bootstrap recovery refuses failed or unverified latches``(initialState: string) =
        withHostForSystemctlStateAndCommands None initialState (fun environment root commands ->
            let journalPath, journalText = saveBootstrapSettingsOwner root owner
            Assert.Throws<HostPrerequisiteError>(fun () ->
                Firewalld.ensureBootstrapRecovery environment owner) |> ignore
            Assert.That(File.ReadAllText(physical root journalPath), Is.EqualTo journalText)
            Assert.That(File.Exists(physical root "/etc/systemd/system/keroosha-iac-firewalld-rollback.timer"), Is.False)
            Assert.That(commands |> Seq.exists (fun args ->
                args = [ "start"; "keroosha-iac-firewalld-boot-recovery.service" ]
                || args = [ "reset-failed"; "keroosha-iac-firewalld-boot-recovery.service" ]), Is.False))

    [<Test>]
    member _.``Bootstrap recovery refuses exact-owner conflicts and orphaned legacy pending journals``() =
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root commands ->
            let journalPath, journalText = saveBootstrapSettingsOwner root "another-owner"
            Assert.Catch<Dorothy.HostHelper.Firewalld.BackendError>(fun () ->
                Firewalld.ensureBootstrapRecovery environment owner) |> ignore
            Assert.That(File.Exists(physical root "/etc/systemd/system/keroosha-iac-firewalld-rollback.timer"), Is.False)
            Assert.That(File.ReadAllText(physical root journalPath), Is.EqualTo journalText)
            Assert.That(commands |> Seq.exists (fun args -> List.contains (List.head args) [ "daemon-reload"; "enable"; "start" ]), Is.False)
            Assert.That(File.Exists(physical root journalPath), Is.True))
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root commands ->
            let settingsPath, settingsText = saveBootstrapSettingsOwner root owner
            let legacy = journal "old-zone-owner" None None
            legacy["pending"] <- JsonObject()
            let legacyPath = "/var/lib/keroosha-iac/firewalld/zone-old.json"
            let legacyText = legacy.ToJsonString()
            writeFile root legacyPath legacyText 0o600
            Assert.Throws<InvalidOperationException>(fun () ->
                Firewalld.ensureBootstrapRecovery environment owner) |> ignore
            Assert.That(File.ReadAllText(physical root settingsPath), Is.EqualTo settingsText)
            Assert.That(File.ReadAllText(physical root legacyPath), Is.EqualTo legacyText)
            Assert.That(File.Exists(physical root "/etc/systemd/system/keroosha-iac-firewalld-rollback.timer"), Is.False)
            Assert.That(commands |> Seq.exists (fun args -> List.contains (List.head args) [ "daemon-reload"; "enable"; "start" ]), Is.False))
    [<Test>]
    member _.``Bootstrap recovery refuses a global transaction reservation``() =
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root commands ->
            let journalPath, journalText = saveBootstrapSettingsOwner root owner
            let marker = pendingRecord 2 false false
            let markerText = marker.ToJsonString()
            savePendingRecord root marker
            Assert.Throws<InvalidOperationException>(fun () ->
                Firewalld.ensureBootstrapRecovery environment owner) |> ignore
            Assert.That(File.ReadAllText(physical root journalPath), Is.EqualTo journalText)
            Assert.That(File.ReadAllText(physical root "/var/lib/keroosha-iac/firewalld/pending-transaction.json"), Is.EqualTo markerText)
            Assert.That(File.Exists(physical root "/etc/systemd/system/keroosha-iac-firewalld-rollback.timer"), Is.False)
            Assert.That(commands |> Seq.exists (fun args -> List.contains (List.head args) [ "daemon-reload"; "enable"; "start" ]), Is.False))

    [<TestCase("disk-wants"); TestCase("disk-hard"); TestCase("live-wants"); TestCase("live-hard")>]
    member _.``Unattributed recovery dependencies refuse before publication or activation``(source: string) =
        let boot = "keroosha-iac-firewalld-boot-recovery.service"
        let foreign = "independent.service"
        let edges =
            match source with
            | "live-wants" -> Map.ofList [ boot, Map.ofList [ "Wants", foreign ] ]
            | "live-hard" -> Map.ofList [ "firewalld.service", Map.ofList [ "Requires", "dbus.socket " + boot ] ]
            | _ -> Map.empty
        withHostForDependencyOverrides edges (fun env root commands _ ->
            let journalPath, original = saveBootstrapSettingsOwner root owner
            let link =
                match source with
                | "disk-wants" -> Some(physical root ("/etc/systemd/system/" + boot + ".wants/" + foreign), "../" + foreign)
                | "disk-hard" -> Some(physical root ("/run/systemd/system/firewalld.service.requires/" + boot), "../" + boot)
                | _ -> None
            for path, target in Option.toList link do
                Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
                File.CreateSymbolicLink(path, target) |> ignore
            Assert.Throws<HostPrerequisiteError>(fun () -> Firewalld.ensureBootstrapRecovery env owner) |> ignore
            for path, target in Option.toList link do Assert.That(FileInfo(path).LinkTarget, Is.EqualTo target)
            for name in recoveryUnitNames do Assert.That(File.Exists(physical root ("/etc/systemd/system/" + name)), Is.False)
            Assert.That(File.ReadAllText(physical root journalPath), Is.EqualTo original)
            Assert.That(commands |> Seq.exists (function ("enable" | "start" | "daemon-reload") :: _ -> true | _ -> false), Is.False))

    [<Test>]
    member _.``Bootstrap recovery upgrades the exact f4a8310 boot unit``() =
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root _ ->
            saveBootstrapSettingsOwner root owner |> ignore
            let oldHelper = "/var/cache/keroosha-iac/helper/linux-x64/" + String.replicate 64 "a"
            let historical =
                String.concat "\n"
                    [ "# Dorothy firewalld transaction recovery"
                      "[Unit]"
                      "Description=Dorothy firewalld boot recovery"
                      "DefaultDependencies=no"
                      "After=local-fs.target"
                      "Before=firewalld.service"
                      "[Service]"
                      "Type=oneshot"
                      "ExecStart=" + oldHelper + " firewalld-recover-boot"
                      "[Install]"
                      "WantedBy=multi-user.target"
                      "" ]
            let unitPath = "/etc/systemd/system/keroosha-iac-firewalld-boot-recovery.service"
            writeFile root unitPath historical 0o644
            Firewalld.ensureBootstrapRecovery environment owner
            let upgraded = File.ReadAllText(physical root unitPath)
            Assert.That(upgraded, Does.Contain("ExecStart=" + Environment.ProcessPath + " firewalld-recover-boot"))
            Assert.That(upgraded, Is.Not.EqualTo historical))

    [<Test>]
    member _.``Bootstrap recovery refuses a lookalike historical boot helper path``() =
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root commands ->
            saveBootstrapSettingsOwner root owner |> ignore
            let lookalikeHelper = "/var/cache/keroosha-iac/helper/linux-x64/not-a-sha256"
            let lookalike =
                String.concat "\n"
                    [ "# Dorothy firewalld transaction recovery"
                      "[Unit]"
                      "Description=Dorothy firewalld boot recovery"
                      "DefaultDependencies=no"
                      "After=local-fs.target"
                      "Before=firewalld.service"
                      "[Service]"
                      "Type=oneshot"
                      "ExecStart=" + lookalikeHelper + " firewalld-recover-boot"
                      "[Install]"
                      "WantedBy=multi-user.target"
                      "" ]
            writeFile root "/etc/systemd/system/keroosha-iac-firewalld-boot-recovery.service" lookalike 0o644
            Assert.Throws<HostPrerequisiteError>(fun () ->
                Firewalld.ensureBootstrapRecovery environment owner) |> ignore
            Assert.That(commands |> Seq.exists (fun args -> args = [ "start"; "keroosha-iac-firewalld-boot-recovery.service" ]), Is.False))

    [<Test>]
    member _.``Bootstrap recovery accepts the exact containment unit``() =
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root _ ->
            saveBootstrapSettingsOwner root owner |> ignore
            let containment =
                String.concat "\n"
                    [ "# Dorothy firewalld transaction recovery"
                      "[Unit]"
                      "Description=Quarantine an unverifiable firewalld boot transaction"
                      "DefaultDependencies=no"
                      "Wants=firewalld.service keroosha-iac-firewalld-boot-recovery.service keroosha-iac-firewalld-postboot-recovery.service"
                      "After=firewalld.service keroosha-iac-firewalld-boot-recovery.service keroosha-iac-firewalld-postboot-recovery.service"
                      "Before=network-pre.target"
                      "ConditionPathExists=/var/lib/keroosha-iac/firewalld/pending-transaction.json"
                      "[Service]"
                      "Type=oneshot"
                      "ExecCondition=/usr/bin/systemctl --quiet is-failed keroosha-iac-firewalld-boot-recovery.service keroosha-iac-firewalld-postboot-recovery.service"
                      "ExecStart=/usr/bin/firewall-cmd --panic-on"
                      "[Install]"
                      "WantedBy=multi-user.target"
                      "" ]
            let unitPath = "/etc/systemd/system/keroosha-iac-firewalld-boot-containment.service"
            writeFile root unitPath containment 0o644
            Firewalld.ensureBootstrapRecovery environment owner
            Assert.That(File.ReadAllText(physical root unitPath), Is.EqualTo containment))

    [<Test>]
    member _.``Bootstrap recovery refuses a changed containment executable path``() =
        withHostForSystemctlStateAndCommands None "inactive" (fun environment root commands ->
            saveBootstrapSettingsOwner root owner |> ignore
            let lookalikeHelper = "/var/cache/keroosha-iac/helper/linux-x64/" + String.replicate 64 "b"
            let containment =
                String.concat "\n"
                    [ "# Dorothy firewalld transaction recovery"
                      "[Unit]"
                      "Description=Quarantine an unverifiable firewalld boot transaction"
                      "DefaultDependencies=no"
                      "Wants=firewalld.service keroosha-iac-firewalld-boot-recovery.service keroosha-iac-firewalld-postboot-recovery.service"
                      "After=firewalld.service keroosha-iac-firewalld-boot-recovery.service keroosha-iac-firewalld-postboot-recovery.service"
                      "Before=network-pre.target"
                      "ConditionPathExists=/var/lib/keroosha-iac/firewalld/pending-transaction.json"
                      "[Service]"
                      "Type=oneshot"
                      "ExecCondition=/usr/bin/systemctl --quiet is-failed keroosha-iac-firewalld-boot-recovery.service keroosha-iac-firewalld-postboot-recovery.service"
                      "ExecStart=" + lookalikeHelper + " --panic-on"
                      "[Install]"
                      "WantedBy=multi-user.target"
                      "" ]
            writeFile root "/etc/systemd/system/keroosha-iac-firewalld-boot-containment.service" containment 0o644
            Assert.Throws<HostPrerequisiteError>(fun () ->
                Firewalld.ensureBootstrapRecovery environment owner) |> ignore
            Assert.That(commands |> Seq.exists (fun args -> args = [ "start"; "keroosha-iac-firewalld-boot-recovery.service" ]), Is.False))
