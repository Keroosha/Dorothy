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

    let withHost (action: HostEnvironment -> string -> unit) =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-lifecycle-" + Guid.NewGuid().ToString("N"))
        for directory in [ "etc/firewalld/zones"; "etc/systemd/system"; "run/lock"; "var/lib" ] do
            Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
        let run (executable: string) (arguments: string list) (_input: string option) : CommandResult =
            if executable = "stat" then
                if List.contains "%u:%g" arguments then
                    { ExitCode = 0; Stdout = "0:0"; Stderr = "" }
                else
                    let target = List.last arguments
                    let mode = File.GetUnixFileMode target |> int |> fun value -> Convert.ToString(value, 8)
                    { ExitCode = 0; Stdout = "0:" + mode; Stderr = "" }
            elif executable = "/usr/bin/systemctl" then
                let createLink directory name target =
                    Directory.CreateDirectory(directory) |> ignore
                    let link = Path.Combine(directory, name)
                    if isNull (FileInfo(link).LinkTarget) && not (File.Exists link || Directory.Exists link) then
                        File.CreateSymbolicLink(link, target) |> ignore
                match arguments with
                | [ "enable"; "keroosha-iac-firewalld-boot-recovery.service" ] ->
                    createLink (Path.Combine(root, "etc/systemd/system/multi-user.target.wants")) "keroosha-iac-firewalld-boot-recovery.service" "../keroosha-iac-firewalld-boot-recovery.service"
                    createLink (Path.Combine(root, "etc/systemd/system/firewalld.service.wants")) "keroosha-iac-firewalld-boot-recovery.service" "../keroosha-iac-firewalld-boot-recovery.service"
                | [ "start"; "keroosha-iac-firewalld-boot-recovery.service" ] -> ()
                | [ "enable"; "keroosha-iac-firewalld-postboot-recovery.service" ] ->
                    createLink (Path.Combine(root, "etc/systemd/system/multi-user.target.wants")) "keroosha-iac-firewalld-postboot-recovery.service" "../keroosha-iac-firewalld-postboot-recovery.service"
                | [ "enable"; "keroosha-iac-firewalld-rollback.timer" ] ->
                    createLink (Path.Combine(root, "etc/systemd/system/timers.target.wants")) "keroosha-iac-firewalld-rollback.timer" (Path.Combine(root, "etc/systemd/system/keroosha-iac-firewalld-rollback.timer"))
                | [ "restart"; "keroosha-iac-firewalld-rollback.timer" ]
                | [ "stop"; "keroosha-iac-firewalld-rollback.timer" ] -> ()
                | _ -> ()
                { ExitCode = 0; Stdout = "success"; Stderr = "" }
            else
                invalidOp ("Unexpected lifecycle command: " + executable + " " + String.concat " " arguments)
        let environment: HostEnvironment =
            { Root = root
              Run = run
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        try action environment root
        finally
            if Directory.Exists root then Directory.Delete(root, true)

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
            readState (writeState environment.Root logical) (fun _ _ -> ()) (fun () -> ()) (fun _ _ -> ())

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

    let savePendingRecord (root: string) (record: JsonObject) =
        writeFile root "/var/lib/keroosha-iac/firewalld/pending-transaction.json" (record.ToJsonString()) 0o600

    [<Test>]
    member _.``Fresh confirmation commits the journaled candidate``() =
        withHost (fun environment root ->
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            let nonce = transact environment value (Some before) (Some after) false false
            Assert.That(nonce.Length, Is.EqualTo 32)
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
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None))

    [<Test>]
    member _.``Populated split zones are refused before mutation``() =
        withHost (fun environment root ->
            let directory = physical root "/usr/lib/firewalld/zones/public"
            Directory.CreateDirectory directory |> ignore
            File.WriteAllText(Path.Combine(directory, "20-local.xml"), "<zone><service name=\"ssh\"/></zone>")
            Assert.Throws<Dorothy.HostHelper.Firewalld.BackendError>(fun () ->
                Dorothy.HostHelper.Firewalld.ensureNoSplitZones environment) |> ignore)
