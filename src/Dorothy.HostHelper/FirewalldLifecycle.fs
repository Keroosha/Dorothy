namespace Dorothy.HostHelper

open System
open System.IO
open System.Text
open System.Text.Json.Nodes
open System.Text.RegularExpressions

module FirewalldLifecycle =
    type RecoveryPhase =
        | ActiveDaemon
        | BootBeforeFirewalld
        | BootAfterFirewalld

    type NativeActivationProgress =
        { CompletedSteps: int
          InFlightStep: int option }

    type NativeUndoProgress =
        { RemainingSteps: int
          InFlightStep: int option
          PreimageVerified: bool }

    type UndoJournal =
        { Previous: NativeUndoProgress option
          Persist: NativeUndoProgress -> unit }

    type PendingTransaction =
        { SchemaVersion: int
          Nonce: string
          OwnerId: string
          Configuration: FirewalldModel.Configuration
          Path: string
          Scope: JsonObject option
          Before: string option
          BeforeMode: int
          After: string option
          AfterMode: int
          ManagedBefore: string option
          ManagedAfter: string option
          RollbackProof: JsonObject option
          NativeProgress: NativeActivationProgress option
          NativeUndo: (Guid * NativeUndoProgress) option
          ActivationStarted: bool
          AwaitingPostBoot: bool
          ReleaseOnRollback: bool
          DeleteOnConfirm: bool
          Status: string }

    let private journalDirectory = "/var/lib/keroosha-iac/firewalld"
    let private pendingPath = journalDirectory + "/pending-transaction.json"
    let private lockPath = "/run/lock/keroosha-firewalld-backend.lock"
    let private servicePath = "/etc/systemd/system/keroosha-iac-firewalld-rollback.service"
    let private timerPath = "/etc/systemd/system/keroosha-iac-firewalld-rollback.timer"
    let private serviceName = "keroosha-iac-firewalld-rollback.service"
    let private timerName = "keroosha-iac-firewalld-rollback.timer"
    let private bootServicePath = "/etc/systemd/system/keroosha-iac-firewalld-boot-recovery.service"
    let private postBootServicePath = "/etc/systemd/system/keroosha-iac-firewalld-postboot-recovery.service"
    let private postBootServiceName = "keroosha-iac-firewalld-postboot-recovery.service"
    let private bootServiceName = "keroosha-iac-firewalld-boot-recovery.service"
    let private containmentName = "keroosha-iac-firewalld-boot-containment.service"
    let private containmentPath = "/etc/systemd/system/" + containmentName
    let private ownerMarker = "# Dorothy firewalld transaction recovery"
    let private timerText =
        String.concat "\n"
            [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld transaction rollback watchdog"; "[Timer]"; "OnActiveSec=2min"; "AccuracySec=1s"; "Unit=" + serviceName; "[Install]"; "WantedBy=timers.target"; "" ]
    let private legacyTimerText =
        String.concat "\n"
            [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld transaction rollback watchdog"; "[Timer]"; "OnActiveSec=2min"; "Unit=" + serviceName; "[Install]"; "WantedBy=timers.target"; "" ]
    let private strictUtf8 = UTF8Encoding(false, true)
    let private fileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead
    let private privateFileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
    let private directoryMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
    let private unitDirectoryMode = directoryMode ||| UnixFileMode.GroupRead ||| UnixFileMode.GroupExecute ||| UnixFileMode.OtherRead ||| UnixFileMode.OtherExecute

    let private fail message = raise (InvalidOperationException(message))
    let private logicalPath (environment: HostEnvironment) path = HostEnvironment.path environment path
    let private journalPath (c: FirewalldModel.Configuration) = journalDirectory + "/" + c.Kind + "-" + c.Name + ".json"
    let private category = function
        | "zone" -> "zones"
        | "policy" -> "policies"
        | "service" -> "services"
        | "ipset" -> "ipsets"
        | "icmptype" -> "icmptypes"
        | "helper" -> "helpers"
        | kind -> fail ("Unsupported firewalld transaction kind: " + kind)

    let private objectFilePath (c: FirewalldModel.Configuration) =
        "/etc/firewalld/" + category c.Kind + "/" + c.Name + ".xml"

    let private expectedPath (c: FirewalldModel.Configuration) =
        if c.Kind = "settings" then "/etc/firewalld/firewalld.conf" else objectFilePath c

    let private diagnostic (text: string) =
        if isNull text then ""
        else text.Substring(0, min 2048 text.Length) |> String.map (fun c -> if Char.IsControl c then ' ' else c)

    let private run (environment: HostEnvironment) executable arguments =
        let result = environment.Run executable arguments None
        if result.ExitCode <> 0 then
            let details = if String.IsNullOrWhiteSpace result.Stderr then result.Stdout else result.Stderr
            fail ("Firewalld recovery command failed: " + executable + " " + String.concat " " arguments + " (exit " + string result.ExitCode + "): " + diagnostic details)
        result.Stdout.Trim()

    let internal regularPath (environment: HostEnvironment) logical =
        let physical = logicalPath environment logical
        let rec inspect item =
            if not (String.IsNullOrEmpty item) then
                if File.Exists item || Directory.Exists item then
                    if File.GetAttributes(item).HasFlag FileAttributes.ReparsePoint then fail "Symlinks are not accepted for firewalld transaction state."
                elif not (isNull (FileInfo(item).LinkTarget)) then
                    fail "Dangling symlink in firewalld transaction state."
                let parent = Path.GetDirectoryName item
                if not (String.IsNullOrEmpty parent) && parent <> item then inspect parent
        inspect physical
        physical

    let private ensureDirectory (environment: HostEnvironment) logical mode =
        let physical = regularPath environment logical
        if not (Directory.Exists physical) then
            Directory.CreateDirectory(physical, enum<UnixFileMode> mode) |> ignore
        regularPath environment logical |> ignore
        physical

    let private checkPrivateDirectory (environment: HostEnvironment) =
        let parent = ensureDirectory environment "/var/lib/keroosha-iac" (int directoryMode)
        let ownership = run environment "stat" [ "-c"; "%u:%a"; "--"; parent ]
        let fields = ownership.Split(':')
        if fields.Length <> 2 || fields[0] <> "0" || (Convert.ToInt32(fields[1], 8) &&& 0o022) <> 0 then
            fail "Firewalld journal parent must be root-owned and not group/world writable."
        let directory = ensureDirectory environment journalDirectory (int directoryMode)
        let details = run environment "stat" [ "-c"; "%u:%a"; "--"; directory ]
        if details <> "0:700" then fail "Firewalld transaction directory must be root-owned with mode 700."
        directory

    let private getOptionalString (node: JsonObject) (key: string) =
        if not (node.ContainsKey key) then fail ("Missing firewalld transaction field " + key + ".")
        match node[key] with null -> None | value -> Some(value.GetValue<string>())

    let private getString (node: JsonObject) (key: string) =
        getOptionalString node key |> Option.defaultWith (fun () -> fail ("Missing firewalld transaction field " + key + "."))

    let private getBool (node: JsonObject) (key: string) =
        match node[key] with null -> fail ("Missing firewalld transaction field " + key + ".") | value -> value.GetValue<bool>()

    let private getInt (node: JsonObject) (key: string) =
        match node[key] with null -> fail ("Missing firewalld transaction field " + key + ".") | value -> value.GetValue<int>()

    let private getOptionalObject (node: JsonObject) (key: string) =
        if not (node.ContainsKey key) then fail ("Missing firewalld transaction field " + key + ".")
        match node[key] with
        | null -> None
        | :? JsonObject as value -> Some(value.DeepClone().AsObject())
        | _ -> fail ("Invalid firewalld transaction field " + key + ".")
    let private setOptionalString (node: JsonObject) (key: string) (value: string option) =
        node[key] <- match value with None -> null | Some text -> JsonValue.Create text :> JsonNode
    let private setOptionalObject (node: JsonObject) (key: string) (value: JsonObject option) =
        node[key] <- match value with None -> null | Some objectValue -> objectValue.DeepClone()
    let private pendingNode (pending: PendingTransaction) =
        let node = JsonObject()
        node["version"] <- JsonValue.Create(max 2 pending.SchemaVersion)
        if pending.SchemaVersion >= 3 then
            let progress = pending.NativeProgress |> Option.map (fun p ->
                let value = JsonObject()
                value["completedSteps"] <- JsonValue.Create p.CompletedSteps
                value["inFlightStep"] <- (match p.InFlightStep with Some i -> JsonValue.Create i :> JsonNode | None -> null)
                value)
            setOptionalObject node "nativeProgress" progress
        if pending.SchemaVersion >= 4 then
            let undo = pending.NativeUndo |> Option.map (fun (boot: Guid, p) ->
                let value = JsonObject()
                value["bootId"] <- JsonValue.Create(boot.ToString("D"))
                value["remainingSteps"] <- JsonValue.Create p.RemainingSteps
                value["inFlightStep"] <- (match p.InFlightStep with Some i -> JsonValue.Create i :> JsonNode | None -> null)
                if pending.SchemaVersion >= 5 then
                    value["preimageVerified"] <- JsonValue.Create p.PreimageVerified
                value)
            setOptionalObject node "nativeUndo" undo
        node["nonce"] <- JsonValue.Create pending.Nonce
        node["ownerId"] <- JsonValue.Create pending.OwnerId
        node["configuration"] <- JsonValue.Create(FirewalldModel.toJson pending.Configuration)
        node["path"] <- JsonValue.Create pending.Path
        setOptionalObject node "scope" pending.Scope
        setOptionalString node "before" pending.Before
        node["beforeMode"] <- JsonValue.Create pending.BeforeMode
        setOptionalString node "after" pending.After
        node["afterMode"] <- JsonValue.Create pending.AfterMode
        setOptionalString node "managedBefore" pending.ManagedBefore
        setOptionalString node "managedAfter" pending.ManagedAfter
        setOptionalObject node "rollbackProof" pending.RollbackProof
        node["activationStarted"] <- JsonValue.Create pending.ActivationStarted
        node["awaitingPostBoot"] <- JsonValue.Create pending.AwaitingPostBoot
        node["releaseOnRollback"] <- JsonValue.Create pending.ReleaseOnRollback
        node["deleteOnConfirm"] <- JsonValue.Create pending.DeleteOnConfirm
        node["status"] <- JsonValue.Create pending.Status
        node

    let private parsePendingNode (node: JsonObject) =
        let fieldsV1 =
            set [ "version"; "nonce"; "ownerId"; "configuration"; "path"; "before"; "beforeMode"; "after"; "afterMode"; "managedBefore"; "managedAfter"; "releaseOnRollback"; "deleteOnConfirm"; "status" ]
        let fieldsV2 =
            Set.union fieldsV1 (set [ "scope"; "rollbackProof"; "activationStarted"; "awaitingPostBoot" ])
        let actual = node |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        let version = getInt node "version"
        let fieldsV3 = Set.add "nativeProgress" fieldsV2
        let fieldsV4 = Set.add "nativeUndo" fieldsV3
        if (version < 1 || version > 5)
           || (version = 1 && actual <> fieldsV1)
           || (version = 2 && actual <> fieldsV2)
           || (version = 3 && actual <> fieldsV3)
           || (version = 4 && actual <> fieldsV4)
           || (version = 5 && actual <> fieldsV4) then
            fail "Invalid firewalld transaction record."
        let nonce = getString node "nonce"
        if not (Regex.IsMatch(nonce, "^[0-9a-f]{32}$", RegexOptions.CultureInvariant)) then fail "Invalid firewalld transaction nonce."
        let owner = getString node "ownerId"
        if String.IsNullOrWhiteSpace owner || owner |> Seq.exists Char.IsControl then fail "Invalid firewalld transaction owner."
        let c = FirewalldModel.parse(getString node "configuration")
        let path = getString node "path"
        if path <> expectedPath c then fail "Invalid firewalld transaction file path."
        let beforeMode, afterMode = getInt node "beforeMode", getInt node "afterMode"
        if beforeMode < 0 || beforeMode > 0o7777 || afterMode < 0 || afterMode > 0o7777 then fail "Invalid firewalld transaction file mode."
        let status = getString node "status"
        if status <> "pending" && status <> "confirmed" then fail "Invalid firewalld transaction status."
        let scope = if version = 1 then None else getOptionalObject node "scope"
        let rollbackProof = if version = 1 then None else getOptionalObject node "rollbackProof"
        let activationStarted = if version = 1 then status = "pending" else getBool node "activationStarted"
        let awaitingPostBoot = if version = 1 then false else getBool node "awaitingPostBoot"
        let nativeProgress =
            if version < 3 then None
            else getOptionalObject node "nativeProgress" |> Option.map (fun value ->
                if (value |> Seq.map _.Key |> Set.ofSeq) <> set [ "completedSteps"; "inFlightStep" ] then fail "Invalid firewalld native progress fields."
                let doneCount = getInt value "completedSteps"
                let inFlight = match value["inFlightStep"] with null -> None | step -> Some(step.GetValue<int>())
                if doneCount < 0 || doneCount > 4096 || (inFlight |> Option.exists ((<>) doneCount)) then fail "Invalid firewalld native progress."
                { CompletedSteps = doneCount; InFlightStep = inFlight })
        let nativeUndo =
            if version < 4 then None
            else getOptionalObject node "nativeUndo" |> Option.map (fun value ->
                let undoFields = set [ "bootId"; "remainingSteps"; "inFlightStep" ]
                let undoFields = if version >= 5 then Set.add "preimageVerified" undoFields else undoFields
                if (value |> Seq.map _.Key |> Set.ofSeq) <> undoFields || nativeProgress.IsNone || status <> "pending" then
                    fail "Invalid firewalld native inverse receipt."
                let remaining = getInt value "remainingSteps"
                let inFlight = match value["inFlightStep"] with null -> None | step -> Some(step.GetValue<int>())
                let preimageVerified = if version >= 5 then getBool value "preimageVerified" else false
                if remaining < 0 || remaining > 4096 || (not awaitingPostBoot && remaining > nativeProgress.Value.CompletedSteps) ||
                   (inFlight |> Option.exists (fun i -> i < 0 || i <> remaining - 1)) ||
                   (preimageVerified && (remaining <> 0 || inFlight.IsSome)) then
                    fail "Invalid firewalld native inverse checkpoint."
                Guid.ParseExact(getString value "bootId", "D"),
                { RemainingSteps = remaining
                  InFlightStep = inFlight
                  PreimageVerified = preimageVerified })
        if version >= 2 && c.Kind = "settings" && scope.IsNone then fail "Invalid firewalld settings transaction scope."
        if activationStarted && rollbackProof.IsNone then fail "Firewalld transaction lacks required runtime rollback proof."
        if awaitingPostBoot && rollbackProof.IsNone then fail "Post-boot recovery lacks a durable inverse."
        { SchemaVersion = version
          Nonce = nonce
          OwnerId = owner
          Configuration = c
          Path = path
          Scope = scope
          Before = getOptionalString node "before"
          BeforeMode = beforeMode
          After = getOptionalString node "after"
          AfterMode = afterMode
          ManagedBefore = getOptionalString node "managedBefore"
          ManagedAfter = getOptionalString node "managedAfter"
          RollbackProof = rollbackProof
          NativeProgress = nativeProgress
          NativeUndo = nativeUndo
          ActivationStarted = activationStarted
          AwaitingPostBoot = awaitingPostBoot
          ReleaseOnRollback = getBool node "releaseOnRollback"
          DeleteOnConfirm = getBool node "deleteOnConfirm"
          Status = status }

    let private decodeFile (bytes: byte array) =
        if bytes.Length >= 3 && bytes[0] = 0xEFuy && bytes[1] = 0xBBuy && bytes[2] = 0xBFuy then
            fail "Firewalld transaction files must use UTF-8 without a byte-order mark."
        strictUtf8.GetString bytes

    let private getJournalText (environment: HostEnvironment) (logical: string) =
        let physical = regularPath environment logical
        if File.Exists physical then
            if File.GetAttributes(physical).HasFlag FileAttributes.Directory then fail "Expected a regular firewalld transaction file."
            Some(decodeFile(File.ReadAllBytes physical))
        elif Directory.Exists physical then fail "Expected a regular firewalld transaction file."
        elif not (isNull (FileInfo(physical).LinkTarget)) then fail "Dangling firewalld transaction symlink."
        else None

    let private saveJournal (environment: HostEnvironment) (c: FirewalldModel.Configuration) (journal: JsonObject) =
        checkPrivateDirectory environment |> ignore
        let destination = regularPath environment (journalPath c)
        HostFiles.atomicWrite destination (strictUtf8.GetBytes(journal.ToJsonString())) privateFileMode

    let private removeJournal (environment: HostEnvironment) (c: FirewalldModel.Configuration) owner =
        match getJournalText environment (journalPath c) with
        | None -> ()
        | Some text ->
            let journal = JsonNode.Parse(text).AsObject()
            if getString journal "ownerId" <> owner then fail "Refusing to remove another owner's firewalld journal."
            let destination = regularPath environment (journalPath c)
            File.Delete destination
            HostFiles.syncDirectory (Path.GetDirectoryName destination)

    let private journalOwner (journal: JsonObject) = getString journal "ownerId"


    let pending (environment: HostEnvironment) =
        match getJournalText environment pendingPath with
        | None -> None
        | Some text ->
            let node = JsonNode.Parse(text).AsObject()
            let details = run environment "stat" [ "-c"; "%u:%a"; "--"; logicalPath environment pendingPath ]
            if details <> "0:600" then fail "Firewalld transaction marker must be root-owned with mode 600."
            Some(parsePendingNode node)

    let private savePending (environment: HostEnvironment) (transaction: PendingTransaction) =
        checkPrivateDirectory environment |> ignore
        let destination = regularPath environment pendingPath
        HostFiles.atomicWrite destination (strictUtf8.GetBytes((pendingNode transaction).ToJsonString())) privateFileMode

    let private bootId environment =
        Guid.ParseExact(File.ReadAllText(logicalPath environment "/proc/sys/kernel/random/boot_id").Trim(), "D")

    /// The caller holds the native writer lock. Only the global intent supplies
    /// authority; the per-owner record is a projection and can lag a crash.
    let undoJournal environment transaction =
        if transaction.SchemaVersion < 4 || transaction.NativeProgress.IsNone then None
        else
            let boot = lazy (bootId environment)
            let previous = transaction.NativeUndo |> Option.map (fun (generation, receipt) ->
                if generation <> boot.Value then fail "Native inverse receipt belongs to a different boot; ordered boot recovery is required."
                receipt)
            let mutable last = previous
            let interrupted = previous |> Option.exists (fun p -> p.InFlightStep.IsSome)
            let completedForward =
                transaction.NativeProgress |> Option.exists (fun progress -> progress.CompletedSteps > 0)
            let freshAuthorityAllowed = transaction.AwaitingPostBoot || completedForward
            let persist (next: NativeUndoProgress) =
                if interrupted then fail "A new recovery attempt cannot attest an interrupted inverse command."
                let valid =
                    match last, next.InFlightStep, next.PreimageVerified with
                    | None, None, false ->
                        freshAuthorityAllowed && next.RemainingSteps = 0
                    | None, Some i, false ->
                        freshAuthorityAllowed && i >= 0 && i < 4096 && next.RemainingSteps = i + 1
                    | Some prior, Some i, false ->
                        not prior.PreimageVerified && prior.InFlightStep.IsNone && prior.RemainingSteps = next.RemainingSteps
                        && i >= 0 && i = next.RemainingSteps - 1
                    | Some prior, None, false ->
                        not prior.PreimageVerified && prior.InFlightStep = Some next.RemainingSteps
                        && prior.RemainingSteps = next.RemainingSteps + 1
                    | Some prior, None, true ->
                        not prior.PreimageVerified && prior.InFlightStep.IsNone && prior.RemainingSteps = 0
                        && next.RemainingSteps = 0
                    | _ -> false
                if not valid then fail "Invalid transition of durable native inverse authority."
                savePending environment { transaction with SchemaVersion = 5; NativeUndo = Some(boot.Value, next) }
                last <- Some next
            Some { Previous = previous; Persist = persist }

    let private clearPending (environment: HostEnvironment) =
        let destination = regularPath environment pendingPath
        if File.Exists destination then
            File.Delete destination
            HostFiles.syncDirectory (Path.GetDirectoryName destination)

    let private readPath (environment: HostEnvironment) (logical: string) =
        let physical = regularPath environment logical
        if File.Exists physical then
            if File.GetAttributes(physical).HasFlag FileAttributes.Directory then fail "Firewalld transaction target is not a regular file."
            let contents = decodeFile(File.ReadAllBytes physical)
            Some contents, int (File.GetUnixFileMode physical)
        elif Directory.Exists physical then fail "Firewalld transaction target is not a regular file."
        elif not (isNull (FileInfo(physical).LinkTarget)) then fail "Dangling firewalld transaction target symlink."
        else None, 0o644

    let private writeJournalPending (journal: JsonObject) (transaction: PendingTransaction) =
        journal["pending"] <- pendingNode transaction

    let private clearJournalPending (journal: JsonObject) = journal["pending"] <- null

    let private validateIdentity (c: FirewalldModel.Configuration) (journal: JsonObject) (transaction: PendingTransaction) =
        if transaction.OwnerId <> journalOwner journal
           || transaction.Configuration.Kind <> c.Kind
           || transaction.Configuration.Name <> c.Name
           || FirewalldModel.toJson transaction.Configuration <> FirewalldModel.toJson c then
            fail "Firewalld transaction does not belong to this resource generation."

    let private updateManaged (journal: JsonObject) (contents: string option) (mode: int) =
        setOptionalString journal "managed" contents
        journal["managedMode"] <- JsonValue.Create mode

    // A key owner may preserve a native 0600 tightening; it never widens a
    // shared config file on rollback. XML owners require exact metadata.
    let internal compatibleMode (scope: JsonObject option) expected actual =
        actual = expected || (scope.IsSome && actual = 0o600 && (expected = 0o644 || expected = 0o640))

    let private verifyMetadata environment transaction contents mode expected =
        if Option.isSome contents then
            let physical = regularPath environment transaction.Path
            if run environment "stat" [ "-c"; "%u:%g"; "--"; physical ] <> "0:0" then
                fail "Firewalld transaction file ownership changed; refusing to replace it."
            if not (compatibleMode transaction.Scope expected mode) then
                fail "Firewalld transaction file permissions changed; refusing to replace it."


    let private restorePending
        (environment: HostEnvironment)
        (transaction: PendingTransaction)
        (journal: JsonObject option)
        (readState: JsonObject option -> string option -> string option)
        (writeState: JsonObject option -> string option -> string option -> int -> unit)
        (restoreRuntime: PendingTransaction -> RecoveryPhase -> unit)
        (phase: RecoveryPhase)
        =
        if phase = BootAfterFirewalld && not transaction.AwaitingPostBoot then
            fail "Post-boot recovery lacks the ordered preboot reservation."
        if transaction.SchemaVersion < 2 && transaction.Status = "pending" then
            fail "Legacy firewalld transaction lacks a durable runtime rollback proof; refusing recovery."
        let inspectDisk () =
            let contents, mode = readPath environment transaction.Path
            let state = if transaction.SchemaVersion = 1 then contents else readState transaction.Scope contents
            contents, mode, state
        let requirePrebootDisk (contents, mode, state) =
            if state <> transaction.Before then
                fail "Firewalld permanent preimage changed after preboot; refusing to overwrite independent disk state."
            verifyMetadata environment transaction contents mode transaction.BeforeMode
            if contents.IsSome then mode else transaction.BeforeMode
        let mode =
            let current, currentMode, state = inspectDisk ()
            if transaction.AwaitingPostBoot then
                // Preboot has already spent disk-write authority, including for
                // an absent override. Matching After again is not provenance.
                requirePrebootDisk (current, currentMode, state)
            else
                if state <> transaction.Before && state <> transaction.After then
                    fail "Firewalld configuration changed during an interrupted transaction; refusing recovery."
                if state = transaction.Before then verifyMetadata environment transaction current currentMode transaction.BeforeMode
                if state = transaction.After then verifyMetadata environment transaction current currentMode transaction.AfterMode
                let mode = if transaction.Scope.IsSome && current.IsSome && currentMode = 0o600 then currentMode else transaction.BeforeMode
                if state <> transaction.Before || (current.IsSome && currentMode <> mode) then
                    writeState transaction.Scope state transaction.Before mode
                mode
        let rollbackStrategy =
            transaction.RollbackProof
            |> Option.bind (fun proof ->
                match proof["strategy"] with
                | null -> None
                | strategy -> Some(strategy.GetValue<string>()))
        let startupLoadsDisk = rollbackStrategy = Some "runtime-delta"
        let legacyNativeRepair =
            startupLoadsDisk || (rollbackStrategy = Some "object-delta" && transaction.ActivationStarted)
        let needsBootInverse = transaction.ActivationStarted || startupLoadsDisk || transaction.AwaitingPostBoot
        if transaction.ActivationStarted || transaction.AwaitingPostBoot || (phase <> ActiveDaemon && needsBootInverse) then
            match phase with
            | BootBeforeFirewalld ->
                // Only a new kernel boot may reset reverse progress: firewalld
                // will start anew from the restored disk. Re-entering this unit
                // in the same boot must never replenish consumed authority.
                let undo = transaction.NativeUndo |> Option.filter (fun (generation, _) -> generation = bootId environment)
                // A legacy forward-only record cannot authorize an active
                // inverse. Upgrade a v3 repair only at a verified stopped
                // daemon boundary, where the next daemon will load the disk.
                let version =
                    if transaction.SchemaVersion = 3 && legacyNativeRepair && transaction.NativeProgress.IsSome then
                        match environment.Run "/usr/bin/systemctl" [ "show"; "--property=ActiveState"; "--value"; "firewalld.service" ] None with
                        | { ExitCode = 0; Stdout = state } when state.Trim() = "inactive" -> 4
                        | _ -> fail "Legacy native repair needs a stopped firewalld before boot-phase migration."
                    else transaction.SchemaVersion
                let waiting = { transaction with SchemaVersion = version; AwaitingPostBoot = true; NativeUndo = undo }
                savePending environment waiting
                match journal with
                | Some value ->
                    writeJournalPending value waiting
                    saveJournal environment transaction.Configuration value
                | None when transaction.ReleaseOnRollback -> ()
                | None -> fail "Firewalld owner journal is missing during boot recovery."
            | BootAfterFirewalld -> restoreRuntime transaction BootAfterFirewalld
            | _ ->
                let hasNativeRepair =
                    transaction.NativeProgress.IsSome
                    || (transaction.RollbackProof
                        |> Option.exists (fun proof ->
                            match proof["strategy"] with
                            | null -> false
                            | strategy -> List.contains (strategy.GetValue<string>()) [ "object-delta"; "runtime-delta" ]))
                if phase = ActiveDaemon && transaction.AwaitingPostBoot && hasNativeRepair then
                    let hasCurrentBootUndo =
                        transaction.NativeUndo
                        |> Option.exists (fun (generation, _) -> generation = bootId environment)
                    if not hasCurrentBootUndo then
                        fail "Ordered post-boot recovery must verify the native repair before active recovery can retire it."
                    // A same-boot receipt keeps ordered startup verification in force.
                    let retryPhase =
                        if transaction.Configuration.Kind = "settings" then phase else BootAfterFirewalld
                    restoreRuntime transaction retryPhase
                else
                    restoreRuntime transaction phase
        if not (needsBootInverse && phase = BootBeforeFirewalld) then
            // Runtime verification can take time. Do not release the reservation
            // if the disk changed while it ran; this second check is read-only.
            let mode = if transaction.AwaitingPostBoot then requirePrebootDisk (inspectDisk ()) else mode
            match journal with
            | Some value ->
                if transaction.ReleaseOnRollback then removeJournal environment transaction.Configuration transaction.OwnerId
                else
                    updateManaged value transaction.ManagedBefore mode
                    clearJournalPending value
                    if value.ContainsKey "deleteOnConfirm" then value.Remove "deleteOnConfirm" |> ignore
                    saveJournal environment transaction.Configuration value
            | None ->
                if not transaction.ReleaseOnRollback then fail "Firewalld owner journal is missing during recovery."
            clearPending environment

    let private hasOwnerPending (journal: JsonObject) =
        match journal["pending"] with
        | null -> false
        | :? JsonObject -> true
        | _ -> fail "Invalid firewalld owner pending transaction."

    let private ensureNoOrphanedOwnerPending (environment: HostEnvironment) =
        let directory = logicalPath environment journalDirectory
        if Directory.Exists directory then
            checkPrivateDirectory environment |> ignore
            for physical in Directory.EnumerateFiles(directory, "*.json") do
                let logical = journalDirectory + "/" + Path.GetFileName physical
                match getJournalText environment logical with
                | None -> ()
                | Some text ->
                    let journal = JsonNode.Parse(text).AsObject()
                    if hasOwnerPending journal then
                        fail "An owner journal contains an unpaired firewalld transaction; refusing new mutations."

    let canClassifyPreStageRefusal (environment: HostEnvironment) =
        try
            match pending environment with
            | Some _ -> false
            | None ->
                ensureNoOrphanedOwnerPending environment
                true
        with _ -> false

    let private ensureNoLegacyPending (journal: JsonObject) =
        if hasOwnerPending journal then
            fail "A legacy firewalld owner transaction has no matching host recovery marker; refusing recovery."

    let private ensureRecoverablePending (transaction: PendingTransaction) =
        if transaction.Status = "pending" && transaction.SchemaVersion < 2 then
            fail "Legacy firewalld host transaction lacks a durable runtime rollback proof; refusing recovery."


    let private createRecoveryUnits (environment: HostEnvironment) =
        let helper = Environment.ProcessPath
        if String.IsNullOrWhiteSpace helper || not (Path.IsPathRooted helper) || helper |> Seq.exists (fun c -> Char.IsControl c || Char.IsWhiteSpace c) then
            fail "Cannot arm firewalld rollback without a canonical native helper executable path."
        let previousServiceText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld transaction rollback"; "DefaultDependencies=no"; "After=local-fs.target"; "StartLimitIntervalSec=0"; "[Service]"; "Type=oneshot"; "TimeoutStartSec=3min"; "Restart=on-failure"; "RestartSec=30s"; "ExecStart=" + helper + " firewalld-recover"; "" ]
        let previousBootServiceText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld boot recovery"; "DefaultDependencies=no"; "After=local-fs.target"; "Before=firewalld.service"; "[Service]"; "Type=oneshot"; "RemainAfterExit=yes"; "TimeoutStartSec=90s"; "ExecStart=" + helper + " firewalld-recover-boot"; "[Install]"; "WantedBy=multi-user.target"; "RequiredBy=firewalld.service"; "" ]
        let previousPostBootServiceText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld post-boot recovery"; "DefaultDependencies=no"; "After=firewalld.service"; "Requires=firewalld.service"; "[Service]"; "Type=oneshot"; "TimeoutStartSec=90s"; "ExecStart=" + helper + " firewalld-recover-postboot"; "[Install]"; "WantedBy=multi-user.target"; "" ]
        // Bound each external command, not the sum over a valid inventory.
        let serviceText = previousServiceText.Replace("TimeoutStartSec=3min", "TimeoutStartSec=infinity")
        let bootServiceText =
            previousBootServiceText.Replace("TimeoutStartSec=90s", "TimeoutStartSec=infinity")
                                   .Replace("WantedBy=multi-user.target\nRequiredBy=firewalld.service", "WantedBy=multi-user.target firewalld.service")
        let postBootServiceText = previousPostBootServiceText.Replace("TimeoutStartSec=90s", "TimeoutStartSec=infinity")
        // No reference to the helper or its cache. If boot recovery actually
        // failed with a reserved transaction, quarantine under the *running*
        // native daemon before the normal network-pre barrier is released.
        let containmentText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Quarantine an unverifiable firewalld boot transaction"
                  "DefaultDependencies=no"; "Wants=firewalld.service " + bootServiceName + " " + postBootServiceName
                  "After=firewalld.service " + bootServiceName + " " + postBootServiceName
                  "Before=network-pre.target"; "ConditionPathExists=" + pendingPath
                  "[Service]"; "Type=oneshot"
                  "ExecCondition=/usr/bin/systemctl --quiet is-failed " + bootServiceName + " " + postBootServiceName
                  "ExecStart=/usr/bin/firewall-cmd --panic-on"; "[Install]"; "WantedBy=multi-user.target"; "" ]
        let legacyServiceText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld transaction rollback"; "DefaultDependencies=no"; "After=local-fs.target"; "[Service]"; "Type=oneshot"; "ExecStart=" + helper + " firewalld-recover"; "" ]
        let legacyBootServiceText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld boot recovery"; "DefaultDependencies=no"; "After=local-fs.target"; "Before=firewalld.service"; "[Service]"; "Type=oneshot"; "ExecStart=" + helper + " firewalld-recover-boot"; "[Install]"; "WantedBy=multi-user.target"; "" ]
        let matchesOwnedUnit (expectedText: string) (actualText: string) =
            let expectedLines = expectedText.Split('\n')
            let actualLines = actualText.Split('\n')
            let executableLine (expected: string) (actual: string) =
                let prefix = "ExecStart="
                if not (expected.StartsWith(prefix, StringComparison.Ordinal) && actual.StartsWith(prefix, StringComparison.Ordinal)) then false
                else
                    let expectedCommand = expected.Substring(prefix.Length)
                    let actualCommand = actual.Substring(prefix.Length)
                    let expectedSpace = expectedCommand.IndexOf(' ')
                    let actualSpace = actualCommand.IndexOf(' ')
                    if expectedSpace <= 0 || actualSpace <= 0 then false
                    else
                        let arguments = expectedCommand.Substring(expectedSpace)
                        let actualArguments = actualCommand.Substring(actualSpace)
                        let oldExecutable = actualCommand.Substring(0, actualSpace)
                        actualArguments = arguments
                        && (oldExecutable = helper
                            || Regex.IsMatch(oldExecutable, "^/var/cache/keroosha-iac/helper/(linux-x64|linux-arm64)/[0-9a-f]{64}$", RegexOptions.CultureInvariant))
            expectedLines.Length = actualLines.Length
            && Array.forall2 (fun expected actual -> expected = actual || executableLine expected actual) expectedLines actualLines
        let writeOwned (logical: string) (text: string) (legacyTexts: string list) =
            let physical = regularPath environment logical
            let expected = strictUtf8.GetBytes(text)
            let currentBytes =
                if File.Exists physical then
                    let owner = run environment "stat" [ "-c"; "%u:%g"; "--"; physical ]
                    if owner <> "0:0" || File.GetUnixFileMode physical <> fileMode then
                        fail "A firewalld recovery systemd unit is not root-owned mode 0644."
                    let bytes = File.ReadAllBytes physical
                    let current = strictUtf8.GetString bytes
                    if not (matchesOwnedUnit text current
                            || legacyTexts |> List.exists (fun legacy -> matchesOwnedUnit legacy current)) then
                        fail "A firewalld recovery systemd unit collides with an unowned or modified unit."
                    Some bytes
                elif Directory.Exists physical || not (isNull (FileInfo(physical).LinkTarget)) then
                    fail "A firewalld recovery systemd unit path is not a regular file."
                else None
            if currentBytes <> Some expected then HostFiles.atomicWrite physical expected fileMode

        let validateEnableLink (logicalLink: string) (logicalTarget: string) =
            let logicalParent = Path.GetDirectoryName logicalLink
            regularPath environment logicalParent |> ignore
            let physicalLink = logicalPath environment logicalLink
            let expectedTarget = Path.GetFullPath(logicalPath environment logicalTarget)
            match FileInfo(physicalLink).LinkTarget with
            | null when File.Exists physicalLink || Directory.Exists physicalLink ->
                fail "A firewalld recovery systemd enable link collides with an unowned path."
            | null -> ()
            | target ->
                let actualTarget =
                    if Path.IsPathRooted target then Path.GetFullPath target
                    else Path.GetFullPath(Path.Combine(Path.GetDirectoryName physicalLink, target))
                if actualTarget <> expectedTarget then
                    fail "A firewalld recovery systemd enable link points to an unowned unit."
        validateEnableLink ("/etc/systemd/system/multi-user.target.wants/" + bootServiceName) bootServicePath
        validateEnableLink ("/etc/systemd/system/firewalld.service.requires/" + bootServiceName) bootServicePath
        validateEnableLink ("/etc/systemd/system/firewalld.service.wants/" + bootServiceName) bootServicePath
        validateEnableLink ("/etc/systemd/system/multi-user.target.wants/" + containmentName) containmentPath
        validateEnableLink ("/etc/systemd/system/multi-user.target.wants/" + postBootServiceName) postBootServicePath
        validateEnableLink ("/etc/systemd/system/timers.target.wants/" + timerName) timerPath
        ensureDirectory environment "/etc/systemd/system" (int unitDirectoryMode) |> ignore
        writeOwned servicePath serviceText [ previousServiceText; legacyServiceText ]
        writeOwned bootServicePath bootServiceText [ previousBootServiceText; legacyBootServiceText ]
        writeOwned postBootServicePath postBootServiceText [ previousPostBootServiceText ]
        writeOwned containmentPath containmentText []
        writeOwned timerPath timerText [ legacyTimerText ]
        let oldLink = logicalPath environment ("/etc/systemd/system/firewalld.service.requires/" + bootServiceName)
        if not (isNull (FileInfo(oldLink).LinkTarget)) then
            File.Delete oldLink
            HostFiles.syncDirectory (Path.GetDirectoryName oldLink)
        run environment "/usr/bin/systemctl" [ "daemon-reload" ] |> ignore
        run environment "/usr/bin/systemctl" [ "enable"; bootServiceName ] |> ignore
        // Latch this boot before timer activation or staging. With RemainAfterExit=yes,
        // a daemon restart cannot re-run the lock-taking preboot hook.
        run environment "/usr/bin/systemctl" [ "start"; bootServiceName ] |> ignore
        run environment "/usr/bin/systemctl" [ "enable"; postBootServiceName ] |> ignore
        run environment "/usr/bin/systemctl" [ "enable"; containmentName ] |> ignore
        // This caller holds the mutation lock and verified there is no pending
        // intent. Cancel any previous generation's delayed callback before
        // arming a new full confirmation interval; retry only FAILED recoveries.
        run environment "/usr/bin/systemctl" [ "stop"; timerName ] |> ignore
        run environment "/usr/bin/systemctl" [ "stop"; serviceName ] |> ignore
        run environment "/usr/bin/systemctl" [ "enable"; timerName ] |> ignore
        run environment "/usr/bin/systemctl" [ "restart"; timerName ] |> ignore

    let private stopRetryTimer (environment: HostEnvironment) =
        let physical = regularPath environment timerPath
        if Directory.Exists physical then
            fail "The firewalld retry timer path is not a regular file."
        elif File.Exists physical then
            let owner = run environment "stat" [ "-c"; "%u:%g"; "--"; physical ]
            let contents = decodeFile(File.ReadAllBytes physical)
            if owner <> "0:0" || File.GetUnixFileMode physical <> fileMode
               || (contents <> timerText && contents <> legacyTimerText) then
                fail "Refusing to stop a modified or unowned firewalld retry timer."
            run environment "/usr/bin/systemctl" [ "stop"; timerName ] |> ignore

    let private hasOtherOwnerJournals (environment: HostEnvironment) excluded =
        let directory = logicalPath environment journalDirectory
        if not (Directory.Exists directory) then false
        else
            checkPrivateDirectory environment |> ignore
            Directory.EnumerateFiles(directory, "*.json")
            |> Seq.exists (fun path -> Path.GetFileName path <> Path.GetFileName pendingPath && Some(Path.GetFileName path) <> excluded)

    let private verifyOwnedUnitFile (environment: HostEnvironment) (logical: string) =
        let physical = regularPath environment logical
        if Directory.Exists physical then fail "A firewalld recovery systemd unit path is not a regular file."
        elif File.Exists physical then
            let owner = run environment "stat" [ "-c"; "%u:%g"; "--"; physical ]
            let text = decodeFile(File.ReadAllBytes physical)
            if owner <> "0:0" || File.GetUnixFileMode physical <> fileMode
               || not (text.StartsWith(ownerMarker + "\n", StringComparison.Ordinal)) then
                fail "A firewalld recovery systemd unit is not an owned root:root mode 0644 unit."

    let private ownedEnableLink
        (environment: HostEnvironment)
        (logicalLink: string)
        (logicalTarget: string)
        =
        regularPath environment (Path.GetDirectoryName logicalLink) |> ignore
        let physicalLink = logicalPath environment logicalLink
        let expectedTarget = Path.GetFullPath(logicalPath environment logicalTarget)
        match FileInfo(physicalLink).LinkTarget with
        | null when File.Exists physicalLink || Directory.Exists physicalLink ->
            fail "A firewalld recovery systemd enable link collides with an unowned path."
        | null -> None
        | target ->
            let actualTarget =
                if Path.IsPathRooted target then Path.GetFullPath target
                else Path.GetFullPath(Path.Combine(Path.GetDirectoryName physicalLink, target))
            if actualTarget <> expectedTarget then
                fail "A firewalld recovery systemd enable link points to an unowned unit."
            Some physicalLink

    let private detachUnusedUnits environment excluded =
        if not (hasOtherOwnerJournals environment excluded) then
            for logical in [ servicePath; bootServicePath; postBootServicePath; containmentPath; timerPath ] do
                verifyOwnedUnitFile environment logical
            let links =
                [ "/etc/systemd/system/multi-user.target.wants/" + bootServiceName, bootServicePath
                  "/etc/systemd/system/firewalld.service.requires/" + bootServiceName, bootServicePath
                  "/etc/systemd/system/firewalld.service.wants/" + bootServiceName, bootServicePath
                  "/etc/systemd/system/multi-user.target.wants/" + containmentName, containmentPath
                  "/etc/systemd/system/multi-user.target.wants/" + postBootServiceName, postBootServicePath
                  "/etc/systemd/system/timers.target.wants/" + timerName, timerPath ]
                |> List.choose (fun (logicalLink, logicalTarget) -> ownedEnableLink environment logicalLink logicalTarget)
            for link in links do
                File.Delete link
                HostFiles.syncDirectory (Path.GetDirectoryName link)
            if not links.IsEmpty then run environment "/usr/bin/systemctl" [ "daemon-reload" ] |> ignore

    let private reconcileRecoveryUnits environment =
        if (pending environment).IsSome then fail "Cannot detach firewalld recovery units while a transaction is pending."
        stopRetryTimer environment
        detachUnusedUnits environment None

    let private finishConfirmed
        (environment: HostEnvironment)
        (transaction: PendingTransaction)
        (journal: JsonObject option)
        (readState: JsonObject option -> string option -> string option)
        =
        let current, currentMode = readPath environment transaction.Path
        let state = if transaction.SchemaVersion = 1 then current else readState transaction.Scope current
        verifyMetadata environment transaction current currentMode transaction.AfterMode
        if state <> transaction.After then
            fail "Confirmed firewalld configuration changed before transaction finalization."
        if transaction.DeleteOnConfirm then
            // Keep both confirmed intent and owner recoverable if a dependency
            // link was retargeted while waiting for the SSH acknowledgement.
            detachUnusedUnits environment (Some(Path.GetFileName(journalPath transaction.Configuration)))
        match journal with
        | Some value ->
            if transaction.DeleteOnConfirm then removeJournal environment transaction.Configuration transaction.OwnerId
            else
                updateManaged value transaction.ManagedAfter (if current.IsSome then currentMode else transaction.AfterMode)
                clearJournalPending value
                if value.ContainsKey "deleteOnConfirm" then value.Remove "deleteOnConfirm" |> ignore
                saveJournal environment transaction.Configuration value
        | None ->
            if not transaction.DeleteOnConfirm then fail "Confirmed firewalld owner journal is missing."
        clearPending environment

    let internal needsBootLinkMigration environment =
        let link = logicalPath environment ("/etc/systemd/system/firewalld.service.requires/" + bootServiceName)
        File.Exists link || not (isNull (FileInfo(link).LinkTarget))

    /// Under the existing mutation lock only. Retire the legacy hard edge
    /// without activating a daemon setting or restarting a dependent service.
    let internal migrateBootLink environment =
        if needsBootLinkMigration environment then
            if (pending environment).IsSome then fail "Cannot migrate recovery units over a pending intent."
            ensureNoOrphanedOwnerPending environment
            createRecoveryUnits environment
            stopRetryTimer environment

    let private makeTransaction
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (releaseOnRollback: bool)
        (deleteOnConfirm: bool)
        (path: string)
        (scope: JsonObject option)
        (before: string option)
        (beforeMode: int)
        (after: string option)
        (afterMode: int)
        (managedBefore: string option)
        (managedAfter: string option)
        (rollbackProof: JsonObject option)
        =
        if path <> expectedPath c then fail "Firewalld transaction path does not match its declared object."
        let owner = journalOwner journal
        { SchemaVersion = 5
          Nonce = Guid.NewGuid().ToString("N")
          OwnerId = owner
          Configuration = c
          Path = path
          Scope = scope |> Option.map (fun value -> value.DeepClone().AsObject())
          Before = before
          BeforeMode = beforeMode
          After = after
          AfterMode = afterMode
          ManagedBefore = managedBefore
          ManagedAfter = managedAfter
          RollbackProof = rollbackProof |> Option.map (fun value -> value.DeepClone().AsObject())
          NativeProgress =
              match rollbackProof |> Option.bind (fun (proof: JsonObject) -> Option.ofObj proof["strategy"]) with
              | Some strategy when List.contains (strategy.GetValue<string>()) [ "object-delta"; "runtime-delta" ] ->
                  Some { CompletedSteps = 0; InFlightStep = None }
              | _ -> None
          NativeUndo = None
          ActivationStarted = false
          AwaitingPostBoot = false
          ReleaseOnRollback = releaseOnRollback
          DeleteOnConfirm = deleteOnConfirm
          Status = "pending" }

    /// The original writer always installed managed zone/policy XML as 0644.
    /// This authenticates the managed mode, not a pre-acquisition baseline mode.
    let preMetadataJournal (journal: JsonObject) =
        journal.Count = 5 && isNull journal["pending"]
        && journal.ContainsKey "version" && journal.ContainsKey "ownerId" && journal.ContainsKey "pending"
        && journal.ContainsKey "baseline" && journal.ContainsKey "managed"

    let transact
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (releaseOnRollback: bool)
        (deleteOnConfirm: bool)
        (path: string)
        (scope: JsonObject option)
        (before: string option)
        (beforeMode: int)
        (after: string option)
        (afterMode: int)
        (managedBefore: string option)
        (managedAfter: string option)
        (rollbackProof: JsonObject option)
        (readState: JsonObject option -> string option -> string option)
        (writeState: JsonObject option -> string option -> string option -> int -> unit)
        (validate: JsonObject option -> string option -> unit)
        (activate: (NativeActivationProgress -> unit) -> unit)
        (restoreRuntime: PendingTransaction -> RecoveryPhase -> unit)
        : string =
        if path <> expectedPath c then fail "Firewalld transaction path does not match its declared object."
        if c.Kind = "settings" && scope.IsNone then fail "Firewalld settings transactions must be scoped to one daemon key."
        if rollbackProof.IsNone then fail "Firewalld transaction has no durable runtime rollback proof; refusing mutation."
        match pending environment with
        | Some _ -> fail "Another firewalld transaction is awaiting confirmation or recovery."
        | None -> ensureNoOrphanedOwnerPending environment
        validate scope after
        let actual, actualMode = readPath environment path
        let actualState = readState scope actual
        if actualState <> before || (actual.IsSome && actualMode <> beforeMode) then
            fail "Firewalld configuration changed before transaction staging."
        if managedBefore <> getOptionalString journal "managed" then
            fail "Firewalld managed configuration changed before transaction staging."
        let legacyObject = not releaseOnRollback && (c.Kind = "zone" || c.Kind = "policy") && preMetadataJournal journal
        if not (journal.ContainsKey "baselineMode") || isNull journal["baselineMode"] then
            match getOptionalString journal "baseline", c.Kind, releaseOnRollback with
            | Some _, ("zone" | "policy" | "service" | "ipset" | "icmptype" | "helper"), false -> ()
            | _ -> journal["baselineMode"] <- JsonValue.Create beforeMode
        let managedMode =
            if journal.ContainsKey "managedMode" && not (isNull journal["managedMode"]) then
                getInt journal "managedMode"
            elif legacyObject then 0o644
            elif c.Kind = "settings" then beforeMode
            else
                if before.IsSome && not (List.contains beforeMode [ 0o600; 0o640; 0o644 ]) then
                    fail "Managed firewalld object mode is unsafe; refusing to replace it."
                beforeMode
        if before.IsSome && managedMode <> beforeMode then
            fail "Firewalld managed file mode changed independently; refusing to overwrite it."
        journal["managedMode"] <- JsonValue.Create managedMode
        if journal.ContainsKey "deleteOnConfirm" then journal.Remove "deleteOnConfirm" |> ignore
        let transaction =
            makeTransaction c journal releaseOnRollback deleteOnConfirm path scope before beforeMode after afterMode
                managedBefore managedAfter rollbackProof
        try
            createRecoveryUnits environment
        with error ->
            try reconcileRecoveryUnits environment with _ -> ()
            fail ("Could not arm independent firewalld recovery before mutation: " + diagnostic error.Message)
        // This is the sole authoritative reservation. Persist it before the owner journal
        // projection so interruption cannot leave an unpaired per-owner pending record.
        try
            savePending environment transaction
        with error ->
            try reconcileRecoveryUnits environment with _ -> ()
            fail ("Could not persist firewalld recovery state before mutation: " + diagnostic error.Message)
        writeJournalPending journal transaction
        saveJournal environment c journal
        let mutable staged = transaction
        try
            if before <> after || (before.IsSome && beforeMode <> afterMode) then
                writeState scope before after afterMode
            let activating = { transaction with ActivationStarted = true }
            savePending environment activating
            staged <- activating
            writeJournalPending journal activating
            saveJournal environment c journal
            let actual, actualMode = readPath environment path
            verifyMetadata environment activating actual actualMode afterMode
            if readState scope actual <> after then
                fail "Firewalld target changed after staging and before native activation."
            let recordProgress progress =
                if staged.NativeProgress.IsNone then fail "Unexpected progress for a non-scoped firewalld transaction."
                let updated = { staged with NativeProgress = Some progress }
                // The global intent is authoritative; a crash may leave the owner
                // projection behind, never ahead of a confirmed native command.
                savePending environment updated
                staged <- updated
            activate recordProgress
        with originalError ->
            try
                restorePending environment staged (Some journal) readState writeState restoreRuntime ActiveDaemon
            with rollbackError ->
                fail ("Firewalld apply failed: " + diagnostic originalError.Message + "; rollback failed: " + diagnostic rollbackError.Message + "; journal retained for independent recovery.")
            try
                reconcileRecoveryUnits environment
            with cleanupError ->
                fail ("Firewalld apply failed and was rolled back, but recovery-unit cleanup failed: " + diagnostic cleanupError.Message)
            fail ("Firewalld apply failed; rollback completed for this transaction: " + diagnostic originalError.Message)
        transaction.Nonce

    let recover
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (path: string)
        (readState: JsonObject option -> string option -> string option)
        (writeState: JsonObject option -> string option -> string option -> int -> unit)
        (restoreRuntime: PendingTransaction -> RecoveryPhase -> unit)
        =
        if path <> expectedPath c then fail "Firewalld recovery path does not match its declared object."
        match pending environment with
        | Some transaction when transaction.OwnerId = journalOwner journal && transaction.Configuration.Kind = c.Kind && transaction.Configuration.Name = c.Name ->
            validateIdentity c journal transaction
            if transaction.Status = "confirmed" then finishConfirmed environment transaction (Some journal) readState
            else
                ensureRecoverablePending transaction
                restorePending environment transaction (Some journal) readState writeState restoreRuntime ActiveDaemon
            reconcileRecoveryUnits environment
        | Some _ -> fail "A different firewalld host transaction is pending; refusing recovery."
        | None -> ensureNoLegacyPending journal

    let recoverPendingTransaction
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (path: string)
        (phase: RecoveryPhase)
        (readState: JsonObject option -> string option -> string option)
        (writeState: JsonObject option -> string option -> string option -> int -> unit)
        (restoreRuntime: PendingTransaction -> RecoveryPhase -> unit)
        =
        if path <> expectedPath c then fail "Firewalld recovery path does not match its declared object."
        match pending environment with
        | Some transaction when transaction.OwnerId = journalOwner journal && transaction.Configuration.Kind = c.Kind && transaction.Configuration.Name = c.Name ->
            validateIdentity c journal transaction
            if transaction.Status = "confirmed" then finishConfirmed environment transaction (Some journal) readState
            else
                ensureRecoverablePending transaction
                restorePending environment transaction (Some journal) readState writeState restoreRuntime phase
        | _ -> fail "No matching firewalld host transaction is pending recovery."

    let confirm
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (nonce: string)
        (readState: JsonObject option -> string option -> string option)
        =
        match pending environment with
        | None -> fail "No firewalld transaction is awaiting confirmation."
        | Some transaction ->
            validateIdentity c journal transaction
            if transaction.Nonce <> nonce then fail "Firewalld transaction confirmation nonce does not match."
            if transaction.AwaitingPostBoot || transaction.NativeUndo.IsSome then
                fail "Cannot confirm a transaction whose rollback has already begun."
            let current, currentMode = readPath environment transaction.Path
            let currentState = if transaction.SchemaVersion = 1 then current else readState transaction.Scope current
            verifyMetadata environment transaction current currentMode transaction.AfterMode
            if currentState <> transaction.After then
                fail "Firewalld configuration changed before fresh-connection confirmation."
            let committed =
                if transaction.Status = "confirmed" then transaction
                else
                    let value = { transaction with Status = "confirmed" }
                    savePending environment value
                    value
            finishConfirmed environment committed (Some journal) readState
            reconcileRecoveryUnits environment


    let private recoverPendingAt
        (environment: HostEnvironment)
        (phase: RecoveryPhase)
        (recover: PendingTransaction -> JsonObject option -> unit)
        =
        let path = logicalPath environment lockPath
        use _lock = HostFiles.lockFile path
        match pending environment with
        | None ->
            ensureNoOrphanedOwnerPending environment
            if phase <> BootBeforeFirewalld then reconcileRecoveryUnits environment
        | Some current ->
            ensureRecoverablePending current
            let journal =
                match getJournalText environment (journalPath current.Configuration) with
                | Some text -> Some(JsonNode.Parse(text).AsObject())
                | None -> None
            recover current journal
            match pending environment with
            | None when phase <> BootBeforeFirewalld -> reconcileRecoveryUnits environment
            | Some waiting when phase = BootBeforeFirewalld && waiting.AwaitingPostBoot -> ()
            | _ -> ()

    let recoverPending
        (environment: HostEnvironment)
        (recover: PendingTransaction -> JsonObject option -> unit)
        =
        recoverPendingAt environment ActiveDaemon recover

    let recoverPendingBoot
        (environment: HostEnvironment)
        (recover: PendingTransaction -> JsonObject option -> unit)
        =
        match pending environment with
        | None -> ensureNoOrphanedOwnerPending environment
        | Some _ -> recoverPendingAt environment BootBeforeFirewalld recover

    let recoverPendingPostBoot
        (environment: HostEnvironment)
        (recover: PendingTransaction -> JsonObject option -> unit)
        =
        recoverPendingAt environment BootAfterFirewalld recover
