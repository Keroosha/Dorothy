namespace Dorothy.HostHelper

open System
open System.IO
open System.Text
open System.Text.Json.Nodes
open System.Text.RegularExpressions

module FirewalldLifecycle =
    type PendingTransaction =
        { Nonce: string
          OwnerId: string
          Configuration: FirewalldModel.Configuration
          Path: string
          Before: string option
          BeforeMode: int
          After: string option
          AfterMode: int
          ManagedBefore: string option
          ManagedAfter: string option
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
    let private bootServiceName = "keroosha-iac-firewalld-boot-recovery.service"
    let private ownerMarker = "# Dorothy firewalld transaction recovery"
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

    let private regularPath (environment: HostEnvironment) logical =
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

    let private setOptionalString (node: JsonObject) (key: string) (value: string option) =
        node[key] <- match value with None -> null | Some text -> JsonValue.Create text :> JsonNode

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

    let private pendingNode (pending: PendingTransaction) =
        let node = JsonObject()
        node["version"] <- JsonValue.Create 1
        node["nonce"] <- JsonValue.Create pending.Nonce
        node["ownerId"] <- JsonValue.Create pending.OwnerId
        node["configuration"] <- JsonValue.Create(FirewalldModel.toJson pending.Configuration)
        node["path"] <- JsonValue.Create pending.Path
        setOptionalString node "before" pending.Before
        node["beforeMode"] <- JsonValue.Create pending.BeforeMode
        setOptionalString node "after" pending.After
        node["afterMode"] <- JsonValue.Create pending.AfterMode
        setOptionalString node "managedBefore" pending.ManagedBefore
        setOptionalString node "managedAfter" pending.ManagedAfter
        node["releaseOnRollback"] <- JsonValue.Create pending.ReleaseOnRollback
        node["deleteOnConfirm"] <- JsonValue.Create pending.DeleteOnConfirm
        node["status"] <- JsonValue.Create pending.Status
        node

    let private parsePendingNode (node: JsonObject) =
        let expected = set [ "version"; "nonce"; "ownerId"; "configuration"; "path"; "before"; "beforeMode"; "after"; "afterMode"; "managedBefore"; "managedAfter"; "releaseOnRollback"; "deleteOnConfirm"; "status" ]
        let actual = node |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        if actual <> expected || getInt node "version" <> 1 then fail "Invalid firewalld transaction record."
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
        { Nonce = nonce
          OwnerId = owner
          Configuration = c
          Path = path
          Before = getOptionalString node "before"
          BeforeMode = beforeMode
          After = getOptionalString node "after"
          AfterMode = afterMode
          ManagedBefore = getOptionalString node "managedBefore"
          ManagedAfter = getOptionalString node "managedAfter"
          ReleaseOnRollback = getBool node "releaseOnRollback"
          DeleteOnConfirm = getBool node "deleteOnConfirm"
          Status = status }

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

    let private finishConfirmed (environment: HostEnvironment) (transaction: PendingTransaction) (journal: JsonObject option) =
        let current, currentMode = readPath environment transaction.Path
        if current <> transaction.After || (transaction.After.IsSome && currentMode <> transaction.AfterMode) then
            fail "Confirmed firewalld configuration changed before transaction finalization."
        match journal with
        | Some value ->
            if transaction.DeleteOnConfirm then removeJournal environment transaction.Configuration transaction.OwnerId
            else
                updateManaged value transaction.ManagedAfter transaction.AfterMode
                clearJournalPending value
                if value.ContainsKey "deleteOnConfirm" then value.Remove "deleteOnConfirm" |> ignore
                saveJournal environment transaction.Configuration value
        | None ->
            if not transaction.DeleteOnConfirm then fail "Confirmed firewalld owner journal is missing."
        clearPending environment

    let private restorePending
        (environment: HostEnvironment)
        (transaction: PendingTransaction)
        (journal: JsonObject option)
        (write: string option -> int -> unit)
        (activate: unit -> unit)
        =
        let current, currentMode = readPath environment transaction.Path
        if current <> transaction.Before && current <> transaction.After then
            fail "Firewalld configuration changed during an interrupted transaction; refusing recovery."
        if transaction.Before.IsSome && current = transaction.Before && currentMode <> transaction.BeforeMode then
            fail "Firewalld configuration mode changed during interrupted transaction; refusing recovery."
        if transaction.After.IsSome && current = transaction.After && currentMode <> transaction.AfterMode then
            fail "Firewalld configuration mode changed during interrupted transaction; refusing recovery."
        if transaction.Before <> transaction.After || (transaction.Before.IsSome && transaction.BeforeMode <> transaction.AfterMode) then
            write transaction.Before transaction.BeforeMode
            activate ()
        match journal with
        | Some value ->
            if transaction.ReleaseOnRollback then removeJournal environment transaction.Configuration transaction.OwnerId
            else
                updateManaged value transaction.ManagedBefore transaction.BeforeMode
                clearJournalPending value
                if value.ContainsKey "deleteOnConfirm" then value.Remove "deleteOnConfirm" |> ignore
                saveJournal environment transaction.Configuration value
        | None ->
            if not transaction.ReleaseOnRollback then fail "Firewalld owner journal is missing during recovery."
        clearPending environment

    let private readLegacyPending (journal: JsonObject) =
        match journal["pending"] with
        | null -> None
        | :? JsonObject as pending ->
            if pending.ContainsKey "nonce" then None
            else
                let keys = pending |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
                if keys <> set [ "before"; "after" ] && keys <> set [ "before"; "after"; "beforeMode"; "afterMode" ] then
                    fail "Invalid legacy firewalld pending transaction."
                let mode key = if pending.ContainsKey key then Some(getInt pending key) else None
                Some(getOptionalString pending "before", getOptionalString pending "after", mode "beforeMode")
        | _ -> fail "Invalid firewalld pending transaction."


    let private createRecoveryUnits (environment: HostEnvironment) =
        let helper = Environment.ProcessPath
        if String.IsNullOrWhiteSpace helper || not (Path.IsPathRooted helper) || helper |> Seq.exists (fun c -> Char.IsControl c || Char.IsWhiteSpace c) then
            fail "Cannot arm firewalld rollback without a canonical native helper executable path."
        let serviceText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld transaction rollback"; "DefaultDependencies=no"; "After=local-fs.target"; "[Service]"; "Type=oneshot"; "ExecStart=" + helper + " firewalld-recover"; "" ]
        let bootServiceText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld boot recovery"; "DefaultDependencies=no"; "After=local-fs.target"; "Before=firewalld.service"; "[Service]"; "Type=oneshot"; "ExecStart=" + helper + " firewalld-recover-boot"; "[Install]"; "WantedBy=multi-user.target"; "" ]
        let timerText =
            String.concat "\n"
                [ ownerMarker; "[Unit]"; "Description=Dorothy firewalld transaction rollback watchdog"; "[Timer]"; "OnActiveSec=2min"; "Unit=" + serviceName; "[Install]"; "WantedBy=timers.target"; "" ]
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
        let writeOwned (logical: string) (text: string) =
            let physical = regularPath environment logical
            let expected = strictUtf8.GetBytes(text)
            let currentBytes =
                if File.Exists physical then
                    let owner = run environment "stat" [ "-c"; "%u:%g"; "--"; physical ]
                    if owner <> "0:0" || File.GetUnixFileMode physical <> fileMode then
                        fail "A firewalld recovery systemd unit is not root-owned mode 0644."
                    let bytes = File.ReadAllBytes physical
                    let current = strictUtf8.GetString bytes
                    if not (matchesOwnedUnit text current) then
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
        validateEnableLink ("/etc/systemd/system/timers.target.wants/" + timerName) timerPath
        ensureDirectory environment "/etc/systemd/system" (int unitDirectoryMode) |> ignore
        writeOwned servicePath serviceText
        writeOwned bootServicePath bootServiceText
        writeOwned timerPath timerText
        run environment "/usr/bin/systemctl" [ "daemon-reload" ] |> ignore
        run environment "/usr/bin/systemctl" [ "enable"; bootServiceName ] |> ignore
        run environment "/usr/bin/systemctl" [ "enable"; "--now"; timerName ] |> ignore
        run environment "/usr/bin/systemctl" [ "restart"; timerName ] |> ignore

    let private makeTransaction
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (releaseOnRollback: bool)
        (path: string)
        (before: string option)
        (beforeMode: int)
        (after: string option)
        (afterMode: int)
        =
        if path <> expectedPath c then fail "Firewalld transaction path does not match its declared object."
        let owner = journalOwner journal
        let nonce = Guid.NewGuid().ToString("N")
        let managedBefore = getOptionalString journal "managed"
        let managedAfter = after
        { Nonce = nonce
          OwnerId = owner
          Configuration = c
          Path = path
          Before = before
          BeforeMode = beforeMode
          After = after
          AfterMode = afterMode
          ManagedBefore = managedBefore
          ManagedAfter = managedAfter
          ReleaseOnRollback = releaseOnRollback
          DeleteOnConfirm =
            match journal["deleteOnConfirm"] with
            | null -> false
            | value -> value.GetValue<bool>()
          Status = "pending" }

    let transact
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (releaseOnRollback: bool)
        (path: string)
        (before: string option)
        (beforeMode: int)
        (after: string option)
        (afterMode: int)
        (managedBefore: string option)
        (managedAfter: string option)
        (write: string option -> int -> unit)
        (validate: string option -> unit)
        (activate: unit -> unit)
        : string =
        match pending environment with
        | Some _ -> fail "Another firewalld transaction is awaiting confirmation or recovery."
        | None -> ()
        validate after
        let actual, actualMode = readPath environment path
        if actual <> before || (before.IsSome && actualMode <> beforeMode) then
            fail "Firewalld configuration changed before transaction staging."
        if managedBefore <> getOptionalString journal "managed" then
            fail "Firewalld managed configuration changed before transaction staging."
        if not (journal.ContainsKey "baselineMode") || isNull journal["baselineMode"] then
            match getOptionalString journal "baseline", c.Kind, releaseOnRollback with
            | Some _, ("zone" | "policy" | "service" | "ipset" | "icmptype" | "helper"), false -> ()
            | _ -> journal["baselineMode"] <- JsonValue.Create beforeMode
        let managedMode =
            if journal.ContainsKey "managedMode" && not (isNull journal["managedMode"]) then
                getInt journal "managedMode"
            elif c.Kind = "settings" then beforeMode
            else
                if before.IsSome && not (List.contains beforeMode [ 0o600; 0o640; 0o644 ]) then
                    fail "Managed firewalld object mode is unsafe; refusing to replace it."
                beforeMode
        if before.IsSome && managedMode <> beforeMode then
            fail "Managed firewalld file mode changed independently; refusing to overwrite it."
        journal["managedMode"] <- JsonValue.Create managedMode
        let transaction = makeTransaction environment c journal releaseOnRollback path before beforeMode after afterMode
        let transaction = { transaction with ManagedBefore = managedBefore; ManagedAfter = managedAfter }
        writeJournalPending journal transaction
        saveJournal environment c journal
        try
            savePending environment transaction
        with error ->
            clearJournalPending journal
            if journal.ContainsKey "deleteOnConfirm" then journal.Remove "deleteOnConfirm" |> ignore
            if releaseOnRollback then removeJournal environment c transaction.OwnerId else saveJournal environment c journal
            fail ("Could not persist firewalld recovery state before mutation: " + diagnostic error.Message)
        try
            createRecoveryUnits environment
        with error ->
            clearJournalPending journal
            if journal.ContainsKey "deleteOnConfirm" then journal.Remove "deleteOnConfirm" |> ignore
            if releaseOnRollback then removeJournal environment c transaction.OwnerId else saveJournal environment c journal
            clearPending environment
            fail ("Could not arm independent firewalld recovery before mutation: " + diagnostic error.Message)
        try
            if before <> after || (before.IsSome && beforeMode <> afterMode) then
                write after afterMode
            activate ()
        with originalError ->
            try
                restorePending environment transaction (Some journal) write activate
            with rollbackError ->
                fail ("Firewalld apply failed: " + diagnostic originalError.Message + "; rollback failed: " + diagnostic rollbackError.Message + "; journal retained for independent recovery.")
            fail ("Firewalld apply failed; original permanent configuration restored and reloaded: " + diagnostic originalError.Message)
        transaction.Nonce

    let recover
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (path: string)
        (write: string option -> int -> unit)
        (validate: string option -> unit)
        (activate: unit -> unit)
        =
        if path <> expectedPath c then fail "Firewalld recovery path does not match its declared object."
        match pending environment with
        | Some transaction when transaction.OwnerId = journalOwner journal && transaction.Configuration.Kind = c.Kind && transaction.Configuration.Name = c.Name ->
            validateIdentity c journal transaction
            if transaction.Status = "confirmed" then finishConfirmed environment transaction (Some journal)
            else fail "A firewalld transaction is awaiting its fresh-connection confirmation; refusing to take it over."
        | Some _ ->
            match readLegacyPending journal with
            | None -> ()
            | Some _ -> fail "A different firewalld host transaction is pending; refusing concurrent recovery."
        | None ->
            match readLegacyPending journal with
            | None -> ()
            | Some(before, after, recordedBeforeMode) ->
                let current, _ = readPath environment path
                if current <> before && current <> after then
                    fail "Firewalld configuration changed during an interrupted transaction; refusing recovery."
                let beforeMode =
                    match recordedBeforeMode, before with
                    | Some mode, _ -> mode
                    | None, None -> 0o644
                    | None, Some _ -> fail "Legacy firewalld transaction lacks the original file mode; refusing an inexact recovery."
                if not (String.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable "SSH_CONNECTION")) then
                    validate before
                write before beforeMode
                activate ()
                updateManaged journal before beforeMode
                clearJournalPending journal
                saveJournal environment c journal
    let recoverPendingTransaction
        (environment: HostEnvironment)
        (c: FirewalldModel.Configuration)
        (journal: JsonObject)
        (path: string)
        (write: string option -> int -> unit)
        (activate: unit -> unit)
        =
        if path <> expectedPath c then fail "Firewalld recovery path does not match its declared object."
        match pending environment with
        | Some transaction when transaction.OwnerId = journalOwner journal && transaction.Configuration.Kind = c.Kind && transaction.Configuration.Name = c.Name ->
            validateIdentity c journal transaction
            if transaction.Status = "confirmed" then finishConfirmed environment transaction (Some journal)
            else restorePending environment transaction (Some journal) write activate
        | _ -> fail "No matching firewalld host transaction is pending recovery."

    let confirm (environment: HostEnvironment) (c: FirewalldModel.Configuration) (journal: JsonObject) (nonce: string) =
        match pending environment with
        | None -> fail "No firewalld transaction is awaiting confirmation."
        | Some transaction ->
            validateIdentity c journal transaction
            if transaction.Nonce <> nonce then fail "Firewalld transaction confirmation nonce does not match."
            if transaction.Status <> "pending" then fail "Firewalld transaction has already been confirmed."
            let current, currentMode = readPath environment transaction.Path
            if current <> transaction.After || (transaction.After.IsSome && currentMode <> transaction.AfterMode) then
                fail "Firewalld configuration changed before fresh-connection confirmation."
            let committed = { transaction with Status = "confirmed" }
            savePending environment committed
            finishConfirmed environment committed (Some journal)

    let recoverPending
        (environment: HostEnvironment)
        (recover: PendingTransaction -> JsonObject option -> unit)
        =
        match pending environment with
        | None -> ()
        | Some _ ->
            let path = logicalPath environment lockPath
            use _lock = HostFiles.lockFile path
            match pending environment with
            | None -> ()
            | Some current ->
                let journal =
                    match getJournalText environment (journalPath current.Configuration) with
                    | Some text -> Some(JsonNode.Parse(text).AsObject())
                    | None -> None
                recover current journal
