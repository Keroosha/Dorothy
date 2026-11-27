namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open Pulumi.Experimental
open Pulumi.Experimental.Provider

open System.IO
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Runtime.InteropServices

module internal FirewalldCreateReceipts =
    type Receipt =
        { Ticket: string
          Urn: string
          Token: string
          OwnerId: string
          Address: string
          User: string
          Port: int
          IdentityFile: string option
          Configuration: string }

    let private ticketPrefix = "fw-recover:"
    let private directoryMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
    let private fileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpenDirectory (string path, int flags)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int private nativeClose (int fileDescriptor)

    let private envValue name =
        match Environment.GetEnvironmentVariable name with null -> "" | value -> value

    let private homePath () =
        let configured = envValue "PULUMI_HOME"
        let home =
            if String.IsNullOrWhiteSpace configured then
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pulumi")
            else configured
        if String.IsNullOrWhiteSpace home || not (Path.IsPathRooted home) then
            invalidOp "Firewalld recovery receipts require an absolute PULUMI_HOME."
        let fullPath = Path.GetFullPath home
        if Directory.Exists fullPath && File.GetAttributes(fullPath).HasFlag FileAttributes.ReparsePoint then
            match DirectoryInfo(fullPath).ResolveLinkTarget(true) with
            | null -> invalidOp "PULUMI_HOME is a dangling symlink."
            | target -> Path.GetFullPath target.FullName
        elif not (isNull (FileInfo(fullPath).LinkTarget)) then
            invalidOp "PULUMI_HOME is a dangling symlink."
        else fullPath

    let private verifyDirectory privateToUser (path: string) =
        if File.GetAttributes(path).HasFlag FileAttributes.ReparsePoint then
            invalidOp "Firewalld recovery receipt directories must not be symlinks."
        if not (OperatingSystem.IsWindows()) then
            let mode = File.GetUnixFileMode path
            let foreignWrite = UnixFileMode.GroupWrite ||| UnixFileMode.OtherWrite
            if (mode &&& foreignWrite) <> enum<UnixFileMode> 0 || (privateToUser && mode <> directoryMode) then
                invalidOp "Unsafe permissions on Firewalld recovery receipt directory."

    let private ensureDirectory privateToUser path =
        if not (Directory.Exists path) then
            if OperatingSystem.IsWindows() then Directory.CreateDirectory(path: string) |> ignore
            else Directory.CreateDirectory(path, directoryMode) |> ignore
        verifyDirectory privateToUser path

    let private receiptDirectory () =
        let home = homePath ()
        let parent = Path.Combine(home, "keroosha-iac")
        ensureDirectory false parent
        let directory = Path.Combine(parent, "firewalld")
        ensureDirectory true directory
        directory

    let private existingReceiptDirectory () =
        let parent = Path.Combine(homePath (), "keroosha-iac")
        let directory = Path.Combine(parent, "firewalld")
        if Directory.Exists directory then
            verifyDirectory false parent
            verifyDirectory true directory
            Some directory
        else None

    let private receiptPath directory ticket = Path.Combine(directory, ticket + ".json")

    let private validTicket (ticket: string) =
        not (isNull ticket) && ticket.Length = 32
        && (ticket |> Seq.forall (fun c -> Char.IsAsciiDigit c || (c >= 'a' && c <= 'f')))

    let private getString (node: JsonObject) (key: string) =
        match node[key] with null -> invalidOp "Invalid firewalld recovery receipt." | value -> value.GetValue<string>()

    let private getOptionalString (node: JsonObject) (key: string) =
        if not (node.ContainsKey key) then invalidOp "Invalid firewalld recovery receipt."
        match node[key] with null -> None | value -> Some(value.GetValue<string>())

    let private toNode receipt =
        let node = JsonObject()
        node["version"] <- JsonValue.Create 1
        node["ticket"] <- JsonValue.Create receipt.Ticket
        node["urn"] <- JsonValue.Create receipt.Urn
        node["token"] <- JsonValue.Create receipt.Token
        node["ownerId"] <- JsonValue.Create receipt.OwnerId
        node["address"] <- JsonValue.Create receipt.Address
        node["user"] <- JsonValue.Create receipt.User
        node["port"] <- JsonValue.Create receipt.Port
        node["identityFile"] <- match receipt.IdentityFile with None -> null | Some value -> JsonValue.Create value :> JsonNode
        node["configuration"] <- JsonValue.Create receipt.Configuration
        node

    let private parseReceipt ticket (node: JsonObject) =
        let expected = set [ "version"; "ticket"; "urn"; "token"; "ownerId"; "address"; "user"; "port"; "identityFile"; "configuration" ]
        let actual = node |> Seq.map (fun pair -> pair.Key) |> Set.ofSeq
        if actual <> expected || node["version"].GetValue<int>() <> 1 || not (validTicket ticket) then
            invalidOp "Invalid firewalld recovery receipt."
        let storedTicket = getString node "ticket"
        let urn = getString node "urn"
        let address = getString node "address"
        let ownerId = getString node "ownerId"
        let port = node["port"].GetValue<int>()
        if storedTicket <> ticket
           || String.IsNullOrWhiteSpace urn
           || String.IsNullOrWhiteSpace address
           || ownerId <> urn + "::" + address + "::" + ticket
           || port < 1
           || port > 65535 then
            invalidOp "Invalid firewalld recovery receipt identity."
        { Ticket = storedTicket
          Urn = urn
          Token = getString node "token"
          OwnerId = ownerId
          Address = address
          User = getString node "user"
          Port = port
          IdentityFile = getOptionalString node "identityFile"
          Configuration = getString node "configuration" }

    let private readReceipt (directory: string) ticket =
        if not (validTicket ticket) then invalidOp "Invalid firewalld recovery receipt identifier."
        let path = receiptPath directory ticket
        if not (File.Exists path) || File.GetAttributes(path).HasFlag FileAttributes.ReparsePoint then
            invalidOp "Firewalld recovery receipt was not found."
        if not (OperatingSystem.IsWindows()) && File.GetUnixFileMode path <> fileMode then
            invalidOp "Firewalld recovery receipt must have mode 0600."
        match JsonNode.Parse(File.ReadAllText(path, Encoding.UTF8)) with
        | :? JsonObject as node -> parseReceipt ticket node
        | _ -> invalidOp "Invalid firewalld recovery receipt."

    let private syncDirectory (directory: string) =
        if OperatingSystem.IsLinux() then
            let descriptor = nativeOpenDirectory(directory, 0x10000 ||| 0x80000)
            if descriptor < 0 then invalidOp "Could not open the Firewalld recovery receipt directory for sync."
            try
                if nativeFsync descriptor <> 0 then invalidOp "Could not durably sync the Firewalld recovery receipt directory."
            finally
                nativeClose descriptor |> ignore

    let private atomicCreate (directory: string) (receipt: Receipt) =
        let destination = receiptPath directory receipt.Ticket
        let temporary = Path.Combine(directory, "." + Guid.NewGuid().ToString("N") + ".tmp")
        let options = FileStreamOptions()
        options.Mode <- FileMode.CreateNew
        options.Access <- FileAccess.Write
        options.Share <- FileShare.None
        options.Options <- FileOptions.WriteThrough
        if not (OperatingSystem.IsWindows()) then
            options.UnixCreateMode <- Nullable<UnixFileMode>(fileMode)
        try
            do
                use output = new FileStream(temporary, options)
                let bytes = Encoding.UTF8.GetBytes((toNode receipt).ToJsonString())
                output.Write(bytes, 0, bytes.Length)
                output.Flush(true)
            // The ticket is freshly random, so replacement would hide a generation collision.
            File.Move(temporary, destination)
            syncDirectory directory
        finally
            if File.Exists temporary then File.Delete temporary

    let create (urn: Pulumi.Urn) token (connection: SshConnection) configuration =
        let parsed = FirewalldModel.parse configuration
        let directory = receiptDirectory ()
        let ticket = Guid.NewGuid().ToString("N")
        let receipt =
            { Ticket = ticket
              Urn = urn.ToString()
              Token = token
              OwnerId = urn.ToString() + "::" + connection.Address + "::" + ticket
              Address = connection.Address
              User = connection.User
              Port = connection.Port
              IdentityFile = connection.IdentityFile
              Configuration = FirewalldModel.toJson parsed }
        atomicCreate directory receipt
        receipt

    let private ticketFromOwnerId (ownerId: string) =
        if isNull ownerId then None
        else
            let separator = ownerId.LastIndexOf("::", StringComparison.Ordinal)
            if separator < 0 then None
            else
                let ticket = ownerId.Substring(separator + 2)
                if validTicket ticket then Some ticket else None

    let acknowledgeOwner (urn: Pulumi.Urn) token ownerId =
        // Retiring a local receipt is optional. Its cleanup must not invalidate
        // a completed host mutation or an observation of the checkpointed ID.
        match ticketFromOwnerId ownerId with
        | None -> ()
        | Some ticket ->
            try
                match existingReceiptDirectory () with
                | Some directory ->
                    let path = receiptPath directory ticket
                    if File.Exists path then
                        let receipt = readReceipt directory ticket
                        if receipt.OwnerId = ownerId && receipt.Urn = urn.ToString() && receipt.Token = token then
                            File.Delete path
                            syncDirectory directory
                | None -> ()
            with
            | :? IOException | :? UnauthorizedAccessException | :? InvalidOperationException | :? JsonException ->
                Console.Error.WriteLine("Unable to retire the local firewalld recovery receipt; review it before manual removal.")

    let isRecoveryTicket (id: string) =
        not (isNull id) && id.StartsWith(ticketPrefix, StringComparison.Ordinal)

    let readTicket (urn: Pulumi.Urn) token (id: string) =
        if not (isRecoveryTicket id) then invalidOp "Invalid Firewalld recovery import identifier."
        let ticket = id.Substring(ticketPrefix.Length)
        let directory = existingReceiptDirectory () |> Option.defaultWith (fun () -> invalidOp "Firewalld recovery receipt was not found.")
        let receipt = readReceipt directory ticket
        if receipt.Urn <> urn.ToString()
           || receipt.Token <> token
           || receipt.OwnerId <> urn.ToString() + "::" + receipt.Address + "::" + ticket then
            invalidOp "Firewalld recovery receipt does not match this resource generation."
        receipt

    let importId (receipt: Receipt) = ticketPrefix + receipt.Ticket
    let private safeFailureSummary (receipt: Receipt) (error: exn) =
        let sensitive =
            [ receipt.Urn
              receipt.Address
              receipt.User
              string receipt.Port
              receipt.Configuration
              receipt.OwnerId
              receipt.Ticket ]
            @ (receipt.IdentityFile |> Option.toList |> List.collect (fun path -> [ path; path + ".pub"; path + "-cert.pub" ]))
        let mutable message = error.Message
        for value in sensitive do
            if not (String.IsNullOrWhiteSpace value) then
                message <- message.Replace(value, "[redacted]", StringComparison.Ordinal)
        message <-
            System.Text.RegularExpressions.Regex.Replace(
                message,
                "-----BEGIN [^-]*-----[\\s\\S]*?-----END [^-]*-----",
                "[key material redacted]"
            )
        message <- System.Text.RegularExpressions.Regex.Replace(message, "SHA256:[A-Za-z0-9+/=]+", "SHA256:[redacted]")
        let sanitized =
            message
            |> Seq.map (fun character -> if Char.IsControl character then ' ' else character)
            |> Array.ofSeq
            |> fun characters -> String(characters)
        if String.IsNullOrWhiteSpace sanitized then error.GetType().Name
        elif sanitized.Length <= 512 then sanitized
        else sanitized.Substring(0, 512)

    let recoveryFailureMessage (receipt: Receipt) (error: exn) =
        let recoveryTicket = importId receipt
        "Firewalld Create failed (" + safeFailureSummary receipt error + "); the remote outcome may be ambiguous. "
        + "Recovery ticket: " + recoveryTicket
        + ". Recover only with `pulumi import --protect=false <type> <resource-name> " + recoveryTicket + "`."

    let pathForTicket ticket = Path.Combine(receiptDirectory (), ticket + ".json")

module private FirewalldProviderLogic =
    let zoneToken = "keroosha:debian:FirewalldZone"
    let policyToken = "keroosha:debian:FirewalldPolicy"
    let settingsToken = "keroosha:debian:FirewalldSettings"
    let private resourceKinds =
        Map.ofList [
            zoneToken, "zone"; policyToken, "policy"; settingsToken, "settings"
            "keroosha:debian:FirewalldService", "service"; "keroosha:debian:FirewalldIPSet", "ipset"
            "keroosha:debian:FirewalldIcmpType", "icmptype"; "keroosha:debian:FirewalldHelper", "helper"
        ]
    let handles token = Map.containsKey token resourceKinds
    let kind token =
        Map.tryFind token resourceKinds |> Option.defaultWith (fun () -> invalidOp "Unexpected firewalld resource token.")


    let schema =
        let resource = """{"inputProperties":{"connection":{"$ref":"#/types/keroosha:debian:SshConnection"},"configuration":{"type":"string"}},"requiredInputs":["connection","configuration"],"properties":{"connection":{"$ref":"#/types/keroosha:debian:SshConnection"},"configuration":{"type":"string"},"exists":{"type":"boolean"},"actual":{"type":"string"},"inSync":{"type":"boolean"},"permanentInSync":{"type":"boolean"},"runtimeObserved":{"type":"boolean"},"runtimeInSync":{"type":"boolean"}},"required":["connection","configuration","exists","actual","inSync","permanentInSync","runtimeObserved","runtimeInSync"]}"""
        let resources = resourceKinds.Keys |> Seq.map (fun token -> "\"" + token + "\":" + resource) |> String.concat ","
        "{\"name\":\"keroosha\",\"version\":\"0.1.0\",\"resources\":{" + resources + "}}"

    let private tryGetMap (value: PropertyValue) =
        let mutable result = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&result) then Some result else None

    let private tryGetArray (value: PropertyValue) =
        let mutable result = ImmutableArray<PropertyValue>.Empty
        if value.TryGetArray(&result) then Some result else None

    let private tryGetString (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>
        if value.TryGetString(&result) then Some result else None

    let private tryGetBool (value: PropertyValue) =
        let mutable result = false
        if value.TryGetBool(&result) then Some result else None

    let rec private containsSecret (value: PropertyValue) =
        if value.IsSecret then
            true
        else
            match tryGetMap value with
            | Some values -> values.Values |> Seq.exists containsSecret
            | None ->
                match tryGetArray value with
                | Some values -> values |> Seq.exists containsSecret
                | None -> false

    let rec private containsUnknown (value: PropertyValue) =
        if value.IsComputed then
            true
        else
            match tryGetMap value with
            | Some values -> values.Values |> Seq.exists containsUnknown
            | None ->
                match tryGetArray value with
                | Some values -> values |> Seq.exists containsUnknown
                | None -> false

    let private hasUnknownInputs (values: ImmutableDictionary<string, PropertyValue>) =
        values.Values |> Seq.exists containsUnknown

    let private addFailure (failures: ResizeArray<CheckFailure>) property reason =
        failures.Add(CheckFailure(property, reason))

    let private withDependencies (source: PropertyValue) (replacement: PropertyValue) =
        replacement.WithDependencies(source.Dependencies)

    let private buildMap (values: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in values do
            builder[key] <- value
        builder.ToImmutable()

    let private makeMapValue (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) =
        withDependencies source (PropertyValue(values))

    let private inputDictionary (values: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in values do
            result.Add(entry.Key, entry.Value)
        result

    let private hasInvalidCharacter (value: string) =
        value |> Seq.exists (fun character -> Char.IsControl character || Char.IsWhiteSpace character)

    let private normalizeConnection
        (source: PropertyValue)
        (values: ImmutableDictionary<string, PropertyValue>)
        (failures: ResizeArray<CheckFailure>)
        =
        let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in values do
            normalized[entry.Key] <- entry.Value

        for entry in values do
            if entry.Key <> "address" && entry.Key <> "user" && entry.Key <> "port" && entry.Key <> "identityFile" then
                addFailure failures ("connection." + entry.Key) "This connection property is not supported."

        let mutable hasUnknown = false
        let normalizeRequiredString name validate reason =
            match values.TryGetValue(name) with
            | false, _ -> addFailure failures ("connection." + name) "This property is required."
            | true, value when value.IsComputed ->
                hasUnknown <- true
                normalized[name] <- value
            | true, value ->
                match tryGetString value with
                | None -> addFailure failures ("connection." + name) "Expected a string."
                | Some text ->
                    let canonical = text.Trim()
                    if String.IsNullOrWhiteSpace canonical || not (validate canonical) then
                        addFailure failures ("connection." + name) reason
                    else
                        normalized[name] <- withDependencies value (PropertyValue(canonical))

        normalizeRequiredString
            "address"
            (fun text -> not (text.StartsWith("-", StringComparison.Ordinal)) && not (text.Contains('@')) && not (hasInvalidCharacter text))
            "Expected a non-empty SSH host address without whitespace or '@'."
        normalizeRequiredString
            "user"
            (fun text -> not (text.StartsWith("-", StringComparison.Ordinal)) && not (text.Contains('/')) && not (text.Contains('@')) && not (hasInvalidCharacter text))
            "Expected a non-empty SSH user without whitespace, '/', or '@'."

        match values.TryGetValue("port") with
        | false, _ -> normalized["port"] <- PropertyValue(22.0)
        | true, value when value.IsComputed ->
            hasUnknown <- true
            normalized["port"] <- value
        | true, value when value.IsNull -> normalized["port"] <- PropertyValue(22.0)
        | true, value ->
            let mutable number = 0.0
            if not (value.TryGetNumber(&number)) || Double.IsNaN number || Double.IsInfinity number || number <> Math.Truncate number || number < 1.0 || number > 65535.0 then
                addFailure failures "connection.port" "Expected an integer SSH port from 1 through 65535."
            else
                normalized["port"] <- withDependencies value (PropertyValue(number))

        match values.TryGetValue("identityFile") with
        | false, _ -> ()
        | true, value when value.IsComputed ->
            hasUnknown <- true
            normalized["identityFile"] <- value
        | true, value when value.IsNull -> normalized.Remove("identityFile") |> ignore
        | true, value ->
            match tryGetString value with
            | None -> addFailure failures "connection.identityFile" "Expected a string when identityFile is provided."
            | Some path when String.IsNullOrWhiteSpace path -> normalized.Remove("identityFile") |> ignore
            | Some path when path |> Seq.exists Char.IsControl -> addFailure failures "connection.identityFile" "identityFile must not contain control characters."
            | Some path -> normalized["identityFile"] <- value

        hasUnknown, makeMapValue source (buildMap (normalized |> Seq.map (fun entry -> entry.Key, entry.Value)))

    let normalize token (values: ImmutableDictionary<string, PropertyValue>) =
        let expectedKind = kind token
        let normalized = inputDictionary values
        let failures = ResizeArray<CheckFailure>()
        let mutable unknown = hasUnknownInputs values
        for entry in values do
            if entry.Key <> "connection" && entry.Key <> "configuration" then
                addFailure failures entry.Key "Unsupported firewalld input."
            if containsSecret entry.Value then
                addFailure failures entry.Key "Firewalld inputs contain no secrets; secret values are not accepted."
        match values.TryGetValue "connection" with
        | false, _ -> addFailure failures "connection" "Required."
        | true, value when value.IsComputed -> ()
        | true, value ->
            match tryGetMap value with
            | None -> addFailure failures "connection" "Expected SSH connection object."
            | Some fields ->
                let pending, connection = normalizeConnection value fields failures
                unknown <- unknown || pending
                normalized["connection"] <- connection
        match values.TryGetValue "configuration" with
        | false, _ -> addFailure failures "configuration" "Required."
        | true, value when value.IsComputed -> ()
        | true, value ->
            match tryGetString value with
            | None -> addFailure failures "configuration" "Expected firewalld configuration JSON."
            | Some text ->
                try
                    let c = FirewalldModel.parse text
                    if c.Kind <> expectedKind then invalidArg "configuration" "Configuration kind differs from resource token."
                    normalized["configuration"] <- withDependencies value (PropertyValue(FirewalldModel.toJson c))
                with
                | :? ArgumentException as error -> addFailure failures "configuration" error.Message
                | :? System.Text.Json.JsonException -> addFailure failures "configuration" "Expected valid firewalld configuration JSON."
        normalized, unknown, failures

    let immutable (values: Dictionary<string, PropertyValue>) =
        ImmutableDictionary.CreateRange(values |> Seq.map (fun p -> KeyValuePair(p.Key, p.Value)))

    let receiptInputs (receipt: FirewalldCreateReceipts.Receipt) =
        let connectionFields = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        connectionFields["address"] <- PropertyValue receipt.Address
        connectionFields["user"] <- PropertyValue receipt.User
        connectionFields["port"] <- PropertyValue(float receipt.Port)
        receipt.IdentityFile |> Option.iter (fun path -> connectionFields["identityFile"] <- PropertyValue path)
        let values = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        values["connection"] <- PropertyValue(immutable connectionFields)
        values["configuration"] <- PropertyValue receipt.Configuration
        immutable values

    let requireValid (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            invalidOp (failures |> Seq.map (fun f -> f.Property + ": " + f.Reason) |> String.concat " ")

    let private connectionValue (value: PropertyValue) =
        let fields = tryGetMap value |> Option.get
        let text key = tryGetString fields[key] |> Option.get
        let mutable port = 0.0
        fields["port"].TryGetNumber(&port) |> ignore
        { Address = text "address"; User = text "user"; Port = int port
          IdentityFile = match fields.TryGetValue "identityFile" with true, v -> tryGetString v | _ -> None }

    let parse token values =
        let normalized, unknown, failures = normalize token values
        requireValid failures
        if unknown then invalidOp "Firewalld inputs must be known before applying."
        normalized, connectionValue normalized["connection"], (tryGetString normalized["configuration"] |> Option.get)

    // Diff reads identity from historical state; it never uses historical
    // configuration as authority to write an object. A valid new configuration
    // must be able to replace a spelling rejected by the current native target.
    let private previousForDiff token (values: ImmutableDictionary<string, PropertyValue>) =
        let failures = ResizeArray<CheckFailure>()
        let old = values["connection"]
        let pending, connection = normalizeConnection old (tryGetMap old |> Option.get) failures
        requireValid failures
        if pending then invalidOp "Stored firewalld connection is unknown."
        let raw = tryGetString values["configuration"] |> Option.get
        use doc = System.Text.Json.JsonDocument.Parse raw
        if doc.RootElement.GetProperty("kind").GetString() <> kind token then invalidOp "Stored firewalld kind differs from its resource."
        let name = doc.RootElement.GetProperty("name").GetString()
        let canonical =
            try FirewalldModel.parse raw |> FirewalldModel.toJson
            with :? ArgumentException -> raw
        connectionValue connection, canonical, name

    let stored (preferred: ImmutableDictionary<string, PropertyValue>) (fallback: ImmutableDictionary<string, PropertyValue>) =
        [ "connection"; "configuration" ]
        |> List.choose (fun key ->
            match preferred.TryGetValue key with
            | true, value -> Some(KeyValuePair(key, value))
            | _ -> match fallback.TryGetValue key with true, value -> Some(KeyValuePair(key, value)) | _ -> None)
        |> ImmutableDictionary.CreateRange

    let outputs (values: Dictionary<string, PropertyValue>) (snapshot: FirewalldSnapshot option) =
        let result = Dictionary<string, PropertyValue>(values)
        match snapshot with
        | None ->
            for key in [ "exists"; "actual"; "inSync"; "permanentInSync"; "runtimeObserved"; "runtimeInSync" ] do
                result[key] <- PropertyValue.Computed
        | Some s ->
            result["exists"] <- PropertyValue s.Exists
            result["actual"] <- PropertyValue s.Actual
            result["inSync"] <- PropertyValue s.InSync
            result["permanentInSync"] <- PropertyValue s.PermanentInSync
            result["runtimeObserved"] <- PropertyValue s.RuntimeObserved
            result["runtimeInSync"] <- PropertyValue s.RuntimeInSync
        result

    let preview token values =
        let normalized, _, failures = normalize token values
        requireValid failures
        outputs normalized None

    let owner (urn: Pulumi.Urn) (connection: SshConnection) = urn.ToString() + "::" + connection.Address

    let run timeout ct action =
        task {
            use linked = CancellationTokenSource.CreateLinkedTokenSource(ct: CancellationToken)
            if timeout > TimeSpan.Zero then linked.CancelAfter(timeout: TimeSpan)
            return! action linked.Token
        }

    let diff (request: DiffRequest) =
        let response = DiffResponse()
        let previous = stored request.OldInputs request.OldOutputs
        let _, unknown, failures = normalize request.Type request.NewInputs
        requireValid failures
        if previous.IsEmpty then response.Changes <- Nullable true
        elif unknown || (request.OldOutputs.Values |> Seq.exists containsUnknown) then response.Changes <- Nullable()
        else
            let oldConnection, oldText, oldName = previousForDiff request.Type previous
            let _, newConnection, newText = parse request.Type request.NewInputs
            let newConfig = FirewalldModel.parse newText
            let details = Dictionary<string, PropertyDiff>()
            let diffs, replaces = List<string>(), List<string>()
            let add path replace inputDiff =
                let detail = PropertyDiff()
                detail.Kind <- if replace then PropertyDiffKind.UpdateReplace else PropertyDiffKind.Update
                detail.InputDiff <- inputDiff
                details[path] <- detail
                diffs.Add path
                if replace then replaces.Add path
            if oldConnection.Address <> newConnection.Address then add "connection.address" true true
            if oldConnection.User <> newConnection.User then add "connection.user" false true
            if oldConnection.Port <> newConnection.Port then add "connection.port" false true
            if oldConnection.IdentityFile <> newConnection.IdentityFile then add "connection.identityFile" false true
            if oldText <> newText then add "configuration" (oldName <> newConfig.Name) true
            match request.OldOutputs.TryGetValue "inSync" with
            | true, value ->
                match tryGetBool value with
                | Some false -> add "inSync" false false
                | Some true -> ()
                | _ -> invalidOp "Stored firewalld inSync snapshot is invalid."
            | _ -> invalidOp "Stored firewalld inSync snapshot is missing."
            response.Changes <- Nullable(diffs.Count > 0)
            response.Diffs <- diffs
            response.Replaces <- replaces
            response.DetailedDiff <- details
            // Replacement Create must run while the old guard still owns the object.
            // A same-object replacement is rejected by the helper's existing journal owner check.
            response.DeleteBeforeReplace <- false
        response

/// One resource token per independently owned permanent object kind; one settings instance per daemon key.
[<Sealed>]
type FirewalldProvider() =
    inherit Pulumi.Experimental.Provider.Provider()
    static member ZoneToken = FirewalldProviderLogic.zoneToken
    static member SettingsToken = FirewalldProviderLogic.settingsToken
    static member PolicyToken = FirewalldProviderLogic.policyToken
    static member Handles token = FirewalldProviderLogic.handles token
    static member Schema = FirewalldProviderLogic.schema

    override _.GetSchema(_, ct) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- FirewalldProviderLogic.schema
        Task.FromResult response

    override _.Check(request, ct) =
        ct.ThrowIfCancellationRequested()
        let values, _, failures = FirewalldProviderLogic.normalize request.Type request.NewInputs
        let response = CheckResponse()
        response.Inputs <- values
        response.Failures <- List<CheckFailure>(failures)
        Task.FromResult response

    override _.Diff(request, ct) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(FirewalldProviderLogic.diff request)

    override _.Create(request, ct) =
        ct.ThrowIfCancellationRequested()
        if request.Preview then
            let response = CreateResponse()
            response.Id <- ""
            response.Outputs <- FirewalldProviderLogic.preview request.Type request.Inputs
            Task.FromResult response
        else
            FirewalldProviderLogic.run request.Timeout ct (fun token -> task {
                let values, connection, configuration = FirewalldProviderLogic.parse request.Type request.Inputs
                let receipt = FirewalldCreateReceipts.create request.Urn request.Type connection configuration
                try
                    let! snapshot = FirewalldBackend.apply connection receipt.OwnerId configuration token
                    let response = CreateResponse()
                    response.Id <- receipt.OwnerId
                    response.Outputs <- FirewalldProviderLogic.outputs values (Some snapshot)
                    return response
                with
                | :? FirewalldPreStageRefusalException as refusal ->
                    let cleanupFailed =
                        try
                            FirewalldCreateReceipts.acknowledgeOwner request.Urn request.Type receipt.OwnerId
                            false
                        with _ -> true
                    let message =
                        if cleanupFailed then "Firewalld Create was refused before staging; local receipt cleanup failed."
                        else "Firewalld Create was refused before staging: " + refusal.Message
                    return raise (InvalidOperationException(message, refusal))
                | error ->
                    let message = FirewalldCreateReceipts.recoveryFailureMessage receipt error
                    Console.Error.WriteLine message
                    return raise (InvalidOperationException(message))
            })

    override _.Update(request, ct) =
        ct.ThrowIfCancellationRequested()
        if request.Preview then
            let response = UpdateResponse()
            response.Outputs <- FirewalldProviderLogic.preview request.Type request.NewInputs
            Task.FromResult response
        else
            FirewalldProviderLogic.run request.Timeout ct (fun token -> task {
                let values, connection, configuration = FirewalldProviderLogic.parse request.Type request.NewInputs
                let! snapshot = FirewalldBackend.apply connection request.Id configuration token
                FirewalldCreateReceipts.acknowledgeOwner request.Urn request.Type request.Id
                let response = UpdateResponse()
                response.Outputs <- FirewalldProviderLogic.outputs values (Some snapshot)
                return response
            })

    override _.Read(request, ct) =
        FirewalldProviderLogic.run TimeSpan.Zero ct (fun token -> task {
            if FirewalldCreateReceipts.isRecoveryTicket request.Id then
                let receipt = FirewalldCreateReceipts.readTicket request.Urn request.Type request.Id
                let storedInputs = FirewalldProviderLogic.receiptInputs receipt
                let values, connection, configuration = FirewalldProviderLogic.parse request.Type storedInputs
                if not request.Inputs.IsEmpty then
                    let _, providedConnection, providedConfiguration =
                        FirewalldProviderLogic.parse request.Type (FirewalldProviderLogic.stored request.Inputs request.Outputs)
                    if providedConnection <> connection || providedConfiguration <> configuration then
                        invalidOp "Firewalld recovery receipt inputs do not match the supplied import state."
                let! snapshot = FirewalldBackend.read connection receipt.OwnerId configuration token
                if not snapshot.Exists
                   || not snapshot.PermanentInSync
                   || not snapshot.InSync
                   || (snapshot.RuntimeObserved && not snapshot.RuntimeInSync) then
                    invalidOp "Firewalld recovery receipt does not identify an owned resource in live and permanent sync."
                // Import does not prove that Pulumi checkpointed the returned owner ID.
                let response = ReadResponse()
                response.Id <- receipt.OwnerId
                response.Inputs <- values
                response.Outputs <- FirewalldProviderLogic.outputs values (Some snapshot)
                return response
            else
                let values, connection, configuration = FirewalldProviderLogic.parse request.Type (FirewalldProviderLogic.stored request.Inputs request.Outputs)
                let owner = if String.IsNullOrEmpty request.Id then FirewalldProviderLogic.owner request.Urn connection else request.Id
                let! snapshot = FirewalldBackend.read connection owner configuration token
                FirewalldCreateReceipts.acknowledgeOwner request.Urn request.Type owner
                let response = ReadResponse()
                response.Id <- owner
                response.Inputs <- values
                response.Outputs <- FirewalldProviderLogic.outputs values (Some snapshot)
                return response
        })

    override _.Delete(request, ct) =
        FirewalldProviderLogic.run request.Timeout ct (fun token -> task {
            let _, connection, configuration = FirewalldProviderLogic.parse request.Type (FirewalldProviderLogic.stored request.OldInputs request.OldOutputs)
            do! FirewalldBackend.delete connection request.Id configuration token
            FirewalldCreateReceipts.acknowledgeOwner request.Urn request.Type request.Id
        }) :> Task
