namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private Fail2BanProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:Fail2Ban"

    type NormalizedInputs =
        {
            Values: Dictionary<string, PropertyValue>
            HasUnknowns: bool
            Failures: ResizeArray<CheckFailure>
        }

    type ParsedInputs =
        {
            Values: Dictionary<string, PropertyValue>
            Connection: SshConnection
            Configuration: Fail2BanConfiguration
        }

    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "resources": {
    "keroosha:debian:Fail2Ban": {
      "description": "Manages caller-supplied native Fail2Ban configuration files on an existing Debian host.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "files": { "type": "object", "additionalProperties": { "type": "string" }, "default": {} },
        "manageSshdPorts": { "type": "boolean", "default": false },
        "sshdPorts": { "type": "array", "items": { "type": "integer" }, "default": [] }
      },
      "requiredInputs": ["connection"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "files": { "type": "object", "additionalProperties": { "type": "string" } },
        "manageSshdPorts": { "type": "boolean" },
        "sshdPorts": { "type": "array", "items": { "type": "integer" } },
        "owned": { "type": "boolean" },
        "actualFiles": { "type": "object", "secret": true, "additionalProperties": { "type": "string" } },
        "active": { "type": "boolean" },
        "activeJails": { "type": "array", "items": { "type": "string" } },
        "socket": { "type": "string", "secret": true },
        "inSync": { "type": "boolean" }
      },
      "required": ["connection", "files", "manageSshdPorts", "sshdPorts", "owned", "actualFiles", "active", "activeJails", "socket", "inSync"]
    }
  }
}"""

    let private declarativeProperties =
        [ "connection"; "files"; "manageSshdPorts"; "sshdPorts" ]

    let private outputProperties =
        [ "owned"; "actualFiles"; "active"; "activeJails"; "socket"; "inSync" ]

    let private knownInputs = Set.ofList declarativeProperties

    let private tryGetMap (value: PropertyValue) =
        let mutable result = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&result) then Some result else None

    let private tryGetArray (value: PropertyValue) =
        let mutable result = ImmutableArray<PropertyValue>.Empty
        if value.TryGetArray(&result) then Some result else None

    let private tryGetString (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>
        if value.TryGetString(&result) then Some result else None

    let private tryGetBoolean (value: PropertyValue) =
        let mutable result = false
        if value.TryGetBool(&result) then Some result else None

    let private tryGetNumber (value: PropertyValue) =
        let mutable result = 0.0
        if value.TryGetNumber(&result) then Some result else None

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

    let private addFailure (failures: ResizeArray<CheckFailure>) property reason =
        failures.Add(CheckFailure(property, reason))

    let private mapEntryPath (path: string) (key: string) =
        path + "[" + JsonSerializer.Serialize(key) + "]"


    let private dictionaryFromImmutable (values: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)

        for entry in values do
            result.Add(entry.Key, entry.Value)

        result

    let private immutableInputs (values: Dictionary<string, PropertyValue>) =
        ImmutableDictionary.CreateRange<string, PropertyValue>(
            values |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
        )

    let private stringWithMetadata (source: PropertyValue) (value: string) =
        PropertyValue(value, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private numberWithMetadata (source: PropertyValue) (value: float) =
        PropertyValue(value, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private booleanWithMetadata (source: PropertyValue) (value: bool) =
        PropertyValue(value, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private mapWithMetadata (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) =
        PropertyValue(values, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private arrayWithMetadata (source: PropertyValue) (values: ImmutableArray<PropertyValue>) =
        PropertyValue(values, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private normalizeConnection
        (source: PropertyValue)
        (values: ImmutableDictionary<string, PropertyValue>)
        (failures: ResizeArray<CheckFailure>)
        =
        let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        let mutable hasUnknown = false

        for entry in values do
            if
                entry.Key <> "address"
                && entry.Key <> "user"
                && entry.Key <> "port"
                && entry.Key <> "identityFile"
            then
                addFailure failures ("connection." + entry.Key) "This connection property is not supported."

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

                    if String.IsNullOrWhiteSpace(canonical) || not (validate canonical) then
                        addFailure failures ("connection." + name) reason
                    else
                        normalized[name] <- stringWithMetadata value canonical

        let invalidCharacter (text: string) =
            text
            |> Seq.exists (fun value -> Char.IsControl(value) || Char.IsWhiteSpace(value))

        normalizeRequiredString
            "address"
            (fun text ->
                not (text.StartsWith("-", StringComparison.Ordinal))
                && not (text.Contains('@'))
                && not (invalidCharacter text))
            "Expected a non-empty SSH host address without whitespace or '@'."

        normalizeRequiredString
            "user"
            (fun text ->
                not (text.StartsWith("-", StringComparison.Ordinal))
                && not (text.Contains('/'))
                && not (text.Contains('@'))
                && not (invalidCharacter text))
            "Expected a non-empty SSH user without whitespace, '/', or '@'."

        match values.TryGetValue("port") with
        | false, _ -> normalized["port"] <- PropertyValue(22.0)
        | true, value when value.IsComputed ->
            hasUnknown <- true
            normalized["port"] <- value
        | true, value when value.IsNull -> normalized["port"] <- numberWithMetadata value 22.0
        | true, value ->
            match tryGetNumber value with
            | Some number when
                not (Double.IsNaN(number) || Double.IsInfinity(number))
                && number = Math.Truncate(number)
                && number >= 1.0
                && number <= 65535.0
                ->
                normalized["port"] <- numberWithMetadata value number
            | _ -> addFailure failures "connection.port" "Expected an integer SSH port from 1 through 65535."

        match values.TryGetValue("identityFile") with
        | false, _ -> ()
        | true, value when value.IsComputed ->
            hasUnknown <- true
            normalized["identityFile"] <- value
        | true, value when value.IsNull -> ()
        | true, value ->
            match tryGetString value with
            | None -> addFailure failures "connection.identityFile" "Expected a string when identityFile is provided."
            | Some path when String.IsNullOrWhiteSpace(path) -> ()
            | Some path when path |> Seq.exists Char.IsControl ->
                addFailure failures "connection.identityFile" "identityFile must not contain control characters."
            | Some path -> normalized["identityFile"] <- stringWithMetadata value path

        hasUnknown,
        mapWithMetadata
            source
            (ImmutableDictionary.CreateRange<string, PropertyValue>(
                normalized |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
            ))

    let private isSafeConfigPath (path: string) =
        not (String.IsNullOrEmpty(path))
        && not (path.StartsWith("/", StringComparison.Ordinal))
        && not (path.Contains('\\'))
        && not (path |> Seq.exists Char.IsControl)
        && (path.Split('/')
            |> Array.forall (fun segment -> segment <> "" && segment <> "." && segment <> ".."))

    let private normalizeFiles
        (values: ImmutableDictionary<string, PropertyValue>)
        (normalized: Dictionary<string, PropertyValue>)
        (failures: ResizeArray<CheckFailure>)
        =
        match values.TryGetValue("files") with
        | false, _ -> normalized["files"] <- PropertyValue(ImmutableDictionary<string, PropertyValue>.Empty)
        | true, source when source.IsComputed -> normalized["files"] <- source
        | true, source when source.IsNull ->
            normalized["files"] <- mapWithMetadata source ImmutableDictionary<string, PropertyValue>.Empty
        | true, source ->
            match tryGetMap source with
            | None ->
                addFailure failures "files" "Expected a map of relative Fail2Ban configuration paths to file contents."
            | Some fields ->
                let result =
                    ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)

                for entry in fields do
                    if not (isSafeConfigPath entry.Key) then
                        addFailure
                            failures
                            (mapEntryPath "files" entry.Key)
                            "Expected a safe relative path beneath the Fail2Ban configuration root."

                    if entry.Value.IsComputed then
                        result[entry.Key] <- entry.Value
                    else
                        match tryGetString entry.Value with
                        | Some content when not (isNull content) ->
                            result[entry.Key] <- stringWithMetadata entry.Value content
                        | _ ->
                            addFailure failures (mapEntryPath "files" entry.Key) "Expected configuration file text."
                            result[entry.Key] <- entry.Value

                normalized["files"] <- mapWithMetadata source (result.ToImmutable())

    let private normalizeManageSshdPorts
        (values: ImmutableDictionary<string, PropertyValue>)
        (normalized: Dictionary<string, PropertyValue>)
        (failures: ResizeArray<CheckFailure>)
        =
        match values.TryGetValue("manageSshdPorts") with
        | false, _ ->
            normalized["manageSshdPorts"] <- PropertyValue(false)
            false
        | true, value when value.IsComputed ->
            normalized["manageSshdPorts"] <- value
            true
        | true, value when value.IsNull ->
            normalized["manageSshdPorts"] <- booleanWithMetadata value false
            false
        | true, value ->
            match tryGetBoolean value with
            | Some boolean ->
                normalized["manageSshdPorts"] <- booleanWithMetadata value boolean
                false
            | None ->
                addFailure failures "manageSshdPorts" "Expected a boolean."
                false

    let private normalizeSshdPorts
        (values: ImmutableDictionary<string, PropertyValue>)
        (normalized: Dictionary<string, PropertyValue>)
        (failures: ResizeArray<CheckFailure>)
        =
        match values.TryGetValue("sshdPorts") with
        | false, _ ->
            normalized["sshdPorts"] <- PropertyValue(ImmutableArray<PropertyValue>.Empty)
            false
        | true, source when source.IsComputed ->
            normalized["sshdPorts"] <- source
            true
        | true, source when source.IsNull ->
            normalized["sshdPorts"] <- arrayWithMetadata source ImmutableArray<PropertyValue>.Empty
            false
        | true, source ->
            match tryGetArray source with
            | None ->
                addFailure failures "sshdPorts" "Expected an array of SSH listener ports."
                false
            | Some items ->
                let result = ResizeArray<PropertyValue>()
                let mutable hasUnknown = false

                for index, item in items |> Seq.indexed do
                    if item.IsComputed then
                        hasUnknown <- true
                        result.Add(item)
                    else
                        match tryGetNumber item with
                        | Some number when
                            not (Double.IsNaN(number) || Double.IsInfinity(number))
                            && number = Math.Truncate(number)
                            && number >= 1.0
                            && number <= 65535.0
                            ->
                            result.Add(numberWithMetadata item number)
                        | _ ->
                            addFailure
                                failures
                                (sprintf "sshdPorts[%d]" index)
                                "Expected an integer SSH port from 1 through 65535."

                            result.Add(item)

                normalized["sshdPorts"] <- arrayWithMetadata source (ImmutableArray.CreateRange(result))
                hasUnknown

    let private normalizeInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = dictionaryFromImmutable values
        let failures = ResizeArray<CheckFailure>()
        let mutable hasUnknown = values.Values |> Seq.exists containsUnknown

        for entry in values do
            if not (knownInputs.Contains(entry.Key)) then
                addFailure failures entry.Key "This resource property is not supported."

        match values.TryGetValue("connection") with
        | false, _ -> addFailure failures "connection" "This property is required."
        | true, connection when connection.IsComputed ->
            normalized["connection"] <- connection
            hasUnknown <- true
        | true, connection ->
            match tryGetMap connection with
            | None -> addFailure failures "connection" "Expected an SSH connection object."
            | Some fields ->
                let connectionUnknown, canonical = normalizeConnection connection fields failures
                normalized["connection"] <- canonical
                hasUnknown <- hasUnknown || connectionUnknown

        normalizeFiles values normalized failures

        if normalizeManageSshdPorts values normalized failures then
            hasUnknown <- true

        if normalizeSshdPorts values normalized failures then
            hasUnknown <- true

        {
            Values = normalized
            HasUnknowns = hasUnknown
            Failures = failures
        }

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let message =
                failures
                |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason)
                |> String.concat " "

            invalidOp ("Invalid Fail2Ban inputs. " + message)


    let private parseConnection (value: PropertyValue) =
        let fields =
            match tryGetMap value with
            | Some values -> values
            | None -> invalidOp "Stored Fail2Ban state has an invalid connection."

        let requiredString name =
            match fields.TryGetValue(name) with
            | true, item ->
                match tryGetString item with
                | Some text when not (String.IsNullOrWhiteSpace(text)) -> text
                | _ -> invalidOp ("Stored Fail2Ban state has an invalid connection." + name + ".")
            | false, _ -> invalidOp ("Stored Fail2Ban state is missing connection." + name + ".")

        let port =
            match fields.TryGetValue("port") with
            | true, item ->
                match tryGetNumber item with
                | Some number when number >= 1.0 && number <= 65535.0 && number = Math.Truncate(number) -> int number
                | _ -> invalidOp "Stored Fail2Ban state has an invalid SSH port."
            | false, _ -> invalidOp "Stored Fail2Ban state is missing its SSH port."

        let identityFile =
            match fields.TryGetValue("identityFile") with
            | false, _ -> None
            | true, item ->
                match tryGetString item with
                | Some path -> Some path
                | None -> invalidOp "Stored Fail2Ban state has an invalid identityFile."

        {
            Address = requiredString "address"
            User = requiredString "user"
            Port = port
            IdentityFile = identityFile
        }

    let private readBoolean name (values: Dictionary<string, PropertyValue>) =
        match values.TryGetValue(name) with
        | true, value ->
            match tryGetBoolean value with
            | Some result -> result
            | None -> invalidOp ("Stored Fail2Ban state has an invalid " + name + ".")
        | false, _ -> invalidOp ("Stored Fail2Ban state is missing " + name + ".")

    let private readFiles (values: Dictionary<string, PropertyValue>) =
        let fields =
            match values.TryGetValue("files") with
            | true, value ->
                match tryGetMap value with
                | Some fields -> fields
                | None -> invalidOp "Stored Fail2Ban state has an invalid files map."
            | false, _ -> invalidOp "Stored Fail2Ban state is missing files."

        let mutable result = Map.empty

        for entry in fields do
            if not (isSafeConfigPath entry.Key) then
                invalidOp "Stored Fail2Ban state contains an unsafe relative configuration path."

            match tryGetString entry.Value with
            | Some content when not (isNull content) -> result <- Map.add entry.Key content result
            | _ -> invalidOp "Stored Fail2Ban state contains a non-string configuration file."

        result

    let private readPorts (values: Dictionary<string, PropertyValue>) =
        let items =
            match values.TryGetValue("sshdPorts") with
            | true, value ->
                match tryGetArray value with
                | Some items -> items
                | None -> invalidOp "Stored Fail2Ban state has an invalid sshdPorts array."
            | false, _ -> invalidOp "Stored Fail2Ban state is missing sshdPorts."

        items
        |> Seq.map (fun item ->
            match tryGetNumber item with
            | Some number when number >= 1.0 && number <= 65535.0 && number = Math.Truncate(number) -> int number
            | _ -> invalidOp "Stored Fail2Ban state has an invalid SSH port.")
        |> List.ofSeq

    let private parseInputs (normalized: NormalizedInputs) =
        failIfFailures normalized.Failures

        if normalized.HasUnknowns then
            invalidOp "Fail2Ban operations require known inputs."

        let connection =
            match normalized.Values.TryGetValue("connection") with
            | true, value -> parseConnection value
            | false, _ -> invalidOp "Stored Fail2Ban state is missing connection."

        let configuration =
            {
                Files = readFiles normalized.Values
                ManageSshdPorts = readBoolean "manageSshdPorts" normalized.Values
                SshdPorts = readPorts normalized.Values
            }

        {
            Values = normalized.Values
            Connection = connection
            Configuration = configuration
        }

    let private normalizeForPreview values =
        let normalized = normalizeInputs values
        failIfFailures normalized.Failures
        normalized

    let private normalizeForOperation values = normalizeInputs values |> parseInputs

    let private inputValuesFromOutputs
        (preferred: ImmutableDictionary<string, PropertyValue>)
        (fallback: ImmutableDictionary<string, PropertyValue>)
        =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)

        for key in declarativeProperties do
            match preferred.TryGetValue(key) with
            | true, value -> result[key] <- value
            | false, _ ->
                match fallback.TryGetValue(key) with
                | true, value -> result[key] <- value
                | false, _ -> ()

        result

    let private storedInputs preferred fallback =
        inputValuesFromOutputs preferred fallback
        |> immutableInputs
        |> normalizeInputs
        |> parseInputs

    let private stableId (urn: Pulumi.Urn) (connection: SshConnection) =
        urn.ToString() + "::" + connection.Address

    let private addDiff
        (diffs: ResizeArray<string>)
        (details: Dictionary<string, PropertyDiff>)
        root
        path
        kind
        inputDiff
        =
        if not (details.ContainsKey(path)) then
            let propertyDiff = PropertyDiff()
            propertyDiff.Kind <- kind
            propertyDiff.InputDiff <- inputDiff
            details.Add(path, propertyDiff)

            if not (diffs.Contains(root)) then
                diffs.Add(root)

    let private tryOutputBoolean name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when not value.IsComputed ->
            let mutable result = false
            if value.TryGetBool(&result) then Some result else None
        | _ -> None

    let private snapshotMatches (_inputs: ParsedInputs) (outputs: ImmutableDictionary<string, PropertyValue>) =
        tryOutputBoolean "owned" outputs = Some true
        && tryOutputBoolean "inSync" outputs = Some true

    let private diffResponse changes diffs replaces details deleteBeforeReplace =
        let response = DiffResponse()
        response.Changes <- changes
        response.Diffs <- diffs
        response.Replaces <- replaces
        response.DetailedDiff <- details
        response.DeleteBeforeReplace <- deleteBeforeReplace
        response

    let private compareArray
        (add: string -> string -> PropertyDiffKind -> bool -> unit)
        (root: string)
        (path: string)
        (oldValue: PropertyValue)
        (newValue: PropertyValue)
        =
        if oldValue.IsSecret <> newValue.IsSecret then
            add root path PropertyDiffKind.Update true

        match tryGetArray oldValue, tryGetArray newValue with
        | Some oldItems, Some newItems ->
            let maxLength = max oldItems.Length newItems.Length

            for index in 0 .. maxLength - 1 do
                let itemPath = sprintf "%s[%d]" path index

                if index >= oldItems.Length then
                    add root itemPath PropertyDiffKind.Add true
                elif index >= newItems.Length then
                    add root itemPath PropertyDiffKind.Delete true
                else
                    let oldItem = oldItems[index]
                    let newItem = newItems[index]

                    if oldItem.IsSecret <> newItem.IsSecret || not (oldItem.Equals(newItem)) then
                        add root itemPath PropertyDiffKind.Update true
        | _ -> add root path PropertyDiffKind.Update true

    let private compareMap
        (add: string -> string -> PropertyDiffKind -> bool -> unit)
        (root: string)
        (path: string)
        (oldValue: PropertyValue)
        (newValue: PropertyValue)
        =
        if oldValue.IsSecret <> newValue.IsSecret then
            add root path PropertyDiffKind.Update true

        match tryGetMap oldValue, tryGetMap newValue with
        | Some oldFields, Some newFields ->
            let names = Set.union (oldFields.Keys |> Set.ofSeq) (newFields.Keys |> Set.ofSeq)

            for name in names do
                let itemPath = mapEntryPath path name

                match oldFields.TryGetValue(name), newFields.TryGetValue(name) with
                | (true, _), (false, _) -> add root itemPath PropertyDiffKind.Delete true
                | (false, _), (true, _) -> add root itemPath PropertyDiffKind.Add true
                | (true, oldItem), (true, newItem) ->
                    if oldItem.IsSecret <> newItem.IsSecret || not (oldItem.Equals(newItem)) then
                        add root itemPath PropertyDiffKind.Update true
                | _ -> ()
        | _ -> add root path PropertyDiffKind.Update true


    let private makeDiff (request: DiffRequest) =
        let previous = inputValuesFromOutputs request.OldInputs request.OldOutputs

        if String.IsNullOrEmpty(request.Id) && previous.Count = 0 then
            diffResponse
                (Nullable<bool>(true))
                (List<string>())
                (List<string>())
                (Dictionary<string, PropertyDiff>())
                false
        elif previous.Count = 0 then
            invalidOp "Stored Fail2Ban state is missing its input declaration."
        else
            let oldNormalized = immutableInputs previous |> normalizeInputs
            let newNormalized = normalizeInputs request.NewInputs
            failIfFailures oldNormalized.Failures
            failIfFailures newNormalized.Failures

            if oldNormalized.HasUnknowns || newNormalized.HasUnknowns then
                let response = DiffResponse()
                response.Changes <- Nullable<bool>()
                response
            else
                let oldInputs = parseInputs oldNormalized
                let newInputs = parseInputs newNormalized
                let diffs = ResizeArray<string>()
                let replaces = ResizeArray<string>()
                let details = Dictionary<string, PropertyDiff>(StringComparer.Ordinal)

                let add root path kind inputDiff =
                    addDiff diffs details root path kind inputDiff

                if oldInputs.Connection.Address <> newInputs.Connection.Address then
                    add "connection" "connection.address" PropertyDiffKind.UpdateReplace true
                    replaces.Add("connection.address")

                if oldInputs.Connection.Port <> newInputs.Connection.Port then
                    add "connection" "connection.port" PropertyDiffKind.Update true

                if oldInputs.Connection.User <> newInputs.Connection.User then
                    add "connection" "connection.user" PropertyDiffKind.Update true

                if oldInputs.Connection.IdentityFile <> newInputs.Connection.IdentityFile then
                    add "connection" "connection.identityFile" PropertyDiffKind.Update true

                if
                    oldNormalized.Values["connection"].IsSecret
                    <> newNormalized.Values["connection"].IsSecret
                then
                    add "connection" "connection" PropertyDiffKind.Update true

                let oldConnectionFields = tryGetMap oldNormalized.Values["connection"] |> Option.get
                let newConnectionFields = tryGetMap newNormalized.Values["connection"] |> Option.get

                for name in [ "address"; "user"; "port"; "identityFile" ] do
                    match oldConnectionFields.TryGetValue(name), newConnectionFields.TryGetValue(name) with
                    | (true, oldValue), (true, newValue) when oldValue.IsSecret <> newValue.IsSecret ->
                        add "connection" ("connection." + name) PropertyDiffKind.Update true
                    | _ -> ()

                for name, oldValue, newValue in
                    [
                        "manageSshdPorts",
                        oldNormalized.Values["manageSshdPorts"],
                        newNormalized.Values["manageSshdPorts"]
                    ] do
                    if oldValue.IsSecret <> newValue.IsSecret || not (oldValue.Equals(newValue)) then
                        add name name PropertyDiffKind.Update true

                compareMap add "files" "files" oldNormalized.Values["files"] newNormalized.Values["files"]

                compareArray
                    add
                    "sshdPorts"
                    "sshdPorts"
                    oldNormalized.Values["sshdPorts"]
                    newNormalized.Values["sshdPorts"]

                if not (snapshotMatches oldInputs request.OldOutputs) then
                    add "inSync" "inSync" PropertyDiffKind.Update false

                diffResponse
                    (Nullable<bool>(diffs.Count > 0))
                    (List<string>(diffs))
                    (List<string>(replaces))
                    details
                    (replaces.Count > 0)

    let private arrayValue (source: PropertyValue) (values: seq<PropertyValue>) =
        PropertyValue(
            ImmutableArray.CreateRange(values),
            IsSecret = containsSecret source,
            Dependencies = source.Dependencies
        )

    let private outputFiles (source: PropertyValue) (values: Map<string, string>) =
        let builder =
            ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)

        for KeyValue(path, content) in values do
            builder[path] <- PropertyValue(content)

        PropertyValue(builder.ToImmutable(), IsSecret = true, Dependencies = source.Dependencies)

    let private outputValues (inputs: Dictionary<string, PropertyValue>) (snapshot: Fail2BanSnapshot) =
        let outputs = Dictionary<string, PropertyValue>(inputs, StringComparer.Ordinal)
        let anySecret = inputs.Values |> Seq.exists containsSecret
        outputs["owned"] <- PropertyValue(snapshot.Owned)
        outputs["actualFiles"] <- outputFiles inputs["files"] snapshot.ActualFiles
        outputs["active"] <- PropertyValue(snapshot.Active)

        outputs["activeJails"] <-
            arrayValue inputs["files"] (snapshot.ActiveJails |> Seq.map (fun jail -> PropertyValue(jail)))

        outputs["socket"] <-
            PropertyValue(snapshot.Socket, IsSecret = true, Dependencies = inputs["connection"].Dependencies)

        outputs["inSync"] <- PropertyValue(snapshot.Owned && snapshot.InSync, IsSecret = anySecret)
        outputs

    let private previewValues (inputs: NormalizedInputs) =
        let outputs =
            Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)

        for property in outputProperties do
            outputs[property] <- PropertyValue.Computed

        outputs

    let private requestTimeout (timeout: TimeSpan) =
        if timeout > TimeSpan.Zero then Some timeout else None

    let runWithTimeout
        (timeout: TimeSpan option)
        (outerToken: CancellationToken)
        (operation: CancellationToken -> Task<'T>)
        =
        task {
            use linked = CancellationTokenSource.CreateLinkedTokenSource(outerToken)

            match timeout with
            | Some value when value > TimeSpan.Zero -> linked.CancelAfter(value)
            | _ -> ()

            return! operation linked.Token
        }

    let private checkResponse (inputs: Dictionary<string, PropertyValue>) (failures: ResizeArray<CheckFailure>) =
        let response = CheckResponse()
        response.Inputs <- inputs
        response.Failures <- List<CheckFailure>(failures)
        response

    let private configureResponse () =
        let response = ConfigureResponse()
        response.AcceptSecrets <- true
        response.AcceptResources <- false
        response.AcceptOutputs <- true
        response.SupportsPreview <- true
        response

    let private makeCheckResponse (request: CheckRequest) =
        if request.Type <> ResourceToken then
            let failures = ResizeArray<CheckFailure>()
            addFailure failures "" "Unexpected resource token for the Dorothy provider."
            checkResponse (dictionaryFromImmutable request.NewInputs) failures
        else
            let normalized = normalizeInputs request.NewInputs
            checkResponse normalized.Values normalized.Failures

    let private createPreviewResponse inputs =
        let response = CreateResponse()
        response.Id <- String.Empty
        response.Outputs <- previewValues inputs
        response

    let private createResponse ownerId inputs snapshot =
        let response = CreateResponse()
        response.Id <- ownerId
        response.Outputs <- outputValues inputs.Values snapshot
        response

    let private updatePreviewResponse inputs =
        let response = UpdateResponse()
        response.Outputs <- previewValues inputs
        response

    let private updateResponse inputs snapshot =
        let response = UpdateResponse()
        response.Outputs <- outputValues inputs.Values snapshot
        response

    let private readResponse (id: string) (urn: Pulumi.Urn) (inputs: ParsedInputs) (snapshot: Fail2BanSnapshot) =
        let response = ReadResponse()

        response.Id <-
            if snapshot.Owned then
                (if String.IsNullOrEmpty(id) then
                     stableId urn inputs.Connection
                 else
                     id)
            else
                String.Empty

        response.Inputs <- immutableInputs inputs.Values
        response.Outputs <- outputValues inputs.Values snapshot
        response

    let ensureResourceToken requestType =
        if requestType <> ResourceToken then
            invalidOp "Unexpected resource token for the Dorothy provider."

    let resourceToken = ResourceToken
    let providerSchema = schema

    let checkConfiguration (request: CheckRequest) =
        let failures = ResizeArray<CheckFailure>()

        for entry in request.NewInputs do
            if entry.Key <> "version" && entry.Key <> "pluginDownloadURL" then
                addFailure failures entry.Key "Dorothy does not accept custom provider configuration properties."

        checkResponse (dictionaryFromImmutable request.NewInputs) failures

    let providerConfigurationDiff (request: DiffRequest) =
        let changed =
            request.OldInputs.Count <> request.NewInputs.Count
            || (request.NewInputs
                |> Seq.exists (fun entry ->
                    match request.OldInputs.TryGetValue(entry.Key) with
                    | true, oldValue -> not (oldValue.Equals(entry.Value))
                    | false, _ -> true))

        diffResponse
            (Nullable<bool>(changed))
            (List<string>())
            (List<string>())
            (Dictionary<string, PropertyDiff>())
            false

    let providerConfigurationResponse () = configureResponse ()
    let resourceCheck = makeCheckResponse
    let makeDiffResponse = makeDiff
    let normalizeForPreviewInputs = normalizeForPreview
    let normalizeForOperationInputs = normalizeForOperation
    let parseStoredState = storedInputs
    let timeoutForRequest = requestTimeout
    let resourceId = stableId
    let makeCreatePreviewResponse = createPreviewResponse
    let makeCreateResponse = createResponse
    let makeUpdatePreviewResponse = updatePreviewResponse
    let makeUpdateResponse = updateResponse
    let makeReadResponse = readResponse

[<Sealed>]
type Fail2BanProvider() =
    inherit Pulumi.Experimental.Provider.Provider()

    static member Version = "0.1.0"
    static member ResourceToken = Fail2BanProviderLogic.resourceToken
    static member Schema = Fail2BanProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- Fail2BanProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(Fail2BanProviderLogic.checkConfiguration request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(Fail2BanProviderLogic.providerConfigurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()

        if
            request.Args.Keys
            |> Seq.exists (fun key -> key <> "version" && key <> "pluginDownloadURL")
        then
            invalidOp "Dorothy does not accept custom provider configuration properties."

        Task.FromResult(Fail2BanProviderLogic.providerConfigurationResponse ())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(Fail2BanProviderLogic.resourceCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Fail2BanProviderLogic.ensureResourceToken request.Type
        Task.FromResult(Fail2BanProviderLogic.makeDiffResponse request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Fail2BanProviderLogic.ensureResourceToken request.Type

        if request.Preview then
            let inputs = Fail2BanProviderLogic.normalizeForPreviewInputs request.Inputs
            Task.FromResult(Fail2BanProviderLogic.makeCreatePreviewResponse inputs)
        else
            Fail2BanProviderLogic.runWithTimeout
                (Fail2BanProviderLogic.timeoutForRequest request.Timeout)
                ct
                (fun operationToken ->
                    task {
                        operationToken.ThrowIfCancellationRequested()
                        let inputs = Fail2BanProviderLogic.normalizeForOperationInputs request.Inputs
                        let ownerId = Fail2BanProviderLogic.resourceId request.Urn inputs.Connection

                        let! snapshot =
                            Fail2BanBackend.apply inputs.Connection ownerId inputs.Configuration operationToken

                        return Fail2BanProviderLogic.makeCreateResponse ownerId inputs snapshot
                    })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        Fail2BanProviderLogic.ensureResourceToken request.Type

        Fail2BanProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = Fail2BanProviderLogic.parseStoredState request.Inputs request.Outputs

                let ownerId =
                    if String.IsNullOrEmpty(request.Id) then
                        Fail2BanProviderLogic.resourceId request.Urn inputs.Connection
                    else
                        request.Id

                let! snapshot =
                    Fail2BanBackend.read inputs.Connection ownerId inputs.Configuration operationToken

                return Fail2BanProviderLogic.makeReadResponse request.Id request.Urn inputs snapshot
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Fail2BanProviderLogic.ensureResourceToken request.Type

        if request.Preview then
            let inputs = Fail2BanProviderLogic.normalizeForPreviewInputs request.NewInputs
            Task.FromResult(Fail2BanProviderLogic.makeUpdatePreviewResponse inputs)
        else
            Fail2BanProviderLogic.runWithTimeout
                (Fail2BanProviderLogic.timeoutForRequest request.Timeout)
                ct
                (fun operationToken ->
                    task {
                        operationToken.ThrowIfCancellationRequested()
                        let inputs = Fail2BanProviderLogic.normalizeForOperationInputs request.NewInputs

                        let ownerId =
                            if String.IsNullOrEmpty(request.Id) then
                                Fail2BanProviderLogic.resourceId request.Urn inputs.Connection
                            else
                                request.Id

                        let! snapshot =
                            Fail2BanBackend.apply inputs.Connection ownerId inputs.Configuration operationToken

                        return Fail2BanProviderLogic.makeUpdateResponse inputs snapshot
                    })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        Fail2BanProviderLogic.ensureResourceToken request.Type

        Fail2BanProviderLogic.runWithTimeout
            (Fail2BanProviderLogic.timeoutForRequest request.Timeout)
            ct
            (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()

                    let inputs =
                        Fail2BanProviderLogic.parseStoredState request.OldInputs request.OldOutputs

                    let ownerId =
                        if String.IsNullOrEmpty(request.Id) then
                            Fail2BanProviderLogic.resourceId request.Urn inputs.Connection
                        else
                            request.Id

                    do! Fail2BanBackend.delete inputs.Connection ownerId inputs.Configuration operationToken
                })
        :> Task
