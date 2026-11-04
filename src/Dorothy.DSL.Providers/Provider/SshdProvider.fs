namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private SshdProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:SshdConfig"

    type NormalizedInputs =
        { Values: Dictionary<string, PropertyValue>
          HasUnknowns: bool
          Failures: ResizeArray<CheckFailure> }

    type ParsedInputs =
        { Values: Dictionary<string, PropertyValue>
          Connection: SshConnection
          Settings: Map<string, string> }

    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "resources": {
    "keroosha:debian:SshdConfig": {
      "description": "Manages an owned subset of effective OpenSSH server settings on an existing Debian host.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "settings": { "type": "object", "additionalProperties": { "type": "string" } }
      },
      "requiredInputs": ["connection", "settings"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "settings": { "type": "object", "additionalProperties": { "type": "string" } },
        "owned": { "type": "boolean" },
        "actualSettings": { "type": "object", "additionalProperties": { "type": "string" } },
        "ports": { "type": "array", "items": { "type": "integer", "minimum": 1, "maximum": 65535 } },
        "inSync": { "type": "boolean" }
      },
      "required": ["connection", "settings", "owned", "actualSettings", "ports", "inSync"]
    }
  }
}"""

    let private declarativeProperties = [ "connection"; "settings" ]
    let private outputProperties = [ "owned"; "actualSettings"; "ports"; "inSync" ]

    let private supportedSettings =
        Set.ofList
            [ "PasswordAuthentication"
              "KbdInteractiveAuthentication"
              "PubkeyAuthentication"
              "PermitRootLogin"
              "Port"
              "MaxAuthTries" ]

    let private tryGetMap (value: PropertyValue) =
        let mutable result = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&result) then Some result else None

    let private tryGetArray (value: PropertyValue) =
        let mutable result = ImmutableArray<PropertyValue>.Empty
        if value.TryGetArray(&result) then Some result else None

    let private tryGetString (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>
        if value.TryGetString(&result) then Some result else None

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

    let private dictionaryFromImmutable (values: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in values do result.Add(entry.Key, entry.Value)
        result

    let private immutableInputs (values: Dictionary<string, PropertyValue>) =
        ImmutableDictionary.CreateRange<string, PropertyValue>(values |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value)))

    let private stringWithMetadata (source: PropertyValue) (value: string) =
        PropertyValue(value, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private numberWithMetadata (source: PropertyValue) (value: float) =
        PropertyValue(value, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private mapWithMetadata (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) =
        PropertyValue(values, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private normalizeConnection
        (source: PropertyValue)
        (values: ImmutableDictionary<string, PropertyValue>)
        (failures: ResizeArray<CheckFailure>)
        =
        let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        let mutable hasUnknown = false
        for entry in values do
            if entry.Key <> "address" && entry.Key <> "user" && entry.Key <> "port" && entry.Key <> "identityFile" then
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

        let invalidCharacter (text: string) = text |> Seq.exists (fun value -> Char.IsControl(value) || Char.IsWhiteSpace(value))
        normalizeRequiredString
            "address"
            (fun text -> not (text.StartsWith("-", StringComparison.Ordinal)) && not (text.Contains('@')) && not (invalidCharacter text))
            "Expected a non-empty SSH host address without whitespace or '@'."
        normalizeRequiredString
            "user"
            (fun text -> not (text.StartsWith("-", StringComparison.Ordinal)) && not (text.Contains('/')) && not (text.Contains('@')) && not (invalidCharacter text))
            "Expected a non-empty SSH user without whitespace, '/', or '@'."

        match values.TryGetValue("port") with
        | false, _ -> normalized["port"] <- PropertyValue(22.0)
        | true, value when value.IsComputed ->
            hasUnknown <- true
            normalized["port"] <- value
        | true, value when value.IsNull -> normalized["port"] <- numberWithMetadata value 22.0
        | true, value ->
            match tryGetNumber value with
            | Some number when not (Double.IsNaN(number) || Double.IsInfinity(number)) && number = Math.Truncate(number) && number >= 1.0 && number <= 65535.0 ->
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
            | Some path when path |> Seq.exists Char.IsControl -> addFailure failures "connection.identityFile" "identityFile must not contain control characters."
            | Some path -> normalized["identityFile"] <- stringWithMetadata value path

        hasUnknown, mapWithMetadata source (ImmutableDictionary.CreateRange<string, PropertyValue>(normalized |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))))

    let private normalizeInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = dictionaryFromImmutable values
        let failures = ResizeArray<CheckFailure>()
        let mutable hasUnknown = values.Values |> Seq.exists containsUnknown

        for entry in values do
            if entry.Key <> "connection" && entry.Key <> "settings" then
                addFailure failures entry.Key "This resource property is not supported."

        match values.TryGetValue("connection") with
        | false, _ -> addFailure failures "connection" "This property is required."
        | true, connection when connection.IsComputed ->
            hasUnknown <- true
            normalized["connection"] <- connection
        | true, connection ->
            match tryGetMap connection with
            | None -> addFailure failures "connection" "Expected an SSH connection object."
            | Some fields ->
                let unknown, value = normalizeConnection connection fields failures
                hasUnknown <- hasUnknown || unknown
                normalized["connection"] <- value

        match values.TryGetValue("settings") with
        | false, _ -> addFailure failures "settings" "This property is required."
        | true, settings when settings.IsComputed ->
            hasUnknown <- true
            normalized["settings"] <- settings
        | true, settings ->
            match tryGetMap settings with
            | None -> addFailure failures "settings" "Expected a map of canonical OpenSSH setting names to string values."
            | Some fields ->
                let settingsValues = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                for entry in fields do
                    settingsValues[entry.Key] <- entry.Value
                    if not (supportedSettings.Contains(entry.Key)) then
                        addFailure failures ("settings." + entry.Key) "This OpenSSH setting is not supported."
                    elif entry.Value.IsComputed then
                        hasUnknown <- true
                    else
                        match tryGetString entry.Value with
                        | None -> addFailure failures ("settings." + entry.Key) "Expected a string setting value."
                        | Some value when not (SshdBackend.isValidSetting entry.Key value) ->
                            addFailure failures ("settings." + entry.Key) "Expected a canonical value for this OpenSSH setting."
                        | Some _ -> ()
                normalized["settings"] <- mapWithMetadata settings (settingsValues.ToImmutable())

        { Values = normalized
          HasUnknowns = hasUnknown
          Failures = failures }

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let message = failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " "
            invalidOp ("Invalid SSHD inputs. " + message)

    let private parseConnection (value: PropertyValue) =
        let fields =
            match tryGetMap value with
            | Some values -> values
            | None -> invalidOp "Stored SSHD state has an invalid connection."
        let requiredString name =
            match fields.TryGetValue(name) with
            | true, item ->
                match tryGetString item with
                | Some text when not (String.IsNullOrWhiteSpace(text)) -> text
                | _ -> invalidOp ("Stored SSHD state has an invalid connection." + name + ".")
            | false, _ -> invalidOp ("Stored SSHD state is missing connection." + name + ".")
        let port =
            match fields.TryGetValue("port") with
            | true, item ->
                match tryGetNumber item with
                | Some number when number >= 1.0 && number <= 65535.0 && number = Math.Truncate(number) -> int number
                | _ -> invalidOp "Stored SSHD state has an invalid SSH port."
            | false, _ -> invalidOp "Stored SSHD state is missing its SSH port."
        let identityFile =
            match fields.TryGetValue("identityFile") with
            | false, _ -> None
            | true, item ->
                match tryGetString item with
                | Some path -> Some path
                | None -> invalidOp "Stored SSHD state has an invalid identityFile."
        { Address = requiredString "address"
          User = requiredString "user"
          Port = port
          IdentityFile = identityFile }

    let private parseSettings (value: PropertyValue) =
        let fields =
            match tryGetMap value with
            | Some values -> values
            | None -> invalidOp "Stored SSHD state has an invalid settings map."
        fields
        |> Seq.map (fun entry ->
            match tryGetString entry.Value with
            | Some text when SshdBackend.isValidSetting entry.Key text -> entry.Key, text
            | _ -> invalidOp ("Stored SSHD state has an invalid settings." + entry.Key + " value."))
        |> Map.ofSeq

    let private parseInputs (normalized: NormalizedInputs) =
        failIfFailures normalized.Failures
        if normalized.HasUnknowns then invalidOp "SSHD operations require known inputs."
        let connection =
            match normalized.Values.TryGetValue("connection") with
            | true, value -> parseConnection value
            | false, _ -> invalidOp "Stored SSHD state is missing connection."
        let settings =
            match normalized.Values.TryGetValue("settings") with
            | true, value -> parseSettings value
            | false, _ -> invalidOp "Stored SSHD state is missing settings."
        { Values = normalized.Values
          Connection = connection
          Settings = settings }

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

    let private stableId (urn: Pulumi.Urn) (connection: SshConnection) = urn.ToString() + "::" + connection.Address

    let private addDiff (diffs: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) root path kind inputDiff =
        if not (details.ContainsKey(path)) then
            let propertyDiff = PropertyDiff()
            propertyDiff.Kind <- kind
            propertyDiff.InputDiff <- inputDiff
            details.Add(path, propertyDiff)
            if not (diffs.Contains(root)) then diffs.Add(root)

    let private tryOutputBoolean name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when not value.IsComputed ->
            let mutable result = false
            if value.TryGetBool(&result) then Some result else None
        | _ -> None

    let private tryOutputStringMap name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when not value.IsComputed ->
            match tryGetMap value with
            | Some fields ->
                let mutable result = Map.empty
                let mutable valid = true
                for entry in fields do
                    match tryGetString entry.Value with
                    | Some text -> result <- Map.add entry.Key text result
                    | None -> valid <- false
                if valid then Some result else None
            | None -> None
        | _ -> None

    let private snapshotMatches (inputs: ParsedInputs) (outputs: ImmutableDictionary<string, PropertyValue>) =
        tryOutputBoolean "owned" outputs = Some true
        && tryOutputBoolean "inSync" outputs = Some true
        && tryOutputStringMap "actualSettings" outputs = Some inputs.Settings

    let private diffResponse changes diffs replaces details deleteBeforeReplace =
        let response = DiffResponse()
        response.Changes <- changes
        response.Diffs <- diffs
        response.Replaces <- replaces
        response.DetailedDiff <- details
        response.DeleteBeforeReplace <- deleteBeforeReplace
        response

    let private makeDiff (request: DiffRequest) =
        let previous = inputValuesFromOutputs request.OldInputs request.OldOutputs
        if String.IsNullOrEmpty(request.Id) && previous.Count = 0 then
            diffResponse (Nullable<bool>(true)) (List<string>()) (List<string>()) (Dictionary<string, PropertyDiff>()) false
        elif previous.Count = 0 then
            invalidOp "Stored SSHD state is missing its input declaration."
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
                let add root path kind inputDiff = addDiff diffs details root path kind inputDiff

                if oldInputs.Connection.Address <> newInputs.Connection.Address then
                    add "connection" "connection.address" PropertyDiffKind.UpdateReplace true
                    replaces.Add("connection.address")
                if oldInputs.Connection.Port <> newInputs.Connection.Port then add "connection" "connection.port" PropertyDiffKind.Update true
                if oldInputs.Connection.User <> newInputs.Connection.User then add "connection" "connection.user" PropertyDiffKind.Update true
                if oldInputs.Connection.IdentityFile <> newInputs.Connection.IdentityFile then add "connection" "connection.identityFile" PropertyDiffKind.Update true
                if oldNormalized.Values["connection"].IsSecret <> newNormalized.Values["connection"].IsSecret then
                    add "connection" "connection" PropertyDiffKind.Update true
                let oldConnectionFields = tryGetMap oldNormalized.Values["connection"] |> Option.get
                let newConnectionFields = tryGetMap newNormalized.Values["connection"] |> Option.get
                for name in [ "address"; "user"; "port"; "identityFile" ] do
                    match oldConnectionFields.TryGetValue(name), newConnectionFields.TryGetValue(name) with
                    | (true, oldValue), (true, newValue) when oldValue.IsSecret <> newValue.IsSecret ->
                        add "connection" ("connection." + name) PropertyDiffKind.Update true
                    | _ -> ()
                match oldNormalized.Values["settings"].IsSecret, newNormalized.Values["settings"].IsSecret with
                | true, false
                | false, true -> add "settings" "settings" PropertyDiffKind.Update true
                | _ -> ()
                let oldSettingValues =
                    match tryGetMap oldNormalized.Values["settings"] with
                    | Some fields -> fields
                    | None -> invalidOp "Stored SSHD state has an invalid settings map."
                let newSettingValues =
                    match tryGetMap newNormalized.Values["settings"] with
                    | Some fields -> fields
                    | None -> invalidOp "New SSHD state has an invalid settings map."
                let allSettingNames = Set.union (oldSettingValues.Keys |> Set.ofSeq) (newSettingValues.Keys |> Set.ofSeq)
                for name in allSettingNames do
                    match oldSettingValues.TryGetValue(name), newSettingValues.TryGetValue(name) with
                    | (true, _), (false, _) -> add "settings" ("settings." + name) PropertyDiffKind.Delete true
                    | (false, _), (true, _) -> add "settings" ("settings." + name) PropertyDiffKind.Add true
                    | (true, oldValue), (true, newValue) ->
                        if oldValue.IsSecret <> newValue.IsSecret then
                            add "settings" ("settings." + name) PropertyDiffKind.Update true
                        elif not (oldValue.Equals(newValue)) then
                            add "settings" ("settings." + name) PropertyDiffKind.Update true
                    | _ -> ()
                if not (snapshotMatches oldInputs request.OldOutputs) then
                    add "inSync" "inSync" PropertyDiffKind.Update false
                diffResponse
                    (Nullable<bool>(diffs.Count > 0))
                    (List<string>(diffs))
                    (List<string>(replaces))
                    details
                    (replaces.Count > 0)

    let private outputSettingMap (source: PropertyValue) (values: Map<string, string>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for KeyValue(name, value) in values do builder[name] <- PropertyValue(value)
        PropertyValue(builder.ToImmutable(), IsSecret = containsSecret source, Dependencies = source.Dependencies)

    let private portsAreSecret (source: PropertyValue) =
        if source.IsSecret then
            true
        else
            match tryGetMap source with
            | Some settings ->
                match settings.TryGetValue("Port") with
                | true, value -> containsSecret value
                | false, _ -> false
            | None -> false

    let private outputPorts (source: PropertyValue) (values: int list) =
        PropertyValue(
            ImmutableArray.CreateRange(values |> List.sort |> Seq.map (fun port -> PropertyValue(float port))),
            IsSecret = portsAreSecret source,
            Dependencies = source.Dependencies
        )

    let private outputValues (inputs: Dictionary<string, PropertyValue>) (snapshot: SshdSnapshot) =
        let outputs = Dictionary<string, PropertyValue>(inputs, StringComparer.Ordinal)
        outputs["owned"] <- PropertyValue(snapshot.Owned)
        outputs["actualSettings"] <- outputSettingMap inputs["settings"] snapshot.ActualSettings
        outputs["ports"] <- outputPorts inputs["settings"] snapshot.Ports
        outputs["inSync"] <-
            PropertyValue(
                snapshot.Owned && snapshot.InSync && snapshot.ActualSettings = parseSettings inputs["settings"],
                IsSecret = containsSecret inputs["settings"],
                Dependencies = inputs["settings"].Dependencies
            )
        outputs

    let private previewValues (inputs: NormalizedInputs) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        for property in outputProperties do outputs[property] <- PropertyValue.Computed
        outputs

    let private requestTimeout (timeout: TimeSpan) = if timeout > TimeSpan.Zero then Some timeout else None

    let runWithTimeout (timeout: TimeSpan option) (outerToken: CancellationToken) (operation: CancellationToken -> Task<'T>) =
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

    let private readResponse (id: string) (urn: Pulumi.Urn) (inputs: ParsedInputs) (snapshot: SshdSnapshot) =
        let response = ReadResponse()
        response.Id <- if snapshot.Owned then (if String.IsNullOrEmpty(id) then stableId urn inputs.Connection else id) else String.Empty
        response.Inputs <- immutableInputs inputs.Values
        response.Outputs <- outputValues inputs.Values snapshot
        response

    let ensureResourceToken requestType =
        if requestType <> ResourceToken then invalidOp "Unexpected resource token for the Dorothy provider."

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
            || (request.NewInputs |> Seq.exists (fun entry ->
                match request.OldInputs.TryGetValue(entry.Key) with
                | true, oldValue -> not (oldValue.Equals(entry.Value))
                | false, _ -> true))
        diffResponse (Nullable<bool>(changed)) (List<string>()) (List<string>()) (Dictionary<string, PropertyDiff>()) false
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
type SshdProvider() =
    inherit Pulumi.Experimental.Provider.Provider()

    static member Version = "0.1.0"
    static member ResourceToken = SshdProviderLogic.resourceToken
    static member Schema = SshdProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- SshdProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SshdProviderLogic.checkConfiguration request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SshdProviderLogic.providerConfigurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        if request.Args.Keys |> Seq.exists (fun key -> key <> "version" && key <> "pluginDownloadURL") then
            invalidOp "Dorothy does not accept custom provider configuration properties."
        Task.FromResult(SshdProviderLogic.providerConfigurationResponse())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SshdProviderLogic.resourceCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SshdProviderLogic.ensureResourceToken request.Type
        Task.FromResult(SshdProviderLogic.makeDiffResponse request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SshdProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = SshdProviderLogic.normalizeForPreviewInputs request.Inputs
            Task.FromResult(SshdProviderLogic.makeCreatePreviewResponse inputs)
        else
            SshdProviderLogic.runWithTimeout (SshdProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = SshdProviderLogic.normalizeForOperationInputs request.Inputs
                    let ownerId = SshdProviderLogic.resourceId request.Urn inputs.Connection
                    let! snapshot = SshdBackend.apply inputs.Connection ownerId inputs.Settings operationToken
                    return SshdProviderLogic.makeCreateResponse ownerId inputs snapshot
                })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        SshdProviderLogic.ensureResourceToken request.Type
        SshdProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = SshdProviderLogic.parseStoredState request.Inputs request.Outputs
                let ownerId = if String.IsNullOrEmpty(request.Id) then SshdProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                let! snapshot = SshdBackend.read inputs.Connection ownerId inputs.Settings operationToken
                return SshdProviderLogic.makeReadResponse request.Id request.Urn inputs snapshot
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SshdProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = SshdProviderLogic.normalizeForPreviewInputs request.NewInputs
            Task.FromResult(SshdProviderLogic.makeUpdatePreviewResponse inputs)
        else
            SshdProviderLogic.runWithTimeout (SshdProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = SshdProviderLogic.normalizeForOperationInputs request.NewInputs
                    let ownerId = if String.IsNullOrEmpty(request.Id) then SshdProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                    let! snapshot = SshdBackend.apply inputs.Connection ownerId inputs.Settings operationToken
                    return SshdProviderLogic.makeUpdateResponse inputs snapshot
                })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        SshdProviderLogic.ensureResourceToken request.Type
        SshdProviderLogic.runWithTimeout (SshdProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = SshdProviderLogic.parseStoredState request.OldInputs request.OldOutputs
                let ownerId = if String.IsNullOrEmpty(request.Id) then SshdProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                do! SshdBackend.delete inputs.Connection ownerId inputs.Settings operationToken
            }) :> Task
