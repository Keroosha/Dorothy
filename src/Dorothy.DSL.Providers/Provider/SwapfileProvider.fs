namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private SwapfileProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:Swapfile"

    [<Literal>]
    let private BytesPerMiB = 1048576L

    type NormalizedInputs =
        { Values: Dictionary<string, PropertyValue>
          HasUnknowns: bool
          Failures: ResizeArray<CheckFailure> }

    type ParsedInputs =
        { Values: Dictionary<string, PropertyValue>
          Connection: SshConnection
          Path: string
          SizeMiB: int
          SizeBytes: int64 }

    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "resources": {
    "keroosha:debian:Swapfile": {
      "description": "Manages one owned swap file and its persistent systemd swap unit on an existing Debian host.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "path": { "type": "string" },
        "sizeMiB": { "type": "integer", "minimum": 1 }
      },
      "requiredInputs": ["connection", "path", "sizeMiB"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "path": { "type": "string" },
        "sizeMiB": { "type": "integer" },
        "owned": { "type": "boolean" },
        "actualPath": { "type": "string" },
        "actualSizeBytes": { "type": "integer" },
        "mode": { "type": "integer" },
        "enabled": { "type": "boolean" },
        "active": { "type": "boolean" },
        "inSync": { "type": "boolean" }
      },
      "required": ["connection", "path", "sizeMiB", "owned", "actualPath", "actualSizeBytes", "mode", "enabled", "active", "inSync"]
    }
  }
}"""

    let private hasControlCharacters (value: string) =
        value |> Seq.exists Char.IsControl

    let private isSafePath (path: string) =
        let validCharacter (character: char) =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character = '_'
            || character = '-'
            || character = '.'
            || character = '+'

        let validSegment (segment: string) =
            segment.Length > 0
            && segment <> "."
            && segment <> ".."
            && (segment |> Seq.forall validCharacter)

        not (String.IsNullOrWhiteSpace path)
        && path[0] = '/'
        && path <> "/"
        && not (path.EndsWith("/", StringComparison.Ordinal))
        && (path.Substring(1).Split('/') |> Array.forall validSegment)

    let private tryGetMap (value: PropertyValue) =
        let mutable result = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&result) then Some result else None

    let private tryGetString (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>
        if value.TryGetString(&result) then Some result else None

    let private tryGetNumber (value: PropertyValue) =
        let mutable result = 0.0
        if value.TryGetNumber(&result) then Some result else None

    let private withDependencies (source: PropertyValue) (replacement: PropertyValue) =
        replacement.WithDependencies(source.Dependencies)

    let private addFailure (failures: ResizeArray<CheckFailure>) property reason =
        failures.Add(CheckFailure(property, reason))

    let private dictionaryFromImmutable (values: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in values do
            result.Add(entry.Key, entry.Value)
        result

    let private normalizeInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        let failures = ResizeArray<CheckFailure>()
        let mutable hasUnknowns = false

        for entry in values do
            if entry.Key <> "connection" && entry.Key <> "path" && entry.Key <> "sizeMiB" then
                addFailure failures entry.Key "This resource property is not supported."

        match values.TryGetValue("connection") with
        | false, _ -> addFailure failures "connection" "This property is required."
        | true, source when source.IsComputed ->
            hasUnknowns <- true
            normalized["connection"] <- source
        | true, source ->
            match tryGetMap source with
            | None -> addFailure failures "connection" "Expected an SSH connection object."
            | Some connectionValues ->
                let connection = Dictionary<string, PropertyValue>(StringComparer.Ordinal)

                for entry in connectionValues do
                    if entry.Key <> "address" && entry.Key <> "user" && entry.Key <> "port" && entry.Key <> "identityFile" then
                        addFailure failures ("connection." + entry.Key) "This connection property is not supported."

                let normalizeRequiredString name validate reason =
                    match connectionValues.TryGetValue(name) with
                    | false, _ -> addFailure failures ("connection." + name) "This property is required."
                    | true, value when value.IsComputed ->
                        hasUnknowns <- true
                        connection[name] <- value
                    | true, value ->
                        match tryGetString value with
                        | None -> addFailure failures ("connection." + name) "Expected a string."
                        | Some text ->
                            let canonical = text.Trim()
                            if String.IsNullOrWhiteSpace(canonical) || not (validate canonical) then
                                addFailure failures ("connection." + name) reason
                            else
                                connection[name] <- withDependencies value (PropertyValue(canonical))

                normalizeRequiredString
                    "address"
                    (fun text ->
                        not (text.StartsWith("-", StringComparison.Ordinal))
                        && not (text.Contains('@'))
                        && not (text |> Seq.exists Char.IsWhiteSpace)
                        && not (hasControlCharacters text))
                    "Expected a non-empty SSH host address without whitespace or '@'."

                normalizeRequiredString
                    "user"
                    (fun text ->
                        not (text.StartsWith("-", StringComparison.Ordinal))
                        && not (text.Contains('/'))
                        && not (text.Contains('@'))
                        && not (text |> Seq.exists Char.IsWhiteSpace)
                        && not (hasControlCharacters text))
                    "Expected a non-empty SSH user without whitespace, '/', or '@'."

                match connectionValues.TryGetValue("port") with
                | false, _ -> connection["port"] <- PropertyValue(22.0)
                | true, value when value.IsComputed ->
                    hasUnknowns <- true
                    connection["port"] <- value
                | true, value when value.IsNull -> connection["port"] <- PropertyValue(22.0)
                | true, value ->
                    match tryGetNumber value with
                    | Some number when not (Double.IsNaN(number) || Double.IsInfinity(number)) && number = Math.Truncate(number) && number >= 1.0 && number <= 65535.0 ->
                        connection["port"] <- withDependencies value (PropertyValue(number))
                    | _ -> addFailure failures "connection.port" "Expected an integer SSH port from 1 through 65535."

                match connectionValues.TryGetValue("identityFile") with
                | false, _ -> ()
                | true, value when value.IsComputed ->
                    hasUnknowns <- true
                    connection["identityFile"] <- value
                | true, value when value.IsNull -> ()
                | true, value ->
                    match tryGetString value with
                    | None -> addFailure failures "connection.identityFile" "Expected a string when identityFile is provided."
                    | Some path when String.IsNullOrWhiteSpace(path) -> ()
                    | Some path when hasControlCharacters path -> addFailure failures "connection.identityFile" "identityFile must not contain control characters."
                    | Some path -> connection["identityFile"] <- withDependencies value (PropertyValue(path))

                let connectionMap = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                for entry in connection do
                    connectionMap[entry.Key] <- entry.Value
                normalized["connection"] <- withDependencies source (PropertyValue(connectionMap.ToImmutable()))

        match values.TryGetValue("path") with
        | false, _ -> addFailure failures "path" "This property is required."
        | true, value when value.IsComputed ->
            hasUnknowns <- true
            normalized["path"] <- value
        | true, value ->
            match tryGetString value with
            | Some path when isSafePath path -> normalized["path"] <- withDependencies value (PropertyValue(path))
            | Some _ -> addFailure failures "path" "Expected a canonical absolute swapfile path with safe path components."
            | None -> addFailure failures "path" "Expected a string swapfile path."

        match values.TryGetValue("sizeMiB") with
        | false, _ -> addFailure failures "sizeMiB" "This property is required."
        | true, value when value.IsComputed ->
            hasUnknowns <- true
            normalized["sizeMiB"] <- value
        | true, value ->
            match tryGetNumber value with
            | Some number when not (Double.IsNaN(number) || Double.IsInfinity(number)) && number = Math.Truncate(number) && number >= 1.0 && number <= float Int32.MaxValue ->
                normalized["sizeMiB"] <- withDependencies value (PropertyValue(number))
            | _ -> addFailure failures "sizeMiB" "Expected a positive integer MiB size no larger than Int32.MaxValue."

        { Values = normalized
          HasUnknowns = hasUnknowns
          Failures = failures }

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let message = failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " "
            invalidOp ("Invalid swapfile inputs. " + message)

    let private parseInputs (normalized: NormalizedInputs) =
        failIfFailures normalized.Failures
        if normalized.HasUnknowns then
            invalidOp "Swapfile operations require known inputs."

        let readMap name =
            match normalized.Values.TryGetValue(name) with
            | true, value ->
                match tryGetMap value with
                | Some values -> values
                | None -> invalidOp ("Stored swapfile state has an invalid " + name + ".")
            | false, _ -> invalidOp ("Stored swapfile state is missing " + name + ".")

        let readString (values: ImmutableDictionary<string, PropertyValue>) name =
            match values.TryGetValue(name) with
            | true, value ->
                match tryGetString value with
                | Some text -> text
                | None -> invalidOp ("Stored swapfile state has an invalid " + name + ".")
            | false, _ -> invalidOp ("Stored swapfile state is missing " + name + ".")

        let readNumber (values: ImmutableDictionary<string, PropertyValue>) name =
            match values.TryGetValue(name) with
            | true, value ->
                match tryGetNumber value with
                | Some number -> number
                | None -> invalidOp ("Stored swapfile state has an invalid " + name + ".")
            | false, _ -> invalidOp ("Stored swapfile state is missing " + name + ".")

        let connectionValues = readMap "connection"
        let portNumber = readNumber connectionValues "port"
        if portNumber < 1.0 || portNumber > 65535.0 || portNumber <> Math.Truncate(portNumber) then
            invalidOp "Stored swapfile state has an invalid SSH port."

        let identityFile =
            match connectionValues.TryGetValue("identityFile") with
            | true, value ->
                match tryGetString value with
                | Some path -> Some path
                | None -> invalidOp "Stored swapfile state has an invalid identityFile."
            | false, _ -> None

        let path =
            match normalized.Values.TryGetValue("path") with
            | true, value ->
                match tryGetString value with
                | Some path when isSafePath path -> path
                | _ -> invalidOp "Stored swapfile state has an invalid path."
            | false, _ -> invalidOp "Stored swapfile state is missing path."

        let sizeNumber =
            match normalized.Values.TryGetValue("sizeMiB") with
            | true, value ->
                match tryGetNumber value with
                | Some number when number >= 1.0 && number <= float Int32.MaxValue && number = Math.Truncate(number) -> number
                | _ -> invalidOp "Stored swapfile state has an invalid sizeMiB."
            | false, _ -> invalidOp "Stored swapfile state is missing sizeMiB."

        let sizeMiB = int sizeNumber
        { Values = normalized.Values
          Connection =
            { Address = readString connectionValues "address"
              User = readString connectionValues "user"
              Port = int portNumber
              IdentityFile = identityFile }
          Path = path
          SizeMiB = sizeMiB
          SizeBytes = int64 sizeMiB * BytesPerMiB }

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
        for key in [ "connection"; "path"; "sizeMiB" ] do
            match preferred.TryGetValue(key) with
            | true, value -> result[key] <- value
            | false, _ ->
                match fallback.TryGetValue(key) with
                | true, value -> result[key] <- value
                | false, _ -> ()
        result

    let private immutableInputs (values: Dictionary<string, PropertyValue>) =
        let entries = values |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
        ImmutableDictionary.CreateRange<string, PropertyValue>(entries)

    let private storedInputs preferred fallback =
        inputValuesFromOutputs preferred fallback
        |> immutableInputs
        |> normalizeInputs
        |> parseInputs

    let private stableId (urn: Pulumi.Urn) (connection: SshConnection) =
        urn.ToString() + "::" + connection.Address

    let private addDiff (diffs: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) root path kind inputDiff =
        if not (details.ContainsKey(path)) then
            let propertyDiff = PropertyDiff()
            propertyDiff.Kind <- kind
            propertyDiff.InputDiff <- inputDiff
            details.Add(path, propertyDiff)
            if not (diffs.Contains(root)) then diffs.Add(root)

    let private outputBoolean name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when not value.IsComputed ->
            let mutable result = false
            if value.TryGetBool(&result) then Some result else None
        | _ -> None

    let private outputString name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when not value.IsComputed -> tryGetString value
        | _ -> None

    let private outputNumber name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when not value.IsComputed -> tryGetNumber value
        | _ -> None

    let private snapshotMatches (inputs: ParsedInputs) (outputs: ImmutableDictionary<string, PropertyValue>) =
        outputBoolean "owned" outputs = Some true
        && outputString "actualPath" outputs = Some inputs.Path
        && outputNumber "actualSizeBytes" outputs = Some(float inputs.SizeBytes)
        && outputNumber "mode" outputs = Some 384.0
        && outputBoolean "enabled" outputs = Some true
        && outputBoolean "active" outputs = Some true
        && outputBoolean "inSync" outputs = Some true

    let private makeDiff (request: DiffRequest) =
        let previous = inputValuesFromOutputs request.OldInputs request.OldOutputs

        if String.IsNullOrEmpty(request.Id) && previous.Count = 0 then
            let response = DiffResponse()
            response.Changes <- Nullable<bool>(true)
            response.Diffs <- List<string>()
            response.Replaces <- List<string>()
            response.DetailedDiff <- Dictionary<string, PropertyDiff>()
            response
        elif previous.Count = 0 then
            invalidOp "Stored swapfile state is missing its input declaration."
        else
            let oldNormalized = normalizeInputs (immutableInputs previous)
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
                let oldConnection = oldInputs.Connection
                let newConnection = newInputs.Connection

                if oldConnection.Address <> newConnection.Address then
                    add "connection" "connection.address" PropertyDiffKind.UpdateReplace true
                    replaces.Add("connection.address")
                if oldConnection.Port <> newConnection.Port then add "connection" "connection.port" PropertyDiffKind.Update true
                if oldConnection.User <> newConnection.User then add "connection" "connection.user" PropertyDiffKind.Update true
                if oldConnection.IdentityFile <> newConnection.IdentityFile then add "connection" "connection.identityFile" PropertyDiffKind.Update true
                if oldInputs.Path <> newInputs.Path then add "path" "path" PropertyDiffKind.Update true
                if oldInputs.SizeMiB <> newInputs.SizeMiB then add "sizeMiB" "sizeMiB" PropertyDiffKind.Update true
                if not (snapshotMatches oldInputs request.OldOutputs) then
                    add "inSync" "inSync" PropertyDiffKind.Update false

                let response = DiffResponse()
                response.Changes <- Nullable<bool>(diffs.Count > 0)
                response.Diffs <- List<string>(diffs)
                response.Replaces <- List<string>(replaces)
                response.DetailedDiff <- details
                response.DeleteBeforeReplace <- replaces.Count > 0
                response

    let private outputProperties = [ "owned"; "actualPath"; "actualSizeBytes"; "mode"; "enabled"; "active"; "inSync" ]

    let private outputValues (inputs: ParsedInputs) (snapshot: SwapfileSnapshot) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        outputs["owned"] <- PropertyValue(snapshot.Owned)
        outputs["actualPath"] <- PropertyValue(snapshot.ActualPath)
        outputs["actualSizeBytes"] <- PropertyValue(float snapshot.ActualSizeBytes)
        outputs["mode"] <- PropertyValue(float snapshot.Mode)
        outputs["enabled"] <- PropertyValue(snapshot.Enabled)
        outputs["active"] <- PropertyValue(snapshot.Active)
        outputs["inSync"] <- PropertyValue(snapshot.InSync)
        outputs

    let private previewValues (inputs: NormalizedInputs) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        for property in outputProperties do
            outputs[property] <- PropertyValue.Computed
        outputs

    let private requestTimeout (timeout: TimeSpan) =
        if timeout > TimeSpan.Zero then Some timeout else None

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

    let providerConfigurationDiff (request: DiffRequest) =
        let changed =
            request.OldInputs.Count <> request.NewInputs.Count
            || (request.NewInputs
                |> Seq.exists (fun entry ->
                    match request.OldInputs.TryGetValue(entry.Key) with
                    | true, oldValue -> not (oldValue.Equals(entry.Value))
                    | false, _ -> true))
        let response = DiffResponse()
        response.Changes <- Nullable<bool>(changed)
        response.Diffs <- List<string>()
        response.Replaces <- List<string>()
        response.DetailedDiff <- Dictionary<string, PropertyDiff>()
        response

    let private createPreviewResponse inputs =
        let response = CreateResponse()
        response.Id <- String.Empty
        response.Outputs <- previewValues inputs
        response

    let private createResponse ownerId inputs snapshot =
        let response = CreateResponse()
        response.Id <- ownerId
        response.Outputs <- outputValues inputs snapshot
        response

    let private updatePreviewResponse inputs =
        let response = UpdateResponse()
        response.Outputs <- previewValues inputs
        response

    let private updateResponse inputs snapshot =
        let response = UpdateResponse()
        response.Outputs <- outputValues inputs snapshot
        response

    let private readResponse (id: string) (urn: Pulumi.Urn) inputs snapshot =
        let response = ReadResponse()
        let resourceId = if snapshot.Owned then (if String.IsNullOrEmpty id then stableId urn inputs.Connection else id) else String.Empty
        response.Id <- resourceId
        response.Inputs <- inputs.Values
        response.Outputs <- outputValues inputs snapshot
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
type SwapfileProvider() =
    inherit Pulumi.Experimental.Provider.Provider()

    static member Version = "0.1.0"
    static member ResourceToken = SwapfileProviderLogic.resourceToken
    static member Schema = SwapfileProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- SwapfileProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SwapfileProviderLogic.checkConfiguration request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SwapfileProviderLogic.providerConfigurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        if request.Args.Keys |> Seq.exists (fun key -> key <> "version" && key <> "pluginDownloadURL") then
            invalidOp "Dorothy does not accept custom provider configuration properties."
        Task.FromResult(SwapfileProviderLogic.providerConfigurationResponse ())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SwapfileProviderLogic.resourceCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SwapfileProviderLogic.ensureResourceToken request.Type
        Task.FromResult(SwapfileProviderLogic.makeDiffResponse request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SwapfileProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = SwapfileProviderLogic.normalizeForPreviewInputs request.Inputs
            Task.FromResult(SwapfileProviderLogic.makeCreatePreviewResponse inputs)
        else
            SwapfileProviderLogic.runWithTimeout (SwapfileProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = SwapfileProviderLogic.normalizeForOperationInputs request.Inputs
                    let ownerId = SwapfileProviderLogic.resourceId request.Urn inputs.Connection
                    let! snapshot = SwapfileBackend.apply inputs.Connection ownerId inputs.Path inputs.SizeBytes operationToken
                    return SwapfileProviderLogic.makeCreateResponse ownerId inputs snapshot
                })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        SwapfileProviderLogic.ensureResourceToken request.Type
        SwapfileProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = SwapfileProviderLogic.parseStoredState request.Inputs request.Outputs
                let ownerId = if String.IsNullOrEmpty request.Id then SwapfileProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                let! snapshot = SwapfileBackend.read inputs.Connection ownerId inputs.Path inputs.SizeBytes operationToken
                return SwapfileProviderLogic.makeReadResponse request.Id request.Urn inputs snapshot
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SwapfileProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = SwapfileProviderLogic.normalizeForPreviewInputs request.NewInputs
            Task.FromResult(SwapfileProviderLogic.makeUpdatePreviewResponse inputs)
        else
            SwapfileProviderLogic.runWithTimeout (SwapfileProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = SwapfileProviderLogic.normalizeForOperationInputs request.NewInputs
                    let ownerId = if String.IsNullOrEmpty request.Id then SwapfileProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                    let! snapshot = SwapfileBackend.apply inputs.Connection ownerId inputs.Path inputs.SizeBytes operationToken
                    return SwapfileProviderLogic.makeUpdateResponse inputs snapshot
                })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SwapfileProviderLogic.ensureResourceToken request.Type
        SwapfileProviderLogic.runWithTimeout (SwapfileProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = SwapfileProviderLogic.parseStoredState request.OldInputs request.OldOutputs
                let ownerId = if String.IsNullOrEmpty request.Id then SwapfileProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                do! SwapfileBackend.delete inputs.Connection ownerId inputs.Path inputs.SizeBytes operationToken
            }) :> Task
