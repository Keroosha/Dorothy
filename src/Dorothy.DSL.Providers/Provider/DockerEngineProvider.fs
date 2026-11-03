namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private DockerEngineProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:DockerEngine"

    type NormalizedInputs =
        { Values: Dictionary<string, PropertyValue>
          HasUnknowns: bool
          Failures: ResizeArray<CheckFailure> }

    type ParsedInputs =
        { Values: Dictionary<string, PropertyValue>
          Connection: SshConnection }

    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "resources": {
    "keroosha:debian:DockerEngine": {
      "description": "Ensures the shared Docker Engine service is enabled and active and the SSH user belongs to the docker group.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" }
      },
      "requiredInputs": ["connection"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "serviceEnabled": { "type": "boolean" },
        "serviceActive": { "type": "boolean" },
        "dockerGroupMembership": { "type": "boolean" },
        "inSync": { "type": "boolean" }
      },
      "required": ["connection", "serviceEnabled", "serviceActive", "dockerGroupMembership", "inSync"]
    }
  }
}"""

    let private hasControlCharacters (value: string) =
        value |> Seq.exists (fun character -> Char.IsControl(character))

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
            if entry.Key <> "connection" then
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

        { Values = normalized
          HasUnknowns = hasUnknowns
          Failures = failures }

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let message = failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " "
            invalidOp ("Invalid Docker Engine inputs. " + message)

    let private parseInputs (normalized: NormalizedInputs) =
        failIfFailures normalized.Failures
        if normalized.HasUnknowns then
            invalidOp "Docker Engine operations require known connection inputs."

        let connectionValue = normalized.Values["connection"]
        let connectionValues =
            match tryGetMap connectionValue with
            | Some values -> values
            | None -> invalidOp "Stored Docker Engine state has an invalid connection."

        let readString name =
            match connectionValues.TryGetValue(name) with
            | true, value ->
                match tryGetString value with
                | Some text -> text
                | None -> invalidOp ("Stored Docker Engine state has an invalid connection." + name + ".")
            | false, _ -> invalidOp ("Stored Docker Engine state is missing connection." + name + ".")

        let port =
            match connectionValues.TryGetValue("port") with
            | true, value ->
                match tryGetNumber value with
                | Some number when number >= 1.0 && number <= 65535.0 && number = Math.Truncate(number) -> int number
                | _ -> invalidOp "Stored Docker Engine state has an invalid SSH port."
            | false, _ -> invalidOp "Stored Docker Engine state is missing the SSH port."

        let identityFile =
            match connectionValues.TryGetValue("identityFile") with
            | true, value ->
                match tryGetString value with
                | Some path -> Some path
                | None -> invalidOp "Stored Docker Engine state has an invalid identityFile."
            | false, _ -> None

        { Values = normalized.Values
          Connection =
            { Address = readString "address"
              User = readString "user"
              Port = port
              IdentityFile = identityFile } }

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
        match preferred.TryGetValue("connection") with
        | true, value -> result["connection"] <- value
        | false, _ ->
            match fallback.TryGetValue("connection") with
            | true, value -> result["connection"] <- value
            | false, _ -> ()
        result

    let private immutableInputs (values: Dictionary<string, PropertyValue>) =
        let entries = values |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
        ImmutableDictionary.CreateRange<string, PropertyValue>(entries)

    let private storedInputs preferred fallback =
        let values = inputValuesFromOutputs preferred fallback |> immutableInputs
        normalizeInputs values |> parseInputs

    let private outputProperties = [ "serviceEnabled"; "serviceActive"; "dockerGroupMembership"; "inSync" ]

    let private outputValues (inputs: ParsedInputs) (snapshot: DockerEngineSnapshot) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        outputs["serviceEnabled"] <- PropertyValue(snapshot.ServiceEnabled)
        outputs["serviceActive"] <- PropertyValue(snapshot.ServiceActive)
        outputs["dockerGroupMembership"] <- PropertyValue(snapshot.DockerGroupMembership)
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

    let private diffResponse changes diffs replaces detailed =
        let response = DiffResponse()
        response.Changes <- Nullable<bool>(changes)
        response.Diffs <- diffs
        response.Replaces <- replaces
        response.DetailedDiff <- detailed
        response

    let private addDiff (diffs: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) root path kind inputDiff =
        if not (details.ContainsKey(path)) then
            let propertyDiff = PropertyDiff()
            propertyDiff.Kind <- kind
            propertyDiff.InputDiff <- inputDiff
            details.Add(path, propertyDiff)
            if not (diffs.Contains(root)) then diffs.Add(root)

    let private outputBool name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when not value.IsComputed ->
            let mutable result = false
            if value.TryGetBool(&result) then Some result else None
        | _ -> None

    let private hasUnknownSnapshot (outputs: ImmutableDictionary<string, PropertyValue>) =
        outputProperties
        |> List.exists (fun key ->
            match outputs.TryGetValue(key) with
            | true, value -> value.IsComputed
            | false, _ -> false)

    let private hasMissingSnapshot (outputs: ImmutableDictionary<string, PropertyValue>) =
        outputProperties |> List.exists (fun key -> not (outputs.ContainsKey key))

    let private stableId (urn: Pulumi.Urn) (connection: SshConnection) =
        urn.ToString() + "::" + connection.Address

    let private makeDiff (request: DiffRequest) =
        let previous = inputValuesFromOutputs request.OldInputs request.OldOutputs

        if String.IsNullOrEmpty(request.Id) && previous.Count = 0 then
            let response = DiffResponse()
            response.Changes <- Nullable<bool>(true)
            response.Diffs <- List<string>()
            response.Replaces <- List<string>()
            response.DetailedDiff <- Dictionary<string, PropertyDiff>()
            response
        elif not (previous.ContainsKey("connection")) then
            invalidOp "Stored Docker Engine state is missing its connection declaration."
        elif hasUnknownSnapshot request.OldOutputs then
            let response = DiffResponse()
            response.Changes <- Nullable<bool>()
            response
        elif hasMissingSnapshot request.OldOutputs then
            invalidOp "Stored Docker Engine state is missing one or more snapshot properties."
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

                match outputBool "serviceEnabled" request.OldOutputs,
                      outputBool "serviceActive" request.OldOutputs,
                      outputBool "dockerGroupMembership" request.OldOutputs,
                      outputBool "inSync" request.OldOutputs with
                | Some serviceEnabled, Some serviceActive, Some groupMembership, Some inSync ->
                    if not serviceEnabled then add "serviceEnabled" "serviceEnabled" PropertyDiffKind.Update false
                    if not serviceActive then add "serviceActive" "serviceActive" PropertyDiffKind.Update false
                    if not groupMembership then add "dockerGroupMembership" "dockerGroupMembership" PropertyDiffKind.Update false

                    let snapshotInSync = serviceEnabled && serviceActive && groupMembership
                    if inSync <> snapshotInSync then add "inSync" "inSync" PropertyDiffKind.Update false
                | _ -> invalidOp "Stored Docker Engine state has an invalid service snapshot."

                let response = diffResponse (diffs.Count > 0) (List<string>(diffs)) (List<string>(replaces)) details
                response.DeleteBeforeReplace <- replaces.Count > 0
                response

    let private makeCheckResponse (request: CheckRequest) =
        if request.Type <> ResourceToken then
            let failures = ResizeArray<CheckFailure>()
            addFailure failures "" "Unexpected resource token for the Dorothy provider."
            checkResponse (dictionaryFromImmutable request.NewInputs) failures
        else
            let normalized = normalizeInputs request.NewInputs
            checkResponse normalized.Values normalized.Failures

    let private configureResponse () =
        let response = ConfigureResponse()
        response.AcceptSecrets <- true
        response.AcceptResources <- false
        response.AcceptOutputs <- true
        response.SupportsPreview <- true
        response

    let private diffConfiguration (request: DiffRequest) =
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
        response.Id <- if String.IsNullOrEmpty id then stableId urn inputs.Connection else id
        response.Inputs <- inputs.Values
        response.Outputs <- outputValues inputs snapshot
        response

    let ensureResourceToken requestType =
        if requestType <> ResourceToken then invalidOp "Unexpected resource token for the Dorothy provider."

    let providerSchema = schema
    let resourceToken = ResourceToken
    let checkConfiguration (request: CheckRequest) =
        let failures = ResizeArray<CheckFailure>()
        for entry in request.NewInputs do
            if entry.Key <> "version" && entry.Key <> "pluginDownloadURL" then
                addFailure failures entry.Key "Dorothy does not accept custom provider configuration properties."
        checkResponse (dictionaryFromImmutable request.NewInputs) failures
    let providerConfigurationDiff = diffConfiguration
    let providerConfigurationResponse () = configureResponse ()
    let resourceCheck = makeCheckResponse
    let makeDiffResponse = makeDiff
    let normalizeForPreviewInputs = normalizeForPreview
    let normalizeForOperationInputs = normalizeForOperation
    let timeoutForRequest = requestTimeout
    let makeCreatePreviewResponse = createPreviewResponse
    let makeCreateResponse = createResponse
    let makeUpdatePreviewResponse = updatePreviewResponse
    let makeUpdateResponse = updateResponse
    let makeReadResponse = readResponse
    let parseStoredState preferred fallback = storedInputs preferred fallback
    let resourceId = stableId

[<Sealed>]
type DockerEngineProvider() =
    inherit Pulumi.Experimental.Provider.Provider()
    static member Version = "0.1.0"
    static member ResourceToken = DockerEngineProviderLogic.resourceToken
    static member Schema = DockerEngineProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- DockerEngineProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(DockerEngineProviderLogic.checkConfiguration request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(DockerEngineProviderLogic.providerConfigurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        if request.Args.Keys |> Seq.exists (fun key -> key <> "version" && key <> "pluginDownloadURL") then
            invalidOp "Dorothy does not accept custom provider configuration properties."
        Task.FromResult(DockerEngineProviderLogic.providerConfigurationResponse())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(DockerEngineProviderLogic.resourceCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        DockerEngineProviderLogic.ensureResourceToken request.Type
        Task.FromResult(DockerEngineProviderLogic.makeDiffResponse request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        DockerEngineProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = DockerEngineProviderLogic.normalizeForPreviewInputs request.Inputs
            Task.FromResult(DockerEngineProviderLogic.makeCreatePreviewResponse inputs)
        else
            DockerEngineProviderLogic.runWithTimeout (DockerEngineProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = DockerEngineProviderLogic.normalizeForOperationInputs request.Inputs
                    let ownerId = DockerEngineProviderLogic.resourceId request.Urn inputs.Connection
                    let! snapshot = DockerEngineBackend.apply inputs.Connection operationToken
                    return DockerEngineProviderLogic.makeCreateResponse ownerId inputs snapshot
                })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        DockerEngineProviderLogic.ensureResourceToken request.Type
        DockerEngineProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = DockerEngineProviderLogic.parseStoredState request.Inputs request.Outputs
                let! snapshot = DockerEngineBackend.read inputs.Connection operationToken
                return DockerEngineProviderLogic.makeReadResponse request.Id request.Urn inputs snapshot
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        DockerEngineProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = DockerEngineProviderLogic.normalizeForPreviewInputs request.NewInputs
            Task.FromResult(DockerEngineProviderLogic.makeUpdatePreviewResponse inputs)
        else
            DockerEngineProviderLogic.runWithTimeout (DockerEngineProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = DockerEngineProviderLogic.normalizeForOperationInputs request.NewInputs
                    let! snapshot = DockerEngineBackend.apply inputs.Connection operationToken
                    return DockerEngineProviderLogic.makeUpdateResponse inputs snapshot
                })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        DockerEngineProviderLogic.ensureResourceToken request.Type
        Task.CompletedTask
