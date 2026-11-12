namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private FirewalldProviderLogic =
    let tokens = [ "keroosha:debian:FirewalldZone"; "keroosha:debian:FirewalldPolicy" ]
    let kind token =
        if token = tokens[0] then "zone"
        elif token = tokens[1] then "policy"
        else invalidOp "Unexpected firewalld resource token."

    let schema =
        let resource = """{"inputProperties":{"connection":{"$ref":"#/types/keroosha:debian:SshConnection"},"configuration":{"type":"string"}},"requiredInputs":["connection","configuration"],"properties":{"connection":{"$ref":"#/types/keroosha:debian:SshConnection"},"configuration":{"type":"string"},"exists":{"type":"boolean"},"actual":{"type":"string"},"inSync":{"type":"boolean"}},"required":["connection","configuration","exists","actual","inSync"]}"""
        "{\"name\":\"keroosha\",\"version\":\"0.1.0\",\"resources\":{" + (tokens |> List.map (fun token -> "\"" + token + "\":" + resource) |> String.concat ",") + "}}"

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
                with _ -> addFailure failures "configuration" "Invalid firewalld configuration, fields, target, port, priority or resource kind."
        normalized, unknown, failures

    let immutable (values: Dictionary<string, PropertyValue>) =
        ImmutableDictionary.CreateRange(values |> Seq.map (fun p -> KeyValuePair(p.Key, p.Value)))

    let requireValid (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            invalidOp (failures |> Seq.map (fun f -> f.Property + ": " + f.Reason) |> String.concat " ")

    let parse token values =
        let normalized, unknown, failures = normalize token values
        requireValid failures
        if unknown then invalidOp "Firewalld inputs must be known before applying."
        let fields = tryGetMap normalized["connection"] |> Option.get
        let text key = tryGetString fields[key] |> Option.get
        let mutable port = 0.0
        fields["port"].TryGetNumber(&port) |> ignore
        let connection =
            { Address = text "address"; User = text "user"; Port = int port
              IdentityFile = match fields.TryGetValue "identityFile" with true, v -> tryGetString v | _ -> None }
        normalized, connection, (tryGetString normalized["configuration"] |> Option.get)

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
        | None -> for key in [ "exists"; "actual"; "inSync" ] do result[key] <- PropertyValue.Computed
        | Some s ->
            result["exists"] <- PropertyValue s.Exists
            result["actual"] <- PropertyValue s.Actual
            result["inSync"] <- PropertyValue s.InSync
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
            let oldValues, oldConnection, oldText = parse request.Type previous
            let newValues, newConnection, newText = parse request.Type request.NewInputs
            let oldConfig, newConfig = FirewalldModel.parse oldText, FirewalldModel.parse newText
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
            if oldText <> newText then add "configuration" (oldConfig.Name <> newConfig.Name) true
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
            response.DeleteBeforeReplace <- replaces.Count > 0
        response

/// One provider implementation for independently owned zone and policy resources.
[<Sealed>]
type FirewalldProvider() =
    inherit Pulumi.Experimental.Provider.Provider()
    static member ZoneToken = "keroosha:debian:FirewalldZone"
    static member PolicyToken = "keroosha:debian:FirewalldPolicy"
    static member Handles token = List.contains token FirewalldProviderLogic.tokens
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
                let owner = FirewalldProviderLogic.owner request.Urn connection
                let! snapshot = FirewalldBackend.apply connection owner configuration token
                let response = CreateResponse()
                response.Id <- owner
                response.Outputs <- FirewalldProviderLogic.outputs values (Some snapshot)
                return response
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
                let response = UpdateResponse()
                response.Outputs <- FirewalldProviderLogic.outputs values (Some snapshot)
                return response
            })

    override _.Read(request, ct) =
        FirewalldProviderLogic.run TimeSpan.Zero ct (fun token -> task {
            let values, connection, configuration = FirewalldProviderLogic.parse request.Type (FirewalldProviderLogic.stored request.Inputs request.Outputs)
            let owner = if String.IsNullOrEmpty request.Id then FirewalldProviderLogic.owner request.Urn connection else request.Id
            let! snapshot = FirewalldBackend.read connection owner configuration token
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
        }) :> Task
