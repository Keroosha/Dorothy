namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private DockerJobProviderLogic =
    let token = "keroosha:debian:DockerJob"
    let inputNames = [ "connection"; "containerId"; "timeoutSeconds" ]
    let schema = """{
  "name": "keroosha", "version": "0.1.0",
  "resources": { "keroosha:debian:DockerJob": {
    "description": "Starts a stopped Docker container once and waits for exit zero, retaining it for logs until replacement or deletion.",
    "inputProperties": {
      "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
      "containerId": { "type": "string" }, "timeoutSeconds": { "type": "integer" }
    },
    "requiredInputs": ["connection", "containerId", "timeoutSeconds"],
    "properties": {
      "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
      "containerId": { "type": "string" }, "timeoutSeconds": { "type": "integer" },
      "exists": { "type": "boolean" }, "completed": { "type": "boolean" }
    },
    "required": ["connection", "containerId", "timeoutSeconds", "exists", "completed"]
  }}
}"""

    let immutable (values: seq<KeyValuePair<string, PropertyValue>>) = ImmutableDictionary.CreateRange values
    let connectionOnly (values: ImmutableDictionary<string, PropertyValue>) =
        values |> Seq.filter (fun entry -> entry.Key = "connection") |> immutable

    let normalize (values: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        let failures = List<CheckFailure>()
        let mutable unknown = false
        try
            let connection = DockerEngineProviderLogic.normalizeForPreviewInputs (connectionOnly values)
            unknown <- connection.HasUnknowns
            for entry in connection.Values do result[entry.Key] <- entry.Value
        with :? InvalidOperationException -> failures.Add(CheckFailure("connection", "Invalid SSH connection."))
        for entry in values do
            if not (List.contains entry.Key inputNames) then failures.Add(CheckFailure(entry.Key, "Unsupported Docker job property."))
        for name in [ "containerId"; "timeoutSeconds" ] do
            match values.TryGetValue name with
            | false, _ -> failures.Add(CheckFailure(name, "This property is required."))
            | true, value when value.IsComputed -> unknown <- true; result[name] <- value
            | true, value ->
                let mutable text = ""
                let mutable number = 0.0
                let valid =
                    if name = "containerId" then
                        value.TryGetString(&text) && text.Length = 64 && (text |> Seq.forall (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    else
                        value.TryGetNumber(&number) && number >= 1.0 && number <= 86400.0 && number = Math.Truncate number
                if valid then result[name] <- value
                else failures.Add(CheckFailure(name, if name = "containerId" then "Expected a full lowercase hexadecimal container ID." else "Expected an integer timeout between 1 and 86400 seconds."))
        result, unknown, failures

    let checkedInputs values =
        let result, unknown, failures = normalize values
        if failures.Count <> 0 then invalidOp (failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " ")
        result, unknown

    let stored (preferred: ImmutableDictionary<string, PropertyValue>) (fallback: ImmutableDictionary<string, PropertyValue>) =
        inputNames
        |> Seq.choose (fun name ->
            match preferred.TryGetValue name with
            | true, value -> Some(KeyValuePair(name, value))
            | _ ->
                match fallback.TryGetValue name with
                | true, value -> Some(KeyValuePair(name, value))
                | _ -> None)
        |> immutable

    let outputs (inputs: Dictionary<string, PropertyValue>) (snapshot: DockerJobSnapshot option) =
        let result = Dictionary<string, PropertyValue>(inputs, StringComparer.Ordinal)
        result["exists"] <- snapshot |> Option.map (fun value -> PropertyValue(value.Exists)) |> Option.defaultValue PropertyValue.Computed
        result["completed"] <- snapshot |> Option.map (fun value -> PropertyValue(value.Completed)) |> Option.defaultValue PropertyValue.Computed
        result

    let invoke operation values timeout ct =
        DockerEngineProviderLogic.runWithTimeout (if timeout > TimeSpan.Zero then Some timeout else None) ct (fun operationToken ->
            task {
                let inputs, unknown = checkedInputs values
                if unknown then invalidOp "Docker job operations require known inputs."
                let connection = DockerEngineProviderLogic.normalizeForOperationInputs (connectionOnly (immutable inputs))
                let mutable id = ""
                let mutable seconds = 0.0
                inputs["containerId"].TryGetString(&id) |> ignore
                inputs["timeoutSeconds"].TryGetNumber(&seconds) |> ignore
                let! snapshot = DockerJobBackend.invoke connection.Connection operation id (int seconds) operationToken
                return inputs, snapshot
            })

    let ensureToken actual = if actual <> token then invalidOp "Unexpected Docker job resource token."

[<Sealed>]
type DockerJobProvider() =
    inherit Pulumi.Experimental.Provider.Provider()
    static member ResourceToken = DockerJobProviderLogic.token
    static member Schema = DockerJobProviderLogic.schema

    override _.GetSchema(_, ct) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- DockerJobProviderLogic.schema
        Task.FromResult response

    override _.Check(request, ct) =
        ct.ThrowIfCancellationRequested()
        DockerJobProviderLogic.ensureToken request.Type
        let inputs, _, failures = DockerJobProviderLogic.normalize request.NewInputs
        let response = CheckResponse()
        response.Inputs <- inputs
        response.Failures <- failures
        Task.FromResult response

    override _.Diff(request, ct) =
        ct.ThrowIfCancellationRequested()
        DockerJobProviderLogic.ensureToken request.Type
        let oldInputs, oldUnknown = DockerJobProviderLogic.checkedInputs (DockerJobProviderLogic.stored request.OldInputs request.OldOutputs)
        let newInputs, newUnknown = DockerJobProviderLogic.checkedInputs request.NewInputs
        let response = DiffResponse()
        if oldUnknown || newUnknown then response.Changes <- Nullable()
        else
            let diffs = List<string>()
            let replacements = List<string>()
            let details = Dictionary<string, PropertyDiff>()
            let add name replacement inputDiff =
                diffs.Add name
                if replacement then replacements.Add name
                let detail = PropertyDiff()
                detail.Kind <- if replacement then PropertyDiffKind.UpdateReplace else PropertyDiffKind.Update
                detail.InputDiff <- inputDiff
                details[name] <- detail
            for name in DockerJobProviderLogic.inputNames do
                if not (oldInputs[name].Equals(newInputs[name])) then add name (name = "connection") true
            let mutable completed = false
            match request.OldOutputs.TryGetValue "completed" with
            | true, value when value.TryGetBool(&completed) && completed -> ()
            | _ -> add "completed" false false
            response.Changes <- Nullable(diffs.Count <> 0)
            response.Diffs <- diffs
            response.Replaces <- replacements
            response.DeleteBeforeReplace <- replacements.Count <> 0
            response.DetailedDiff <- details
        Task.FromResult response

    override _.Create(request, ct) =
        ct.ThrowIfCancellationRequested()
        DockerJobProviderLogic.ensureToken request.Type
        task {
            let response = CreateResponse()
            if request.Preview then
                let inputs, _ = DockerJobProviderLogic.checkedInputs request.Inputs
                response.Id <- ""
                response.Outputs <- DockerJobProviderLogic.outputs inputs None
            else
                let! inputs, snapshot = DockerJobProviderLogic.invoke "apply" request.Inputs request.Timeout ct
                response.Id <- request.Urn.ToString()
                response.Outputs <- DockerJobProviderLogic.outputs inputs (Some snapshot)
            return response
        }

    override _.Update(request, ct) =
        ct.ThrowIfCancellationRequested()
        DockerJobProviderLogic.ensureToken request.Type
        task {
            let response = UpdateResponse()
            if request.Preview then
                let inputs, _ = DockerJobProviderLogic.checkedInputs request.NewInputs
                response.Outputs <- DockerJobProviderLogic.outputs inputs None
            else
                let! inputs, snapshot = DockerJobProviderLogic.invoke "apply" request.NewInputs request.Timeout ct
                response.Outputs <- DockerJobProviderLogic.outputs inputs (Some snapshot)
            return response
        }

    override _.Read(request, ct) =
        DockerJobProviderLogic.ensureToken request.Type
        task {
            let! inputs, snapshot = DockerJobProviderLogic.invoke "read" (DockerJobProviderLogic.stored request.Inputs request.Outputs) TimeSpan.Zero ct
            let response = ReadResponse()
            response.Id <- if snapshot.Exists then request.Id else ""
            response.Inputs <- inputs
            response.Outputs <- DockerJobProviderLogic.outputs inputs (Some snapshot)
            return response
        }

    override _.Delete(request, ct) =
        DockerJobProviderLogic.ensureToken request.Type
        task {
            let! _ = DockerJobProviderLogic.invoke "delete" (DockerJobProviderLogic.stored request.OldInputs request.OldOutputs) request.Timeout ct
            return ()
        } :> Task
