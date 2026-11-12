namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Text.Json.Nodes
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider
open Dorothy.DSL

module private HostResourceInputs =
    let contentToken = "keroosha:debian:Content"
    let serviceToken = "keroosha:debian:Service"
    let isService token =
        if token <> contentToken && token <> serviceToken then invalidOp "Unexpected host resource token."
        token = serviceToken
    let dictionary (values: ImmutableDictionary<string, PropertyValue>) = Dictionary<string, PropertyValue>(values)
    let immutable (values: IDictionary<string, PropertyValue>) = ImmutableDictionary.CreateRange<string, PropertyValue>(values)
    let stringValue (value: PropertyValue) =
        let mutable text = ""
        if not (value.TryGetString(&text)) then invalidOp "Expected a string property."
        text
    let boolean (value: PropertyValue) =
        let mutable result = false
        if not (value.TryGetBool(&result)) then invalidOp "Expected a boolean property."
        result
    let get name fallback (values: IDictionary<string, PropertyValue>) =
        match values.TryGetValue name with true, value -> value | _ -> fallback
    let text name fallback values = get name (PropertyValue(fallback: string)) values |> stringValue
    let rec unknown (value: PropertyValue) =
        let mutable map = ImmutableDictionary<string, PropertyValue>.Empty
        let mutable array = ImmutableArray<PropertyValue>.Empty
        value.IsComputed || (value.TryGetMap(&map) && map.Values |> Seq.exists unknown) || (value.TryGetArray(&array) && array |> Seq.exists unknown)
    let hasUnknown (values: IDictionary<string, PropertyValue>) = values.Values |> Seq.exists unknown
    let keys service = if service then [ "connection"; "specification"; "triggers"; "restartOnChange" ] else [ "connection"; "specification"; "payload" ]
    let stored service (preferred: ImmutableDictionary<string, PropertyValue>) (fallback: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>()
        for key in keys service do
            match preferred.TryGetValue key with
            | true, value -> result[key] <- value
            | _ -> match fallback.TryGetValue key with true, value -> result[key] <- value | _ -> ()
        result
    let connection (values: IDictionary<string, PropertyValue>) =
        let mutable map = ImmutableDictionary<string, PropertyValue>.Empty
        if not (values["connection"].TryGetMap(&map)) then invalidOp "Expected an SSH connection object."
        let values = dictionary map
        let address = text "address" "" values
        let user = text "user" "" values
        let mutable port = 22.
        match values.TryGetValue "port" with
        | true, value -> if not (value.TryGetNumber(&port)) then invalidOp "Invalid SSH port."
        | _ -> ()
        if String.IsNullOrWhiteSpace address || address.StartsWith('-') || address.Contains('@') || address |> Seq.exists (fun c -> Char.IsWhiteSpace c || Char.IsControl c)
           || String.IsNullOrWhiteSpace user || user.StartsWith('-') || user.Contains('@') || user.Contains('/') || user |> Seq.exists (fun c -> Char.IsWhiteSpace c || Char.IsControl c)
           || port < 1. || port > 65535. || port <> Math.Truncate port then invalidOp "Invalid SSH connection."
        let identity = text "identityFile" "" values
        if identity |> Seq.exists Char.IsControl then invalidOp "Invalid SSH identity path."
        { Address = address; User = user; Port = int port; IdentityFile = if identity = "" then None else Some identity }

    let specification (values: IDictionary<string, PropertyValue>) = text "specification" "" values
    let jsonText (node: JsonNode) (key: string) = node[key].GetValue<string>()
    let contentOwnership values = JsonNode.Parse(specification values) |> fun node -> jsonText node "ownership"
    let private validateSpec service (spec: string) =
        let node = JsonNode.Parse(spec).AsObject()
        if service then
            let name = jsonText node "name"
            if String.IsNullOrWhiteSpace name || name.StartsWith('-') || not (name.EndsWith ".service") || name.Length > 248
               || name |> Seq.exists (fun c -> not (Char.IsAsciiLetterOrDigit c || "_.@:-\\".Contains c)) then invalidOp "Invalid service name."
            let managed = node["managed"].GetValue<bool>()
            let config = jsonText node "configuration"
            if managed && (String.IsNullOrWhiteSpace config || not (config.Contains "ExecStart=")) then invalidOp "A managed service requires ExecStart."
            if not managed && config <> "" then invalidOp "A package service cannot own configuration."
            if node.Count <> 3 then invalidOp "Unsupported service specification fields."
        else
            let kind = jsonText node "kind"
            if not (List.contains kind [ "archive"; "download"; "file"; "text"; "directory" ]) then invalidOp "Invalid content kind."
            let ownership = jsonText node "ownership"
            if ownership <> "managed" && ownership <> "createOnly" then invalidOp "Invalid content ownership."
            if kind <> "directory" then
                let hash = jsonText node "sha256"
                if hash.Length <> 64 || not (hash |> Seq.forall Uri.IsHexDigit) then invalidOp "Content SHA-256 is required."
            if kind = "archive" && not (List.contains (jsonText node "format") [ "zip"; "tarGz"; "tarZst" ]) then invalidOp "Invalid archive format."
            let paths = HashSet<string>(StringComparer.Ordinal)
            let targets = node["targets"].AsArray()
            if targets.Count = 0 || (kind <> "archive" && targets.Count <> 1) then invalidOp "Invalid content target count."
            for target in targets do
                let path = jsonText target "path"
                if String.IsNullOrWhiteSpace path || not (path.StartsWith('/')) || path = "/" || System.IO.Path.GetFullPath path <> path || path.EndsWith('/')
                   || path.Contains("//") || path.Split('/') |> Array.exists (fun part -> part = "." || part = "..") || path |> Seq.exists Char.IsControl
                   || not (paths.Add path) then invalidOp "Content target paths must be distinct canonical absolute paths."
                let mode = target["mode"].GetValue<int>()
                if mode < 0 || mode > 0o7777 then invalidOp "Invalid content mode."
                for key in [ "owner"; "group" ] do
                    if not (isNull target[key]) then
                        let identity = jsonText target key
                        if String.IsNullOrWhiteSpace identity || identity.StartsWith('-') || identity |> Seq.exists (fun c -> Char.IsWhiteSpace c || Char.IsControl c || c = ':' || c = '/') then invalidOp "Invalid content ownership identity."
                if kind = "archive" then
                    let source = jsonText target "source"
                    if String.IsNullOrWhiteSpace source || source.StartsWith('/') || source.Contains('\\') || source |> Seq.exists Char.IsControl
                       || source.Split('/') |> Array.exists (fun part -> part = "" || part = "." || part = "..") then invalidOp "Invalid archive member."
            let allowed = set [ "kind"; "ownership"; "sha256"; "format"; "targets"; "headerNames" ]
            for entry in node do if not (allowed.Contains entry.Key) then invalidOp "Unsupported content specification field."
            for name in node["headerNames"].AsArray() do
                let name = name.GetValue<string>()
                if String.IsNullOrEmpty name || name |> Seq.exists (fun c -> not (Char.IsAsciiLetterOrDigit c || "!#$%&'*+-.^_`|~".Contains c)) then invalidOp "Invalid header name."

    let check service (inputs: ImmutableDictionary<string, PropertyValue>) =
        let values = dictionary inputs
        let failures = List<CheckFailure>()
        for entry in inputs do if not (List.contains entry.Key (keys service)) then failures.Add(CheckFailure(entry.Key, "Unsupported property."))
        for key in [ "connection"; "specification" ] do
            if not (values.ContainsKey key) then failures.Add(CheckFailure(key, "Required property."))
        if service then
            if not (values.ContainsKey "triggers") then values["triggers"] <- PropertyValue "[]"
            if not (values.ContainsKey "restartOnChange") then values["restartOnChange"] <- PropertyValue true
        else
            if values.ContainsKey "payload" then values["payload"] <- values["payload"].WithSecret(true)
        if failures.Count = 0 then
            if not (unknown values["connection"]) then
                try connection values |> ignore with _ -> failures.Add(CheckFailure("connection", "Invalid SSH connection."))
            if not (unknown values["specification"]) then
                try validateSpec service (specification values) with _ -> failures.Add(CheckFailure("specification", "Invalid content/service specification; check paths, required fields and metadata."))
            if service then
                try
                    if not (unknown values["restartOnChange"]) then boolean values["restartOnChange"] |> ignore
                    if not (unknown values["triggers"]) then JsonNode.Parse(stringValue values["triggers"]).AsArray() |> ignore
                with _ -> failures.Add(CheckFailure("triggers", "Invalid service restart inputs."))
        values, failures
    let checkedInputs service inputs =
        let values, failures = check service inputs
        if failures.Count <> 0 then invalidOp "Invalid content/service resource inputs."
        values
    let identity service values =
        let spec = specification values
        if service then spec else HostContentInputs.identity spec
    let replacementIdentity service values =
        let node = JsonNode.Parse(specification values)
        if service then jsonText node "name" + string (node["managed"].GetValue<bool>())
        else jsonText node "kind" + (node["targets"].AsArray() |> Seq.map (fun target -> jsonText target "path") |> String.concat "\n")
    let outputs service (values: IDictionary<string, PropertyValue>) (exists: bool) (inSync: bool) hashes actualHashes =
        let result = Dictionary<string, PropertyValue>()
        for key in keys service do
            if key <> "payload" && values.ContainsKey key then result[key] <- values[key]
        result["exists"] <- PropertyValue exists
        result["inSync"] <- PropertyValue inSync
        if not service then
            result["hashes"] <- PropertyValue(hashes: string).WithSecret(values["specification"].IsSecret)
            result["actualHashes"] <- PropertyValue(actualHashes: string).WithSecret(values["specification"].IsSecret)
            result["fingerprint"] <- PropertyValue(if contentOwnership values = "createOnly" then "" else HostContentInputs.fingerprint (specification values)).WithSecret(values["specification"].IsSecret)
        result
    let preview service values =
        let result = Dictionary<string, PropertyValue>(values: IDictionary<string, PropertyValue>)
        result.Remove "payload" |> ignore
        for key in (if service then [ "exists"; "inSync" ] else [ "exists"; "inSync"; "hashes"; "actualHashes"; "fingerprint" ]) do result[key] <- PropertyValue.Computed
        result
    let hashState (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue "hashes" with true, value -> stringValue value | _ -> "{}"

    let schema =
        let root = JsonObject()
        root["name"] <- JsonValue.Create "keroosha"
        root["version"] <- JsonValue.Create "0.1.0"
        let resources = JsonObject()
        for service, token in [ false, contentToken; true, serviceToken ] do
            let resource = JsonObject()
            let inputs = JsonObject()
            inputs["connection"] <- JsonNode.Parse "{\"$ref\":\"#/types/keroosha:debian:SshConnection\"}"
            inputs["specification"] <- JsonNode.Parse "{\"type\":\"string\"}"
            if service then
                inputs["triggers"] <- JsonNode.Parse "{\"type\":\"string\"}"
                inputs["restartOnChange"] <- JsonNode.Parse "{\"type\":\"boolean\"}"
            else inputs["payload"] <- JsonNode.Parse "{\"type\":\"string\",\"secret\":true}"
            resource["inputProperties"] <- inputs
            resource["requiredInputs"] <- JsonNode.Parse "[\"connection\",\"specification\"]"
            let properties = inputs.DeepClone().AsObject()
            properties.Remove "payload" |> ignore
            properties["exists"] <- JsonNode.Parse "{\"type\":\"boolean\"}"
            properties["inSync"] <- JsonNode.Parse "{\"type\":\"boolean\"}"
            if not service then
                for key in [ "hashes"; "actualHashes"; "fingerprint" ] do properties[key] <- JsonNode.Parse "{\"type\":\"string\"}"
            resource["properties"] <- properties
            resources[token] <- resource
        root["resources"] <- resources
        root.ToJsonString()

/// Independent content and service resources share only input/lifecycle plumbing.
type ContentServicesProvider() =
    inherit Pulumi.Experimental.Provider.Provider()
    static member ContentToken = HostResourceInputs.contentToken
    static member ServiceToken = HostResourceInputs.serviceToken
    static member Schema = HostResourceInputs.schema

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let service = HostResourceInputs.isService request.Type
        let values, failures = HostResourceInputs.check service request.NewInputs
        Task.FromResult(CheckResponse(Inputs = values, Failures = failures))

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let service = HostResourceInputs.isService request.Type
        let fresh = HostResourceInputs.checkedInputs service request.NewInputs
        let old = HostResourceInputs.stored service request.OldInputs request.OldOutputs
        let response = DiffResponse(Diffs = List<string>(), Replaces = List<string>(), DetailedDiff = Dictionary<string, PropertyDiff>())
        if HostResourceInputs.hasUnknown fresh then response.Changes <- Nullable()
        elif old.Count = 0 then response.Changes <- Nullable true
        else
            let add key replace input =
                response.Diffs.Add key
                if replace then response.Replaces.Add key
                response.DetailedDiff[key] <- PropertyDiff(Kind = (if replace then PropertyDiffKind.UpdateReplace else PropertyDiffKind.Update), InputDiff = input)
            if HostResourceInputs.connection old <> HostResourceInputs.connection fresh then
                add "connection" ((HostResourceInputs.connection old).Address <> (HostResourceInputs.connection fresh).Address) true
            if HostResourceInputs.identity service old <> HostResourceInputs.identity service fresh then
                add "specification" (HostResourceInputs.replacementIdentity service old <> HostResourceInputs.replacementIdentity service fresh) true
            if service then
                for key in [ "triggers"; "restartOnChange" ] do
                    if not ((HostResourceInputs.get key PropertyValue.Null old).Equals fresh[key]) then add key false true
            match request.OldOutputs.TryGetValue "inSync" with
            | true, value when not value.IsComputed && not (HostResourceInputs.boolean value) -> add "inSync" false false
            | _ -> ()
            response.Changes <- Nullable(response.Diffs.Count > 0)
            response.DeleteBeforeReplace <- response.Replaces.Count > 0
        Task.FromResult response

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        task {
            let service = HostResourceInputs.isService request.Type
            let values = HostResourceInputs.checkedInputs service request.Inputs
            if request.Preview then return CreateResponse(Id = "", Outputs = HostResourceInputs.preview service values)
            else
                if HostResourceInputs.hasUnknown values then invalidOp "Host resource creation requires known inputs."
                use linked = CancellationTokenSource.CreateLinkedTokenSource ct
                if request.Timeout > TimeSpan.Zero then linked.CancelAfter request.Timeout
                let connection = HostResourceInputs.connection values
                let spec = HostResourceInputs.specification values
                let id = request.Urn.ToString() + "::" + connection.Address
                if service then
                    let! snapshot = ServiceBackend.invoke connection "apply" spec false linked.Token
                    return CreateResponse(Id = id, Outputs = HostResourceInputs.outputs true values snapshot.Exists snapshot.InSync "{}" "{}")
                else
                    let! snapshot = ContentBackend.invoke connection "apply" spec (HostResourceInputs.text "payload" "{}" values) "{}" linked.Token
                    return CreateResponse(Id = id, Outputs = HostResourceInputs.outputs false values snapshot.Exists snapshot.InSync snapshot.Hashes snapshot.Hashes)
        }

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        task {
            let service = HostResourceInputs.isService request.Type
            let values = HostResourceInputs.stored service request.Inputs request.Outputs
            if values.ContainsKey "payload" then values["payload"] <- values["payload"].WithSecret(true)
            let connection = HostResourceInputs.connection values
            let spec = HostResourceInputs.specification values
            if service then
                let! snapshot = ServiceBackend.invoke connection "read" spec false ct
                // Preserve identity when stopped/missing so drift is repaired as Update rather than seed-replacement.
                return ReadResponse(Id = request.Id, Inputs = values, Outputs = HostResourceInputs.outputs true values snapshot.Exists snapshot.InSync "{}" "{}")
            else
                let hashes = HostResourceInputs.hashState request.Outputs
                let! snapshot = ContentBackend.invoke connection "read" spec "{}" hashes ct
                return ReadResponse(Id = request.Id, Inputs = values, Outputs = HostResourceInputs.outputs false values snapshot.Exists snapshot.InSync hashes snapshot.Hashes)
        }

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        task {
            let service = HostResourceInputs.isService request.Type
            let values = HostResourceInputs.checkedInputs service request.NewInputs
            if request.Preview then return UpdateResponse(Outputs = HostResourceInputs.preview service values)
            else
                if HostResourceInputs.hasUnknown values then invalidOp "Host resource update requires known inputs."
                use linked = CancellationTokenSource.CreateLinkedTokenSource ct
                if request.Timeout > TimeSpan.Zero then linked.CancelAfter request.Timeout
                let connection = HostResourceInputs.connection values
                let spec = HostResourceInputs.specification values
                if service then
                    let old = HostResourceInputs.stored true request.OldInputs request.OldOutputs
                    let restart = HostResourceInputs.boolean values["restartOnChange"] && HostResourceInputs.text "triggers" "[]" old <> HostResourceInputs.text "triggers" "[]" values
                    let! snapshot = ServiceBackend.invoke connection "apply" spec restart linked.Token
                    return UpdateResponse(Outputs = HostResourceInputs.outputs true values snapshot.Exists snapshot.InSync "{}" "{}")
                else
                    let hashes = HostResourceInputs.hashState request.OldOutputs
                    let knownPresent =
                        match request.OldOutputs.TryGetValue "exists", request.OldOutputs.TryGetValue "inSync" with
                        | (true, exists), (true, inSync) when not exists.IsComputed && not inSync.IsComputed ->
                            HostResourceInputs.boolean exists && HostResourceInputs.boolean inSync
                        | _ -> false
                    let old = HostResourceInputs.stored false request.OldInputs request.OldOutputs
                    let keepSeed =
                        knownPresent && HostResourceInputs.contentOwnership values = "createOnly"
                        && HostResourceInputs.contentOwnership old = "createOnly"
                        && HostResourceInputs.replacementIdentity false old = HostResourceInputs.replacementIdentity false values
                    if keepSeed then
                        return UpdateResponse(Outputs = HostResourceInputs.outputs false values true true hashes hashes)
                    else
                        let! snapshot = ContentBackend.invoke connection "apply" spec (HostResourceInputs.text "payload" "{}" values) hashes linked.Token
                        return UpdateResponse(Outputs = HostResourceInputs.outputs false values snapshot.Exists snapshot.InSync snapshot.Hashes snapshot.Hashes)
        }

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        task {
            let service = HostResourceInputs.isService request.Type
            let values = HostResourceInputs.stored service request.OldInputs request.OldOutputs
            use linked = CancellationTokenSource.CreateLinkedTokenSource ct
            if request.Timeout > TimeSpan.Zero then linked.CancelAfter request.Timeout
            let connection = HostResourceInputs.connection values
            let spec = HostResourceInputs.specification values
            if service then
                let! _ = ServiceBackend.invoke connection "delete" spec false linked.Token
                ()
            elif HostResourceInputs.contentOwnership values <> "createOnly" then
                let! _ = ContentBackend.invoke connection "delete" spec "{}" "{}" linked.Token
                ()
        } :> Task
