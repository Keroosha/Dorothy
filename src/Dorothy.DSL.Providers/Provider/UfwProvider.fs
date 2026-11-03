namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private UfwProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:Ufw"

    type NormalizedInputs =
        { Values: Dictionary<string, PropertyValue>
          HasUnknowns: bool
          Failures: ResizeArray<CheckFailure> }

    type ParsedInputs =
        { Values: Dictionary<string, PropertyValue>
          Connection: SshConnection
          Config: UfwConfig }

    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "resources": {
    "keroosha:debian:Ufw": {
      "description": "Manages an owned rule block and global defaults in UFW on an existing SSH host.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "rules": {
          "type": "array",
          "items": { "type": "array", "items": { "type": "string" } }
        },
        "enabled": { "type": "boolean", "default": true },
        "defaultIn": { "type": "string", "enum": ["allow", "deny", "reject"], "default": "deny" },
        "defaultOut": { "type": "string", "enum": ["allow", "deny", "reject"], "default": "allow" }
      },
      "requiredInputs": ["connection", "rules"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "rules": {
          "type": "array",
          "items": { "type": "array", "items": { "type": "string" } }
        },
        "enabled": { "type": "boolean" },
        "defaultIn": { "type": "string", "enum": ["allow", "deny", "reject"] },
        "defaultOut": { "type": "string", "enum": ["allow", "deny", "reject"] },
        "actualRules": { "type": "array", "items": { "type": "string" } },
        "actualEnabled": { "type": "boolean" },
        "actualDefaultIn": { "type": "string" },
        "actualDefaultOut": { "type": "string" },
        "inSync": { "type": "boolean" }
      },
      "required": ["connection", "rules", "enabled", "defaultIn", "defaultOut", "actualRules", "actualEnabled", "actualDefaultIn", "actualDefaultOut", "inSync"]
    }
  }
}"""

    let private policyNames = Set.ofList [ "allow"; "deny"; "reject" ]
    let private ruleActions = Set.ofList [ "allow"; "deny"; "reject"; "limit" ]
    let private knownProperties = Set.ofList [ "connection"; "rules"; "enabled"; "defaultIn"; "defaultOut" ]
    let private declarativeProperties = [ "connection"; "rules"; "enabled"; "defaultIn"; "defaultOut" ]
    let private outputProperties = [ "actualRules"; "actualEnabled"; "actualDefaultIn"; "actualDefaultOut"; "inSync" ]

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

    let private hasShellOperator (token: string) =
        token
        |> Seq.exists (fun character ->
            character = ';' || character = '|' || character = '&' || character = '<' || character = '>'
            || character = '`' || character = '$' || character = '(' || character = ')' || character = '*'
            || character = '?' || character = '{' || character = '}' || character = '[' || character = ']'
            || character = '\\')

    let private validateRule (index: int) (tokens: string list) (failures: ResizeArray<CheckFailure>) =
        let path = sprintf "rules[%d]" index
        if List.isEmpty tokens then
            addFailure failures path "A firewall rule must contain at least one argument."
        else
            match tokens with
            | "route" :: action :: _ when not (ruleActions.Contains action) ->
                addFailure failures (path + "[1]") "Rule action must be allow, deny, reject, or limit."
            | "route" :: _ :: _ -> ()
            | "route" :: [] ->
                addFailure failures (path + "[0]") "Route rules must be followed by allow, deny, reject, or limit."
            | action :: _ when not (ruleActions.Contains action) ->
                addFailure failures (path + "[0]") "Rule action must be allow, deny, reject, or limit."
            | _ -> ()

            for tokenIndex, token in tokens |> List.indexed do
                let tokenPath = sprintf "%s[%d]" path tokenIndex
                if String.IsNullOrWhiteSpace token then
                    addFailure failures tokenPath "Rule arguments must not be empty."
                elif token |> Seq.exists Char.IsControl then
                    addFailure failures tokenPath "Rule arguments must not contain control characters."
                elif hasShellOperator token then
                    addFailure failures tokenPath "Shell operators are not allowed in rule arguments."
                elif token.StartsWith("-", StringComparison.Ordinal) then
                    addFailure failures tokenPath "Rule options are not allowed."
                elif String.Equals(token, "comment", StringComparison.OrdinalIgnoreCase) then
                    addFailure failures tokenPath "UFW comments are reserved for provider ownership markers."

    let private normalizeRules
        (source: PropertyValue)
        (failures: ResizeArray<CheckFailure>)
        =
        match tryGetArray source with
        | None -> false, source
        | Some rules ->
            let mutable hasUnknown = false
            let normalizedRules = ResizeArray<PropertyValue>()
            for ruleIndex, rule in rules |> Seq.indexed do
                if rule.IsComputed then
                    hasUnknown <- true
                    normalizedRules.Add(rule)
                else
                    match tryGetArray rule with
                    | None ->
                        addFailure failures (sprintf "rules[%d]" ruleIndex) "Expected a rule as an argv array of strings."
                        normalizedRules.Add(rule)
                    | Some argv ->
                        let normalizedArgv = ResizeArray<PropertyValue>()
                        let mutable ruleUnknown = false
                        let mutable allKnownStrings = true
                        let tokens = ResizeArray<string>()
                        for argumentIndex, argument in argv |> Seq.indexed do
                            if argument.IsComputed then
                                hasUnknown <- true
                                ruleUnknown <- true
                                allKnownStrings <- false
                                normalizedArgv.Add(argument)
                            else
                                match tryGetString argument with
                                | Some token ->
                                    tokens.Add(token)
                                    normalizedArgv.Add(argument)
                                | None ->
                                    allKnownStrings <- false
                                    addFailure failures (sprintf "rules[%d][%d]" ruleIndex argumentIndex) "Expected a string rule argument."
                                    normalizedArgv.Add(argument)
                        if not ruleUnknown && allKnownStrings then validateRule ruleIndex (List.ofSeq tokens) failures
                        let argvArray = ImmutableArray.CreateRange<PropertyValue>(normalizedArgv)
                        normalizedRules.Add(withDependencies rule (PropertyValue(argvArray)))
            let array = ImmutableArray.CreateRange<PropertyValue>(normalizedRules)
            hasUnknown, withDependencies source (PropertyValue(array))

    let private normalizePolicy
        (property: string)
        (defaultValue: string)
        (values: ImmutableDictionary<string, PropertyValue>)
        (normalized: Dictionary<string, PropertyValue>)
        (failures: ResizeArray<CheckFailure>)
        =
        match values.TryGetValue(property) with
        | false, _ -> normalized[property] <- PropertyValue(defaultValue); false
        | true, value when value.IsComputed -> normalized[property] <- value; true
        | true, value when value.IsNull -> normalized[property] <- PropertyValue(defaultValue); false
        | true, value ->
            match tryGetString value with
            | None -> addFailure failures property "Expected allow, deny, or reject."; false
            | Some policy ->
                let canonical = policy.Trim().ToLowerInvariant()
                if not (policyNames.Contains canonical) then
                    addFailure failures property "Expected allow, deny, or reject."
                else
                    normalized[property] <- withDependencies value (PropertyValue(canonical))
                false

    let normalizeInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = inputDictionary values
        let failures = ResizeArray<CheckFailure>()
        for key in values.Keys do
            if not (knownProperties.Contains key) then
                addFailure failures key "This resource property is not supported."

        let mutable hasUnknown = hasUnknownInputs values
        if values.Values |> Seq.exists containsSecret then
            for entry in values do
                if containsSecret entry.Value then
                    addFailure failures entry.Key "Secret values are not supported by this resource."
            { Values = normalized; HasUnknowns = hasUnknown; Failures = failures }
        else
            match values.TryGetValue("connection") with
            | false, _ -> addFailure failures "connection" "This property is required."
            | true, value when value.IsComputed -> hasUnknown <- true
            | true, value ->
                match tryGetMap value with
                | None -> addFailure failures "connection" "Expected a connection object."
                | Some connectionValues ->
                    let connectionUnknown, connectionValue = normalizeConnection value connectionValues failures
                    hasUnknown <- hasUnknown || connectionUnknown
                    normalized["connection"] <- connectionValue

            match values.TryGetValue("rules") with
            | false, _ -> addFailure failures "rules" "This property is required."
            | true, value when value.IsComputed -> hasUnknown <- true
            | true, value ->
                match tryGetArray value with
                | None -> addFailure failures "rules" "Expected an array of argv arrays."
                | Some _ ->
                    let rulesUnknown, rulesValue = normalizeRules value failures
                    hasUnknown <- hasUnknown || rulesUnknown
                    normalized["rules"] <- rulesValue

            match values.TryGetValue("enabled") with
            | false, _ -> normalized["enabled"] <- PropertyValue(true)
            | true, value when value.IsComputed -> hasUnknown <- true
            | true, value when value.IsNull -> normalized["enabled"] <- PropertyValue(true)
            | true, value ->
                match tryGetBool value with
                | None -> addFailure failures "enabled" "Expected a boolean."
                | Some enabled -> normalized["enabled"] <- value

            hasUnknown <- normalizePolicy "defaultIn" "deny" values normalized failures || hasUnknown
            hasUnknown <- normalizePolicy "defaultOut" "allow" values normalized failures || hasUnknown
            { Values = normalized; HasUnknowns = hasUnknown; Failures = failures }

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let reasons = failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " "
            invalidOp reasons

    let private failIfUnknown hasUnknown =
        if hasUnknown then invalidOp "Ufw cannot be applied while one or more input values are unknown."

    let private tryMap (value: PropertyValue) =
        match tryGetMap value with
        | Some result -> result
        | None -> invalidOp "connection must be an object."

    let private knownString path (values: ImmutableDictionary<string, PropertyValue>) =
        match values.TryGetValue(path) with
        | true, value ->
            match tryGetString value with
            | Some text -> text
            | None -> invalidOp (path + " must be a known string.")
        | false, _ -> invalidOp (path + " is required.")

    let private parseInputs (values: Dictionary<string, PropertyValue>) =
        let immutableMap (dictionary: Dictionary<string, PropertyValue>) =
            let entries = dictionary |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
            ImmutableDictionary.CreateRange<string, PropertyValue>(entries)

        let connectionValues = values["connection"] |> tryMap
        let address = knownString "address" connectionValues
        let user = knownString "user" connectionValues
        let port =
            match connectionValues.TryGetValue("port") with
            | true, value ->
                let mutable number = 0.0
                if value.TryGetNumber(&number) && number >= 1.0 && number <= 65535.0 then int number
                else invalidOp "connection.port must be a known integer SSH port."
            | false, _ -> 22
        let identityFile =
            match connectionValues.TryGetValue("identityFile") with
            | true, value when value.IsNull -> None
            | true, value -> tryGetString value
            | false, _ -> None
        let rules =
            match tryGetArray values["rules"] with
            | None -> invalidOp "rules must be an argv array."
            | Some entries ->
                entries
                |> Seq.map (fun entry ->
                    match tryGetArray entry with
                    | None -> invalidOp "Each rules entry must be an argv array."
                    | Some argv ->
                        argv
                        |> Seq.map (fun argument ->
                            match tryGetString argument with
                            | Some token -> token
                            | None -> invalidOp "Rule arguments must be known strings.")
                        |> Seq.toList)
                |> Seq.toList
        let enabled =
            match tryGetBool values["enabled"] with
            | Some result -> result
            | None -> invalidOp "enabled must be a known boolean."
        let defaultIn = knownString "defaultIn" (immutableMap values)
        let defaultOut = knownString "defaultOut" (immutableMap values)
        { Values = values
          Connection =
            { Address = address
              User = user
              Port = port
              IdentityFile = identityFile }
          Config =
            { Rules = rules
              Enabled = enabled
              DefaultIn = defaultIn
              DefaultOut = defaultOut } }

    let private normalizedKnownInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = normalizeInputs values
        failIfFailures normalized.Failures
        failIfUnknown normalized.HasUnknowns
        parseInputs normalized.Values

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

    let private stableId (urn: Pulumi.Urn) (connection: SshConnection) =
        urn.ToString() + "::" + connection.Address

    let resourceId (urn: Pulumi.Urn) (connection: SshConnection) = stableId urn connection

    let private stringArrayValue (values: string list) =
        let entries = values |> Seq.map (fun value -> PropertyValue(value))
        PropertyValue(ImmutableArray.CreateRange<PropertyValue>(entries))

    let private outputValues (inputs: ParsedInputs) (snapshot: UfwSnapshot) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        outputs["actualRules"] <- stringArrayValue snapshot.ActualRules
        outputs["actualEnabled"] <- PropertyValue(snapshot.ActualEnabled)
        outputs["actualDefaultIn"] <- PropertyValue(snapshot.ActualDefaultIn)
        outputs["actualDefaultOut"] <- PropertyValue(snapshot.ActualDefaultOut)
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

    let private newDiffResult changes (diffs: ResizeArray<string>) (replaces: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) =
        let response = diffResponse changes (List<string>(diffs)) (List<string>(replaces)) details
        response.DeleteBeforeReplace <- replaces.Count > 0
        response

    let private tryOutputBool name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when value.IsComputed -> None
        | true, value -> tryGetBool value
        | false, _ -> None
    let private tryOutputString name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value -> tryGetString value
        | false, _ -> None

    let private hasUnknownSnapshot (outputs: ImmutableDictionary<string, PropertyValue>) =
        outputProperties
        |> List.exists (fun key ->
            match outputs.TryGetValue(key) with
            | true, value -> containsUnknown value
            | false, _ -> false)

    let private hasMissingSnapshot (outputs: ImmutableDictionary<string, PropertyValue>) =
        outputProperties |> List.exists (fun key -> not (outputs.ContainsKey key))

    let private oldInputValues (request: DiffRequest) =
        inputValuesFromOutputs request.OldInputs request.OldOutputs

    let private makeDiff (request: DiffRequest) =
        let previous = oldInputValues request
        if String.IsNullOrEmpty request.Id && previous.Count = 0 then
            let response = DiffResponse()
            response.Changes <- Nullable<bool>(true)
            response.Diffs <- List<string>()
            response.Replaces <- List<string>()
            response.DetailedDiff <- Dictionary<string, PropertyDiff>()
            response
        elif not (previous.ContainsKey("connection")) || not (previous.ContainsKey("rules")) then
            invalidOp "Stored Ufw state is missing its connection or rules declaration."
        elif hasUnknownSnapshot request.OldOutputs then
            let response = DiffResponse()
            response.Changes <- Nullable<bool>()
            response
        elif hasMissingSnapshot request.OldOutputs then
            invalidOp "Stored Ufw state is missing one or more snapshot properties."
        else
            let oldEntries = previous |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
            let oldImmutable = ImmutableDictionary.CreateRange<string, PropertyValue>(oldEntries)
            let oldNormalized = normalizeInputs oldImmutable
            let newNormalized = normalizeInputs request.NewInputs
            failIfFailures oldNormalized.Failures
            failIfFailures newNormalized.Failures

            if oldNormalized.HasUnknowns || newNormalized.HasUnknowns then
                let response = DiffResponse()
                response.Changes <- Nullable<bool>()
                response
            else
                let oldInputs = parseInputs oldNormalized.Values
                let newInputs = parseInputs newNormalized.Values
                let diffs = ResizeArray<string>()
                let replaces = ResizeArray<string>()
                let details = Dictionary<string, PropertyDiff>(StringComparer.Ordinal)
                let add root path kind inputDiff = addDiff diffs details root path kind inputDiff
                let addReplace path =
                    add "connection" path PropertyDiffKind.UpdateReplace true
                    if not (replaces.Contains(path)) then replaces.Add(path)

                if oldInputs.Connection.Address <> newInputs.Connection.Address then addReplace "connection.address"
                if oldInputs.Connection.Port <> newInputs.Connection.Port then add "connection" "connection.port" PropertyDiffKind.Update true
                if oldInputs.Connection.User <> newInputs.Connection.User then add "connection" "connection.user" PropertyDiffKind.Update true
                if oldInputs.Connection.IdentityFile <> newInputs.Connection.IdentityFile then add "connection" "connection.identityFile" PropertyDiffKind.Update true
                let oldRules = oldInputs.Config.Rules |> List.toArray
                let newRules = newInputs.Config.Rules |> List.toArray
                for ruleIndex in 0 .. max oldRules.Length newRules.Length - 1 do
                    if ruleIndex >= oldRules.Length then
                        add "rules" (sprintf "rules[%d]" ruleIndex) PropertyDiffKind.Add true
                    elif ruleIndex >= newRules.Length then
                        add "rules" (sprintf "rules[%d]" ruleIndex) PropertyDiffKind.Delete true
                    else
                        let oldArguments = oldRules[ruleIndex] |> List.toArray
                        let newArguments = newRules[ruleIndex] |> List.toArray
                        for argumentIndex in 0 .. max oldArguments.Length newArguments.Length - 1 do
                            let path = sprintf "rules[%d][%d]" ruleIndex argumentIndex
                            if argumentIndex >= oldArguments.Length then
                                add "rules" path PropertyDiffKind.Add true
                            elif argumentIndex >= newArguments.Length then
                                add "rules" path PropertyDiffKind.Delete true
                            elif oldArguments[argumentIndex] <> newArguments[argumentIndex] then
                                add "rules" path PropertyDiffKind.Update true
                if oldInputs.Config.Enabled <> newInputs.Config.Enabled then add "enabled" "enabled" PropertyDiffKind.Update true
                if oldInputs.Config.DefaultIn <> newInputs.Config.DefaultIn then add "defaultIn" "defaultIn" PropertyDiffKind.Update true
                if oldInputs.Config.DefaultOut <> newInputs.Config.DefaultOut then add "defaultOut" "defaultOut" PropertyDiffKind.Update true
                match tryOutputBool "inSync" request.OldOutputs with

                | Some false ->
                    add "inSync" "inSync" PropertyDiffKind.Update false
                    match tryOutputBool "actualEnabled" request.OldOutputs with
                    | Some actual when actual <> oldInputs.Config.Enabled ->
                        add "actualEnabled" "actualEnabled" PropertyDiffKind.Update false
                    | Some _ -> ()
                    | None -> invalidOp "Stored Ufw state has an invalid actualEnabled snapshot."
                    match tryOutputString "actualDefaultIn" request.OldOutputs with
                    | Some actual when actual <> oldInputs.Config.DefaultIn ->
                        add "actualDefaultIn" "actualDefaultIn" PropertyDiffKind.Update false
                    | Some _ -> ()
                    | None -> invalidOp "Stored Ufw state has an invalid actualDefaultIn snapshot."
                    match tryOutputString "actualDefaultOut" request.OldOutputs with
                    | Some actual when actual <> oldInputs.Config.DefaultOut ->
                        add "actualDefaultOut" "actualDefaultOut" PropertyDiffKind.Update false
                    | Some _ -> ()
                    | None -> invalidOp "Stored Ufw state has an invalid actualDefaultOut snapshot."
                | Some true -> ()
                | None -> invalidOp "Stored Ufw state has an invalid inSync snapshot."

                newDiffResult (diffs.Count > 0) diffs replaces details

    let private ensureToken actual =
        if actual <> ResourceToken then invalidOp "Unexpected resource token for the Dorothy provider."

    let private configurationCheck (request: CheckRequest) =
        let failures = ResizeArray<CheckFailure>()
        for entry in request.NewInputs do
            if entry.Key <> "version" && entry.Key <> "pluginDownloadURL" then
                addFailure failures entry.Key "Dorothy does not accept custom provider configuration properties."
        checkResponse (inputDictionary request.NewInputs) failures

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
        diffResponse changed (List<string>()) (List<string>()) (Dictionary<string, PropertyDiff>())

    let private makeCheckResponse (request: CheckRequest) =
        if request.Type <> ResourceToken then
            let failures = ResizeArray<CheckFailure>()
            addFailure failures "" "Unexpected resource token for the Dorothy provider."
            checkResponse (inputDictionary request.NewInputs) failures
        else
            let normalized = normalizeInputs request.NewInputs
            checkResponse normalized.Values normalized.Failures

    let private normalizeForPreview (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = normalizeInputs values
        failIfFailures normalized.Failures
        normalized

    let private normalizeForOperation values = normalizedKnownInputs values

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

    let private oldConfig (outputs: ImmutableDictionary<string, PropertyValue>) (inputs: ImmutableDictionary<string, PropertyValue>) =
        let source = inputValuesFromOutputs inputs outputs
        let entries = source |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
        let immutable = ImmutableDictionary.CreateRange<string, PropertyValue>(entries)
        normalizedKnownInputs immutable

    let ensureResourceToken requestType = ensureToken requestType
    let providerSchema = schema
    let resourceToken = ResourceToken
    let checkConfiguration = configurationCheck
    let providerConfigurationDiff = diffConfiguration
    let providerConfigurationResponse = configureResponse
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
    let parseStoredState (preferred: ImmutableDictionary<string, PropertyValue>) (fallback: ImmutableDictionary<string, PropertyValue>) = oldConfig fallback preferred

[<Sealed>]
type UfwProvider() =
    inherit Pulumi.Experimental.Provider.Provider()
    static member Version = "0.1.0"
    static member ResourceToken = UfwProviderLogic.resourceToken
    static member Schema = UfwProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- UfwProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(UfwProviderLogic.checkConfiguration request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(UfwProviderLogic.providerConfigurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        if request.Args.Keys |> Seq.exists (fun key -> key <> "version" && key <> "pluginDownloadURL") then
            invalidOp "Dorothy does not accept custom provider configuration properties."
        Task.FromResult(UfwProviderLogic.providerConfigurationResponse())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(UfwProviderLogic.resourceCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        UfwProviderLogic.ensureResourceToken request.Type
        Task.FromResult(UfwProviderLogic.makeDiffResponse request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        UfwProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = UfwProviderLogic.normalizeForPreviewInputs request.Inputs
            Task.FromResult(UfwProviderLogic.makeCreatePreviewResponse inputs)
        else
            UfwProviderLogic.runWithTimeout (UfwProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = UfwProviderLogic.normalizeForOperationInputs request.Inputs
                    let connection = inputs.Connection
                    let ownerId = UfwProviderLogic.resourceId request.Urn connection
                    let! snapshot = UfwBackend.apply connection ownerId inputs.Config operationToken
                    return UfwProviderLogic.makeCreateResponse ownerId inputs snapshot
                })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        UfwProviderLogic.ensureResourceToken request.Type
        UfwProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = UfwProviderLogic.parseStoredState request.Inputs request.Outputs
                let ownerId =
                    if String.IsNullOrEmpty request.Id then UfwProviderLogic.resourceId request.Urn inputs.Connection
                    else request.Id
                let! snapshot = UfwBackend.read inputs.Connection ownerId inputs.Config operationToken
                return UfwProviderLogic.makeReadResponse request.Id request.Urn inputs snapshot
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        UfwProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = UfwProviderLogic.normalizeForPreviewInputs request.NewInputs
            Task.FromResult(UfwProviderLogic.makeUpdatePreviewResponse inputs)
        else
            UfwProviderLogic.runWithTimeout (UfwProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = UfwProviderLogic.normalizeForOperationInputs request.NewInputs
                    let connection = inputs.Connection
                    let ownerId =
                        if String.IsNullOrEmpty request.Id then UfwProviderLogic.resourceId request.Urn connection
                        else request.Id
                    let! snapshot = UfwBackend.apply connection ownerId inputs.Config operationToken
                    return UfwProviderLogic.makeUpdateResponse inputs snapshot
                })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        UfwProviderLogic.ensureResourceToken request.Type
        UfwProviderLogic.runWithTimeout (UfwProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = UfwProviderLogic.parseStoredState request.OldInputs request.OldOutputs
                let ownerId =
                    if String.IsNullOrEmpty request.Id then UfwProviderLogic.resourceId request.Urn inputs.Connection
                    else request.Id
                do! UfwBackend.delete inputs.Connection ownerId inputs.Config operationToken
            }) :> Task
