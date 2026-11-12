namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private SudoProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:Sudo"

    type NormalizedInputs =
        { Values: Dictionary<string, PropertyValue>
          HasUnknowns: bool
          Failures: ResizeArray<CheckFailure> }

    type ParsedInputs =
        { Values: Dictionary<string, PropertyValue>
          Connection: SshConnection
          Grants: SudoGrant list }

    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "resources": {
    "keroosha:debian:Sudo": {
      "description": "Manages this Pulumi resource's owned sudo policy grants on an existing Debian host.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "grants": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "subjects": {
                "type": "array",
                "items": {
                  "type": "object",
                  "additionalProperties": false,
                  "properties": {
                    "kind": { "type": "string", "enum": ["user", "group"] },
                    "name": { "type": "string" }
                  },
                  "required": ["kind", "name"]
                }
              },
              "runAs": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "kind": { "type": "string", "enum": ["all", "specific"] },
                  "user": { "type": "string" },
                  "group": { "type": "string" }
                },
                "required": ["kind"]
              },
              "authentication": { "type": "string", "enum": ["required", "passwordless"], "default": "required" },
              "allCommands": { "type": "boolean", "default": false },
              "commands": {
                "type": "array",
                "items": {
                  "type": "object",
                  "additionalProperties": false,
                  "properties": {
                    "path": { "type": "string" },
                    "arguments": {
                      "type": "object",
                      "additionalProperties": false,
                      "properties": {
                        "kind": { "type": "string", "enum": ["none", "exact", "glob", "any"] },
                        "value": { "type": "string" }
                      },
                      "required": ["kind"]
                    }
                  },
                  "required": ["path", "arguments"]
                }
              }
            },
            "required": ["subjects", "runAs"]
          }
        }
      },
      "requiredInputs": ["connection", "grants"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "grants": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "subjects": { "type": "array", "items": { "type": "object", "additionalProperties": false, "properties": { "kind": { "type": "string", "enum": ["user", "group"] }, "name": { "type": "string" } }, "required": ["kind", "name"] } },
              "runAs": { "type": "object", "additionalProperties": false, "properties": { "kind": { "type": "string", "enum": ["all", "specific"] }, "user": { "type": "string" }, "group": { "type": "string" } }, "required": ["kind"] },
              "authentication": { "type": "string", "enum": ["required", "passwordless"] },
              "allCommands": { "type": "boolean" },
              "commands": { "type": "array", "items": { "type": "object", "additionalProperties": false, "properties": { "path": { "type": "string" }, "arguments": { "type": "object", "additionalProperties": false, "properties": { "kind": { "type": "string", "enum": ["none", "exact", "glob", "any"] }, "value": { "type": "string" } }, "required": ["kind"] } }, "required": ["path", "arguments"] } }
            },
            "required": ["subjects", "runAs"]
          }
        },
        "exists": { "type": "boolean" },
        "inSync": { "type": "boolean" },
        "actual": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "filePath": { "type": "string" },
            "filePresent": { "type": "boolean" },
            "fileSha256": { "type": "string", "description": "SHA-256 when the owned policy file is present; null otherwise." },
            "fileMode": { "type": "integer", "description": "File mode when the policy file is present; null otherwise." },
            "fileOwnerUid": { "type": "integer", "description": "Owner UID when the policy file is present; null otherwise." },
            "grants": { "type": "array", "items": { "type": "object", "additionalProperties": false, "properties": { "name": { "type": "string" }, "effectiveVerified": { "type": "boolean" }, "coverage": { "type": "string", "enum": ["direct-user", "nss-enumerated-group-members", "empty-group-structural", "unresolved-principal"] } }, "required": ["name", "effectiveVerified", "coverage"] } }
          },
          "required": ["filePath", "filePresent", "fileSha256", "fileMode", "fileOwnerUid", "grants"]
        }
      },
      "required": ["connection", "grants", "exists", "inSync", "actual"]
    }
  }
}"""

    let private knownProperties = Set.ofList [ "connection"; "grants" ]
    let private outputProperties = [ "exists"; "inSync"; "actual" ]
    let private diffSnapshotProperties = [ "exists"; "inSync" ]

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

    let private withDependencies (source: PropertyValue) (replacement: PropertyValue) =
        replacement.WithDependencies(source.Dependencies)

    let private addFailure (failures: ResizeArray<CheckFailure>) property reason =
        failures.Add(CheckFailure(property, reason))

    let private dictionaryFromImmutable (values: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in values do
            result.Add(entry.Key, entry.Value)
        result

    let private immutableMap (values: Dictionary<string, PropertyValue>) =
        let entries = values |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
        ImmutableDictionary.CreateRange<string, PropertyValue>(entries)

    let private buildMap (values: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in values do
            builder[key] <- value
        builder.ToImmutable()

    let private mapWithDependencies (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) =
        withDependencies source (PropertyValue(values))

    let private hasInvalidCharacter (value: string) =
        value |> Seq.exists (fun character -> Char.IsControl(character) || Char.IsWhiteSpace(character))

    let private isAsciiLower (character: char) = character >= 'a' && character <= 'z'
    let private isAsciiDigit (character: char) = character >= '0' && character <= '9'

    let private isValidLoginName allowDollar (name: string) =
        if String.IsNullOrEmpty(name) || name.Length > 32 then
            false
        else
            let body, hasDollar =
                if name.EndsWith("$", StringComparison.Ordinal) then name.Substring(0, name.Length - 1), true
                else name, false
            not (hasDollar && not allowDollar)
            && body.Length > 0
            && (isAsciiLower body[0] || body[0] = '_')
            && (body |> Seq.forall (fun character ->
                isAsciiLower character || isAsciiDigit character || character = '_' || character = '-'))

    let private isValidGrantName (name: string) =
        not (String.IsNullOrEmpty(name))
        && name.Length <= 64
        && ((isAsciiLower name[0]) || (name[0] >= 'A' && name[0] <= 'Z') || isAsciiDigit name[0] || name[0] = '_')
        && (name |> Seq.forall (fun character ->
            isAsciiLower character
            || (character >= 'A' && character <= 'Z')
            || isAsciiDigit character
            || character = '_'
            || character = '-'))

    let private isValidCommandPath (path: string) =
        let validCharacter character =
            isAsciiLower character
            || (character >= 'A' && character <= 'Z')
            || isAsciiDigit character
            || character = '_'
            || character = '-'
            || character = '.'
            || character = '+'
            || character = '@'
        not (String.IsNullOrEmpty(path))
        && path[0] = '/'
        && path <> "/"
        && not (path.EndsWith("/", StringComparison.Ordinal))
        && (path.Substring(1).Split('/')
            |> Array.forall (fun segment ->
                segment.Length > 0
                && segment <> "."
                && segment <> ".."
                && (segment |> Seq.forall validCharacter)))

    let private isSafeExactArguments (value: string) =
        not (String.IsNullOrEmpty(value))
        && value[0] <> ' '
        && value[value.Length - 1] <> ' '
        && (value |> Seq.forall (fun character ->
            (isAsciiLower character)
            || (character >= 'A' && character <= 'Z')
            || isAsciiDigit character
            || character = ' '
            || character = '_'
            || character = '-'
            || character = '.'
            || character = '/'
            || character = ':'
            || character = '='
            || character = '+'
            || character = ','
            || character = '@'
            || character = '%'
            || character = '*'
            || character = '?'
            || character = '['
            || character = ']'
            || character = '\\'
            || character = '$'
            || character = '^'))

    let private checkFields (allowed: Set<string>) (path: string) (values: ImmutableDictionary<string, PropertyValue>) (failures: ResizeArray<CheckFailure>) =
        for entry in values do
            if not (allowed.Contains(entry.Key)) then
                addFailure failures (path + entry.Key) "This nested property is not supported."

    let private normalizeRequiredText
        (source: ImmutableDictionary<string, PropertyValue>)
        (normalized: Dictionary<string, PropertyValue>)
        (name: string)
        (path: string)
        (validate: string -> bool)
        (reason: string)
        (failures: ResizeArray<CheckFailure>)
        =
        match source.TryGetValue(name) with
        | false, _ -> addFailure failures (path + name) "This property is required."
        | true, value when value.IsComputed -> normalized[name] <- value
        | true, value ->
            match tryGetString value with
            | None -> addFailure failures (path + name) "Expected a string."
            | Some text ->
                if String.IsNullOrWhiteSpace(text) || not (validate text) then
                    addFailure failures (path + name) reason
                else
                    normalized[name] <- withDependencies value (PropertyValue(text))

    let private normalizeOptionalText
        (source: ImmutableDictionary<string, PropertyValue>)
        (normalized: Dictionary<string, PropertyValue>)
        (name: string)
        (path: string)
        (validate: string -> bool)
        (reason: string)
        (failures: ResizeArray<CheckFailure>)
        =
        match source.TryGetValue(name) with
        | false, _ -> ()
        | true, value when value.IsComputed -> normalized[name] <- value
        | true, value when value.IsNull -> normalized.Remove(name) |> ignore
        | true, value ->
            match tryGetString value with
            | None -> addFailure failures (path + name) "Expected a string when this property is provided."
            | Some text ->
                if String.IsNullOrWhiteSpace(text) || not (validate text) then
                    addFailure failures (path + name) reason
                else
                    normalized[name] <- withDependencies value (PropertyValue(text))

    let private normalizeEnum
        (source: ImmutableDictionary<string, PropertyValue>)
        (normalized: Dictionary<string, PropertyValue>)
        (name: string)
        (path: string)
        (allowed: Set<string>)
        (defaultValue: string option)
        (failures: ResizeArray<CheckFailure>)
        =
        match source.TryGetValue(name) with
        | false, _ ->
            match defaultValue with
            | Some value -> normalized[name] <- PropertyValue(value)
            | None -> addFailure failures (path + name) "This property is required."
        | true, value when value.IsComputed -> normalized[name] <- value
        | true, value when value.IsNull ->
            match defaultValue with
            | Some fallback -> normalized[name] <- withDependencies value (PropertyValue(fallback))
            | None -> addFailure failures (path + name) "This property is required."
        | true, value ->
            match tryGetString value with
            | Some text when allowed.Contains(text) -> normalized[name] <- withDependencies value (PropertyValue(text))
            | Some _ -> addFailure failures (path + name) ("Expected one of: " + (allowed |> Seq.sort |> String.concat ", ") + ".")
            | None -> addFailure failures (path + name) "Expected a string."

    let private normalizeRequiredBoolean
        (source: ImmutableDictionary<string, PropertyValue>)
        (normalized: Dictionary<string, PropertyValue>)
        (name: string)
        (path: string)
        (defaultValue: bool option)
        (failures: ResizeArray<CheckFailure>)
        =
        match source.TryGetValue(name) with
        | false, _ ->
            match defaultValue with
            | Some value -> normalized[name] <- PropertyValue(value)
            | None -> addFailure failures (path + name) "This property is required."
        | true, value when value.IsComputed -> normalized[name] <- value
        | true, value when value.IsNull ->
            match defaultValue with
            | Some fallback -> normalized[name] <- withDependencies value (PropertyValue(fallback))
            | None -> addFailure failures (path + name) "This property is required."
        | true, value ->
            match tryGetBool value with
            | Some _ -> normalized[name] <- value
            | None -> addFailure failures (path + name) "Expected a boolean."

    let private normalizeConnection
        (source: PropertyValue)
        (values: ImmutableDictionary<string, PropertyValue>)
        (failures: ResizeArray<CheckFailure>)
        =
        checkFields (Set.ofList [ "address"; "user"; "port"; "identityFile" ]) "connection." values failures
        let normalized = dictionaryFromImmutable values
        normalizeRequiredText
            values normalized "address" "connection."
            (fun text ->
                not (text.StartsWith("-", StringComparison.Ordinal))
                && not (text.Contains('@'))
                && not (hasInvalidCharacter text)
                && not (text |> Seq.exists Char.IsControl))
            "Expected a non-empty SSH host address without whitespace or '@'."
            failures
        normalizeRequiredText
            values normalized "user" "connection."
            (fun text ->
                not (text.StartsWith("-", StringComparison.Ordinal))
                && not (text.Contains('/'))
                && not (text.Contains('@'))
                && not (hasInvalidCharacter text)
                && not (text |> Seq.exists Char.IsControl))
            "Expected a non-empty SSH user without whitespace, '/', or '@'."
            failures

        match values.TryGetValue("port") with
        | false, _ -> normalized["port"] <- PropertyValue(22.0)
        | true, value when value.IsComputed -> normalized["port"] <- value
        | true, value when value.IsNull -> normalized["port"] <- PropertyValue(22.0)
        | true, value ->
            match tryGetNumber value with
            | Some number when not (Double.IsNaN(number) || Double.IsInfinity(number)) && number = Math.Truncate(number) && number >= 1.0 && number <= 65535.0 ->
                normalized["port"] <- withDependencies value (PropertyValue(number))
            | _ -> addFailure failures "connection.port" "Expected an integer SSH port from 1 through 65535."

        normalizeOptionalText
            values normalized "identityFile" "connection."
            (fun text -> not (text |> Seq.exists Char.IsControl))
            "identityFile must not contain control characters."
            failures
        mapWithDependencies source (immutableMap normalized)

    let private normalizeSubject (source: PropertyValue) (path: string) (failures: ResizeArray<CheckFailure>) =
        if source.IsComputed then
            source
        else
            match tryGetMap source with
            | None ->
                addFailure failures path "Expected a subject object."
                source
            | Some values ->
                let normalized = dictionaryFromImmutable values
                checkFields (Set.ofList [ "kind"; "name" ]) (path + ".") values failures
                normalizeEnum values normalized "kind" (path + ".") (Set.ofList [ "user"; "group" ]) None failures
                normalizeRequiredText
                    values normalized "name" (path + ".")
                    (fun name -> isValidLoginName true name)
                    "Expected a conservative local user or group name."
                    failures
                match normalized.TryGetValue("kind"), normalized.TryGetValue("name") with
                | (true, kindValue), (true, nameValue) ->
                    match tryGetString kindValue, tryGetString nameValue with
                    | Some "group", Some name when not (isValidLoginName false name) ->
                        addFailure failures (path + ".name") "Group names must use a conservative local group identifier."
                    | _ -> ()
                | _ -> ()
                withDependencies source (PropertyValue(immutableMap normalized))

    let private normalizeSubjects (source: PropertyValue) (path: string) (failures: ResizeArray<CheckFailure>) =
        if source.IsComputed then
            source
        else
            match tryGetArray source with
            | None ->
                addFailure failures path "Expected an array of sudo subjects."
                source
            | Some subjects ->
                let normalized = ResizeArray<PropertyValue>()
                let seen = HashSet<string>(StringComparer.Ordinal)
                for index, subject in subjects |> Seq.indexed do
                    let item = normalizeSubject subject (sprintf "%s[%d]" path index) failures
                    normalized.Add(item)
                    match tryGetMap item with
                    | Some fields ->
                        match fields.TryGetValue("kind"), fields.TryGetValue("name") with
                        | (true, kindValue), (true, nameValue) ->
                            match tryGetString kindValue, tryGetString nameValue with
                            | Some kind, Some name ->
                                if not (seen.Add(kind + "\u0000" + name)) then
                                    addFailure failures (sprintf "%s[%d]" path index) "Duplicate sudo subjects are not allowed."
                            | _ -> ()
                        | _ -> ()
                    | None -> ()
                if subjects.Length = 0 then addFailure failures path "At least one sudo subject is required."
                withDependencies source (PropertyValue(ImmutableArray.CreateRange<PropertyValue>(normalized)))

    let private normalizeRunAs (source: PropertyValue) (path: string) (failures: ResizeArray<CheckFailure>) =
        if source.IsComputed then
            source
        else
            match tryGetMap source with
            | None ->
                addFailure failures path "Expected a run-as object."
                source
            | Some values ->
                let normalized = dictionaryFromImmutable values
                checkFields (Set.ofList [ "kind"; "user"; "group" ]) (path + ".") values failures
                normalizeEnum values normalized "kind" (path + ".") (Set.ofList [ "all"; "specific" ]) None failures
                normalizeOptionalText
                    values normalized "user" (path + ".") (isValidLoginName true)
                    "Expected a conservative local run-as user name."
                    failures
                normalizeOptionalText
                    values normalized "group" (path + ".") (isValidLoginName false)
                    "Expected a conservative local run-as group name."
                    failures
                match normalized.TryGetValue("kind") with
                | true, kindValue ->
                    match tryGetString kindValue with
                    | Some "all" ->
                        for name in [ "user"; "group" ] do
                            match normalized.TryGetValue(name) with
                            | true, value when value.IsComputed -> ()
                            | true, _ -> addFailure failures (path + "." + name) "Run-as kind 'all' cannot specify a user or group."
                            | false, _ -> ()
                    | Some "specific" ->
                        match normalized.TryGetValue("user") with
                        | true, value when value.IsComputed -> ()
                        | true, _ -> ()
                        | false, _ -> addFailure failures (path + ".user") "Run-as kind 'specific' requires an explicit user."
                    | _ -> ()
                | false, _ -> ()
                withDependencies source (PropertyValue(immutableMap normalized))

    let private normalizeArguments (source: PropertyValue) (path: string) (failures: ResizeArray<CheckFailure>) =
        if source.IsComputed then
            source
        else
            match tryGetMap source with
            | None ->
                addFailure failures path "Expected a command arguments object."
                source
            | Some values ->
                let normalized = dictionaryFromImmutable values
                checkFields (Set.ofList [ "kind"; "value" ]) (path + ".") values failures
                normalizeEnum values normalized "kind" (path + ".") (Set.ofList [ "none"; "exact"; "glob"; "any" ]) None failures
                normalizeOptionalText
                    values normalized "value" (path + ".") isSafeExactArguments
                    "Exact sudo arguments must use supported printable ASCII and cannot contain controls, '#', quotes, or leading/trailing spaces."
                    failures
                match normalized.TryGetValue("kind"), normalized.TryGetValue("value") with
                | (true, kindValue), valueField ->
                    match tryGetString kindValue with
                    | Some "exact" ->
                        match valueField with
                        | true, value when value.IsComputed -> ()
                        | true, _ -> ()
                        | false, _ -> addFailure failures (path + ".value") "Arguments kind 'exact' requires a literal value."
                    | Some "glob" ->
                        match valueField with
                        | true, value when value.IsComputed -> ()
                        | true, value ->
                            match tryGetString value with
                            | Some pattern when (pattern.Contains('*') || pattern.Contains('?')) && pattern.IndexOfAny([| '['; ']'; '\\' |]) < 0 -> ()
                            | _ -> addFailure failures (path + ".value") "Arguments kind 'glob' requires a pattern with * or ? and without [ ] or \\."
                        | false, _ -> addFailure failures (path + ".value") "Arguments kind 'glob' requires a pattern."
                    | Some "none"
                    | Some "any" ->
                        match valueField with
                        | true, value when value.IsComputed -> ()
                        | true, _ -> addFailure failures (path + ".value") "Arguments kind 'none' or 'any' cannot specify a value."
                        | false, _ -> ()
                    | _ -> ()
                | _ -> ()
                withDependencies source (PropertyValue(immutableMap normalized))

    let private normalizeCommand (source: PropertyValue) (path: string) (failures: ResizeArray<CheckFailure>) =
        if source.IsComputed then
            source
        else
            match tryGetMap source with
            | None ->
                addFailure failures path "Expected a sudo command object."
                source
            | Some values ->
                let normalized = dictionaryFromImmutable values
                checkFields (Set.ofList [ "path"; "arguments" ]) (path + ".") values failures
                normalizeRequiredText
                    values normalized "path" (path + ".") isValidCommandPath
                    "Expected a canonical absolute executable path with safe path components."
                    failures
                match values.TryGetValue("arguments") with
                | false, _ -> addFailure failures (path + ".arguments") "This property is required."
                | true, value -> normalized["arguments"] <- normalizeArguments value (path + ".arguments") failures
                withDependencies source (PropertyValue(immutableMap normalized))

    let private normalizeCommands (source: PropertyValue) (path: string) (failures: ResizeArray<CheckFailure>) =
        if source.IsComputed then
            source
        else
            match tryGetArray source with
            | None ->
                addFailure failures path "Expected an array of sudo command objects."
                source
            | Some commands ->
                let normalized = ResizeArray<PropertyValue>()
                let seen = HashSet<string>(StringComparer.Ordinal)
                for index, command in commands |> Seq.indexed do
                    let item = normalizeCommand command (sprintf "%s[%d]" path index) failures
                    normalized.Add(item)
                    match tryGetMap item with
                    | Some fields ->
                        match fields.TryGetValue("path"), fields.TryGetValue("arguments") with
                        | (true, pathValue), (true, argsValue) ->
                            match tryGetString pathValue, tryGetMap argsValue with
                            | Some commandPath, Some args ->
                                match args.TryGetValue("kind"), args.TryGetValue("value") with
                                | (true, kindValue), (false, _) ->
                                    match tryGetString kindValue with
                                    | Some ("none" | "any") ->
                                        let key = commandPath + "\u0000" + (tryGetString kindValue |> Option.defaultValue "?")
                                        if not (seen.Add(key)) then
                                            addFailure failures (sprintf "%s[%d]" path index) "Duplicate sudo commands are not allowed."
                                    | _ -> ()
                                | (true, kindValue), (true, argValue) ->
                                    match tryGetString kindValue, tryGetString argValue with
                                    | Some ("exact" | "glob" as kind), Some value ->
                                        let key = commandPath + "\u0000" + kind + "\u0000" + value
                                        if not (seen.Add(key)) then
                                            addFailure failures (sprintf "%s[%d]" path index) "Duplicate sudo commands are not allowed."
                                    | _ -> ()
                                | _ -> ()
                            | _ -> ()
                        | _ -> ()
                    | None -> ()
                withDependencies source (PropertyValue(ImmutableArray.CreateRange<PropertyValue>(normalized)))

    let private normalizeGrant (grantName: string) (source: PropertyValue) (path: string) (failures: ResizeArray<CheckFailure>) =
        if not (isValidGrantName grantName) then
            addFailure failures ("grants." + grantName) "Grant names must be 1-64 ASCII letters, digits, underscores, or hyphens and cannot contain dots."

        if source.IsComputed then
            source
        else
            match tryGetMap source with
            | None ->
                addFailure failures ("grants." + grantName) "Expected a sudo grant object."
                source
            | Some values ->
                let normalized = dictionaryFromImmutable values
                checkFields (Set.ofList [ "subjects"; "runAs"; "authentication"; "allCommands"; "commands" ]) (path + ".") values failures
                match values.TryGetValue("subjects") with
                | false, _ -> addFailure failures (path + ".subjects") "This property is required."
                | true, value -> normalized["subjects"] <- normalizeSubjects value (path + ".subjects") failures
                match values.TryGetValue("runAs") with
                | false, _ -> addFailure failures (path + ".runAs") "This property is required."
                | true, value -> normalized["runAs"] <- normalizeRunAs value (path + ".runAs") failures
                normalizeEnum values normalized "authentication" (path + ".") (Set.ofList [ "required"; "passwordless" ]) (Some "required") failures
                normalizeRequiredBoolean values normalized "allCommands" (path + ".") (Some false) failures
                match values.TryGetValue("commands") with
                | false, _ -> normalized["commands"] <- PropertyValue(ImmutableArray<PropertyValue>.Empty)
                | true, value when value.IsNull -> normalized["commands"] <- withDependencies value (PropertyValue(ImmutableArray<PropertyValue>.Empty))
                | true, value -> normalized["commands"] <- normalizeCommands value (path + ".commands") failures

                match normalized.TryGetValue("allCommands"), normalized.TryGetValue("commands") with
                | (true, allValue), (true, commandsValue) ->
                    match tryGetBool allValue, tryGetArray commandsValue with
                    | Some true, Some commands when commands.Length > 0 ->
                        addFailure failures (path + ".commands") "allCommands and explicit commands are mutually exclusive."
                    | Some false, Some commands when commands.Length = 0 ->
                        addFailure failures (path + ".commands") "At least one command is required when allCommands is false."
                    | _ -> ()
                | _ -> ()
                withDependencies source (PropertyValue(immutableMap normalized))

    let private normalizeGrants (source: PropertyValue) (failures: ResizeArray<CheckFailure>) =
        if source.IsComputed then
            source
        else
            match tryGetMap source with
            | None ->
                addFailure failures "grants" "Expected an object keyed by sudo grant name."
                source
            | Some grants ->
                let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
                for entry in grants do
                    let path = "grants." + entry.Key
                    normalized[entry.Key] <- normalizeGrant entry.Key entry.Value path failures
                mapWithDependencies source (immutableMap normalized)

    let normalizeInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = dictionaryFromImmutable values
        let failures = ResizeArray<CheckFailure>()
        for entry in values do
            if not (knownProperties.Contains(entry.Key)) then
                addFailure failures entry.Key "This resource property is not supported."

        let hasSecrets = values.Values |> Seq.exists containsSecret
        if hasSecrets then
            for entry in values do
                if containsSecret entry.Value then
                    addFailure failures entry.Key "Secret values are not supported by the sudo resource."
        else
            match values.TryGetValue("connection") with
            | false, _ -> addFailure failures "connection" "This property is required."
            | true, source when source.IsComputed -> ()
            | true, source ->
                match tryGetMap source with
                | None -> addFailure failures "connection" "Expected an SSH connection object."
                | Some connection -> normalized["connection"] <- normalizeConnection source connection failures

            match values.TryGetValue("grants") with
            | false, _ -> addFailure failures "grants" "This property is required."
            | true, source -> normalized["grants"] <- normalizeGrants source failures

        let hasUnknowns = normalized.Values |> Seq.exists containsUnknown
        { Values = normalized
          HasUnknowns = hasUnknowns
          Failures = failures }

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let reasons = failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " "
            invalidOp ("Invalid sudo inputs. " + reasons)

    let private immutableInputs (values: Dictionary<string, PropertyValue>) =
        let entries = values |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
        ImmutableDictionary.CreateRange<string, PropertyValue>(entries)

    let private parseKnownString (values: ImmutableDictionary<string, PropertyValue>) name =
        match values.TryGetValue(name) with
        | true, value ->
            match tryGetString value with
            | Some text -> text
            | None -> invalidOp ("Stored sudo state has an invalid " + name + ".")
        | false, _ -> invalidOp ("Stored sudo state is missing " + name + ".")

    let private parseOptionalString (values: ImmutableDictionary<string, PropertyValue>) name =
        match values.TryGetValue(name) with
        | true, value ->
            match tryGetString value with
            | Some text -> Some text
            | None -> invalidOp ("Stored sudo state has an invalid " + name + ".")
        | false, _ -> None

    let private parseKnownBool (values: ImmutableDictionary<string, PropertyValue>) name =
        match values.TryGetValue(name) with
        | true, value ->
            match tryGetBool value with
            | Some result -> result
            | None -> invalidOp ("Stored sudo state has an invalid " + name + ".")
        | false, _ -> invalidOp ("Stored sudo state is missing " + name + ".")

    let private parseConnection (value: PropertyValue) =
        match tryGetMap value with
        | None -> invalidOp "Stored sudo state has an invalid connection object."
        | Some fields ->
            let port =
                match fields.TryGetValue("port") with
                | true, value ->
                    match tryGetNumber value with
                    | Some number when number = Math.Truncate(number) && number >= 1.0 && number <= 65535.0 -> int number
                    | _ -> invalidOp "Stored sudo state has an invalid SSH port."
                | false, _ -> 22
            { Address = parseKnownString fields "address"
              User = parseKnownString fields "user"
              Port = port
              IdentityFile = parseOptionalString fields "identityFile" }

    let private parseSubject (value: PropertyValue) =
        match tryGetMap value with
        | None -> invalidOp "Stored sudo state has an invalid subject."
        | Some fields ->
            { Kind = parseKnownString fields "kind"
              Name = parseKnownString fields "name" }

    let private parseRunAs (value: PropertyValue) =
        match tryGetMap value with
        | None -> invalidOp "Stored sudo state has an invalid runAs object."
        | Some fields ->
            { Kind = parseKnownString fields "kind"
              User = parseOptionalString fields "user"
              Group = parseOptionalString fields "group" }

    let private parseArguments (value: PropertyValue) =
        match tryGetMap value with
        | None -> invalidOp "Stored sudo state has invalid command arguments."
        | Some fields ->
            { Kind = parseKnownString fields "kind"
              Value = parseOptionalString fields "value" }

    let private parseCommand (value: PropertyValue) =
        match tryGetMap value with
        | None -> invalidOp "Stored sudo state has an invalid command."
        | Some fields ->
            match fields.TryGetValue("arguments") with
            | true, args ->
                { Path = parseKnownString fields "path"
                  Arguments = parseArguments args }
            | false, _ -> invalidOp "Stored sudo state is missing command arguments."

    let private parseGrant (name: string) (value: PropertyValue) =
        match tryGetMap value with
        | None -> invalidOp ("Stored sudo state has an invalid grant '" + name + "'.")
        | Some fields ->
            let subjects =
                match fields.TryGetValue("subjects") with
                | true, value ->
                    match tryGetArray value with
                    | Some values -> values |> Seq.map parseSubject |> Seq.toList
                    | None -> invalidOp "Stored sudo state has invalid grant subjects."
                | false, _ -> invalidOp "Stored sudo state is missing grant subjects."
            let runAs =
                match fields.TryGetValue("runAs") with
                | true, value -> parseRunAs value
                | false, _ -> invalidOp "Stored sudo state is missing grant runAs."
            let commands =
                match fields.TryGetValue("commands") with
                | true, value ->
                    match tryGetArray value with
                    | Some values -> values |> Seq.map parseCommand |> Seq.toList
                    | None -> invalidOp "Stored sudo state has invalid grant commands."
                | false, _ -> []
            { Name = name
              Subjects = subjects
              RunAs = runAs
              Authentication =
                match fields.TryGetValue("authentication") with
                | true, value ->
                    match tryGetString value with
                    | Some text -> text
                    | None -> invalidOp "Stored sudo state has invalid grant authentication."
                | false, _ -> "required"
              AllCommands =
                match fields.TryGetValue("allCommands") with
                | true, value ->
                    match tryGetBool value with
                    | Some result -> result
                    | None -> invalidOp "Stored sudo state has invalid allCommands."
                | false, _ -> false
              Commands = commands }

    let private parseInputs (normalized: NormalizedInputs) =
        failIfFailures normalized.Failures
        if normalized.HasUnknowns then
            invalidOp "Sudo operations require known inputs."

        let connection =
            match normalized.Values.TryGetValue("connection") with
            | true, value -> parseConnection value
            | false, _ -> invalidOp "Stored sudo state is missing connection."
        let grants =
            match normalized.Values.TryGetValue("grants") with
            | true, value ->
                match tryGetMap value with
                | Some values ->
                    values
                    |> Seq.map (fun entry -> parseGrant entry.Key entry.Value)
                    |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left.Name, right.Name))
                    |> Seq.toList
                | None -> invalidOp "Stored sudo state has an invalid grants object."
            | false, _ -> invalidOp "Stored sudo state is missing grants."
        { Values = normalized.Values
          Connection = connection
          Grants = grants }

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
        for key in [ "connection"; "grants" ] do
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

    let private addDiff (diffs: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) root path kind inputDiff =
        if not (details.ContainsKey(path)) then
            let propertyDiff = PropertyDiff()
            propertyDiff.Kind <- kind
            propertyDiff.InputDiff <- inputDiff
            details.Add(path, propertyDiff)
            if not (diffs.Contains(root)) then diffs.Add(root)

    let private outputBool name (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue(name) with
        | true, value when not value.IsComputed -> tryGetBool value
        | _ -> None

    let private containsOutputUnknown (outputs: ImmutableDictionary<string, PropertyValue>) =
        diffSnapshotProperties
        |> List.exists (fun name ->
            match outputs.TryGetValue(name) with
            | true, value -> containsUnknown value
            | false, _ -> false)

    let private hasMissingSnapshot (outputs: ImmutableDictionary<string, PropertyValue>) =
        diffSnapshotProperties |> List.exists (fun name -> not (outputs.ContainsKey(name)))

    let private comparePropertyValues
        (add: string -> string -> PropertyDiffKind -> bool -> unit)
        (root: string)
        (path: string)
        (oldValue: PropertyValue)
        (newValue: PropertyValue)
        =
        let rec compare path oldValue newValue =
            match tryGetMap oldValue, tryGetMap newValue with
            | Some oldMap, Some newMap ->
                let keys = Seq.append oldMap.Keys newMap.Keys |> Seq.distinct |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
                for key in keys do
                    let childPath = path + "." + key
                    match oldMap.TryGetValue(key), newMap.TryGetValue(key) with
                    | (true, _), (false, _) -> add root childPath PropertyDiffKind.Delete true
                    | (false, _), (true, _) -> add root childPath PropertyDiffKind.Add true
                    | (true, oldChild), (true, newChild) -> compare childPath oldChild newChild
                    | _ -> ()
            | _ ->
                match tryGetArray oldValue, tryGetArray newValue with
                | Some oldArray, Some newArray ->
                    for index in 0 .. max oldArray.Length newArray.Length - 1 do
                        let childPath = sprintf "%s[%d]" path index
                        if index >= oldArray.Length then add root childPath PropertyDiffKind.Add true
                        elif index >= newArray.Length then add root childPath PropertyDiffKind.Delete true
                        else compare childPath oldArray[index] newArray[index]
                | _ when not (oldValue.Equals(newValue)) -> add root path PropertyDiffKind.Update true
                | _ -> ()
        compare path oldValue newValue

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
            invalidOp "Stored sudo state is missing its input declaration."
        elif containsOutputUnknown request.OldOutputs then
            let response = DiffResponse()
            response.Changes <- Nullable<bool>()
            response
        elif hasMissingSnapshot request.OldOutputs then
            invalidOp "Stored sudo state is missing one or more snapshot properties."
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

                if oldInputs.Connection.Address <> newInputs.Connection.Address then
                    add "connection" "connection.address" PropertyDiffKind.UpdateReplace true
                    replaces.Add("connection.address")
                if oldInputs.Connection.User <> newInputs.Connection.User then add "connection" "connection.user" PropertyDiffKind.Update true
                if oldInputs.Connection.Port <> newInputs.Connection.Port then add "connection" "connection.port" PropertyDiffKind.Update true
                if oldInputs.Connection.IdentityFile <> newInputs.Connection.IdentityFile then add "connection" "connection.identityFile" PropertyDiffKind.Update true

                match oldNormalized.Values.TryGetValue("grants"), newNormalized.Values.TryGetValue("grants") with
                | (true, oldGrants), (true, newGrants) -> comparePropertyValues add "grants" "grants" oldGrants newGrants
                | _ -> invalidOp "Stored sudo state is missing grants."

                let exists = outputBool "exists" request.OldOutputs
                let inSync = outputBool "inSync" request.OldOutputs
                match exists, inSync with
                | Some oldExists, Some oldInSync ->
                    if not oldExists || not oldInSync then
                        add "inSync" "inSync" PropertyDiffKind.Update false
                | _ -> invalidOp "Stored sudo state has an invalid ownership or inSync snapshot."

                let response = DiffResponse()
                response.Changes <- Nullable<bool>(diffs.Count > 0)
                response.Diffs <- List<string>(diffs)
                response.Replaces <- List<string>(replaces)
                response.DetailedDiff <- details
                response.DeleteBeforeReplace <- replaces.Count > 0
                response

    let rec private propertyValueFromJson (element: JsonElement) : PropertyValue =
        match element.ValueKind with
        | JsonValueKind.Object ->
            let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
            for property in element.EnumerateObject() do
                builder[property.Name] <- propertyValueFromJson property.Value
            PropertyValue(builder.ToImmutable())
        | JsonValueKind.Array ->
            let values = element.EnumerateArray() |> Seq.map propertyValueFromJson |> ImmutableArray.CreateRange<PropertyValue>
            PropertyValue(values)
        | JsonValueKind.String ->
            match element.GetString() with
            | null -> PropertyValue.Null
            | text -> PropertyValue(text)
        | JsonValueKind.Number ->
            let mutable integer = 0L
            if element.TryGetInt64(&integer) then PropertyValue(float integer)
            else PropertyValue(element.GetDouble())
        | JsonValueKind.True -> PropertyValue(true)
        | JsonValueKind.False -> PropertyValue(false)
        | JsonValueKind.Null
        | JsonValueKind.Undefined -> PropertyValue.Null
        | _ -> invalidOp "The sudo helper returned an unsupported JSON value."

    let private outputValues (inputs: Dictionary<string, PropertyValue>) (snapshot: SudoSnapshot) =
        let outputs = Dictionary<string, PropertyValue>(inputs, StringComparer.Ordinal)
        use document = JsonDocument.Parse(snapshot.ActualJson)
        outputs["exists"] <- PropertyValue(snapshot.Exists)
        outputs["inSync"] <- PropertyValue(snapshot.InSync)
        outputs["actual"] <- propertyValueFromJson document.RootElement
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

    let private readResponse (id: string) (urn: Pulumi.Urn) (inputs: ParsedInputs) snapshot =
        let response = ReadResponse()
        response.Id <- if snapshot.Exists then (if String.IsNullOrEmpty(id) then stableId urn inputs.Connection else id) else String.Empty
        response.Inputs <- inputs.Values
        response.Outputs <- outputValues inputs.Values snapshot
        response

    let ensureResourceToken requestType =
        if requestType <> ResourceToken then invalidOp "Unexpected resource token for the Dorothy provider."

    let resourceToken = ResourceToken
    let providerSchema = schema
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
    let providerConfigurationResponse = configureResponse
    let checkConfiguration (request: CheckRequest) =
        let failures = ResizeArray<CheckFailure>()
        for entry in request.NewInputs do
            if entry.Key <> "version" && entry.Key <> "pluginDownloadURL" then
                addFailure failures entry.Key "Dorothy does not accept custom provider configuration properties."
        checkResponse (dictionaryFromImmutable request.NewInputs) failures

[<Sealed>]
type SudoProvider() =
    inherit Pulumi.Experimental.Provider.Provider()

    static member Version = "0.1.0"
    static member ResourceToken = SudoProviderLogic.resourceToken
    static member Schema = SudoProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- SudoProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SudoProviderLogic.checkConfiguration request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SudoProviderLogic.providerConfigurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        if request.Args.Keys |> Seq.exists (fun key -> key <> "version" && key <> "pluginDownloadURL") then
            invalidOp "Dorothy does not accept custom provider configuration properties."
        Task.FromResult(SudoProviderLogic.providerConfigurationResponse())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(SudoProviderLogic.resourceCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SudoProviderLogic.ensureResourceToken request.Type
        Task.FromResult(SudoProviderLogic.makeDiffResponse request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SudoProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = SudoProviderLogic.normalizeForPreviewInputs request.Inputs
            Task.FromResult(SudoProviderLogic.makeCreatePreviewResponse inputs)
        else
            SudoProviderLogic.runWithTimeout (SudoProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = SudoProviderLogic.normalizeForOperationInputs request.Inputs
                    let ownerId = SudoProviderLogic.resourceId request.Urn inputs.Connection
                    let! snapshot = SudoBackend.apply inputs.Connection ownerId inputs.Grants operationToken
                    return SudoProviderLogic.makeCreateResponse ownerId inputs snapshot
                })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        SudoProviderLogic.ensureResourceToken request.Type
        SudoProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = SudoProviderLogic.parseStoredState request.Inputs request.Outputs
                let ownerId = if String.IsNullOrEmpty(request.Id) then SudoProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                let! snapshot = SudoBackend.read inputs.Connection ownerId inputs.Grants operationToken
                return SudoProviderLogic.makeReadResponse request.Id request.Urn inputs snapshot
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SudoProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = SudoProviderLogic.normalizeForPreviewInputs request.NewInputs
            Task.FromResult(SudoProviderLogic.makeUpdatePreviewResponse inputs)
        else
            SudoProviderLogic.runWithTimeout (SudoProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = SudoProviderLogic.normalizeForOperationInputs request.NewInputs
                    let ownerId = if String.IsNullOrEmpty(request.Id) then SudoProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                    let! snapshot = SudoBackend.apply inputs.Connection ownerId inputs.Grants operationToken
                    return SudoProviderLogic.makeUpdateResponse inputs snapshot
                })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        SudoProviderLogic.ensureResourceToken request.Type
        SudoProviderLogic.runWithTimeout (SudoProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = SudoProviderLogic.parseStoredState request.OldInputs request.OldOutputs
                let ownerId = if String.IsNullOrEmpty(request.Id) then SudoProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                do! SudoBackend.delete inputs.Connection ownerId inputs.Grants operationToken
            }) :> Task
