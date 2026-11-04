namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Globalization
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private UsersProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:Users"

    type NormalizedInputs =
        { Values: Dictionary<string, PropertyValue>
          HasUnknowns: bool
          Failures: ResizeArray<CheckFailure> }

    type ParsedInputs =
        { Values: Dictionary<string, PropertyValue>
          Connection: SshConnection
          Groups: PropertyValue
          Users: PropertyValue }

    type private Shape =
        | Text of (string -> bool) option
        | Enum of string list
        | Integer of int64 * int64
        | Boolean
        | TextArray of (string -> bool) option
        | Array of Shape
        | Object of Map<string, Shape> * Set<string>

    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "types": {
    "keroosha:debian:UserGroup": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "gid": { "type": "integer", "minimum": 1, "maximum": 2147483647 },
        "kind": { "type": "string", "enum": ["human", "system"] },
        "existing": { "type": "string", "enum": ["reject", "adopt"] },
        "state": { "type": "string", "enum": ["present", "absent"] }
      }
    },
    "keroosha:debian:UserPrimaryGroup": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "kind": { "type": "string", "enum": ["private", "existing"] },
        "name": { "type": "string" }
      },
      "required": ["kind"]
    },
    "keroosha:debian:UserSupplementaryGroups": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "mode": { "type": "string", "enum": ["managed", "exclusive"] },
        "names": { "type": "array", "items": { "type": "string" } }
      },
      "required": ["mode", "names"]
    },
    "keroosha:debian:UserHome": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "kind": { "type": "string", "enum": ["create", "existing", "none"] },
        "path": { "type": "string" },
        "mode": { "type": "integer", "minimum": 0, "maximum": 511 },
        "skeleton": { "type": "string" }
      },
      "required": ["kind"]
    },
    "keroosha:debian:UserPassword": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "kind": { "type": "string", "enum": ["locked", "hash"] },
        "hash": { "type": "string", "secret": true, "minLength": 1, "maxLength": 4096, "pattern": "^\\$[^:\\s]+$" },
        "update": { "type": "string", "enum": ["always", "onCreate"] }
      },
      "required": ["kind"]
    },
    "keroosha:debian:UserAccountExpiry": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "kind": { "type": "string", "enum": ["never", "on"] },
        "date": { "type": "string", "format": "date" }
      },
      "required": ["kind"]
    },
    "keroosha:debian:UserPasswordPolicy": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "minDays": { "type": "integer", "minimum": 0, "maximum": 2147483647 },
        "maxDays": { "type": "integer", "minimum": 0, "maximum": 2147483647 },
        "warnDays": { "type": "integer", "minimum": 0, "maximum": 2147483647 },
        "inactiveDays": { "type": "integer", "minimum": 0, "maximum": 2147483647 }
      }
    },
    "keroosha:debian:UserSubordinateIdRange": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "start": { "type": "integer", "minimum": 1, "maximum": 2147483647 },
        "count": { "type": "integer", "minimum": 1, "maximum": 2147483647 }
      },
      "required": ["start", "count"]
    },
    "keroosha:debian:UserAuthorizedKey": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "id": { "type": "string", "minLength": 1 },
        "publicKey": { "type": "string", "minLength": 1 },
        "comment": { "type": "string" },
        "restrict": { "type": "boolean" },
        "allowPty": { "type": "boolean" },
        "allowAgentForwarding": { "type": "boolean" },
        "allowPortForwarding": { "type": "boolean" },
        "allowX11Forwarding": { "type": "boolean" },
        "allowUserRc": { "type": "boolean" },
        "allowFrom": { "type": "array", "items": { "type": "string" } },
        "command": { "type": "string" },
        "expires": { "type": "string", "format": "date-time" },
        "permitOpen": { "type": "array", "items": { "type": "string" } },
        "permitListen": { "type": "array", "items": { "type": "string" } },
        "verifyRequired": { "type": "boolean" }
      },
      "required": ["id", "publicKey"]
    },
    "keroosha:debian:UserAuthorizedKeys": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "mode": { "type": "string", "enum": ["managed", "exclusive"] },
        "keys": { "type": "array", "items": { "$ref": "#/types/keroosha:debian:UserAuthorizedKey" } }
      },
      "required": ["mode", "keys"]
    },
    "keroosha:debian:UserAccount": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "state": { "type": "string", "enum": ["present", "absent"] },
        "kind": { "type": "string", "enum": ["human", "system"] },
        "existing": { "type": "string", "enum": ["reject", "adopt"] },
        "uid": { "type": "integer", "minimum": 1, "maximum": 2147483647 },
        "description": { "type": "string" },
        "primaryGroup": { "$ref": "#/types/keroosha:debian:UserPrimaryGroup" },
        "supplementaryGroups": { "$ref": "#/types/keroosha:debian:UserSupplementaryGroups" },
        "home": { "$ref": "#/types/keroosha:debian:UserHome" },
        "shell": { "type": "string" },
        "password": { "$ref": "#/types/keroosha:debian:UserPassword" },
        "accountExpiry": { "$ref": "#/types/keroosha:debian:UserAccountExpiry" },
        "passwordPolicy": { "$ref": "#/types/keroosha:debian:UserPasswordPolicy" },
        "subordinateUids": { "type": "array", "items": { "$ref": "#/types/keroosha:debian:UserSubordinateIdRange" } },
        "subordinateGids": { "type": "array", "items": { "$ref": "#/types/keroosha:debian:UserSubordinateIdRange" } },
        "onDelete": { "type": "string", "enum": ["retainIdentity"] },
        "authorizedKeys": { "$ref": "#/types/keroosha:debian:UserAuthorizedKeys" }
      }
    }
  },
  "resources": {
    "keroosha:debian:Users": {
      "description": "Manages declared local groups, users, password policy, subordinate ID ranges, and authorized keys on an existing Debian host.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "groups": { "type": "object", "additionalProperties": { "$ref": "#/types/keroosha:debian:UserGroup" } },
        "users": { "type": "object", "additionalProperties": { "$ref": "#/types/keroosha:debian:UserAccount" } }
      },
      "requiredInputs": ["connection", "groups", "users"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "groups": { "type": "object", "additionalProperties": { "$ref": "#/types/keroosha:debian:UserGroup" } },
        "users": { "type": "object", "additionalProperties": { "$ref": "#/types/keroosha:debian:UserAccount" } },
        "exists": { "type": "boolean" },
        "inSync": { "type": "boolean" },
        "actual": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "groups": {
              "type": "array",
              "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "name": { "type": "string" },
                  "exists": { "type": "boolean" },
                  "gid": { "type": "integer", "description": "Observed GID, or null when the group is absent." },
                  "kind": { "type": "string", "enum": ["human", "system"], "description": "Observed group kind, or null when unavailable." },
                  "state": { "type": "string", "enum": ["present", "absent"] },
                  "members": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["name", "exists", "gid", "kind", "state", "members"]
              }
            },
            "users": {
              "type": "array",
              "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "name": { "type": "string" },
                  "exists": { "type": "boolean" },
                  "uid": { "type": "integer", "description": "Observed UID, or null when the user is absent." },
                  "gid": { "type": "integer", "description": "Observed primary GID, or null when the user is absent." },
                  "description": { "type": "string", "description": "Observed account description, or null when absent." },
                  "home": { "type": "string", "description": "Observed home path, or null when absent." },
                  "shell": { "type": "string", "description": "Observed shell, or null when absent." },
                  "locked": { "type": "boolean", "description": "Observed lock state, or null when absent." },
                  "accountExpiry": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                      "kind": { "type": "string", "enum": ["on"] },
                      "date": { "type": "string", "format": "date" }
                    },
                    "required": ["kind", "date"],
                    "description": "Observed expiry date, or null when never."
                  },
                  "passwordPolicy": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                      "minDays": { "type": "integer" },
                      "maxDays": { "type": "integer" },
                      "warnDays": { "type": "integer" },
                      "inactiveDays": { "type": "integer" }
                    },
                    "required": ["minDays", "maxDays", "warnDays", "inactiveDays"]
                  },
                  "supplementaryGroups": { "type": "array", "items": { "type": "string" } },
                  "subordinateUids": {
                    "type": "array",
                    "items": {
                      "type": "object",
                      "additionalProperties": false,
                      "properties": {
                        "start": { "type": "integer" },
                        "count": { "type": "integer" }
                      },
                      "required": ["start", "count"]
                    }
                  },
                  "subordinateGids": {
                    "type": "array",
                    "items": {
                      "type": "object",
                      "additionalProperties": false,
                      "properties": {
                        "start": { "type": "integer" },
                        "count": { "type": "integer" }
                      },
                      "required": ["start", "count"]
                    }
                  },
                  "authorizedKeys": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["name", "exists", "uid", "gid", "description", "home", "shell", "locked", "accountExpiry", "passwordPolicy", "supplementaryGroups", "subordinateUids", "subordinateGids", "authorizedKeys"]
              }
            }
          },
          "required": ["groups", "users"]
        }
      },
      "required": ["connection", "groups", "users", "exists", "inSync", "actual"]
    }
  }
}"""

    let private declarativeProperties = [ "connection"; "groups"; "users" ]
    let private outputProperties = [ "exists"; "inSync"; "actual" ]
    let private maximumInteger = int64 Int32.MaxValue

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

    let private addFailure (failures: ResizeArray<CheckFailure>) property reason =
        failures.Add(CheckFailure(property, reason))

    let private immutableMap (values: Dictionary<string, PropertyValue>) =
        values
        |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
        |> ImmutableDictionary.CreateRange<string, PropertyValue>

    let private mapWithMetadata (source: PropertyValue) (fields: ImmutableDictionary<string, PropertyValue>) =
        PropertyValue(fields, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let rec private containsUnknown (value: PropertyValue) =
        if value.IsComputed then
            true
        else
            match tryGetMap value with
            | Some fields -> fields.Values |> Seq.exists containsUnknown
            | None ->
                match tryGetArray value with
                | Some values -> values |> Seq.exists containsUnknown
                | None -> false

    let private hasUnknownInputs (values: ImmutableDictionary<string, PropertyValue>) =
        values.Values |> Seq.exists containsUnknown

    let private isSafeText (text: string) =
        not (String.IsNullOrWhiteSpace(text)) && not (text |> Seq.exists Char.IsControl)

    let private isPasswordHash (text: string) =
        text.Length > 0
        && text.Length <= 4096
        && text[0] = '$'
        && not (text.Contains(':'))
        && not (text |> Seq.exists Char.IsControl)
        && not (text |> Seq.exists Char.IsWhiteSpace)

    let private isIdentity (text: string) =
        let validRest character =
            (character >= 'a' && character <= 'z')
            || (character >= '0' && character <= '9')
            || character = '_'
            || character = '-'
        text.Length > 0
        && text.Length <= 32
        && ((text[0] >= 'a' && text[0] <= 'z') || text[0] = '_')
        && (text |> Seq.skip 1 |> Seq.forall validRest)

    let private isSafePath (text: string) =
        not (String.IsNullOrWhiteSpace(text))
        && text[0] = '/'
        && text <> "/"
        && not (text.EndsWith("/", StringComparison.Ordinal))
        && not (text |> Seq.exists Char.IsControl)
        && (text.Substring(1).Split('/')
            |> Array.forall (fun segment -> segment.Length > 0 && segment <> "." && segment <> ".."))

    let private isDate (text: string) =
        let mutable parsed = DateTime.MinValue
        DateTime.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, &parsed)

    let private isUtcTimestamp (text: string) =
        let mutable parsed = DateTimeOffset.MinValue
        DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, &parsed)
        && parsed.Offset = TimeSpan.Zero
        && not (text |> Seq.exists Char.IsWhiteSpace)
        && (text.Contains('T') || text.Contains('t'))
        && (text.EndsWith("Z", StringComparison.Ordinal) || text.EndsWith("+00:00", StringComparison.Ordinal))

    let private objectShape fields required = Object(Map.ofList fields, Set.ofList required)
    let private anyText = Text(Some(fun text -> not (text |> Seq.exists Char.IsControl)))
    let private identityText = Text(Some isIdentity)
    let private pathText = Text(Some isSafePath)
    let private dateText = Text(Some isDate)
    let private timestampText = Text(Some isUtcTimestamp)

    let private groupShape =
        objectShape
            [ "gid", Integer(1L, maximumInteger)
              "kind", Enum [ "human"; "system" ]
              "existing", Enum [ "reject"; "adopt" ]
              "state", Enum [ "present"; "absent" ] ]
            []

    let private primaryGroupShape =
        objectShape [ "kind", Enum [ "private"; "existing" ]; "name", identityText ] [ "kind" ]

    let private supplementaryGroupsShape =
        objectShape [ "mode", Enum [ "managed"; "exclusive" ]; "names", TextArray(Some isIdentity) ] [ "mode"; "names" ]

    let private homeShape =
        objectShape
            [ "kind", Enum [ "create"; "existing"; "none" ]
              "path", pathText
              "mode", Integer(0L, 511L)
              "skeleton", pathText ]
            [ "kind" ]

    let private passwordShape =
        objectShape [ "kind", Enum [ "locked"; "hash" ]; "hash", Text(Some isPasswordHash); "update", Enum [ "always"; "onCreate" ] ] [ "kind" ]

    let private accountExpiryShape =
        objectShape [ "kind", Enum [ "never"; "on" ]; "date", dateText ] [ "kind" ]

    let private passwordPolicyShape =
        objectShape
            [ "minDays", Integer(0L, maximumInteger)
              "maxDays", Integer(0L, maximumInteger)
              "warnDays", Integer(0L, maximumInteger)
              "inactiveDays", Integer(0L, maximumInteger) ]
            []

    let private subordinateRangeShape =
        objectShape [ "start", Integer(1L, maximumInteger); "count", Integer(1L, maximumInteger) ] [ "start"; "count" ]

    let private authorizedKeyShape =
        objectShape
            [ "id", Text(Some isIdentity)
              "publicKey", Text(Some isSafeText)
              "comment", anyText
              "restrict", Boolean
              "allowPty", Boolean
              "allowAgentForwarding", Boolean
              "allowPortForwarding", Boolean
              "allowX11Forwarding", Boolean
              "allowUserRc", Boolean
              "allowFrom", TextArray(Some isSafeText)
              "command", anyText
              "expires", timestampText
              "permitOpen", TextArray(Some isSafeText)
              "permitListen", TextArray(Some isSafeText)
              "verifyRequired", Boolean ]
            [ "id"; "publicKey" ]

    let private authorizedKeysShape =
        objectShape [ "mode", Enum [ "managed"; "exclusive" ]; "keys", Array authorizedKeyShape ] [ "mode"; "keys" ]

    let private userShape =
        objectShape
            [ "state", Enum [ "present"; "absent" ]
              "kind", Enum [ "human"; "system" ]
              "existing", Enum [ "reject"; "adopt" ]
              "uid", Integer(1L, maximumInteger)
              "description", anyText
              "primaryGroup", primaryGroupShape
              "supplementaryGroups", supplementaryGroupsShape
              "home", homeShape
              "shell", pathText
              "password", passwordShape
              "accountExpiry", accountExpiryShape
              "passwordPolicy", passwordPolicyShape
              "subordinateUids", Array subordinateRangeShape
              "subordinateGids", Array subordinateRangeShape
              "onDelete", Enum [ "retainIdentity" ]
              "authorizedKeys", authorizedKeysShape ]
            []

    let private tryNumberInt64 (value: PropertyValue) =
        match tryGetNumber value with
        | Some number when not (Double.IsNaN(number) || Double.IsInfinity(number)) && number = Math.Truncate(number) && number >= float Int64.MinValue && number <= float Int64.MaxValue -> Some(int64 number)
        | _ -> None

    let private validateShape (path: string) (shape: Shape) (value: PropertyValue) (failures: ResizeArray<CheckFailure>) (hasUnknown: bool ref) =
        let rec validate (currentPath: string) (currentShape: Shape) (currentValue: PropertyValue) =
            if currentValue.IsComputed then
                hasUnknown.Value <- true
            elif currentValue.IsNull then
                ()
            else
                match currentShape with
                | Text predicate ->
                    match tryGetString currentValue with
                    | Some text when (predicate |> Option.forall (fun check -> check text)) -> ()
                    | _ -> addFailure failures currentPath "Expected a valid string value."
                | Enum allowed ->
                    match tryGetString currentValue with
                    | Some text when List.contains text allowed -> ()
                    | _ -> addFailure failures currentPath "Expected one of the supported values."
                | Integer(minimum, maximum) ->
                    match tryNumberInt64 currentValue with
                    | Some number when number >= minimum && number <= maximum -> ()
                    | _ -> addFailure failures currentPath "Expected an integer within the supported range."
                | Boolean ->
                    let mutable boolean = false
                    if not (currentValue.TryGetBool(&boolean)) then addFailure failures currentPath "Expected a boolean value."
                | TextArray predicate ->
                    match tryGetArray currentValue with
                    | None -> addFailure failures currentPath "Expected an array of strings."
                    | Some items ->
                        for index in 0 .. items.Length - 1 do
                            let item = items[index]
                            if item.IsComputed then
                                hasUnknown.Value <- true
                            else
                                match tryGetString item with
                                | Some text when (predicate |> Option.forall (fun check -> check text)) -> ()
                                | _ -> addFailure failures (sprintf "%s[%d]" currentPath index) "Expected a valid string value."
                | Array itemShape ->
                    match tryGetArray currentValue with
                    | None -> addFailure failures currentPath "Expected an array value."
                    | Some items ->
                        for index in 0 .. items.Length - 1 do
                            if items[index].IsNull then
                                addFailure failures (sprintf "%s[%d]" currentPath index) "Array items must not be null."
                            else
                                validate (sprintf "%s[%d]" currentPath index) itemShape items[index]
                | Object(fields, required) ->
                    match tryGetMap currentValue with
                    | None -> addFailure failures currentPath "Expected an object value."
                    | Some properties ->
                        for entry in properties do
                            if not (Map.containsKey entry.Key fields) then
                                addFailure failures (currentPath + "." + entry.Key) "This property is not supported."
                            else
                                validate (currentPath + "." + entry.Key) fields[entry.Key] entry.Value
                        for field in required do
                            match properties.TryGetValue(field) with
                            | false, _ -> addFailure failures (currentPath + "." + field) "This property is required."
                            | true, fieldValue when fieldValue.IsNull -> addFailure failures (currentPath + "." + field) "This property is required."
                            | _ -> ()
        validate path shape value

    let private getField (fields: ImmutableDictionary<string, PropertyValue>) name =
        match fields.TryGetValue(name) with
        | true, value -> Some value
        | false, _ -> None

    let private stringField (fields: ImmutableDictionary<string, PropertyValue>) name =
        getField fields name |> Option.bind tryGetString

    let private withSecretHash (user: PropertyValue) =
        match tryGetMap user with
        | None -> user
        | Some userFields ->
            match userFields.TryGetValue("password") with
            | false, _ -> user
            | true, password when password.IsComputed -> user
            | true, password ->
                match tryGetMap password with
                | None -> user
                | Some passwordFields ->
                    match passwordFields.TryGetValue("hash") with
                    | false, _ -> user
                    | true, hash when hash.IsNull || hash.IsSecret -> user
                    | true, hash when hash.IsComputed ->
                        let secretPassword = PropertyValue(passwordFields, IsSecret = true, Dependencies = password.Dependencies)
                        let fields = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                        for entry in userFields do fields[entry.Key] <- if entry.Key = "password" then secretPassword else entry.Value
                        mapWithMetadata user (fields.ToImmutable())
                    | true, hash ->
                        match tryGetString hash with
                        | None -> user
                        | Some text ->
                            let secretHash = PropertyValue(text, IsSecret = true, Dependencies = hash.Dependencies)
                            let newPassword = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                            for entry in passwordFields do newPassword[entry.Key] <- if entry.Key = "hash" then secretHash else entry.Value
                            let secretPassword = mapWithMetadata password (newPassword.ToImmutable())
                            let newUser = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                            for entry in userFields do newUser[entry.Key] <- if entry.Key = "password" then secretPassword else entry.Value
                            mapWithMetadata user (newUser.ToImmutable())

    let private normalizeNamedMap (name: string) (shape: Shape) (source: PropertyValue) (failures: ResizeArray<CheckFailure>) (hasUnknown: bool ref) =
        if source.IsComputed then
            hasUnknown := true
            source
        else
            match tryGetMap source with
            | None ->
                addFailure failures name "Expected an object map keyed by identity."
                source
            | Some entries ->
                let normalized = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                for entry in entries do
                    let path = name + "." + entry.Key
                    if not (isIdentity entry.Key) then addFailure failures path "Expected a conservative Linux account or group name."
                    let value = if name = "users" then withSecretHash entry.Value else entry.Value
                    if value.IsNull then
                        addFailure failures path "Expected an object identity declaration."
                    elif value.IsComputed then
                        hasUnknown := true
                    else
                        validateShape path shape value failures hasUnknown
                    normalized[entry.Key] <- value
                PropertyValue(normalized.ToImmutable(), IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private validateConditionalFields (name: string) (user: PropertyValue) (failures: ResizeArray<CheckFailure>) =
        match tryGetMap user with
        | None -> ()
        | Some fields ->
            match stringField fields "state" with
            | Some "absent" ->
                for entry in fields do
                    if entry.Key <> "state" && entry.Key <> "existing" && not entry.Value.IsNull && not entry.Value.IsComputed then
                        addFailure failures (name + "." + entry.Key) "Absent users may only specify state and existing."
            | _ -> ()
            let childObject child = getField fields child |> Option.bind tryGetMap
            let conditionalField objectName discriminator allowedValues requiredValues fieldName =
                match childObject objectName with
                | Some objectFields ->
                    match stringField objectFields discriminator with
                    | Some selectedKind when List.contains selectedKind requiredValues ->
                        match objectFields.TryGetValue(fieldName) with
                        | false, _ -> addFailure failures (name + "." + objectName + "." + fieldName) "This property is required for the selected kind."
                        | true, value when value.IsNull -> addFailure failures (name + "." + objectName + "." + fieldName) "This property is required for the selected kind."
                        | _ -> ()
                    | Some selectedKind when not (List.contains selectedKind allowedValues) ->
                        match objectFields.TryGetValue(fieldName) with
                        | true, value when not value.IsNull && not value.IsComputed -> addFailure failures (name + "." + objectName + "." + fieldName) "This property is not valid for the selected kind."
                        | _ -> ()
                    | _ -> ()
                | None -> ()
            conditionalField "primaryGroup" "kind" [ "existing" ] [ "existing" ] "name"
            conditionalField "home" "kind" [ "create"; "existing" ] [ "create"; "existing" ] "path"
            conditionalField "home" "kind" [ "create" ] [] "mode"
            conditionalField "home" "kind" [ "create" ] [] "skeleton"
            conditionalField "accountExpiry" "kind" [ "on" ] [ "on" ] "date"
            match childObject "passwordPolicy" with
            | Some policy ->
                let minimum = getField policy "minDays" |> Option.bind tryNumberInt64
                let maximum = getField policy "maxDays" |> Option.bind tryNumberInt64
                match minimum, maximum with
                | Some minDays, Some maxDays when maxDays > 0L && minDays > maxDays ->
                    addFailure failures (name + ".passwordPolicy.maxDays") "Password policy maxDays must not be less than minDays."
                | _ -> ()
            | None -> ()
            match childObject "password" with
            | Some password when stringField password "kind" = Some "hash" ->
                match password.TryGetValue("hash") with
                | false, _ -> addFailure failures (name + ".password.hash") "A password hash is required when password.kind is hash."
                | true, value when value.IsNull -> addFailure failures (name + ".password.hash") "A password hash is required when password.kind is hash."
                | _ -> ()
            | Some password when stringField password "kind" = Some "locked" ->
                for field in [ "hash"; "update" ] do
                    match password.TryGetValue(field) with
                    | true, value when not value.IsNull && not value.IsComputed ->
                        addFailure failures (name + ".password." + field) "Locked passwords cannot specify a hash or update policy."
                    | _ -> ()
            | _ -> ()
            match childObject "supplementaryGroups" with
            | Some supplementaryGroups ->
                match supplementaryGroups.TryGetValue("names") with
                | true, namesValue ->
                    match tryGetArray namesValue with
                    | Some names ->
                        let uniqueNames = HashSet<string>(StringComparer.Ordinal)
                        for index in 0 .. names.Length - 1 do
                            match tryGetString names[index] with
                            | Some groupName when not (uniqueNames.Add(groupName)) ->
                                addFailure failures (sprintf "%s.supplementaryGroups.names[%d]" name index) "Supplementary group names must be unique."
                            | _ -> ()
                    | None -> ()
                | _ -> ()
            | None -> ()
            match childObject "authorizedKeys" with
            | Some keyConfig ->
                match keyConfig.TryGetValue("keys") with
                | true, keysValue ->
                    match tryGetArray keysValue with
                    | Some keys ->
                        let ids = HashSet<string>(StringComparer.Ordinal)
                        let materials = HashSet<string>(StringComparer.Ordinal)
                        for index in 0 .. keys.Length - 1 do
                            match tryGetMap keys[index] with
                            | Some key ->
                                match stringField key "id", stringField key "publicKey" with
                                | Some id, Some material ->
                                    if not (ids.Add(id)) then addFailure failures (sprintf "%s.authorizedKeys.keys[%d].id" name index) "Authorized key identifiers must be unique per user."
                                    if not (materials.Add(material)) then addFailure failures (sprintf "%s.authorizedKeys.keys[%d].publicKey" name index) "Authorized key material must be unique per user."
                                | _ -> ()
                            | None -> ()
                    | None -> ()
                | _ -> ()
            | None -> ()

    let private rangeValues (property: string) (userName: string) (user: PropertyValue) =
        match tryGetMap user with
        | Some fields ->
            match fields.TryGetValue(property) with
            | true, value when not value.IsComputed ->
                match tryGetArray value with
                | Some ranges ->
                    ranges
                    |> Seq.choose (fun range ->
                        match tryGetMap range with
                        | Some values ->
                            let startValue =
                                match values.TryGetValue("start") with
                                | true, value -> tryNumberInt64 value
                                | false, _ -> None
                            let countValue =
                                match values.TryGetValue("count") with
                                | true, value -> tryNumberInt64 value
                                | false, _ -> None
                            match startValue, countValue with
                            | Some start, Some count when count > 0L && start <= maximumInteger - count + 1L -> Some(start, start + count - 1L, userName)
                            | _ -> None
                        | None -> None)
                    |> Seq.toList
                | None -> []
            | _ -> []
        | None -> []
    let private validateRangeBounds (property: string) (userName: string) (user: PropertyValue) (failures: ResizeArray<CheckFailure>) =
        match tryGetMap user with
        | Some fields ->
            match fields.TryGetValue(property) with
            | true, value when not value.IsComputed ->
                match tryGetArray value with
                | Some ranges ->
                    for index in 0 .. ranges.Length - 1 do
                        match tryGetMap ranges[index] with
                        | Some range ->
                            let start =
                                match range.TryGetValue("start") with
                                | true, value -> tryNumberInt64 value
                                | false, _ -> None
                            let count =
                                match range.TryGetValue("count") with
                                | true, value -> tryNumberInt64 value
                                | false, _ -> None
                            match start, count with
                            | Some startValue, Some countValue when countValue > 0L && startValue > maximumInteger - countValue + 1L ->
                                addFailure failures (sprintf "users.%s.%s[%d]" userName property index) "Subordinate ID range exceeds the supported integer range."
                            | _ -> ()
                        | None -> ()
                | None -> ()
            | _ -> ()
        | None -> ()

    let private validateGlobalDeclarations groups users failures =
        let gidOwners = Dictionary<int64, string>()
        match tryGetMap groups with
        | Some declarations ->
            for entry in declarations do
                match tryGetMap entry.Value with
                | Some fields ->
                    match stringField fields "state" with
                    | Some "absent" ->
                        for field in [ "gid"; "kind" ] do
                            match fields.TryGetValue(field) with
                            | true, value when not value.IsNull && not value.IsComputed ->
                                addFailure failures ("groups." + entry.Key + "." + field) "Absent groups may only specify state and existing."
                            | _ -> ()
                    | _ -> ()
                    match fields.TryGetValue("gid") with
                    | true, value when not value.IsComputed ->
                        match tryNumberInt64 value with
                        | Some gid ->
                            match gidOwners.TryGetValue(gid) with
                            | true, other -> addFailure failures ("groups." + entry.Key + ".gid") ("GID conflicts with another declaration at " + other + ".")
                            | false, _ -> gidOwners[gid] <- entry.Key
                        | None -> ()
                    | _ -> ()
                | None -> ()
        | None -> ()
        let uidOwners = Dictionary<int64, string>()
        let uidRanges = ResizeArray<int64 * int64 * string>()
        let gidRanges = ResizeArray<int64 * int64 * string>()
        match tryGetMap users with
        | Some declarations ->
            for entry in declarations do
                match tryGetMap entry.Value with
                | Some fields ->
                    match fields.TryGetValue("uid") with
                    | true, value when not value.IsComputed ->
                        match tryNumberInt64 value with
                        | Some uid ->
                            match uidOwners.TryGetValue(uid) with
                            | true, other -> addFailure failures ("users." + entry.Key + ".uid") ("UID conflicts with another declaration at " + other + ".")
                            | false, _ -> uidOwners[uid] <- entry.Key
                        | None -> ()
                    | _ -> ()
                | None -> ()
                validateRangeBounds "subordinateUids" entry.Key entry.Value failures
                validateRangeBounds "subordinateGids" entry.Key entry.Value failures
                uidRanges.AddRange(rangeValues "subordinateUids" entry.Key entry.Value)
                gidRanges.AddRange(rangeValues "subordinateGids" entry.Key entry.Value)
                validateConditionalFields ("users." + entry.Key) entry.Value failures
        | None -> ()
        let validateRanges label (ranges: seq<int64 * int64 * string>) =
            let ordered = ranges |> Seq.sortBy (fun (start, _, _) -> start)
            let mutable maximumEnd = Int64.MinValue
            let mutable maximumOwner = String.Empty
            for (start, rangeEnd, name) in ordered do
                if start <= maximumEnd then
                    addFailure failures ("users." + name + "." + label) ("Subordinate ID range overlaps another declaration at users." + maximumOwner + ".")
                if rangeEnd > maximumEnd then
                    maximumEnd <- rangeEnd
                    maximumOwner <- name
        validateRanges "subordinateUids" uidRanges
        validateRanges "subordinateGids" gidRanges

    let private normalizeConnection (source: PropertyValue) failures hasUnknown =
        if source.IsComputed then
            hasUnknown := true
            source
        else
            match tryGetMap source with
            | None ->
                addFailure failures "connection" "Expected an SSH connection object."
                source
            | Some connection ->
                let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
                for entry in connection do
                    if entry.Key <> "address" && entry.Key <> "user" && entry.Key <> "port" && entry.Key <> "identityFile" then
                        addFailure failures ("connection." + entry.Key) "This connection property is not supported."
                    else normalized[entry.Key] <- entry.Value
                let normalizeRequired name valid reason =
                    match connection.TryGetValue(name) with
                    | false, _ -> addFailure failures ("connection." + name) "This property is required."
                    | true, value when value.IsComputed -> hasUnknown := true
                    | true, value ->
                        match tryGetString value with
                        | Some text ->
                            let canonical = text.Trim()
                            if String.IsNullOrWhiteSpace(canonical) || not (valid canonical) then addFailure failures ("connection." + name) reason
                            else normalized[name] <- PropertyValue(canonical, IsSecret = value.IsSecret, Dependencies = value.Dependencies)
                        | None -> addFailure failures ("connection." + name) "Expected a string value."
                let noWhitespace (text: string) = not (text.StartsWith("-", StringComparison.Ordinal)) && not (text.Contains('@')) && not (text |> Seq.exists Char.IsWhiteSpace) && not (text |> Seq.exists Char.IsControl)
                normalizeRequired "address" noWhitespace "Expected a non-empty SSH address without whitespace or '@'."
                normalizeRequired "user" (fun text -> noWhitespace text && not (text.Contains('/'))) "Expected a non-empty SSH user without whitespace, '/', or '@'."
                match connection.TryGetValue("port") with
                | false, _ -> normalized["port"] <- PropertyValue(22.0)
                | true, value when value.IsComputed -> hasUnknown := true
                | true, value when value.IsNull -> normalized["port"] <- PropertyValue(22.0)
                | true, value ->
                    match tryGetNumber value with
                    | Some number when not (Double.IsNaN(number) || Double.IsInfinity(number)) && number = Math.Truncate(number) && number >= 1.0 && number <= 65535.0 ->
                        normalized["port"] <- PropertyValue(number, IsSecret = value.IsSecret, Dependencies = value.Dependencies)
                    | _ -> addFailure failures "connection.port" "Expected an integer SSH port from 1 through 65535."
                match connection.TryGetValue("identityFile") with
                | false, _ -> ()
                | true, value when value.IsComputed -> hasUnknown := true
                | true, value when value.IsNull -> normalized.Remove("identityFile") |> ignore
                | true, value ->
                    match tryGetString value with
                    | Some path when not (String.IsNullOrWhiteSpace(path)) && not (path |> Seq.exists Char.IsControl) -> normalized["identityFile"] <- value
                    | Some path when String.IsNullOrWhiteSpace(path) -> normalized.Remove("identityFile") |> ignore
                    | _ -> addFailure failures "connection.identityFile" "Expected a non-empty identity-file path without control characters."
                PropertyValue(immutableMap normalized, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private normalizeInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        let failures = ResizeArray<CheckFailure>()
        let hasUnknown = ref (hasUnknownInputs values)
        for entry in values do
            if not (List.contains entry.Key declarativeProperties) then addFailure failures entry.Key "This resource property is not supported."
        match values.TryGetValue("connection") with
        | false, _ -> addFailure failures "connection" "This property is required."
        | true, source -> normalized["connection"] <- normalizeConnection source failures hasUnknown
        match values.TryGetValue("groups") with
        | false, _ -> addFailure failures "groups" "This property is required."
        | true, source -> normalized["groups"] <- normalizeNamedMap "groups" groupShape source failures hasUnknown
        match values.TryGetValue("users") with
        | false, _ -> addFailure failures "users" "This property is required."
        | true, source -> normalized["users"] <- normalizeNamedMap "users" userShape source failures hasUnknown
        match normalized.TryGetValue("groups"), normalized.TryGetValue("users") with
        | (true, groups), (true, users) -> validateGlobalDeclarations groups users failures
        | _ -> ()
        { Values = normalized
          HasUnknowns = hasUnknown.Value
          Failures = failures }

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let message = failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " "
            invalidOp ("Invalid users inputs. " + message)

    let private readMap (values: Dictionary<string, PropertyValue>) name =
        match values.TryGetValue(name) with
        | true, value ->
            match tryGetMap value with
            | Some map -> map
            | None -> invalidOp ("Stored users state has an invalid " + name + ".")
        | false, _ -> invalidOp ("Stored users state is missing " + name + ".")

    let private readString (values: ImmutableDictionary<string, PropertyValue>) name =
        match values.TryGetValue(name) with
        | true, value ->
            match tryGetString value with
            | Some text -> text
            | None -> invalidOp ("Stored users state has an invalid " + name + ".")
        | false, _ -> invalidOp ("Stored users state is missing " + name + ".")

    let private parseInputs (normalized: NormalizedInputs) =
        failIfFailures normalized.Failures
        if normalized.HasUnknowns then invalidOp "Users operations require known inputs."
        let connection = readMap normalized.Values "connection"
        let port =
            match connection.TryGetValue("port") with
            | true, value ->
                match tryGetNumber value with
                | Some number when number >= 1.0 && number <= 65535.0 && number = Math.Truncate(number) -> int number
                | _ -> invalidOp "Stored users state has an invalid SSH port."
            | false, _ -> invalidOp "Stored users state is missing connection.port."
        let identityFile =
            match connection.TryGetValue("identityFile") with
            | true, value ->
                match tryGetString value with
                | Some path -> Some path
                | None -> invalidOp "Stored users state has an invalid identityFile."
            | false, _ -> None
        let groups = normalized.Values["groups"]
        let users = normalized.Values["users"]
        { Values = normalized.Values
          Connection =
            { Address = readString connection "address"
              User = readString connection "user"
              Port = port
              IdentityFile = identityFile }
          Groups = groups
          Users = users }

    let private normalizeForPreview values =
        let normalized = normalizeInputs values
        failIfFailures normalized.Failures
        normalized

    let private normalizeForOperation values = normalizeInputs values |> parseInputs

    let private inputValuesFromOutputs (preferred: ImmutableDictionary<string, PropertyValue>) (fallback: ImmutableDictionary<string, PropertyValue>) =
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
        let selected = inputValuesFromOutputs preferred fallback
        selected
        |> immutableMap
        |> normalizeInputs
        |> parseInputs

    let private stableId (urn: Pulumi.Urn) (connection: SshConnection) =
        urn.ToString() + "::" + connection.Address

    let private addDiff (diffs: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) (root: string) (path: string) (kind: PropertyDiffKind) inputDiff =
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

    let private snapshotsMatch (outputs: ImmutableDictionary<string, PropertyValue>) =
        outputBoolean "exists" outputs = Some true && outputBoolean "inSync" outputs = Some true
    let private snapshotHasUnknown (outputs: ImmutableDictionary<string, PropertyValue>) =
        [ "exists"; "inSync" ]
        |> List.exists (fun property ->
            match outputs.TryGetValue(property) with
            | true, value -> containsUnknown value
            | false, _ -> false)

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
            invalidOp "Stored users state is missing its input declaration."
        elif snapshotHasUnknown request.OldOutputs then
            let response = DiffResponse()
            response.Changes <- Nullable<bool>()
            response
        else
            let oldNormalized = normalizeInputs (immutableMap previous)
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
                if not (oldInputs.Groups.Equals(newInputs.Groups)) then add "groups" "groups" PropertyDiffKind.Update true
                if not (oldInputs.Users.Equals(newInputs.Users)) then add "users" "users" PropertyDiffKind.Update true
                if not (snapshotsMatch request.OldOutputs) then add "inSync" "inSync" PropertyDiffKind.Update false
                let response = DiffResponse()
                response.Changes <- Nullable<bool>(diffs.Count > 0)
                response.Diffs <- List<string>(diffs)
                response.Replaces <- List<string>(replaces)
                response.DetailedDiff <- details
                response.DeleteBeforeReplace <- replaces.Count > 0
                response

    let private outputValues (inputs: ParsedInputs) (snapshot: UsersSnapshot) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        outputs["exists"] <- PropertyValue(snapshot.Exists)
        outputs["inSync"] <- PropertyValue(snapshot.InSync)
        outputs["actual"] <-
            let rec convert (element: JsonElement) =
                match element.ValueKind with
                | JsonValueKind.Object ->
                    let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                    for property in element.EnumerateObject() do builder[property.Name] <- convert property.Value
                    PropertyValue(builder.ToImmutable())
                | JsonValueKind.Array ->
                    let values = element.EnumerateArray() |> Seq.map convert |> ImmutableArray.CreateRange<PropertyValue>
                    PropertyValue(values)
                | JsonValueKind.String ->
                    match element.GetString() with
                    | null -> PropertyValue.Null
                    | text -> PropertyValue(text)
                | JsonValueKind.Number ->
                    let mutable integer = 0L
                    if element.TryGetInt64(&integer) then PropertyValue(float integer) else PropertyValue(element.GetDouble())
                | JsonValueKind.True -> PropertyValue(true)
                | JsonValueKind.False -> PropertyValue(false)
                | JsonValueKind.Null
                | JsonValueKind.Undefined -> PropertyValue.Null
                | _ -> invalidOp "Users helper returned an unsupported JSON value."
            convert snapshot.Actual
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
            let inputs = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
            for entry in request.NewInputs do inputs[entry.Key] <- entry.Value
            checkResponse inputs failures
        else
            let normalized = normalizeInputs request.NewInputs
            checkResponse normalized.Values normalized.Failures

    let resourceToken = ResourceToken
    let providerSchema = schema
    let resourceCheck = makeCheckResponse
    let makeDiffResponse = makeDiff
    let normalizeForPreviewInputs = normalizeForPreview
    let normalizeForOperationInputs = normalizeForOperation
    let parseStoredState = storedInputs
    let timeoutForRequest = requestTimeout
    let resourceId = stableId
    let makeOutputValues = outputValues
    let makePreviewValues = previewValues
    let makeCheckConfiguration (request: CheckRequest) =
        let failures = ResizeArray<CheckFailure>()
        for entry in request.NewInputs do
            if entry.Key <> "version" && entry.Key <> "pluginDownloadURL" then addFailure failures entry.Key "Dorothy does not accept custom provider configuration properties."
        let inputs = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in request.NewInputs do inputs[entry.Key] <- entry.Value
        checkResponse inputs failures
    let configure = configureResponse
    let configurationDiff (request: DiffRequest) =
        let changed =
            request.OldInputs.Count <> request.NewInputs.Count
            || (request.NewInputs |> Seq.exists (fun entry -> match request.OldInputs.TryGetValue(entry.Key) with true, oldValue -> not (oldValue.Equals(entry.Value)) | false, _ -> true))
        let response = DiffResponse()
        response.Changes <- Nullable<bool>(changed)
        response.Diffs <- List<string>()
        response.Replaces <- List<string>()
        response.DetailedDiff <- Dictionary<string, PropertyDiff>()
        response
    let private ensureResourceToken requestType =
        if requestType <> ResourceToken then invalidOp "Unexpected resource token for the Dorothy provider."
    let ensureToken = ensureResourceToken
    let createPreviewResponse (inputs: NormalizedInputs) =
        let response = CreateResponse()
        response.Id <- String.Empty
        response.Outputs <- previewValues inputs
        response
    let createResponse (ownerId: string) (inputs: ParsedInputs) (snapshot: UsersSnapshot) =
        let response = CreateResponse()
        response.Id <- ownerId
        response.Outputs <- outputValues inputs snapshot
        response
    let updatePreviewResponse (inputs: NormalizedInputs) =
        let response = UpdateResponse()
        response.Outputs <- previewValues inputs
        response
    let updateResponse (inputs: ParsedInputs) (snapshot: UsersSnapshot) =
        let response = UpdateResponse()
        response.Outputs <- outputValues inputs snapshot
        response
    let readResponse (id: string) (urn: Pulumi.Urn) (inputs: ParsedInputs) (snapshot: UsersSnapshot) =
        let response = ReadResponse()
        response.Id <- if snapshot.Exists then (if String.IsNullOrEmpty id then stableId urn inputs.Connection else id) else String.Empty
        response.Inputs <- inputs.Values
        response.Outputs <- outputValues inputs snapshot
        response

[<Sealed>]
type UsersProvider() =
    inherit Pulumi.Experimental.Provider.Provider()

    static member Version = "0.1.0"
    static member ResourceToken = UsersProviderLogic.resourceToken
    static member Schema = UsersProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- UsersProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(UsersProviderLogic.makeCheckConfiguration request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(UsersProviderLogic.configurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        if request.Args.Keys |> Seq.exists (fun key -> key <> "version" && key <> "pluginDownloadURL") then
            invalidOp "Dorothy does not accept custom provider configuration properties."
        Task.FromResult(UsersProviderLogic.configure ())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(UsersProviderLogic.resourceCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        UsersProviderLogic.ensureToken request.Type
        Task.FromResult(UsersProviderLogic.makeDiffResponse request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        UsersProviderLogic.ensureToken request.Type
        if request.Preview then
            let inputs = UsersProviderLogic.normalizeForPreviewInputs request.Inputs
            Task.FromResult(UsersProviderLogic.createPreviewResponse inputs)
        else
            UsersProviderLogic.runWithTimeout (UsersProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = UsersProviderLogic.normalizeForOperationInputs request.Inputs
                    let ownerId = UsersProviderLogic.resourceId request.Urn inputs.Connection
                    let! snapshot = UsersBackend.apply inputs.Connection ownerId inputs.Groups inputs.Users operationToken
                    return UsersProviderLogic.createResponse ownerId inputs snapshot
                })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        UsersProviderLogic.ensureToken request.Type
        UsersProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = UsersProviderLogic.parseStoredState request.Inputs request.Outputs
                let ownerId = if String.IsNullOrEmpty request.Id then UsersProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                let! snapshot = UsersBackend.read inputs.Connection ownerId inputs.Groups inputs.Users operationToken
                return UsersProviderLogic.readResponse request.Id request.Urn inputs snapshot
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        UsersProviderLogic.ensureToken request.Type
        if request.Preview then
            let inputs = UsersProviderLogic.normalizeForPreviewInputs request.NewInputs
            Task.FromResult(UsersProviderLogic.updatePreviewResponse inputs)
        else
            UsersProviderLogic.runWithTimeout (UsersProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = UsersProviderLogic.normalizeForOperationInputs request.NewInputs
                    let ownerId = if String.IsNullOrEmpty request.Id then UsersProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                    let! snapshot = UsersBackend.apply inputs.Connection ownerId inputs.Groups inputs.Users operationToken
                    return UsersProviderLogic.updateResponse inputs snapshot
                })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        UsersProviderLogic.ensureToken request.Type
        UsersProviderLogic.runWithTimeout (UsersProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = UsersProviderLogic.parseStoredState request.OldInputs request.OldOutputs
                let ownerId = if String.IsNullOrEmpty request.Id then UsersProviderLogic.resourceId request.Urn inputs.Connection else request.Id
                do! UsersBackend.delete inputs.Connection ownerId inputs.Groups inputs.Users operationToken
            }) :> Task
