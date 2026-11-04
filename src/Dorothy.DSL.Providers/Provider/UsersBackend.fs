namespace Dorothy.DSL.Provider

open System
open System.Collections.Immutable
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

type UsersSnapshot =
    { Exists: bool
      InSync: bool
      Actual: JsonElement }

module UsersBackend =
    let private tryGetMap (value: PropertyValue) =
        let mutable result = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&result) then Some result else None

    let private tryGetArray (value: PropertyValue) =
        let mutable result = ImmutableArray<PropertyValue>.Empty
        if value.TryGetArray(&result) then Some result else None

    let private tryGetString (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>
        if value.TryGetString(&result) then Some result else None

    let private hasPasswordHash (users: PropertyValue) =
        match tryGetMap users with
        | None -> false
        | Some userMap ->
            userMap.Values
            |> Seq.exists (fun user ->
                match tryGetMap user with
                | Some fields ->
                    match fields.TryGetValue("password") with
                    | true, password ->
                        match tryGetMap password with
                        | Some passwordFields ->
                            match passwordFields.TryGetValue("hash") with
                            | true, hash -> not hash.IsNull
                            | false, _ -> false
                        | None -> false
                    | false, _ -> false
                | None -> false)

    let private writePropertyValue (writer: Utf8JsonWriter) (value: PropertyValue) =
        let rec writeValue (current: PropertyValue) =
            if current.IsComputed then
                invalidOp "Users helper requests require known input values."
            elif current.IsNull then
                writer.WriteNullValue()
            else
                match tryGetMap current with
                | Some properties ->
                    writer.WriteStartObject()
                    for entry in properties |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left.Key, right.Key)) do
                        if not entry.Value.IsNull then
                            writer.WritePropertyName(entry.Key)
                            writeValue entry.Value
                    writer.WriteEndObject()
                | None ->
                    match tryGetArray current with
                    | Some items ->
                        writer.WriteStartArray()
                        for item in items do writeValue item
                        writer.WriteEndArray()
                    | None ->
                        match tryGetString current with
                        | Some text -> writer.WriteStringValue(text)
                        | None ->
                            let mutable boolean = false
                            if current.TryGetBool(&boolean) then
                                writer.WriteBooleanValue(boolean)
                            else
                                let mutable number = 0.0
                                if current.TryGetNumber(&number) then
                                    writer.WriteNumberValue(number)
                                else
                                    invalidOp "Users helper request contains an unsupported input value."
        writeValue value

    let private writeNamedEntries (writer: Utf8JsonWriter) (value: PropertyValue) =
        match tryGetMap value with
        | None -> invalidOp "Users helper request contains an invalid identity map."
        | Some entries ->
            writer.WriteStartArray()
            for entry in entries |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left.Key, right.Key)) do
                match tryGetMap entry.Value with
                | None -> invalidOp "Users helper request contains an invalid identity declaration."
                | Some fields ->
                    if fields.ContainsKey("name") then
                        invalidOp "Users helper identity declarations must not contain a name field."
                    writer.WriteStartObject()
                    writer.WriteString("name", entry.Key)
                    for field in fields |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left.Key, right.Key)) do
                        if not field.Value.IsNull then
                            writer.WritePropertyName(field.Key)
                            writePropertyValue writer field.Value
                    writer.WriteEndObject()
            writer.WriteEndArray()

    let private serializeRequest
        (operation: string)
        (resourceId: string)
        (connectionUser: string)
        (groups: PropertyValue)
        (users: PropertyValue)
        =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("resourceId", resourceId)
        writer.WriteString("connectionUser", connectionUser)
        writer.WritePropertyName("groups")
        writeNamedEntries writer groups
        writer.WritePropertyName("users")
        writeNamedEntries writer users
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let private ensureObject (element: JsonElement) message =
        if element.ValueKind <> JsonValueKind.Object then invalidOp message

    let private ensureExactProperties (element: JsonElement) (expected: Set<string>) message =
        ensureObject element message
        let properties = element.EnumerateObject() |> Seq.toArray
        let names = properties |> Seq.map (fun property -> property.Name) |> Set.ofSeq
        if properties.Length <> expected.Count || names <> expected then invalidOp message

    let private ensureBoolean (element: JsonElement) message =
        if element.ValueKind <> JsonValueKind.True && element.ValueKind <> JsonValueKind.False then
            invalidOp message

    let private ensureArray (element: JsonElement) message =
        if element.ValueKind <> JsonValueKind.Array then invalidOp message
    let private requiredProperty (element: JsonElement) (name: string) =
        let mutable value = Unchecked.defaultof<JsonElement>
        if not (element.TryGetProperty(name, &value)) then
            invalidOp "Users helper returned an incomplete actual record."
        value

    let private ensureString (element: JsonElement) message =
        if element.ValueKind <> JsonValueKind.String then invalidOp message

    let private ensureNullableString (element: JsonElement) message =
        if element.ValueKind <> JsonValueKind.Null then ensureString element message

    let private ensureInteger (element: JsonElement) message =
        let mutable value = 0L
        if element.ValueKind <> JsonValueKind.Number || not (element.TryGetInt64(&value)) || value < int64 Int32.MinValue || value > int64 Int32.MaxValue then
            invalidOp message

    let private ensureNullableInteger (element: JsonElement) message =
        if element.ValueKind <> JsonValueKind.Null then ensureInteger element message

    let private ensureStringArray (element: JsonElement) message =
        ensureArray element message
        for value in element.EnumerateArray() do ensureString value message

    let private ensureNullableBoolean (element: JsonElement) message =
        if element.ValueKind <> JsonValueKind.Null then ensureBoolean element message

    let private ensureActualExpiry (element: JsonElement) =
        if element.ValueKind <> JsonValueKind.Null then
            ensureExactProperties element (Set.ofList [ "kind"; "date" ]) "Users helper returned an invalid account expiry observation."
            let kind = requiredProperty element "kind"
            let date = requiredProperty element "date"
            ensureString kind "Users helper returned an invalid account expiry kind."
            ensureString date "Users helper returned an invalid account expiry date."
            match kind.GetString() with
            | null -> invalidOp "Users helper returned an invalid account expiry kind."
            | "on" -> ()
            | _ -> invalidOp "Users helper returned an unsupported account expiry kind."
    let private ensureActualRanges (element: JsonElement) =
        ensureArray element "Users helper returned an invalid subordinate ID range array."
        for range in element.EnumerateArray() do
            ensureExactProperties range (Set.ofList [ "start"; "count" ]) "Users helper returned an invalid subordinate ID range."
            let ensureUInt32 (element: JsonElement) =
                let mutable number = 0u
                if element.ValueKind <> JsonValueKind.Number || not (element.TryGetUInt32(&number)) || number = 0u then
                    invalidOp "Users helper returned an invalid subordinate ID range."
            ensureUInt32 (requiredProperty range "start")
            ensureUInt32 (requiredProperty range "count")

    let private ensureActualPasswordPolicy (element: JsonElement) =
        ensureExactProperties element (Set.ofList [ "minDays"; "maxDays"; "warnDays"; "inactiveDays" ]) "Users helper returned an invalid password policy observation."
        for name in [ "minDays"; "maxDays"; "warnDays"; "inactiveDays" ] do
            ensureNullableInteger (requiredProperty element name) "Users helper returned an invalid password policy value."


    let private rejectSensitiveActualFields (actual: JsonElement) =
        let rec visit (element: JsonElement) =
            match element.ValueKind with
            | JsonValueKind.Object ->
                for property in element.EnumerateObject() do
                    let name = property.Name
                    if String.Equals(name, "hash", StringComparison.OrdinalIgnoreCase)
                       || String.Equals(name, "passwordHash", StringComparison.OrdinalIgnoreCase)
                       || String.Equals(name, "password_hash", StringComparison.OrdinalIgnoreCase)
                       || String.Equals(name, "password", StringComparison.OrdinalIgnoreCase) then
                        invalidOp "Users helper returned an actual value containing a forbidden password field."
                    visit property.Value
            | JsonValueKind.Array ->
                for item in element.EnumerateArray() do visit item
            | _ -> ()
        visit actual
    let private rejectHashEcho (users: PropertyValue) (actual: JsonElement) =
        let hashes =
            match tryGetMap users with
            | None -> []
            | Some declarations ->
                declarations.Values
                |> Seq.choose (fun user ->
                    match tryGetMap user with
                    | Some fields ->
                        match fields.TryGetValue("password") with
                        | true, password ->
                            match tryGetMap password with
                            | Some passwordFields ->
                                match passwordFields.TryGetValue("hash") with
                                | true, value -> tryGetString value
                                | false, _ -> None
                            | None -> None
                        | false, _ -> None
                    | None -> None)
                |> Seq.filter (String.IsNullOrEmpty >> not)
                |> Seq.toList
        let rec visit (element: JsonElement) =
            match element.ValueKind with
            | JsonValueKind.Object ->
                for property in element.EnumerateObject() do visit property.Value
            | JsonValueKind.Array ->
                for item in element.EnumerateArray() do visit item
            | JsonValueKind.String ->
                let text = element.GetString()
                if not (isNull text) && (hashes |> List.exists (fun hash -> text.Contains(hash, StringComparison.Ordinal))) then
                    invalidOp "Users helper returned an actual value containing submitted secret material."
            | _ -> ()
        visit actual


    let private validateActual (actual: JsonElement) =
        ensureExactProperties actual (Set.ofList [ "groups"; "users" ]) "Users helper returned an invalid actual object."
        let groups = requiredProperty actual "groups"
        let users = requiredProperty actual "users"
        ensureArray groups "Users helper returned an invalid groups array."
        ensureArray users "Users helper returned an invalid users array."
        let groupProperties = Set.ofList [ "name"; "exists"; "gid"; "kind"; "state"; "members" ]
        for group in groups.EnumerateArray() do
            ensureExactProperties group groupProperties "Users helper returned an invalid group observation."
            ensureString (requiredProperty group "name") "Users helper returned an invalid group name."
            ensureBoolean (requiredProperty group "exists") "Users helper returned an invalid group exists flag."
            let gid = requiredProperty group "gid"
            ensureNullableInteger gid "Users helper returned an invalid group GID."
            let kind = requiredProperty group "kind"
            ensureNullableString kind "Users helper returned an invalid group kind."
            if kind.ValueKind = JsonValueKind.String then
                match kind.GetString() with
                | null -> invalidOp "Users helper returned an invalid group kind."
                | "human"
                | "system" -> ()
                | _ -> invalidOp "Users helper returned an unsupported group kind."
            let state = requiredProperty group "state"
            ensureString state "Users helper returned an invalid group state."
            match state.GetString() with
            | null -> invalidOp "Users helper returned an invalid group state."
            | "present"
            | "absent" -> ()
            | _ -> invalidOp "Users helper returned an unsupported group state."
            ensureStringArray (requiredProperty group "members") "Users helper returned invalid group members."
        let userProperties =
            Set.ofList [ "name"; "exists"; "uid"; "gid"; "description"; "home"; "shell"; "locked"; "accountExpiry"; "passwordPolicy"; "supplementaryGroups"; "subordinateUids"; "subordinateGids"; "authorizedKeys" ]
        for user in users.EnumerateArray() do
            ensureExactProperties user userProperties "Users helper returned an invalid user observation."
            ensureString (requiredProperty user "name") "Users helper returned an invalid user name."
            ensureBoolean (requiredProperty user "exists") "Users helper returned an invalid user exists flag."
            ensureNullableInteger (requiredProperty user "uid") "Users helper returned an invalid user UID."
            ensureNullableInteger (requiredProperty user "gid") "Users helper returned an invalid user GID."
            ensureNullableString (requiredProperty user "description") "Users helper returned an invalid user description."
            ensureNullableString (requiredProperty user "home") "Users helper returned an invalid user home."
            ensureNullableString (requiredProperty user "shell") "Users helper returned an invalid user shell."
            ensureNullableBoolean (requiredProperty user "locked") "Users helper returned an invalid user lock state."
            ensureActualExpiry (requiredProperty user "accountExpiry")
            ensureActualPasswordPolicy (requiredProperty user "passwordPolicy")
            ensureStringArray (requiredProperty user "supplementaryGroups") "Users helper returned invalid supplementary groups."
            ensureActualRanges (requiredProperty user "subordinateUids")
            ensureActualRanges (requiredProperty user "subordinateGids")
            ensureStringArray (requiredProperty user "authorizedKeys") "Users helper returned invalid authorized keys."
        rejectSensitiveActualFields actual

    let private parseSnapshot (users: PropertyValue) (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement
            ensureExactProperties root (Set.ofList [ "exists"; "inSync"; "actual" ]) "Users helper returned an invalid response envelope."
            let existsElement = root.GetProperty("exists")
            let inSyncElement = root.GetProperty("inSync")
            ensureBoolean existsElement "Users helper returned an invalid exists flag."
            ensureBoolean inSyncElement "Users helper returned an invalid inSync flag."
            let actual = root.GetProperty("actual")
            validateActual actual
            rejectHashEcho users actual
            { Exists = existsElement.GetBoolean()
              InSync = inSyncElement.GetBoolean()
              Actual = actual.Clone() }
        with
        | :? JsonException -> invalidOp "Users helper returned invalid JSON."

    let private invoke
        (connection: SshConnection)
        (operation: string)
        (resourceId: string)
        (groups: PropertyValue)
        (users: PropertyValue)
        (cancellationToken: CancellationToken)
        : Task<UsersSnapshot> =
            task {
                let containsHash = hasPasswordHash users
                let payload =
                    try
                        serializeRequest operation resourceId connection.User groups users
                    with
                    | _ when containsHash -> invalidOp "Users helper request could not be serialized; diagnostics are suppressed because it contains a password hash."
                let! output =
                    task {
                        try
                            return! SshTransport.runHelper connection "users" "users" payload cancellationToken
                        with
                        | :? OperationCanceledException as error -> return raise error
                        | _ when containsHash ->
                            return raise (InvalidOperationException("Remote users helper operation failed; diagnostics are suppressed because the request contains a password hash."))
                    }
                try
                    return parseSnapshot users output
                with
                | :? OperationCanceledException as error -> return raise error
                | _ when containsHash ->
                    return raise (InvalidOperationException("Remote users helper returned an invalid response; diagnostics are suppressed because the request contains a password hash."))
            }

    let read connection resourceId groups users cancellationToken =
        invoke connection "read" resourceId groups users cancellationToken

    let apply connection resourceId groups users cancellationToken =
        invoke connection "apply" resourceId groups users cancellationToken

    let delete connection resourceId groups users cancellationToken =
        task {
            let! snapshot = invoke connection "delete" resourceId groups users cancellationToken
            if snapshot.Exists || not snapshot.InSync then
                invalidOp "Users helper reported an unsuccessful delete."
        }
