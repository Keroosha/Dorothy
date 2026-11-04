namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

type SudoSubject =
    { Kind: string
      Name: string }

type SudoRunAs =
    { Kind: string
      User: string option
      Group: string option }

type SudoCommandArguments =
    { Kind: string
      Value: string option }

type SudoCommand =
    { Path: string
      Arguments: SudoCommandArguments }

type SudoGrant =
    { Name: string
      Subjects: SudoSubject list
      RunAs: SudoRunAs
      Authentication: string
      AllCommands: bool
      Commands: SudoCommand list }

type SudoSnapshot =
    { Exists: bool
      InSync: bool
      ActualJson: string }

module SudoBackend =
    let private writeGrant (writer: Utf8JsonWriter) (grant: SudoGrant) =
        writer.WriteStartObject()
        writer.WriteString("name", grant.Name)
        writer.WriteStartArray("subjects")
        for subject in grant.Subjects do
            writer.WriteStartObject()
            writer.WriteString("kind", subject.Kind)
            writer.WriteString("name", subject.Name)
            writer.WriteEndObject()
        writer.WriteEndArray()
        writer.WriteStartObject("runAs")
        writer.WriteString("kind", grant.RunAs.Kind)
        grant.RunAs.User |> Option.iter (fun user -> writer.WriteString("user", user))
        grant.RunAs.Group |> Option.iter (fun group -> writer.WriteString("group", group))
        writer.WriteEndObject()
        writer.WriteString("authentication", grant.Authentication)
        writer.WriteBoolean("allCommands", grant.AllCommands)
        writer.WriteStartArray("commands")
        for command in grant.Commands do
            writer.WriteStartObject()
            writer.WriteString("path", command.Path)
            writer.WriteStartObject("arguments")
            writer.WriteString("kind", command.Arguments.Kind)
            command.Arguments.Value |> Option.iter (fun value -> writer.WriteString("value", value))
            writer.WriteEndObject()
            writer.WriteEndObject()
        writer.WriteEndArray()
        writer.WriteEndObject()

    let private serializePayload (operation: string) (resourceId: string) (connectionUser: string) (grants: SudoGrant list) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("resourceId", resourceId)
        writer.WriteString("connectionUser", connectionUser)
        writer.WriteStartArray("grants")
        for grant in grants |> List.sortWith (fun left right -> StringComparer.Ordinal.Compare(left.Name, right.Name)) do
            writeGrant writer grant
        writer.WriteEndArray()
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let private exactObject (element: JsonElement) (expected: Set<string>) (description: string) =
        if element.ValueKind <> JsonValueKind.Object then
            raise (FormatException(description + " must be a JSON object."))

        let properties = element.EnumerateObject() |> Seq.toArray
        let names = HashSet<string>(StringComparer.Ordinal)
        for property in properties do
            if not (names.Add(property.Name)) then
                raise (FormatException(description + " contains a duplicate property."))

        if properties.Length <> expected.Count || Set.ofSeq names <> expected then
            raise (FormatException(description + " has an unexpected property set."))

        properties

    let private readBoolean (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        if value.ValueKind <> JsonValueKind.True && value.ValueKind <> JsonValueKind.False then
            raise (FormatException("Remote " + name + " must be a boolean."))
        value.GetBoolean()

    let private readString (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        if value.ValueKind <> JsonValueKind.String then
            raise (FormatException("Remote " + name + " must be a string."))
        match value.GetString() with
        | null -> raise (FormatException("Remote " + name + " must not be null."))
        | text -> text

    let private readNullableString (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        match value.ValueKind with
        | JsonValueKind.Null -> None
        | JsonValueKind.String ->
            match value.GetString() with
            | null -> raise (FormatException("Remote " + name + " must not be null."))
            | text -> Some text
        | _ -> raise (FormatException("Remote " + name + " must be a string or null."))

    let private readNullableInt32 (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        match value.ValueKind with
        | JsonValueKind.Null -> None
        | JsonValueKind.Number ->
            let mutable number = 0
            if not (value.TryGetInt32(&number)) then
                raise (FormatException("Remote " + name + " must be an integer or null."))
            Some number
        | _ -> raise (FormatException("Remote " + name + " must be an integer or null."))

    let private readNullableUInt32 (element: JsonElement) (name: string) =
        let value = element.GetProperty(name)
        match value.ValueKind with
        | JsonValueKind.Null -> None
        | JsonValueKind.Number ->
            let mutable number = 0u
            if not (value.TryGetUInt32(&number)) then
                raise (FormatException("Remote " + name + " must be an unsigned integer or null."))
            Some number
        | _ -> raise (FormatException("Remote " + name + " must be an unsigned integer or null."))

    let private isSha256 (value: string) =
        value.Length = 64
        && (value |> Seq.forall (fun character ->
            (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f')
            || (character >= 'A' && character <= 'F')))

    let private parseSnapshot (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement
            exactObject root (Set.ofList [ "exists"; "inSync"; "actual" ]) "Remote sudo result" |> ignore
            let exists = readBoolean root "exists"
            let inSync = readBoolean root "inSync"
            let actual = root.GetProperty("actual")
            exactObject
                actual
                (Set.ofList [ "filePath"; "filePresent"; "fileSha256"; "fileMode"; "fileOwnerUid"; "grants" ])
                "Remote sudo actual"
            |> ignore

            let filePath = readString actual "filePath"
            if String.IsNullOrWhiteSpace(filePath) || filePath[0] <> '/' || (filePath |> Seq.exists Char.IsControl) then
                raise (FormatException("Remote sudo filePath must be an absolute path without control characters."))

            let filePresent = readBoolean actual "filePresent"
            let fileSha256 = readNullableString actual "fileSha256"
            let fileMode = readNullableInt32 actual "fileMode"
            let fileOwnerUid = readNullableUInt32 actual "fileOwnerUid"
            match fileMode with
            | Some mode when mode < 0 || mode > 511 -> raise (FormatException("Remote sudo fileMode is outside its valid range."))
            | _ -> ()

            match filePresent, fileSha256, fileMode, fileOwnerUid with
            | true, Some digest, Some _, Some _ when isSha256 digest -> ()
            | true, _, _, _ -> raise (FormatException("A present remote sudo file must report its SHA-256, mode, and owner UID."))
            | false, None, None, None -> ()
            | false, _, _, _ -> raise (FormatException("An absent remote sudo file must not report file metadata."))

            let grants = actual.GetProperty("grants")
            if grants.ValueKind <> JsonValueKind.Array then
                raise (FormatException("Remote sudo actual grants must be an array."))
            let seenNames = HashSet<string>(StringComparer.Ordinal)
            for grant in grants.EnumerateArray() do
                exactObject grant (Set.ofList [ "name"; "effectiveVerified"; "coverage" ]) "Remote sudo actual grant" |> ignore
                let name = readString grant "name"
                if String.IsNullOrWhiteSpace(name) || (name |> Seq.exists Char.IsControl) || not (seenNames.Add(name)) then
                    raise (FormatException("Remote sudo actual grants contain an empty, invalid, or duplicate name."))
                readBoolean grant "effectiveVerified" |> ignore
                let coverage = readString grant "coverage"
                if coverage <> "direct-user" && coverage <> "nss-enumerated-group-members" && coverage <> "empty-group-structural" && coverage <> "unresolved-principal" then
                    raise (FormatException("Remote sudo actual grant has an unsupported coverage label."))

            { Exists = exists
              InSync = inSync
              ActualJson = actual.GetRawText() }
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote sudo helper returned invalid JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote sudo helper returned an invalid snapshot.", error))

    let private invoke
        (connection: SshConnection)
        (operation: string)
        (resourceId: string)
        (grants: SudoGrant list)
        (cancellationToken: CancellationToken)
        : Task<SudoSnapshot> =
        task {
            let payload = serializePayload operation resourceId connection.User grants
            let! output = SshTransport.runHelper connection "sudo" "sudo policy" payload cancellationToken
            return parseSnapshot output
        }

    let read (connection: SshConnection) (resourceId: string) (grants: SudoGrant list) (cancellationToken: CancellationToken) =
        invoke connection "read" resourceId grants cancellationToken

    let apply (connection: SshConnection) (resourceId: string) (grants: SudoGrant list) (cancellationToken: CancellationToken) =
        invoke connection "apply" resourceId grants cancellationToken

    let delete (connection: SshConnection) (resourceId: string) (grants: SudoGrant list) (cancellationToken: CancellationToken) =
        task {
            let! snapshot = invoke connection "delete" resourceId grants cancellationToken
            if snapshot.Exists then
                raise (InvalidOperationException("Remote sudo helper reported that owned policy still exists after deletion."))
        }
