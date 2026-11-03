namespace Dorothy.DSL.Provider

open System
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

type SwapfileSnapshot =
    { Owned: bool
      ActualPath: string
      ActualSizeBytes: int64
      Mode: int
      Enabled: bool
      Active: bool
      InSync: bool }

module SwapfileBackend =
    let private serializePayload (operation: string) (ownerId: string) (path: string) (sizeBytes: int64) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("ownerId", ownerId)
        writer.WriteString("path", path)
        writer.WriteNumber("sizeBytes", sizeBytes)
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let private parseSnapshot (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement

            if root.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote result must be a JSON object."))

            let properties = root.EnumerateObject() |> Seq.toArray
            let propertyNames = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
            let expected = Set.ofList [ "owned"; "actualPath"; "actualSizeBytes"; "mode"; "enabled"; "active"; "inSync" ]

            if properties.Length <> expected.Count || propertyNames <> expected then
                raise (FormatException("Remote result must contain only the swapfile ownership and synchronization snapshot."))

            let readBoolean (name: string) =
                let value = root.GetProperty(name)
                if value.ValueKind <> JsonValueKind.True && value.ValueKind <> JsonValueKind.False then
                    raise (FormatException("Remote " + name + " must be a boolean."))
                value.GetBoolean()

            let readString (name: string) =
                let value = root.GetProperty(name)
                if value.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote " + name + " must be a string."))
                match value.GetString() with
                | null -> raise (FormatException("Remote " + name + " must not be null."))
                | text -> text

            let readInt64 (name: string) =
                let value = root.GetProperty(name)
                let mutable number = 0L
                if value.ValueKind <> JsonValueKind.Number || not (value.TryGetInt64(&number)) then
                    raise (FormatException("Remote " + name + " must be an integer."))
                number

            let owned = readBoolean "owned"
            let actualPath = readString "actualPath"
            let actualSizeBytes = readInt64 "actualSizeBytes"
            let modeValue = readInt64 "mode"
            if modeValue < 0L || modeValue > 511L || actualSizeBytes < 0L then
                raise (FormatException("Remote swapfile size or mode is outside its valid range."))

            if not owned && (actualPath <> String.Empty || actualSizeBytes <> 0L || modeValue <> 0L || readBoolean "enabled" || readBoolean "active" || readBoolean "inSync") then
                raise (FormatException("An unowned remote swapfile must have an empty snapshot."))

            { Owned = owned
              ActualPath = actualPath
              ActualSizeBytes = actualSizeBytes
              Mode = int modeValue
              Enabled = readBoolean "enabled"
              Active = readBoolean "active"
              InSync = readBoolean "inSync" }
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote swapfile helper returned invalid JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote swapfile helper returned an invalid snapshot.", error))

    let private parseDeleteResult (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement
            if root.ValueKind <> JsonValueKind.Object || not (root.EnumerateObject() |> Seq.isEmpty) then
                raise (FormatException("Remote delete result must be an empty JSON object."))
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote swapfile helper returned invalid delete JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote swapfile helper returned an invalid delete result.", error))

    let private invoke
        (connection: SshConnection)
        (operation: string)
        (ownerId: string)
        (path: string)
        (sizeBytes: int64)
        (cancellationToken: CancellationToken)
        : Task<SwapfileSnapshot> =
        task {
            let payload = serializePayload operation ownerId path sizeBytes
            let! output = SshTransport.runHelper connection "swapfile" "swap file" payload cancellationToken
            return parseSnapshot output
        }

    let read connection ownerId path sizeBytes cancellationToken =
        invoke connection "read" ownerId path sizeBytes cancellationToken

    let apply connection ownerId path sizeBytes cancellationToken =
        invoke connection "apply" ownerId path sizeBytes cancellationToken

    let delete
        (connection: SshConnection)
        (ownerId: string)
        (path: string)
        (sizeBytes: int64)
        (cancellationToken: CancellationToken)
        =
        task {
            let payload = serializePayload "delete" ownerId path sizeBytes
            let! output = SshTransport.runHelper connection "swapfile" "swap file" payload cancellationToken
            parseDeleteResult output
        }
