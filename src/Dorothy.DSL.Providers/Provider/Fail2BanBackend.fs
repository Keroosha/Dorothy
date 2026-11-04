namespace Dorothy.DSL.Provider

open System
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

type Fail2BanConfiguration =
    {
        Files: Map<string, string>
        ManageSshdPorts: bool
        SshdPorts: int list
    }

type Fail2BanSnapshot =
    {
        Owned: bool
        ActualFiles: Map<string, string>
        Active: bool
        ActiveJails: string list
        Socket: string
        InSync: bool
    }

module Fail2BanBackend =
    let private serializePayload (operation: string) (ownerId: string) (configuration: Fail2BanConfiguration) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("ownerId", ownerId)
        writer.WriteStartObject("files")

        for KeyValue(path, content) in configuration.Files do
            writer.WriteString(path, content)

        writer.WriteEndObject()
        writer.WriteBoolean("manageSshdPorts", configuration.ManageSshdPorts)
        writer.WriteStartArray("sshdPorts")

        for port in configuration.SshdPorts do
            writer.WriteNumberValue(port)

        writer.WriteEndArray()
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let parseSnapshot (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement

            if root.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote Fail2Ban result must be a JSON object."))

            let properties = root.EnumerateObject() |> Seq.toArray

            let expectedProperties =
                Set.ofList [ "owned"; "actualFiles"; "active"; "activeJails"; "socket"; "inSync" ]

            let propertyNames =
                properties |> Array.map (fun property -> property.Name) |> Set.ofArray

            if
                properties.Length <> expectedProperties.Count
                || propertyNames <> expectedProperties
            then
                raise (
                    FormatException(
                        "Remote Fail2Ban result must contain only the complete configuration snapshot fields."
                    )
                )

            let readBoolean (name: string) =
                let value = root.GetProperty(name)

                if value.ValueKind <> JsonValueKind.True && value.ValueKind <> JsonValueKind.False then
                    raise (FormatException("Remote Fail2Ban " + name + " must be a boolean."))

                value.GetBoolean()

            let readString (name: string) =
                let value = root.GetProperty(name)

                if value.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote Fail2Ban " + name + " must be a string."))

                match value.GetString() with
                | null -> raise (FormatException("Remote Fail2Ban " + name + " must not be null."))
                | text -> text

            let actualFilesElement = root.GetProperty("actualFiles")

            if actualFilesElement.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote Fail2Ban actualFiles must be a JSON object."))

            let mutable actualFiles = Map.empty

            for property in actualFilesElement.EnumerateObject() do
                if Map.containsKey property.Name actualFiles then
                    raise (FormatException("Remote Fail2Ban actualFiles contains duplicate keys."))

                if property.Value.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote Fail2Ban actualFiles values must be strings."))

                match property.Value.GetString() with
                | null -> raise (FormatException("Remote Fail2Ban actualFiles values must not be null."))
                | content -> actualFiles <- Map.add property.Name content actualFiles

            let activeJailsElement = root.GetProperty("activeJails")

            if activeJailsElement.ValueKind <> JsonValueKind.Array then
                raise (FormatException("Remote Fail2Ban activeJails must be a JSON array."))

            let activeJails = ResizeArray<string>()

            for item in activeJailsElement.EnumerateArray() do
                if item.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote Fail2Ban activeJails entries must be strings."))

                match item.GetString() with
                | null -> raise (FormatException("Remote Fail2Ban activeJails entries must not be null."))
                | jail -> activeJails.Add(jail)

            {
                Owned = readBoolean "owned"
                ActualFiles = actualFiles
                Active = readBoolean "active"
                ActiveJails = List.ofSeq activeJails
                Socket = readString "socket"
                InSync = readBoolean "inSync"
            }
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote Fail2Ban helper returned invalid JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote Fail2Ban helper returned an invalid snapshot.", error))

    let private parseDeleteResult (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement

            if
                root.ValueKind <> JsonValueKind.Object
                || not (root.EnumerateObject() |> Seq.isEmpty)
            then
                raise (FormatException("Remote Fail2Ban delete result must be an empty JSON object."))
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote Fail2Ban helper returned invalid delete JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote Fail2Ban helper returned an invalid delete result.", error))

    let private invoke
        (connection: SshConnection)
        (operation: string)
        (ownerId: string)
        (configuration: Fail2BanConfiguration)
        (cancellationToken: CancellationToken)
        =
        task {
            let payload = serializePayload operation ownerId configuration

            let! output =
                SshTransport.runHelper connection "fail2ban" "Fail2Ban" payload cancellationToken

            return parseSnapshot output
        }

    let read
        (connection: SshConnection)
        (ownerId: string)
        (configuration: Fail2BanConfiguration)
        (cancellationToken: CancellationToken)
        : Task<Fail2BanSnapshot> =
        invoke connection "read" ownerId configuration cancellationToken

    let apply
        (connection: SshConnection)
        (ownerId: string)
        (configuration: Fail2BanConfiguration)
        (cancellationToken: CancellationToken)
        : Task<Fail2BanSnapshot> =
        invoke connection "apply" ownerId configuration cancellationToken

    let delete
        (connection: SshConnection)
        (ownerId: string)
        (configuration: Fail2BanConfiguration)
        (cancellationToken: CancellationToken)
        : Task<unit> =
        task {
            let payload = serializePayload "delete" ownerId configuration

            let! output =
                SshTransport.runHelper connection "fail2ban" "Fail2Ban" payload cancellationToken

            parseDeleteResult output
        }
