namespace Dorothy.DSL.Provider

open System
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

type SshdSnapshot =
    {
        Owned: bool
        ActualConfiguration: string
        ActualConnectionConfiguration: string
        Ports: int list
        InSync: bool
        PendingToken: string
    }

module SshdBackend =
    let private validatePendingToken (token: string) =
        if
            not (String.IsNullOrEmpty(token))
            && (String.IsNullOrWhiteSpace(token)
                || token.Length > 4096
                || (token |> Seq.exists Char.IsControl))
        then
            raise (FormatException("Remote SSHD pendingToken is not a valid transaction token."))

        token

    let private serializePayload
        (operation: string)
        (ownerId: string)
        (configuration: string)
        (transactionToken: string option)
        =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("ownerId", ownerId)
        writer.WriteString("configuration", configuration)

        match transactionToken with
        | Some token -> writer.WriteString("transactionToken", token)
        | None -> ()

        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let parseSnapshot (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement

            if root.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote SSHD result must be a JSON object."))

            let properties = root.EnumerateObject() |> Seq.toArray

            let expectedProperties =
                Set.ofList
                    [
                        "owned"
                        "actualConfiguration"
                        "actualConnectionConfiguration"
                        "ports"
                        "inSync"
                        "pendingToken"
                    ]

            let propertyNames =
                properties |> Array.map (fun property -> property.Name) |> Set.ofArray

            if
                properties.Length <> expectedProperties.Count
                || propertyNames <> expectedProperties
            then
                raise (
                    FormatException("Remote SSHD result must contain only the complete configuration snapshot fields.")
                )

            let readBoolean (name: string) =
                let value = root.GetProperty(name)

                if value.ValueKind <> JsonValueKind.True && value.ValueKind <> JsonValueKind.False then
                    raise (FormatException("Remote SSHD " + name + " must be a boolean."))

                value.GetBoolean()

            let readString (name: string) =
                let value = root.GetProperty(name)

                if value.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote SSHD " + name + " must be a string."))

                match value.GetString() with
                | null -> raise (FormatException("Remote SSHD " + name + " must not be null."))
                | text -> text

            let portsElement = root.GetProperty("ports")

            if portsElement.ValueKind <> JsonValueKind.Array then
                raise (FormatException("Remote SSHD ports must be a JSON array."))

            let ports = ResizeArray<int>()

            for item in portsElement.EnumerateArray() do
                let mutable number = 0

                if item.ValueKind <> JsonValueKind.Number || not (item.TryGetInt32(&number)) then
                    raise (FormatException("Remote SSHD ports must contain 32-bit integers."))

                ports.Add(number)

            {
                Owned = readBoolean "owned"
                ActualConfiguration = readString "actualConfiguration"
                ActualConnectionConfiguration = readString "actualConnectionConfiguration"
                Ports = List.ofSeq ports
                InSync = readBoolean "inSync"
                PendingToken = readString "pendingToken" |> validatePendingToken
            }
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote SSHD helper returned invalid JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote SSHD helper returned an invalid snapshot.", error))

    let private parseDeleteResult (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement

            if root.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote SSHD delete result must be a JSON object."))

            let properties = root.EnumerateObject() |> Seq.toArray

            if
                properties.Length <> 1
                || properties[0].Name <> "pendingToken"
                || properties[0].Value.ValueKind <> JsonValueKind.String
            then
                raise (FormatException("Remote SSHD delete result must contain only a string pendingToken."))

            match properties[0].Value.GetString() with
            | null -> raise (FormatException("Remote SSHD delete pendingToken must not be null."))
            | token -> validatePendingToken token
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote SSHD helper returned invalid delete JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote SSHD helper returned an invalid delete result.", error))

    let private parseEmptyResult (operation: string) (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement

            if
                root.ValueKind <> JsonValueKind.Object
                || not (root.EnumerateObject() |> Seq.isEmpty)
            then
                raise (FormatException("Remote SSHD " + operation + " result must be an empty JSON object."))
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote SSHD helper returned invalid " + operation + " JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote SSHD helper returned an invalid " + operation + " result.", error))

    let private invoke
        (connection: SshConnection)
        (operation: string)
        (ownerId: string)
        (configuration: string)
        (transactionToken: string option)
        (freshConnection: bool)
        (cancellationToken: CancellationToken)
        =
        task {
            let payload = serializePayload operation ownerId configuration transactionToken

            let! output =
                if freshConnection then
                    SshTransport.runHelperFreshConnection connection "sshd" "SSHD" payload cancellationToken
                else
                    SshTransport.runHelper connection "sshd" "SSHD" payload cancellationToken

            return output
        }

    let private confirm
        (connection: SshConnection)
        (ownerId: string)
        (configuration: string)
        (transactionToken: string)
        (cancellationToken: CancellationToken)
        =
        task {
            let! output =
                invoke connection "confirm" ownerId configuration (Some transactionToken) true cancellationToken

            parseEmptyResult "confirmation" output
        }

    let read
        (connection: SshConnection)
        (ownerId: string)
        (configuration: string)
        (cancellationToken: CancellationToken)
        : Task<SshdSnapshot> =
        task {
            let! output =
                invoke connection "read" ownerId configuration None false cancellationToken

            return parseSnapshot output
        }

    let apply
        (connection: SshConnection)
        (ownerId: string)
        (configuration: string)
        (cancellationToken: CancellationToken)
        : Task<SshdSnapshot> =
        task {
            let! output =
                invoke connection "apply" ownerId configuration None false cancellationToken

            let initialSnapshot = parseSnapshot output

            if String.IsNullOrEmpty(initialSnapshot.PendingToken) then
                if not initialSnapshot.Owned || not initialSnapshot.InSync then
                    invalidOp "Remote SSHD apply did not establish the requested owned configuration."

                return initialSnapshot
            else
                if not initialSnapshot.Owned then
                    invalidOp "Remote SSHD apply started a transaction without establishing an owned configuration."

                do! confirm connection ownerId configuration initialSnapshot.PendingToken cancellationToken

                let! finalizedOutput =
                    invoke connection "read" ownerId configuration None true cancellationToken

                let finalizedSnapshot = parseSnapshot finalizedOutput

                if
                    not finalizedSnapshot.Owned
                    || not finalizedSnapshot.InSync
                    || not (String.IsNullOrEmpty(finalizedSnapshot.PendingToken))
                then
                    invalidOp "Remote SSHD confirmation did not finalize the requested owned configuration."

                return finalizedSnapshot
        }

    let delete
        (connection: SshConnection)
        (ownerId: string)
        (configuration: string)
        (cancellationToken: CancellationToken)
        : Task<unit> =
        task {
            let! output =
                invoke connection "delete" ownerId configuration None false cancellationToken

            let pendingToken = parseDeleteResult output

            if not (String.IsNullOrEmpty(pendingToken)) then
                do! confirm connection ownerId configuration pendingToken cancellationToken

            let! verificationOutput =
                invoke connection "read" ownerId configuration None true cancellationToken

            let verificationSnapshot = parseSnapshot verificationOutput

            if
                verificationSnapshot.Owned
                || not (String.IsNullOrEmpty(verificationSnapshot.PendingToken))
            then
                invalidOp "Remote SSHD delete did not remove the owned configuration."
        }
