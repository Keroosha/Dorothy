namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

type SshdSnapshot =
    { Owned: bool
      ActualSettings: Map<string, string>
      Ports: int list
      InSync: bool
      PendingToken: string }

module SshdBackend =
    let isValidSetting (name: string) (value: string) =
        let canonicalPositiveInteger minimum maximum =
            let mutable number = 0
            Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, &number)
            && number >= minimum
            && number <= maximum
            && String.Equals(value, number.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)

        match name, value with
        | ("PasswordAuthentication" | "KbdInteractiveAuthentication" | "PubkeyAuthentication"), ("yes" | "no") -> true
        | "PermitRootLogin", ("yes" | "no" | "prohibit-password" | "forced-commands-only") -> true
        | "Port", _ -> canonicalPositiveInteger 1 65535
        | "MaxAuthTries", _ -> canonicalPositiveInteger 1 Int32.MaxValue
        | _ -> false

    let isValidObservedSetting (name: string) (value: string) =
        (name = "MaxAuthTries" && value = "0")
        || (name = "PermitRootLogin" && value = "without-password")
        || isValidSetting name value

    let private validatePendingToken (token: string) =
        if not (String.IsNullOrEmpty(token))
           && (String.IsNullOrWhiteSpace(token) || token.Length > 4096 || (token |> Seq.exists Char.IsControl)) then
            raise (FormatException("Remote SSHD pendingToken is not a valid transaction token."))
        token

    let private serializePayload
        (operation: string)
        (ownerId: string)
        (settings: Map<string, string>)
        (transactionToken: string option)
        =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("ownerId", ownerId)
        writer.WriteStartObject("settings")
        for KeyValue(name, value) in settings do
            writer.WriteString(name, value)
        writer.WriteEndObject()
        match transactionToken with
        | Some token -> writer.WriteString("transactionToken", token)
        | None -> ()
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let parseSnapshot (expectedSettings: Map<string, string>) (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement
            if root.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote SSHD result must be a JSON object."))

            let properties = root.EnumerateObject() |> Seq.toArray
            let expectedProperties = Set.ofList [ "owned"; "actualSettings"; "ports"; "inSync"; "pendingToken" ]
            let propertyNames = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
            if properties.Length <> expectedProperties.Count || propertyNames <> expectedProperties then
                raise (FormatException("Remote SSHD result must contain only the ownership and synchronization snapshot fields."))

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

            let actualSettingsElement = root.GetProperty("actualSettings")
            if actualSettingsElement.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote SSHD actualSettings must be a JSON object."))

            let mutable actualSettings = Map.empty
            for property in actualSettingsElement.EnumerateObject() do
                if actualSettings.ContainsKey(property.Name) then
                    raise (FormatException("Remote SSHD actualSettings contains duplicate keys."))
                if not (expectedSettings.ContainsKey(property.Name)) then
                    raise (FormatException("Remote SSHD actualSettings contains a key that was not requested."))
                if property.Value.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote SSHD actualSettings values must be strings."))
                let value = property.Value.GetString()
                if isNull value || not (isValidObservedSetting property.Name value) then
                    raise (FormatException("Remote SSHD actualSettings contains an invalid or unsupported observed value."))
                actualSettings <- Map.add property.Name value actualSettings

            if actualSettings.Count <> expectedSettings.Count then
                raise (FormatException("Remote SSHD actualSettings omitted one or more requested settings."))

            let portsElement = root.GetProperty("ports")
            if portsElement.ValueKind <> JsonValueKind.Array then
                raise (FormatException("Remote SSHD ports must be a JSON array."))
            let ports = ResizeArray<int>()
            let seenPorts = HashSet<int>()
            for item in portsElement.EnumerateArray() do
                let mutable number = 0
                if item.ValueKind <> JsonValueKind.Number || not (item.TryGetInt32(&number)) || number < 1 || number > 65535 then
                    raise (FormatException("Remote SSHD ports must contain integers from 1 through 65535."))
                if not (seenPorts.Add(number)) then
                    raise (FormatException("Remote SSHD ports contains a duplicate port."))
                ports.Add(number)
            if ports.Count = 0 then
                raise (FormatException("Remote SSHD ports must not be empty."))

            let pendingToken = readString "pendingToken" |> validatePendingToken

            { Owned = readBoolean "owned"
              ActualSettings = actualSettings
              Ports = List.ofSeq ports
              InSync = readBoolean "inSync"
              PendingToken = pendingToken }
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
            if properties.Length <> 1 || properties[0].Name <> "pendingToken" || properties[0].Value.ValueKind <> JsonValueKind.String then
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
            if root.ValueKind <> JsonValueKind.Object || not (root.EnumerateObject() |> Seq.isEmpty) then
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
        (settings: Map<string, string>)
        (transactionToken: string option)
        (freshConnection: bool)
        (cancellationToken: CancellationToken)
        =
        task {
            let payload = serializePayload operation ownerId settings transactionToken
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
        (settings: Map<string, string>)
        (transactionToken: string)
        (cancellationToken: CancellationToken)
        =
        task {
            let! output = invoke connection "confirm" ownerId settings (Some transactionToken) true cancellationToken
            parseEmptyResult "confirmation" output
        }

    let read
        (connection: SshConnection)
        (ownerId: string)
        (settings: Map<string, string>)
        (cancellationToken: CancellationToken)
        : Task<SshdSnapshot> =
        task {
            let! output = invoke connection "read" ownerId settings None false cancellationToken
            return parseSnapshot settings output
        }

    let apply
        (connection: SshConnection)
        (ownerId: string)
        (settings: Map<string, string>)
        (cancellationToken: CancellationToken)
        : Task<SshdSnapshot> =
        task {
            let! output = invoke connection "apply" ownerId settings None false cancellationToken
            let initialSnapshot = parseSnapshot settings output

            if String.IsNullOrEmpty(initialSnapshot.PendingToken) then
                if not initialSnapshot.Owned || not initialSnapshot.InSync || initialSnapshot.ActualSettings <> settings then
                    invalidOp "Remote SSHD apply did not establish the requested owned configuration."
                return initialSnapshot
            else
                if not initialSnapshot.Owned || initialSnapshot.ActualSettings <> settings then
                    invalidOp "Remote SSHD apply started a transaction without establishing the requested owned settings."
                do! confirm connection ownerId settings initialSnapshot.PendingToken cancellationToken
                let! finalizedOutput = invoke connection "read" ownerId settings None true cancellationToken
                let finalizedSnapshot = parseSnapshot settings finalizedOutput
                if not finalizedSnapshot.Owned
                   || not finalizedSnapshot.InSync
                   || finalizedSnapshot.ActualSettings <> settings
                   || not (String.IsNullOrEmpty(finalizedSnapshot.PendingToken)) then
                    invalidOp "Remote SSHD confirmation did not finalize the requested owned configuration."
                return finalizedSnapshot
        }

    let delete
        (connection: SshConnection)
        (ownerId: string)
        (settings: Map<string, string>)
        (cancellationToken: CancellationToken)
        : Task<unit> =
        task {
            let! output = invoke connection "delete" ownerId settings None false cancellationToken
            let pendingToken = parseDeleteResult output
            if not (String.IsNullOrEmpty(pendingToken)) then
                do! confirm connection ownerId settings pendingToken cancellationToken
            let! verificationOutput = invoke connection "read" ownerId settings None true cancellationToken
            let verificationSnapshot = parseSnapshot settings verificationOutput
            if verificationSnapshot.Owned || not (String.IsNullOrEmpty(verificationSnapshot.PendingToken)) then
                invalidOp "Remote SSHD delete did not remove the owned configuration."
        }
