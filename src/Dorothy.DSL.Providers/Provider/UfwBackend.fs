namespace Dorothy.DSL.Provider

open System
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

type UfwConfig =
    { Rules: string list list
      Enabled: bool
      DefaultIn: string
      DefaultOut: string }

type UfwSnapshot =
    { ActualRules: string list
      ActualEnabled: bool
      ActualDefaultIn: string
      ActualDefaultOut: string
      InSync: bool }

module UfwBackend =

    let private serializePayload
        (operation: string)
        (connection: SshConnection)
        (ownerId: string)
        (config: UfwConfig)
        =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("ownerId", ownerId)
        writer.WriteNumber("sshPort", connection.Port)
        writer.WriteStartArray("rules")

        for rule in config.Rules do
            writer.WriteStartArray()
            for argument in rule do
                writer.WriteStringValue(argument)
            writer.WriteEndArray()

        writer.WriteEndArray()
        writer.WriteBoolean("enabled", config.Enabled)
        writer.WriteString("defaultIn", config.DefaultIn)
        writer.WriteString("defaultOut", config.DefaultOut)
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let private readSnapshot (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement

            if root.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote UFW result must be a JSON object."))

            let properties = root.EnumerateObject() |> Seq.toArray
            let expectedProperties =
                Set.ofList [ "actualRules"; "actualEnabled"; "actualDefaultIn"; "actualDefaultOut"; "inSync" ]

            let propertyNames = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
            if properties.Length <> expectedProperties.Count || propertyNames <> expectedProperties then
                raise (FormatException("Remote UFW result must contain only the five snapshot properties."))

            let getString (name: string) =
                let value = root.GetProperty(name)
                if value.ValueKind <> JsonValueKind.String then
                    raise (FormatException(sprintf "Remote UFW %s must be a string." name))
                let result = value.GetString()
                if isNull result || String.IsNullOrWhiteSpace result || (result |> Seq.exists Char.IsControl) then
                    raise (FormatException(sprintf "Remote UFW %s is empty or contains control characters." name))
                result

            let actualRulesElement = root.GetProperty("actualRules")
            if actualRulesElement.ValueKind <> JsonValueKind.Array then
                raise (FormatException("Remote UFW actualRules must be a JSON array."))

            let actualRules = ResizeArray<string>()
            for item in actualRulesElement.EnumerateArray() do
                if item.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote UFW actualRules entries must be strings."))
                let rule = item.GetString()
                if isNull rule || String.IsNullOrWhiteSpace rule || (rule |> Seq.exists Char.IsControl) then
                    raise (FormatException("Remote UFW actualRules contains an empty or invalid rule."))
                actualRules.Add(rule)

            let actualEnabledElement = root.GetProperty("actualEnabled")
            if actualEnabledElement.ValueKind <> JsonValueKind.True && actualEnabledElement.ValueKind <> JsonValueKind.False then
                raise (FormatException("Remote UFW actualEnabled must be a JSON boolean."))

            let inSyncElement = root.GetProperty("inSync")

            let actualDefaultIn = getString "actualDefaultIn"
            let actualDefaultOut = getString "actualDefaultOut"
            let validDefault value = value = "allow" || value = "deny" || value = "reject"
            if not (validDefault actualDefaultIn) || not (validDefault actualDefaultOut) then
                raise (FormatException("Remote UFW default policies must be allow, deny, or reject."))

            { ActualRules = List.ofSeq actualRules
              ActualEnabled = actualEnabledElement.GetBoolean()
              ActualDefaultIn = actualDefaultIn
              ActualDefaultOut = actualDefaultOut
              InSync = inSyncElement.GetBoolean() }
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote UFW helper returned invalid JSON.", error))

    let private validateDeleteResult (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement
            if root.ValueKind <> JsonValueKind.Object || not (root.EnumerateObject() |> Seq.isEmpty) then
                raise (FormatException("Remote UFW delete result must be an empty JSON object."))
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote UFW helper returned invalid JSON after delete.", error))

    let private invoke operation connection ownerId config cancellationToken =
        let payload = serializePayload operation connection ownerId config
        SshTransport.runHelper connection "ufw" "UFW" payload cancellationToken

    let read
        (connection: SshConnection)
        (ownerId: string)
        (config: UfwConfig)
        (cancellationToken: CancellationToken)
        : Task<UfwSnapshot> =
        task {
            let! output = invoke "read" connection ownerId config cancellationToken
            return readSnapshot output
        }

    let apply
        (connection: SshConnection)
        (ownerId: string)
        (config: UfwConfig)
        (cancellationToken: CancellationToken)
        : Task<UfwSnapshot> =
        task {
            let! output = invoke "apply" connection ownerId config cancellationToken
            return readSnapshot output
        }

    let delete
        (connection: SshConnection)
        (ownerId: string)
        (config: UfwConfig)
        (cancellationToken: CancellationToken)
        : Task<unit> =
        task {
            let! output = invoke "delete" connection ownerId config cancellationToken
            validateDeleteResult output
        }
