namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks

type DockerEngineSnapshot =
    { ServiceEnabled: bool
      ServiceActive: bool
      DockerGroupMembership: bool
      InSync: bool }

module DockerEngineBackend =
    let private serializePayload (operation: string) (user: string) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("user", user)
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
            let expectedProperties = Set.ofList [ "serviceEnabled"; "serviceActive"; "dockerGroupMembership" ]

            if properties.Length <> expectedProperties.Count || propertyNames <> expectedProperties then
                raise (FormatException("Remote result must contain only serviceEnabled, serviceActive, and dockerGroupMembership."))

            let readBoolean (name: string) =
                let property = root.GetProperty(name)
                if property.ValueKind <> JsonValueKind.True && property.ValueKind <> JsonValueKind.False then
                    raise (FormatException(sprintf "Remote %s must be a boolean." name))
                property.GetBoolean()

            let serviceEnabled = readBoolean "serviceEnabled"
            let serviceActive = readBoolean "serviceActive"
            let dockerGroupMembership = readBoolean "dockerGroupMembership"

            { ServiceEnabled = serviceEnabled
              ServiceActive = serviceActive
              DockerGroupMembership = dockerGroupMembership
              InSync = serviceEnabled && serviceActive && dockerGroupMembership }
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote Docker Engine helper returned invalid JSON.", error))
        | :? FormatException as error ->
            raise (InvalidOperationException("Remote Docker Engine helper returned an invalid snapshot.", error))

    let private invoke
        (connection: SshConnection)
        (operation: string)
        (cancellationToken: CancellationToken)
        : Task<DockerEngineSnapshot> =
        task {
            let payload = serializePayload operation connection.User
            let! output = SshTransport.runHelper connection "docker" "Docker Engine" payload cancellationToken
            return parseSnapshot output
        }

    let read (connection: SshConnection) (cancellationToken: CancellationToken) =
        invoke connection "read" cancellationToken

    let apply (connection: SshConnection) (cancellationToken: CancellationToken) =
        invoke connection "apply" cancellationToken
