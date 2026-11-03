namespace Dorothy.DSL.Provider

open System
open System.Collections.Immutable
open System.IO
open System.Text
open System.Text.Json
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL

type TraefikConfig =
    { EntryPoints: ImmutableDictionary<string, int>
      Resolvers: ImmutableDictionary<string, TraefikResolver>
      Routers: ImmutableDictionary<string, TraefikRouter>
      Certificates: ImmutableDictionary<string, NormalizedCertificate>
      AdminPort: int }

type TraefikSnapshot =
    { InSync: bool
      ActualConfigHash: string
      CertificateFingerprints: ImmutableDictionary<string, string> }

module TraefikBackend =

    let private writeInputMap
        (writer: Utf8JsonWriter)
        (name: string)
        (values: ImmutableDictionary<string, 'T>)
        (writeValue: Utf8JsonWriter -> 'T -> unit)
        =
        writer.WriteStartObject(name)
        for KeyValue(key, value) in values do
            writer.WritePropertyName(key)
            writeValue writer value
        writer.WriteEndObject()

    let private serializeRequest (operation: string) (ownerId: string) (desired: TraefikConfig) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writer.WriteString("ownerId", ownerId)

        writeInputMap writer "entryPoints" desired.EntryPoints (fun json port -> json.WriteNumberValue(port))

        writeInputMap writer "resolvers" desired.Resolvers (fun json resolver ->
            json.WriteStartObject()
            json.WriteString("email", resolver.Email)
            json.WriteString("httpChallengeEntryPoint", resolver.HttpChallengeEntryPoint)
            json.WriteString("caServer", resolver.CaServer)
            json.WriteEndObject())

        writeInputMap writer "routers" desired.Routers (fun json router ->
            json.WriteStartObject()
            json.WriteString("host", router.Host)
            json.WriteString("entryPoint", router.EntryPoint)
            json.WriteString("backend", router.Backend)
            json.WriteStartObject("tls")
            json.WriteString("kind", router.Tls.Kind)
            json.WriteString("name", router.Tls.Name)
            json.WriteEndObject()
            json.WriteEndObject())

        writeInputMap writer "certificates" desired.Certificates (fun json certificate ->
            json.WriteStartObject()
            json.WriteString("certificatePem", certificate.CertificatePem)
            json.WriteString("privateKeyPem", certificate.PrivateKeyPem)
            json.WriteString("fingerprint", certificate.Fingerprint)
            json.WriteEndObject())

        writer.WriteNumber("adminPort", desired.AdminPort)
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)


    let private readRequiredString (root: JsonElement) (name: string) =
        let property = root.GetProperty(name)
        if property.ValueKind <> JsonValueKind.String then
            invalidOp "Remote Traefik response contains an invalid string field."
        property.GetString()

    let private isLowerHexSha256 (value: string) =
        value.Length = 64
        && (value
            |> Seq.forall (fun character ->
                (character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f')))

    let private isTraefikName (value: string) =
        let isAsciiLetterOrDigit character =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
        not (String.IsNullOrWhiteSpace(value))
        && value.Length <= 63
        && isAsciiLetterOrDigit value[0]
        && (value
            |> Seq.forall (fun character ->
                isAsciiLetterOrDigit character || character = '.' || character = '_' || character = '-'))

    let private parseSnapshot (expectedCertificateNames: Set<string>) (output: string) =
        use document = JsonDocument.Parse(output)
        let root = document.RootElement
        if root.ValueKind <> JsonValueKind.Object then
            invalidOp "Remote Traefik response must be an object."

        let properties = root.EnumerateObject() |> Seq.toArray
        let expected = Set.ofList [ "inSync"; "actualConfigHash"; "certificateFingerprints" ]
        let names = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
        if names <> expected || properties.Length <> expected.Count then
            invalidOp "Remote Traefik response has an invalid shape."

        let inSyncElement = root.GetProperty("inSync")
        if inSyncElement.ValueKind <> JsonValueKind.True && inSyncElement.ValueKind <> JsonValueKind.False then
            invalidOp "Remote Traefik response contains an invalid inSync field."

        let hash = readRequiredString root "actualConfigHash"
        if not (isLowerHexSha256 hash) then
            invalidOp "Remote Traefik response contains an invalid actualConfigHash."
        let fingerprintsElement = root.GetProperty("certificateFingerprints")
        if fingerprintsElement.ValueKind <> JsonValueKind.Object then
            invalidOp "Remote Traefik response contains an invalid certificate fingerprint map."

        let mutable fingerprints = ImmutableDictionary.Create<string, string>(StringComparer.Ordinal)
        for property in fingerprintsElement.EnumerateObject() do
            if not (isTraefikName property.Name)
               || not (Set.contains property.Name expectedCertificateNames)
               || property.Value.ValueKind <> JsonValueKind.String
               || fingerprints.ContainsKey(property.Name) then
                invalidOp "Remote Traefik response contains an invalid certificate fingerprint entry."
            let fingerprint = property.Value.GetString()
            if not (isLowerHexSha256 fingerprint) then
                invalidOp "Remote Traefik response contains an invalid certificate fingerprint."
            fingerprints <- fingerprints.Add(property.Name, fingerprint)

        { InSync = inSyncElement.GetBoolean()
          ActualConfigHash = hash
          CertificateFingerprints = fingerprints }

    let private parseDeleteResponse (output: string) =
        use document = JsonDocument.Parse(output)
        let root = document.RootElement
        if root.ValueKind <> JsonValueKind.Object then
            invalidOp "Remote Traefik delete response must be an object."
        let properties = root.EnumerateObject() |> Seq.toArray
        if properties.Length <> 0 then
            invalidOp "Remote Traefik delete response has an invalid shape."

    let private invoke
        (connection: SshConnection)
        (operation: string)
        (ownerId: string)
        (desired: TraefikConfig)
        (cancellationToken: CancellationToken)
        : Task<TraefikSnapshot> =
        task {
            cancellationToken.ThrowIfCancellationRequested()
            let payload = serializeRequest operation ownerId desired
            try
                let! output =
                    SshTransport.runHelper connection "traefik" "Traefik" payload cancellationToken
                return parseSnapshot (desired.Certificates.Keys |> Set.ofSeq) output
            with
            | :? OperationCanceledException as error -> return raise error
            | :? NativeHelperUnavailableException as error -> return raise error
            | :? NativeHelperBackendException as error -> return raise error
            | _ ->
                return
                    raise (
                        InvalidOperationException(
                            "Remote Traefik operation failed; provider diagnostics omit configuration and certificate material."
                        )
                    )
        }

    let apply (connection: SshConnection) (ownerId: string) (desired: TraefikConfig) (cancellationToken: CancellationToken) : Task<TraefikSnapshot> =
        invoke connection "apply" ownerId desired cancellationToken

    let read (connection: SshConnection) (ownerId: string) (desired: TraefikConfig) (cancellationToken: CancellationToken) : Task<TraefikSnapshot> =
        invoke connection "read" ownerId desired cancellationToken

    let delete (connection: SshConnection) (ownerId: string) (desired: TraefikConfig) (cancellationToken: CancellationToken) : Task<unit> =
        task {
            cancellationToken.ThrowIfCancellationRequested()
            let payload = serializeRequest "delete" ownerId desired
            try
                let! output =
                    SshTransport.runHelper connection "traefik" "Traefik" payload cancellationToken
                parseDeleteResponse output
                return ()
            with
            | :? OperationCanceledException as error -> return raise error
            | :? NativeHelperUnavailableException as error -> return raise error
            | :? NativeHelperBackendException as error -> return raise error
            | _ ->
                return
                    raise (
                        InvalidOperationException(
                            "Remote Traefik deletion failed; provider diagnostics omit configuration and certificate material."
                        )
                    )
        }
