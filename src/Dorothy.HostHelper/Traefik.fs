namespace Dorothy.HostHelper

open System
open System.Collections.Generic
open System.Diagnostics
open System.Formats.Asn1
open System.Formats.Tar
open System.Globalization
open System.IO
open System.IO.Compression
open System.Net
open System.Net.Http
open System.Net.Security
open System.Net.Sockets
open Microsoft.Win32.SafeHandles
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Text.Encodings.Web
open System.Text.Json
open System.Text.Json.Nodes
open System.Text.RegularExpressions
open System.Threading
open System.Threading.Tasks

[<Struct; StructLayout(LayoutKind.Sequential, Size = 256)>]
type private TraefikLinuxStatx =
    val mutable Mask: uint32
    val mutable BlockSize: uint32
    val mutable Attributes: uint64
    val mutable LinkCount: uint32
    val mutable UserId: uint32
    val mutable GroupId: uint32
    val mutable Mode: uint16

[<AutoOpen>]
module private TraefikNativeInterop =
    [<DllImport("libc", EntryPoint = "statx", SetLastError = true)>]
    extern int nativeStatx (int directoryFileDescriptor, string path, int flags, uint32 mask, TraefikLinuxStatx& result)

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int nativeOpen(string path, int flags, int mode)

    [<DllImport("libc", EntryPoint = "fchmod", SetLastError = true)>]
    extern int nativeFchmod(int descriptor, uint32 mode)

    [<DllImport("libc", EntryPoint = "fchown", SetLastError = true)>]
    extern int nativeFchown(int descriptor, uint32 uid, uint32 gid)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int nativeFsync(int descriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int nativeClose(int descriptor)

module Traefik =
    type BackendError(message: string) =
        inherit Exception(message)

    [<Literal>]
    let Version = "3.7.16"

    [<Literal>]
    let ServiceName = "keroosha-traefik.service"

    [<Literal>]
    let ServiceUser = "keroosha-traefik"

    [<Literal>]
    let ServiceGroup = "keroosha-traefik"

    [<Literal>]
    let DefaultAdminPort = 19080

    [<Literal>]
    let DefaultCaServer = "https://acme-v02.api.letsencrypt.org/directory"

    [<Literal>]
    let MaximumCertificateBytes = 2 * 1024 * 1024

    [<Literal>]
    let MaximumArchiveBytes = 128 * 1024 * 1024

    [<Literal>]
    let private ActivationTimeoutSeconds = 120.0

    [<Literal>]
    let private ActivationPollMilliseconds = 250

    [<Literal>]
    let private ServiceStopTimeoutSeconds = 10.0

    [<Literal>]
    let private ConnectTimeoutMilliseconds = 2000

    [<Literal>]
    let private ApiMaximumBytes = 1024 * 1024

    let private archiveChecksums =
        dict [
            "amd64", "759a7bc0d66b74c588255ed9e41c7f9d4aba60bdb7bce9dde551b1268a55eb07"
            "arm64", "8f9463a7dd3a618569aaa46e19500331d7374a2e6f6ee300a50df5bb49132e1a"
        ]

    let private releaseUrl architecture =
        "https://github.com/traefik/traefik/releases/download/v" + Version + "/traefik_v" + Version + "_linux_" + architecture + ".tar.gz"
    let archiveChecksum architecture = archiveChecksums[architecture]

    let private namePattern = Regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", RegexOptions.CultureInvariant)
    let private dnsLabelPattern = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)
    let private fingerprintPattern = Regex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)
    let private certificateFilenamePattern = Regex("^[0-9a-f]{64}\\.(?:crt|key)$", RegexOptions.CultureInvariant)
    let private acmeFilenamePattern = Regex("^acme-[0-9a-f]{64}\\.json$", RegexOptions.CultureInvariant)

    type RuntimePaths =
        { ConfigDir: string
          StateDir: string
          InstallDir: string
          UnitPath: string }
        member this.DynamicDir = Path.Combine(this.ConfigDir, "dynamic")
        member this.CertificateDir = Path.Combine(this.DynamicDir, "certificates")
        member this.RollbackPath = Path.Combine(this.ConfigDir, ".keroosha-rollback.json")
        member this.BinaryPath = Path.Combine(this.InstallDir, Version, "traefik")

    type private Resolver =
        { Email: string
          HttpChallengeEntryPoint: string
          CaServer: string option }

    type private Certificate =
        { CertificatePem: string
          PrivateKeyPem: string
          Fingerprint: string }

    type private RouterTls =
        { Kind: string
          Name: string }

    type private Redirect =
        { Origin: string }

    type private Router =
        { Host: string
          EntryPoint: string
          Backend: string option
          Redirect: Redirect option
          Tls: RouterTls }

    type private Request =
        { Operation: string
          OwnerId: string
          EntryPoints: Map<string, int>
          Resolvers: Map<string, Resolver>
          Routers: Map<string, Router>
          Certificates: Map<string, Certificate>
          AdminPort: int }

    type private FsEntry =
        { Kind: string
          Mode: int
          Uid: int
          Gid: int }

    type private ServiceAccount =
        { Uid: int
          Gid: int
          Home: string
          Shell: string }

    type ApiConfiguration =
        { Routers: JsonElement
          Services: JsonElement
          Middlewares: JsonElement }

    type private PendingTransaction =
        { Static: byte[] option
          Dynamic: byte[] option
          Unit: byte[] option
          ReleaseMarker: byte[] option
          BinaryPresent: bool
          BinarySha256: string option
          WasActive: bool
          WasEnabled: bool
          CertificateFiles: string list }

    let pathsFor (environment: HostEnvironment) =
        { ConfigDir = HostEnvironment.path environment "/etc/keroosha-iac/traefik"
          StateDir = HostEnvironment.path environment "/var/lib/keroosha-traefik"
          InstallDir = HostEnvironment.path environment "/usr/local/libexec/keroosha-iac/traefik"
          UnitPath = HostEnvironment.path environment "/etc/systemd/system/keroosha-traefik.service" }

    let private fail message = raise (BackendError message)

    let private sha256Bytes (bytes: byte[]) =
        SHA256.HashData(bytes) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private sha256Text (value: string) =
        value |> Encoding.UTF8.GetBytes |> sha256Bytes

    let private ownerDigest (ownerId: string) =
        if String.IsNullOrEmpty(ownerId) || ownerId.Length > 4096 then
            fail "ownerId must be a non-empty string"
        if ownerId |> Seq.exists (fun character -> int character < 32 || int character = 127) then
            fail "ownerId contains unsupported characters"
        sha256Text ownerId

    let private stringValue (message: string) (element: JsonElement) =
        if element.ValueKind <> JsonValueKind.String then fail message
        match element.GetString() with
        | null -> fail message
        | value -> value

    let private tryProperty (element: JsonElement) (name: string) =
        let mutable property = Unchecked.defaultof<JsonElement>
        if element.ValueKind = JsonValueKind.Object && element.TryGetProperty(name, &property) then Some property else None

    let private requiredProperty (element: JsonElement) (name: string) (message: string) =
        match tryProperty element name with
        | Some value -> value
        | None -> fail message

    let private requireObject (field: string) (element: JsonElement) =
        if element.ValueKind <> JsonValueKind.Object then fail (field + " must be an object")
        element

    let private objectProperties (field: string) (element: JsonElement) =
        requireObject field element |> fun value -> value.EnumerateObject() |> Seq.toArray

    let private objectNames (element: JsonElement) =
        element.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq

    let private validateName (field: string) (reserved: string list) (value: string) =
        let reservedNames = reserved |> Seq.map (fun name -> name.ToLowerInvariant()) |> Set.ofSeq
        if not (namePattern.IsMatch(value)) || reservedNames.Contains(value.ToLowerInvariant()) then
            fail (field + " contains an unsafe name")
        value

    let private validateDnsName (host: string) =
        if String.IsNullOrEmpty(host) || host.Length > 253 || host.Contains('%') then
            fail "router host must be a DNS name or IP address"
        let mutable address = Unchecked.defaultof<IPAddress>
        if IPAddress.TryParse(host, &address) then
            if address.AddressFamily = AddressFamily.InterNetwork then
                let segments = host.Split('.')
                let validOctets =
                    segments.Length = 4
                    && (segments
                        |> Array.forall (fun segment ->
                            let mutable octet = 0
                            segment.Length > 0
                            && (segment |> Seq.forall Char.IsAsciiDigit)
                            && (segment.Length = 1 || segment[0] <> '0')
                            && Int32.TryParse(segment, NumberStyles.None, CultureInfo.InvariantCulture, &octet)
                            && octet <= 255))
                if not validOctets then fail "router host must be a DNS name or IP address"
            address.ToString().ToLowerInvariant()
        else
            let withoutTrailingDot =
                if host.EndsWith(".", StringComparison.Ordinal) then host.Substring(0, host.Length - 1) else host
            try
                let idn = IdnMapping()
                idn.UseStd3AsciiRules <- true
                let asciiHost = idn.GetAscii(withoutTrailingDot).ToLowerInvariant()
                let labels = asciiHost.Split('.')
                if labels.Length = 0 || (labels |> Array.exists (dnsLabelPattern.IsMatch >> not)) then
                    fail "router host must be a DNS name or IP address"
                asciiHost
            with
            | :? BackendError -> reraise()
            | _ -> fail "router host must be a DNS name or IP address"

    let private validateNetworkUrl message maxLength allowBlank (value: string) =
        if allowBlank && value = "" then None
        else
            try
                if String.IsNullOrEmpty(value)
                   || value.Length > maxLength
                   || (value |> Seq.exists (fun character -> int character < 32 || int character = 127)) then
                    fail message
                let mutable uri = Unchecked.defaultof<Uri>
                if not (Uri.TryCreate(value, UriKind.Absolute, &uri))
                   || (uri.Scheme <> Uri.UriSchemeHttp && uri.Scheme <> Uri.UriSchemeHttps)
                   || String.IsNullOrEmpty(uri.Host)
                   || uri.Authority.Contains('@')
                   || not (String.IsNullOrEmpty(uri.Query.TrimStart('?')))
                   || not (String.IsNullOrEmpty(uri.Fragment.TrimStart('#')))
                   || uri.Port < 1 || uri.Port > 65535 then
                    fail message
                let idn = IdnMapping()
                idn.GetAscii(uri.DnsSafeHost) |> ignore
                Some value
            with
            | :? BackendError -> reraise()
            | _ -> fail message

    let private validateRedirectOrigin (value: string) =
        let message = "redirect origin must be an HTTP or HTTPS origin without a path, userinfo, query, or fragment"
        try
            if String.IsNullOrEmpty(value)
               || value.Length > 2048
               || (value |> Seq.exists (fun character -> Char.IsWhiteSpace(character) || Char.IsControl(character) || character = '\\')) then
                fail message

            let separator = value.IndexOf("://", StringComparison.Ordinal)
            if separator < 0 then fail message
            let scheme = value.Substring(0, separator)
            if not (scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                    || scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) then
                fail message

            let authority = value.Substring(separator + 3)
            if String.IsNullOrEmpty(authority)
               || authority.IndexOfAny([| '/'; '?'; '#'; '@'; '\\'; '%' |]) >= 0 then
                fail message

            let mutable uri = Unchecked.defaultof<Uri>
            if not (Uri.TryCreate(value, UriKind.Absolute, &uri))
               || (uri.Scheme <> Uri.UriSchemeHttp && uri.Scheme <> Uri.UriSchemeHttps)
               || String.IsNullOrEmpty(uri.Host)
               || not (String.IsNullOrEmpty(uri.UserInfo))
               || uri.Port < 1 || uri.Port > 65535 then
                fail message
            match uri.HostNameType with
            | UriHostNameType.Dns -> validateDnsName uri.DnsSafeHost |> ignore
            | UriHostNameType.IPv4
            | UriHostNameType.IPv6 -> ()
            | _ -> fail message
            uri.GetLeftPart(UriPartial.Authority)
        with
        | :? BackendError -> reraise()
        | _ -> fail message

    let private parseInt32 (field: string) (element: JsonElement) =
        let mutable number = 0
        if element.ValueKind <> JsonValueKind.Number || not (element.TryGetInt32(&number)) || number < 1 || number > 65535 then
            fail (field + " must be an integer between 1 and 65535")
        number

    let private parseStringMap (field: string) (parser: string -> JsonElement -> 'T) (element: JsonElement) =
        let values = Dictionary<string, 'T>(StringComparer.Ordinal)
        for property in objectProperties field element do
            values[property.Name] <- parser property.Name property.Value
        values |> Seq.map (fun pair -> pair.Key, pair.Value) |> Map.ofSeq

    let private validateRequest (request: JsonElement) : Request =
        if request.ValueKind <> JsonValueKind.Object then fail "request must be an object"
        let operation =
            requiredProperty request "operation" "unsupported Traefik backend operation"
            |> stringValue "unsupported Traefik backend operation"
        if operation <> "read" && operation <> "apply" && operation <> "delete" then
            fail "unsupported Traefik backend operation"
        let ownerId = requiredProperty request "ownerId" "ownerId must be a non-empty string" |> stringValue "ownerId must be a non-empty string"
        ownerDigest ownerId |> ignore

        if operation = "delete" then
            let allowed = set [ "operation"; "ownerId"; "entryPoints"; "resolvers"; "routers"; "certificates"; "adminPort" ]
            if not (Set.isEmpty (Set.difference (objectNames request) allowed)) then
                fail "delete request contains unsupported fields"
            { Operation = operation
              OwnerId = ownerId
              EntryPoints = Map.empty
              Resolvers = Map.empty
              Routers = Map.empty
              Certificates = Map.empty
              AdminPort = DefaultAdminPort }
        else
            let allowed = set [ "operation"; "ownerId"; "entryPoints"; "resolvers"; "routers"; "certificates"; "adminPort" ]
            if not (Set.isEmpty (Set.difference (objectNames request) allowed)) then fail "request contains unsupported fields"
            for field in [ "entryPoints"; "resolvers"; "routers"; "certificates" ] do
                if tryProperty request field |> Option.isNone then fail ("request is missing " + field)

            let entryPoints =
                parseStringMap "entryPoints" (fun name value ->
                    validateName "entryPoint" [ "keroosha-admin"; "traefik" ] name |> ignore
                    parseInt32 "entryPoint port" value) (requiredProperty request "entryPoints" "request is missing entryPoints")
            let adminPort =
                match tryProperty request "adminPort" with
                | None -> DefaultAdminPort
                | Some value -> parseInt32 "adminPort" value
            if entryPoints |> Map.exists (fun _ port -> port = adminPort) then fail "adminPort must not collide with an entryPoint port"

            let resolvers =
                parseStringMap "resolvers" (fun name value ->
                    validateName "resolver" [] name |> ignore
                    requireObject "resolver" value |> ignore
                    let allowedResolver = set [ "email"; "httpChallengeEntryPoint"; "caServer" ]
                    if not (Set.isEmpty (Set.difference (objectNames value) allowedResolver)) then fail "resolver configuration is invalid"
                    let email = requiredProperty value "email" "resolver email is invalid" |> stringValue "resolver email is invalid"
                    if email.Length > 254
                       || ((email |> Seq.filter ((=) '@') |> Seq.length) <> 1)
                       || (email |> Seq.exists (fun character -> int character < 33 || int character = 127)) then
                        fail "resolver email is invalid"
                    let challenge = requiredProperty value "httpChallengeEntryPoint" "httpChallengeEntryPoint contains an unsafe name" |> stringValue "httpChallengeEntryPoint contains an unsafe name"
                    validateName "httpChallengeEntryPoint" [] challenge |> ignore
                    if not (entryPoints.ContainsKey(challenge)) then fail "resolver HTTP challenge entryPoint is not declared"
                    let caServer =
                        match tryProperty value "caServer" with
                        | None -> None
                        | Some ca when ca.ValueKind = JsonValueKind.Null -> None
                        | Some ca ->
                            let raw = stringValue "resolver caServer must be an HTTP or HTTPS URL" ca
                            validateNetworkUrl "resolver caServer must be an HTTP or HTTPS URL" 2048 true raw

                    { Email = email; HttpChallengeEntryPoint = challenge; CaServer = caServer }) (requiredProperty request "resolvers" "request is missing resolvers")

            let certificates =
                parseStringMap "certificates" (fun name value ->
                    validateName "certificate" [] name |> ignore
                    requireObject "certificate" value |> ignore
                    if objectNames value <> set [ "certificatePem"; "privateKeyPem"; "fingerprint" ] then fail "certificate configuration is invalid"
                    let certificatePem = requiredProperty value "certificatePem" "certificatePem is not valid PEM material" |> stringValue "certificatePem is not valid PEM material"
                    if String.IsNullOrEmpty(certificatePem) || Encoding.UTF8.GetByteCount(certificatePem) > MaximumCertificateBytes || not (certificatePem.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)) then
                        fail "certificatePem is not valid PEM material"
                    let privateKeyPem = requiredProperty value "privateKeyPem" "privateKeyPem is not valid PEM material" |> stringValue "privateKeyPem is not valid PEM material"
                    if String.IsNullOrEmpty(privateKeyPem) || Encoding.UTF8.GetByteCount(privateKeyPem) > MaximumCertificateBytes || not (privateKeyPem.Contains("-----BEGIN ", StringComparison.Ordinal)) || not (privateKeyPem.Contains("PRIVATE KEY-----", StringComparison.Ordinal)) then
                        fail "privateKeyPem is not valid PEM material"
                    let fingerprint = requiredProperty value "fingerprint" "certificate fingerprint must be lowercase SHA-256 hex" |> stringValue "certificate fingerprint must be lowercase SHA-256 hex"
                    if not (fingerprintPattern.IsMatch(fingerprint)) then fail "certificate fingerprint must be lowercase SHA-256 hex"
                    { CertificatePem = certificatePem; PrivateKeyPem = privateKeyPem; Fingerprint = fingerprint }) (requiredProperty request "certificates" "request is missing certificates")

            let routers =
                parseStringMap "routers" (fun name value ->
                    validateName "router" [ "keroosha-admin" ] name |> ignore
                    requireObject "router" value |> ignore
                    let fields = objectNames value
                    if not (Set.isSubset (set [ "host"; "entryPoint"; "tls" ]) fields)
                       || not (Set.isEmpty (Set.difference fields (set [ "host"; "entryPoint"; "backend"; "redirect"; "tls" ]))) then
                        fail "router configuration is invalid"
                    let host = requiredProperty value "host" "router host must be a DNS name or IP address" |> stringValue "router host must be a DNS name or IP address" |> validateDnsName
                    let entryPoint = requiredProperty value "entryPoint" "router entryPoint contains an unsafe name" |> stringValue "router entryPoint contains an unsafe name"
                    validateName "router entryPoint" [] entryPoint |> ignore
                    if not (entryPoints.ContainsKey(entryPoint)) then fail "router entryPoint is not declared"
                    let tls = requiredProperty value "tls" "router TLS configuration is invalid"
                    requireObject "router TLS configuration" tls |> ignore
                    if objectNames tls <> set [ "kind"; "name" ] then fail "router TLS configuration is invalid"
                    let kind = requiredProperty tls "kind" "router TLS kind is invalid" |> stringValue "router TLS kind is invalid"
                    let tlsName = requiredProperty tls "name" "router TLS configuration is invalid" |> stringValue "router TLS configuration is invalid"
                    match kind with
                    | "none" -> if tlsName <> "" then fail "non-TLS router name must be empty"
                    | "acme" ->
                        validateName "TLS resolver" [] tlsName |> ignore
                        if not (resolvers.ContainsKey(tlsName)) then fail "router references an undeclared ACME resolver"
                    | "provided" ->
                        validateName "TLS certificate" [] tlsName |> ignore
                        if not (certificates.ContainsKey(tlsName)) then fail "router references an undeclared certificate"
                    | _ -> fail "router TLS kind is invalid"
                    let backend, redirect =
                        match tryProperty value "backend", tryProperty value "redirect" with
                        | Some backend, None ->
                            let backend = stringValue "router backend must be an HTTP or HTTPS URL" backend
                            validateNetworkUrl "router backend must be an HTTP or HTTPS URL" 2048 false backend |> ignore
                            Some backend, None
                        | None, Some redirect ->
                            requireObject "router redirect" redirect |> ignore
                            if objectNames redirect <> set [ "kind"; "origin" ] then fail "router redirect configuration is invalid"
                            let redirectKind = requiredProperty redirect "kind" "router redirect kind is invalid" |> stringValue "router redirect kind is invalid"
                            if redirectKind <> "permanentToOrigin" then fail "router redirect kind is invalid"
                            let origin = requiredProperty redirect "origin" "router redirect origin is invalid" |> stringValue "router redirect origin is invalid"
                            None, Some { Origin = validateRedirectOrigin origin }
                        | _ -> fail "router must specify exactly one of backend or redirect"
                    { Host = host; EntryPoint = entryPoint; Backend = backend; Redirect = redirect; Tls = { Kind = kind; Name = tlsName } }) (requiredProperty request "routers" "request is missing routers")

            { Operation = operation
              OwnerId = ownerId
              EntryPoints = entryPoints
              Resolvers = resolvers
              Routers = routers
              Certificates = certificates
              AdminPort = adminPort }

    let private jsonWriterOptions =
        JsonWriterOptions(Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping)

    let private serializerOptions = JsonSerializerOptions(Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping)

    let private writeSortedNode (writer: Utf8JsonWriter) (node: JsonNode) =
        let rec write (current: JsonNode) =
            match current with
            | null -> writer.WriteNullValue()
            | :? JsonObject as objectNode ->
                writer.WriteStartObject()
                objectNode
                |> Seq.sortBy (fun item -> item.Key)
                |> Seq.iter (fun item ->
                    writer.WritePropertyName(item.Key)
                    write item.Value)
                writer.WriteEndObject()
            | :? JsonArray as arrayNode ->
                writer.WriteStartArray()
                for item in arrayNode do write item
                writer.WriteEndArray()
            | _ -> current.WriteTo(writer, serializerOptions)
        write node

    let private jsonText (node: JsonNode) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream, jsonWriterOptions)
        writeSortedNode writer node
        writer.Flush()
        Encoding.UTF8.GetString(stream.ToArray()) + "\n"

    let private serviceNameForBackend backend = "keroosha-backend-" + sha256Text backend
    let private redirectMiddlewareName routerName origin = "keroosha-redirect-" + sha256Text (routerName + "\n" + origin)
    let private redirectRegex = "^https?://[^/?#]+(.*)$"

    let private redirectReplacement (origin: string) =
        origin.Replace("$", "$$") + "${1}"

    let private materialDigest (certificate: Certificate) =
        let certificateBytes = Encoding.UTF8.GetBytes(certificate.CertificatePem)
        let keyBytes = Encoding.UTF8.GetBytes(certificate.PrivateKeyPem)
        let material = Array.zeroCreate<byte> (certificateBytes.Length + 1 + keyBytes.Length)
        Buffer.BlockCopy(certificateBytes, 0, material, 0, certificateBytes.Length)
        Buffer.BlockCopy(keyBytes, 0, material, certificateBytes.Length + 1, keyBytes.Length)
        sha256Bytes material

    let private hostRuleValue (host: string) =
        let mutable address = Unchecked.defaultof<IPAddress>
        if IPAddress.TryParse(host, &address) && address.AddressFamily = AddressFamily.InterNetworkV6 then
            "[" + address.ToString().ToLowerInvariant() + "]"
        else host

    let renderStaticConfig (request: JsonElement) (paths: RuntimePaths) (listenHost: string) =
        let normalized = validateRequest request
        let staticConfig = JsonObject()
        let entryPoints = JsonObject()
        for KeyValue(name, port) in normalized.EntryPoints do
            let entryPoint = JsonObject()
            entryPoint["address"] <- JsonValue.Create(listenHost + ":" + port.ToString(CultureInfo.InvariantCulture))
            entryPoints[name] <- entryPoint
        let admin = JsonObject()
        admin["address"] <- JsonValue.Create("127.0.0.1:" + normalized.AdminPort.ToString(CultureInfo.InvariantCulture))
        entryPoints["keroosha-admin"] <- admin
        staticConfig["entryPoints"] <- entryPoints
        let api = JsonObject()
        api["dashboard"] <- JsonValue.Create(true)
        staticConfig["api"] <- api
        let fileProvider = JsonObject()
        fileProvider["directory"] <- JsonValue.Create(paths.DynamicDir)
        fileProvider["watch"] <- JsonValue.Create(true)
        let providers = JsonObject()
        providers["file"] <- fileProvider
        staticConfig["providers"] <- providers
        let resolvers = JsonObject()
        for KeyValue(name, resolver) in normalized.Resolvers do
            let acme = JsonObject()
            acme["email"] <- JsonValue.Create(resolver.Email)
            acme["storage"] <- JsonValue.Create(Path.Combine(paths.StateDir, "acme-" + sha256Text name + ".json"))
            let challenge = JsonObject()
            challenge["entryPoint"] <- JsonValue.Create(resolver.HttpChallengeEntryPoint)
            acme["httpChallenge"] <- challenge
            acme["caServer"] <- JsonValue.Create(defaultArg resolver.CaServer DefaultCaServer)
            let resolverConfig = JsonObject()
            resolverConfig["acme"] <- acme
            resolvers[name] <- resolverConfig
        if resolvers.Count > 0 then
            staticConfig["certificatesResolvers"] <- resolvers
        jsonText staticConfig

    let renderDynamicConfig (request: JsonElement) (paths: RuntimePaths) =
        let normalized = validateRequest request
        let dynamicConfig = JsonObject()
        let http = JsonObject()
        let routers = JsonObject()
        let admin = JsonObject()
        admin["rule"] <- JsonValue.Create("PathPrefix(`/api`) || PathPrefix(`/dashboard`)")
        let adminEntryPoints = JsonArray()
        adminEntryPoints.Add(JsonValue.Create("keroosha-admin"))
        admin["entryPoints"] <- adminEntryPoints
        admin["service"] <- JsonValue.Create("api@internal")
        admin["priority"] <- JsonValue.Create(1000000)
        routers["keroosha-admin"] <- admin
        let services = JsonObject()
        let middlewares = JsonObject()
        for KeyValue(name, router) in normalized.Routers do
            let dynamicRouter = JsonObject()
            dynamicRouter["rule"] <- JsonValue.Create("Host(`" + hostRuleValue router.Host + "`)") 
            let entryPoints = JsonArray()
            entryPoints.Add(JsonValue.Create(router.EntryPoint))
            dynamicRouter["entryPoints"] <- entryPoints
            match router.Backend, router.Redirect with
            | Some backend, None ->
                let serviceName = serviceNameForBackend backend
                dynamicRouter["service"] <- JsonValue.Create(serviceName)
                let loadBalancer = JsonObject()
                let servers = JsonArray()
                let server = JsonObject()
                server["url"] <- JsonValue.Create(backend)
                servers.Add(server)
                loadBalancer["servers"] <- servers
                let service = JsonObject()
                service["loadBalancer"] <- loadBalancer
                services[serviceName] <- service
            | None, Some redirect ->
                let middlewareName = redirectMiddlewareName name redirect.Origin
                let redirectRegexConfig = JsonObject()
                redirectRegexConfig["regex"] <- JsonValue.Create(redirectRegex)
                redirectRegexConfig["replacement"] <- JsonValue.Create(redirectReplacement redirect.Origin)
                redirectRegexConfig["permanent"] <- JsonValue.Create(true)
                let middleware = JsonObject()
                middleware["redirectRegex"] <- redirectRegexConfig
                middlewares[middlewareName] <- middleware
                let routeMiddlewares = JsonArray()
                routeMiddlewares.Add(JsonValue.Create(middlewareName))
                dynamicRouter["middlewares"] <- routeMiddlewares
                dynamicRouter["service"] <- JsonValue.Create("noop@internal")
            | _ -> fail "router must specify exactly one of backend or redirect"
            match router.Tls.Kind with
            | "acme" ->
                let tls = JsonObject()
                tls["certResolver"] <- JsonValue.Create(router.Tls.Name)
                dynamicRouter["tls"] <- tls
            | "provided" -> dynamicRouter["tls"] <- JsonObject()
            | _ -> ()
            routers[name] <- dynamicRouter
        http["routers"] <- routers
        if services.Count > 0 then http["services"] <- services
        if middlewares.Count > 0 then http["middlewares"] <- middlewares
        dynamicConfig["http"] <- http
        let tlsRoot = JsonObject()
        let certificates = JsonArray()
        for KeyValue(_, certificate) in normalized.Certificates do
            let digest = materialDigest certificate
            let item = JsonObject()
            item["certFile"] <- JsonValue.Create(Path.Combine(paths.CertificateDir, digest + ".crt"))
            item["keyFile"] <- JsonValue.Create(Path.Combine(paths.CertificateDir, digest + ".key"))
            certificates.Add(item)
        tlsRoot["certificates"] <- certificates
        dynamicConfig["tls"] <- tlsRoot
        jsonText dynamicConfig

    let renderSystemdUnit (paths: RuntimePaths) =
        String.concat "\n" [
            "[Unit]"
            "Description=Dorothy managed Traefik reverse proxy"
            "Wants=network-online.target"
            "After=network-online.target"
            ""
            "[Service]"
            "Type=simple"
            "User=" + ServiceUser
            "Group=" + ServiceGroup
            "ExecStart=" + paths.BinaryPath + " --configFile=" + Path.Combine(paths.ConfigDir, "static.yml")
            "Restart=on-failure"
            "RestartSec=2s"
            "StateDirectory=keroosha-traefik"
            "StateDirectoryMode=0700"
            "WorkingDirectory=" + paths.StateDir
            "NoNewPrivileges=true"
            "ProtectSystem=strict"
            "ProtectHome=true"
            "PrivateTmp=true"
            "ProtectKernelTunables=true"
            "ProtectKernelModules=true"
            "ProtectControlGroups=true"
            "RestrictSUIDSGID=true"
            "LockPersonality=true"
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
            "AmbientCapabilities=CAP_NET_BIND_SERVICE"
            ""
            "[Install]"
            "WantedBy=multi-user.target"
            ""
        ]

    let private unitText (paths: RuntimePaths) (ownerId: string) : string = "# keroosha-owner=" + ownerDigest ownerId + "\n" + renderSystemdUnit paths

    let private unixMode (value: int) = enum<UnixFileMode>(value)

    let private run (environment: HostEnvironment) executable arguments =
        environment.Run executable arguments None

    let private runOk (environment: HostEnvironment) (message: string) (executable: string) (arguments: string list) : CommandResult =
        let result = run environment executable arguments
        if result.ExitCode <> 0 then fail message
        result

    let private nativeKind (mode: int) =
        match mode &&& 0xF000 with
        | 0x4000 -> "directory"
        | 0x8000 -> "regular file"
        | 0xA000 -> "symbolic link"
        | _ -> "other"

    let private tryStat (_environment: HostEnvironment) (path: string) : FsEntry option =
        let mutable metadata = Unchecked.defaultof<TraefikLinuxStatx>
        let result = nativeStatx(-100, path, 0x100, 0x1Bu, &metadata)
        if result = 0 then
            Some {
                Kind = nativeKind (int metadata.Mode)
                Mode = int metadata.Mode &&& 0x0FFF
                Uid = int metadata.UserId
                Gid = int metadata.GroupId
            }
        elif Marshal.GetLastWin32Error() = 2 then None
        else fail "cannot inspect Traefik path"

    let private fsEntry (metadata: TraefikLinuxStatx) : FsEntry =
        { Kind = nativeKind (int metadata.Mode)
          Mode = int metadata.Mode &&& 0x0FFF
          Uid = int metadata.UserId
          Gid = int metadata.GroupId }

    let private statDescriptor (descriptor: int) : FsEntry =
        let mutable metadata = Unchecked.defaultof<TraefikLinuxStatx>
        if nativeStatx(descriptor, "", 0x1000, 0x1Bu, &metadata) <> 0 then
            fail "cannot safely inspect Traefik owned path"
        fsEntry metadata

    let private openChecked (path: string) (directory: bool) : int =
        // Metadata syscalls work on read-only descriptors; O_RDWR rejects running executables.
        let flags = 0x80000 ||| 0x20000 ||| (if directory then 0x10000 else 0x800)
        let descriptor = nativeOpen(path, flags, 0)
        if descriptor < 0 then fail "cannot safely open Traefik owned path"
        try
            let metadata = statDescriptor descriptor
            let expectedKind = if directory then "directory" else "regular file"
            if metadata.Kind <> expectedKind then fail "Traefik owned path has an unexpected file type"
            descriptor
        with _ ->
            nativeClose(descriptor) |> ignore
            reraise()

    let private assertDirectory (environment: HostEnvironment) (path: string) (description: string) : bool =
        match tryStat environment path with
        | None -> false
        | Some item when item.Kind = "directory" -> true
        | Some _ -> fail (description + " collides with a non-directory path")

    let private assertRegular (environment: HostEnvironment) (path: string) (description: string) : bool =
        match tryStat environment path with
        | None -> false
        | Some item when item.Kind = "regular file" -> true
        | Some _ -> fail (description + " collides with a non-regular file")

    let private readDescriptor (descriptor: int) : byte[] =
        let handle = new SafeFileHandle(nativeint descriptor, false)
        use stream = new FileStream(handle, FileAccess.Read)
        use output = new MemoryStream()
        stream.CopyTo(output)
        output.ToArray()

    let private readBytes (_environment: HostEnvironment) (path: string) : byte[] =
        let descriptor = openChecked path false
        try
            try readDescriptor descriptor
            with _ -> fail "cannot read Traefik owned file"
        finally
            nativeClose(descriptor) |> ignore
    let private setMode (_environment: HostEnvironment) (path: string) (mode: int) (directory: bool) =
        let descriptor = openChecked path directory
        try
            if nativeFchmod(descriptor, uint32 mode) <> 0 || nativeFsync(descriptor) <> 0 then
                fail "cannot secure Traefik file permissions"
        finally nativeClose(descriptor) |> ignore
    let private chown (environment: HostEnvironment) (path: string) (uid: int) (gid: int) =
        let directory =
            match tryStat environment path with
            | Some item when item.Kind = "directory" -> true
            | Some item when item.Kind = "regular file" -> false
            | _ -> fail "cannot secure Traefik file ownership"
        let descriptor = openChecked path directory
        try
            if nativeFchown(descriptor, uint32 uid, uint32 gid) <> 0 || nativeFsync(descriptor) <> 0 then
                fail "cannot secure Traefik file ownership"
        finally nativeClose(descriptor) |> ignore

    let private writeAtomic (environment: HostEnvironment) (path: string) (data: byte[]) (mode: int) (groupId: int option) =
        if not (assertDirectory environment (Path.GetDirectoryName(path)) "Traefik configuration directory") then
            fail "Traefik configuration directory is unavailable"
        HostFiles.atomicWrite path data (unixMode mode)
        let uid = runOk environment "cannot secure Traefik file ownership" "id" [ "-u" ] |> fun result -> Int32.Parse(result.Stdout.Trim(), CultureInfo.InvariantCulture)
        let gid = defaultArg groupId (runOk environment "cannot secure Traefik file ownership" "id" [ "-g" ] |> fun result -> Int32.Parse(result.Stdout.Trim(), CultureInfo.InvariantCulture))
        chown environment path uid gid

    let private chmod (environment: HostEnvironment) (path: string) (mode: int) =
        setMode environment path mode false


    let private fsyncDirectory (path: string) =
        let descriptor = nativeOpen(path, 0x80000 ||| 0x20000 ||| 0x10000, 0)
        if descriptor < 0 then fail "cannot synchronize Traefik directory"
        try
            if nativeFsync(descriptor) <> 0 then fail "cannot synchronize Traefik directory"
        finally
            nativeClose(descriptor) |> ignore

    let private modeHas (mode: int) (bit: int) : bool = mode &&& bit <> 0

    let private ensureDirectory (environment: HostEnvironment) (path: string) (mode: int) (groupId: int option) =
        let path = Path.GetFullPath(path)
        let missing = ResizeArray<string>()
        let mutable cursor = path
        let mutable found = false
        while not found do
            match tryStat environment cursor with
            | Some item when item.Kind = "directory" -> found <- true
            | Some _ -> fail "Traefik directory collides with a non-directory path"
            | None ->
                missing.Add(cursor)
                let parent = Directory.GetParent(cursor)
                if isNull parent then fail "Traefik directory is unavailable"
                cursor <- parent.FullName
        let mutable ancestor = Directory.GetParent(cursor)
        while not (isNull ancestor) && ancestor.FullName <> Path.GetPathRoot(ancestor.FullName) do
            match tryStat environment ancestor.FullName with
            | Some item when item.Kind = "directory" ->
                let groupTraversable = groupId |> Option.exists (fun gid -> item.Gid = gid && modeHas item.Mode 0o010)
                if not groupTraversable && not (modeHas item.Mode 0o001) then
                    fail "Traefik service account cannot traverse a managed path"
            | _ -> fail "Traefik path contains a symbolic-link or non-directory ancestor"
            ancestor <- Directory.GetParent(ancestor.FullName)
        for directory in missing |> Seq.rev do
            try
                Directory.CreateDirectory(directory) |> ignore
                if directory <> path then setMode environment directory 0o755 true
            with _ -> fail "cannot create Traefik directory"
            if not (assertDirectory environment directory "Traefik directory") then fail "Traefik directory is unavailable"
        if not (assertDirectory environment path "Traefik directory") then fail "Traefik directory is unavailable"
        try
            setMode environment path mode true
            match groupId with
            | Some gid ->
                let uid = runOk environment "cannot secure Traefik directory" "id" [ "-u" ] |> fun result -> Int32.Parse(result.Stdout.Trim(), CultureInfo.InvariantCulture)
                chown environment path uid gid
            | None -> ()
        with
        | :? BackendError -> reraise()
        | _ -> fail "cannot secure Traefik directory"

    let private markerStatus (environment: HostEnvironment) (directory: string) (ownerId: string) : string =
        if not (assertDirectory environment directory "Traefik owned directory") then "absent"
        else
            let marker = Path.Combine(directory, ".keroosha-owner")
            if not (assertRegular environment marker "Traefik ownership marker") then "unmarked"
            else
                let bytes = readBytes environment marker
                if bytes |> Array.exists (fun value -> value > 127uy) then fail "cannot read Traefik ownership marker"
                let value = Encoding.ASCII.GetString(bytes).Trim()
                if value = ownerDigest ownerId then "owned" else "foreign"

    let private checkDirectoryOwnership (environment: HostEnvironment) (directory: string) (ownerId: string) (description: string) : string =
        let status = markerStatus environment directory ownerId
        if status = "unmarked" || status = "foreign" then fail (description + " collides with an unowned Traefik path")
        status

    let private entries (directory: string) : string[] =
        try Directory.EnumerateFileSystemEntries(directory) |> Seq.map (fun (entry: string) -> Path.GetFileName(entry)) |> Seq.toArray
        with _ -> fail "cannot inspect Traefik directory"

    let private validateOwnedConfigContents (environment: HostEnvironment) (paths: RuntimePaths) =
        let allowedRoot = set [ ".keroosha-owner"; ".keroosha-rollback.json"; "static.yml"; "dynamic" ]
        try
            let rootEntries = entries paths.ConfigDir |> Set.ofArray
            if not (Set.isEmpty (Set.difference rootEntries allowedRoot)) then
                fail "configuration directory contains unknown files"
            if assertDirectory environment paths.DynamicDir "dynamic configuration directory" then
                let dynamicEntries = entries paths.DynamicDir |> Set.ofArray
                if not (Set.isEmpty (Set.difference dynamicEntries (set [ ".keroosha-owner"; "current.yml"; "certificates" ]))) then
                    fail "dynamic configuration directory contains unknown files"
            if assertDirectory environment paths.CertificateDir "certificate directory" then
                for filename in entries paths.CertificateDir do
                    if filename <> ".keroosha-owner" then
                        if not (certificateFilenamePattern.IsMatch(filename)) then fail "certificate directory contains unknown files"
                        if not (assertRegular environment (Path.Combine(paths.CertificateDir, filename)) "certificate material") then
                            fail "certificate material is unavailable"
            for filePath in [ Path.Combine(paths.ConfigDir, "static.yml"); Path.Combine(paths.DynamicDir, "current.yml") ] do
                if tryStat environment filePath |> Option.isSome then
                    if not (assertRegular environment filePath "configuration file") then fail "configuration file is unavailable"
        with
        | :? BackendError -> reraise()
        | _ -> fail "cannot inspect Traefik configuration directory"

    let private validateOwnedStateContents (environment: HostEnvironment) (stateDir: string) =
        try
            for filename in entries stateDir do
                if filename <> ".keroosha-owner" then
                    if not (acmeFilenamePattern.IsMatch(filename)) then fail "state directory contains unknown files"
                    if not (assertRegular environment (Path.Combine(stateDir, filename)) "ACME storage") then fail "ACME storage is unavailable"
        with
        | :? BackendError -> reraise()
        | _ -> fail "cannot inspect Traefik state directory"

    let rec checkLayoutCollisions (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) : string * string * string * byte[] option =
        let configStatus = checkDirectoryOwnership environment paths.ConfigDir ownerId "configuration directory"
        let stateStatus = checkDirectoryOwnership environment paths.StateDir ownerId "state directory"
        let installStatus = checkDirectoryOwnership environment paths.InstallDir ownerId "installation directory"
        for path, description in [
            paths.DynamicDir, "dynamic configuration directory"
            paths.CertificateDir, "certificate directory"
            Path.GetDirectoryName(paths.BinaryPath), "binary version directory"
        ] do assertDirectory environment path description |> ignore
        for path, description in [
            Path.Combine(paths.ConfigDir, "static.yml"), "static configuration"
            Path.Combine(paths.DynamicDir, "current.yml"), "dynamic configuration"
            paths.UnitPath, "systemd service unit"
            paths.BinaryPath, "Traefik binary"
            paths.RollbackPath, "activation rollback journal"
        ] do assertRegular environment path description |> ignore
        if configStatus = "owned" then validateOwnedConfigContents environment paths
        if installStatus = "owned" then
            let known = set [ ".keroosha-owner"; ".keroosha-release.json"; Version ]
            if not (Set.isEmpty (Set.difference (Set.ofArray (entries paths.InstallDir)) known)) then
                fail "installation directory contains unknown files"
            let releasePath = Path.Combine(paths.InstallDir, ".keroosha-release.json")
            if (tryStat environment releasePath |> Option.isSome) && not (assertRegular environment releasePath "Traefik release marker") then
                fail "Traefik release marker is unavailable"
            let versionPath = Path.Combine(paths.InstallDir, Version)
            if assertDirectory environment versionPath "binary directory" then
                if not (Set.isEmpty (Set.difference (Set.ofArray (entries versionPath)) (set [ "traefik" ]))) then
                    fail "binary directory contains unknown files"
        if stateStatus = "owned" then validateOwnedStateContents environment paths.StateDir
        let unitData = safeUnitStatus environment paths.UnitPath ownerId
        if unitData.IsSome && configStatus <> "owned" then fail "Traefik service unit has no matching owned configuration"
        configStatus, stateStatus, installStatus, unitData

    and private safeUnitStatus (environment: HostEnvironment) (path: string) (ownerId: string) : byte[] option =
        if not (assertRegular environment path "systemd service unit") then None
        else
            let data = readBytes environment path
            let expectedLine = "# keroosha-owner=" + ownerDigest ownerId
            let hasOwnerLine =
                try
                    let text = UTF8Encoding(false, true).GetString(data)
                    let lines = text.Split('\n', StringSplitOptions.None)
                    lines
                    |> Array.mapi (fun index line -> index, line)
                    |> Array.exists (fun (index, line) -> index < lines.Length - 1 && line = expectedLine)
                with _ -> false
            if not hasOwnerLine then fail "systemd service unit collides with an unowned unit"
            Some data

    let private createOwnedDirectory (environment: HostEnvironment) (path: string) (ownerId: string) (mode: int) (groupId: int option) : string =
        let status = markerStatus environment path ownerId
        if status = "unmarked" || status = "foreign" then fail "Traefik directory collides with an unowned path"
        ensureDirectory environment path mode groupId
        if status = "absent" then
            let marker = Encoding.ASCII.GetBytes(ownerDigest ownerId + "\n")
            writeAtomic environment (Path.Combine(path, ".keroosha-owner")) marker 0o644 None
        status

    let private parseIdCommand (environment: HostEnvironment) (optionName: string) : int =
        let result = runOk environment "cannot inspect Traefik host identity" "id" [ optionName ]
        Int32.Parse(result.Stdout.Trim(), CultureInfo.InvariantCulture)

    let private lookupUser (environment: HostEnvironment) : ServiceAccount option =
        let result = run environment "getent" [ "passwd"; ServiceUser ]
        if result.ExitCode <> 0 then None
        else
            try
                let fields = result.Stdout.Trim().Split(':')
                if fields.Length < 7 || fields[0] <> ServiceUser then fail "dedicated Traefik service account has unexpected properties"
                Some { Uid = Int32.Parse(fields[2], CultureInfo.InvariantCulture); Gid = Int32.Parse(fields[3], CultureInfo.InvariantCulture); Home = fields[5]; Shell = fields[6] }
            with
            | :? BackendError -> reraise()
            | _ -> fail "cannot inspect dedicated Traefik service account"

    let private lookupGroup (environment: HostEnvironment) : int option =
        let result = run environment "getent" [ "group"; ServiceGroup ]
        if result.ExitCode <> 0 then None
        else
            try
                let fields = result.Stdout.Trim().Split(':')
                if fields.Length < 3 || fields[0] <> ServiceGroup then fail "dedicated Traefik service account has unexpected properties"
                Some(Int32.Parse(fields[2], CultureInfo.InvariantCulture))
            with
            | :? BackendError -> reraise()
            | _ -> fail "cannot inspect dedicated Traefik service account"

    let private ensureServiceUser (environment: HostEnvironment) (ownedLayout: bool) (stateDir: string) : ServiceAccount * int =
        let user = lookupUser environment
        let group = lookupGroup environment
        match user, group with
        | Some _, Some _ when not ownedLayout -> fail "dedicated Traefik service account collides with an unowned account"
        | None, None ->
            runOk environment "cannot create dedicated non-root Traefik service account" "useradd" [
                "--system"; "--user-group"; "--no-create-home"; "--home-dir"; stateDir; "--shell"; "/usr/sbin/nologin"; ServiceUser
            ] |> ignore
            match lookupUser environment, lookupGroup environment with
            | Some createdUser, Some createdGroup ->
                if createdUser.Gid <> createdGroup || createdUser.Shell <> "/usr/sbin/nologin" || createdUser.Home <> stateDir || createdUser.Uid = 0 then
                    fail "dedicated Traefik service account has unexpected properties"
                createdUser, createdGroup
            | _ -> fail "cannot create dedicated non-root Traefik service account"
        | Some existingUser, Some existingGroup ->
            if existingUser.Gid <> existingGroup || existingUser.Shell <> "/usr/sbin/nologin" || existingUser.Home <> stateDir || existingUser.Uid = 0 then
                fail "dedicated Traefik service account has unexpected properties"
            existingUser, existingGroup
        | _ ->
            runOk environment "cannot create dedicated non-root Traefik service account" "useradd" [
                "--system"; "--user-group"; "--no-create-home"; "--home-dir"; stateDir; "--shell"; "/usr/sbin/nologin"; ServiceUser
            ] |> ignore
            match lookupUser environment, lookupGroup environment with
            | Some createdUser, Some createdGroup -> createdUser, createdGroup
            | _ -> fail "cannot create dedicated non-root Traefik service account"

    let private ensureLayout (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) (existingOwned: bool) : ServiceAccount * int =
        let user, groupId = ensureServiceUser environment existingOwned paths.StateDir
        createOwnedDirectory environment paths.ConfigDir ownerId 0o750 (Some groupId) |> ignore
        createOwnedDirectory environment paths.DynamicDir ownerId 0o750 (Some groupId) |> ignore
        createOwnedDirectory environment paths.CertificateDir ownerId 0o750 (Some groupId) |> ignore
        createOwnedDirectory environment paths.StateDir ownerId 0o700 None |> ignore
        chown environment paths.StateDir user.Uid groupId
        try
            for filename in entries paths.StateDir do
                if acmeFilenamePattern.IsMatch(filename) then
                    let storagePath = Path.Combine(paths.StateDir, filename)
                    chmod environment storagePath 0o600
                    chown environment storagePath user.Uid groupId
        with
        | :? BackendError -> reraise()
        | _ -> fail "cannot secure Traefik ACME storage"
        user, groupId

    let metadataMatches (environment: HostEnvironment) (path: string) (expectedKind: string) (mode: int) (uid: int) (gid: int) : bool =
        match tryStat environment path with
        | Some item ->
            let validKind =
                if expectedKind = "directory" then item.Kind = "directory"
                else item.Kind = "regular file" || item.Kind = "regular empty file"
            validKind && item.Mode = mode && item.Uid = uid && item.Gid = gid
        | None -> false

    let private hostOwner (environment: HostEnvironment) : int * int =
        let uid = parseIdCommand environment "-u"
        let gid = parseIdCommand environment "-g"
        if uid = 0 then 0, 0 else uid, gid

    let private architecture () : string =
        if not (OperatingSystem.IsLinux()) then fail "Traefik binary is supported only on Linux amd64 and arm64"
        match RuntimeInformation.OSArchitecture with
        | Architecture.X64 -> "amd64"
        | Architecture.Arm64 -> "arm64"
        | _ -> fail "Traefik binary is supported only on Linux amd64 and arm64"

    let private createTemporaryFile () =
        let path = Path.Combine(Path.GetTempPath(), "dorothy-traefik-" + Guid.NewGuid().ToString("N"))
        let options = FileStreamOptions()
        options.Mode <- FileMode.CreateNew
        options.Access <- FileAccess.ReadWrite
        options.Share <- FileShare.None
        options.BufferSize <- 65536
        options.Options <- FileOptions.DeleteOnClose ||| FileOptions.SequentialScan
        options.UnixCreateMode <- Nullable<UnixFileMode>(UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
        new FileStream(path, options)

    /// Copies a release archive with bounded buffers and verifies its compressed size and SHA-256.
    /// Leaves both streams open; callers must discard the destination if verification fails.
    let copyVerifiedArchive
        (source: Stream)
        (destination: Stream)
        (maximumBytes: int64)
        (expectedChecksum: string)
        (readTimeout: CancellationTokenSource)
        : Task<int64> =
        if isNull source then nullArg "source"
        if isNull destination then nullArg "destination"
        if isNull readTimeout then nullArg "readTimeout"
        if maximumBytes < 0L then invalidArg "maximumBytes" "The archive size limit cannot be negative."
        if not source.CanRead then invalidArg "source" "The archive stream must be readable."
        if not destination.CanWrite then invalidArg "destination" "The archive destination must be writable."

        task {
            use hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
            let buffer = Array.zeroCreate<byte> 65536
            let mutable total = 0L
            let mutable finished = false

            while not finished do
                readTimeout.CancelAfter(TimeSpan.FromSeconds(30.0))
                let! count = source.ReadAsync(buffer.AsMemory(0, buffer.Length), readTimeout.Token).ConfigureAwait(false)
                readTimeout.CancelAfter(Timeout.InfiniteTimeSpan)

                if count = 0 then
                    finished <- true
                else
                    if int64 count > maximumBytes - total then
                        fail "pinned Traefik release archive exceeds the size limit"

                    hash.AppendData(buffer, 0, count)
                    destination.Write(buffer, 0, count)
                    total <- total + int64 count

            let checksum =
                hash.GetHashAndReset()
                |> Convert.ToHexString
                |> fun value -> value.ToLowerInvariant()

            if checksum <> expectedChecksum then
                fail "pinned Traefik release archive checksum does not match"

            return total
        }

    let private downloadArchive (architecture: string) (cancellationToken: CancellationToken) : Task<FileStream> =
        task {
            let output = createTemporaryFile ()

            try
                use client = new HttpClient(Timeout = TimeSpan.FromSeconds(30.0))
                use request = new HttpRequestMessage(HttpMethod.Get, releaseUrl architecture)
                request.Headers.UserAgent.ParseAdd("keroosha-iac-traefik/1")
                use! response =
                    client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                        .ConfigureAwait(false)

                if not response.IsSuccessStatusCode then
                    fail "cannot download the pinned Traefik release archive"

                if response.Content.Headers.ContentLength.HasValue
                   && response.Content.Headers.ContentLength.Value > int64 MaximumArchiveBytes then
                    fail "pinned Traefik release archive exceeds the size limit"

                use! stream = response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false)
                use readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
                let! _ =
                    (copyVerifiedArchive stream output (int64 MaximumArchiveBytes) archiveChecksums[architecture] readTimeout)
                        .ConfigureAwait(false)
                output.Flush(true)
                output.Position <- 0L
                return output
            with
            | :? BackendError as error ->
                output.Dispose()
                return raise error
            | :? OperationCanceledException as error ->
                output.Dispose()
                return raise error
            | _ ->
                output.Dispose()
                return fail "cannot download the pinned Traefik release archive"
        }

    let private maximumBinaryBytes = 512L * 1024L * 1024L

    let private safeArchiveMemberName (name: string) =
        not (String.IsNullOrWhiteSpace name)
        && not (name.StartsWith("/", StringComparison.Ordinal))
        && not (name.StartsWith("\\", StringComparison.Ordinal))
        && not (name.Contains(':'))
        && not (name.Split([| '/'; '\\' |], StringSplitOptions.None)
                |> Array.exists (fun segment -> segment = "." || segment = ".."))

    /// Streams the single regular traefik member into a staging stream and returns its length/hash.
    /// Rewinds the seekable archive; does not install or execute unverified staging content.
    let extractBinary (archive: Stream) (destination: Stream) : int64 * string =
        try
            if not archive.CanRead || not archive.CanSeek then fail "pinned Traefik archive is invalid"
            if not destination.CanWrite then fail "pinned Traefik archive is invalid"
            archive.Position <- 0L
            use gzip = new GZipStream(archive, CompressionMode.Decompress, true)
            use tarReader = new TarReader(gzip, true)
            let mutable exactNameCount = 0
            let mutable selected: (int64 * string) option = None
            let mutable entry = tarReader.GetNextEntry()

            while not (isNull entry) do
                if not (safeArchiveMemberName entry.Name) then
                    fail "pinned Traefik archive has an invalid layout"

                if entry.Name = "traefik" then
                    exactNameCount <- exactNameCount + 1

                    if entry.EntryType <> TarEntryType.RegularFile
                       || entry.Length <= 0L
                       || entry.Length > maximumBinaryBytes then
                        fail "pinned Traefik archive has an invalid layout"

                    match entry.DataStream with
                    | null -> fail "pinned Traefik archive is incomplete"
                    | dataStream ->
                        use hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
                        let buffer = Array.zeroCreate<byte> 65536
                        let mutable total = 0L
                        let mutable read = dataStream.Read(buffer, 0, buffer.Length)

                        while read > 0 do
                            if int64 read > maximumBinaryBytes - total then
                                fail "pinned Traefik archive has an invalid layout"

                            destination.Write(buffer, 0, read)
                            hash.AppendData(buffer, 0, read)
                            total <- total + int64 read
                            read <- dataStream.Read(buffer, 0, buffer.Length)

                        if total <> entry.Length then
                            fail "pinned Traefik archive is incomplete"

                        let checksum =
                            hash.GetHashAndReset()
                            |> Convert.ToHexString
                            |> fun value -> value.ToLowerInvariant()
                        selected <- Some(total, checksum)

                entry <- tarReader.GetNextEntry()

            if exactNameCount <> 1 then
                fail "pinned Traefik archive has an invalid layout"

            match selected with
            | Some result -> result
            | None -> fail "pinned Traefik archive is incomplete"
        with
        | :? BackendError -> reraise()
        | _ -> fail "pinned Traefik archive is invalid"


    let private binaryVersion (environment: HostEnvironment) (binaryPath: string) : bool =
        try
            let result = run environment binaryPath [ "version" ]
            result.ExitCode = 0
            && (result.Stdout.Split('\n')
                |> Array.exists (fun line -> Regex.IsMatch(line.TrimEnd('\r'), "^Version:\\s+" + Regex.Escape(Version) + "\\s*$", RegexOptions.CultureInvariant)))
        with _ -> false

    let private binarySha256 (environment: HostEnvironment) (binaryPath: string) : string =
        if not (assertRegular environment binaryPath "Traefik binary") then fail "cannot hash installed Traefik binary"
        let descriptor = openChecked binaryPath false
        try
            let handle = new SafeFileHandle(nativeint descriptor, false)
            use stream = new FileStream(handle, FileAccess.Read)
            SHA256.HashData(stream)
            |> Convert.ToHexString
            |> fun value -> value.ToLowerInvariant()
        finally
            nativeClose descriptor |> ignore

    let private installBinary (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) (architecture: string) : bool =
        let archive =
            downloadArchive architecture CancellationToken.None
            |> fun work -> work.GetAwaiter().GetResult()

        use archive = archive
        let temporaryBinary = createTemporaryFile ()
        let mutable stagedBinaryPath: string option = None

        try
            use temporaryBinary = temporaryBinary
            let _, binaryHash = extractBinary archive temporaryBinary
            temporaryBinary.Flush(true)

            let rootUid, rootGid = hostOwner environment
            createOwnedDirectory environment paths.InstallDir ownerId 0o755 (Some rootGid) |> ignore
            let versionDir = Path.GetDirectoryName(paths.BinaryPath)
            ensureDirectory environment versionDir 0o755 (Some rootGid)
            let stagedBinary = Path.Combine(versionDir, ".traefik-install-" + Guid.NewGuid().ToString("N"))
            stagedBinaryPath <- Some stagedBinary
            temporaryBinary.Position <- 0L
            HostFiles.atomicWriteStream stagedBinary temporaryBinary (unixMode 0o700)

            if not (binaryVersion environment stagedBinary) then
                fail "installed Traefik binary version could not be verified"

            chown environment stagedBinary rootUid rootGid
            chmod environment stagedBinary 0o755
            assertRegular environment paths.BinaryPath "Traefik binary" |> ignore
            File.Move(stagedBinary, paths.BinaryPath, true)
            stagedBinaryPath <- None
            fsyncDirectory versionDir

            let marker = JsonObject()
            marker["owner"] <- JsonValue.Create(ownerDigest ownerId)
            marker["version"] <- JsonValue.Create(Version)
            marker["architecture"] <- JsonValue.Create(architecture)
            marker["archiveSha256"] <- JsonValue.Create(archiveChecksums[architecture])
            marker["binarySha256"] <- JsonValue.Create(binaryHash)
            writeAtomic environment (Path.Combine(paths.InstallDir, ".keroosha-release.json")) (Encoding.UTF8.GetBytes(jsonText marker)) 0o644 (Some rootGid)
            true
        finally
            match stagedBinaryPath with
            | Some path -> try File.Delete path with _ -> ()
            | None -> ()

    let private ensureInstalledBinary (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) : bool =
        let arch = architecture ()
        checkDirectoryOwnership environment paths.InstallDir ownerId "installation directory" |> ignore
        let _, rootGid = hostOwner environment
        if assertDirectory environment paths.InstallDir "installation directory" then
            ensureDirectory environment paths.InstallDir 0o755 (Some rootGid)
            if assertDirectory environment (Path.GetDirectoryName(paths.BinaryPath)) "binary version directory" then
                ensureDirectory environment (Path.GetDirectoryName(paths.BinaryPath)) 0o755 (Some rootGid)
            let markerPath = Path.Combine(paths.InstallDir, ".keroosha-release.json")
            let marker, binaryHash =
                try
                    use document = JsonDocument.Parse(readBytes environment markerPath)
                    let hash = binarySha256 environment paths.BinaryPath
                    Some(document.RootElement.Clone()), Some hash
                with _ -> None, None
            let matches =
                match marker, binaryHash with
                | Some release, Some hash ->
                    release.ValueKind = JsonValueKind.Object
                    && ((release.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq) = set [ "owner"; "version"; "architecture"; "archiveSha256"; "binarySha256" ])
                    && (tryProperty release "owner" |> Option.exists (fun value -> value.ValueKind = JsonValueKind.String && value.GetString() = ownerDigest ownerId))
                    && (tryProperty release "version" |> Option.exists (fun value -> value.ValueKind = JsonValueKind.String && value.GetString() = Version))
                    && (tryProperty release "architecture" |> Option.exists (fun value -> value.ValueKind = JsonValueKind.String && value.GetString() = arch))
                    && (tryProperty release "archiveSha256" |> Option.exists (fun value -> value.ValueKind = JsonValueKind.String && value.GetString() = archiveChecksums[arch]))
                    && (tryProperty release "binarySha256" |> Option.exists (fun value -> value.ValueKind = JsonValueKind.String && value.GetString() = hash))
                    && assertRegular environment paths.BinaryPath "Traefik binary"
                    && binaryVersion environment paths.BinaryPath
                | _ -> false
            if matches then
                chmod environment paths.BinaryPath 0o755
                chown environment paths.BinaryPath (fst (hostOwner environment)) rootGid
                chmod environment markerPath 0o644
                chown environment markerPath (fst (hostOwner environment)) rootGid
                false
            else installBinary environment paths ownerId arch
        else installBinary environment paths ownerId arch

    let rec private ensureEffectiveUnit (environment: HostEnvironment) (paths: RuntimePaths) =
        if unitMatches environment paths then ()
        else
            runOk environment "systemd Traefik operation failed" "systemctl" [ "daemon-reload" ] |> ignore
            if not (unitMatches environment paths) then fail "effective systemd Traefik unit is not owned"

    and private unitMatches (environment: HostEnvironment) (paths: RuntimePaths) : bool =
        match showUnit environment [ "FragmentPath"; "DropInPaths"; "ExecStart"; "MainPID"; "ActiveState"; "SubState"; "User"; "Group" ] with
        | None -> false
        | Some properties when properties.TryFind("FragmentPath") <> Some paths.UnitPath
                              || (properties.TryFind("DropInPaths") |> Option.defaultValue "").Trim() <> ""
                              || properties.TryFind("User") <> Some ServiceUser
                              || properties.TryFind("Group") <> Some ServiceGroup -> false
        | Some properties ->
            let binary = paths.BinaryPath
            let config = Path.Combine(paths.ConfigDir, "static.yml")
            let expectedExec = "path=" + binary + " ; argv[]=" + binary + " --configFile=" + config + " ;"
            let execStart = properties.TryFind("ExecStart") |> Option.defaultValue ""
            if Regex.Matches(execStart, "path=").Count <> 1 || not (execStart.Contains(expectedExec, StringComparison.Ordinal)) then false
            elif not (isActive environment) then true
            else
                try
                    let pid = properties.TryFind("MainPID") |> Option.defaultValue "0" |> Int32.Parse
                    if pid <= 0 then properties.TryFind("ActiveState") |> Option.exists (fun state -> state = "activating" || state = "deactivating")
                    else
                        let proc = HostEnvironment.path environment ("/proc/" + pid.ToString(CultureInfo.InvariantCulture))
                        let executableLink = run environment "readlink" [ Path.Combine(proc, "exe") ]
                        if executableLink.ExitCode <> 0 then false
                        else
                            let executable = executableLink.Stdout.Trim().Replace(" (deleted)", "", StringComparison.Ordinal)
                            let expectedReal = Path.GetFullPath(binary)
                            let commandLine = File.ReadAllBytes(Path.Combine(proc, "cmdline")) |> fun bytes -> Encoding.UTF8.GetString(bytes).Split('\000', StringSplitOptions.RemoveEmptyEntries)
                            let uidLine, gidLine =
                                File.ReadLines(Path.Combine(proc, "status"))
                                |> Seq.fold (fun (uid, gid) line ->
                                    if line.StartsWith("Uid:", StringComparison.Ordinal) then Some line, gid
                                    elif line.StartsWith("Gid:", StringComparison.Ordinal) then uid, Some line
                                    else uid, gid) (None, None)
                            match uidLine, gidLine with
                            | Some uidText, Some gidText ->
                                let uidValues = uidText.Split((null: char[]), StringSplitOptions.RemoveEmptyEntries)
                                let gidValues = gidText.Split((null: char[]), StringSplitOptions.RemoveEmptyEntries)
                                let processUid = Int32.Parse(uidValues[1], CultureInfo.InvariantCulture)
                                let processGid = Int32.Parse(gidValues[1], CultureInfo.InvariantCulture)
                                let serviceUser = lookupUser environment
                                let serviceGroup = lookupGroup environment
                                let pathMatches = Path.GetFullPath(executable) = expectedReal
                                let argsMatch = commandLine = [| binary; "--configFile=" + config |]
                                pathMatches && argsMatch
                                && (serviceUser |> Option.exists (fun user -> user.Uid = processUid))
                                && (serviceGroup = Some processGid)
                            | _ -> false
                with _ -> false

    and private showUnit (environment: HostEnvironment) (properties: string list) : Map<string, string> option =
        let arguments = [ "show"; ServiceName; "--no-pager" ] @ (properties |> List.map (fun property -> "--property=" + property))
        let result = run environment "systemctl" arguments
        if result.ExitCode <> 0 then None
        else
            result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            |> Seq.choose (fun line ->
                let index = line.IndexOf('=')
                if index < 0 then None else Some(line.Substring(0, index), line.Substring(index + 1).TrimEnd('\r')))
            |> Map.ofSeq
            |> Some

    and private isActive (environment: HostEnvironment) : bool =
        let result = run environment "systemctl" [ "is-active"; "--quiet"; ServiceName ]
        result.ExitCode = 0

    let private isEnabled (environment: HostEnvironment) : bool =
        let result = run environment "systemctl" [ "is-enabled"; "--quiet"; ServiceName ]
        result.ExitCode = 0

    let private jobFinished (properties: Map<string, string>) =
        match properties.TryFind("Job") with
        | Some "" | Some "0" -> true
        | _ -> false

    let private mainProcessIsStopped (properties: Map<string, string>) =
        properties.TryFind("MainPID") = Some "0"

    let private isStopped (environment: HostEnvironment) : bool =
        match showUnit environment [ "ActiveState"; "SubState"; "Job"; "MainPID" ] with
        | Some values ->
            values.TryFind("ActiveState") = Some "inactive"
            && values.TryFind("SubState") = Some "dead"
            && mainProcessIsStopped values
            && jobFinished values
        | None -> false

    let private isSettled (environment: HostEnvironment) : bool =
        match showUnit environment [ "ActiveState"; "SubState"; "Job"; "MainPID" ] with
        | Some values ->
            let inactive = values.TryFind("ActiveState") = Some "inactive" && values.TryFind("SubState") = Some "dead"
            let failed =
                values.TryFind("ActiveState") = Some "failed"
                && (values.TryFind("SubState") = Some "failed" || values.TryFind("SubState") = Some "dead")
            (inactive || failed) && mainProcessIsStopped values && jobFinished values
        | None -> false

    let private systemctl (environment: HostEnvironment) (arguments: string list) (check: bool) : bool =
        let result = run environment "systemctl" arguments
        if check && result.ExitCode <> 0 then fail "systemd Traefik operation failed"
        result.ExitCode = 0

    let private daemonReload environment = systemctl environment [ "daemon-reload" ] true |> ignore
    let private enableService environment = systemctl environment [ "enable"; ServiceName ] true |> ignore
    let private startService environment = systemctl environment [ "start"; ServiceName ] true |> ignore
    let private restartService environment = systemctl environment [ "restart"; ServiceName ] true |> ignore
    let private stopService environment = systemctl environment [ "stop"; ServiceName ] true |> ignore
    let private resetFailedService environment = systemctl environment [ "reset-failed"; ServiceName ] true |> ignore
    let private disableService environment = systemctl environment [ "disable"; ServiceName ] false |> ignore

    let private stopOwnedService (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) =
        if (safeUnitStatus environment paths.UnitPath ownerId).IsNone then
            fail "owned Traefik service has no owned unit"
        ensureEffectiveUnit environment paths
        stopService environment
        let deadline = Stopwatch.GetTimestamp() + int64 (ServiceStopTimeoutSeconds * float Stopwatch.Frequency)
        let mutable stopped = false
        while not stopped && Stopwatch.GetTimestamp() < deadline do
            stopped <- isSettled environment
            if not stopped then Thread.Sleep(100)
        if not stopped then fail "owned Traefik service did not stop"
        // Failed units retain restart counters; inactive units may already be garbage-collected.
        match showUnit environment [ "ActiveState" ] |> Option.bind (fun values -> values.TryFind("ActiveState")) with
        | Some "failed" -> resetFailedService environment
        | _ -> ()
        if not (isStopped environment) then fail "owned Traefik service did not stop"

    let private validateActualOwner (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) =
        let configStatus, stateStatus, installStatus, unitData = checkLayoutCollisions environment paths ownerId
        if unitData.IsSome && configStatus <> "owned" then fail "Traefik service unit has no matching owned configuration"
        configStatus, stateStatus, installStatus, unitData

    let private ensureGroupedAtomicWrite environment path data mode groupId = writeAtomic environment path data mode (Some groupId)

    let private certificateIdentity (certificate: Certificate) =
        try
            use cert = X509Certificate2.CreateFromPem(certificate.CertificatePem.AsSpan(), certificate.PrivateKeyPem.AsSpan())
            let der = cert.Export(X509ContentType.Cert)
            let fingerprint = sha256Bytes der
            if fingerprint <> certificate.Fingerprint then fail "certificate identity or fingerprint does not match"
            fingerprint
        with
        | :? BackendError -> reraise()
        | _ -> fail "certificate or private key cannot be validated"

    let private validateCertificateMaterial (request: Request) : unit =
        request.Certificates |> Map.iter (fun _ certificate -> certificateIdentity certificate |> ignore)

    let private writeCertificateFiles (environment: HostEnvironment) (paths: RuntimePaths) (request: Request) (groupId: int) : unit =
        for KeyValue(_, certificate) in request.Certificates do
            let digest = materialDigest certificate
            let certificatePem: string = certificate.CertificatePem
            let privateKeyPem: string = certificate.PrivateKeyPem
            let values: (string * byte[] * string) list = [
                Path.Combine(paths.CertificateDir, digest + ".crt"), Encoding.UTF8.GetBytes(certificatePem), "certificate"
                Path.Combine(paths.CertificateDir, digest + ".key"), Encoding.UTF8.GetBytes(privateKeyPem), "key"
            ]
            for path, contents, description in values do
                if assertRegular environment path "versioned certificate material" then
                    if readBytes environment path <> contents then fail ("versioned " + description + " path collides with different material")
                    chmod environment path 0o640
                    chown environment path (fst (hostOwner environment)) groupId
                else ensureGroupedAtomicWrite environment path contents 0o640 groupId

    let private readApiEndpoint (adminPort: int) (resource: string) : Task<JsonElement option> =
        task {
            try
                use client = new HttpClient()
                use request = new HttpRequestMessage(HttpMethod.Get, "http://127.0.0.1:" + adminPort.ToString(CultureInfo.InvariantCulture) + "/api/http/" + resource)
                request.Headers.Accept.ParseAdd("application/json")
                use cancellation = new CancellationTokenSource(ConnectTimeoutMilliseconds)
                use! response = client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token).ConfigureAwait(false)
                if response.StatusCode <> HttpStatusCode.OK then return None
                elif response.Content.Headers.ContentLength.HasValue
                     && response.Content.Headers.ContentLength.Value > int64 ApiMaximumBytes then return None
                else
                    use! stream = response.Content.ReadAsStreamAsync(cancellation.Token).ConfigureAwait(false)
                    use output = new MemoryStream()
                    let buffer = Array.zeroCreate<byte> 16384
                    let mutable count = 0
                    let mutable finished = false
                    while not finished && count <= ApiMaximumBytes do
                        let! read = stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellation.Token).ConfigureAwait(false)
                        if read = 0 then finished <- true
                        else
                            output.Write(buffer, 0, read)
                            count <- count + read
                    if count > ApiMaximumBytes then return None
                    else
                        use document = JsonDocument.Parse(output.ToArray())
                        if document.RootElement.ValueKind = JsonValueKind.Array then return Some(document.RootElement.Clone()) else return None
            with _ -> return None
        }

    let private readApi (adminPort: int) : Task<ApiConfiguration option> =
        task {
            let! routers = readApiEndpoint adminPort "routers"
            let! services = readApiEndpoint adminPort "services"
            let! middlewares = readApiEndpoint adminPort "middlewares"
            match routers, services, middlewares with
            | Some routerValues, Some serviceValues, Some middlewareValues ->
                return Some { Routers = routerValues; Services = serviceValues; Middlewares = middlewareValues }
            | _ -> return None
        }

    let private tryString (element: JsonElement) (name: string) : string =
        match tryProperty element name with
        | Some value when value.ValueKind = JsonValueKind.String -> value.GetString()
        | _ -> null

    let private jsonArrayStrings (element: JsonElement) : string[] option =
        if element.ValueKind <> JsonValueKind.Array then None
        else
            let values = element.EnumerateArray() |> Seq.map (fun value -> if value.ValueKind = JsonValueKind.String then value.GetString() else null) |> Seq.toArray
            if values |> Array.exists isNull then None else Some values

    let private jsonArrayUrls (element: JsonElement) : string[] option =
        if element.ValueKind <> JsonValueKind.Array then None
        else
            let values = element.EnumerateArray() |> Seq.map (fun value -> tryString value "url") |> Seq.toArray
            if values |> Array.exists isNull then None else Some values

    let private providerIsFile (item: JsonElement) : bool =
        match tryProperty item "provider" with
        | None -> true
        | Some value -> value.ValueKind = JsonValueKind.String && value.GetString() = "file"

    let private withoutProviderSuffix (provider: string) (name: string) =
        let suffix = "@" + provider
        if name.EndsWith(suffix, StringComparison.Ordinal) then name.Substring(0, name.Length - suffix.Length)
        elif name.Contains("@", StringComparison.Ordinal) then null
        else name

    let apiMatchesDynamic (apiConfiguration: ApiConfiguration option) (dynamicData: byte[] option) : bool =
        match apiConfiguration, dynamicData with
        | None, _ | _, None -> false
        | Some api, Some bytes ->
            try
                use document = JsonDocument.Parse(bytes)
                let http = document.RootElement.GetProperty("http")
                let expectedRouters = http.GetProperty("routers")
                let expectedServiceEntries =
                    match tryProperty http "services" with
                    | None -> Some [||]
                    | Some value when value.ValueKind = JsonValueKind.Object -> Some(value.EnumerateObject() |> Seq.toArray)
                    | _ -> None
                let expectedMiddlewareEntries =
                    match tryProperty http "middlewares" with
                    | None -> Some [||]
                    | Some value when value.ValueKind = JsonValueKind.Object -> Some(value.EnumerateObject() |> Seq.toArray)
                    | _ -> None
                let actualRouters =
                    api.Routers.EnumerateArray()
                    |> Seq.choose (fun item ->
                        let name = tryString item "name"
                        if String.IsNullOrEmpty(name) then None else Some(name, item))
                    |> Map.ofSeq
                let fileRouterNames =
                    actualRouters
                    |> Seq.map (fun (KeyValue(name, _)) -> name)
                    |> Seq.filter (fun name -> name.EndsWith("@file", StringComparison.Ordinal))
                    |> Set.ofSeq
                let expectedRouterNames = expectedRouters.EnumerateObject() |> Seq.map (fun item -> item.Name + "@file") |> Set.ofSeq
                let routersMatch =
                    fileRouterNames = expectedRouterNames
                    && (expectedRouters.EnumerateObject()
                        |> Seq.forall (fun property ->
                            match actualRouters.TryFind(property.Name + "@file") with
                            | None -> false
                            | Some actual ->
                                let expected = property.Value
                                let expectedEntryPoints = expected.GetProperty("entryPoints") |> jsonArrayStrings
                                let actualEntryPoints = tryProperty actual "entryPoints" |> Option.bind jsonArrayStrings
                                let expectedTls = tryProperty expected "tls"
                                let actualTls = tryProperty actual "tls"
                                let tlsMatches =
                                    match expectedTls, actualTls with
                                    | None, None -> true
                                    | None, Some value when value.ValueKind = JsonValueKind.Null -> true
                                    | None, Some value when value.ValueKind = JsonValueKind.Object -> Seq.isEmpty (value.EnumerateObject())
                                    | None, Some _ -> false
                                    | Some _, None -> false
                                    | Some _, Some found when found.ValueKind <> JsonValueKind.Object -> false
                                    | Some wanted, Some found ->
                                        let optionsMatches =
                                            match tryProperty found "options" with
                                            | None -> true
                                            | Some options -> options.ValueKind = JsonValueKind.String && options.GetString() = "default"
                                        let wantedResolver = tryString wanted "certResolver"
                                        let foundResolver = tryString found "certResolver"
                                        optionsMatches
                                        && (if not (String.IsNullOrEmpty(wantedResolver)) then wantedResolver = foundResolver else String.IsNullOrEmpty(foundResolver))
                                let expectedService = tryString expected "service"
                                let actualService = tryString actual "service"
                                let serviceMatches =
                                    if expectedService.EndsWith("@internal", StringComparison.Ordinal) then
                                        actualService = expectedService
                                        || actualService = expectedService.Substring(0, expectedService.Length - "@internal".Length)
                                    else actualService = expectedService
                                let expectedMiddlewareNames =
                                    match tryProperty expected "middlewares" with
                                    | None -> Some [||]
                                    | Some value when value.ValueKind = JsonValueKind.Null -> Some [||]
                                    | Some value -> jsonArrayStrings value
                                let actualMiddlewareNames =
                                    match tryProperty actual "middlewares" with
                                    | None -> Some [||]
                                    | Some value when value.ValueKind = JsonValueKind.Null -> Some [||]
                                    | Some value -> jsonArrayStrings value
                                let routeMiddlewaresMatch =
                                    match expectedMiddlewareNames, actualMiddlewareNames with
                                    | Some wanted, Some found when wanted.Length = found.Length ->
                                        Array.forall2 (fun expectedName actualName ->
                                            actualName = expectedName
                                            || actualName = expectedName + "@file") wanted found
                                    | _ -> false
                                tryString actual "rule" = tryString expected "rule"
                                && actualEntryPoints = expectedEntryPoints
                                && serviceMatches
                                && tryString actual "status" = "enabled"
                                && providerIsFile actual
                                && routeMiddlewaresMatch
                                && tlsMatches))

                let actualServices =
                    api.Services.EnumerateArray()
                    |> Seq.choose (fun item ->
                        let name = tryString item "name"
                        if String.IsNullOrEmpty(name) then None else Some(name, item))
                    |> Map.ofSeq
                let fileServiceNames =
                    actualServices
                    |> Seq.map (fun (KeyValue(name, _)) -> name)
                    |> Seq.filter (fun name -> name.EndsWith("@file", StringComparison.Ordinal))
                    |> Set.ofSeq
                let servicesMatch =
                    match expectedServiceEntries with
                    | None -> false
                    | Some entries ->
                        let expectedServiceNames = entries |> Array.map (fun item -> item.Name + "@file") |> Set.ofArray
                        fileServiceNames = expectedServiceNames
                        && (entries |> Array.forall (fun property ->
                            match actualServices.TryFind(property.Name + "@file") with
                            | None -> false
                            | Some actual ->
                                let loadBalancer = tryProperty actual "loadBalancer"
                                let servers = loadBalancer |> Option.bind (fun value -> tryProperty value "servers")
                                let actualUrls = servers |> Option.bind jsonArrayUrls
                                let expectedUrls = property.Value.GetProperty("loadBalancer").GetProperty("servers") |> jsonArrayUrls
                                let serviceType = tryString actual "type"
                                let passHostHeader =
                                    match loadBalancer |> Option.bind (fun value -> tryProperty value "passHostHeader") with
                                    | None -> true
                                    | Some value -> value.ValueKind = JsonValueKind.True
                                tryString actual "status" = "enabled"
                                && not (String.IsNullOrEmpty(serviceType))
                                && serviceType.Equals("loadbalancer", StringComparison.OrdinalIgnoreCase)
                                && providerIsFile actual
                                && passHostHeader
                                && actualUrls = expectedUrls))

                let actualMiddlewareEntries =
                    api.Middlewares.EnumerateArray()
                    |> Seq.choose (fun item ->
                        let name = tryString item "name"
                        if String.IsNullOrEmpty(name) || not (providerIsFile item) then None
                        else
                            let unqualifiedName = withoutProviderSuffix "file" name
                            if String.IsNullOrEmpty(unqualifiedName) then None
                            else Some(unqualifiedName, item))
                    |> Seq.toArray
                let actualMiddlewares = actualMiddlewareEntries |> Map.ofArray
                let actualFileMiddlewareNames = actualMiddlewareEntries |> Seq.map fst |> Set.ofSeq
                let expectedMiddlewareNames =
                    expectedMiddlewareEntries
                    |> Option.map (Array.map (fun property -> property.Name) >> Set.ofArray)
                    |> Option.defaultValue Set.empty
                let middlewaresMatch =
                    match expectedMiddlewareEntries with
                    | None -> false
                    | Some entries ->
                        actualFileMiddlewareNames = expectedMiddlewareNames
                        && (entries
                            |> Array.forall (fun property ->
                                match actualMiddlewares.TryFind(property.Name) with
                                | None -> false
                                | Some actual ->
                                    let expectedConfig = property.Value.GetProperty("redirectRegex")
                                    let actualConfig = tryProperty actual "redirectRegex"
                                    let redirectConfigMatches =
                                        match actualConfig with
                                        | Some found when found.ValueKind = JsonValueKind.Object ->
                                            tryString found "regex" = tryString expectedConfig "regex"
                                            && tryString found "replacement" = tryString expectedConfig "replacement"
                                            && (match tryProperty found "permanent" with
                                                | Some value -> value.ValueKind = JsonValueKind.True
                                                | None -> false)
                                        | _ -> false
                                    let expectedUsers =
                                        expectedRouters.EnumerateObject()
                                        |> Seq.choose (fun router ->
                                            match tryProperty router.Value "middlewares" |> Option.bind jsonArrayStrings with
                                            | Some names when names |> Array.contains property.Name -> Some(router.Name)
                                            | _ -> None)
                                        |> Set.ofSeq
                                    let actualUsers =
                                        tryProperty actual "usedBy"
                                        |> Option.bind jsonArrayStrings
                                        |> Option.map (Array.map (withoutProviderSuffix "file"))
                                        |> Option.filter (fun names -> names |> Array.forall (String.IsNullOrEmpty >> not))
                                        |> Option.map Set.ofArray
                                    tryString actual "status" = "enabled"
                                    && String.Equals(tryString actual "type", "RedirectRegex", StringComparison.OrdinalIgnoreCase)
                                    && providerIsFile actual
                                    && redirectConfigMatches
                                    && actualUsers = Some expectedUsers))
                routersMatch && servicesMatch && middlewaresMatch
            with _ -> false

    let private certificateFingerprint (pem: byte[]) : string option =
        try
            let text = UTF8Encoding(false, true).GetString(pem)
            use certificate = X509Certificate2.CreateFromPem(text.AsSpan())
            Some(sha256Bytes (certificate.Export(X509ContentType.Cert)))
        with _ -> None

    let private certificateIsCurrentAt (now: DateTimeOffset) (pem: byte[]) : bool =
        try
            let text = UTF8Encoding(false, true).GetString(pem)
            use certificate = X509Certificate2.CreateFromPem(text.AsSpan())
            now.UtcDateTime >= certificate.NotBefore.ToUniversalTime() && now.UtcDateTime < certificate.NotAfter.ToUniversalTime()
        with _ -> false

    let private dnsPatternCoversHost (host: string) (candidate: string) : bool =
        if String.IsNullOrEmpty(candidate) then false
        elif candidate.StartsWith("*.", StringComparison.Ordinal) then
            try
                let suffix = validateDnsName (candidate.Substring(2))
                let mutable ip = Unchecked.defaultof<IPAddress>
                not (IPAddress.TryParse(host, &ip))
                && host.EndsWith("." + suffix, StringComparison.Ordinal)
                && (host |> Seq.filter ((=) '.') |> Seq.length) = (suffix |> Seq.filter ((=) '.') |> Seq.length) + 1
            with _ -> false
        else
            try validateDnsName candidate = host with _ -> false

    let private certificateCoversHost (pem: byte[]) (host: string) : bool =
        try
            let text = UTF8Encoding(false, true).GetString(pem)
            use certificate = X509Certificate2.CreateFromPem(text.AsSpan())
            let mutable ipAddress = Unchecked.defaultof<IPAddress>
            let isIp = IPAddress.TryParse(host, &ipAddress)
            let mutable dnsNames = ResizeArray<string>()
            let mutable ipNames = ResizeArray<byte[]>()
            let san = certificate.Extensions |> Seq.cast<X509Extension> |> Seq.tryFind (fun extension -> extension.Oid.Value = "2.5.29.17")
            match san with
            | Some extension ->
                let reader = AsnReader(extension.RawData, AsnEncodingRules.DER)
                let sequence = reader.ReadSequence()
                let dnsTag = Nullable<Asn1Tag>(Asn1Tag(TagClass.ContextSpecific, 2))
                let ipTag = Nullable<Asn1Tag>(Asn1Tag(TagClass.ContextSpecific, 7))
                while sequence.HasData do
                    let tag = sequence.PeekTag()
                    if tag.TagClass = TagClass.ContextSpecific && tag.TagValue = 2 then
                        dnsNames.Add(sequence.ReadCharacterString(UniversalTagNumber.IA5String, dnsTag))
                    elif tag.TagClass = TagClass.ContextSpecific && tag.TagValue = 7 then
                        ipNames.Add(sequence.ReadOctetString(ipTag))
                    else sequence.ReadEncodedValue() |> ignore
                reader.ThrowIfNotEmpty()
            | None -> ()
            if isIp then
                ipNames |> Seq.exists (fun bytes -> bytes.AsSpan().SequenceEqual(ipAddress.GetAddressBytes().AsSpan()))
            elif dnsNames.Count > 0 then
                dnsNames |> Seq.exists (dnsPatternCoversHost host)
            else
                let commonName = certificate.GetNameInfo(X509NameType.DnsName, false)
                dnsPatternCoversHost host commonName
        with _ -> false

    let private sniFingerprint (host: string) (port: int) : Task<string option> =
        task {
            try
                use client = new TcpClient()
                use cancellation = new CancellationTokenSource(ConnectTimeoutMilliseconds)
                do! client.ConnectAsync(IPAddress.Loopback, port, cancellation.Token).ConfigureAwait(false)
                use stream = new SslStream(client.GetStream(), false, RemoteCertificateValidationCallback(fun _ _ _ _ -> true))
                let options = SslClientAuthenticationOptions(TargetHost = host)
                do! stream.AuthenticateAsClientAsync(options, cancellation.Token).ConfigureAwait(false)
                match stream.RemoteCertificate with
                | null -> return None
                | remote -> return Some(sha256Bytes(remote.GetRawCertData()))
            with _ -> return None
        }

    let acmeCertificateFingerprint (environment: HostEnvironment) (paths: RuntimePaths) (resolverName: string) (host: string) : string option =
        let storagePath = Path.Combine(paths.StateDir, "acme-" + sha256Text resolverName + ".json")
        try
            use document = JsonDocument.Parse(readBytes environment storagePath)
            let root = document.RootElement
            let resolverStorage = tryProperty root resolverName
            let certificates = resolverStorage |> Option.bind (fun item -> tryProperty item "Certificates")
            match certificates with
            | Some values when values.ValueKind = JsonValueKind.Array ->
                values.EnumerateArray()
                |> Seq.tryPick (fun entry ->
                    match tryProperty entry "domain" with
                    | Some domain when domain.ValueKind = JsonValueKind.Object ->
                        let candidates = ResizeArray<string>()
                        match tryProperty domain "main" with
                        | Some main when main.ValueKind = JsonValueKind.String -> candidates.Add(main.GetString())
                        | _ -> ()
                        match tryProperty domain "sans" with
                        | Some sans when sans.ValueKind = JsonValueKind.Array ->
                            for item in sans.EnumerateArray() do
                                if item.ValueKind = JsonValueKind.String then candidates.Add(item.GetString())
                        | _ -> ()
                        if not (candidates |> Seq.exists (dnsPatternCoversHost host)) then None
                        else
                            match tryProperty entry "certificate" with
                            | Some encoded when encoded.ValueKind = JsonValueKind.String && not (String.IsNullOrEmpty(encoded.GetString())) ->
                                let raw = encoded.GetString()
                                let pem =
                                    if raw.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal) then Encoding.ASCII.GetBytes(raw)
                                    else
                                        try Convert.FromBase64String(raw)
                                        with _ -> Array.empty<byte>
                                if pem.Length = 0 || not (certificateIsCurrentAt (environment.UtcNow()) pem) || not (certificateCoversHost pem host) then None
                                else certificateFingerprint pem
                            | _ -> None
                    | _ -> None)
            | _ -> None
        with _ -> None

    let private serviceMaterialOwner (environment: HostEnvironment) : int * int =
        let uid, hostGid = hostOwner environment
        let gid = lookupGroup environment |> Option.defaultValue hostGid
        uid, gid

    let private serviceAccountOwner (environment: HostEnvironment) : int * int =
        match lookupUser environment, lookupGroup environment with
        | Some user, Some groupId -> user.Uid, groupId
        | _ -> parseIdCommand environment "-u", parseIdCommand environment "-g"

    let readProtectedMaterial (_environment: HostEnvironment) (path: string) (expectedUid: int) (expectedGid: int) : byte[] =
        let descriptor = openChecked path false
        try
            let metadata = statDescriptor descriptor
            if metadata.Mode <> 0o640 || metadata.Uid <> expectedUid || metadata.Gid <> expectedGid then
                fail "Traefik certificate material permissions drifted"
            try readDescriptor descriptor
            with _ -> fail "cannot read protected Traefik certificate material"
        finally nativeClose(descriptor) |> ignore

    let private certificateObservations (environment: HostEnvironment) (paths: RuntimePaths) (request: Request) : JsonObject * bool =
        let observed = JsonObject()
        let mutable certificatesMatch = true
        let hostsForCertificate = Dictionary<string, ResizeArray<string * int>>(StringComparer.Ordinal)
        let acmeRoutes = ResizeArray<string * int * string>()
        for KeyValue(_, router) in request.Routers do
            let port = request.EntryPoints[router.EntryPoint]
            match router.Tls.Kind with
            | "provided" ->
                if not (hostsForCertificate.ContainsKey(router.Tls.Name)) then hostsForCertificate[router.Tls.Name] <- ResizeArray()
                hostsForCertificate[router.Tls.Name].Add((router.Host, port))
            | "acme" -> acmeRoutes.Add((router.Host, port, router.Tls.Name))
            | _ -> ()
        let expectedUid, expectedGid = serviceMaterialOwner environment
        for KeyValue(name, certificate) in request.Certificates do
            let digest = materialDigest certificate
            let certPath = Path.Combine(paths.CertificateDir, digest + ".crt")
            let keyPath = Path.Combine(paths.CertificateDir, digest + ".key")
            let certificatePem, materialMatches =
                try
                    let certBytes = readProtectedMaterial environment certPath expectedUid expectedGid
                    let keyBytes = readProtectedMaterial environment keyPath expectedUid expectedGid
                    certBytes, certBytes = Encoding.UTF8.GetBytes(certificate.CertificatePem) && keyBytes = Encoding.UTF8.GetBytes(certificate.PrivateKeyPem)
                with _ -> Array.empty<byte>, false
            let fingerprint = if certificatePem.Length = 0 then None else certificateFingerprint certificatePem
            match fingerprint with
            | Some value -> observed[name] <- JsonValue.Create(value)
            | None -> ()
            if not materialMatches || fingerprint <> Some certificate.Fingerprint || not (certificateIsCurrentAt (environment.UtcNow()) certificatePem) then certificatesMatch <- false
            match hostsForCertificate.TryGetValue(name) with
            | true, routes ->
                for host, port in routes do
                    if not (certificateCoversHost certificatePem host) then certificatesMatch <- false
                    let sni = sniFingerprint host port |> fun operation -> operation.GetAwaiter().GetResult()
                    if sni <> Some certificate.Fingerprint then certificatesMatch <- false
                    else observed[name] <- JsonValue.Create(certificate.Fingerprint)
            | _ -> ()
        for host, port, resolverName in acmeRoutes do
            let storedFingerprint = acmeCertificateFingerprint environment paths resolverName host
            let sni = sniFingerprint host port |> fun operation -> operation.GetAwaiter().GetResult()
            if storedFingerprint.IsNone || sni.IsNone || sni <> storedFingerprint then certificatesMatch <- false
        observed, certificatesMatch

    let private actualConfigHash (environment: HostEnvironment) (paths: RuntimePaths) : string =
        use digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
        let add (path: string) (relative: string) =
            try
                let data = readBytes environment path
                let relativeBytes = Encoding.UTF8.GetBytes(relative)
                let length4 = Array.zeroCreate<byte> 4
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(length4.AsSpan(), uint32 relativeBytes.Length)
                digest.AppendData(ReadOnlySpan<byte>(length4))
                digest.AppendData(ReadOnlySpan<byte>(relativeBytes))
                let length8 = Array.zeroCreate<byte> 8
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(length8.AsSpan(), uint64 data.Length)
                digest.AppendData(ReadOnlySpan<byte>(length8))
                digest.AppendData(ReadOnlySpan<byte>(data))
            with _ -> ()
        add (Path.Combine(paths.ConfigDir, "static.yml")) "static.yml"
        add (Path.Combine(paths.DynamicDir, "current.yml")) "dynamic/current.yml"
        let certificateFiles =
            try entries paths.CertificateDir |> Array.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            with _ -> Array.empty
        for filename in certificateFiles do
            if certificateFilenamePattern.IsMatch(filename) then add (Path.Combine(paths.CertificateDir, filename)) ("dynamic/certificates/" + filename)
        digest.GetHashAndReset() |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let rec observeRuntime (environment: HostEnvironment) (requestElement: JsonElement) (listenHost: string) (ignorePending: bool) : JsonObject =
        let request = validateRequest requestElement
        let paths = pathsFor environment
        let mutable ownerMatches = false
        let mutable staticMatches = false
        let mutable dynamicMatches = false
        try
            let ownerStatus, stateStatus, installStatus, _ = checkLayoutCollisions environment paths request.OwnerId
            let dynamicStatus = markerStatus environment paths.DynamicDir request.OwnerId
            let certificateStatus = markerStatus environment paths.CertificateDir request.OwnerId
            let unitData = safeUnitStatus environment paths.UnitPath request.OwnerId
            let arch = architecture ()
            let binaryHash = binarySha256 environment paths.BinaryPath
            use markerDocument = JsonDocument.Parse(readBytes environment (Path.Combine(paths.InstallDir, ".keroosha-release.json")))
            let marker = markerDocument.RootElement
            let releaseMatches =
                marker.ValueKind = JsonValueKind.Object
                && objectNames marker = set [ "owner"; "version"; "architecture"; "archiveSha256"; "binarySha256" ]
                && tryString marker "owner" = ownerDigest request.OwnerId
                && tryString marker "version" = Version
                && tryString marker "architecture" = arch
                && tryString marker "archiveSha256" = archiveChecksums[arch]
                && tryString marker "binarySha256" = binaryHash
            ownerMatches <-
                ownerStatus = "owned" && stateStatus = "owned" && installStatus = "owned"
                && dynamicStatus = "owned" && certificateStatus = "owned"
                && unitData = Some(Encoding.UTF8.GetBytes(unitText paths request.OwnerId))
                && releaseMatches && binaryVersion environment paths.BinaryPath
                && filesystemMetadataMatches environment paths
            staticMatches <- readBytes environment (Path.Combine(paths.ConfigDir, "static.yml")) = Encoding.UTF8.GetBytes(renderStaticConfig requestElement paths listenHost)
            dynamicMatches <- readBytes environment (Path.Combine(paths.DynamicDir, "current.yml")) = Encoding.UTF8.GetBytes(renderDynamicConfig requestElement paths)
        with _ ->
            ownerMatches <- false
            staticMatches <- false
            dynamicMatches <- false
        let active, enabled, effectiveUnit =
            try
                isActive environment, isEnabled environment, unitMatches environment paths
            with _ -> false, false, false
        let api = if active && ownerMatches then readApi request.AdminPort |> fun operation -> operation.GetAwaiter().GetResult() else None
        let dynamicBytes =
            try Some(readBytes environment (Path.Combine(paths.DynamicDir, "current.yml")))
            with _ -> None
        let apiMatches = apiMatchesDynamic api dynamicBytes
        let fingerprints, certificatesMatch = certificateObservations environment paths request
        let pending = tryStat environment paths.RollbackPath |> Option.isSome
        let inSync = ownerMatches && staticMatches && dynamicMatches && active && enabled && effectiveUnit && apiMatches && certificatesMatch && (ignorePending || not pending)
        let result = JsonObject()
        result["inSync"] <- JsonValue.Create(inSync)
        result["actualConfigHash"] <- JsonValue.Create(actualConfigHash environment paths)
        result["certificateFingerprints"] <- fingerprints
        result

    and private filesystemMetadataMatches (environment: HostEnvironment) (paths: RuntimePaths) : bool =
        let rootUid, rootGid = hostOwner environment
        let serviceUid, serviceGid = serviceAccountOwner environment
        let directories = [
            paths.ConfigDir, 0o750, rootUid, serviceGid
            paths.DynamicDir, 0o750, rootUid, serviceGid
            paths.CertificateDir, 0o750, rootUid, serviceGid
            paths.StateDir, 0o700, serviceUid, serviceGid
            paths.InstallDir, 0o755, rootUid, rootGid
            Path.GetDirectoryName(paths.BinaryPath), 0o755, rootUid, rootGid
        ]
        let files = [
            Path.Combine(paths.ConfigDir, "static.yml"), 0o640, rootUid, serviceGid
            Path.Combine(paths.DynamicDir, "current.yml"), 0o640, rootUid, serviceGid
            paths.UnitPath, 0o644, rootUid, rootGid
            paths.BinaryPath, 0o755, rootUid, rootGid
            Path.Combine(paths.InstallDir, ".keroosha-release.json"), 0o644, rootUid, rootGid
        ]
        if directories |> List.exists (fun (path, mode, uid, gid) -> not (metadataMatches environment path "directory" mode uid gid)) then false
        elif files |> List.exists (fun (path, mode, uid, gid) -> not (metadataMatches environment path "file" mode uid gid)) then false
        else
            try
                entries paths.StateDir
                |> Array.forall (fun filename ->
                    filename = ".keroosha-owner"
                    || not (acmeFilenamePattern.IsMatch(filename))
                    || metadataMatches environment (Path.Combine(paths.StateDir, filename)) "file" 0o600 serviceUid serviceGid)
            with _ -> false

    let private waitForActivation (environment: HostEnvironment) (requestElement: JsonElement) (paths: RuntimePaths) (timeoutSeconds: float) : JsonObject =
        let deadline = Stopwatch.GetTimestamp() + int64 (timeoutSeconds * float Stopwatch.Frequency)
        let mutable latest = JsonObject()
        latest["inSync"] <- JsonValue.Create(false)
        latest["actualConfigHash"] <- JsonValue.Create(actualConfigHash environment paths)
        latest["certificateFingerprints"] <- JsonObject()
        let mutable complete = false
        while not complete do
            latest <- observeRuntime environment requestElement "" true
            if latest["inSync"].GetValue<bool>() then complete <- true
            elif Stopwatch.GetTimestamp() >= deadline then complete <- true
            else Thread.Sleep(ActivationPollMilliseconds)
        latest

    let private readOptional (environment: HostEnvironment) (path: string) : byte[] option =
        if assertRegular environment path "Traefik owned file" then Some(readBytes environment path) else None

    let private restoreFile (environment: HostEnvironment) (path: string) (contents: byte[] option) (mode: int) (groupId: int option) : unit =
        match contents with
        | None ->
            try
                File.Delete(path)
                fsyncDirectory (Path.GetDirectoryName(path))
            with _ -> fail "cannot roll back Traefik configuration"
        | Some bytes -> writeAtomic environment path bytes mode groupId

    let private encodeSnapshot (contents: byte[] option) =
        match contents with None -> null | Some bytes -> JsonValue.Create(Convert.ToBase64String(bytes)) :> JsonNode

    let private savePendingTransaction
        (environment: HostEnvironment)
        (paths: RuntimePaths)
        (ownerId: string)
        (staticData: byte[] option)
        (dynamicData: byte[] option)
        (unitData: byte[] option)
        (releaseMarker: byte[] option)
        (binaryPresent: bool)
        (binarySha256: string option)
        (wasActive: bool)
        (wasEnabled: bool)
        (certificateFiles: string list)
        (groupId: int)
        =
        let journal = JsonObject()
        journal["version"] <- JsonValue.Create(1)
        journal["owner"] <- JsonValue.Create(ownerDigest ownerId)
        journal["static"] <- encodeSnapshot staticData
        journal["dynamic"] <- encodeSnapshot dynamicData
        journal["unit"] <- encodeSnapshot unitData
        journal["releaseMarker"] <- encodeSnapshot releaseMarker
        journal["binaryPresent"] <- JsonValue.Create(binaryPresent)
        match binarySha256 with None -> journal["binarySha256"] <- null | Some value -> journal["binarySha256"] <- JsonValue.Create(value)
        journal["wasActive"] <- JsonValue.Create(wasActive)
        journal["wasEnabled"] <- JsonValue.Create(wasEnabled)
        let files = JsonArray()
        for filename in certificateFiles |> List.sortWith (fun (left: string) (right: string) -> StringComparer.Ordinal.Compare(left, right)) do files.Add(JsonValue.Create(filename))
        journal["certificateFiles"] <- files
        writeAtomic environment paths.RollbackPath (Encoding.UTF8.GetBytes(jsonText journal)) 0o640 (Some groupId)

    let private jsonInt (element: JsonElement) : int option =
        let mutable value = 0
        if element.ValueKind = JsonValueKind.Number && element.TryGetInt32(&value) then Some value else None

    let private jsonBool (element: JsonElement) : bool option =
        if element.ValueKind = JsonValueKind.True then Some true
        elif element.ValueKind = JsonValueKind.False then Some false
        else None

    let private decodeSnapshot (element: JsonElement) : byte[] option =
        if element.ValueKind = JsonValueKind.Null then None
        elif element.ValueKind <> JsonValueKind.String then fail "Traefik rollback journal is invalid"
        else
            try
                let value = element.GetString()
                let bytes = Convert.FromBase64String(value)
                if Convert.ToBase64String(bytes) <> value then fail "Traefik rollback journal is invalid"
                Some bytes
            with _ -> fail "Traefik rollback journal is invalid"

    let private loadPendingTransaction (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) : PendingTransaction option =
        if not (assertRegular environment paths.RollbackPath "activation rollback journal") then None
        else
            try
                use document = JsonDocument.Parse(readBytes environment paths.RollbackPath)
                let journal = document.RootElement
                let expected = set [ "version"; "owner"; "static"; "dynamic"; "unit"; "releaseMarker"; "binaryPresent"; "binarySha256"; "wasActive"; "wasEnabled"; "certificateFiles" ]
                if journal.ValueKind <> JsonValueKind.Object || objectNames journal <> expected then fail "Traefik rollback journal is invalid"
                let get (name: string) = journal.GetProperty(name)
                let version = jsonInt (get "version")
                let owner = tryString journal "owner"
                let binaryPresent = jsonBool (get "binaryPresent")
                let wasActive = jsonBool (get "wasActive")
                let wasEnabled = jsonBool (get "wasEnabled")
                let binarySha = if (get "binarySha256").ValueKind = JsonValueKind.Null then None else Some(stringValue "Traefik rollback journal is invalid" (get "binarySha256"))
                let names = get "certificateFiles"
                if version <> Some 1 || owner <> ownerDigest ownerId || binaryPresent.IsNone || wasActive.IsNone || wasEnabled.IsNone || names.ValueKind <> JsonValueKind.Array then
                    fail "Traefik rollback journal is invalid"
                match binarySha with Some value when not (fingerprintPattern.IsMatch(value)) -> fail "Traefik rollback journal is invalid" | _ -> ()
                let certificateFiles =
                    names.EnumerateArray()
                    |> Seq.map (fun value ->
                        let filename = stringValue "Traefik rollback journal is invalid" value
                        if filename <> ".keroosha-owner" && not (certificateFilenamePattern.IsMatch(filename)) then fail "Traefik rollback journal is invalid"
                        filename)
                    |> Seq.toList
                if certificateFiles.Length <> (certificateFiles |> Set.ofList |> Set.count) then fail "Traefik rollback journal is invalid"
                if binaryPresent = Some true && binarySha.IsNone then fail "Traefik rollback journal is invalid"
                Some {
                    Static = decodeSnapshot (get "static")
                    Dynamic = decodeSnapshot (get "dynamic")
                    Unit = decodeSnapshot (get "unit")
                    ReleaseMarker = decodeSnapshot (get "releaseMarker")
                    BinaryPresent = binaryPresent.Value
                    BinarySha256 = binarySha
                    WasActive = wasActive.Value
                    WasEnabled = wasEnabled.Value
                    CertificateFiles = certificateFiles
                }
            with
            | :? BackendError -> fail "Traefik rollback journal is invalid"
            | _ -> fail "Traefik rollback journal is invalid"

    let private removePendingTransaction (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) : unit =
        match loadPendingTransaction environment paths ownerId with
        | None -> ()
        | Some _ ->
            try
                File.Delete(paths.RollbackPath)
                fsyncDirectory paths.ConfigDir
            with _ -> fail "cannot clear Traefik rollback journal"

    let private adminPortFromStatic (staticData: byte[] option) : int option =
        match staticData with
        | None -> None
        | Some bytes ->
            try
                use document = JsonDocument.Parse(bytes)
                let address: string = document.RootElement.GetProperty("entryPoints").GetProperty("keroosha-admin").GetProperty("address").GetString()
                if isNull address || not (address.StartsWith("127.0.0.1:", StringComparison.Ordinal)) then None
                else
                    match Int32.TryParse(address.Substring(address.LastIndexOf(':') + 1), NumberStyles.None, CultureInfo.InvariantCulture) with
                    | true, port when port >= 1 && port <= 65535 -> Some port
                    | _ -> None
            with _ -> None

    let private waitForRollback (environment: HostEnvironment) (paths: RuntimePaths) (serviceControllerTimeout: float) (staticData: byte[] option) (dynamicData: byte[] option) : bool =
        match staticData, dynamicData with
        | Some staticBytes, Some dynamicBytes ->
            match adminPortFromStatic staticData with
            | None -> false
            | Some adminPort ->
                let deadline = Stopwatch.GetTimestamp() + int64 (serviceControllerTimeout * float Stopwatch.Frequency)
                let mutable restored = false
                while not restored && Stopwatch.GetTimestamp() < deadline do
                    if isActive environment then
                        let filesMatch =
                            try
                                readBytes environment (Path.Combine(paths.ConfigDir, "static.yml")) = staticBytes
                                && readBytes environment (Path.Combine(paths.DynamicDir, "current.yml")) = dynamicBytes
                            with _ -> false
                        if filesMatch then
                            let api = readApi adminPort |> fun operation -> operation.GetAwaiter().GetResult()
                            restored <- apiMatchesDynamic api (Some dynamicBytes)
                    if not restored && Stopwatch.GetTimestamp() < deadline then Thread.Sleep(ActivationPollMilliseconds)
                restored
        | _ -> false

    let private removeExtraCertificateFiles (environment: HostEnvironment) (paths: RuntimePaths) (allowedFiles: Set<string>) (errorMessage: string) : unit =
        try
            for filename in entries paths.CertificateDir do
                if not (allowedFiles |> Set.contains filename) && certificateFilenamePattern.IsMatch(filename) then
                    File.Delete(Path.Combine(paths.CertificateDir, filename))
            fsyncDirectory paths.CertificateDir
        with _ -> fail errorMessage

    let private recoverPendingTransaction (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) (request: JsonElement) (groupId: int) (activationTimeout: float) : unit =
        match loadPendingTransaction environment paths ownerId with
        | None -> ()
        | Some journal ->
            let currentUnit = safeUnitStatus environment paths.UnitPath ownerId
            if currentUnit.IsSome then ensureEffectiveUnit environment paths
            elif isActive environment || isEnabled environment then fail "interrupted Traefik service has no owned unit"
            let currentSync = observeRuntime environment request "" true
            if currentSync["inSync"].GetValue<bool>() then removePendingTransaction environment paths ownerId
            else
                let oldStatic = journal.Static
                let oldDynamic = journal.Dynamic
                let oldUnit = journal.Unit
                let currentStatic = readOptional environment (Path.Combine(paths.ConfigDir, "static.yml"))
                let currentBinaryExists = assertRegular environment paths.BinaryPath "Traefik binary"
                let currentBinaryHash = if currentBinaryExists then Some(binarySha256 environment paths.BinaryPath) else None
                let restartRequired = currentStatic <> oldStatic || currentUnit <> oldUnit || currentBinaryHash <> journal.BinarySha256
                let currentActive = isActive environment
                if currentUnit.IsSome && (restartRequired || not journal.WasActive || not currentActive) then
                    stopOwnedService environment paths ownerId
                restoreFile environment (Path.Combine(paths.ConfigDir, "static.yml")) oldStatic 0o640 (Some groupId)
                restoreFile environment (Path.Combine(paths.DynamicDir, "current.yml")) oldDynamic 0o640 (Some groupId)
                restoreFile environment paths.UnitPath oldUnit 0o644 None
                if not journal.BinaryPresent then
                    for path in [ paths.BinaryPath; Path.Combine(paths.InstallDir, ".keroosha-release.json") ] do
                        try File.Delete(path) with _ -> ()
                elif currentBinaryHash = journal.BinarySha256 then
                    restoreFile environment (Path.Combine(paths.InstallDir, ".keroosha-release.json")) journal.ReleaseMarker 0o644 None
                removeExtraCertificateFiles environment paths (Set.ofList journal.CertificateFiles) "cannot remove interrupted Traefik certificate material"
                if currentUnit <> oldUnit then daemonReload environment
                if oldUnit.IsSome then ensureEffectiveUnit environment paths
                if isEnabled environment <> journal.WasEnabled then
                    if journal.WasEnabled then enableService environment else disableService environment
                if isEnabled environment <> journal.WasEnabled then fail "cannot restore interrupted Traefik enablement state"
                if journal.WasActive then
                    if not (isActive environment) then startService environment
                    elif restartRequired then restartService environment
                    if not (waitForRollback environment paths activationTimeout oldStatic oldDynamic) then fail "cannot restore interrupted Traefik configuration"
                if isActive environment <> journal.WasActive then fail "cannot restore interrupted Traefik service state"
                removePendingTransaction environment paths ownerId

    let private removeUnusedCertificates (environment: HostEnvironment) (paths: RuntimePaths) (request: Request) : unit =
        let wanted =
            request.Certificates
            |> Seq.collect (fun (KeyValue(_, certificate)) ->
                let digest = materialDigest certificate
                [ digest + ".crt"; digest + ".key" ])
            |> Set.ofSeq
        try
            for filename in entries paths.CertificateDir do
                if not (wanted.Contains(filename)) && certificateFilenamePattern.IsMatch(filename) then
                    File.Delete(Path.Combine(paths.CertificateDir, filename))
            fsyncDirectory paths.CertificateDir
        with _ -> fail "cannot remove obsolete Traefik certificate material"

    let private apply (environment: HostEnvironment) (requestElement: JsonElement) (activationTimeout: float) : JsonObject =
        let request = validateRequest requestElement
        if request.Operation <> "apply" then fail "apply requires an apply operation"
        let paths = pathsFor environment
        validateCertificateMaterial request
        let configStatus, stateStatus, installStatus, oldUnit = validateActualOwner environment paths request.OwnerId
        if oldUnit.IsSome then ensureEffectiveUnit environment paths
        let mutable wasActive = isActive environment
        let mutable wasEnabled = isEnabled environment
        if oldUnit.IsNone && (wasActive || wasEnabled) then fail "Traefik service name collides with an unowned systemd unit"
        let existingOwned = configStatus = "owned" || stateStatus = "owned" || installStatus = "owned"
        let _, serviceGroup = ensureLayout environment paths request.OwnerId existingOwned
        recoverPendingTransaction environment paths request.OwnerId requestElement serviceGroup activationTimeout
        let configStatus, stateStatus, installStatus, oldUnit = validateActualOwner environment paths request.OwnerId
        if oldUnit.IsSome then ensureEffectiveUnit environment paths
        wasActive <- isActive environment
        wasEnabled <- isEnabled environment
        if oldUnit.IsNone && (wasActive || wasEnabled) then fail "Traefik service name collides with an unowned systemd unit"
        let oldStatic = readOptional environment (Path.Combine(paths.ConfigDir, "static.yml"))
        let oldDynamic = readOptional environment (Path.Combine(paths.DynamicDir, "current.yml"))
        let oldBinaryExists = assertRegular environment paths.BinaryPath "Traefik binary"
        let oldBinaryHash = if oldBinaryExists then Some(binarySha256 environment paths.BinaryPath) else None
        let oldReleaseMarker = readOptional environment (Path.Combine(paths.InstallDir, ".keroosha-release.json"))
        let oldUnitBytes = oldUnit
        let currentUnit = Encoding.UTF8.GetBytes(unitText paths request.OwnerId)
        let staticData = Encoding.UTF8.GetBytes(renderStaticConfig requestElement paths "")
        let dynamicData = Encoding.UTF8.GetBytes(renderDynamicConfig requestElement paths)
        let oldCertificateFiles = entries paths.CertificateDir |> Set.ofArray
        savePendingTransaction environment paths request.OwnerId oldStatic oldDynamic oldUnitBytes oldReleaseMarker oldBinaryExists oldBinaryHash wasActive wasEnabled (Set.toList oldCertificateFiles) serviceGroup
        let mutable binaryChanged = false
        let rootUid, rootGid = hostOwner environment
        let unitChanged = oldUnitBytes <> Some currentUnit || not (metadataMatches environment paths.UnitPath "file" 0o644 rootUid rootGid)
        try
            binaryChanged <- ensureInstalledBinary environment paths request.OwnerId
            writeCertificateFiles environment paths request serviceGroup
            ensureGroupedAtomicWrite environment (Path.Combine(paths.ConfigDir, "static.yml")) staticData 0o640 serviceGroup
            ensureGroupedAtomicWrite environment (Path.Combine(paths.DynamicDir, "current.yml")) dynamicData 0o640 serviceGroup
            if unitChanged then
                writeAtomic environment paths.UnitPath currentUnit 0o644 (Some rootGid)
                daemonReload environment
            if not (isEnabled environment) then enableService environment
            if not (isActive environment) then startService environment
            elif binaryChanged || oldStatic <> Some staticData || unitChanged then restartService environment
            let result = waitForActivation environment requestElement paths activationTimeout
            if not (result["inSync"].GetValue<bool>()) then fail "Traefik activation did not satisfy the bounded readiness checks"
            removePendingTransaction environment paths request.OwnerId
            try removeUnusedCertificates environment paths request with :? BackendError -> ()
            result["actualConfigHash"] <- JsonValue.Create(actualConfigHash environment paths)
            result
        with error ->
            let failureReason =
                match error with
                | :? BackendError -> error.Message
                | _ -> error.GetType().Name
            try
                let currentOwnedUnit = safeUnitStatus environment paths.UnitPath request.OwnerId
                let restartRequired = binaryChanged || oldStatic <> Some staticData || unitChanged
                let currentActive = isActive environment
                if currentOwnedUnit.IsSome && (restartRequired || not wasActive || not currentActive) then
                    stopOwnedService environment paths request.OwnerId
                elif currentOwnedUnit.IsNone && currentActive then
                    fail "interrupted Traefik service has no owned unit"
                restoreFile environment (Path.Combine(paths.ConfigDir, "static.yml")) oldStatic 0o640 (Some serviceGroup)
                restoreFile environment (Path.Combine(paths.DynamicDir, "current.yml")) oldDynamic 0o640 (Some serviceGroup)
                restoreFile environment paths.UnitPath oldUnitBytes 0o644 None
                if not oldBinaryExists then
                    for path in [ paths.BinaryPath; Path.Combine(paths.InstallDir, ".keroosha-release.json") ] do
                        try File.Delete(path) with _ -> ()
                elif (assertRegular environment paths.BinaryPath "Traefik binary") && Some(binarySha256 environment paths.BinaryPath) = oldBinaryHash then
                    restoreFile environment (Path.Combine(paths.InstallDir, ".keroosha-release.json")) oldReleaseMarker 0o644 None
                removeExtraCertificateFiles environment paths oldCertificateFiles "cannot remove interrupted Traefik certificate material"
                daemonReload environment
                if oldUnitBytes.IsSome then ensureEffectiveUnit environment paths
                if isEnabled environment <> wasEnabled then
                    if wasEnabled then enableService environment else disableService environment
                if isEnabled environment <> wasEnabled then fail "previous Traefik enablement state was not restored"
                if wasActive then
                    if not (isActive environment) then startService environment
                    elif restartRequired then restartService environment
                    if not (waitForRollback environment paths activationTimeout oldStatic oldDynamic) then fail "previous Traefik configuration was not restored"
                if isActive environment <> wasActive then fail "previous Traefik service state was not restored"
                removePendingTransaction environment paths request.OwnerId
            with _ -> fail "Traefik activation failed and the prior configuration could not be restored"
            fail ("Traefik activation failed; the prior configuration was restored: " + failureReason)

    let private read (environment: HostEnvironment) (requestElement: JsonElement) : JsonObject =
        let request = validateRequest requestElement
        if request.Operation <> "read" then fail "read requires a read operation"
        observeRuntime environment requestElement "" false

    let private removeOwnedTree (environment: HostEnvironment) (directory: string) (ownerId: string) (description: string) : unit =
        let status = markerStatus environment directory ownerId
        if status = "absent" then ()
        elif status <> "owned" then fail ("refusing to remove an unowned " + description)
        else
            let rec deleteContents path =
                for child in entries path do
                    let childPath = Path.Combine(path, child)
                    match tryStat environment childPath with
                    | Some item when item.Kind = "directory" -> deleteContents childPath; Directory.Delete(childPath, false)
                    | Some item when item.Kind = "regular file" || item.Kind = "regular empty file" -> File.Delete(childPath)
                    | _ -> fail "refusing to remove an unsafe Traefik path"
            deleteContents directory
            Directory.Delete(directory, false)
            fsyncDirectory (Path.GetDirectoryName(directory))

    let private delete (environment: HostEnvironment) (requestElement: JsonElement) : JsonObject =
        let request = validateRequest requestElement
        if request.Operation <> "delete" then fail "delete requires a delete operation"
        let paths = pathsFor environment
        let configStatus, _, installStatus, _ = checkLayoutCollisions environment paths request.OwnerId
        let unitData = safeUnitStatus environment paths.UnitPath request.OwnerId
        if configStatus = "absent" && installStatus = "absent" && unitData.IsNone then JsonObject()
        else
            if unitData.IsNone && (isActive environment || isEnabled environment) then fail "Traefik service name collides with an unowned systemd unit"
            if unitData.IsSome then
                ensureEffectiveUnit environment paths
                disableService environment
                if isEnabled environment then fail "owned Traefik service could not be disabled"
                stopOwnedService environment paths request.OwnerId
                try
                    File.Delete(paths.UnitPath)
                    fsyncDirectory (Path.GetDirectoryName(paths.UnitPath))
                with _ -> fail "cannot remove owned Traefik service unit"
                daemonReload environment
            removeOwnedTree environment paths.ConfigDir request.OwnerId "configuration directory"
            removeOwnedTree environment paths.InstallDir request.OwnerId "installation directory"
            JsonObject()

    let private rootRequired (environment: HostEnvironment) : unit =
        let result = run environment "id" [ "-u" ]
        if result.ExitCode <> 0 || result.Stdout.Trim() <> "0" then fail "Traefik host operations require root privileges"

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        try
            let normalized = validateRequest request
            rootRequired environment
            use lock = HostFiles.lockFile (HostEnvironment.path environment "/run/lock/keroosha-iac-traefik.lock")
            match normalized.Operation with
            | "read" -> read environment request :> JsonNode
            | "apply" -> apply environment request ActivationTimeoutSeconds :> JsonNode
            | "delete" -> delete environment request :> JsonNode
            | _ -> fail "unsupported Traefik backend operation"
        with
        | :? BackendError -> reraise ()
        | _ -> fail "Traefik backend failed unexpectedly"
