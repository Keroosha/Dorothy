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
open System.Net.NetworkInformation
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

    [<DllImport("libc", EntryPoint = "linkat", SetLastError = true)>]
    extern int nativeLinkAt(int oldDirectory, string oldPath, int newDirectory, string newPath, int flags)

    [<DllImport("libc", EntryPoint = "rename", SetLastError = true)>]
    extern int nativeRename(string oldPath, string newPath)

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
    let private ApiMaximumBytes = 16 * 1024 * 1024

    let private archiveChecksums =
        dict [
            "amd64", "759a7bc0d66b74c588255ed9e41c7f9d4aba60bdb7bce9dde551b1268a55eb07"
            "arm64", "8f9463a7dd3a618569aaa46e19500331d7374a2e6f6ee300a50df5bb49132e1a"
        ]

    let private releaseUrl architecture =
        "https://github.com/traefik/traefik/releases/download/v" + Version + "/traefik_v" + Version + "_linux_" + architecture + ".tar.gz"
    let archiveChecksum architecture = archiveChecksums[architecture]

    let private dnsLabelPattern = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)
    let private fingerprintPattern = Regex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)
    let private certificateFilenamePattern = Regex("^[0-9a-f]{64}\\.(?:crt|key)$", RegexOptions.CultureInvariant)
    let private acmeFilenamePattern = Regex("^acme-[0-9a-f]{64}\\.json$", RegexOptions.CultureInvariant)
    let private systemdEnvironmentNamePattern = Regex("^[A-Z][A-Z0-9_]*$", RegexOptions.CultureInvariant)
    let private credentialFilename = "dns-credentials.env"

    type RuntimePaths =
        { ConfigDir: string
          StateDir: string
          InstallDir: string
          UnitPath: string }
        member this.DynamicDir = Path.Combine(this.ConfigDir, "dynamic")
        member this.CertificateDir = Path.Combine(this.DynamicDir, "certificates")
        member this.RollbackPath = Path.Combine(this.ConfigDir, ".keroosha-rollback.json")
        member this.StaticReceipt = Path.Combine(this.ConfigDir, ".keroosha-static-receipt")
        member this.BinaryPath = Path.Combine(this.InstallDir, Version, "traefik")
        member this.CredentialsPath = Path.Combine(this.ConfigDir, credentialFilename)

    type private Resolver =
        { Email: string
          HttpChallengeEntryPoint: string
          CaServer: string option }

    type private Certificate =
        { CertificatePem: string
          PrivateKeyPem: string
          Fingerprint: string
          Usage: string }
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
          ExcludedPathSubtree: string option
          Tls: RouterTls }

    type private Request =
        { Operation: string
          OwnerId: string
          EntryPoints: Map<string, int>
          Resolvers: Map<string, Resolver>
          Routers: Map<string, Router>
          Certificates: Map<string, Certificate>
          Configuration: JsonObject option
          MergedDynamic: JsonObject option
          PreviousUdpEntryPoints: Set<string> option
          ReadProbeSafe: bool
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
        { RawData: JsonElement
          EntryPoints: JsonElement
          Version: JsonElement
          AdminPort: int }

    type private RecoveryStart =
        { Job: string
          Invocation: string
          PriorReceipt: string
          Preimage: string
          Target: string option }

    type private PendingTransaction =
        { Static: byte[] option
          Dynamic: byte[] option
          Credentials: byte[] option
          CredentialsKnown: bool
          Unit: byte[] option
          ReleaseMarker: byte[] option
          BinaryPresent: bool
          BinarySha256: string option
          WasActive: bool
          WasEnabled: bool
          RestartRequired: bool
          CertificateFiles: string list
          JournalSha256: string
          Recovery: RecoveryStart option }

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
        if not (TraefikHttpGraphModel.isValidName 63 value) || reservedNames.Contains(value.ToLowerInvariant()) then
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
            if not (values.TryAdd(property.Name, parser property.Name property.Value)) then fail "duplicate Traefik declaration"
        values |> Seq.map (fun pair -> pair.Key, pair.Value) |> Map.ofSeq
    let private parseCertificates (element: JsonElement) =
        parseStringMap "certificates" (fun name value ->
            validateName "certificate" [] name |> ignore
            requireObject "certificate" value |> ignore
            let fields = objectNames value
            let requiredFields = set [ "certificatePem"; "privateKeyPem"; "fingerprint" ]
            let allowedFields = Set.add "usage" requiredFields
            if not (Set.isSubset requiredFields fields)
               || not (Set.isEmpty (Set.difference fields allowedFields)) then
                fail "certificate configuration is invalid"
            let certificatePem = requiredProperty value "certificatePem" "certificatePem is not valid PEM material" |> stringValue "certificatePem is not valid PEM material"
            if String.IsNullOrEmpty(certificatePem) || Encoding.UTF8.GetByteCount(certificatePem) > MaximumCertificateBytes || not (certificatePem.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)) then
                fail "certificatePem is not valid PEM material"
            let privateKeyPem = requiredProperty value "privateKeyPem" "privateKeyPem is not valid PEM material" |> stringValue "privateKeyPem is not valid PEM material"
            if String.IsNullOrEmpty(privateKeyPem) || Encoding.UTF8.GetByteCount(privateKeyPem) > MaximumCertificateBytes || not (privateKeyPem.Contains("-----BEGIN ", StringComparison.Ordinal)) || not (privateKeyPem.Contains("PRIVATE KEY-----", StringComparison.Ordinal)) then
                fail "privateKeyPem is not valid PEM material"
            let fingerprint = requiredProperty value "fingerprint" "certificate fingerprint must be lowercase SHA-256 hex" |> stringValue "certificate fingerprint must be lowercase SHA-256 hex"
            if not (fingerprintPattern.IsMatch(fingerprint)) then fail "certificate fingerprint must be lowercase SHA-256 hex"
            let usage =
                match tryProperty value "usage" with
                | None -> "server"
                | Some property -> stringValue "certificate usage is invalid" property
            if usage <> "server" && usage <> "client" then fail "certificate usage is invalid"
            { CertificatePem = certificatePem
              PrivateKeyPem = privateKeyPem
              Fingerprint = fingerprint
              Usage = usage }) element

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
            let allowed = set [ "operation"; "ownerId"; "entryPoints"; "resolvers"; "routers"; "certificates"; "adminPort"; "configuration" ]
            if not (Set.isEmpty (Set.difference (objectNames request) allowed)) then
                fail "delete request contains unsupported fields"
            { Operation = operation
              OwnerId = ownerId
              EntryPoints = Map.empty
              Resolvers = Map.empty
              Routers = Map.empty
              Certificates = Map.empty
              Configuration = None
              MergedDynamic = None
              PreviousUdpEntryPoints = None
              ReadProbeSafe = false
              AdminPort = DefaultAdminPort }
        else
            let allowed = set [ "operation"; "ownerId"; "entryPoints"; "resolvers"; "routers"; "certificates"; "adminPort"; "configuration"; "previousUdpEntryPoints" ]
            if not (Set.isEmpty (Set.difference (objectNames request) allowed)) then fail "request contains unsupported fields"
            for field in [ "entryPoints"; "resolvers"; "routers"; "certificates" ] do
                if tryProperty request field |> Option.isNone then fail ("request is missing " + field)

            let previousUdpEntryPoints =
                match tryProperty request "previousUdpEntryPoints" with
                | None -> None
                | Some value when operation = "apply" && value.ValueKind = JsonValueKind.Array && value.GetArrayLength() <= 256 ->
                    let mutable names = Set.empty
                    for item in value.EnumerateArray() do
                        let name = stringValue "previousUdpEntryPoints must contain safe entrypoint names" item
                        validateName "previous UDP entrypoint" [] name |> ignore
                        if Set.contains name names then fail "previousUdpEntryPoints contains duplicates"
                        names <- Set.add name names
                    Some names
                | _ -> fail "previousUdpEntryPoints is invalid"
            let mutable readProbeSafe = true

            let entryPoints =
                parseStringMap "entryPoints" (fun name value ->
                    validateName "entryPoint" [ "keroosha-admin"; "traefik" ] name |> ignore
                    parseInt32 "entryPoint port" value) (requiredProperty request "entryPoints" "request is missing entryPoints")
            let adminPort =
                match tryProperty request "adminPort" with
                | None -> DefaultAdminPort
                | Some value -> parseInt32 "adminPort" value
            if entryPoints |> Map.exists (fun _ port -> port = adminPort) then
                if operation = "read" then readProbeSafe <- false
                else fail "adminPort must not collide with an entryPoint port"

            let resolvers =
                parseStringMap "resolvers" (fun name value ->
                    validateName "resolver" [] name |> ignore
                    requireObject "resolver" value |> ignore
                    let allowedResolver = set [ "email"; "httpChallengeEntryPoint"; "caServer" ]
                    if not (Set.isEmpty (Set.difference (objectNames value) allowedResolver)) then fail "resolver configuration is invalid"
                    let email =
                        match tryProperty value "email" with
                        | None -> ""
                        | Some property when property.ValueKind = JsonValueKind.Null -> ""
                        | Some property -> stringValue "resolver email is invalid" property
                    if email <> ""
                       && (email.Length > 254
                           || ((email |> Seq.filter ((=) '@') |> Seq.length) <> 1)
                           || (email |> Seq.exists (fun character -> int character < 33 || int character = 127))) then
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
                parseCertificates (requiredProperty request "certificates" "request is missing certificates")

            let routers =
                parseStringMap "routers" (fun name value ->
                    validateName "router" [ "keroosha-admin" ] name |> ignore
                    requireObject "router" value |> ignore
                    let fields = objectNames value
                    if not (Set.isSubset (set [ "host"; "entryPoint"; "tls" ]) fields)
                       || not (Set.isEmpty (Set.difference fields (set [ "host"; "entryPoint"; "backend"; "redirect"; "excludedPathSubtree"; "tls" ]))) then
                        fail "router configuration is invalid"
                    let host = requiredProperty value "host" "router host must be a DNS name or IP address" |> stringValue "router host must be a DNS name or IP address" |> validateDnsName
                    let excludedPathSubtree =
                        match tryProperty value "excludedPathSubtree" with
                        | None -> None
                        | Some subtree ->
                            let subtree = stringValue "router excludedPathSubtree must be a canonical subtree" subtree
                            if not (TraefikPathModel.isCanonicalSubtree subtree) then
                                fail "router excludedPathSubtree must be a canonical subtree"
                            Some subtree
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
                        if certificates[tlsName].Usage <> "server" then fail "router cannot use an outbound-only certificate"
                    let backend, redirect =
                        match tryProperty value "backend", tryProperty value "redirect" with
                        | Some backend, None ->
                            let backend = stringValue "router backend must be an HTTP or HTTPS URL" backend
                            validateNetworkUrl "router backend must be an HTTP or HTTPS URL" 2048 false backend |> ignore
                            try TraefikSettings.guardAdminDestination adminPort backend
                            with :? InvalidOperationException ->
                                if operation = "read" then readProbeSafe <- false
                                else fail "proxy destination must not use the private Traefik administration port"
                            Some backend, None
                        | None, Some redirect ->
                            requireObject "router redirect" redirect |> ignore
                            if objectNames redirect <> set [ "kind"; "origin" ] then fail "router redirect configuration is invalid"
                            let redirectKind = requiredProperty redirect "kind" "router redirect kind is invalid" |> stringValue "router redirect kind is invalid"
                            if redirectKind <> "permanentToOrigin" then fail "router redirect kind is invalid"
                            let origin = requiredProperty redirect "origin" "router redirect origin is invalid" |> stringValue "router redirect origin is invalid"
                            None, Some { Origin = validateRedirectOrigin origin }
                        | _ -> fail "router must specify exactly one of backend or redirect"
                    { Host = host; EntryPoint = entryPoint; Backend = backend; Redirect = redirect; ExcludedPathSubtree = excludedPathSubtree; Tls = { Kind = kind; Name = tlsName } }) (requiredProperty request "routers" "request is missing routers")

            let serverCertificates =
                certificates
                |> Seq.choose (fun (KeyValue(name, certificate)) -> if certificate.Usage = "server" then Some name else None)
                |> Set.ofSeq
            let clientCertificates =
                certificates
                |> Seq.choose (fun (KeyValue(name, certificate)) -> if certificate.Usage = "client" then Some name else None)
                |> Set.ofSeq
            let legacyRoutes =
                routers
                |> Seq.map (fun (KeyValue(name, router)) ->
                    let target: TraefikHttpGraphModel.LegacyTarget =
                        match router.Backend, router.Redirect with
                        | Some backend, None -> TraefikHttpGraphModel.LegacyTarget.Backend backend
                        | None, Some redirect -> TraefikHttpGraphModel.LegacyTarget.Redirect redirect.Origin
                        | _ -> fail "router must specify exactly one of backend or redirect"
                    let tls: TraefikHttpGraphModel.LegacyTls =
                        match router.Tls.Kind with
                        | "none" -> TraefikHttpGraphModel.LegacyTls.None
                        | "acme" -> TraefikHttpGraphModel.LegacyTls.Acme router.Tls.Name
                        | "provided" -> TraefikHttpGraphModel.LegacyTls.Provided
                        | _ -> fail "router TLS kind is invalid"
                    let legacyRouter: TraefikHttpGraphModel.LegacyRouter =
                        { Name = name
                          Host = router.Host
                          EntryPoint = router.EntryPoint
                          ExcludedPathSubtree = router.ExcludedPathSubtree
                          Target = target
                          Tls = tls }
                    legacyRouter)
            let configuration =
                tryProperty request "configuration"
                |> Option.map (fun input -> TraefikSettings.parse (input.GetRawText()))
            let configurationRoot = defaultArg configuration (JsonObject())
            let _, mergedDynamic, safe =
                try
                    if operation = "read" then
                        TraefikSettings.validateForReadWithLegacyRoutes
                            entryPoints adminPort (Set.ofSeq resolvers.Keys) serverCertificates clientCertificates legacyRoutes configurationRoot
                    else
                        let graph, dynamic =
                            TraefikSettings.validateWithLegacyRoutes
                                entryPoints adminPort (Set.ofSeq resolvers.Keys) serverCertificates clientCertificates legacyRoutes configurationRoot
                        graph, dynamic, true
                with :? TraefikSettings.InvalidConfiguration as invalid -> fail invalid.Message
            if not safe then readProbeSafe <- false

            { Operation = operation
              OwnerId = ownerId
              EntryPoints = entryPoints
              Resolvers = resolvers
              Routers = routers
              Certificates = certificates
              Configuration = configuration
              MergedDynamic = Some mergedDynamic
              PreviousUdpEntryPoints = previousUdpEntryPoints
              ReadProbeSafe = readProbeSafe
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

    let private materialDigest (certificate: Certificate) =
        let certificateBytes = Encoding.UTF8.GetBytes(certificate.CertificatePem)
        let keyBytes = Encoding.UTF8.GetBytes(certificate.PrivateKeyPem)
        let material = Array.zeroCreate<byte> (certificateBytes.Length + 1 + keyBytes.Length)
        Buffer.BlockCopy(certificateBytes, 0, material, 0, certificateBytes.Length)
        Buffer.BlockCopy(keyBytes, 0, material, certificateBytes.Length + 1, keyBytes.Length)
        sha256Bytes material

    let private legacyAcmeStoragePath
        (paths: RuntimePaths)
        (resolverName: string)
        (caServer: string)
        (previousStatic: byte[] option)
        =
        let legacyPath = TraefikTlsSettings.legacyAcmeStoragePath paths.StateDir resolverName
        let issuerPath = TraefikTlsSettings.acmeStoragePath paths.StateDir resolverName caServer
        let sameLegacyIssuer =
            match previousStatic with
            | None -> false
            | Some bytes ->
                try
                    use document = JsonDocument.Parse(ReadOnlyMemory<byte>(bytes))
                    let root = document.RootElement
                    let resolver =
                        tryProperty root "certificatesResolvers"
                        |> Option.bind (fun values -> tryProperty values resolverName)
                    let acme = resolver |> Option.bind (fun value -> tryProperty value "acme")
                    let stringOr name fallback =
                        acme
                        |> Option.bind (fun value -> tryProperty value name)
                        |> Option.bind (fun value ->
                            if value.ValueKind <> JsonValueKind.String then None
                            else
                                match value.GetString() with
                                | null -> None
                                | text -> Some text)
                        |> Option.defaultValue fallback
                    stringOr "caServer" DefaultCaServer = caServer
                    && stringOr "storage" "" = legacyPath
                with _ -> false
        if sameLegacyIssuer then legacyPath else issuerPath

    let private renderStaticWithPrevious
        (normalized: Request)
        (paths: RuntimePaths)
        (listenHost: string)
        (previousStatic: byte[] option)
        =
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
            if not (String.IsNullOrEmpty resolver.Email) then acme["email"] <- JsonValue.Create(resolver.Email)
            let caServer = defaultArg resolver.CaServer DefaultCaServer
            acme["storage"] <- JsonValue.Create(legacyAcmeStoragePath paths name caServer previousStatic)
            let challenge = JsonObject()
            challenge["entryPoint"] <- JsonValue.Create(resolver.HttpChallengeEntryPoint)
            acme["httpChallenge"] <- challenge
            acme["caServer"] <- JsonValue.Create(caServer)
            let resolverConfig = JsonObject()
            resolverConfig["acme"] <- acme
            resolvers[name] <- resolverConfig
        if resolvers.Count > 0 then
            staticConfig["certificatesResolvers"] <- resolvers
        match normalized.Configuration with
        | Some root ->
            let native = TraefikSettings.section root "static" |> TraefikTlsSettings.staticSettings paths.StateDir
            match native["certificatesResolvers"] with
            | :? JsonObject as nativeResolvers ->
                for KeyValue(name, resolverNode) in nativeResolvers do
                    match resolverNode with
                    | :? JsonObject as resolver ->
                        match resolver["acme"] with
                        | :? JsonObject as acme ->
                            let caServer =
                                match acme["caServer"] with
                                | :? JsonValue as value when value.GetValueKind() = JsonValueKind.String ->
                                    match value.GetValue<string>() with
                                    | null -> DefaultCaServer
                                    | text -> text
                                | _ -> DefaultCaServer
                            acme["storage"] <- JsonValue.Create(legacyAcmeStoragePath paths name caServer previousStatic)
                        | _ -> ()
                    | _ -> ()
            | _ -> ()
            let hasOtlpLogs (sectionName: string) =
                let mutable section = null
                if not (native.TryGetPropertyValue(sectionName, &section)) then
                    false
                else
                    match section with
                    | :? JsonObject as fields ->
                        let mutable otlp = null
                        fields.TryGetPropertyValue("otlp", &otlp) && not (isNull otlp)
                    | _ -> false
            let enableOtlpLogs = hasOtlpLogs "log" || hasOtlpLogs "accessLog"
            TraefikSettings.merge 1 staticConfig native
            if enableOtlpLogs then
                let experimental = JsonObject()
                experimental["otlpLogs"] <- JsonValue.Create(true)
                staticConfig["experimental"] <- experimental
        | None -> ()
        jsonText staticConfig

    let private renderStatic (normalized: Request) (paths: RuntimePaths) (listenHost: string) =
        renderStaticWithPrevious normalized paths listenHost None

    let renderStaticConfig request paths listenHost = renderStatic (validateRequest request) paths listenHost

    // Independent commitment for the bodies absent from rawdata. The first digest
    // remains the full activation digest, including the observable graph.
    let private opaqueDigest (root: JsonObject) =
        use hash = SHA256.Create()
        use sink = new CryptoStream(Stream.Null, hash, CryptoStreamMode.Write)
        use writer = new Utf8JsonWriter(sink, jsonWriterOptions)
        writer.WriteStartArray()
        let memberOf (section: string) (key: string) =
            match root[section] with
            | :? JsonObject as fields -> fields[key]
            | _ -> null
        for item in [root["tls"]; memberOf "http" "serversTransports"; memberOf "tcp" "serversTransports"] do
            if isNull item then writer.WriteNullValue() else writeSortedNode writer item
        writer.WriteEndArray()
        writer.Flush()
        sink.FlushFinalBlock()
        Convert.ToHexStringLower(hash.Hash)

    let private renderDynamicFormat markLegacy (normalized: Request) (paths: RuntimePaths) =
        let mergedDynamic =
            normalized.MergedDynamic
            |> Option.defaultWith (fun () -> fail "lowered Traefik dynamic configuration is unavailable")
        let material =
            normalized.Certificates
            |> Map.map (fun _ certificate ->
                let digest = materialDigest certificate
                Path.Combine(paths.CertificateDir, digest + ".crt"), Path.Combine(paths.CertificateDir, digest + ".key"))
        let dynamicConfig = TraefikTlsSettings.dynamicSettings material mergedDynamic
        // paerser rejects a standalone empty resource map (e.g. tcp.middlewares after
        // withdrawing its last member). Empty maps mean no resource; named empty objects
        // such as a router's tls:{} still have semantics and must remain untouched.
        let omitEmptyMaps (name: string) =
            match dynamicConfig[name] with
            | :? JsonObject as section ->
                for index = section.Count - 1 downto 0 do
                    match section.GetAt(index).Value with
                    | :? JsonObject as resources when resources.Count = 0 -> section.RemoveAt(index)
                    | _ -> ()
                if section.Count = 0 then dynamicConfig.Remove(name) |> ignore
            | _ -> ()
        omitEmptyMaps "http"
        omitEmptyMaps "tcp"
        omitEmptyMaps "udp"
        omitEmptyMaps "tls"
        let tlsRoot =
            match dynamicConfig["tls"] with
            | null -> JsonObject()
            | :? JsonObject as value -> value
            | _ -> fail "TLS configuration is invalid"
        let certificates, explicitPaths =
            if tlsRoot.ContainsKey("certificates") then
                let items = tlsRoot["certificates"].AsArray()
                tlsRoot.Remove("certificates") |> ignore
                let paths =
                    items
                    |> Seq.map (fun item -> item["certFile"].GetValue<string>(), item["keyFile"].GetValue<string>())
                    |> Set.ofSeq
                if paths.Count <> items.Count || not (Set.isSubset paths (material.Values |> Set.ofSeq)) then
                    fail "TLS store registration must reference distinct managed certificates"
                items, paths
            else
                JsonArray(), Set.empty
        for KeyValue(name, ((certFile, keyFile) as pair)) in material do
            if normalized.Certificates[name].Usage = "server" && not (explicitPaths.Contains(pair)) then
                let item = JsonObject()
                item["certFile"] <- JsonValue.Create(certFile)
                item["keyFile"] <- JsonValue.Create(keyFile)
                certificates.Add(item)
        tlsRoot["certificates"] <- certificates
        dynamicConfig["tls"] <- tlsRoot

        if markLegacy || normalized.Configuration.IsSome then
            let http = dynamicConfig["http"] :?> JsonObject
            let routers = http["routers"] :?> JsonObject
            let admin = routers["keroosha-admin"] :?> JsonObject
            // Some file-provider settings (e.g. transports) have no public API collection.
            // A changed rule on this private router acknowledges the generation, not acceptance.
            use hash = SHA256.Create()
            use sink = new CryptoStream(Stream.Null, hash, CryptoStreamMode.Write)
            use writer = new Utf8JsonWriter(sink, jsonWriterOptions)
            writeSortedNode writer dynamicConfig
            writer.Flush()
            sink.FlushFinalBlock()
            let generation = Convert.ToHexStringLower(hash.Hash)
            admin["rule"] <- JsonValue.Create(TraefikHttpGraphModel.generatedAdminRuleWithGeneration (generation + opaqueDigest dynamicConfig))

        // validateRequest already validated the merged graph, including trusted generated routes,
        // before resolving certificate aliases. Native certFile/keyFile are outputs of the
        // protected-material transform, never admissible operator paths.
        // JSON is valid YAML. Keep literal braces in legacy URL paths from becoming Go templates.
        (jsonText dynamicConfig).Replace("{{", "\\u007b\\u007b", StringComparison.Ordinal)

    let private renderDynamic request paths = renderDynamicFormat true request paths

    let renderDynamicConfig request paths = renderDynamic (validateRequest request) paths
    let internal renderHistoricalDynamicConfig request paths = renderDynamicFormat false (validateRequest request) paths
    let private udpGraphEntryPoints (dynamicData: byte[] option) : Set<string> option =
        match dynamicData with
        | None -> Some Set.empty
        | Some bytes ->
            let malformed () = raise (InvalidDataException())
            let requireObject (element: JsonElement) =
                if element.ValueKind <> JsonValueKind.Object then malformed ()
                element
            let uniqueNames (element: JsonElement) =
                let mutable names = Set.empty
                for property in (requireObject element).EnumerateObject() do
                    if Set.contains property.Name names then malformed ()
                    names <- Set.add property.Name names
                names
            let stringProperty (element: JsonElement) (name: string) =
                match tryProperty element name with
                | Some value when value.ValueKind = JsonValueKind.String ->
                    match value.GetString() with
                    | null -> malformed ()
                    | text -> text
                | _ -> malformed ()
            let requiredObjectProperty (element: JsonElement) (name: string) =
                match tryProperty element name with
                | Some value -> requireObject value
                | None -> malformed ()
            try
                use document = JsonDocument.Parse(bytes, JsonDocumentOptions(MaxDepth = 64, AllowDuplicateProperties = false))
                let root = requireObject document.RootElement
                match tryProperty root "udp" with
                | None -> Some Set.empty
                | Some udp ->
                    let udp = requireObject udp
                    let udpNames = uniqueNames udp
                    if not (Set.isSubset udpNames (set [ "routers"; "services" ])) then malformed ()
                    match tryProperty udp "routers" with
                    | None -> Some Set.empty
                    | Some routers ->
                        let routers = requireObject routers
                        let routerNames = uniqueNames routers
                        if Set.isEmpty routerNames then Some Set.empty
                        else
                            let services = requiredObjectProperty udp "services"
                            uniqueNames services |> ignore
                            let validatedServices = HashSet<string>(StringComparer.Ordinal)
                            let activeServices = HashSet<string>(StringComparer.Ordinal)
                            let normalizeServiceName (value: string) =
                                if value.EndsWith("@file", StringComparison.Ordinal) then
                                    value.Substring(0, value.Length - 5)
                                else value
                            let rec validateService depth (rawName: string) =
                                let name = normalizeServiceName rawName
                                if String.IsNullOrWhiteSpace(name) || depth > 128 then malformed ()
                                elif validatedServices.Contains(name) then ()
                                elif not (activeServices.Add(name)) then malformed ()
                                else
                                    try
                                        let service = requiredObjectProperty services name
                                        let serviceNames = uniqueNames service
                                        if serviceNames = set [ "loadBalancer" ] then
                                            let loadBalancer = requiredObjectProperty service "loadBalancer"
                                            if uniqueNames loadBalancer <> set [ "servers" ] then malformed ()
                                            match tryProperty loadBalancer "servers" with
                                            | Some servers when servers.ValueKind = JsonValueKind.Array && servers.GetArrayLength() > 0 ->
                                                for server in servers.EnumerateArray() do
                                                    let serverNames = uniqueNames server
                                                    if serverNames <> set [ "address" ] then malformed ()
                                                    let address = stringProperty server "address"
                                                    if String.IsNullOrWhiteSpace(address) then malformed ()
                                            | _ -> malformed ()
                                        elif serviceNames = set [ "weighted" ] then
                                            let weighted = requiredObjectProperty service "weighted"
                                            if uniqueNames weighted <> set [ "services" ] then malformed ()
                                            match tryProperty weighted "services" with
                                            | Some children when children.ValueKind = JsonValueKind.Array && children.GetArrayLength() > 0 ->
                                                for child in children.EnumerateArray() do
                                                    let childNames = uniqueNames child
                                                    if not (Set.isSubset childNames (set [ "name"; "weight" ]))
                                                       || not (Set.contains "name" childNames) then
                                                        malformed ()
                                                    match tryProperty child "weight" with
                                                    | Some weight ->
                                                        let mutable value = 0
                                                        if weight.ValueKind <> JsonValueKind.Number || not (weight.TryGetInt32(&value)) then malformed ()
                                                    | None -> ()
                                                    validateService (depth + 1) (stringProperty child "name")
                                            | _ -> malformed ()
                                        else malformed ()
                                        activeServices.Remove(name) |> ignore
                                        validatedServices.Add(name) |> ignore
                                    with error ->
                                        activeServices.Remove(name) |> ignore
                                        raise error
                            let mutable entryPoints = Set.empty
                            for routerName in routerNames do
                                let router = requiredObjectProperty routers routerName
                                if uniqueNames router <> set [ "entryPoints"; "service" ] then malformed ()
                                let service = stringProperty router "service"
                                validateService 0 service
                                match tryProperty router "entryPoints" with
                                | Some values when values.ValueKind = JsonValueKind.Array && values.GetArrayLength() > 0 ->
                                    let mutable routeEntryPoints = Set.empty
                                    for value in values.EnumerateArray() do
                                        if value.ValueKind <> JsonValueKind.String then malformed ()
                                        match value.GetString() with
                                        | null
                                        | "" -> malformed ()
                                        | name ->
                                            if Set.contains name routeEntryPoints then malformed ()
                                            routeEntryPoints <- Set.add name routeEntryPoints
                                    entryPoints <- Set.union entryPoints routeEntryPoints
                                | _ -> malformed ()
                            Some entryPoints
            with _ -> None

    let private boundUdpEntryPoints (staticData: byte[] option) : Set<string> option =
        match staticData with
        | None -> Some Set.empty
        | Some bytes ->
            try
                use document = JsonDocument.Parse(bytes, JsonDocumentOptions(MaxDepth = 64, AllowDuplicateProperties = false))
                let root = document.RootElement
                if root.ValueKind <> JsonValueKind.Object then None
                else
                    match tryProperty root "entryPoints" with
                    | Some entryPoints when entryPoints.ValueKind = JsonValueKind.Object ->
                        let result =
                            entryPoints.EnumerateObject()
                            |> Seq.choose (fun entryPoint ->
                                match tryProperty entryPoint.Value "address" with
                                | Some address when address.ValueKind = JsonValueKind.String ->
                                    match address.GetString() with
                                    | null -> None
                                    | value when value.EndsWith("/udp", StringComparison.OrdinalIgnoreCase) -> Some entryPoint.Name
                                    | _ -> None
                                | _ -> None)
                            |> Set.ofSeq
                        Some result
                    | _ -> None
            with _ -> None
    // Rawdata can confirm route removal, but cannot observe an already-open peer session
    // using the removed UDP handler. Restart when its last route disappears to clear it.
    let udpWithdrawalRequiresRestartForAcceptedEntryPoints
        (previous: Set<string>)
        (nextDynamic: byte[] option)
        (targetStatic: byte[] option)
        : bool =
        let next = udpGraphEntryPoints nextDynamic
        let bound = boundUdpEntryPoints targetStatic
        match next, bound with
        | Some next, Some bound ->
            Set.difference previous next
            |> Set.intersect bound
            |> Set.isEmpty
            |> not
        | None, Some bound -> Set.intersect previous bound |> Set.isEmpty |> not
        | Some next, None -> not (Set.isEmpty (Set.difference previous next))
        | None, None -> not (Set.isEmpty previous)

    let udpWithdrawalRequiresRestart
        (previousDynamic: byte[] option)
        (nextDynamic: byte[] option)
        (targetStatic: byte[] option)
        : bool =
        match udpGraphEntryPoints previousDynamic with
        | Some previous -> udpWithdrawalRequiresRestartForAcceptedEntryPoints previous nextDynamic targetStatic
        | None ->
            match boundUdpEntryPoints targetStatic with
            | Some entryPoints -> not (Set.isEmpty entryPoints)
            | None -> true

    /// Disk may have drifted since the checkpoint. Either graph can describe a handler the
    /// daemon is still serving; if a previous graph is unknown, a bound idle listener is ambiguous.
    let udpUpdateRequiresRestart accepted previousDynamic nextDynamic targetStatic =
        match boundUdpEntryPoints targetStatic, udpGraphEntryPoints nextDynamic with
        | Some bound, Some desired when not bound.IsEmpty ->
            let disk = udpGraphEntryPoints previousDynamic
            bound |> Set.exists (fun name ->
                not (desired.Contains name)
                && (Option.forall (Set.contains name) accepted || Option.forall (Set.contains name) disk))
        | Some bound, _ -> not bound.IsEmpty
        | None, _ -> true


    let private credentialData (configuration: JsonObject option) : byte[] option =
        let values = TraefikTlsSettings.dnsEnvironment configuration
        if values.IsEmpty then None
        else
            let lines =
                values
                |> List.map (fun (name, value) ->
                    if not (systemdEnvironmentNamePattern.IsMatch(name))
                       || String.IsNullOrEmpty(value)
                       || value.Length > 16384
                       || (value |> Seq.exists Char.IsControl) then
                        fail "Traefik DNS credentials are invalid"
                    let escaped = value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)
                    name + "=\"" + escaped + "\"")
            let bytes = Encoding.UTF8.GetBytes(String.concat "\n" lines + "\n")
            if bytes.Length > 512 * 1024 then fail "Traefik DNS credentials exceed their size limit"
            Some bytes

    let private renderSystemdUnitWithCredentials (paths: RuntimePaths) (hasCredentials: bool) =
        String.concat "\n" (
            [
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
            ]
            @ (if hasCredentials then [ "EnvironmentFile=" + paths.CredentialsPath ] else [])
            @ [
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
        )

    let renderSystemdUnit (paths: RuntimePaths) = renderSystemdUnitWithCredentials paths false

    let private unitText (paths: RuntimePaths) (ownerId: string) (configuration: JsonObject option) : string =
        "# keroosha-owner=" + ownerDigest ownerId + "\n" + renderSystemdUnitWithCredentials paths (credentialData configuration |> Option.isSome)


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
    let private readDescriptorBounded (descriptor: int) (maximumBytes: int) : byte[] option =
        let handle = new SafeFileHandle(nativeint descriptor, false)
        use stream = new FileStream(handle, FileAccess.Read)
        use output = new MemoryStream(min maximumBytes 65536)
        let buffer = Array.zeroCreate<byte> 8192
        let mutable total = 0
        let mutable complete = false
        let mutable oversized = false
        while not complete && not oversized do
            let count = stream.Read(buffer, 0, min buffer.Length (maximumBytes + 1 - total))
            if count = 0 then complete <- true
            else
                total <- total + count
                if total > maximumBytes then oversized <- true
                else output.Write(buffer, 0, count)
        if oversized then None else Some(output.ToArray())

    let private readBytesBounded (_environment: HostEnvironment) (path: string) (maximumBytes: int) : byte[] option =
        let descriptor = openChecked path false
        try
            try readDescriptorBounded descriptor maximumBytes
            with _ -> None
        finally
            nativeClose(descriptor) |> ignore


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
        let parent = Path.GetDirectoryName(path)
        if not (assertDirectory environment parent "Traefik configuration directory") then
            fail "Traefik configuration directory is unavailable"
        assertRegular environment path "Traefik owned file" |> ignore
        let uid = runOk environment "cannot secure Traefik file ownership" "id" [ "-u" ] |> fun result -> Int32.Parse(result.Stdout.Trim(), CultureInfo.InvariantCulture)
        let gid = defaultArg groupId (runOk environment "cannot secure Traefik file ownership" "id" [ "-g" ] |> fun result -> Int32.Parse(result.Stdout.Trim(), CultureInfo.InvariantCulture))
        let temporaryPath = Path.Combine(parent, ".keroosha-traefik-write-" + Guid.NewGuid().ToString("N"))
        let mutable temporaryExists = false
        try
            let options = FileStreamOptions()
            options.Mode <- FileMode.CreateNew
            options.Access <- FileAccess.Write
            options.Share <- FileShare.None
            options.BufferSize <- 4096
            options.Options <- FileOptions.WriteThrough
            options.UnixCreateMode <- Nullable<UnixFileMode>(unixMode mode)
            do
                use output = new FileStream(temporaryPath, options)
                temporaryExists <- true
                output.Write(data, 0, data.Length)
                output.Flush(true)
            chown environment temporaryPath uid gid
            setMode environment temporaryPath mode false
            assertRegular environment path "Traefik owned file" |> ignore
            File.Move(temporaryPath, path, true)
            temporaryExists <- false
            HostFiles.syncDirectory parent
        finally
            if temporaryExists then
                try File.Delete(temporaryPath) with _ -> ()

    let private chmod (environment: HostEnvironment) (path: string) (mode: int) =
        setMode environment path mode false


    let private fsyncDirectory (path: string) =
        let descriptor = nativeOpen(path, 0x80000 ||| 0x20000 ||| 0x10000, 0)
        if descriptor < 0 then fail "cannot synchronize Traefik directory"
        try
            if nativeFsync(descriptor) <> 0 then fail "cannot synchronize Traefik directory"
        finally
            nativeClose(descriptor) |> ignore

    let private removeCredentialFile (environment: HostEnvironment) (paths: RuntimePaths) : unit =
        match tryStat environment paths.CredentialsPath with
        | None -> ()
        | Some item when item.Kind = "regular file" || item.Kind = "regular empty file" ->
            try
                File.Delete(paths.CredentialsPath)
                fsyncDirectory paths.ConfigDir
            with _ -> fail "cannot remove Traefik DNS credentials"
        | Some _ -> fail "Traefik DNS credential path is unsafe"

    let private writeCredentialFile
        (environment: HostEnvironment)
        (paths: RuntimePaths)
        (configuration: JsonObject option)
        : unit =
        match credentialData configuration with
        | None -> removeCredentialFile environment paths
        | Some bytes -> writeAtomic environment paths.CredentialsPath bytes 0o600 None

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
        let allowedRoot = set [ ".keroosha-owner"; ".keroosha-rollback.json"; ".keroosha-static-receipt"; "static.yml"; "dns-credentials.env"; "dynamic" ]
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
            for filePath in [ Path.Combine(paths.ConfigDir, "static.yml"); Path.Combine(paths.DynamicDir, "current.yml"); paths.CredentialsPath ] do
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
            paths.StaticReceipt, "static activation receipt"
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
        if assertRegular environment paths.CredentialsPath "DNS credential file" then
            try
                chmod environment paths.CredentialsPath 0o600
                chown environment paths.CredentialsPath (parseIdCommand environment "-u") (parseIdCommand environment "-g")
            with
            | :? BackendError -> reraise()
            | _ -> fail "cannot secure Traefik DNS credentials"
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

    let private credentialSnapshotMatches (environment: HostEnvironment) (paths: RuntimePaths) (expected: byte[] option) : bool =
        try
            match expected with
            | None -> tryStat environment paths.CredentialsPath |> Option.isNone
            | Some bytes ->
                let expectedUid, expectedGid = hostOwner environment
                match tryStat environment paths.CredentialsPath with
                | Some item
                    when (item.Kind = "regular file" || item.Kind = "regular empty file")
                         && item.Mode = 0o600
                         && item.Uid = expectedUid
                         && item.Gid = expectedGid ->
                    readBytesBounded environment paths.CredentialsPath (512 * 1024) = Some bytes
                | _ -> false
        with _ -> false

    let credentialFileMatches (environment: HostEnvironment) (paths: RuntimePaths) (configuration: JsonObject option) : bool =
        try credentialSnapshotMatches environment paths (credentialData configuration)
        with _ -> false

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

    let private pinnedReleaseMatches environment (paths: RuntimePaths) ownerId arch (hash: string option) =
        try
            use doc = JsonDocument.Parse(readBytes environment (Path.Combine(paths.InstallDir, ".keroosha-release.json")))
            let release = doc.RootElement
            let field name expected = tryProperty release name |> Option.exists (fun v -> v.ValueKind = JsonValueKind.String && v.GetString() = expected)
            match hash with
            | Some digest -> release.ValueKind = JsonValueKind.Object && release.EnumerateObject() |> Seq.length = 5
                             && field "owner" (ownerDigest ownerId) && field "version" Version && field "architecture" arch
                             && field "archiveSha256" archiveChecksums[arch] && field "binarySha256" digest
                             && binaryVersion environment paths.BinaryPath
            | None -> false
        with _ -> false

    let private ensureInstalledBinary (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) allowReplacement : bool =
        let arch = architecture ()
        checkDirectoryOwnership environment paths.InstallDir ownerId "installation directory" |> ignore
        let _, rootGid = hostOwner environment
        if assertDirectory environment paths.InstallDir "installation directory" then
            ensureDirectory environment paths.InstallDir 0o755 (Some rootGid)
            if assertDirectory environment (Path.GetDirectoryName(paths.BinaryPath)) "binary version directory" then
                ensureDirectory environment (Path.GetDirectoryName(paths.BinaryPath)) 0o755 (Some rootGid)
            let markerPath = Path.Combine(paths.InstallDir, ".keroosha-release.json")
            let matches = pinnedReleaseMatches environment paths ownerId arch (if assertRegular environment paths.BinaryPath "Traefik binary" then Some(binarySha256 environment paths.BinaryPath) else None)
            if matches then
                chmod environment paths.BinaryPath 0o755
                chown environment paths.BinaryPath (fst (hostOwner environment)) rootGid
                chmod environment markerPath 0o644
                chown environment markerPath (fst (hostOwner environment)) rootGid
                false
            elif allowReplacement then installBinary environment paths ownerId arch
            else fail "running service release changed during admission; refusing binary replacement"
        elif allowReplacement then installBinary environment paths ownerId arch
        else fail "running service installation disappeared"

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

    let private staticReceipt environment owner (bytes: byte[]) =
        showUnit environment [ "InvocationID" ]
        |> Option.bind (Map.tryFind "InvocationID")
        |> Option.filter (fun id -> id.Length = 32 && Seq.forall Uri.IsHexDigit id && id <> String('0', 32))
        |> Option.map (fun id -> Encoding.UTF8.GetBytes(String.concat "\n" [ owner; id; Convert.ToHexString(SHA256.HashData bytes) ]))

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
    // StartUnit returns the manager's job path, unlike a later PID/InvocationID
    // lookup which cannot distinguish our start from an independent restart.
    let private enqueueServiceJob environment restart =
        let methodName = if restart then "RestartUnit" else "StartUnit"
        let reply = run environment "busctl" [ "--system"; "--timeout=10s"; "call"; "org.freedesktop.systemd1"; "/org/freedesktop/systemd1"; "org.freedesktop.systemd1.Manager"; methodName; "ss"; ServiceName; "fail" ]
        let parsed = Regex.Match(reply.Stdout.Trim(), "^o \"/org/freedesktop/systemd1/job/([1-9][0-9]{0,9})\"$")
        if reply.ExitCode <> 0 || not parsed.Success then fail "cannot identify the systemd rollback start job"
        parsed.Groups[1].Value

    let private managedJobInvocation environment job =
        let reply = run environment "journalctl" [ "--boot"; "--no-pager"; "--output=json"; "--lines=1"; "_PID=1"; "UNIT=" + ServiceName; "MESSAGE_ID=39f53479d3a045ac8e11786248231fbf"; "JOB_TYPE=start"; "JOB_RESULT=done"; "JOB_ID=" + job ]
        if reply.ExitCode <> 0 then None
        else
            try
                use record = JsonDocument.Parse(reply.Stdout.Trim())
                let mutable property = Unchecked.defaultof<JsonElement>
                let id = if record.RootElement.TryGetProperty("INVOCATION_ID", &property) && property.ValueKind = JsonValueKind.String then property.GetString() else ""
                let completedStart = record.RootElement.TryGetProperty("JOB_TYPE", &property) && property.GetString() = "start"
                if completedStart && id.Length = 32 && Seq.forall Uri.IsHexDigit id && (showUnit environment [ "InvocationID" ] |> Option.bind (Map.tryFind "InvocationID")) = Some id then Some id else None
            with :? JsonException -> None

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
            let requiredEku =
                match certificate.Usage with
                | "server" -> "1.3.6.1.5.5.7.3.1"
                | "client" -> "1.3.6.1.5.5.7.3.2"
                | _ -> fail "certificate usage is invalid"
            let ekuExtensions =
                cert.Extensions
                |> Seq.cast<X509Extension>
                |> Seq.filter (fun extension ->
                    not (isNull extension.Oid)
                    && String.Equals(extension.Oid.Value, "2.5.29.37", StringComparison.Ordinal))
                |> Seq.toArray
            if ekuExtensions.Length <> 1 then fail "certificate extended key usage is invalid"
            let eku = X509EnhancedKeyUsageExtension(ekuExtensions[0], ekuExtensions[0].Critical)
            if not (eku.EnhancedKeyUsages |> Seq.cast<Oid> |> Seq.exists (fun oid -> String.Equals(oid.Value, requiredEku, StringComparison.Ordinal))) then
                fail "certificate extended key usage does not match its declared use"
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

    let private apiHttpClient =
        let handler = new SocketsHttpHandler()
        handler.UseProxy <- false
        handler.AllowAutoRedirect <- false
        new HttpClient(handler, true)

    [<Literal>]
    let private ApiEntryPointPageSize = 100
    [<Literal>]
    let private ApiMaximumEntryPoints = TraefikStatic.MaximumObservedEntryPoints

    let private readApiEndpointResponse
        (adminPort: int)
        (resource: string)
        (expectedKind: JsonValueKind)
        (cancellationToken: CancellationToken)
        : Task<(JsonElement * int option * int) option> =
        task {
            try
                use request =
                    new HttpRequestMessage(
                        HttpMethod.Get,
                        "http://127.0.0.1:" + adminPort.ToString(CultureInfo.InvariantCulture) + "/api/" + resource
                    )
                request.Headers.Accept.ParseAdd("application/json")
                use! response =
                    apiHttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                        .ConfigureAwait(false)
                if response.StatusCode <> HttpStatusCode.OK then return None
                elif response.Content.Headers.ContentLength.HasValue
                     && response.Content.Headers.ContentLength.Value > int64 ApiMaximumBytes then
                    return None
                else
                    let mutable nextPageValues = Unchecked.defaultof<System.Collections.Generic.IEnumerable<string>>
                    let nextPage =
                        if response.Headers.TryGetValues("X-Next-Page", &nextPageValues) then
                            match Seq.toArray nextPageValues with
                            | [| value |] ->
                                let mutable page = 0
                                if Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, &page)
                                   && page > 0 then
                                    Some page
                                else
                                    None
                            | _ -> None
                        else
                            None
                    use! stream = response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false)
                    use output = new MemoryStream()
                    let buffer = Array.zeroCreate<byte> 16384
                    let mutable count = 0
                    let mutable finished = false
                    while not finished && count <= ApiMaximumBytes do
                        let! read = stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)
                        if read = 0 then finished <- true
                        else
                            output.Write(buffer, 0, read)
                            count <- count + read
                    if count > ApiMaximumBytes then return None
                    else
                        use document = JsonDocument.Parse(output.GetBuffer().AsMemory(0, count))
                        if document.RootElement.ValueKind = expectedKind then
                            return Some(document.RootElement.Clone(), nextPage, count)
                        else
                            return None
            with _ ->
                return None
        }

    let private readApiEndpoint
        (adminPort: int)
        (resource: string)
        (expectedKind: JsonValueKind)
        (cancellationToken: CancellationToken)
        : Task<JsonElement option> =
        task {
            let! response = readApiEndpointResponse adminPort resource expectedKind cancellationToken
            return response |> Option.map (fun (value, _, _) -> value)
        }

    let internal readApiEntryPoints (adminPort: int) (cancellationToken: CancellationToken) : Task<JsonElement option> =
        task {
            let maximumPages = (ApiMaximumEntryPoints + ApiEntryPointPageSize - 1) / ApiEntryPointPageSize
            let pages = ResizeArray<JsonElement>()
            let mutable page = 1
            let mutable itemCount = 0
            let mutable totalBytes = 0
            let mutable finished = false
            let mutable valid = true
            while valid && not finished do
                if page > maximumPages then
                    valid <- false
                else
                    let requestedPage = page
                    let resource =
                        "entrypoints?per_page="
                        + ApiEntryPointPageSize.ToString(CultureInfo.InvariantCulture)
                        + "&page="
                        + requestedPage.ToString(CultureInfo.InvariantCulture)
                    let! response =
                        readApiEndpointResponse adminPort resource JsonValueKind.Array cancellationToken
                    match response with
                    | Some(items, Some nextPage, bytes) when items.ValueKind = JsonValueKind.Array ->
                        let count = items.GetArrayLength()
                        if count > ApiMaximumEntryPoints - itemCount || bytes > ApiMaximumBytes - totalBytes then
                            valid <- false
                        else
                            pages.Add(items)
                            itemCount <- itemCount + count
                            totalBytes <- totalBytes + bytes
                            if nextPage = 1 then
                                finished <- true
                            elif nextPage = requestedPage + 1 && nextPage <= maximumPages then
                                page <- nextPage
                            else
                                valid <- false
                    | _ -> valid <- false

            if not valid then
                return None
            else
                use output = new MemoryStream()
                use writer = new Utf8JsonWriter(output)
                writer.WriteStartArray()
                for items in pages do
                    for item in items.EnumerateArray() do item.WriteTo(writer)
                writer.WriteEndArray()
                writer.Flush()
                if output.Length > int64 ApiMaximumBytes then
                    return None
                else
                    use document = JsonDocument.Parse(output.GetBuffer().AsMemory(0, int output.Length))
                    return Some(document.RootElement.Clone())
        }

    let private readApi (adminPort: int) : Task<ApiConfiguration option> =
        task {
            use deadline = new CancellationTokenSource(ConnectTimeoutMilliseconds)
            let! responses =
                Task.WhenAll(
                    [| readApiEndpoint adminPort "rawdata" JsonValueKind.Object deadline.Token
                       readApiEntryPoints adminPort deadline.Token
                       readApiEndpoint adminPort "version" JsonValueKind.Object deadline.Token |]
                ).ConfigureAwait(false)
            match responses with
            | [| Some rawData; Some entryPoints; Some version |] ->
                return Some {
                    RawData = rawData
                    EntryPoints = entryPoints
                    Version = version
                    AdminPort = adminPort
                }
            | _ -> return None
        }
    let private readApiStatic (adminPort: int) : Task<ApiConfiguration option> =
        task {
            use deadline = new CancellationTokenSource(ConnectTimeoutMilliseconds)
            let! responses =
                Task.WhenAll(
                    [| readApiEntryPoints adminPort deadline.Token
                       readApiEndpoint adminPort "version" JsonValueKind.Object deadline.Token |]
                ).ConfigureAwait(false)
            match responses with
            | [| Some entryPoints; Some version |] ->
                use emptyRawData = JsonDocument.Parse("{}")
                return Some {
                    RawData = emptyRawData.RootElement.Clone()
                    EntryPoints = entryPoints
                    Version = version
                    AdminPort = adminPort
                }
            | _ -> return None
        }

    let private tryString (element: JsonElement) (name: string) : string =
        match tryProperty element name with
        | Some value when value.ValueKind = JsonValueKind.String -> value.GetString()
        | _ -> null

    let private jsonArrayStrings (element: JsonElement) : string[] option =
        if element.ValueKind <> JsonValueKind.Array then None
        else
            let values =
                element.EnumerateArray()
                |> Seq.map (fun value -> if value.ValueKind = JsonValueKind.String then value.GetString() else null)
                |> Seq.toArray
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

    let private namedResources (element: JsonElement) : Map<string, JsonElement> option =
        let values = Dictionary<string, JsonElement>(StringComparer.Ordinal)
        let mutable valid = true
        let add name (value: JsonElement) =
            if String.IsNullOrEmpty(name)
               || value.ValueKind <> JsonValueKind.Object
               || not (values.TryAdd(name, value)) then
                valid <- false
        match element.ValueKind with
        | JsonValueKind.Object ->
            for property in element.EnumerateObject() do add property.Name property.Value
        | JsonValueKind.Array ->
            for item in element.EnumerateArray() do add (tryString item "name") item
        | _ -> valid <- false
        if not valid then None
        else Some(values |> Seq.map (fun pair -> pair.Key, pair.Value) |> Map.ofSeq)

    let private fileResources (resources: Map<string, JsonElement>) : Map<string, JsonElement> option =
        let suffix = "@file"
        let values = ResizeArray<string * JsonElement>()
        let mutable valid = true
        for KeyValue(name, item) in resources do
            if name.EndsWith(suffix, StringComparison.Ordinal) then
                let unqualified = name.Substring(0, name.Length - suffix.Length)
                if String.IsNullOrEmpty(unqualified) || not (providerIsFile item) then
                    valid <- false
                else
                    values.Add((unqualified, item))
        if not valid then None
        else
            let result = values |> Seq.map id |> Map.ofSeq
            if result.Count <> values.Count then None else Some result

    let private expectedSectionResources
        (root: JsonElement)
        (sectionName: string)
        (allowedFields: Set<string>)
        (resourceName: string)
        : Map<string, JsonElement> option =
        match tryProperty root sectionName with
        | None -> Some Map.empty
        | Some section when section.ValueKind = JsonValueKind.Object
                            && Set.isEmpty (Set.difference (objectNames section) allowedFields) ->
            match tryProperty section resourceName with
            | None -> Some Map.empty
            | Some resources when resources.ValueKind = JsonValueKind.Object -> namedResources resources
            | _ -> None
        | _ -> None

    let private actualApiResources (api: ApiConfiguration) (resourceName: string) : Map<string, JsonElement> option =
        match tryProperty api.RawData resourceName with
        | None -> Some Map.empty
        | Some resources -> namedResources resources

    type private HttpEntryPointModel =
        { Middlewares: string array
          Tls: JsonElement option
          Observability: JsonElement option
          AsDefault: bool
          Applies: bool }
    type private RouterProtocol =
        | HttpProtocol
        | TcpProtocol
        | UdpProtocol

    let private httpRouterFields =
        set [ "entryPoints"; "middlewares"; "service"; "rule"; "ruleSyntax"; "priority"; "tls"; "observability"; "parentRefs" ]

    let private tcpRouterFields =
        set [ "entryPoints"; "middlewares"; "service"; "rule"; "ruleSyntax"; "priority"; "tls" ]

    let private udpRouterFields =
        set [ "entryPoints"; "service" ]

    let private udpRouterFieldsComparedSeparately =
        set [ "entryPoints"; "service" ]
    let private defaultTrueBooleanFields =
        set [ "followRedirects"; "mirrorBody"; "passHostHeader" ]

    let private routerFieldsComparedSeparately =
        set [ "service"; "middlewares"; "parentRefs"; "tls"; "priority"; "entryPoints" ]

    let private routerApiMetadataFields =
        set [ "name"; "provider"; "status"; "using" ]

    let private serviceApiMetadataFields =
        set [ "name"; "provider"; "serverStatus"; "status"; "type"; "usedBy" ]

    let private referenceMatches (expected: JsonElement) (actual: JsonElement) : bool =
        match expected.ValueKind, actual.ValueKind with
        | JsonValueKind.String, JsonValueKind.String ->
            let wanted = expected.GetString()
            let found = actual.GetString()
            found = wanted || found = wanted + "@file"
        | _ -> false

    let private referenceArraysMatch (expected: JsonElement option) (actual: JsonElement option) : bool =
        let readValues (values: JsonElement option) =
            match values with
            | None -> Some [||]
            | Some (value: JsonElement) when value.ValueKind = JsonValueKind.Null -> Some [||]
            | Some (value: JsonElement) -> jsonArrayStrings value
        match readValues expected, readValues actual with
        | Some wanted, Some found when wanted.Length = found.Length ->
            Array.forall2
                (fun expectedName actualName ->
                    actualName = expectedName || actualName = expectedName + "@file")
                wanted
                found
        | _ -> false

    let private parentRefsMatch (expected: JsonElement option) (actual: JsonElement option) : bool =
        let normalize (values: JsonElement option) =
            match values with
            | None -> Some [||]
            | Some value when value.ValueKind = JsonValueKind.Null -> Some [||]
            | Some value ->
                jsonArrayStrings value
                |> Option.bind (fun names ->
                    let normalized = names |> Array.map (withoutProviderSuffix "file")
                    if normalized |> Array.exists String.IsNullOrEmpty then None
                    else Some(Array.sort normalized))
        match normalize expected, normalize actual with
        | Some wanted, Some found -> wanted = found
        | _ -> false

    let private literalMapPath (path: string list) =
        match path with
        | "customRequestHeaders" :: "headers" :: _
        | "customResponseHeaders" :: "headers" :: _
        | "headers" :: "healthCheck" :: "loadBalancer" :: _ -> true
        | _ -> false

    let private durationFieldNames =
        set [
            "dialKeepAlive"; "dialTimeout"; "failureWindow"; "flushInterval"; "graceTimeOut"
            "idleConnTimeout"; "idleTimeout"; "interval"; "keepAliveMaxTime"; "readTimeout"
            "requestAcceptGraceTimeout"; "responseHeaderTimeout"; "terminationDelay"; "timeout"
            "unhealthyInterval"; "writeTimeout"
        ]

    let private durationFieldAt path name =
        Set.contains name durationFieldNames && not (literalMapPath path)

    let private tryDurationNanoseconds (value: string) : decimal option =
        if String.IsNullOrEmpty(value) then None
        elif value = "0" then Some 0M
        else
            let mutable index = 0
            let mutable sign = 1M
            if value[index] = '-' then
                sign <- -1M
                index <- index + 1
            elif value[index] = '+' then
                index <- index + 1
            let mutable total = 0M
            let mutable valid = index < value.Length
            while valid && index < value.Length do
                let numberStart = index
                let mutable sawDigit = false
                let mutable sawDecimal = false
                while index < value.Length
                      && ((value[index] >= '0' && value[index] <= '9')
                          || (value[index] = '.' && not sawDecimal)) do
                    if value[index] = '.' then sawDecimal <- true
                    else sawDigit <- true
                    index <- index + 1
                if not sawDigit || index = value.Length then
                    valid <- false
                else
                    let numberSpan = value.AsSpan(numberStart, index - numberStart)
                    let mutable number = 0M
                    if not (Decimal.TryParse(numberSpan, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, &number)) then
                        valid <- false
                    else
                        let unit, scale =
                            if value.AsSpan(index).StartsWith("ns".AsSpan(), StringComparison.Ordinal) then "ns", 1M
                            elif value.AsSpan(index).StartsWith("us".AsSpan(), StringComparison.Ordinal) then "us", 1000M
                            elif value.AsSpan(index).StartsWith("µs".AsSpan(), StringComparison.Ordinal) then "µs", 1000M
                            elif value.AsSpan(index).StartsWith("ms".AsSpan(), StringComparison.Ordinal) then "ms", 1000000M
                            elif value.AsSpan(index).StartsWith("s".AsSpan(), StringComparison.Ordinal) then "s", 1000000000M
                            elif value.AsSpan(index).StartsWith("m".AsSpan(), StringComparison.Ordinal) then "m", 60000000000M
                            elif value.AsSpan(index).StartsWith("h".AsSpan(), StringComparison.Ordinal) then "h", 3600000000000M
                            else "", 0M
                        if String.IsNullOrEmpty(unit) then valid <- false
                        else
                            total <- total + number * scale
                            index <- index + unit.Length
            if valid then Some(sign * Decimal.Truncate(total)) else None

    let private jsonStringIs (expected: string) (actual: JsonElement) =
        actual.ValueKind = JsonValueKind.String && actual.GetString() = expected

    let private defaultHttpResponseForwarding (value: JsonElement) =
        value.ValueKind = JsonValueKind.Object
        && objectNames value = set [ "flushInterval" ]
        && (tryProperty value "flushInterval"
            |> Option.bind (fun interval ->
                tryDurationNanoseconds (if interval.ValueKind = JsonValueKind.String then interval.GetString() else null)))
           = Some 100000000M

    let private defaultValueForMissingExpected (path: string list) (name: string) (actual: JsonElement) =
        let isInteger expected =
            let mutable found = 0L
            actual.ValueKind = JsonValueKind.Number && actual.TryGetInt64(&found) && found = expected
        match path, name with
        | "loadBalancer" :: _, "strategy" -> jsonStringIs "wrr" actual
        | "loadBalancer" :: _, "passHostHeader" -> actual.ValueKind = JsonValueKind.True
        | "loadBalancer" :: _, "responseForwarding" -> defaultHttpResponseForwarding actual
        | "responseForwarding" :: "loadBalancer" :: _, "flushInterval" ->
            tryDurationNanoseconds (if actual.ValueKind = JsonValueKind.String then actual.GetString() else null) = Some 100000000M
        | "healthCheck" :: "loadBalancer" :: _, "mode" -> jsonStringIs "http" actual
        | "healthCheck" :: "loadBalancer" :: _, "interval" ->
            tryDurationNanoseconds (if actual.ValueKind = JsonValueKind.String then actual.GetString() else null) = Some 30000000000M
        | "healthCheck" :: "loadBalancer" :: _, "timeout" ->
            tryDurationNanoseconds (if actual.ValueKind = JsonValueKind.String then actual.GetString() else null) = Some 5000000000M
        | "healthCheck" :: "loadBalancer" :: _, "followRedirects" -> actual.ValueKind = JsonValueKind.True
        | "cookie" :: "sticky" :: ("loadBalancer" | "weighted") :: _, "path" -> jsonStringIs "/" actual
        | "passiveHealthCheck" :: "loadBalancer" :: _, "failureWindow" ->
            tryDurationNanoseconds (if actual.ValueKind = JsonValueKind.String then actual.GetString() else null) = Some 10000000000M
        | "passiveHealthCheck" :: "loadBalancer" :: _, "maxFailedAttempts" -> isInteger 1L
        | "mirroring" :: _, "mirrorBody" -> actual.ValueKind = JsonValueKind.True
        | "mirroring" :: _, "maxBodySize" -> isInteger -1L
        | "errors" :: "failover" :: _, "maxRequestBodyBytes" -> isInteger -1L
        | "observability" :: _, _ -> false
        | _, _ when actual.ValueKind = JsonValueKind.False ->
            not (Set.contains name defaultTrueBooleanFields)
        | _ -> false

    let rec private jsonConfigMatches (path: string list) (expected: JsonElement) (actual: JsonElement) : bool =
        match expected.ValueKind, actual.ValueKind with
        | JsonValueKind.Object, JsonValueKind.Object ->
            let wantedNames = objectNames expected
            let mapKeysMatch =
                not (literalMapPath path) || wantedNames = objectNames actual
            let expectedPropertiesMatch =
                expected.EnumerateObject()
                |> Seq.forall (fun property ->
                    let propertyPath = property.Name :: path
                    match property.Name, tryProperty actual property.Name with
                    | "middlewares", found when path = [] || path = [ "chain" ] ->
                        referenceArraysMatch (Some property.Value) found
                    | "parentRefs", found when path = [] ->
                        parentRefsMatch (Some property.Value) found
                    | ("service" | "serversTransport"), Some found
                        when (property.Name = "service" && (path = [ "mirroring" ] || path = [ "failover" ]))
                             || (property.Name = "serversTransport" && path = [ "loadBalancer" ]) ->
                        referenceMatches property.Value found
                    | "fallback", Some found when path = [ "failover" ] ->
                        referenceMatches property.Value found
                    | "name", Some found
                        when path = [ "[]"; "services"; "weighted" ]
                             || path = [ "[]"; "mirrors"; "mirroring" ] ->
                        referenceMatches property.Value found
                    | _, Some found when durationFieldAt path property.Name
                                          && property.Value.ValueKind = JsonValueKind.String
                                          && found.ValueKind = JsonValueKind.String ->
                        match tryDurationNanoseconds (property.Value.GetString()), tryDurationNanoseconds (found.GetString()) with
                        | Some wanted, Some found -> wanted = found
                        | _ -> false
                    | _, Some found -> jsonConfigMatches propertyPath property.Value found
                    // Do not treat an arbitrary absent field as a native zero
                    // value: Traefik may have rejected this entire file.
                    | ("secure" | "httpOnly"), None when property.Value.ValueKind = JsonValueKind.False
                                                         && (path = [ "cookie"; "sticky"; "loadBalancer" ] || path = [ "cookie"; "sticky"; "weighted" ]) -> true
                    | _ -> false)
            let unexpectedPropertiesMatch =
                actual.EnumerateObject()
                |> Seq.forall (fun property ->
                    if Set.contains property.Name wantedNames then true
                    elif path = []
                         && Set.contains property.Name serviceApiMetadataFields then
                        true
                    elif path = [] && property.Name = "error"
                         && (tryString actual "status" = "disabled" || tryString actual "status" = "warning")
                         && property.Value.ValueKind = JsonValueKind.Array then
                        property.Value.EnumerateArray() |> Seq.forall (fun message -> message.ValueKind = JsonValueKind.String)
                    else
                        defaultValueForMissingExpected path property.Name property.Value)
            mapKeysMatch && expectedPropertiesMatch && unexpectedPropertiesMatch
        | JsonValueKind.Array, JsonValueKind.Array ->
            let wanted = expected.EnumerateArray() |> Seq.toArray
            let found = actual.EnumerateArray() |> Seq.toArray
            if wanted.Length <> found.Length then false
            else
                Array.map2 (fun left right -> jsonConfigMatches ("[]" :: path) left right) wanted found
                |> Array.forall id
        | JsonValueKind.String, JsonValueKind.String ->
            match path with
            | "name" :: "[]" :: "services" :: "weighted" :: _
            | "name" :: "[]" :: "mirrors" :: "mirroring" :: _ -> referenceMatches expected actual
            | name :: parentPath when durationFieldAt parentPath name ->
                match tryDurationNanoseconds (expected.GetString()), tryDurationNanoseconds (actual.GetString()) with
                | Some wanted, Some found -> wanted = found
                | _ -> false
            | _ -> expected.GetString() = actual.GetString()
        | JsonValueKind.Number, JsonValueKind.Number ->
            let mutable wanted = 0M
            let mutable found = 0M
            expected.TryGetDecimal(&wanted) && actual.TryGetDecimal(&found) && wanted = found
        | JsonValueKind.True, JsonValueKind.True
        | JsonValueKind.False, JsonValueKind.False
        | JsonValueKind.Null, JsonValueKind.Null -> true
        | _ -> false

    let private tlsRouterMatches (expected: JsonElement option) (actual: JsonElement option) : bool =
        match expected, actual with
        | None, None -> true
        | None, Some value when value.ValueKind = JsonValueKind.Null -> true
        | None, Some value when value.ValueKind = JsonValueKind.Object -> Seq.isEmpty (value.EnumerateObject())
        | None, _ -> false
        | Some _, None -> false
        | Some wanted, Some found when wanted.ValueKind = JsonValueKind.Object && found.ValueKind = JsonValueKind.Object ->
            let resolverMatches =
                match tryProperty wanted "certResolver", tryProperty found "certResolver" with
                | None, None -> true
                | None, Some value when value.ValueKind = JsonValueKind.Null -> true
                | None, Some value when value.ValueKind = JsonValueKind.String -> String.IsNullOrEmpty(value.GetString())
                | Some expectedResolver, Some actualResolver -> jsonConfigMatches [ "certResolver" ] expectedResolver actualResolver
                | _ -> false
            let optionsMatches =
                match tryProperty wanted "options", tryProperty found "options" with
                | None, None -> true
                | None, Some value -> jsonStringIs "default" value
                | Some expectedOptions, None -> jsonStringIs "default" expectedOptions
                | Some expectedOptions, Some actualOptions ->
                    if jsonStringIs "default" expectedOptions then jsonStringIs "default" actualOptions
                    else referenceMatches expectedOptions actualOptions
            let expectedNames = objectNames wanted
            let otherPropertiesMatch =
                wanted.EnumerateObject()
                |> Seq.filter (fun property -> property.Name <> "certResolver" && property.Name <> "options")
                |> Seq.forall (fun property ->
                    match tryProperty found property.Name with
                    | Some value -> jsonConfigMatches [ property.Name ] property.Value value
                    | None ->
                        property.Value.ValueKind = JsonValueKind.False
                        && property.Name = "passthrough")
            let unexpectedPropertiesMatch =
                found.EnumerateObject()
                |> Seq.forall (fun property ->
                    Set.contains property.Name expectedNames
                    || (property.Name = "options" && jsonStringIs "default" property.Value)
                    || (property.Value.ValueKind = JsonValueKind.False
                        && not (Set.contains property.Name defaultTrueBooleanFields)))
            resolverMatches && optionsMatches && otherPropertiesMatch && unexpectedPropertiesMatch
        | _ -> false

    let private skipRuleWhitespace (rule: string) (index: byref<int>) =
        while index < rule.Length && Char.IsWhiteSpace(rule[index]) do
            index <- index + 1

    let private isTcpCatchAllRule (rule: string) =
        let matcher = "HostSNI"
        let mutable index = 0
        skipRuleWhitespace rule &index
        let mutable matcherIndex = 0
        let mutable matches = true
        while matches && matcherIndex < matcher.Length do
            if index >= rule.Length
               || Char.ToUpperInvariant(rule[index]) <> Char.ToUpperInvariant(matcher[matcherIndex]) then
                matches <- false
            else
                index <- index + 1
                matcherIndex <- matcherIndex + 1
        skipRuleWhitespace rule &index
        if not matches || index >= rule.Length || rule[index] <> '(' then false
        else
            index <- index + 1
            skipRuleWhitespace rule &index
            if index >= rule.Length || (rule[index] <> '`' && rule[index] <> '"' && rule[index] <> char 39) then false
            else
                let quote = rule[index]
                index <- index + 1
                if index >= rule.Length || rule[index] <> '*' then false
                else
                    index <- index + 1
                    if index >= rule.Length || rule[index] <> quote then false
                    else
                        index <- index + 1
                        skipRuleWhitespace rule &index
                        if index >= rule.Length || rule[index] <> ')' then false
                        else
                            index <- index + 1
                            skipRuleWhitespace rule &index
                            index = rule.Length

    /// Mirrors the pinned effective priorities used when Traefik builds HTTP/TCP handlers.
    /// HTTP and TCP priority handling: https://github.com/traefik/traefik/blob/v3.7.16/pkg/server/router/router.go#L243-L250
    /// TCP HostSNI catchall priority: https://github.com/traefik/traefik/blob/v3.7.16/pkg/muxer/tcp/mux.go
    /// Effective-zero branches: https://github.com/traefik/traefik/blob/v3.7.16/pkg/server/router/tcp/manager.go#L217-L225
    let private effectiveRouterPriority (tcp: bool) (router: JsonElement) : int64 option =
        let rule = tryString router "rule"
        if String.IsNullOrEmpty(rule) then None
        else
            let computed =
                if tcp && isTcpCatchAllRule rule then -1L
                else int64 (Encoding.UTF8.GetByteCount(rule))
            match tryProperty router "priority" with
            | None -> Some computed
            | Some value when value.ValueKind = JsonValueKind.Null -> Some computed
            | Some value when value.ValueKind = JsonValueKind.Number ->
                let mutable explicitPriority = 0L
                if value.TryGetInt64(&explicitPriority) then
                    if explicitPriority = 0L then Some computed else Some explicitPriority
                else None
            | _ -> None

    let private entryPointsMatch (expected: JsonElement option) (actual: JsonElement option) =
        let read (values: JsonElement option) =
            match values with
            | None -> Some [||]
            | Some value when value.ValueKind = JsonValueKind.Null -> Some [||]
            | Some value -> jsonArrayStrings value |> Option.map Array.sort
        match read expected, read actual with
        | Some wanted, Some found -> wanted = found
        | _ -> false


    type private GraphPurpose = Activation | Attribution

    let private statusMatches purpose actual =
        match tryString actual "status", purpose with
        | "enabled", _ | ("disabled" | "warning"), Attribution -> true
        | _ -> false

    let private routerMatches purpose (protocol: RouterProtocol) (expected: JsonElement) (actual: JsonElement) : bool =
        let allowedFields, fieldsComparedSeparately =
            match protocol with
            | HttpProtocol -> httpRouterFields, routerFieldsComparedSeparately
            | TcpProtocol -> tcpRouterFields, routerFieldsComparedSeparately
            | UdpProtocol -> udpRouterFields, udpRouterFieldsComparedSeparately
        let expectedFieldsMatch =
            Set.isEmpty (Set.difference (objectNames expected) allowedFields)
        let expectedService = tryString expected "service"
        let actualService = tryString actual "service"
        let serviceMatches =
            if String.IsNullOrEmpty(expectedService) then String.IsNullOrEmpty(actualService)
            elif expectedService.EndsWith("@internal", StringComparison.Ordinal) then
                actualService = expectedService
                || actualService = expectedService.Substring(0, expectedService.Length - "@internal".Length)
            else
                actualService = expectedService
        let middlewareMatches =
            match protocol with
            | UdpProtocol ->
                Option.isNone (tryProperty expected "middlewares")
                && Option.isNone (tryProperty actual "middlewares")
            | _ ->
                referenceArraysMatch (tryProperty expected "middlewares") (tryProperty actual "middlewares")
        let parentMatches =
            match protocol with
            | HttpProtocol -> parentRefsMatch (tryProperty expected "parentRefs") (tryProperty actual "parentRefs")
            | _ -> Option.isNone (tryProperty expected "parentRefs") && Option.isNone (tryProperty actual "parentRefs")
        let tlsMatches =
            match protocol with
            | UdpProtocol -> Option.isNone (tryProperty expected "tls") && Option.isNone (tryProperty actual "tls")
            | _ -> tlsRouterMatches (tryProperty expected "tls") (tryProperty actual "tls")
        let priorityMatches =
            match protocol with
            | UdpProtocol ->
                Option.isNone (tryProperty expected "priority")
                && Option.isNone (tryProperty actual "priority")
            | HttpProtocol
            | TcpProtocol ->
                let expectedPriority = effectiveRouterPriority (protocol = TcpProtocol) expected
                let actualPriority = effectiveRouterPriority (protocol = TcpProtocol) actual
                expectedPriority.IsSome && expectedPriority = actualPriority
        let entryPointsMatches = entryPointsMatch (tryProperty expected "entryPoints") (tryProperty actual "entryPoints")
        let otherPropertiesMatch =
            expected.EnumerateObject()
            |> Seq.filter (fun property -> not (Set.contains property.Name fieldsComparedSeparately))
            |> Seq.forall (fun property ->
                tryProperty actual property.Name
                |> Option.exists (jsonConfigMatches [ property.Name ] property.Value))
        let unexpectedPropertiesMatch =
            let expectedNames = objectNames expected
            actual.EnumerateObject()
            |> Seq.forall (fun property ->
                if Set.contains property.Name expectedNames
                   || Set.contains property.Name routerApiMetadataFields then true
                elif purpose = Attribution && property.Name = "error" && property.Value.ValueKind = JsonValueKind.Array then true
                elif property.Name = "entryPoints" then true
                elif property.Name = "priority" && protocol <> UdpProtocol then true
                elif property.Name = "middlewares" && protocol <> UdpProtocol then middlewareMatches
                elif property.Name = "ruleSyntax" && protocol <> UdpProtocol then
                    jsonStringIs "v3" property.Value
                else false)
        statusMatches purpose actual
        && providerIsFile actual
        && expectedFieldsMatch
        && serviceMatches
        && middlewareMatches
        && parentMatches
        && tlsMatches
        && priorityMatches
        && entryPointsMatches
        && otherPropertiesMatch
        && unexpectedPropertiesMatch

    let private apiUsers (actual: JsonElement) : Map<string, int> option =
        match tryProperty actual "usedBy" with
        | None -> Some Map.empty
        | Some value ->
            match jsonArrayStrings value with
            | None -> None
            | Some names ->
                let normalized = names |> Array.map (withoutProviderSuffix "file")
                if normalized |> Array.exists String.IsNullOrEmpty then None
                else
                    normalized
                    |> Array.countBy id
                    |> Map.ofArray
                    |> Some

    let private serviceUsers
        (expectedRouters: Map<string, JsonElement>)
        (serviceName: string)
        : Map<string, int> =
        let mutable users = Map.empty
        for KeyValue(routerName, router) in expectedRouters do
            let service = tryString router "service"
            if not (String.IsNullOrEmpty(service))
               && withoutProviderSuffix "file" service = serviceName then
                users <- Map.change routerName (function None -> Some 1 | Some count -> Some(count + 1)) users
        users

    let private serviceMatches
        purpose
        (expectedRouters: Map<string, JsonElement>)
        (name: string)
        (expected: JsonElement)
        (actual: JsonElement)
        : bool =
        let expectedKind =
            expected.EnumerateObject()
            |> Seq.filter (fun property -> property.Name <> "middlewares")
            |> Seq.map (fun property -> property.Name.ToLowerInvariant())
            |> Seq.tryHead
        let actualType = tryString actual "type"
        let typeMatches =
            String.IsNullOrEmpty(actualType)
            || (expectedKind |> Option.exists (fun kind -> kind = actualType.ToLowerInvariant()))
        statusMatches purpose actual
        && providerIsFile actual
        && typeMatches
        && jsonConfigMatches [] expected actual
        && apiUsers actual = Some(serviceUsers expectedRouters name)
    let private defaultHttpLoadBalancerMatches (expected: JsonElement) (actual: JsonElement) : bool =
        match tryProperty expected "loadBalancer", tryProperty actual "loadBalancer" with
        | None, None -> true
        | None, Some actualBalancer when actualBalancer.ValueKind = JsonValueKind.Object ->
            let onlyDefaults =
                actualBalancer.EnumerateObject()
                |> Seq.forall (fun property ->
                    defaultValueForMissingExpected [ "loadBalancer" ] property.Name property.Value)
            onlyDefaults
        | None, _ -> false
        | Some _, None -> false
        | Some expectedBalancer, Some actualBalancer
            when expectedBalancer.ValueKind = JsonValueKind.Object && actualBalancer.ValueKind = JsonValueKind.Object ->
            let normalizedFieldMatches name defaultMatches =
                match tryProperty expectedBalancer name, tryProperty actualBalancer name with
                | None, None -> true
                | None, Some actualValue -> defaultMatches actualValue
                | Some expectedValue, Some actualValue -> jsonConfigMatches [ name ] expectedValue actualValue
                | _ -> false
            let strategyMatches =
                normalizedFieldMatches "strategy" (jsonStringIs "wrr")
            let passHostHeaderMatches =
                normalizedFieldMatches "passHostHeader" (fun value -> value.ValueKind = JsonValueKind.True)
            let responseForwardingMatches =
                normalizedFieldMatches "responseForwarding" defaultHttpResponseForwarding
            strategyMatches && passHostHeaderMatches && responseForwardingMatches
        | _ -> false

    let private httpServiceMatches
        purpose
        (expectedRouters: Map<string, JsonElement>)
        (name: string)
        (expected: JsonElement)
        (actual: JsonElement)
        : bool =
        serviceMatches purpose expectedRouters name expected actual
        && defaultHttpLoadBalancerMatches expected actual

    /// Mirrors the pinned PopulateUsedBy relationship index: router-level HTTP middleware occurrences only.
    /// It does not add chain-child, service-level, or TCP-router middleware users.
    /// https://github.com/traefik/traefik/blob/v3.7.16/pkg/config/runtime/runtime.go#L128-L194
    let private middlewareUsers
        (expectedRouters: Map<string, JsonElement>)
        (middlewareName: string)
        : Map<string, int> =
        let mutable users = Map.empty
        for KeyValue(routerName, router) in expectedRouters do
            match tryProperty router "middlewares" |> Option.bind jsonArrayStrings with
            | Some names ->
                for name in names do
                    let normalized = withoutProviderSuffix "file" name
                    if normalized = middlewareName then
                        users <- Map.change routerName (function None -> Some 1 | Some count -> Some(count + 1)) users
            | None -> ()
        users



    let private middlewareMatches
        purpose
        (countRouterUsers: bool)
        (expectedRouters: Map<string, JsonElement>)
        (name: string)
        (expected: JsonElement)
        (actual: JsonElement)
        : bool =
        let expectedConfigurations = expected.EnumerateObject() |> Seq.toArray
        let configMatches =
            expectedConfigurations.Length = 1
            && (expectedConfigurations
                |> Array.forall (fun property ->
                    tryProperty actual property.Name
                    |> Option.exists (jsonConfigMatches [ property.Name ] property.Value)))
        let expectedUsers = if countRouterUsers then middlewareUsers expectedRouters name else Map.empty
        let actualType = tryString actual "type"
        let typeMatches =
            String.IsNullOrEmpty(actualType)
            || (expectedConfigurations.Length = 1
                && actualType.Equals(expectedConfigurations[0].Name, StringComparison.OrdinalIgnoreCase))
        statusMatches purpose actual
        && providerIsFile actual
        && configMatches
        && typeMatches
        && apiUsers actual = Some expectedUsers

    let private resourcesMatch
        (expected: Map<string, JsonElement>)
        (actual: Map<string, JsonElement> option)
        (matches: string -> JsonElement -> JsonElement -> bool)
        : bool =
        match actual |> Option.bind fileResources with
        | Some fileValues when fileValues.Count = expected.Count ->
            expected
            |> Map.forall (fun name wanted ->
                match Map.tryFind name fileValues with
                | Some found -> matches name wanted found
                | None -> false)
        | _ -> false

    let private readEntryPointModel (config: JsonElement) : HttpEntryPointModel option =
        if config.ValueKind <> JsonValueKind.Object then None
        else
            let asDefault =
                match tryProperty config "asDefault" with
                | None -> Some false
                | Some value when value.ValueKind = JsonValueKind.True -> Some true
                | Some value when value.ValueKind = JsonValueKind.False -> Some false
                | _ -> None
            let http =
                match tryProperty config "http" with
                | None -> Some None
                | Some value when value.ValueKind = JsonValueKind.Null -> Some None
                | Some value when value.ValueKind = JsonValueKind.Object -> Some(Some value)
                | _ -> None
            let observability =
                match tryProperty config "observability" with
                | None -> Some None
                | Some value when value.ValueKind = JsonValueKind.Null -> Some None
                | Some value when value.ValueKind = JsonValueKind.Object -> Some(Some value)
                | _ -> None
            match asDefault, http, observability with
            | Some asDefaultValue, Some httpValue, Some observabilityValue ->
                let middlewares =
                    match httpValue |> Option.bind (fun value -> tryProperty value "middlewares") with
                    | None -> Some [||]
                    | Some value when value.ValueKind = JsonValueKind.Null -> Some [||]
                    | Some value -> jsonArrayStrings value
                let tls =
                    match httpValue |> Option.bind (fun value -> tryProperty value "tls") with
                    | None -> Some None
                    | Some value when value.ValueKind = JsonValueKind.Null -> Some None
                    | Some value when value.ValueKind = JsonValueKind.Object -> Some(Some value)
                    | _ -> None
                match middlewares, tls with
                | Some middlewareNames, Some tlsValue ->
                    Some {
                        Middlewares = middlewareNames
                        Tls = tlsValue
                        Observability = observabilityValue
                        AsDefault = asDefaultValue
                        Applies = middlewareNames.Length > 0 || tlsValue.IsSome || observabilityValue.IsSome
                    }
                | _ -> None
            | _ -> None

    let private entryPointModelsFromStatic (root: JsonElement) : Map<string, HttpEntryPointModel> option =
        match tryProperty root "entryPoints" with
        | Some values when values.ValueKind = JsonValueKind.Object ->
            let entries = ResizeArray<string * HttpEntryPointModel>()
            let mutable valid = true
            for property in values.EnumerateObject() do
                match readEntryPointModel property.Value with
                | Some model -> entries.Add(property.Name, model)
                | None -> valid <- false
            if valid then Some(Map.ofSeq entries) else None
        | _ -> None

    let private entryPointModelsFromApi (element: JsonElement) : Map<string, HttpEntryPointModel> option =
        if element.ValueKind <> JsonValueKind.Array then None
        else
            let entries = ResizeArray<string * HttpEntryPointModel>()
            let names = HashSet<string>(StringComparer.Ordinal)
            let mutable valid = true
            for item in element.EnumerateArray() do
                let name = tryString item "name"
                match readEntryPointModel item with
                | Some model when not (String.IsNullOrEmpty(name)) && names.Add(name) ->
                    entries.Add(name, model)
                | _ -> valid <- false
            if valid then Some(Map.ofSeq entries) else None

    let private defaultEntryPoints (models: Map<string, HttpEntryPointModel>) =
        let selected =
            models
            |> Map.toSeq
            |> Seq.choose (fun (name, model) -> if model.AsDefault then Some name else None)
            |> Seq.toArray
        if selected.Length > 0 then Array.sort selected
        else models |> Map.toSeq |> Seq.map fst |> Seq.toArray

    let private jsonNodeStringArray (values: string array) =
        let result = JsonArray()
        for value in values do result.Add(JsonValue.Create(value))
        result

    let private setRootObservability
        (router: JsonElement)
        (model: HttpEntryPointModel option)
        (projected: JsonObject)
        =
        let routerValues =
            match tryProperty router "observability" with
            | Some value when value.ValueKind = JsonValueKind.Object -> Some value
            | _ -> None
        let modelValues = model |> Option.bind (fun value -> value.Observability)
        let isUnset name (value: JsonElement) =
            value.ValueKind = JsonValueKind.Null
            || (name = "traceVerbosity"
                && value.ValueKind = JsonValueKind.String
                && String.IsNullOrEmpty(value.GetString()))
        let effectiveValue name =
            match routerValues |> Option.bind (fun value -> tryProperty value name) with
            | Some value when not (isUnset name value) -> Some value
            | _ ->
                modelValues
                |> Option.bind (fun value -> tryProperty value name)
                |> Option.filter (isUnset name >> not)
        let valueNode (name: string) (fallback: JsonNode) : JsonNode =
            match effectiveValue name with
            | Some value -> JsonNode.Parse(value.GetRawText())
            | None -> fallback
        let observability = JsonObject()
        observability["accessLogs"] <- valueNode "accessLogs" (JsonValue.Create(true) :> JsonNode)
        observability["metrics"] <- valueNode "metrics" (JsonValue.Create(true) :> JsonNode)
        observability["tracing"] <- valueNode "tracing" (JsonValue.Create(true) :> JsonNode)
        observability["traceVerbosity"] <- valueNode "traceVerbosity" (JsonValue.Create("minimal") :> JsonNode)
        projected["observability"] <- observability

    /// Mirrors 3.7.16 applyModel/mergeConfiguration: entrypoint defaults, inherited middleware/TLS/observability,
    /// multi-entrypoint router copies, and child parentRefs are projected before rawdata comparison.
    /// Upstream: https://github.com/traefik/traefik/blob/v3.7.16/pkg/server/aggregator.go#L20-L82
    /// and https://github.com/traefik/traefik/blob/v3.7.16/pkg/server/aggregator.go#L348-L400
    let private projectExpectedDynamic (models: Map<string, HttpEntryPointModel>) (root: JsonElement) : JsonDocument option =
        try
            let rootNode = JsonNode.Parse(root.GetRawText()) :?> JsonObject
            match rootNode["http"] with
            | :? JsonObject as http when (match http["routers"] with | :? JsonObject -> true | _ -> false) ->
                let routers = http["routers"] :?> JsonObject
                let sourceRoutes =
                    root.GetProperty("http").GetProperty("routers").EnumerateObject()
                    |> Seq.map (fun property -> property.Name, property.Value)
                    |> Seq.toArray
                let output = JsonObject()
                let splitNames = Dictionary<string, string[]>(StringComparer.Ordinal)
                let anyModels = models |> Map.exists (fun _ model -> model.Applies)
                let defaults = defaultEntryPoints models
                let mutable valid = true
                let addProjected name (router: JsonObject) =
                    if output.ContainsKey(name) then valid <- false
                    else output[name] <- router
                let readNames (router: JsonElement) propertyName =
                    match tryProperty router propertyName with
                    | None -> Some [||]
                    | Some value when value.ValueKind = JsonValueKind.Null -> Some [||]
                    | Some value -> jsonArrayStrings value
                let copyRoute (name: string) = routers[name].DeepClone() :?> JsonObject
                let isRootRouter (router: JsonElement) =
                    match tryProperty router "parentRefs" with
                    | None -> true
                    | Some value when value.ValueKind = JsonValueKind.Null -> true
                    | _ -> false
                for name, router in sourceRoutes do
                    if isRootRouter router then
                        match readNames router "entryPoints", readNames router "middlewares" with
                        | Some configuredEntryPoints, Some configuredMiddlewares ->
                            let entryPoints =
                                if configuredEntryPoints.Length = 0 then defaults
                                else configuredEntryPoints
                            if anyModels then
                                let unmodelled = ResizeArray<string>()
                                let projectedNames = ResizeArray<string>()
                                for entryPoint in entryPoints do
                                    match Map.tryFind entryPoint models with
                                    | Some model when model.Applies ->
                                        let projectedName =
                                            if entryPoints.Length > 1 then entryPoint + "-" + name else name
                                        let projected = copyRoute name
                                        projected["entryPoints"] <- jsonNodeStringArray [| entryPoint |]
                                        if configuredMiddlewares.Length + model.Middlewares.Length > 0 then
                                            projected["middlewares"] <-
                                                jsonNodeStringArray (Array.append model.Middlewares configuredMiddlewares)
                                        if tryProperty router "tls" |> Option.isNone then
                                            match model.Tls with
                                            | Some tls -> projected["tls"] <- JsonNode.Parse(tls.GetRawText())
                                            | None -> ()
                                        setRootObservability router (Some model) projected
                                        addProjected projectedName projected
                                        projectedNames.Add(projectedName)
                                    | _ -> unmodelled.Add(entryPoint)
                                if unmodelled.Count > 0 || entryPoints.Length = 0 then
                                    let projected = copyRoute name
                                    projected["entryPoints"] <- jsonNodeStringArray (unmodelled.ToArray())
                                    setRootObservability router None projected
                                    addProjected name projected
                                    projectedNames.Add(name)
                                splitNames[name] <- projectedNames.ToArray()
                            else
                                let projected = copyRoute name
                                if entryPoints.Length > 0 then projected["entryPoints"] <- jsonNodeStringArray entryPoints
                                setRootObservability router None projected
                                addProjected name projected
                                splitNames[name] <- [| name |]
                        | _ -> valid <- false
                for name, router in sourceRoutes do
                    if not (isRootRouter router) then
                        let projected = copyRoute name
                        if anyModels then
                            match readNames router "parentRefs" with
                            | Some parentRefs ->
                                let expanded = ResizeArray<string>()
                                for parentRef in parentRefs do
                                    let localName = withoutProviderSuffix "file" parentRef
                                    match splitNames.TryGetValue(localName) with
                                    | true, names -> expanded.AddRange(names)
                                    | _ -> expanded.Add(parentRef)
                                projected["parentRefs"] <- jsonNodeStringArray (expanded.ToArray())
                            | None -> valid <- false
                        addProjected name projected
                if not valid then None
                else
                    http["routers"] <- output
                    Some(JsonDocument.Parse(rootNode.ToJsonString()))
            | :? JsonObject as http ->
                Some(JsonDocument.Parse(rootNode.ToJsonString()))
            | _ -> Some(JsonDocument.Parse(rootNode.ToJsonString()))
        with _ -> None

    let private hasOpaqueDynamicSettings (root: JsonElement) : bool =
        let nonEmptyObject sectionName propertyName =
            match tryProperty root sectionName with
            | Some section ->
                match tryProperty section propertyName with
                | Some value when value.ValueKind = JsonValueKind.Object -> not (Seq.isEmpty (value.EnumerateObject()))
                | _ -> false
            | None -> false
        nonEmptyObject "http" "serversTransports"
        || nonEmptyObject "tcp" "serversTransports"
        || nonEmptyObject "tls" "options"
        || nonEmptyObject "tls" "stores"


    let private generationHash (root: JsonElement) : string option =
        try
            match JsonNode.Parse(root.GetRawText()) with
            | :? JsonObject as node ->
                let http = node["http"] :?> JsonObject
                let routers = http["routers"] :?> JsonObject
                let admin = routers["keroosha-admin"] :?> JsonObject
                admin["rule"] <- JsonValue.Create(TraefikHttpGraphModel.adminRuleBase)
                use stream = new MemoryStream()
                use writer = new Utf8JsonWriter(stream, jsonWriterOptions)
                writeSortedNode writer node
                writer.Flush()
                let bytes = ReadOnlySpan<byte>(stream.GetBuffer(), 0, int stream.Length)
                Some(SHA256.HashData(bytes) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant())
            | _ -> None
        with _ -> None

    let private generationRuleMatches (root: JsonElement) : bool =
        try
            let router = root.GetProperty("http").GetProperty("routers").GetProperty("keroosha-admin")
            let rule = tryString router "rule"
            if rule = TraefikHttpGraphModel.adminRuleBase then not (hasOpaqueDynamicSettings root)
            elif TraefikHttpGraphModel.isGeneratedAdminRule rule then
                generationHash root
                |> Option.exists (fun digest ->
                    rule = TraefikHttpGraphModel.generatedAdminRuleWithGeneration digest
                    || rule = TraefikHttpGraphModel.generatedAdminRuleWithGeneration (digest + opaqueDigest (JsonNode.Parse(root.GetRawText()).AsObject())))
            else
                false
        with _ -> false

    let private apiDynamicMatches
        purpose
        (api: ApiConfiguration)
        (expectedStatic: JsonElement option)
        (expectedRoot: JsonElement)
        (generationMatches: bool)
        : bool =
        let rootFields = set [ "http"; "tcp"; "udp"; "tls" ]
        let validRoot = expectedRoot.ValueKind = JsonValueKind.Object && Set.isEmpty (Set.difference (objectNames expectedRoot) rootFields)
        if not validRoot || not generationMatches then false
        else
            let models =
                match expectedStatic with
                | Some staticRoot -> entryPointModelsFromStatic staticRoot
                | None -> entryPointModelsFromApi api.EntryPoints
            match models |> Option.bind (fun values -> projectExpectedDynamic values expectedRoot) with
            | None -> false
            | Some projectedDocument ->
                use projectedDocument = projectedDocument
                let projectedRoot = projectedDocument.RootElement
                let expectedResources sectionName allowedFields resourceName =
                    expectedSectionResources projectedRoot sectionName allowedFields resourceName
                let actualResources resourceName = actualApiResources api resourceName
                let domainMatches sectionName allowedFields routerApiName serviceApiName middlewareApiName serviceMatcher protocol countRouterMiddlewareUsers =
                    match expectedResources sectionName allowedFields "routers",
                          expectedResources sectionName allowedFields "services",
                          (if String.IsNullOrEmpty(middlewareApiName) then Some Map.empty
                           else expectedResources sectionName allowedFields "middlewares") with
                    | Some expectedRouters, Some expectedServices, Some expectedMiddlewares ->
                        let routesMatch =
                            resourcesMatch expectedRouters (actualResources routerApiName)
                                (fun _ wanted found -> routerMatches purpose protocol wanted found)
                        let servicesMatch =
                            resourcesMatch expectedServices (actualResources serviceApiName)
                                (fun name wanted found -> serviceMatcher purpose expectedRouters name wanted found)
                        let middlewaresMatch =
                            if String.IsNullOrEmpty(middlewareApiName) then
                                true
                            else
                                resourcesMatch expectedMiddlewares (actualResources middlewareApiName)
                                    (middlewareMatches purpose countRouterMiddlewareUsers expectedRouters)
                        routesMatch && servicesMatch && middlewaresMatch
                    | _ -> false
                domainMatches "http" (set [ "routers"; "services"; "middlewares"; "serversTransports" ]) "routers" "services" "middlewares" httpServiceMatches HttpProtocol true
                && domainMatches "tcp" (set [ "routers"; "services"; "middlewares"; "serversTransports" ]) "tcpRouters" "tcpServices" "tcpMiddlewares" serviceMatches TcpProtocol false
                && domainMatches "udp" (set [ "routers"; "services" ]) "udpRouters" "udpServices" "" serviceMatches UdpProtocol false
    let private apiEntrypoints (element: JsonElement) : Map<string, JsonElement> option =
        if element.ValueKind <> JsonValueKind.Array then None
        else
            let values = Dictionary<string, JsonElement>(StringComparer.Ordinal)
            let mutable valid = true
            for item in element.EnumerateArray() do
                let name = tryString item "name"
                if item.ValueKind <> JsonValueKind.Object
                   || String.IsNullOrEmpty(name)
                   || not (values.TryAdd(name, item)) then
                    valid <- false
            if not valid then None
            else Some(values |> Seq.map (fun pair -> pair.Key, pair.Value) |> Map.ofSeq)

    let private staticEntrypoints (root: JsonElement) : Map<string, JsonElement> option =
        match tryProperty root "entryPoints" with
        | Some entryPoints when entryPoints.ValueKind = JsonValueKind.Object ->
            let values = Dictionary<string, JsonElement>(StringComparer.Ordinal)
            let mutable valid = true
            for property in entryPoints.EnumerateObject() do
                if property.Value.ValueKind <> JsonValueKind.Object
                   || not (values.TryAdd(property.Name, property.Value)) then
                    valid <- false
            if not valid then None
            else Some(values |> Seq.map (fun pair -> pair.Key, pair.Value) |> Map.ofSeq)
        | _ -> None

    let private normalizedEntrypoint (element: JsonElement) : JsonObject option =
        try
            match JsonNode.Parse(element.GetRawText()) with
            | :? JsonObject as entryPoint ->
                let mutable address = null
                if not (entryPoint.TryGetPropertyValue("address", &address))
                   || isNull address
                   || not (address :? JsonValue)
                   || (address :?> JsonValue).GetValueKind() <> JsonValueKind.String then
                    None
                else
                    let objectField (parent: JsonObject) (name: string) =
                        let mutable value = null
                        if parent.TryGetPropertyValue(name, &value) then
                            match value with
                            | :? JsonObject as fields -> fields
                            | _ -> invalidOp "Invalid entrypoint object."
                        else
                            let fields = JsonObject()
                            parent[name] <- fields
                            fields
                    let defaultField (fields: JsonObject) (name: string) (value: JsonNode) =
                        let mutable existing = null
                        if fields.TryGetPropertyValue(name, &existing) then
                            if isNull existing then invalidOp "Invalid entrypoint value."
                        else
                            fields[name] <- value
                    let boolean (value: bool) = JsonValue.Create(value) :> JsonNode
                    let integer (value: int64) = JsonValue.Create(value) :> JsonNode
                    let text (value: string) = JsonValue.Create(value) :> JsonNode
                    let defaultObject (fields: JsonObject) name values =
                        let child = objectField fields name
                        for key, value in values do defaultField child key value
                        child
                    let normalizeDuration (fields: JsonObject) (name: string) =
                        let mutable value = null
                        if fields.TryGetPropertyValue(name, &value) then
                            match value with
                            | :? JsonValue as jsonValue when jsonValue.GetValueKind() = JsonValueKind.String ->
                                match TraefikStatic.tryDurationNanoseconds (jsonValue.GetValue<string>()) with
                                | Some nanoseconds -> fields[name] <- integer nanoseconds
                                | None -> invalidOp "Invalid entrypoint duration."
                            | _ -> invalidOp "Invalid entrypoint duration."
                    let rec removeEmptyArrays (fields: JsonObject) =
                        let emptyArrays = ResizeArray<string>()
                        for field in fields do
                            match field.Value with
                            | :? JsonObject as child -> removeEmptyArrays child
                            | :? JsonArray as values when values.Count = 0 -> emptyArrays.Add(field.Key)
                            | _ -> ()
                        for name in emptyArrays do fields.Remove(name) |> ignore

                    entryPoint.Remove("name") |> ignore
                    defaultField entryPoint "allowACMEByPass" (boolean false)
                    defaultField entryPoint "reusePort" (boolean false)
                    defaultField entryPoint "asDefault" (boolean false)

                    let transport = objectField entryPoint "transport"
                    let lifeCycle =
                        defaultObject transport "lifeCycle"
                            [ "requestAcceptGraceTimeout", text "0s"
                              "graceTimeOut", text "10s" ]
                    let respondingTimeouts =
                        defaultObject transport "respondingTimeouts"
                            [ "readTimeout", text "1m0s"
                              "writeTimeout", text "0s"
                              "idleTimeout", text "3m0s" ]
                    defaultField transport "keepAliveMaxTime" (text "0s")
                    defaultField transport "keepAliveMaxRequests" (integer 0)

                    let proxyProtocol = objectField entryPoint "proxyProtocol"
                    defaultField proxyProtocol "insecure" (boolean false)
                    defaultField proxyProtocol "trustedIPs" (JsonArray() :> JsonNode)

                    let forwardedHeaders = objectField entryPoint "forwardedHeaders"
                    defaultField forwardedHeaders "insecure" (boolean false)
                    defaultField forwardedHeaders "trustedIPs" (JsonArray() :> JsonNode)
                    defaultField forwardedHeaders "connection" (JsonArray() :> JsonNode)
                    defaultField forwardedHeaders "notAppendXForwardedFor" (boolean false)

                    let http = objectField entryPoint "http"
                    defaultObject http "encodedCharacters"
                        [ "allowEncodedSlash", boolean true
                          "allowEncodedBackSlash", boolean true
                          "allowEncodedNullCharacter", boolean true
                          "allowEncodedSemicolon", boolean true
                          "allowEncodedPercent", boolean true
                          "allowEncodedQuestionMark", boolean true
                          "allowEncodedHash", boolean true ]
                    |> ignore
                    defaultField http "encodeQuerySemicolons" (boolean false)
                    defaultField http "sanitizePath" (boolean true)
                    defaultField http "maxHeaderBytes" (integer 1048576)
                    let mutable redirectionsNode = null
                    if http.TryGetPropertyValue("redirections", &redirectionsNode) then
                        match redirectionsNode with
                        | :? JsonObject as redirections ->
                            let mutable redirectNode = null
                            if redirections.TryGetPropertyValue("entryPoint", &redirectNode) then
                                match redirectNode with
                                | :? JsonObject as redirect ->
                                    defaultField redirect "scheme" (text "https")
                                    defaultField redirect "permanent" (boolean true)
                                    defaultField redirect "priority" (integer (Int64.MaxValue - 1L))
                                | _ -> invalidOp "Invalid entrypoint redirect."
                        | _ -> invalidOp "Invalid entrypoint redirections."

                    defaultObject entryPoint "http2"
                        [ "maxConcurrentStreams", integer 250
                          "maxDecoderHeaderTableSize", integer 4096
                          "maxEncoderHeaderTableSize", integer 4096 ]
                    |> ignore
                    let mutable http3Node = null
                    if entryPoint.TryGetPropertyValue("http3", &http3Node) then
                        match http3Node with
                        | :? JsonObject as http3 -> defaultField http3 "advertisedPort" (integer 0)
                        | _ -> invalidOp "Invalid entrypoint HTTP/3 configuration."

                    let udp = defaultObject entryPoint "udp" [ "timeout", text "3s" ]
                    defaultObject entryPoint "observability"
                        [ "accessLogs", boolean true
                          "metrics", boolean true
                          "tracing", boolean true
                          "traceVerbosity", text "minimal" ]
                    |> ignore

                    for durationName in [ "requestAcceptGraceTimeout"; "graceTimeOut" ] do
                        normalizeDuration lifeCycle durationName
                    for durationName in [ "readTimeout"; "writeTimeout"; "idleTimeout" ] do
                        normalizeDuration respondingTimeouts durationName
                    normalizeDuration transport "keepAliveMaxTime"
                    normalizeDuration udp "timeout"
                    removeEmptyArrays entryPoint
                    Some entryPoint
            | _ -> None
        with _ -> None

    let private apiVersionMatches (api: ApiConfiguration) =
        tryString api.Version "Version" = Version

    /// The entrypoint API exposes effective static listener values after Traefik applies defaults.
    let private apiStaticMatches (api: ApiConfiguration) (expectedRoot: JsonElement) : bool =
        match staticEntrypoints expectedRoot, apiEntrypoints api.EntryPoints with
        | Some expected, Some actual when expected.Count = actual.Count ->
            let adminAddress =
                Map.tryFind "keroosha-admin" expected
                |> Option.bind (fun item -> tryString item "address" |> Option.ofObj)
            adminAddress = Some("127.0.0.1:" + api.AdminPort.ToString(CultureInfo.InvariantCulture))
            && (expected
                |> Map.forall (fun name wanted ->
                    match Map.tryFind name actual with
                    | Some found ->
                        match normalizedEntrypoint wanted, normalizedEntrypoint found with
                        | Some expectedValues, Some actualValues -> JsonNode.DeepEquals(expectedValues :> JsonNode, actualValues :> JsonNode)
                        | _ -> false
                    | None -> false))
        | _ -> false

    let private apiRuntimeMatches
        (api: ApiConfiguration)
        (expectedStatic: JsonElement)
        (expectedDynamic: JsonElement)
        (generationMatches: bool)
        : bool =
        apiVersionMatches api
        && apiStaticMatches api expectedStatic
        && apiDynamicMatches Activation api (Some expectedStatic) expectedDynamic generationMatches

    let apiMatchesDynamic (apiConfiguration: ApiConfiguration option) (dynamicData: byte[] option) : bool =
        match apiConfiguration, dynamicData with
        | Some api, Some bytes ->
            try
                use document = JsonDocument.Parse(bytes)
                let generationMatches = generationRuleMatches document.RootElement
                apiDynamicMatches Activation api None document.RootElement generationMatches
            with _ -> false
        | _ -> false

    let apiMatchesStatic (apiConfiguration: ApiConfiguration option) (staticData: byte[] option) : bool =
        match apiConfiguration, staticData with
        | Some api, Some bytes ->
            try
                use document = JsonDocument.Parse(bytes)
                apiVersionMatches api && apiStaticMatches api document.RootElement
            with _ -> false
        | _ -> false

    let apiMatchesRuntime
        (apiConfiguration: ApiConfiguration option)
        (staticData: byte[] option)
        (dynamicData: byte[] option)
        : bool =
        match apiConfiguration, staticData, dynamicData with
        | Some api, Some staticBytes, Some dynamicBytes ->
            try
                use staticDocument = JsonDocument.Parse(staticBytes)
                use dynamicDocument = JsonDocument.Parse(dynamicBytes)
                let generationMatches = generationRuleMatches dynamicDocument.RootElement
                apiRuntimeMatches api staticDocument.RootElement dynamicDocument.RootElement generationMatches
            with _ -> false
        | _ -> false

    /// Traefik 3.7.16 rawdata exposes protocol resources and references, but not root TLS options/stores or named server transports.
    /// Opaque values are trusted only as a generation loaded by the private-router hash and exact managed file bytes; this is not per-field API readback.
    /// Concrete TLS behavior is separately covered by bounded handshake observations, with omitted and client-auth cases remaining unproven.
    let private apiMatchesRuntimeElements
        (api: ApiConfiguration option)
        (expectedStatic: JsonElement)
        (expectedDynamic: JsonElement)
        (generationMatches: bool)
        : bool =
        match api with
        | Some value -> apiRuntimeMatches value expectedStatic expectedDynamic generationMatches
        | None -> false

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

    let private sniFingerprintAt (bindAddress: IPAddress) (host: string) (port: int) (cancellationToken: CancellationToken) : Task<string option> =
        task {
            try
                use client = new TcpClient(bindAddress.AddressFamily)
                use timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
                timeout.CancelAfter(ConnectTimeoutMilliseconds)
                do! client.ConnectAsync(bindAddress, port, timeout.Token).ConfigureAwait(false)
                use stream = new SslStream(client.GetStream(), false, RemoteCertificateValidationCallback(fun _ _ _ _ -> true))
                let options = SslClientAuthenticationOptions(TargetHost = host)
                do! stream.AuthenticateAsClientAsync(options, timeout.Token).ConfigureAwait(false)
                match stream.RemoteCertificate with
                | null -> return None
                | remote -> return Some(sha256Bytes(remote.GetRawCertData()))
            with _ -> return None
        }



    let private serviceMaterialOwner (environment: HostEnvironment) : int * int =
        let uid, hostGid = hostOwner environment
        let gid = lookupGroup environment |> Option.defaultValue hostGid
        uid, gid

    let private serviceAccountOwner (environment: HostEnvironment) : int * int =
        match lookupUser environment, lookupGroup environment with
        | Some user, Some groupId -> user.Uid, groupId
        | _ -> parseIdCommand environment "-u", parseIdCommand environment "-g"

    [<Literal>]
    let private MaximumAcmeStorageBytes = 16 * 1024 * 1024

    let private tryNativeObject (value: JsonObject) (name: string) =
        match value[name] with
        | :? JsonObject as child -> Some child
        | _ -> None

    let private nativeStringOr (value: JsonObject) (name: string) (fallback: string) =
        match value[name] with
        | :? JsonValue as child when child.GetValueKind() = JsonValueKind.String ->
            match child.GetValue<string>() with
            | null -> fallback
            | text -> text
        | _ -> fallback

    let private acmeResolverSettings (request: Request) (resolverName: string) =
        match Map.tryFind resolverName request.Resolvers with
        | Some resolver -> resolver.Email, defaultArg resolver.CaServer DefaultCaServer
        | None ->
            let staticRoot =
                request.Configuration
                |> Option.bind (fun configuration -> tryNativeObject configuration "static")
                |> Option.defaultValue (JsonObject())
            let resolvers = tryNativeObject staticRoot "certificatesResolvers" |> Option.defaultValue (JsonObject())
            let resolver = tryNativeObject resolvers resolverName |> Option.defaultValue (JsonObject())
            let acme = tryNativeObject resolver "acme" |> Option.defaultValue (JsonObject())
            nativeStringOr acme "email" "", nativeStringOr acme "caServer" DefaultCaServer

    let private tryJsonString (element: JsonElement) (name: string) =
        match tryProperty element name with
        | Some value when value.ValueKind = JsonValueKind.String ->
            match value.GetString() with
            | null -> None
            | text -> Some text
        | _ -> None

    let private jsonHasUniqueProperties (root: JsonElement) =
        let rec visit (element: JsonElement) =
            match element.ValueKind with
            | JsonValueKind.Object ->
                let names = HashSet<string>(StringComparer.Ordinal)
                element.EnumerateObject()
                |> Seq.forall (fun property -> names.Add(property.Name) && visit property.Value)
            | JsonValueKind.Array -> element.EnumerateArray() |> Seq.forall visit
            | _ -> true
        visit root

    let private sameAcmeAuthority (expectedUrl: string) (registrationUrl: string) =
        try
            let expected = Uri(expectedUrl, UriKind.Absolute)
            let actual = Uri(registrationUrl, UriKind.Absolute)
            expected.Scheme = actual.Scheme
            && String.Equals(expected.IdnHost, actual.IdnHost, StringComparison.OrdinalIgnoreCase)
            && expected.Port = actual.Port
            && String.IsNullOrEmpty(actual.UserInfo)
        with _ -> false

    let private acmeAccountMatches (expectedEmail: string) (expectedCaServer: string) (resolverStorage: JsonElement) =
        try
            let account = tryProperty resolverStorage "Account"
            match account with
            | Some value when value.ValueKind = JsonValueKind.Object ->
                let email = tryJsonString value "Email"
                let privateKey = tryJsonString value "PrivateKey"
                let registration = tryProperty value "Registration"
                let registrationUri, registrationBody =
                    match registration with
                    | Some resource when resource.ValueKind = JsonValueKind.Object ->
                        tryJsonString resource "uri",
                        (tryProperty resource "body" |> Option.exists (fun body -> body.ValueKind = JsonValueKind.Object))
                    | _ -> None, false
                let privateKeyValid =
                    match privateKey with
                    | Some encoded ->
                        try
                            let bytes = Convert.FromBase64String(encoded)
                            use rsa = RSA.Create()
                            let mutable bytesRead = 0
                            rsa.ImportRSAPrivateKey(bytes.AsSpan(), &bytesRead) |> ignore
                            bytesRead = bytes.Length
                        with _ -> false
                    | None -> false
                email = Some expectedEmail
                && registrationBody
                && (registrationUri |> Option.exists (sameAcmeAuthority expectedCaServer))
                && privateKeyValid
            | _ -> false
        with _ -> false

    let private acmeCertificateFingerprintFromEntry (now: DateTimeOffset) (host: string) (entry: JsonElement) =
        try
            let domain = tryProperty entry "domain"
            let names =
                match domain with
                | Some value when value.ValueKind = JsonValueKind.Object ->
                    let candidates = ResizeArray<string>()
                    tryJsonString value "main" |> Option.iter candidates.Add
                    match tryProperty value "sans" with
                    | Some sans when sans.ValueKind = JsonValueKind.Array ->
                        for item in sans.EnumerateArray() do
                            if item.ValueKind = JsonValueKind.String then
                                match item.GetString() with
                                | null -> ()
                                | name -> candidates.Add(name)
                    | _ -> ()
                    candidates
                | _ -> ResizeArray<string>()
            if not (names |> Seq.exists (dnsPatternCoversHost host)) then None
            else
                match tryJsonString entry "certificate", tryJsonString entry "key" with
                | Some encodedCertificate, Some encodedKey when not (String.IsNullOrEmpty(encodedCertificate) || String.IsNullOrEmpty(encodedKey)) ->
                    let certificatePem = Convert.FromBase64String(encodedCertificate)
                    let privateKeyPem = Convert.FromBase64String(encodedKey)
                    let certificateText = UTF8Encoding(false, true).GetString(certificatePem)
                    let keyText = UTF8Encoding(false, true).GetString(privateKeyPem)
                    use pair = X509Certificate2.CreateFromPem(certificateText.AsSpan(), keyText.AsSpan())
                    if pair.HasPrivateKey
                       && certificateIsCurrentAt now certificatePem
                       && certificateCoversHost certificatePem host then
                        certificateFingerprint certificatePem
                    else None
                | _ -> None
        with _ -> None

    let private readAcmeStorage (environment: HostEnvironment) (paths: RuntimePaths) (storagePath: string) =
        try
            let serviceUid, serviceGid = serviceAccountOwner environment
            if not (assertRegular environment storagePath "ACME storage")
               || not (metadataMatches environment storagePath "file" 0o600 serviceUid serviceGid) then None
            else
                match readBytesBounded environment storagePath MaximumAcmeStorageBytes with
                | None -> None
                | Some bytes ->
                    let document = JsonDocument.Parse(ReadOnlyMemory<byte>(bytes), JsonDocumentOptions(MaxDepth = 64))
                    if jsonHasUniqueProperties document.RootElement then Some document
                    else
                        document.Dispose()
                        None
        with _ -> None

    let private acmeStoragePathsFromStaticRoot (root: JsonElement) =
        let mutable paths = Map.empty
        match tryProperty root "certificatesResolvers" with
        | Some resolvers when resolvers.ValueKind = JsonValueKind.Object ->
            for resolver in resolvers.EnumerateObject() do
                let path =
                    tryProperty resolver.Value "acme"
                    |> Option.bind (fun acme -> tryJsonString acme "storage")
                match path with
                | Some value -> paths <- Map.add resolver.Name value paths
                | None -> ()
        | _ -> ()
        paths

    type private AcmeStoreCache
        (environment: HostEnvironment, paths: RuntimePaths, resolverSettings: string -> string * string, storagePaths: Map<string, string>) =
        let documents = Dictionary<string, JsonDocument option>(StringComparer.Ordinal)
        let fingerprints = Dictionary<string * string, string option>()

        let documentFor resolverName =
            match documents.TryGetValue(resolverName) with
            | true, document -> document
            | _ ->
                let _, caServer = resolverSettings resolverName
                let storagePath =
                    Map.tryFind resolverName storagePaths
                    |> Option.defaultValue (TraefikTlsSettings.acmeStoragePath paths.StateDir resolverName caServer)
                let document = readAcmeStorage environment paths storagePath
                documents.Add(resolverName, document)
                document

        member _.AccountMatches(resolverName: string) =
            let email, caServer = resolverSettings resolverName
            match documentFor resolverName with
            | Some document when document.RootElement.ValueKind = JsonValueKind.Object ->
                match tryProperty document.RootElement resolverName with
                | Some resolverStorage when resolverStorage.ValueKind = JsonValueKind.Object ->
                    acmeAccountMatches email caServer resolverStorage
                | _ -> false
            | _ -> false

        member _.Fingerprint(resolverName: string, host: string) =
            let key = resolverName, host
            match fingerprints.TryGetValue(key) with
            | true, fingerprint -> fingerprint
            | _ ->
                let fingerprint =
                    match documentFor resolverName with
                    | Some document when document.RootElement.ValueKind = JsonValueKind.Object ->
                        match tryProperty document.RootElement resolverName with
                        | Some resolverStorage when resolverStorage.ValueKind = JsonValueKind.Object ->
                            let email, caServer = resolverSettings resolverName
                            if not (acmeAccountMatches email caServer resolverStorage) then None
                            else
                                match tryProperty resolverStorage "Certificates" with
                                | Some certificates when certificates.ValueKind = JsonValueKind.Array ->
                                    certificates.EnumerateArray()
                                    |> Seq.tryPick (acmeCertificateFingerprintFromEntry (environment.UtcNow()) host)
                                | _ -> None
                        | _ -> None
                    | _ -> None
                fingerprints.Add(key, fingerprint)
                fingerprint

        interface IDisposable with
            member _.Dispose() =
                for document in documents.Values do
                    document |> Option.iter (fun value -> value.Dispose())

    let acmeCertificateFingerprint
        (environment: HostEnvironment)
        (paths: RuntimePaths)
        (resolverName: string)
        (expectedEmail: string)
        (expectedCaServer: string)
        (host: string)
        : string option =
        let storagePaths =
            Map.ofList [ resolverName, TraefikTlsSettings.acmeStoragePath paths.StateDir resolverName expectedCaServer ]
        use cache = new AcmeStoreCache(environment, paths, (fun _ -> expectedEmail, expectedCaServer), storagePaths)
        cache.Fingerprint(resolverName, host)
    let private previousAcmeStorage (previousStatic: byte[] option) (resolverName: string) =
        match previousStatic with
        | None -> None
        | Some bytes ->
            try
                use document = JsonDocument.Parse(ReadOnlyMemory<byte>(bytes), JsonDocumentOptions(MaxDepth = 64))
                if not (jsonHasUniqueProperties document.RootElement) then None
                else
                    let resolver =
                        tryProperty document.RootElement "certificatesResolvers"
                        |> Option.bind (fun values -> tryProperty values resolverName)
                    let acme = resolver |> Option.bind (fun value -> tryProperty value "acme")
                    match acme with
                    | Some value when value.ValueKind = JsonValueKind.Object ->
                        let caServer = tryJsonString value "caServer" |> Option.defaultValue DefaultCaServer
                        Some(caServer, tryJsonString value "storage")
                    | _ -> None
            with _ -> None

    let private sameAcmeDirectory (left: string) (right: string) =
        try
            String.Equals(Uri(left, UriKind.Absolute).AbsoluteUri, Uri(right, UriKind.Absolute).AbsoluteUri, StringComparison.Ordinal)
        with _ -> false

    /// Validates that an existing destination store is safe for this issuer. Resolver identity is
    /// encoded in the managed path; historical name-only stores are reused only when the prior
    /// static snapshot proves the exact same directory URL.
    let private ensureAcmeIssuerTransitionSafe
        (environment: HostEnvironment)
        (paths: RuntimePaths)
        (previousStatic: byte[] option)
        (request: Request)
        =
        let staticData = Encoding.UTF8.GetBytes(renderStaticWithPrevious request paths "" previousStatic)
        use staticDocument = JsonDocument.Parse(staticData)
        let storagePaths = acmeStoragePathsFromStaticRoot staticDocument.RootElement
        use stores = new AcmeStoreCache(environment, paths, acmeResolverSettings request, storagePaths)
        let serviceUid, serviceGid = serviceAccountOwner environment
        for KeyValue(resolverName, storagePath) in storagePaths do
            let _, caServer = acmeResolverSettings request resolverName
            match previousAcmeStorage previousStatic resolverName with
            | Some (previousCaServer, Some previousPath)
                when previousPath = storagePath && not (sameAcmeDirectory previousCaServer caServer) ->
                fail "Traefik ACME storage cannot be reused across issuer changes"
            | _ -> ()
            match tryStat environment storagePath with
            | None -> ()
            | Some _ ->
                let descriptor = openChecked storagePath false
                try
                    let metadata = statDescriptor descriptor
                    if metadata.Mode <> 0o600 || metadata.Uid <> serviceUid || metadata.Gid <> serviceGid then
                        fail "Traefik ACME storage has unsafe ownership or permissions"
                    use handle = new SafeFileHandle(nativeint descriptor, false)
                    // Traefik creates a zero-length store even for a configured, unused resolver.
                    // There is no account to overwrite there. Issued routes still require a
                    // validated account and matching leaf/key before readiness or a positive Read.
                    if RandomAccess.GetLength(handle) <> 0L && not (stores.AccountMatches(resolverName)) then
                        fail "Traefik ACME storage is unsafe for the configured resolver"
                finally
                    nativeClose(descriptor) |> ignore



    let readProtectedMaterial (_environment: HostEnvironment) (path: string) (expectedUid: int) (expectedGid: int) : byte[] =
        let descriptor = openChecked path false
        try
            let metadata = statDescriptor descriptor
            if metadata.Mode <> 0o640 || metadata.Uid <> expectedUid || metadata.Gid <> expectedGid then
                fail "Traefik certificate material permissions drifted"
            try readDescriptor descriptor
            with _ -> fail "cannot read protected Traefik certificate material"
        finally nativeClose(descriptor) |> ignore

    let private legacyRouteRequiresClientCertificate (request: Request) (entryPointName: string) =
        let isRequired (optionReference: string) =
            let separator = optionReference.IndexOf('@')
            let optionName = if separator < 0 then optionReference else optionReference.Substring(0, separator)
            let dynamicRoot =
                request.Configuration
                |> Option.bind (fun configuration -> tryNativeObject configuration "dynamic")
                |> Option.defaultValue (JsonObject())
            let tls = tryNativeObject dynamicRoot "tls" |> Option.defaultValue (JsonObject())
            let options = tryNativeObject tls "options" |> Option.defaultValue (JsonObject())
            let option = tryNativeObject options optionName
            let clientAuth = option |> Option.bind (fun value -> tryNativeObject value "clientAuth")
            clientAuth
            |> Option.map (fun value -> nativeStringOr value "clientAuthType" "")
            |> Option.exists (fun value -> value = "RequireAnyClientCert" || value = "RequireAndVerifyClientCert")

        let entryPointOption =
            request.Configuration
            |> Option.bind (fun configuration -> tryNativeObject configuration "static")
            |> Option.bind (fun staticRoot -> tryNativeObject staticRoot "entryPoints")
            |> Option.bind (fun entryPoints -> tryNativeObject entryPoints entryPointName)
            |> Option.bind (fun entryPoint -> tryNativeObject entryPoint "http")
            |> Option.bind (fun http -> tryNativeObject http "tls")
            |> Option.map (fun tls -> nativeStringOr tls "options" "default")
            |> Option.defaultValue "default"
        isRequired entryPointOption

    [<Literal>]
    let private MaximumConcurrentTlsProbes = 4

    [<Literal>]
    let private TlsProbeWallBudgetSeconds = 15

    let private probeSniTargets (targets: (string * string * int) array) (deadlineTicks: int64) =
        let observations: string option option array = Array.create targets.Length None
        let mutable nextIndex = -1
        let mutable attempted = 0
        let remainingTicks = deadlineTicks - Stopwatch.GetTimestamp()
        if targets.Length > 0 && remainingTicks > 0L then
            let remainingMilliseconds = Math.Max(1.0, Math.Ceiling(float remainingTicks * 1000.0 / float Stopwatch.Frequency))
            use cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(remainingMilliseconds))
            let worker () =
                task {
                    let mutable running = true
                    while running do
                        let index = Interlocked.Increment(&nextIndex)
                        if index >= targets.Length || cancellation.IsCancellationRequested then
                            running <- false
                        else
                            let host, bindAddress, port = targets[index]
                            let mutable bindIp = Unchecked.defaultof<IPAddress>
                            if IPAddress.TryParse(bindAddress, &bindIp) then
                                Interlocked.Increment(&attempted) |> ignore
                                let! fingerprint = sniFingerprintAt bindIp host port cancellation.Token
                                observations[index] <- Some fingerprint
                            else
                                Interlocked.Increment(&attempted) |> ignore
                                observations[index] <- Some None
                }
            let workers = Array.init (min MaximumConcurrentTlsProbes targets.Length) (fun _ -> worker ())
            Task.WhenAll(workers).GetAwaiter().GetResult() |> ignore
        let results = Dictionary<string * string * int, string option option>()
        for index in 0 .. targets.Length - 1 do
            results.Add(targets[index], observations[index])
        results, attempted, targets.Length - attempted

    let private legacyTlsProbeTargets (request: Request) =
        let mutable targets = Set.empty
        let loopback = IPAddress.Loopback.ToString()
        for KeyValue(_, router) in request.Routers do
            if router.Tls.Kind = "provided" || router.Tls.Kind = "acme" then
                targets <- targets.Add((router.Host, loopback, request.EntryPoints[router.EntryPoint]))
        targets

    let private certificateObservations
        (environment: HostEnvironment)
        (paths: RuntimePaths)
        (request: Request)
        (certificateMaterialDigests: Map<string, string>)
        (probeEligible: bool)
        (acmeStores: AcmeStoreCache)
        (probeDeadlineTicks: int64)
        : JsonObject * bool * Set<string * string * int> * Set<string * string * int> * int * int * bool * Dictionary<string * string * int, string option option> =
        let observed = JsonObject()
        let mutable certificatesMatch = true
        let hostsForCertificate = Dictionary<string, ResizeArray<string * string * int>>(StringComparer.Ordinal)
        let acmeRoutes = ResizeArray<string * string * int * string>()
        let loopback = IPAddress.Loopback.ToString()
        let expectedFingerprints = Dictionary<string * string * int, Set<string>>()
        let addExpected target fingerprint =
            let values =
                match expectedFingerprints.TryGetValue(target) with
                | true, existing -> existing
                | _ -> Set.empty
            expectedFingerprints[target] <- values.Add(fingerprint)

        for KeyValue(_, router) in request.Routers do
            let target = router.Host, loopback, request.EntryPoints[router.EntryPoint]
            match router.Tls.Kind with
            | "provided" ->
                if not (hostsForCertificate.ContainsKey(router.Tls.Name)) then
                    hostsForCertificate[router.Tls.Name] <- ResizeArray()
                hostsForCertificate[router.Tls.Name].Add(target)
            | "acme" -> acmeRoutes.Add((router.Host, router.EntryPoint, request.EntryPoints[router.EntryPoint], router.Tls.Name))
            | _ -> ()

        let expectedUid, expectedGid = serviceMaterialOwner environment
        for KeyValue(name, certificate) in request.Certificates do
            let digest = Map.tryFind name certificateMaterialDigests |> Option.defaultWith (fun () -> materialDigest certificate)
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
            if not materialMatches
               || fingerprint <> Some certificate.Fingerprint
               || not (certificateIsCurrentAt (environment.UtcNow()) certificatePem) then
                certificatesMatch <- false
            match hostsForCertificate.TryGetValue(name) with
            | true, routes ->
                for host, bindAddress, port in routes do
                    if not (certificateCoversHost certificatePem host) then certificatesMatch <- false
                    addExpected (host, bindAddress, port) certificate.Fingerprint
            | _ -> ()

        for host, _, port, resolverName in acmeRoutes do
            match acmeStores.Fingerprint(resolverName, host) with
            | Some fingerprint -> addExpected (host, loopback, port) fingerprint
            | None -> certificatesMatch <- false

        let legacyTargets = legacyTlsProbeTargets request
        let mTlsTargets =
            request.Routers
            |> Seq.choose (fun (KeyValue(_, router)) ->
                let target = router.Host, loopback, request.EntryPoints[router.EntryPoint]
                if (router.Tls.Kind = "provided" || router.Tls.Kind = "acme")
                   && legacyRouteRequiresClientCertificate request router.EntryPoint then Some target
                else None)
            |> Set.ofSeq
        let eligibleTargets = Set.difference legacyTargets mTlsTargets
        let probeResults, probesAttempted, notStarted =
            if probeEligible then probeSniTargets (eligibleTargets |> Set.toArray) probeDeadlineTicks
            else Dictionary<string * string * int, string option option>(), 0, 0
        if probeEligible then
            for target in eligibleTargets do
                match probeResults.TryGetValue(target), expectedFingerprints.TryGetValue(target) with
                | (true, Some(Some fingerprint)), (true, expected) when expected.Contains(fingerprint) -> ()
                | (true, Some _), (true, _) -> certificatesMatch <- false
                | (true, Some _), _ -> certificatesMatch <- false
                | _ -> certificatesMatch <- false
        let unprobedCount =
            if probeEligible then mTlsTargets.Count + notStarted
            else legacyTargets.Count
        let truncated = probeEligible && notStarted > 0
        observed, certificatesMatch, legacyTargets, mTlsTargets, probesAttempted, unprobedCount, truncated, probeResults

    // The public &&& combinator parenthesizes each operand. Leading grouping does not negate
    // the literal; the conservative remainder check below still excludes alternation/negation.
    let private nativeHostRulePattern = Regex("""^\s*(?:\(\s*)*Host\s*\(([^()]*)\)""", RegexOptions.CultureInvariant)
    let private nativeHostSniPattern = Regex("""^\s*(?:\(\s*)*HostSNI\s*\(([^()]*)\)""", RegexOptions.CultureInvariant)
    let private nativeHostLiteralPattern = Regex("""(?:`([^`]+)`|"([^"]+)")""", RegexOptions.CultureInvariant)
    let private nativeHostArgumentsPattern = Regex("""^\s*(?:`[^`]+`|"[^"]+")\s*(?:,\s*(?:`[^`]+`|"[^"]+"))*\s*$""", RegexOptions.CultureInvariant)
    let private nativeAmbiguousHostPattern = Regex("""(?:Host(?:SNI)?Regexp\s*\(|(?:^|[^A-Za-z0-9_])!?\s*Host(?:SNI)?\s*\()""", RegexOptions.CultureInvariant)

    let private canonicalProbeHost (value: string) =
        try
            let host = validateDnsName value
            let mutable address = Unchecked.defaultof<IPAddress>
            if IPAddress.TryParse(host, &address) then None else Some host
        with _ -> None

    /// Conservative SNI extraction: only a positive leading Host/HostSNI list of quoted DNS literals.
    let probeHostsFromRule (isTcp: bool) (rule: string) : string list =
        if String.IsNullOrWhiteSpace rule then []
        else
            let trimmed = rule.TrimStart()
            let pattern = if isTcp then nativeHostSniPattern else nativeHostRulePattern
            let matcher = pattern.Match(trimmed)
            let result = HashSet<string>(StringComparer.Ordinal)
            if matcher.Success then
                let arguments = matcher.Groups[1].Value
                let remainder = trimmed.Substring(matcher.Length)
                if nativeHostArgumentsPattern.IsMatch(arguments)
                   && not (remainder.Contains("!", StringComparison.Ordinal))
                   && not (remainder.Contains("||", StringComparison.Ordinal))
                   && not (nativeAmbiguousHostPattern.IsMatch(remainder)) then
                    for hostMatch in (nativeHostLiteralPattern.Matches(arguments) |> Seq.cast<Match>) do
                        let host = if hostMatch.Groups[1].Success then hostMatch.Groups[1].Value else hostMatch.Groups[2].Value
                        canonicalProbeHost host |> Option.iter (fun value -> result.Add(value) |> ignore)
            result |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right)) |> Seq.toList


    let private tryNativeNodeProperty (value: JsonObject) (name: string) =
        let mutable property: JsonNode = null
        if value.TryGetPropertyValue(name, &property) then Some property else None

    let private tryNativeObjectProperty (value: JsonObject) (name: string) =
        match tryNativeNodeProperty value name with
        | Some (:? JsonObject as property) -> Some property
        | _ -> None

    let private tryNativeString (value: JsonNode) =
        match value with
        | :? JsonValue as scalar when scalar.GetValueKind() = JsonValueKind.String ->
            match scalar.GetValue<string>() with
            | null -> None
            | text -> Some text
        | _ -> None

    let private tryNativeStringProperty (value: JsonObject) (name: string) =
        tryNativeNodeProperty value name |> Option.bind tryNativeString

    let private tryNativeBool (value: JsonNode) =
        match value with
        | :? JsonValue as scalar when scalar.GetValueKind() = JsonValueKind.True -> Some true
        | :? JsonValue as scalar when scalar.GetValueKind() = JsonValueKind.False -> Some false
        | _ -> None

    let private tryNativeBind (address: string) (localAddresses: Set<string>) =
        if String.IsNullOrWhiteSpace address then None
        else
            let slash = address.IndexOf('/')
            let socketAddress, protocol =
                if slash < 0 then address, "tcp"
                elif slash = 0 || address.IndexOf('/', slash + 1) >= 0 then "", ""
                else address.Substring(0, slash), address.Substring(slash + 1).ToLowerInvariant()
            if protocol <> "tcp" || String.IsNullOrEmpty(socketAddress) then None
            else
                let hostText, portText, bracketed =
                    if socketAddress.StartsWith("[", StringComparison.Ordinal) then
                        let close = socketAddress.IndexOf(']')
                        if close < 2 || close + 1 >= socketAddress.Length || socketAddress[close + 1] <> ':' then "", "", false
                        else socketAddress.Substring(1, close - 1), socketAddress.Substring(close + 2), true
                    else
                        let colon = socketAddress.LastIndexOf(':')
                        if colon < 0 || socketAddress.IndexOf(':') <> colon then "", "", false
                        else socketAddress.Substring(0, colon), socketAddress.Substring(colon + 1), false
                let mutable port = 0
                if String.IsNullOrEmpty(portText)
                   || not (Int32.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, &port))
                   || port < 1 || port > 65535 then None
                else
                    let mutable parsed = Unchecked.defaultof<IPAddress>
                    let parsedAddress =
                        if String.IsNullOrEmpty(hostText) then Some IPAddress.Any
                        elif IPAddress.TryParse(hostText, &parsed) then Some parsed
                        else None
                    match parsedAddress with
                    | None -> None
                    | Some ip when bracketed && ip.AddressFamily <> AddressFamily.InterNetworkV6 -> None
                    | Some ip when not bracketed && not (String.IsNullOrEmpty(hostText)) && ip.AddressFamily <> AddressFamily.InterNetwork -> None
                    | Some ip ->
                        let probeAddress =
                            if ip.Equals(IPAddress.Any) then IPAddress.Loopback
                            elif ip.Equals(IPAddress.IPv6Any) then IPAddress.IPv6Loopback
                            else ip
                        let local = IPAddress.IsLoopback(probeAddress) || localAddresses.Contains(probeAddress.ToString())
                        Some(probeAddress, port, local)

    /// Resolves a numeric listener to a safe local probe target; hostnames and non-local IPs are never contacted.
    let resolveProbeBind (address: string) (localAddresses: Set<string>) : (IPAddress * int) option =
        match tryNativeBind address localAddresses with
        | Some (ip, port, true) -> Some(ip, port)
        | _ -> None

    let private localProbeAddresses () =
        try
            NetworkInterface.GetAllNetworkInterfaces()
            |> Seq.truncate 64
            |> Seq.collect (fun networkInterface ->
                try
                    networkInterface.GetIPProperties().UnicastAddresses
                    |> Seq.truncate 256
                    |> Seq.map (fun address -> address.Address.ToString())
                with _ -> Seq.empty)
            |> Seq.truncate 512
            |> Set.ofSeq
        with _ -> Set.empty

    let private nativeTlsObservations (request: Request)
        (probeEligible: bool)
        (acmeStores: AcmeStoreCache)
        (probeDeadlineTicks: int64)
        (legacyTargets: Set<string * string * int>)
        (legacyMtlsTargets: Set<string * string * int>)
        (legacyProbeResults: Dictionary<string * string * int, string option option>)
        (legacyProbeAttempts: int)
        (legacyUnprobed: int)
        (legacyTruncated: bool)
        : JsonObject * bool =
        let report = JsonObject()
        let mutable opaqueRoutes = 0
        let localAddresses = localProbeAddresses ()
        let loopbackAddress = IPAddress.Loopback.ToString()
        let candidates =
            Dictionary<string * string * int, (Set<string> * Set<string> * bool)>()
        let configuration = defaultArg request.Configuration (JsonObject())
        let staticRoot = TraefikSettings.section configuration "static"
        let dynamicRoot = TraefikSettings.section configuration "dynamic"
        let tlsRoot = TraefikSettings.section dynamicRoot "tls"
        let tlsOptions = TraefikSettings.section tlsRoot "options"
        let stores = TraefikSettings.section tlsRoot "stores"
        let defaultStore = tryNativeObjectProperty stores "default"
        let defaultCertificateName =
            defaultStore
            |> Option.bind (fun store -> tryNativeObjectProperty store "defaultCertificate")
            |> Option.bind (fun certificate -> tryNativeStringProperty certificate "certificate")
        let defaultGenerated =
            defaultStore
            |> Option.bind (fun store -> tryNativeObjectProperty store "defaultGeneratedCert")

        let mutable entryPointBinds =
            request.EntryPoints
            |> Map.map (fun _ port -> loopbackAddress, port, true)
        match tryNativeObjectProperty staticRoot "entryPoints" with
        | Some entryPoints ->
            for entryPoint in entryPoints do
                match entryPoint.Value with
                | :? JsonObject as settings ->
                    match tryNativeStringProperty settings "address" |> Option.bind (fun address -> tryNativeBind address localAddresses) with
                    | Some (address, port, local) -> entryPointBinds <- Map.add entryPoint.Key (address.ToString(), port, local) entryPointBinds
                    | None -> ()
                | _ -> ()
        | None -> ()
        let allBinds = entryPointBinds |> Map.toSeq |> Seq.map snd |> Set.ofSeq
        let entryPointTlsModels =
            match tryNativeObjectProperty staticRoot "entryPoints" with
            | Some entryPoints ->
                entryPoints
                |> Seq.choose (fun (KeyValue(name, value)) ->
                    match value with
                    | :? JsonObject as settings ->
                        tryNativeObjectProperty settings "http"
                        |> Option.bind (fun http -> tryNativeObjectProperty http "tls")
                        |> Option.map (fun tls -> name, tls)
                    | _ -> None)
                |> Map.ofSeq
            | None -> Map.empty

        let portsForRouter (router: JsonObject) =
            match tryNativeNodeProperty router "entryPoints" with
            | Some (:? JsonArray as names) when names.Count > 0 ->
                names
                |> Seq.choose tryNativeString
                |> Seq.choose (fun name -> Map.tryFind name entryPointBinds)
                |> Set.ofSeq
            | _ -> allBinds
        // Pinned v3.7.16 applies an entrypoint TLS model only when a root router has no TLS object;
        // it splits that router by modeled entrypoint and does not inherit entrypoints to parentRefs children.
        let httpTlsBindings (router: JsonObject) =
            let hasParents = tryNativeNodeProperty router "parentRefs" |> Option.isSome
            match tryNativeNodeProperty router "tls" with
            | Some (:? JsonObject as tls) -> [ tls, portsForRouter router ]
            | Some _ -> []
            | None when hasParents -> []
            | None ->
                let entryPointNames =
                    match tryNativeNodeProperty router "entryPoints" with
                    | Some (:? JsonArray as names) when names.Count > 0 ->
                        names |> Seq.choose tryNativeString |> Seq.toList
                    | _ -> entryPointTlsModels |> Map.toSeq |> Seq.map fst |> Seq.toList
                entryPointNames
                |> Seq.choose (fun name ->
                    match Map.tryFind name entryPointTlsModels, Map.tryFind name entryPointBinds with
                    | Some tls, Some bind -> Some(tls, Set.singleton bind)
                    | _ -> None)
                |> Seq.toList

        let hostsInDomains (tls: JsonObject) =
            let result = HashSet<string>(StringComparer.Ordinal)
            match tryNativeNodeProperty tls "domains" with
            | Some (:? JsonArray as domains) ->
                for domain in domains do
                    match domain with
                    | :? JsonObject as fields ->
                        match tryNativeStringProperty fields "main" with
                        | Some main -> canonicalProbeHost main |> Option.iter (fun host -> result.Add(host) |> ignore)
                        | None -> ()
                        match tryNativeNodeProperty fields "sans" with
                        | Some (:? JsonArray as sans) ->
                            for san in sans do
                                match tryNativeString san with
                                | Some value -> canonicalProbeHost value |> Option.iter (fun host -> result.Add(host) |> ignore)
                                | None -> ()
                        | _ -> ()
                    | _ -> ()
            | _ -> ()
            result |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right)) |> Seq.toList

        let clientAuthType (optionReference: string option) =
            let reference = defaultArg optionReference "default"
            let separator = reference.IndexOf('@')
            let name = if separator < 0 then reference else reference.Substring(0, separator)
            tryNativeObjectProperty tlsOptions name
            |> Option.bind (fun option -> tryNativeObjectProperty option "clientAuth")
            |> Option.bind (fun auth -> tryNativeStringProperty auth "clientAuthType")

        let addCandidate (host: string) (bindAddress: string) (port: int) (bindIsLocal: bool) (resolverName: string option) (authType: string option) =
            let key = host, bindAddress, port
            let resolvers = resolverName |> Option.toList |> Set.ofList
            let authTypes = authType |> Option.toList |> Set.ofList
            match candidates.TryGetValue(key) with
            | true, (oldResolvers, oldAuthTypes, oldLocal) ->
                candidates[key] <- Set.union oldResolvers resolvers, Set.union oldAuthTypes authTypes, oldLocal && bindIsLocal
            | _ -> candidates.Add(key, (resolvers, authTypes, bindIsLocal))
        let collectTlsBinding (isTcp: bool) (router: JsonObject) (tls: JsonObject) (ports: Set<string * int * bool>) =
            let passthrough =
                isTcp
                && (tryNativeNodeProperty tls "passthrough" |> Option.bind tryNativeBool = Some true)
            if passthrough then opaqueRoutes <- opaqueRoutes + 1
            else
                let hosts = HashSet<string>(StringComparer.Ordinal)
                for host in hostsInDomains tls do hosts.Add(host) |> ignore
                match tryNativeStringProperty router "rule" with
                | Some rule ->
                    for host in probeHostsFromRule isTcp rule do hosts.Add(host) |> ignore
                | None -> ()
                if hosts.Count = 0 || ports.IsEmpty then opaqueRoutes <- opaqueRoutes + 1
                else
                    let resolverName =
                        tryNativeStringProperty tls "certResolver"
                        |> Option.filter (String.IsNullOrEmpty >> not)
                    let authType = clientAuthType (tryNativeStringProperty tls "options")
                    for host in hosts |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right)) do
                        for bindAddress, port, local in ports do
                            addCandidate host bindAddress port local resolverName authType

        let collectRouters (sectionName: string) (isTcp: bool) =
            match tryNativeObjectProperty dynamicRoot sectionName with
            | None -> ()
            | Some section ->
                match tryNativeObjectProperty section "routers" with
                | None -> ()
                | Some routers ->
                    for routerEntry in routers do
                        match routerEntry.Value with
                        | :? JsonObject as router when isTcp ->
                            match tryNativeObjectProperty router "tls" with
                            | Some tls -> collectTlsBinding true router tls (portsForRouter router)
                            | None -> ()
                        | :? JsonObject as router ->
                            for tls, ports in httpTlsBindings router do
                                collectTlsBinding false router tls ports
                        | _ -> opaqueRoutes <- opaqueRoutes + 1

        collectRouters "http" false
        collectRouters "tcp" true

        let defaultGeneratedResolver (host: string) =
            defaultGenerated
            |> Option.bind (fun generated ->
                match tryNativeStringProperty generated "resolver", tryNativeObjectProperty generated "domain" with
                | Some resolver, Some domain ->
                    let domainNames = ResizeArray<string>()
                    tryNativeStringProperty domain "main" |> Option.iter domainNames.Add
                    match tryNativeNodeProperty domain "sans" with
                    | Some (:? JsonArray as sans) ->
                        for value in sans do tryNativeString value |> Option.iter domainNames.Add
                    | _ -> ()
                    if domainNames |> Seq.exists (dnsPatternCoversHost host) then Some resolver else None
                | _ -> None)

        let mutable nativeTlsMatches = true
        let acmeExpectedFingerprint resolver host =
            match acmeStores.Fingerprint(resolver, host) with
            | Some fingerprint -> Some fingerprint
            | None ->
                nativeTlsMatches <- false
                None

        let expectedFingerprints (host: string) (resolvers: Set<string>) =
            if not resolvers.IsEmpty then
                let values = resolvers |> Seq.map (fun resolver -> acmeExpectedFingerprint resolver host) |> Seq.toArray
                if values |> Array.exists Option.isNone then Some Set.empty
                else values |> Array.choose id |> Set.ofArray |> Some
            else
                let matchingManaged =
                    request.Certificates
                    |> Seq.choose (fun (KeyValue(_, certificate)) ->
                        if certificate.Usage = "server" && certificateCoversHost (Encoding.UTF8.GetBytes(certificate.CertificatePem)) host then
                            Some certificate.Fingerprint
                        else None)
                    |> Set.ofSeq
                if not matchingManaged.IsEmpty then Some matchingManaged
                else
                    match defaultCertificateName with
                    | Some name ->
                        request.Certificates
                        |> Map.tryFind name
                        |> Option.map (fun certificate -> Set.singleton certificate.Fingerprint)
                        |> Option.orElse (defaultGeneratedResolver host |> Option.map (fun resolver ->
                            acmeExpectedFingerprint resolver host |> Option.toList |> Set.ofList))
                    | None ->
                        defaultGeneratedResolver host
                        |> Option.map (fun resolver -> acmeExpectedFingerprint resolver host |> Option.toList |> Set.ofList)

        let candidatePairs =
            candidates
            |> Seq.map (fun item -> item.Key, item.Value)
            |> Seq.sortBy fst
            |> Seq.toArray
        let expectedByTarget = Dictionary<string * string * int, Set<string> option>()
        let nativeProbeTargets = ResizeArray<string * string * int>()
        let mutable unprobedNative = opaqueRoutes

        for (host, bindAddress, port), (resolvers, authTypes, bindIsLocal) in candidatePairs do
            let target = host, bindAddress, port
            let expected = expectedFingerprints host resolvers
            if legacyTargets.Contains(target) then
                if not (legacyMtlsTargets.Contains(target)) then
                    match legacyProbeResults.TryGetValue(target) with
                    | true, Some(Some fingerprint) ->
                        match expected with
                        | Some values when not (values.Contains(fingerprint)) -> nativeTlsMatches <- false
                        | _ -> ()
                    | true, Some None -> nativeTlsMatches <- false
                    | true, None when expected.IsSome -> nativeTlsMatches <- false
                    | _ -> ()
            else
                let requiresClientCertificate =
                    authTypes.Contains("RequireAnyClientCert")
                    || authTypes.Contains("RequireAndVerifyClientCert")
                if not probeEligible || not bindIsLocal || requiresClientCertificate then
                    unprobedNative <- unprobedNative + 1
                else
                    let mutable bindIp = Unchecked.defaultof<IPAddress>
                    if not (IPAddress.TryParse(bindAddress, &bindIp)) then
                        unprobedNative <- unprobedNative + 1
                        nativeTlsMatches <- false
                    else
                        expectedByTarget[target] <- expected
                        nativeProbeTargets.Add(target)

        let nativeProbeResults, nativeProbeAttempts, nativeNotStarted =
            if probeEligible then probeSniTargets (nativeProbeTargets.ToArray()) probeDeadlineTicks
            else Dictionary<string * string * int, string option option>(), 0, 0

        for target in nativeProbeTargets do
            match nativeProbeResults.TryGetValue(target), expectedByTarget[target] with
            | (true, Some(Some fingerprint)), Some expected when expected.Contains(fingerprint) -> ()
            | (true, Some(Some _)), Some _ -> nativeTlsMatches <- false
            | (true, Some None), Some _ -> nativeTlsMatches <- false
            | (true, Some(Some _)), None -> unprobedNative <- unprobedNative + 1
            | (true, Some None), None ->
                unprobedNative <- unprobedNative + 1
                nativeTlsMatches <- false
            | _ ->
                unprobedNative <- unprobedNative + 1
                nativeTlsMatches <- false

        unprobedNative <- unprobedNative + legacyUnprobed
        report["unprobedCount"] <- JsonValue.Create(unprobedNative)
        report["opaqueRouterCount"] <- JsonValue.Create(opaqueRoutes)
        report["legacyProbesAttempted"] <- JsonValue.Create(legacyProbeAttempts)
        report["nativeProbesAttempted"] <- JsonValue.Create(nativeProbeAttempts)
        report["truncated"] <- JsonValue.Create(legacyTruncated || nativeNotStarted > 0)
        report, nativeTlsMatches

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

    let rec private observeRuntimePrepared
        (environment: HostEnvironment)
        (request: Request)
        (certificateMaterialDigests: Map<string, string>)
        (paths: RuntimePaths)
        (expectedStaticData: byte[])
        (expectedDynamicData: byte[])
        (expectedStaticRoot: JsonElement)
        (expectedDynamicRoot: JsonElement)
        (generationMatches: bool)
        (ignorePending: bool)
        (verifyPinnedBinary: bool)
        (cachedConfigHash: string option)
        : JsonObject =
        let mutable ownerMatches = false
        let mutable staticMatches = false
        let mutable dynamicMatches = false
        try
            let ownerStatus, stateStatus, installStatus, _ = checkLayoutCollisions environment paths request.OwnerId
            let dynamicStatus = markerStatus environment paths.DynamicDir request.OwnerId
            let certificateStatus = markerStatus environment paths.CertificateDir request.OwnerId
            let unitData = safeUnitStatus environment paths.UnitPath request.OwnerId
            let arch = architecture ()
            use markerDocument = JsonDocument.Parse(readBytes environment (Path.Combine(paths.InstallDir, ".keroosha-release.json")))
            let marker = markerDocument.RootElement
            let releaseShapeMatches =
                marker.ValueKind = JsonValueKind.Object
                && objectNames marker = set [ "owner"; "version"; "architecture"; "archiveSha256"; "binarySha256" ]
                && tryString marker "owner" = ownerDigest request.OwnerId
                && tryString marker "version" = Version
                && tryString marker "architecture" = arch
                && tryString marker "archiveSha256" = archiveChecksums[arch]
            let binaryMatches =
                if not verifyPinnedBinary then true
                else
                    tryString marker "binarySha256" = binarySha256 environment paths.BinaryPath
                    && binaryVersion environment paths.BinaryPath
            let releaseMatches = releaseShapeMatches && binaryMatches
            ownerMatches <-
                ownerStatus = "owned" && stateStatus = "owned" && installStatus = "owned"
                && dynamicStatus = "owned" && certificateStatus = "owned"
                && unitData = Some(Encoding.UTF8.GetBytes(unitText paths request.OwnerId request.Configuration))
                && releaseMatches && filesystemMetadataMatches environment paths
            staticMatches <- readBytes environment (Path.Combine(paths.ConfigDir, "static.yml")) = expectedStaticData
            dynamicMatches <- readBytes environment (Path.Combine(paths.DynamicDir, "current.yml")) = expectedDynamicData
        with _ ->
            ownerMatches <- false
            staticMatches <- false
            dynamicMatches <- false
        let active, enabled, effectiveUnit =
            try
                isActive environment, isEnabled environment, unitMatches environment paths
            with _ -> false, false, false
        let api =
            if active && ownerMatches && request.ReadProbeSafe then readApi request.AdminPort |> fun operation -> operation.GetAwaiter().GetResult()
            else None
        let apiMatches = apiMatchesRuntimeElements api expectedStaticRoot expectedDynamicRoot generationMatches
        let probeEligible =
            verifyPinnedBinary && ownerMatches && staticMatches && dynamicMatches
            && active && effectiveUnit && apiMatches && request.ReadProbeSafe
        let acmeStoragePaths = acmeStoragePathsFromStaticRoot expectedStaticRoot
        use acmeStores = new AcmeStoreCache(environment, paths, acmeResolverSettings request, acmeStoragePaths)
        let probeDeadlineTicks = Stopwatch.GetTimestamp() + int64 TlsProbeWallBudgetSeconds * Stopwatch.Frequency
        let fingerprints, certificatesMatch, legacyTargets, legacyMtlsTargets, legacyProbeAttempts, legacyUnprobed, legacyTruncated, legacyProbeResults =
            certificateObservations environment paths request certificateMaterialDigests probeEligible acmeStores probeDeadlineTicks
        let tlsObservations, nativeTlsMatches =
            nativeTlsObservations request probeEligible acmeStores probeDeadlineTicks legacyTargets legacyMtlsTargets legacyProbeResults legacyProbeAttempts legacyUnprobed legacyTruncated
        let credentialsMatch = credentialFileMatches environment paths request.Configuration
        let pending = tryStat environment paths.RollbackPath |> Option.isSome
        let inSync =
            ownerMatches && staticMatches && dynamicMatches && active && enabled && effectiveUnit
            && apiMatches && certificatesMatch && nativeTlsMatches && credentialsMatch && request.ReadProbeSafe
            && (ignorePending || not pending)
        let configHash =
            match cachedConfigHash with
            | Some value -> value
            | None -> actualConfigHash environment paths
        let result = JsonObject()
        result["inSync"] <- JsonValue.Create(inSync)
        result["actualConfigHash"] <- JsonValue.Create(configHash)
        result["certificateFingerprints"] <- fingerprints
        result["tlsObservations"] <- tlsObservations
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
            let credentialMetadataMatches =
                match tryStat environment paths.CredentialsPath with
                | None -> true
                | Some _ -> metadataMatches environment paths.CredentialsPath "file" 0o600 rootUid rootGid
            if not credentialMetadataMatches then false
            else
                try
                    entries paths.StateDir
                    |> Array.forall (fun filename ->
                        if filename = ".keroosha-owner" then true
                        elif acmeFilenamePattern.IsMatch(filename) then
                            metadataMatches environment (Path.Combine(paths.StateDir, filename)) "file" 0o600 serviceUid serviceGid
                        else false)
                with _ -> false
    let private existingStaticSnapshot (environment: HostEnvironment) (paths: RuntimePaths) =
        try
            let path = Path.Combine(paths.ConfigDir, "static.yml")
            if assertRegular environment path "Traefik static configuration" then Some(readBytes environment path)
            else None
        with _ -> None

    let observeRuntime (environment: HostEnvironment) (requestElement: JsonElement) (listenHost: string) (ignorePending: bool) : JsonObject =
        let request = validateRequest requestElement
        let certificateMaterialDigests = request.Certificates |> Map.map (fun _ certificate -> materialDigest certificate)
        let paths = pathsFor environment
        let expectedStaticData =
            Encoding.UTF8.GetBytes(renderStaticWithPrevious request paths listenHost (existingStaticSnapshot environment paths))
        let expectedDynamicData =
            if request.Configuration.IsSome then Encoding.UTF8.GetBytes(renderDynamic request paths)
            else
                // A historical Read may recognize the exact former representation;
                // this byte comparison is not rollback authority for masked TLS.
                let historical = Encoding.UTF8.GetBytes(renderDynamicFormat false request paths)
                let historicalOnDisk =
                    try readBytes environment (Path.Combine(paths.DynamicDir, "current.yml")) = historical
                    with _ -> false
                if historicalOnDisk then historical else Encoding.UTF8.GetBytes(renderDynamic request paths)
        use staticDocument = JsonDocument.Parse(expectedStaticData)
        use dynamicDocument = JsonDocument.Parse(expectedDynamicData)
        let generationMatches = generationRuleMatches dynamicDocument.RootElement
        observeRuntimePrepared
            environment
            request
            certificateMaterialDigests
            paths
            expectedStaticData
            expectedDynamicData
            staticDocument.RootElement
            dynamicDocument.RootElement
            generationMatches
            ignorePending
            true
            None

    let private managerRecord environment filters =
        let r = run environment "journalctl" ([ "--boot"; "--no-pager"; "--output=json"; "--lines=1"; "_PID=1"; "UNIT=" + ServiceName ] @ filters)
        if r.ExitCode <> 0 then None
        else
            try
                use doc = JsonDocument.Parse(r.Stdout)
                Some(doc.RootElement.Clone())
            with :? JsonException -> None

    let internal checkActivationJob environment job knownInvocation =
        let invocation =
            match knownInvocation with
            | Some _ -> knownInvocation
            | None ->
                managerRecord environment [ "JOB_ID=" + job ]
                |> Option.bind (fun entry ->
                    match tryString entry "JOB_RESULT", tryString entry "JOB_TYPE" with
                    | "done", "start" when tryString entry "MESSAGE_ID" = "39f53479d3a045ac8e11786248231fbf" ->
                        let id = tryString entry "INVOCATION_ID"
                        if id.Length = 32 && Seq.forall Uri.IsHexDigit id then Some id else None
                    | ("dependency" | "failed" | "timeout" | "canceled" | "skipped" | "assert" | "unsupported" | "collected") as result, _ ->
                        fail ("Traefik systemd activation job " + job + " failed: " + result)
                    | _ -> None)
        invocation |> Option.iter (fun id ->
            match managerRecord environment [ "INVOCATION_ID=" + id; "MESSAGE_ID=d9b373ed55a64feb8242e02dbe79a49c" ] with
            | Some record -> fail ("Traefik activation invocation " + id + " failed: " + tryString record "UNIT_RESULT")
            | None ->
                match showUnit environment [ "InvocationID" ] |> Option.bind (Map.tryFind "InvocationID") with
                | Some current when current.Length = 32 && current <> String('0',32) && current <> id -> fail ("Traefik activation invocation " + id + " was replaced before readiness")
                | _ -> ())
        invocation

    let private waitForActivation (environment: HostEnvironment) (requestElement: JsonElement) (paths: RuntimePaths) (timeoutSeconds: float) job : JsonObject =
        let jobMatches () = job |> Option.forall (fun id -> (managedJobInvocation environment id).IsSome)
        let request = validateRequest requestElement
        let certificateMaterialDigests = request.Certificates |> Map.map (fun _ certificate -> materialDigest certificate)
        let expectedStaticData =
            Encoding.UTF8.GetBytes(renderStaticWithPrevious request paths "" (existingStaticSnapshot environment paths))
        let expectedDynamicData = Encoding.UTF8.GetBytes(renderDynamic request paths)
        use staticDocument = JsonDocument.Parse(expectedStaticData)
        use dynamicDocument = JsonDocument.Parse(expectedDynamicData)
        let generationMatches = generationRuleMatches dynamicDocument.RootElement
        let cachedConfigHash = actualConfigHash environment paths
        let deadline = Stopwatch.GetTimestamp() + int64 (timeoutSeconds * float Stopwatch.Frequency)
        let fullVerificationIntervalTicks = 2L * Stopwatch.Frequency
        let mutable lastFullVerification = 0L
        let mutable latest = JsonObject()
        latest["inSync"] <- JsonValue.Create(false)
        latest["actualConfigHash"] <- JsonValue.Create(cachedConfigHash)
        latest["certificateFingerprints"] <- JsonObject()
        latest["tlsObservations"] <- JsonObject()
        let mutable complete = false
        let mutable started = None
        while not complete do
            job |> Option.iter (fun j -> started <- checkActivationJob environment j started)
            let candidate =
                observeRuntimePrepared
                    environment request certificateMaterialDigests paths expectedStaticData expectedDynamicData
                    staticDocument.RootElement dynamicDocument.RootElement generationMatches
                    true false (Some cachedConfigHash)
            let now = Stopwatch.GetTimestamp()
            let fullVerificationAttempted =
                candidate["inSync"].GetValue<bool>()
                && jobMatches ()
                && (lastFullVerification = 0L || now - lastFullVerification >= fullVerificationIntervalTicks)
            if fullVerificationAttempted then
                latest <-
                    observeRuntimePrepared
                        environment request certificateMaterialDigests paths expectedStaticData expectedDynamicData
                        staticDocument.RootElement dynamicDocument.RootElement generationMatches
                        true true None
                lastFullVerification <- Stopwatch.GetTimestamp()
                if latest["inSync"].GetValue<bool>() && jobMatches () then complete <- true
            else
                latest <- candidate
                if candidate["inSync"].GetValue<bool>() then
                    latest["inSync"] <- JsonValue.Create(false)
            if not complete && Stopwatch.GetTimestamp() >= deadline then
                if not fullVerificationAttempted then
                    latest <-
                        observeRuntimePrepared
                            environment request certificateMaterialDigests paths expectedStaticData expectedDynamicData
                            staticDocument.RootElement dynamicDocument.RootElement generationMatches
                            true true None
                if not (jobMatches ()) then latest["inSync"] <- JsonValue.Create(false)
                complete <- true
            elif not complete then
                Thread.Sleep(ActivationPollMilliseconds)
        latest
    let private readOptional (environment: HostEnvironment) (path: string) : byte[] option =
        if assertRegular environment path "Traefik owned file" then Some(readBytes environment path) else None
    let private readCredentialSnapshot (environment: HostEnvironment) (paths: RuntimePaths) : byte[] option =
        match tryStat environment paths.CredentialsPath with
        | None -> None
        | Some item when item.Kind = "regular file" || item.Kind = "regular empty file" ->
            match readBytesBounded environment paths.CredentialsPath (512 * 1024) with
            | Some bytes -> Some bytes
            | None -> fail "Traefik DNS credential file exceeds its size limit"
        | Some _ -> fail "Traefik DNS credential path is unsafe"

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
        (credentialsData: byte[] option)
        (unitData: byte[] option)
        (releaseMarker: byte[] option)
        (binaryPresent: bool)
        (binarySha256: string option)
        (wasActive: bool)
        (wasEnabled: bool)
        (restartRequired: bool)
        (certificateFiles: string list)
        =
        let journal = JsonObject()
        journal["version"] <- JsonValue.Create(3)
        journal["owner"] <- JsonValue.Create(ownerDigest ownerId)
        journal["static"] <- encodeSnapshot staticData
        journal["dynamic"] <- encodeSnapshot dynamicData
        journal["credentials"] <- encodeSnapshot credentialsData
        journal["unit"] <- encodeSnapshot unitData
        journal["releaseMarker"] <- encodeSnapshot releaseMarker
        journal["binaryPresent"] <- JsonValue.Create(binaryPresent)
        match binarySha256 with None -> journal["binarySha256"] <- null | Some value -> journal["binarySha256"] <- JsonValue.Create(value)
        journal["wasActive"] <- JsonValue.Create(wasActive)
        journal["wasEnabled"] <- JsonValue.Create(wasEnabled)
        journal["restartRequired"] <- JsonValue.Create(restartRequired)
        let files = JsonArray()
        for filename in certificateFiles |> List.sortWith (fun (left: string) (right: string) -> StringComparer.Ordinal.Compare(left, right)) do files.Add(JsonValue.Create(filename))
        journal["certificateFiles"] <- files
        writeAtomic environment paths.RollbackPath (Encoding.UTF8.GetBytes(jsonText journal)) 0o600 None

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

    let private recoveryDirectory environment (paths: RuntimePaths) =
        let parent = Path.GetDirectoryName(paths.ConfigDir)
        let dir = Path.Combine(parent, ".dorothy-traefik-recovery")
        let uid, gid = hostOwner environment
        match tryStat environment parent with
        | Some p when p.Kind = "directory" && p.Uid = uid && (p.Mode &&& 0o022) = 0 -> ()
        | _ -> fail "recovery directory parent is not private to the administrator"
        Directory.CreateDirectory(dir, unixMode 0o700) |> ignore
        if not (metadataMatches environment dir "directory" 0o700 uid gid) then fail "unsafe recovery directory"
        fsyncDirectory parent
        dir

    // SIGKILL during write leaves no name. After linkat only a complete,
    // content-addressed inode exists in the root-only administrative directory.
    // No filename wildcard or sweep is a source of deletion authority.
    let private writeRecoveryFile environment paths generation (path: string) (data: byte[]) mode gid replace check =
        let dir = recoveryDirectory environment paths
        let uid, _ = hostOwner environment
        let stage =
            if replace then Path.Combine(dir, "stage-" + sha256Text (generation + "\n" + path + "\n" + sha256Bytes data))
            else path
        let verifyStage () =
            if not (metadataMatches environment stage "file" mode uid gid) || readOptional environment stage <> Some data then
                fail "recovery staging collision; preserving existing file"
        match tryStat environment stage with
        | Some _ -> verifyStage (); fsyncDirectory dir
        | None ->
            // O_TMPFILE | O_RDWR | O_CLOEXEC | O_NOFOLLOW
            let fd = nativeOpen(dir, 0x410000 ||| 2 ||| 0x80000 ||| 0x20000, 0o600)
            if fd < 0 then fail "recovery requires a filesystem supporting anonymous tmpfiles"
            use handle = new SafeFileHandle(nativeint fd, true)
            use stream = new FileStream(handle, FileAccess.Write)
            stream.Write(data.AsSpan())
            stream.Flush(true)
            if nativeFchown(fd, uint32 uid, uint32 gid) <> 0 || nativeFchmod(fd, uint32 mode) <> 0 || nativeFsync(fd) <> 0 then fail "cannot secure recovery output"
            check ()
            if nativeLinkAt(fd, "", -100, stage, 0x1000) <> 0 then fail "cannot publish recovery output without overwrite"
            fsyncDirectory dir
        if replace then
            verifyStage ()
            check ()
            if nativeRename(stage, path) <> 0 then fail "cannot atomically commit recovery output; paths must share a filesystem"
            fsyncDirectory (Path.GetDirectoryName(path))
            fsyncDirectory dir

    let private transactionPreimage (journal: JsonObject) =
        let prior = journal.DeepClone().AsObject()
        prior.Remove("recovery") |> ignore
        prior["version"] <- JsonValue.Create(3)
        sha256Text (jsonText prior)

    let private persistRecovery environment (paths: RuntimePaths) (expected: byte[]) witness verify =
        let uid, gid = hostOwner environment
        if not (metadataMatches environment paths.RollbackPath "file" 0o600 uid gid) || readOptional environment paths.RollbackPath <> Some expected then
            fail "recovery journal changed; refusing to advance its phase"
        let root = JsonNode.Parse(expected).AsObject()
        let phase = JsonObject()
        phase["job"] <- JsonValue.Create(witness.Job)
        phase["invocation"] <- JsonValue.Create(witness.Invocation)
        phase["priorReceipt"] <- JsonValue.Create(witness.PriorReceipt)
        phase["preimage"] <- JsonValue.Create(witness.Preimage)
        phase["target"] <- match witness.Target with Some digest -> JsonValue.Create(digest) | None -> null
        root["recovery"] <- phase
        root["version"] <- JsonValue.Create(4)
        let bytes = Encoding.UTF8.GetBytes(jsonText root)
        writeRecoveryFile environment paths witness.Preimage paths.RollbackPath bytes 0o600 gid true (fun () ->
            verify ()
            if readOptional environment paths.RollbackPath <> Some expected then fail "recovery journal changed before commit")
        bytes

    let private loadPendingTransaction (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) : PendingTransaction option =
        if not (assertRegular environment paths.RollbackPath "activation rollback journal") then None
        else
            try
                let bytes = readBytes environment paths.RollbackPath
                use document = JsonDocument.Parse(bytes)
                let journal = document.RootElement
                if journal.ValueKind <> JsonValueKind.Object then fail "Traefik rollback journal is invalid"
                let get (name: string) = journal.GetProperty(name)
                let version = jsonInt (get "version")
                let baseFields = set [ "version"; "owner"; "static"; "dynamic"; "unit"; "releaseMarker"; "binaryPresent"; "binarySha256"; "wasActive"; "wasEnabled"; "certificateFiles" ]
                let expected =
                    match version with
                    | Some 1 -> baseFields
                    | Some 2 -> Set.add "credentials" baseFields
                    | Some 3 -> Set.add "restartRequired" (Set.add "credentials" baseFields)
                    | Some 4 -> Set.union baseFields (set [ "credentials"; "restartRequired"; "recovery" ])
                    | _ -> fail "Traefik rollback journal is invalid"
                if objectNames journal <> expected then fail "Traefik rollback journal is invalid"
                let owner = tryString journal "owner"
                let binaryPresent = jsonBool (get "binaryPresent")
                let wasActive = jsonBool (get "wasActive")
                let wasEnabled = jsonBool (get "wasEnabled")
                let restartRequired = if version = Some 3 || version = Some 4 then jsonBool (get "restartRequired") else Some true
                let binarySha = if (get "binarySha256").ValueKind = JsonValueKind.Null then None else Some(stringValue "Traefik rollback journal is invalid" (get "binarySha256"))
                let names = get "certificateFiles"
                if owner <> ownerDigest ownerId || binaryPresent.IsNone || wasActive.IsNone || wasEnabled.IsNone || restartRequired.IsNone || names.ValueKind <> JsonValueKind.Array then
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
                    JournalSha256 = sha256Bytes bytes
                    Recovery =
                        if version <> Some 4 then None
                        else
                            let phase = get "recovery"
                            let job, id = tryString phase "job", tryString phase "invocation"
                            let prior, preimage = tryString phase "priorReceipt", tryString phase "preimage"
                            let target = phase.GetProperty("target")
                            if objectNames phase <> set [ "job"; "invocation"; "priorReceipt"; "preimage"; "target" ]
                               || not (Regex.IsMatch(job, "^[1-9][0-9]{0,9}$")) || not (Regex.IsMatch(id, "^[0-9a-f]{32}$"))
                               || not (fingerprintPattern.IsMatch(prior)) || preimage <> transactionPreimage (JsonNode.Parse(journal.GetRawText()).AsObject()) then fail "recovery phase is invalid"
                            let targetHash =
                                if target.ValueKind = JsonValueKind.Null then None
                                elif target.ValueKind = JsonValueKind.String && fingerprintPattern.IsMatch(target.GetString()) then Some(target.GetString())
                                else fail "recovery target is invalid"
                            Some { Job = job; Invocation = id; PriorReceipt = prior; Preimage = preimage; Target = targetHash }
                    Static = decodeSnapshot (get "static")
                    Dynamic = decodeSnapshot (get "dynamic")
                    Credentials = if version = Some 1 then None else decodeSnapshot (get "credentials")
                    CredentialsKnown = version <> Some 1
                    Unit = decodeSnapshot (get "unit")
                    ReleaseMarker = decodeSnapshot (get "releaseMarker")
                    BinaryPresent = binaryPresent.Value
                    BinarySha256 = binarySha
                    WasActive = wasActive.Value
                    WasEnabled = wasEnabled.Value
                    RestartRequired = restartRequired.Value
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

    let private waitForRollback (environment: HostEnvironment) (paths: RuntimePaths) (serviceControllerTimeout: float) (staticData: byte[] option) (dynamicData: byte[] option) (credentialsData: byte[] option) : bool =
        match staticData, dynamicData, credentialsData with
        | Some staticBytes, Some dynamicBytes, expectedCredentials ->
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
                                && credentialSnapshotMatches environment paths expectedCredentials
                            with _ -> false
                        if filesMatch then
                            let api = readApi adminPort |> fun operation -> operation.GetAwaiter().GetResult()
                            restored <- apiMatchesRuntime api (Some staticBytes) (Some dynamicBytes)
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

    let private attestedStatic environment (paths: RuntimePaths) owner bytes =
        let uid, gid = hostOwner environment
        match bytes |> Option.bind (staticReceipt environment owner) with
        | Some expected -> metadataMatches environment paths.StaticReceipt "file" 0o600 uid gid && readOptional environment paths.StaticReceipt = Some expected
        | None -> false

    let private recordManagedStart environment (paths: RuntimePaths) owner bytes invocation =
        match invocation with
        | Some expected when staticReceipt environment owner bytes = Some expected && readOptional environment (Path.Combine(paths.ConfigDir, "static.yml")) = Some bytes ->
            writeRecoveryFile environment paths (sha256Bytes expected) paths.StaticReceipt expected 0o600 (snd (hostOwner environment)) true (fun () ->
                if staticReceipt environment owner bytes <> Some expected || readOptional environment (Path.Combine(paths.ConfigDir,"static.yml")) <> Some bytes then fail "managed start changed before receipt commit")
        | _ -> fail "cannot attest the managed Traefik invocation and static file after activation"

    let private receiptForJob environment owner (bytes: byte[]) job =
        let id = managedJobInvocation environment job |> Option.defaultWith (fun () -> fail "running Traefik invocation does not belong to the managed systemd job")
        Some(Encoding.UTF8.GetBytes(String.concat "\n" [ owner; id; Convert.ToHexString(SHA256.HashData bytes) ]))

    /// Compare the recoverable file graph, not desired inputs or route health. In
    /// particular an empty backend that is actually loaded is not a healthy backend.
    let internal loadedRollbackGraph (api: ApiConfiguration option) (disk: byte[] option) =
        match api, disk with
        | Some observed, Some bytes when apiVersionMatches observed ->
            try
                use document = JsonDocument.Parse(bytes)
                let root = document.RootElement
                let rule = root.GetProperty("http").GetProperty("routers").GetProperty("keroosha-admin").GetProperty("rule").GetString()
                let opaqueConfirmed =
                    if rule = TraefikHttpGraphModel.adminRuleBase then
                        let noTransport key = tryProperty root key |> Option.bind (fun section -> tryProperty section "serversTransports") |> Option.isNone
                        let emptyTls =
                            match tryProperty root "tls" with
                            | None -> true
                            | Some tls when tls.ValueKind = JsonValueKind.Object ->
                                tls.EnumerateObject() |> Seq.forall (fun p -> p.Name = "certificates" && p.Value.ValueKind = JsonValueKind.Array && p.Value.GetArrayLength() = 0)
                            | _ -> false
                        noTransport "http" && noTransport "tcp" && emptyTls
                    else
                        generationRuleMatches root
                        || (TraefikHttpGraphModel.isGeneratedAdminRule rule
                            && rule.EndsWith(opaqueDigest (JsonNode.Parse(bytes).AsObject()) + "`)", StringComparison.Ordinal))
                jsonHasUniqueProperties root && opaqueConfirmed
                && apiDynamicMatches Attribution observed None root true
            with :? JsonException | :? KeyNotFoundException | :? InvalidOperationException -> false
        | _ -> false
    let private recoverPendingTransaction (environment: HostEnvironment) (paths: RuntimePaths) (ownerId: string) (request: JsonElement) (activationTimeout: float) : PendingTransaction option =
        match loadPendingTransaction environment paths ownerId with
        | None -> None
        | Some journal when journal.Recovery.IsSome -> fail "pending recovery start requires scoped dynamic repair"
        | Some journal ->
            let currentUnit = safeUnitStatus environment paths.UnitPath ownerId
            if currentUnit.IsSome then
                if not (unitMatches environment paths) then fail "interrupted transaction has a different effective unit"
            elif isActive environment || isEnabled environment then fail "interrupted Traefik service has no owned unit"
            let oldStatic = journal.Static
            let oldDynamic = journal.Dynamic
            let oldUnit = journal.Unit
            let oldCredentials = journal.Credentials
            let requestState = validateRequest request
            let issuerFailure =
                try
                    ensureAcmeIssuerTransitionSafe environment paths oldStatic requestState
                    None
                with
                | :? BackendError as error -> Some error.Message
                | _ -> Some "Traefik ACME issuer transition could not be verified"
            let currentStatic = readOptional environment (Path.Combine(paths.ConfigDir, "static.yml"))
            let currentDynamic = readOptional environment (Path.Combine(paths.DynamicDir, "current.yml"))
            let currentSync =
                match issuerFailure with
                | Some _ -> false
                | None -> (observeRuntime environment request "" true).["inSync"].GetValue<bool>()
            let currentCredentials = readCredentialSnapshot environment paths
            let currentBinaryExists = assertRegular environment paths.BinaryPath "Traefik binary"
            let currentBinaryHash = if currentBinaryExists then Some(binarySha256 environment paths.BinaryPath) else None
            let priorCertificateFiles = entries paths.CertificateDir |> Set.ofArray
            let priorFilesRestored =
                currentStatic = oldStatic
                && currentDynamic = oldDynamic
                && (not journal.CredentialsKnown || currentCredentials = oldCredentials)
                && currentUnit = oldUnit
                && currentBinaryHash = journal.BinarySha256
                && readOptional environment (Path.Combine(paths.InstallDir, ".keroosha-release.json")) = journal.ReleaseMarker
                && priorCertificateFiles = Set.ofList journal.CertificateFiles
            if currentSync then
                if not journal.WasActive || not (attestedStatic environment paths ownerId oldStatic) then
                    fail "interrupted activation cannot establish the previous invocation; use offline maintenance"
                let restartRequired =
                    journal.RestartRequired
                    || not journal.CredentialsKnown
                    || currentBinaryHash <> journal.BinarySha256
                    || udpWithdrawalRequiresRestart oldDynamic currentDynamic currentStatic
                if restartRequired then
                    let desired = Encoding.UTF8.GetBytes(renderStaticWithPrevious requestState paths "" oldStatic)
                    if currentStatic <> Some desired || not (attestedStatic environment paths ownerId oldStatic) then
                        fail "interrupted restart refused: the previous invocation or staged static bytes are not confirmed; preserve the journal and reconcile the service"
                    let job = enqueueServiceJob environment true
                    let result = waitForActivation environment request paths activationTimeout (Some job)
                    if not (result["inSync"].GetValue<bool>()) then fail "interrupted Traefik restart intent did not recover"
                    recordManagedStart environment paths ownerId desired (receiptForJob environment ownerId desired job)
                removePendingTransaction environment paths ownerId
                None
            elif priorFilesRestored then
                if journal.WasActive then
                    let port = adminPortFromStatic oldStatic |> Option.defaultWith (fun () -> fail "missing static preimage")
                    let api = (readApi port).GetAwaiter().GetResult()
                    if not (attestedStatic environment paths ownerId oldStatic && apiMatchesStatic api oldStatic && loadedRollbackGraph api oldDynamic) then
                        fail "restored files do not establish the running transaction preimage; use offline maintenance"
                match issuerFailure with
                | Some message -> fail message
                | None -> Some journal
            else
                // v1–v3 do not bind every staged byte to a specific candidate
                // and systemd job. A third file or invocation is not ours to undo.
                fail "interrupted transaction has no attributable preimage or verified target; no restart or restore attempted"

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


    let private applyTransaction (environment: HostEnvironment) (requestElement: JsonElement) (activationTimeout: float) : JsonObject =
        let request = validateRequest requestElement
        if request.Operation <> "apply" then fail "apply requires an apply operation"
        let paths = pathsFor environment
        validateCertificateMaterial request
        // A running file watcher may still serve its last good graph after rejecting
        // external bytes. Do not use those bytes as an undo log or repair them by fiat.
        let staticPath = Path.Combine(paths.ConfigDir, "static.yml")
        let dynamicPath = Path.Combine(paths.DynamicDir, "current.yml")
        let hasPending = assertRegular environment paths.RollbackPath "activation rollback journal"
        let pending = recoverPendingTransaction environment paths request.OwnerId requestElement activationTimeout
        let capture () = struct (readOptional environment staticPath, readOptional environment dynamicPath)
        let initial = capture ()
        match initial with
        | struct (previousStatic, disk) when (safeUnitStatus environment paths.UnitPath request.OwnerId).IsSome && isActive environment ->
            let port = adminPortFromStatic previousStatic |> Option.defaultWith (fun () -> fail "Apply refused: missing or invalid static rollback file; preserve the file and reconcile it with the running process.")
            let observed = (readApi port).GetAwaiter().GetResult()
            if observed.IsNone then fail "Apply refused: private API unavailable at the captured admin address; verify service readiness and static configuration, then retry."
            if not (apiMatchesStatic observed previousStatic) then fail "Apply refused: static listener configuration on disk differs from the running process; preserve external changes, reconcile the file and process, then retry."
            if previousStatic <> Some(Encoding.UTF8.GetBytes(renderStaticWithPrevious request paths "" previousStatic)) && not (attestedStatic environment paths request.OwnerId previousStatic) then
                fail "Apply refused: restart requires a confirmed static file for this service invocation; reconcile during a maintenance window"
            if disk.IsNone then fail "Apply refused: missing dynamic rollback file; restore a confirmed copy of the loaded file before retrying."
            if not (loadedRollbackGraph observed disk) then
                fail "Apply refused: cannot establish that the dynamic rollback file represents the running graph. Preserve the external change, reconcile the file with the running configuration, then retry Apply."
        | _ -> ()
        let configStatus, stateStatus, installStatus, initialUnit = validateActualOwner environment paths request.OwnerId
        if initialUnit.IsSome then ensureEffectiveUnit environment paths
        let initiallyActive = isActive environment
        let initiallyEnabled = isEnabled environment
        if initialUnit.IsNone && (initiallyActive || initiallyEnabled) then fail "Traefik service name collides with an unowned systemd unit"
        let existingOwned = configStatus = "owned" || stateStatus = "owned" || installStatus = "owned"
        let _, serviceGroup = ensureLayout environment paths request.OwnerId existingOwned
        let configStatus, stateStatus, installStatus, currentUnit = validateActualOwner environment paths request.OwnerId
        if currentUnit.IsSome then ensureEffectiveUnit environment paths
        if currentUnit.IsNone && (isActive environment || isEnabled environment) then fail "Traefik service name collides with an unowned systemd unit"
        let wasActive = pending |> Option.map (fun transaction -> transaction.WasActive) |> Option.defaultWith (fun () -> isActive environment)
        let wasEnabled = pending |> Option.map (fun transaction -> transaction.WasEnabled) |> Option.defaultWith (fun () -> isEnabled environment)
        let struct (oldStatic, oldDynamic) =
            match pending with
            | Some transaction -> struct (transaction.Static, transaction.Dynamic)
            | None -> initial
        let oldCredentials =
            match pending with
            | Some transaction when transaction.CredentialsKnown -> transaction.Credentials
            | _ -> readCredentialSnapshot environment paths
        let oldBinaryExists =
            pending
            |> Option.map (fun transaction -> transaction.BinaryPresent)
            |> Option.defaultWith (fun () -> assertRegular environment paths.BinaryPath "Traefik binary")
        let oldBinaryHash =
            match pending with
            | Some transaction -> transaction.BinarySha256
            | None -> if oldBinaryExists then Some(binarySha256 environment paths.BinaryPath) else None
        let actualBinaryExists = assertRegular environment paths.BinaryPath "Traefik binary"
        let actualBinaryHash = if actualBinaryExists then Some(binarySha256 environment paths.BinaryPath) else None
        let oldReleaseMarker =
            match pending with
            | Some transaction -> transaction.ReleaseMarker
            | None -> readOptional environment (Path.Combine(paths.InstallDir, ".keroosha-release.json"))
        let oldUnitBytes =
            match pending with
            | Some transaction -> transaction.Unit
            | None -> currentUnit
        let currentUnitText = Encoding.UTF8.GetBytes(unitText paths request.OwnerId request.Configuration)
        let staticData = Encoding.UTF8.GetBytes(renderStaticWithPrevious request paths "" oldStatic)
        let dynamicData = Encoding.UTF8.GetBytes(renderDynamic request paths)
        let udpWithdrawalRestart =
            wasActive && oldStatic = Some staticData
            && udpUpdateRequiresRestart request.PreviousUdpEntryPoints oldDynamic (Some dynamicData) (Some staticData)
        let desiredCredentials = credentialData request.Configuration
        let credentialsChanged = oldCredentials <> desiredCredentials
        let liveStaticMatches =
            if wasActive && oldStatic = Some staticData then
                readApiStatic request.AdminPort
                |> fun operation -> operation.GetAwaiter().GetResult()
                |> fun api -> apiMatchesStatic api (Some staticData)
            else false
        let rootUid, rootGid = hostOwner environment
        let unitChanged = oldUnitBytes <> Some currentUnitText || not (metadataMatches environment paths.UnitPath "file" 0o644 rootUid rootGid)
        if wasActive && not (pinnedReleaseMatches environment paths request.OwnerId (architecture ()) actualBinaryHash) then
            fail "Apply refused: running service binary or release marker is not confirmed; reconcile the pinned release during maintenance"
        ensureAcmeIssuerTransitionSafe environment paths oldStatic request
        let restartRequired =
            (pending |> Option.exists (fun transaction -> transaction.RestartRequired))
            || (wasActive
                && (oldStatic <> Some staticData
                    || credentialsChanged
                    || unitChanged
                    || not liveStaticMatches
                    || udpWithdrawalRestart
                    || actualBinaryHash <> oldBinaryHash))
        let recordStart = recordManagedStart environment paths request.OwnerId
        let previouslyAttested = wasActive && attestedStatic environment paths request.OwnerId oldStatic
        let priorReceipt =
            if previouslyAttested then oldStatic |> Option.bind (staticReceipt environment request.OwnerId) |> Option.map sha256Bytes
            else None
        if wasActive && not previouslyAttested && (restartRequired || udpWithdrawalRequiresRestart (Some dynamicData) oldDynamic oldStatic) then
            fail "Apply refused: restart requires a confirmed static file for this service invocation. Back up configuration, reconcile its source, then stop the owned service in a maintenance window for a managed Apply."
        let oldCertificateFiles =
            match pending with
            | Some transaction -> Set.ofList transaction.CertificateFiles
            | None -> entries paths.CertificateDir |> Set.ofArray
        let confirmUnchanged () =
            if capture () <> initial then
                fail "Apply refused: rollback files changed after inspection; preserve concurrent edits and retry with a reconciled configuration."
        confirmUnchanged ()
        savePendingTransaction environment paths request.OwnerId oldStatic oldDynamic oldCredentials oldUnitBytes oldReleaseMarker oldBinaryExists oldBinaryHash wasActive wasEnabled restartRequired (Set.toList oldCertificateFiles)
        let stagedJournal = readBytes environment paths.RollbackPath
        // A conflict here is not an activation failure: no candidate file was installed.
        // The generic rollback handler must not replace the newly observed external bytes.
        try confirmUnchanged ()
        with error ->
            if not hasPending then removePendingTransaction environment paths request.OwnerId
            raise error
        let mutable binaryChanged = false
        let mutable restartAttempted = false
        let mutable candidateJob = None
        try
            binaryChanged <- ensureInstalledBinary environment paths request.OwnerId (not wasActive)
            writeCredentialFile environment paths request.Configuration
            writeCertificateFiles environment paths request serviceGroup
            confirmUnchanged ()
            ensureGroupedAtomicWrite environment (Path.Combine(paths.ConfigDir, "static.yml")) staticData 0o640 serviceGroup
            ensureGroupedAtomicWrite environment (Path.Combine(paths.DynamicDir, "current.yml")) dynamicData 0o640 serviceGroup
            if unitChanged then
                writeAtomic environment paths.UnitPath currentUnitText 0o644 (Some rootGid)
                daemonReload environment
            if not (isEnabled environment) then enableService environment
            let needsStart = not (isActive environment)
            if (needsStart || restartRequired || binaryChanged) &&
               (capture () <> struct (Some staticData, Some dynamicData) || readCredentialSnapshot environment paths <> desiredCredentials ||
                safeUnitStatus environment paths.UnitPath request.OwnerId <> Some currentUnitText) then fail "candidate changed before managed start"
            if needsStart then
                if wasActive then restartAttempted <- true
                candidateJob <- Some(enqueueServiceJob environment false)
            elif binaryChanged || restartRequired then
                restartAttempted <- true
                candidateJob <- Some(enqueueServiceJob environment true)
            let result = waitForActivation environment requestElement paths activationTimeout candidateJob
            if not (result["inSync"].GetValue<bool>()) then fail "Traefik activation did not satisfy the bounded readiness checks"
            candidateJob |> Option.iter (fun job -> recordStart staticData (receiptForJob environment request.OwnerId staticData job))
            removePendingTransaction environment paths request.OwnerId
            try removeUnusedCertificates environment paths request with :? BackendError -> ()
            result["actualConfigHash"] <- JsonValue.Create(actualConfigHash environment paths)
            result
        with error ->
            let failureReason =
                match error with
                | :? BackendError -> error.Message
                | _ -> error.GetType().Name
            let rollbackFailure =
                try
                    if isActive environment && (candidateJob |> Option.exists (fun job -> (managedJobInvocation environment job).IsNone)) then
                        fail "active invocation does not belong to the candidate job; rollback refused before stopping or writing"
                    let currentOwnedUnit = safeUnitStatus environment paths.UnitPath request.OwnerId
                    let currentStatic = readOptional environment (Path.Combine(paths.ConfigDir, "static.yml"))
                    let currentDynamic = readOptional environment (Path.Combine(paths.DynamicDir, "current.yml"))
                    if (currentStatic <> oldStatic && currentStatic <> Some staticData)
                       || (currentDynamic <> oldDynamic && currentDynamic <> Some dynamicData) then
                        fail "rollback stopped before overwriting an externally changed configuration file; preserve the files and reconcile the pending transaction"
                    let currentCredentials = readCredentialSnapshot environment paths
                    let currentUnitData = readOptional environment paths.UnitPath
                    if (currentCredentials <> oldCredentials && currentCredentials <> desiredCredentials)
                       || (currentUnitData <> oldUnitBytes && currentUnitData <> Some currentUnitText) then
                        fail "rollback refused to overwrite an externally changed credential or unit"
                    let currentBinaryExists = assertRegular environment paths.BinaryPath "Traefik binary"
                    let currentBinaryHash = if currentBinaryExists then Some(binarySha256 environment paths.BinaryPath) else None
                    let rollbackUdpWithdrawal = udpWithdrawalRequiresRestart currentDynamic oldDynamic oldStatic
                    let rollbackRestartRequired =
                        restartAttempted
                        || currentBinaryHash <> oldBinaryHash
                        || rollbackUdpWithdrawal
                    let currentActive = isActive environment
                    if currentOwnedUnit.IsSome && currentActive && (rollbackRestartRequired || not wasActive) then
                        stopOwnedService environment paths request.OwnerId
                    elif currentOwnedUnit.IsNone && currentActive then
                        fail "interrupted Traefik service has no owned unit"
                    if currentStatic <> oldStatic then
                        restoreFile environment (Path.Combine(paths.ConfigDir, "static.yml")) oldStatic 0o640 (Some serviceGroup)
                    if currentDynamic <> oldDynamic then
                        restoreFile environment (Path.Combine(paths.DynamicDir, "current.yml")) oldDynamic 0o640 (Some serviceGroup)
                    if currentCredentials <> oldCredentials then
                        restoreFile environment paths.CredentialsPath oldCredentials 0o600 None
                    if currentUnitData <> oldUnitBytes then restoreFile environment paths.UnitPath oldUnitBytes 0o644 None
                    let releaseMarkerPath = Path.Combine(paths.InstallDir, ".keroosha-release.json")
                    if not oldBinaryExists then
                        if currentBinaryExists then
                            File.Delete(paths.BinaryPath)
                            fsyncDirectory (Path.GetDirectoryName(paths.BinaryPath))
                        if readOptional environment releaseMarkerPath <> oldReleaseMarker then
                            restoreFile environment releaseMarkerPath oldReleaseMarker 0o644 None
                    elif currentBinaryHash = oldBinaryHash && readOptional environment releaseMarkerPath <> oldReleaseMarker then
                        restoreFile environment releaseMarkerPath oldReleaseMarker 0o644 None
                    removeExtraCertificateFiles environment paths oldCertificateFiles "cannot remove interrupted Traefik certificate material"
                    if currentUnitData <> oldUnitBytes then daemonReload environment
                    if oldUnitBytes.IsSome then ensureEffectiveUnit environment paths
                    if isEnabled environment <> wasEnabled then
                        if wasEnabled then enableService environment else disableService environment
                    if isEnabled environment <> wasEnabled then fail "previous Traefik enablement state was not restored"
                    if wasActive then
                        let rollbackStarts = rollbackRestartRequired || not (isActive environment)
                        let rollbackJob =
                            if rollbackStarts then
                                if isActive environment then stopOwnedService environment paths request.OwnerId
                                if readOptional environment staticPath <> oldStatic || readOptional environment dynamicPath <> oldDynamic
                                   || readCredentialSnapshot environment paths <> oldCredentials || safeUnitStatus environment paths.UnitPath request.OwnerId <> oldUnitBytes
                                   || (oldBinaryExists && Some(binarySha256 environment paths.BinaryPath) <> oldBinaryHash) then fail "rollback preimage changed before managed start"
                                Some(enqueueServiceJob environment false)
                            else None
                        if not (waitForRollback environment paths activationTimeout oldStatic oldDynamic oldCredentials) then
                            match rollbackJob, priorReceipt, oldStatic with
                            | Some job, Some prior, Some bytes when not restartRequired && readOptional environment staticPath = Some bytes && readOptional environment dynamicPath = oldDynamic ->
                                let api = (readApi request.AdminPort).GetAwaiter().GetResult()
                                match managedJobInvocation environment job with
                                | Some id when apiMatchesStatic api oldStatic && loadedRollbackGraph api oldDynamic
                                               && (readOptional environment paths.StaticReceipt |> Option.map sha256Bytes) = Some prior ->
                                    let generation = transactionPreimage (JsonNode.Parse(stagedJournal).AsObject())
                                    persistRecovery environment paths stagedJournal { Job = job; Invocation = id; PriorReceipt = prior; Preimage = generation; Target = None } (fun () ->
                                        if managedJobInvocation environment job <> Some id || readOptional environment staticPath <> oldStatic ||
                                           readOptional environment dynamicPath <> oldDynamic || readCredentialSnapshot environment paths <> oldCredentials then
                                            fail "rollback start or preimage changed before committing recovery witness") |> ignore
                                | _ -> ()
                            | _ -> ()
                            fail "previous Traefik configuration could not be verified"
                        if rollbackStarts && previouslyAttested then
                            let id = rollbackJob |> Option.bind (managedJobInvocation environment) |> Option.defaultWith (fun () -> fail "rollback readiness passed but its systemd start job cannot be attributed")
                            match oldStatic with
                            | Some bytes -> recordStart bytes (Some(Encoding.UTF8.GetBytes(String.concat "\n" [ request.OwnerId; id; Convert.ToHexString(SHA256.HashData bytes) ])))
                            | None -> fail "verified static rollback bytes are missing"
                    if isActive environment <> wasActive then fail "previous Traefik service state was not restored"
                    removePendingTransaction environment paths request.OwnerId
                    None
                with rollbackError ->
                    let detail =
                        match rollbackError with
                        | :? BackendError -> rollbackError.Message
                        | _ -> rollbackError.GetType().Name
                    Some detail
            match rollbackFailure with
            | None -> fail ("Traefik activation failed; the prior configuration was restored: " + failureReason)
            | Some detail ->
                fail ("Traefik activation failed; the prior configuration could not be verified (" + failureReason + "): " + detail)

    /// An interrupted rename leaves either the preimage or the target. A target
    /// already on disk before binding is not evidence of an interrupted retry.
    let internal recoveryDiskAccepted (bound: string option) (target: string) atPreimage atTarget =
        match bound with
        | None -> atPreimage
        | Some expected -> expected = target && (atPreimage || atTarget)

    let private repairDynamic environment requestElement (request: Request) (paths: RuntimePaths) timeout (journal: PendingTransaction) phase =
        let refuse message = fail ("dynamic recovery refused: " + message)
        let staticBytes = Option.defaultWith (fun () -> refuse "missing static preimage") journal.Static
        let desired = Encoding.UTF8.GetBytes(renderDynamic request paths)
        let target = sha256Bytes desired
        if phase.Target |> Option.exists ((<>) target) then refuse "this transaction is already bound to another target"
        if not journal.WasActive || journal.RestartRequired || not journal.CredentialsKnown
           || Encoding.UTF8.GetBytes(renderStaticWithPrevious request paths "" journal.Static) <> staticBytes
           || journal.Credentials <> credentialData request.Configuration
           || journal.Unit <> Some(Encoding.UTF8.GetBytes(unitText paths request.OwnerId request.Configuration))
           || udpUpdateRequiresRestart request.PreviousUdpEntryPoints journal.Dynamic (Some desired) journal.Static then
            refuse "the request requires more than a dynamic file update"
        let receipt = Encoding.UTF8.GetBytes(String.concat "\n" [ request.OwnerId; phase.Invocation; Convert.ToHexString(SHA256.HashData staticBytes) ])
        let file = Path.Combine(paths.DynamicDir, "current.yml")
        let uid, gid = hostOwner environment
        let _, group = serviceAccountOwner environment
        let verifyBindings staged =
            if not (metadataMatches environment paths.RollbackPath "file" 0o600 uid gid) || readBytes environment paths.RollbackPath <> staged then refuse "journal generation changed"
            if managedJobInvocation environment phase.Job <> Some phase.Invocation then refuse "rollback start is no longer the running invocation"
            let current = readOptional environment file
            let prior = readOptional environment paths.StaticReceipt
            if not (metadataMatches environment paths.StaticReceipt "file" 0o600 uid gid)
               || ((prior |> Option.map sha256Bytes) <> Some phase.PriorReceipt && not (phase.Target = Some target && current = Some desired && prior = Some receipt)) then refuse "previous static confirmation changed"
            let config, state, install, unit = validateActualOwner environment paths request.OwnerId
            if config <> "owned" || state <> "owned" || install <> "owned" || unit <> journal.Unit then refuse "owner or systemd unit changed"
            if not (unitMatches environment paths) then refuse "effective systemd unit changed"
            if readOptional environment (Path.Combine(paths.ConfigDir,"static.yml")) <> journal.Static then refuse "static file changed"
            if readCredentialSnapshot environment paths <> journal.Credentials then refuse "credential file changed"
            if not journal.BinaryPresent || Some(binarySha256 environment paths.BinaryPath) <> journal.BinarySha256
               || readOptional environment (Path.Combine(paths.InstallDir,".keroosha-release.json")) <> journal.ReleaseMarker then refuse "binary or release changed"
            if not (filesystemMetadataMatches environment paths) || isEnabled environment <> journal.WasEnabled then refuse "owned metadata or service enablement changed"
            let files = Set.ofArray (entries paths.CertificateDir)
            let mutable required = Set.singleton ".keroosha-owner"
            for KeyValue(_, certificate) in request.Certificates do
                let digest = materialDigest certificate
                for suffix, text in [ ".crt", certificate.CertificatePem; ".key", certificate.PrivateKeyPem ] do
                    let name = digest + suffix
                    required <- Set.add name required
                    if readOptional environment (Path.Combine(paths.CertificateDir,name)) <> Some(Encoding.UTF8.GetBytes(text:string)) then refuse "certificate material changed"
            if files <> Set.ofList journal.CertificateFiles || required <> files then refuse "certificate inventory changed"
            current
        let mutable staged = readBytes environment paths.RollbackPath
        if sha256Bytes staged <> journal.JournalSha256 then refuse "journal changed since decoding"
        let current = verifyBindings staged
        let api = (readApi request.AdminPort).GetAwaiter().GetResult()
        if not (apiMatchesStatic api journal.Static) then refuse "live static policy changed"
        if not (recoveryDiskAccepted phase.Target target (current = journal.Dynamic) (current = Some desired)) then refuse "external dynamic bytes do not belong to this step"
        if current = journal.Dynamic then
            if not (loadedRollbackGraph api current) then refuse "restored dynamic preimage no longer matches the live graph"
        if phase.Target.IsNone then
            staged <- persistRecovery environment paths staged { phase with Target = Some target } (fun () ->
                if verifyBindings staged <> current then refuse "bindings changed before target claim")
        if verifyBindings staged <> current then refuse "preimage changed during admission"
        if current <> Some desired then
            writeRecoveryFile environment paths phase.Preimage file desired 0o640 group true (fun () ->
                if verifyBindings staged <> current then refuse "preimage changed before target rename")
        let result = waitForActivation environment requestElement paths timeout None
        if not (result["inSync"].GetValue<bool>()) then
            let verifyUndo () =
                if verifyBindings staged <> Some desired then refuse "failed target changed; retain journal for offline maintenance"
                let observed = (readApi request.AdminPort).GetAwaiter().GetResult()
                if not (apiMatchesStatic observed journal.Static && (loadedRollbackGraph observed (Some desired) || loadedRollbackGraph observed journal.Dynamic)) then
                    refuse "failed target is not attributable; use offline maintenance"
            match journal.Dynamic with
            | Some old when not (udpWithdrawalRequiresRestart (Some desired) journal.Dynamic journal.Static) ->
                verifyUndo ()
                writeRecoveryFile environment paths phase.Preimage file old 0o640 group true verifyUndo
                let deadline = Stopwatch.StartNew()
                let mutable restored = false
                while not restored && deadline.Elapsed.TotalSeconds < timeout do
                    let observed = (readApi request.AdminPort).GetAwaiter().GetResult()
                    restored <- verifyBindings staged = journal.Dynamic && apiMatchesStatic observed journal.Static && loadedRollbackGraph observed journal.Dynamic
                    if not restored then Thread.Sleep(ActivationPollMilliseconds)
                if restored then refuse "failed target restored to its attributed preimage, not certified healthy; use offline maintenance to change target"
                else refuse "dynamic preimage was restored on disk but not verified live; use offline maintenance"
            | _ -> refuse "bound target failed readiness; safe withdrawal requires a restart; use offline maintenance"
        if verifyBindings staged <> Some desired then refuse "target changed during readiness"
        recordManagedStart environment paths request.OwnerId staticBytes (Some receipt)
        removePendingTransaction environment paths request.OwnerId
        result["actualConfigHash"] <- JsonValue.Create(actualConfigHash environment paths)
        result

    let private apply environment requestElement timeout =
        let request = validateRequest requestElement
        let paths = pathsFor environment
        match loadPendingTransaction environment paths request.OwnerId with
        | Some ({ Recovery = Some phase } as journal) -> repairDynamic environment requestElement request paths timeout journal phase
        | _ -> applyTransaction environment requestElement timeout

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
        let configStatus, stateStatus, installStatus, _ = checkLayoutCollisions environment paths request.OwnerId
        let unitData = safeUnitStatus environment paths.UnitPath request.OwnerId
        if configStatus = "absent" && stateStatus = "absent" && installStatus = "absent" && unitData.IsNone then JsonObject()
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
            removeCredentialFile environment paths
            removeOwnedTree environment paths.ConfigDir request.OwnerId "configuration directory"
            removeOwnedTree environment paths.InstallDir request.OwnerId "installation directory"
            JsonObject()

    let private rootRequired (environment: HostEnvironment) : unit =
        let result = run environment "id" [ "-u" ]
        if result.ExitCode <> 0 || result.Stdout.Trim() <> "0" then fail "Traefik host operations require root privileges"

#if TRAEFIK_MAINTENANCE
    /// Compiled only into the standalone administrator binary. Never dispatch
    /// through the deployment helper (which may itself have passwordless sudo).
    let maintainStopped owner (expected: string) =
        let environment = HostEnvironment.system
        let paths = pathsFor environment
        rootRequired environment
        let ownerHash = ownerDigest owner
        if not (fingerprintPattern.IsMatch(expected)) then fail "expected full lowercase journal SHA-256"
        use guard = HostFiles.lockFile "/run/lock/keroosha-iac-traefik.lock"
        let uid, gid = hostOwner environment
        let _, serviceGroup = serviceAccountOwner environment
        let verifyStopped () =
            if not (isStopped environment) || not (unitMatches environment paths) then fail "operator must stop the owned unit and wait for all jobs"
        verifyStopped ()
        let archiveDir = Path.Combine(Path.GetDirectoryName(paths.ConfigDir), ".dorothy-traefik-recovery")
        let archive = Path.Combine(archiveDir, ownerHash + "-" + expected + ".journal")
        let verifiedArchive () =
            metadataMatches environment archiveDir "directory" 0o700 uid gid &&
            metadataMatches environment archive "file" 0o600 uid gid &&
            sha256Bytes (readBytes environment archive) = expected
        match loadPendingTransaction environment paths owner with
        | None when verifiedArchive () -> fsyncDirectory paths.ConfigDir
        | None -> fail "no pending journal or matching completed archival handoff"
        | Some journal ->
            if journal.JournalSha256 <> expected || not journal.CredentialsKnown || not journal.BinaryPresent then fail "journal hash mismatch or incomplete protected preimage"
            let dynamicPath = Path.Combine(paths.DynamicDir, "current.yml")
            let old = journal.Dynamic |> Option.defaultWith (fun () -> fail "missing dynamic preimage")
            let verify () =
                verifyStopped ()
                if not (metadataMatches environment paths.RollbackPath "file" 0o600 uid gid) || sha256Bytes (readBytes environment paths.RollbackPath) <> expected then fail "journal changed during maintenance"
                let c,s,i,unit = validateActualOwner environment paths owner
                if (c,s,i) <> ("owned","owned","owned") || unit <> journal.Unit || unit.IsNone || not (filesystemMetadataMatches environment paths) then fail "ownership, metadata or unit differs"
                if readOptional environment (Path.Combine(paths.ConfigDir,"static.yml")) <> journal.Static || journal.Static.IsNone ||
                   readCredentialSnapshot environment paths <> journal.Credentials || Some(binarySha256 environment paths.BinaryPath) <> journal.BinarySha256 ||
                   readOptional environment (Path.Combine(paths.InstallDir,".keroosha-release.json")) <> journal.ReleaseMarker then fail "protected preimage differs; no automatic overwrite"
                let files = Set.ofArray(entries paths.CertificateDir)
                if files <> Set.ofList journal.CertificateFiles || markerStatus environment paths.CertificateDir owner <> "owned" then fail "certificate inventory differs"
                for filename in files do
                    if filename <> ".keroosha-owner" then
                        let stem = Path.GetFileNameWithoutExtension(filename)
                        let crt = Path.Combine(paths.CertificateDir, stem + ".crt")
                        let key = Path.Combine(paths.CertificateDir, stem + ".key")
                        if not (metadataMatches environment crt "file" 0o640 uid serviceGroup && metadataMatches environment key "file" 0o640 uid serviceGroup) then fail "unattributable certificate pair"
                        if filename.EndsWith(".crt", StringComparison.Ordinal) then
                            use hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
                            hash.AppendData(readBytes environment crt)
                            hash.AppendData([|0uy|])
                            hash.AppendData(readBytes environment key)
                            if Convert.ToHexStringLower(hash.GetHashAndReset()) <> stem then fail "certificate contents differ"
                let current = readBytes environment dynamicPath
                if current <> old && (journal.Recovery |> Option.bind (fun w -> w.Target)) <> Some(sha256Bytes current) then fail "dynamic file is neither preimage nor transaction target"
                current
            let current = verify ()
            let unchanged () = if verify () <> current then fail "preimage changed before maintenance commit"
            let journalBytes = readBytes environment paths.RollbackPath
            if sha256Bytes journalBytes <> expected then fail "journal changed before archival"
            writeRecoveryFile environment paths expected archive journalBytes 0o600 gid false unchanged
            let archived () = unchanged (); if not (verifiedArchive ()) then fail "archive integrity lost"
            archived ()
            if current <> old then writeRecoveryFile environment paths expected dynamicPath old 0o640 serviceGroup true archived
            if verify () <> old || not (verifiedArchive ()) then fail "restored preimage or archive not verified"
            File.Delete(paths.RollbackPath)
            fsyncDirectory paths.ConfigDir
#endif

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
        | :? TraefikSettings.InvalidConfiguration as error -> fail error.Message
        | _ -> fail "Traefik backend failed unexpectedly"
