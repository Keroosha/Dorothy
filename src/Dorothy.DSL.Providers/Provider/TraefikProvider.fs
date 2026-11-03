namespace Dorothy.DSL.Provider

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private TraefikProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:Traefik"

    [<Literal>]
    let private DefaultCaServer = "https://acme-v02.api.letsencrypt.org/directory"

    type NormalizedInputs =
        { Values: Dictionary<string, PropertyValue>
          HasUnknowns: bool
          Failures: ResizeArray<CheckFailure> }

    type ParsedInputs =
        { Values: Dictionary<string, PropertyValue>
          Connection: SshConnection
          Config: TraefikConfig }

    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "resources": {
    "keroosha:debian:Traefik": {
      "description": "Manages one owned native Traefik instance on an existing Debian host.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "entryPoints": { "type": "object", "additionalProperties": { "type": "integer" } },
        "resolvers": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "properties": {
              "email": { "type": "string" },
              "httpChallengeEntryPoint": { "type": "string" },
              "caServer": { "type": "string", "default": "https://acme-v02.api.letsencrypt.org/directory" }
            },
            "required": ["email", "httpChallengeEntryPoint"]
          }
        },
        "routers": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "properties": {
              "host": { "type": "string" },
              "entryPoint": { "type": "string" },
              "backend": { "type": "string" },
              "tls": {
                "type": "object",
                "properties": {
                  "kind": { "type": "string", "enum": ["none", "acme", "provided"] },
                  "name": { "type": "string" }
                },
                "required": ["kind", "name"]
              }
            },
            "required": ["host", "entryPoint", "backend", "tls"]
          }
        },
        "certificates": {
          "type": "object",
          "secret": true,
          "additionalProperties": {
            "type": "object",
            "properties": {
              "certificatePem": { "type": "string" },
              "privateKeyPem": { "type": "string", "secret": true },
              "fingerprint": { "type": "string" }
            },
            "required": ["certificatePem", "privateKeyPem", "fingerprint"]
          }
        },
        "adminPort": { "type": "integer", "default": 19080 }
      },
      "requiredInputs": ["connection", "entryPoints", "resolvers", "routers", "certificates"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "entryPoints": { "type": "object", "additionalProperties": { "type": "integer" } },
        "resolvers": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "properties": {
              "email": { "type": "string" },
              "httpChallengeEntryPoint": { "type": "string" },
              "caServer": { "type": "string" }
            }
          }
        },
        "routers": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "properties": {
              "host": { "type": "string" },
              "entryPoint": { "type": "string" },
              "backend": { "type": "string" },
              "tls": {
                "type": "object",
                "properties": {
                  "kind": { "type": "string", "enum": ["none", "acme", "provided"] },
                  "name": { "type": "string" }
                }
              }
            }
          }
        },
        "certificates": {
          "type": "object",
          "secret": true,
          "additionalProperties": {
            "type": "object",
            "properties": {
              "certificatePem": { "type": "string" },
              "privateKeyPem": { "type": "string", "secret": true },
              "fingerprint": { "type": "string" }
            }
          }
        },
        "adminPort": { "type": "integer" },
        "inSync": { "type": "boolean" },
        "actualConfigHash": { "type": "string" },
        "certificateFingerprints": { "type": "object", "additionalProperties": { "type": "string" } }
      },
      "required": ["connection", "entryPoints", "resolvers", "routers", "certificates", "adminPort", "inSync", "actualConfigHash", "certificateFingerprints"]
    }
  }
}"""

    let private declarativeProperties = [ "connection"; "entryPoints"; "resolvers"; "routers"; "certificates"; "adminPort" ]
    let private outputProperties = [ "inSync"; "actualConfigHash"; "certificateFingerprints" ]
    let private knownProperties = Set.ofList declarativeProperties

    let private tryGetMap (value: PropertyValue) =
        let mutable result = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&result) then Some result else None

    let private tryGetArray (value: PropertyValue) =
        let mutable result = ImmutableArray<PropertyValue>.Empty
        if value.TryGetArray(&result) then Some result else None

    let private tryGetString (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>
        if value.TryGetString(&result) then Some result else None

    let private addFailure (failures: ResizeArray<CheckFailure>) property reason =
        failures.Add(CheckFailure(property, reason))

    let private inputDictionary (values: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in values do
            result.Add(entry.Key, entry.Value)
        result

    let rec private containsUnknown (value: PropertyValue) =
        if value.IsComputed then
            true
        else
            match tryGetMap value with
            | Some values -> values.Values |> Seq.exists containsUnknown
            | None ->
                match tryGetArray value with
                | Some values -> values |> Seq.exists containsUnknown
                | None -> false

    let private hasUnknownInputs (values: ImmutableDictionary<string, PropertyValue>) =
        values.Values |> Seq.exists containsUnknown

    let private markCertificatesSecret (values: Dictionary<string, PropertyValue>) =
        match values.TryGetValue("certificates") with
        | true, value when value.IsSecret -> ()
        | true, value ->
            match tryGetMap value with
            | Some contents ->
                values["certificates"] <- PropertyValue(contents, IsSecret = true, Dependencies = value.Dependencies)
            | None -> ()
        | false, _ -> ()

    let private mapWithMetadata (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) =
        PropertyValue(values, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private numberWithMetadata (source: PropertyValue) (number: float) =
        PropertyValue(number, IsSecret = source.IsSecret, Dependencies = source.Dependencies)

    let private stringWithMetadata (source: PropertyValue) (text: string) =
        PropertyValue(text, IsSecret = source.IsSecret, Dependencies = source.Dependencies)
    let private normalizeKnownDefaults (normalized: Dictionary<string, PropertyValue>) =
        match normalized.TryGetValue("connection") with
        | true, source ->
            match tryGetMap source with
            | Some fields ->
                let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                for entry in fields do
                    builder[entry.Key] <- entry.Value
                match fields.TryGetValue("port") with
                | false, _ -> builder["port"] <- PropertyValue(22.0)
                | true, port when port.IsNull -> builder["port"] <- numberWithMetadata port 22.0
                | _ -> ()
                normalized["connection"] <- mapWithMetadata source (builder.ToImmutable())
            | None -> ()
        | false, _ -> ()

        match normalized.TryGetValue("resolvers") with
        | true, source ->
            match tryGetMap source with
            | Some entries ->
                let resolvers = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                for entry in entries do
                    match tryGetMap entry.Value with
                    | Some fields ->
                        let resolver = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
                        for field in fields do
                            resolver[field.Key] <- field.Value
                        match fields.TryGetValue("caServer") with
                        | false, _ -> resolver["caServer"] <- PropertyValue(DefaultCaServer)
                        | true, caServer when caServer.IsNull -> resolver["caServer"] <- stringWithMetadata caServer DefaultCaServer
                        | _ -> ()
                        resolvers[entry.Key] <- mapWithMetadata entry.Value (resolver.ToImmutable())
                    | None -> resolvers[entry.Key] <- entry.Value
                normalized["resolvers"] <- mapWithMetadata source (resolvers.ToImmutable())
            | None -> ()
        | false, _ -> ()

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let reasons = failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " "
            invalidOp reasons

    let private tryMap (value: PropertyValue) =
        match tryGetMap value with
        | Some result -> result
        | None -> invalidOp "Traefik configuration must contain object values."

    let private requiredValue (name: string) (values: ImmutableDictionary<string, PropertyValue>) =
        match values.TryGetValue(name) with
        | true, value when not value.IsComputed -> value
        | _ -> invalidOp "A required Traefik property is missing or unknown."

    let private requiredString (name: string) (values: ImmutableDictionary<string, PropertyValue>) =
        match tryGetString (requiredValue name values) with
        | Some value when not (String.IsNullOrWhiteSpace(value)) -> value
        | _ -> invalidOp "A required Traefik string property is invalid."

    let private optionalString (name: string) (defaultValue: string) (values: ImmutableDictionary<string, PropertyValue>) =
        match values.TryGetValue(name) with
        | false, _ -> defaultValue
        | true, value when value.IsNull -> defaultValue
        | true, value when value.IsComputed -> invalidOp "A Traefik string property is unknown."
        | true, value ->
            match tryGetString value with
            | Some text when not (String.IsNullOrWhiteSpace(text)) -> text
            | _ -> invalidOp "A Traefik string property is invalid."


    let private optionalInteger (name: string) (defaultValue: int) (values: ImmutableDictionary<string, PropertyValue>) =
        match values.TryGetValue(name) with
        | false, _ -> defaultValue
        | true, value when value.IsNull -> defaultValue
        | true, value when value.IsComputed -> invalidOp "A Traefik integer property is unknown."
        | true, value ->
            let mutable number = 0.0
            if not (value.TryGetNumber(&number)) || Double.IsNaN(number) || Double.IsInfinity(number) || number <> Math.Truncate(number) then
                invalidOp "A Traefik integer property is invalid."
            int number

    let private validIdentifier (value: string) =
        not (String.IsNullOrWhiteSpace(value))
        && value.Length <= 63
        && ((value[0] >= 'a' && value[0] <= 'z')
            || (value[0] >= 'A' && value[0] <= 'Z')
            || (value[0] >= '0' && value[0] <= '9'))
        && (value |> Seq.forall (fun character ->
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character = '.'
            || character = '_'
            || character = '-'))

    let private requireIdentifier (path: string) (value: string) =
        let reserved =
            (String.Equals(path, "entryPoints", StringComparison.Ordinal)
             && (String.Equals(value, "keroosha-admin", StringComparison.OrdinalIgnoreCase)
                 || String.Equals(value, "traefik", StringComparison.OrdinalIgnoreCase)))
            || (String.Equals(path, "routers", StringComparison.Ordinal)
                && String.Equals(value, "keroosha-admin", StringComparison.OrdinalIgnoreCase))
        if not (validIdentifier value) || reserved then
            invalidOp (path + " must be a non-empty Traefik identifier.")
    let private validateSshConnection (connection: SshConnection) =
        let hasInvalidCharacter (value: string) =
            value |> Seq.exists (fun character -> Char.IsControl(character) || Char.IsWhiteSpace(character))

        if String.IsNullOrWhiteSpace(connection.Address)
           || connection.Address.StartsWith("-", StringComparison.Ordinal)
           || connection.Address.Contains('@')
           || hasInvalidCharacter connection.Address then
            invalidOp "Traefik connection address is invalid."
        if String.IsNullOrWhiteSpace(connection.User)
           || connection.User.StartsWith("-", StringComparison.Ordinal)
           || connection.User.Contains('/')
           || connection.User.Contains('@')
           || hasInvalidCharacter connection.User then
            invalidOp "Traefik connection user is invalid."
        if connection.Port < 1 || connection.Port > 65535 then
            invalidOp "Traefik connection port is invalid."
        match connection.IdentityFile with
        | Some path when String.IsNullOrWhiteSpace(path) || path.Contains('\000') ->
            invalidOp "Traefik connection identityFile is invalid."
        | _ -> ()

    let private parseConnection (value: PropertyValue) =
        let values = tryMap value
        for entry in values do
            if entry.Key <> "address" && entry.Key <> "user" && entry.Key <> "port" && entry.Key <> "identityFile" then
                invalidOp "Traefik connection contains an unsupported property."
        let address = requiredString "address" values
        let user = requiredString "user" values
        let port = optionalInteger "port" 22 values
        let identityFile =
            match values.TryGetValue("identityFile") with
            | false, _ -> None
            | true, identity when identity.IsNull -> None
            | true, identity when identity.IsComputed -> invalidOp "Traefik identityFile is unknown."
            | true, identity ->
                match tryGetString identity with
                | Some path when not (String.IsNullOrWhiteSpace(path)) -> Some path
                | _ -> invalidOp "Traefik identityFile is invalid."
        let connection =
            { Address = address
              User = user
              Port = port
              IdentityFile = identityFile }
        validateSshConnection connection
        connection

    let private validateEmail (email: string) =
        email.Length <= 254
        && not (email |> Seq.exists Char.IsControl)
        && (try
                let address = System.Net.Mail.MailAddress(email)
                String.Equals(address.Address, email, StringComparison.Ordinal)
            with _ -> false)

    let private validateCaUri (value: string) =
        let mutable uri = Unchecked.defaultof<Uri>
        value.Length <= 2048
        && not (value |> Seq.exists Char.IsControl)
        && Uri.TryCreate(value, UriKind.Absolute, &uri)
        && (uri.Scheme = Uri.UriSchemeHttps || uri.Scheme = Uri.UriSchemeHttp)
        && String.IsNullOrEmpty(uri.UserInfo)
        && String.IsNullOrEmpty(uri.Query)
        && String.IsNullOrEmpty(uri.Fragment)
    let private parseEntryPoints (value: PropertyValue) =
        let values = tryMap value
        let builder = ImmutableDictionary.CreateBuilder<string, int>(StringComparer.Ordinal)
        let ports = HashSet<int>()
        for entry in values do
            requireIdentifier "entryPoints" entry.Key
            if entry.Value.IsComputed then invalidOp "A Traefik entryPoint port is unknown."
            let mutable number = 0.0
            if not (entry.Value.TryGetNumber(&number))
               || Double.IsNaN(number)
               || Double.IsInfinity(number)
               || number <> Math.Truncate(number)
               || number < 1.0
               || number > 65535.0 then
                invalidOp "A Traefik entryPoint port must be an integer from 1 through 65535."
            let port = int number
            if not (ports.Add(port)) then
                invalidOp "Traefik entryPoint ports must be unique."
            builder.Add(entry.Key, port)
        builder.ToImmutable()

    let private parseResolvers (value: PropertyValue) (entryPoints: ImmutableDictionary<string, int>) =
        let values = tryMap value
        let builder = ImmutableDictionary.CreateBuilder<string, TraefikResolver>(StringComparer.Ordinal)
        for entry in values do
            requireIdentifier "resolvers" entry.Key
            let fields = tryMap entry.Value
            for field in fields do
                if field.Key <> "email" && field.Key <> "httpChallengeEntryPoint" && field.Key <> "caServer" then
                    invalidOp "A Traefik resolver contains an unsupported property."
            let email = requiredString "email" fields
            if not (validateEmail email) then invalidOp "A Traefik resolver email address is invalid."
            let httpChallengeEntryPoint = requiredString "httpChallengeEntryPoint" fields
            if not (entryPoints.ContainsKey(httpChallengeEntryPoint)) then
                invalidOp "A Traefik resolver references an undeclared HTTP challenge entryPoint."
            let caServer = optionalString "caServer" DefaultCaServer fields
            if not (validateCaUri caServer) then invalidOp "A Traefik ACME CA server URL is invalid."
            builder.Add(
                entry.Key,
                { Email = email
                  HttpChallengeEntryPoint = httpChallengeEntryPoint
                  CaServer = caServer }
            )
        builder.ToImmutable()

    let private parseTls (value: PropertyValue) =
        let fields = tryMap value
        for field in fields do
            if field.Key <> "kind" && field.Key <> "name" then
                invalidOp "A Traefik router TLS declaration contains an unsupported property."
        let kind = requiredString "kind" fields
        let name =
            match fields.TryGetValue("name") with
            | false, _ -> ""
            | true, field when field.IsComputed -> invalidOp "A Traefik router TLS name is unknown."
            | true, field when field.IsNull -> ""
            | true, field ->
                match tryGetString field with
                | Some text -> text
                | None -> invalidOp "A Traefik router TLS name is invalid."
        if kind <> "none" && kind <> "acme" && kind <> "provided" then
            invalidOp "A Traefik router TLS kind must be none, acme, or provided."
        if kind = "none" && not (String.IsNullOrEmpty(name)) then
            invalidOp "A router without TLS must use an empty TLS name."
        if kind <> "none" && String.IsNullOrWhiteSpace(name) then
            invalidOp "A TLS-enabled router must name its certificate or ACME resolver."
        { Kind = kind; Name = name }

    let private validateRouterHost (host: string) =
        let hostName =
            if host.EndsWith(".", StringComparison.Ordinal) then host.Substring(0, host.Length - 1)
            else host
        let hostType = Uri.CheckHostName(hostName)
        let isAsciiLetterOrDigit character =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
        let validDnsName =
            try
                let ascii = System.Globalization.IdnMapping().GetAscii(hostName).ToLowerInvariant()
                let labels = ascii.Split('.')
                ascii.Length <= 253
                && (labels
                    |> Array.forall (fun label ->
                        label.Length >= 1
                        && label.Length <= 63
                        && isAsciiLetterOrDigit label[0]
                        && isAsciiLetterOrDigit label[label.Length - 1]
                        && (label |> Seq.forall (fun character -> isAsciiLetterOrDigit character || character = '-'))))
            with _ -> false
        host.Length <= 253
        && hostName.Length <= 253
        && not (host |> Seq.exists (fun character -> Char.IsControl(character) || Char.IsWhiteSpace(character)))
        && not (host.Contains('/') || host.Contains('*') || host.Contains('%'))
        && (hostType = UriHostNameType.IPv4 || hostType = UriHostNameType.IPv6 || validDnsName)

    let private validateBackend (backend: string) =
        let mutable uri = Unchecked.defaultof<Uri>
        backend.Length <= 2048
        && not (backend |> Seq.exists (fun character -> Char.IsControl(character)))
        && Uri.TryCreate(backend, UriKind.Absolute, &uri)
        && (uri.Scheme = Uri.UriSchemeHttp || uri.Scheme = Uri.UriSchemeHttps)
        && String.IsNullOrEmpty(uri.UserInfo)
        && String.IsNullOrEmpty(uri.Query)
        && String.IsNullOrEmpty(uri.Fragment)

    let private parseRouters
        (value: PropertyValue)
        (entryPoints: ImmutableDictionary<string, int>)
        (resolvers: ImmutableDictionary<string, TraefikResolver>)
        (certificates: ImmutableDictionary<string, NormalizedCertificate>)
        =
        let values = tryMap value
        let builder = ImmutableDictionary.CreateBuilder<string, TraefikRouter>(StringComparer.Ordinal)
        for entry in values do
            requireIdentifier "routers" entry.Key
            let fields = tryMap entry.Value
            for field in fields do
                if field.Key <> "host" && field.Key <> "entryPoint" && field.Key <> "backend" && field.Key <> "tls" then
                    invalidOp "A Traefik router contains an unsupported property."
            let host = requiredString "host" fields
            if not (validateRouterHost host) then invalidOp "A Traefik router host is invalid."
            let entryPoint = requiredString "entryPoint" fields
            if not (entryPoints.ContainsKey(entryPoint)) then
                invalidOp "A Traefik router references an undeclared entryPoint."
            let backend = requiredString "backend" fields
            if not (validateBackend backend) then invalidOp "A Traefik router backend must be an HTTP or HTTPS URL."
            let tls =
                match fields.TryGetValue("tls") with
                | true, tlsValue when not tlsValue.IsComputed -> parseTls tlsValue
                | _ -> invalidOp "A Traefik router TLS declaration is missing or unknown."
            if tls.Kind = "acme" && not (resolvers.ContainsKey(tls.Name)) then
                invalidOp "A Traefik router references an undeclared ACME resolver."
            if tls.Kind = "provided" && not (certificates.ContainsKey(tls.Name)) then
                invalidOp "A Traefik router references an undeclared provided certificate."
            builder.Add(
                entry.Key,
                { Host = host
                  EntryPoint = entryPoint
                  Backend = backend
                  Tls = tls }
            )
        builder.ToImmutable()

    let private parseCertificates (value: PropertyValue) =
        let values = tryMap value
        let builder = ImmutableDictionary.CreateBuilder<string, NormalizedCertificate>(StringComparer.Ordinal)
        for entry in values do
            requireIdentifier "certificates" entry.Key
            let fields = tryMap entry.Value
            for field in fields do
                if field.Key <> "certificatePem" && field.Key <> "privateKeyPem" && field.Key <> "fingerprint" then
                    invalidOp "A Traefik certificate contains an unsupported property."
            let certificatePem = requiredString "certificatePem" fields
            let privateKeyPem = requiredString "privateKeyPem" fields
            let fingerprint = requiredString "fingerprint" fields
            if fingerprint.Length <> 64 || (fingerprint |> Seq.exists (fun character -> not ((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))) then
                invalidOp "A Traefik certificate fingerprint must be a lowercase SHA-256 value."
            builder.Add(
                entry.Key,
                { Name = entry.Key
                  CertificatePem = certificatePem
                  PrivateKeyPem = privateKeyPem
                  Fingerprint = fingerprint }
            )
        builder.ToImmutable()

    let private parseConfig (values: Dictionary<string, PropertyValue>) : TraefikConfig =
        let requiredMap name =
            match values.TryGetValue(name) with
            | true, value when not value.IsComputed -> value
            | _ -> invalidOp "A required Traefik map is missing or unknown."
        let entryPoints = parseEntryPoints (requiredMap "entryPoints")
        let resolvers = parseResolvers (requiredMap "resolvers") entryPoints
        let certificates = parseCertificates (requiredMap "certificates")
        let routers = parseRouters (requiredMap "routers") entryPoints resolvers certificates
        let adminPort =
            match values.TryGetValue("adminPort") with
            | false, _ -> 19080
            | true, value when value.IsNull -> 19080
            | true, value when value.IsComputed -> invalidOp "The Traefik adminPort is unknown."
            | true, value ->
                let mutable number = 0.0
                if not (value.TryGetNumber(&number))
                   || Double.IsNaN(number)
                   || Double.IsInfinity(number)
                   || number <> Math.Truncate(number)
                   || number < 1.0
                   || number > 65535.0 then
                    invalidOp "The Traefik adminPort must be an integer from 1 through 65535."
                int number
        if entryPoints.Values |> Seq.exists ((=) adminPort) then
            invalidOp "The loopback Traefik adminPort must not overlap a public entryPoint."
        { EntryPoints = entryPoints
          Resolvers = resolvers
          Routers = routers
          Certificates = certificates
          AdminPort = adminPort }

    let private validateTls (config: TraefikConfig) =
        try
            TraefikCertificateValidation.validateNormalizedCertificates config.Certificates.Values
        with _ ->
            invalidOp "Traefik TLS certificate validation failed; certificate material is omitted."
        let providedRouters =
            config.Routers
            |> Seq.choose (fun (KeyValue(name, router)) ->
                if router.Tls.Kind = "provided" then Some(name, router.Host, router.Tls.Name) else None)
        try
            TraefikCertificateValidation.validateRouterCertificateCoverage providedRouters config.Certificates.Values
        with _ ->
            invalidOp "Traefik TLS router coverage validation failed; certificate material is omitted."

    let private normalizeInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = inputDictionary values
        let failures = ResizeArray<CheckFailure>()
        for key in values.Keys do
            if not (knownProperties.Contains(key)) then
                addFailure failures key "This resource property is not supported."
        for key in [ "connection"; "entryPoints"; "resolvers"; "routers"; "certificates" ] do
            if not (values.ContainsKey(key)) then addFailure failures key "This property is required."
        let hasUnknown = hasUnknownInputs values
        match normalized.TryGetValue("adminPort") with
        | false, _ -> normalized["adminPort"] <- PropertyValue(19080.0)
        | true, value when value.IsNull -> normalized["adminPort"] <- numberWithMetadata value 19080.0
        | _ -> ()
        markCertificatesSecret normalized
        if not hasUnknown then normalizeKnownDefaults normalized
        { Values = normalized
          HasUnknowns = hasUnknown
          Failures = failures }

    let private normalizeForPreview (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = normalizeInputs values
        failIfFailures normalized.Failures
        normalized

    let private normalizeForOperation (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = normalizeInputs values
        failIfFailures normalized.Failures
        if normalized.HasUnknowns then
            invalidOp "Traefik cannot be applied while one or more input values are unknown."
        let connection = parseConnection normalized.Values["connection"]
        let config = parseConfig normalized.Values
        validateTls config
        { Values = normalized.Values
          Connection = connection
          Config = config }

    let private inputValuesFromOutputs
        (preferred: ImmutableDictionary<string, PropertyValue>)
        (fallback: ImmutableDictionary<string, PropertyValue>)
        =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for key in declarativeProperties do
            match preferred.TryGetValue(key) with
            | true, value -> result[key] <- value
            | false, _ ->
                match fallback.TryGetValue(key) with
                | true, value -> result[key] <- value
                | false, _ -> ()
        result

    let private storedInputs (preferred: ImmutableDictionary<string, PropertyValue>) (fallback: ImmutableDictionary<string, PropertyValue>) =
        let selected = inputValuesFromOutputs preferred fallback
        let immutable = ImmutableDictionary.CreateRange<string, PropertyValue>(selected |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value)))
        let normalized = normalizeInputs immutable
        failIfFailures normalized.Failures
        if normalized.HasUnknowns then invalidOp "Stored Traefik state contains unknown input values."
        let connection = parseConnection normalized.Values["connection"]
        let config = parseConfig normalized.Values
        { Values = normalized.Values
          Connection = connection
          Config = config }



    let private stableId (urn: Pulumi.Urn) (connection: SshConnection) =
        urn.ToString() + "::" + connection.Address

    let private stringMapValue (values: ImmutableDictionary<string, string>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for KeyValue(key, value) in values do
            builder.Add(key, PropertyValue(value))
        PropertyValue(builder.ToImmutable())

    let private outputValues (inputs: Dictionary<string, PropertyValue>) (snapshot: TraefikSnapshot) =
        let outputs = Dictionary<string, PropertyValue>(inputs, StringComparer.Ordinal)
        markCertificatesSecret outputs
        outputs["inSync"] <- PropertyValue(snapshot.InSync)
        outputs["actualConfigHash"] <- PropertyValue(snapshot.ActualConfigHash)
        outputs["certificateFingerprints"] <- stringMapValue snapshot.CertificateFingerprints
        outputs

    let private previewValues (inputs: NormalizedInputs) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        markCertificatesSecret outputs
        for property in outputProperties do
            outputs[property] <- PropertyValue.Computed
        outputs

    let private requestTimeout (timeout: TimeSpan) =
        if timeout > TimeSpan.Zero then Some timeout else None

    let runWithTimeout (timeout: TimeSpan option) (outerToken: CancellationToken) (operation: CancellationToken -> Task<'T>) =
        task {
            use linked = CancellationTokenSource.CreateLinkedTokenSource(outerToken)
            match timeout with
            | Some value when value > TimeSpan.Zero -> linked.CancelAfter(value)
            | _ -> ()
            return! operation linked.Token
        }

    let private checkResponse (inputs: Dictionary<string, PropertyValue>) (failures: ResizeArray<CheckFailure>) =
        let response = CheckResponse()
        response.Inputs <- inputs
        response.Failures <- List<CheckFailure>(failures)
        response

    let private diffResponse
        (changes: Nullable<bool>)
        (diffs: List<string>)
        (replaces: List<string>)
        (detailed: Dictionary<string, PropertyDiff>)
        (deleteBeforeReplace: bool)
        =
        let response = DiffResponse()
        response.Changes <- changes
        response.Diffs <- diffs
        response.Replaces <- replaces
        response.DetailedDiff <- detailed
        response.DeleteBeforeReplace <- deleteBeforeReplace
        response

    let private noDiffResponse () =
        let response = DiffResponse()
        response.Changes <- Nullable<bool>()
        response

    let private addDiff (diffs: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) root path kind inputDiff =
        if not (details.ContainsKey(path)) then
            let propertyDiff = PropertyDiff()
            propertyDiff.Kind <- kind
            propertyDiff.InputDiff <- inputDiff
            details.Add(path, propertyDiff)
            if not (diffs.Contains(root)) then diffs.Add(root)

    let private inputValuesForDiff (request: DiffRequest) =
        inputValuesFromOutputs request.OldInputs request.OldOutputs

    let private makeDiff (request: DiffRequest) =
        let previous = inputValuesForDiff request
        if String.IsNullOrEmpty(request.Id) && previous.Count = 0 then
            diffResponse (Nullable<bool>(true)) (List<string>()) (List<string>()) (Dictionary<string, PropertyDiff>()) false
        elif previous.Count = 0 then
            noDiffResponse ()
        else
            let oldImmutable = ImmutableDictionary.CreateRange<string, PropertyValue>(previous |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value)))
            let oldNormalized = normalizeInputs oldImmutable
            let newNormalized = normalizeInputs request.NewInputs
            failIfFailures oldNormalized.Failures
            failIfFailures newNormalized.Failures
            if oldNormalized.HasUnknowns || newNormalized.HasUnknowns then
                noDiffResponse ()
            else
                let oldConnection = parseConnection oldNormalized.Values["connection"]
                let newConnection = parseConnection newNormalized.Values["connection"]
                let diffs = ResizeArray<string>()
                let replaces = ResizeArray<string>()
                let details = Dictionary<string, PropertyDiff>(StringComparer.Ordinal)
                let add root path kind inputDiff = addDiff diffs details root path kind inputDiff

                let rec compareValue root path (oldValue: PropertyValue) (newValue: PropertyValue) =
                    if oldValue.IsComputed || newValue.IsComputed then
                        ()
                    elif oldValue.IsSecret <> newValue.IsSecret then
                        add root path PropertyDiffKind.Update true
                    elif oldValue.Equals(newValue) then
                        ()
                    else
                        match tryGetMap oldValue, tryGetMap newValue with
                        | Some oldMap, Some newMap ->
                            let keys = Set.union (oldMap.Keys |> Set.ofSeq) (newMap.Keys |> Set.ofSeq)
                            for key in keys do
                                let childPath = path + "." + key
                                match oldMap.TryGetValue(key), newMap.TryGetValue(key) with
                                | (true, _), (false, _) -> add root childPath PropertyDiffKind.Delete true
                                | (false, _), (true, _) -> add root childPath PropertyDiffKind.Add true
                                | (true, oldChild), (true, newChild) -> compareValue root childPath oldChild newChild
                                | _ -> ()
                        | _ ->
                            match tryGetArray oldValue, tryGetArray newValue with
                            | Some oldArray, Some newArray ->
                                for index in 0 .. max oldArray.Length newArray.Length - 1 do
                                    let childPath = sprintf "%s[%d]" path index
                                    if index >= oldArray.Length then add root childPath PropertyDiffKind.Add true
                                    elif index >= newArray.Length then add root childPath PropertyDiffKind.Delete true
                                    else compareValue root childPath oldArray[index] newArray[index]
                            | _ -> add root path PropertyDiffKind.Update true

                match oldConnection.Address, newConnection.Address with
                | oldAddress, newAddress when oldAddress <> newAddress ->
                    add "connection" "connection.address" PropertyDiffKind.UpdateReplace true
                    replaces.Add("connection.address")
                | _ -> ()

                for property in [ "connection"; "entryPoints"; "resolvers"; "routers"; "certificates"; "adminPort" ] do
                    if property <> "connection" then
                        match oldNormalized.Values.TryGetValue(property), newNormalized.Values.TryGetValue(property) with
                        | (true, oldValue), (true, newValue) -> compareValue property property oldValue newValue
                        | (true, _), (false, _) -> add property property PropertyDiffKind.Delete true
                        | (false, _), (true, _) -> add property property PropertyDiffKind.Add true
                        | _ -> ()
                    else
                        match oldNormalized.Values.TryGetValue(property), newNormalized.Values.TryGetValue(property) with
                        | (true, oldValue), (true, newValue) -> compareValue property property oldValue newValue
                        | _ -> ()

                match request.OldOutputs.TryGetValue("inSync") with
                | true, value when value.IsComputed -> invalidOp "Stored Traefik state has an unknown inSync snapshot."
                | true, value ->
                    let mutable inSync = false
                    if not (value.TryGetBool(&inSync)) then
                        invalidOp "Stored Traefik state has an invalid inSync snapshot."
                    elif not inSync then
                        add "inSync" "inSync" PropertyDiffKind.Update false
                | false, _ -> invalidOp "Stored Traefik state is missing its inSync snapshot."
                diffResponse
                    (Nullable<bool>(diffs.Count > 0))
                    (List<string>(diffs))
                    (List<string>(replaces))
                    details
                    (replaces.Count > 0)

    let private configurationCheck (request: CheckRequest) =
        let failures = ResizeArray<CheckFailure>()
        for entry in request.NewInputs do
            if entry.Key <> "version" && entry.Key <> "pluginDownloadURL" then
                addFailure failures entry.Key "Dorothy does not accept custom provider configuration properties."
        checkResponse (inputDictionary request.NewInputs) failures

    let private configureResponse () =
        let response = ConfigureResponse()
        response.AcceptSecrets <- true
        response.AcceptResources <- false
        response.AcceptOutputs <- true
        response.SupportsPreview <- true
        response

    let private diffConfiguration (request: DiffRequest) =
        let changed =
            request.OldInputs.Count <> request.NewInputs.Count
            || (request.NewInputs
                |> Seq.exists (fun entry ->
                    match request.OldInputs.TryGetValue(entry.Key) with
                    | true, oldValue -> not (oldValue.Equals(entry.Value))
                    | false, _ -> true))
        diffResponse (Nullable<bool>(changed)) (List<string>()) (List<string>()) (Dictionary<string, PropertyDiff>()) false

    let private makeCheckResponse (request: CheckRequest) =
        if request.Type <> ResourceToken then
            let failures = ResizeArray<CheckFailure>()
            addFailure failures "" "Unexpected resource token for the Dorothy provider."
            checkResponse (inputDictionary request.NewInputs) failures
        else
            let normalized = normalizeInputs request.NewInputs
            if not normalized.HasUnknowns && normalized.Failures.Count = 0 then
                try
                    parseConnection normalized.Values["connection"] |> ignore
                    parseConfig normalized.Values |> validateTls
                with _ ->
                    addFailure normalized.Failures "" "Traefik configuration or TLS certificate material is invalid."
            checkResponse normalized.Values normalized.Failures

    let private createPreviewResponse inputs =
        let response = CreateResponse()
        response.Id <- String.Empty
        response.Outputs <- previewValues inputs
        response

    let private createResponse ownerId inputs snapshot =
        let response = CreateResponse()
        response.Id <- ownerId
        response.Outputs <- outputValues inputs.Values snapshot
        response

    let private updatePreviewResponse inputs =
        let response = UpdateResponse()
        response.Outputs <- previewValues inputs
        response

    let private updateResponse inputs snapshot =
        let response = UpdateResponse()
        response.Outputs <- outputValues inputs.Values snapshot
        response

    let private readResponse (id: string) (urn: Pulumi.Urn) (inputs: ParsedInputs) snapshot =
        let response = ReadResponse()
        response.Id <- if String.IsNullOrEmpty(id) then stableId urn inputs.Connection else id
        response.Inputs <- inputs.Values
        response.Outputs <- outputValues inputs.Values snapshot
        response

    let ensureResourceToken actual =
        if actual <> ResourceToken then invalidOp "Unexpected resource token for the Dorothy provider."

    let resourceToken = ResourceToken
    let providerSchema = schema
    let checkConfiguration = configurationCheck
    let providerConfigurationDiff = diffConfiguration
    let providerConfigurationResponse = configureResponse
    let resourceCheck = makeCheckResponse
    let makeDiffResponse = makeDiff
    let normalizeForPreviewInputs = normalizeForPreview
    let normalizeForOperationInputs = normalizeForOperation
    let makeCreatePreviewResponse = createPreviewResponse
    let makeCreateResponse = createResponse
    let makeUpdatePreviewResponse = updatePreviewResponse
    let makeUpdateResponse = updateResponse
    let makeReadResponse = readResponse
    let parseStoredState preferred fallback = storedInputs preferred fallback
    let timeoutForRequest = requestTimeout
    let resourceId = stableId

[<Sealed>]
type TraefikProvider() =
    inherit Pulumi.Experimental.Provider.Provider()

    static member Version = "0.1.0"
    static member ResourceToken = TraefikProviderLogic.resourceToken
    static member Schema = TraefikProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- TraefikProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(TraefikProviderLogic.checkConfiguration request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(TraefikProviderLogic.providerConfigurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        if request.Args.Keys |> Seq.exists (fun key -> key <> "version" && key <> "pluginDownloadURL") then
            invalidOp "Dorothy does not accept custom provider configuration properties."
        Task.FromResult(TraefikProviderLogic.providerConfigurationResponse())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(TraefikProviderLogic.resourceCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        TraefikProviderLogic.ensureResourceToken request.Type
        Task.FromResult(TraefikProviderLogic.makeDiffResponse request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        TraefikProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = TraefikProviderLogic.normalizeForPreviewInputs request.Inputs
            Task.FromResult(TraefikProviderLogic.makeCreatePreviewResponse inputs)
        else
            TraefikProviderLogic.runWithTimeout (TraefikProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = TraefikProviderLogic.normalizeForOperationInputs request.Inputs
                    let ownerId = TraefikProviderLogic.resourceId request.Urn inputs.Connection
                    let! snapshot = TraefikBackend.apply inputs.Connection ownerId inputs.Config operationToken
                    return TraefikProviderLogic.makeCreateResponse ownerId inputs snapshot
                })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        TraefikProviderLogic.ensureResourceToken request.Type
        TraefikProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = TraefikProviderLogic.parseStoredState request.Inputs request.Outputs
                let ownerId =
                    if String.IsNullOrEmpty(request.Id) then TraefikProviderLogic.resourceId request.Urn inputs.Connection
                    else request.Id
                let! snapshot = TraefikBackend.read inputs.Connection ownerId inputs.Config operationToken
                return TraefikProviderLogic.makeReadResponse request.Id request.Urn inputs snapshot
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        TraefikProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = TraefikProviderLogic.normalizeForPreviewInputs request.NewInputs
            Task.FromResult(TraefikProviderLogic.makeUpdatePreviewResponse inputs)
        else
            TraefikProviderLogic.runWithTimeout (TraefikProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = TraefikProviderLogic.normalizeForOperationInputs request.NewInputs
                    let ownerId =
                        if String.IsNullOrEmpty(request.Id) then TraefikProviderLogic.resourceId request.Urn inputs.Connection
                        else request.Id
                    let! snapshot = TraefikBackend.apply inputs.Connection ownerId inputs.Config operationToken
                    return TraefikProviderLogic.makeUpdateResponse inputs snapshot
                })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        TraefikProviderLogic.ensureResourceToken request.Type
        TraefikProviderLogic.runWithTimeout (TraefikProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let inputs = TraefikProviderLogic.parseStoredState request.OldInputs request.OldOutputs
                let ownerId =
                    if String.IsNullOrEmpty(request.Id) then TraefikProviderLogic.resourceId request.Urn inputs.Connection
                    else request.Id
                do! TraefikBackend.delete inputs.Connection ownerId inputs.Config operationToken
            }) :> Task
