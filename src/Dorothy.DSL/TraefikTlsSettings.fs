#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Net
open System.Net.Mail
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Text.RegularExpressions

/// Validates the native TLS/ACME boundary and injects helper-owned material paths.
[<RequireQualifiedAccess>]
module TraefikTlsSettings =
    let private failure () = invalidOp "Traefik TLS or ACME configuration is invalid."

    let private namePattern = Regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", RegexOptions.CultureInvariant)
    let private durationPattern = Regex("^(?:0|(?:[0-9]+(?:\\.[0-9]+)?(?:ns|us|µs|ms|s|m|h))+)$", RegexOptions.CultureInvariant)
    let private dnsUpdateEnvironment =
        set [
            "DNSUPDATE_NAMESERVER"
            "DNSUPDATE_DNS_TIMEOUT"
            "DNSUPDATE_ZONES"
            "DNSUPDATE_TTL"
            "DNSUPDATE_PROPAGATION_TIMEOUT"
            "DNSUPDATE_POLLING_INTERVAL"
            "DNSUPDATE_SEQUENCE_INTERVAL"
            "DNSUPDATE_TSIG_KEY"
            "DNSUPDATE_TSIG_SECRET"
            "DNSUPDATE_TSIG_ALGORITHM"
        ]

    // Only explicitly vetted environment inputs are accepted. In particular, no _FILE,
    // GSS keytab, custom endpoint, execution hook, or ambient SDK credential source is passed.
    let private providerEnvironment =
        Map.ofList [
            "dnsupdate", dnsUpdateEnvironment
            "cloudflare", set [ "CLOUDFLARE_DNS_API_TOKEN"; "CLOUDFLARE_ZONE_API_TOKEN" ]
            "digitalocean", set [ "DO_AUTH_TOKEN" ]
            "linode", set [ "LINODE_TOKEN" ]
            "vultr", set [ "VULTR_API_KEY" ]
        ]

    let private tryProperty (value: JsonObject) (name: string) =
        let mutable property: JsonNode = null
        if value.TryGetPropertyValue(name, &property) then Some property else None

    let private objectValue (value: JsonNode) =
        match value with
        | :? JsonObject as result -> result
        | _ -> failure ()

    let private arrayValue (value: JsonNode) =
        match value with
        | :? JsonArray as result -> result
        | _ -> failure ()

    let private requireObject (value: JsonNode) = objectValue value

    let private required (value: JsonObject) (name: string) =
        match tryProperty value name with
        | Some result when not (isNull result) -> result
        | _ -> failure ()

    let private optional (value: JsonObject) (name: string) =
        match tryProperty value name with
        | Some result when not (isNull result) -> Some result
        | Some _ -> failure ()
        | None -> None

    let private keys (value: JsonObject) =
        value |> Seq.map (fun property -> property.Key) |> Set.ofSeq

    let private allowKeys (value: JsonObject) (allowed: Set<string>) =
        if not (Set.isSubset (keys value) allowed) then failure ()

    let private stringValue (value: JsonNode) =
        match value with
        | :? JsonValue as scalar when scalar.GetValueKind() = JsonValueKind.String ->
            match scalar.GetValue<string>() with
            | null -> failure ()
            | result -> result
        | _ -> failure ()

    let private boolValue (value: JsonNode) =
        match value with
        | :? JsonValue as scalar when scalar.GetValueKind() = JsonValueKind.True -> true
        | :? JsonValue as scalar when scalar.GetValueKind() = JsonValueKind.False -> false
        | _ -> failure ()

    let private intValue (value: JsonNode) =
        match value with
        | :? JsonValue as scalar ->
            try scalar.GetValue<int>()
            with _ -> failure ()
        | _ -> failure ()

    let private requiredString value name = required value name |> stringValue

    let private optionalString value name = optional value name |> Option.map stringValue
    let private optionalBool value name = optional value name |> Option.iter (boolValue >> ignore)
    let private optionalInt value name = optional value name |> Option.iter (intValue >> ignore)

    let private safeText (value: string) =
        if String.IsNullOrWhiteSpace value
           || value.Length > 4096
           || (value |> Seq.exists Char.IsControl) then failure ()
        value

    let private validateName (value: string) =
        if String.IsNullOrWhiteSpace value || not (namePattern.IsMatch(value)) then failure ()
        value

    let private validateUniqueStrings (values: string list) =
        if values.Length <> (values |> Set.ofList |> Set.count) then failure ()
        values

    let private stringArray (value: JsonNode) =
        arrayValue value
        |> Seq.map stringValue
        |> Seq.toList
        |> validateUniqueStrings

    let private validatePublicCertificatePem (value: string) =
        if String.IsNullOrWhiteSpace value
           || value.Length > 2 * 1024 * 1024
           || not (value.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
           || value.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase) then failure ()
        let certificates = X509Certificate2Collection()
        try
            try
                certificates.ImportFromPem(value.AsSpan())
                if certificates.Count = 0 then failure ()
                for certificate in certificates do
                    if certificate.HasPrivateKey then failure ()
            with _ -> failure ()
        finally
            for certificate in certificates do certificate.Dispose()

    let private validateCaMaterial (certificateNames: Set<string>) (node: JsonNode) =
        let value = stringValue node
        if not (certificateNames.Contains(value)) then validatePublicCertificatePem value
        value

    let private validateCaArray (certificateNames: Set<string>) (node: JsonNode) =
        arrayValue node
        |> Seq.map (validateCaMaterial certificateNames)
        |> Seq.toList
        |> validateUniqueStrings

    let private validateDuration (value: JsonNode) =
        let duration = stringValue value
        if not (durationPattern.IsMatch(duration)) then failure ()

    let private validateEmail (value: string) =
        if value.Length > 254 || value |> Seq.exists Char.IsControl then failure ()
        try
            let parsed = MailAddress(value)
            if not (String.Equals(parsed.Address, value, StringComparison.Ordinal)) then failure ()
        with _ -> failure ()

    let private validateUrl (value: string) =
        if String.IsNullOrWhiteSpace value
           || value.Length > 2048
           || (value |> Seq.exists (fun character -> Char.IsControl(character) || Char.IsWhiteSpace(character))) then failure ()
        let mutable uri = Unchecked.defaultof<Uri>
        if not (Uri.TryCreate(value, UriKind.Absolute, &uri))
           || (uri.Scheme <> Uri.UriSchemeHttp && uri.Scheme <> Uri.UriSchemeHttps)
           || String.IsNullOrEmpty(uri.Host)
           || not (String.IsNullOrEmpty(uri.UserInfo))
           || not (String.IsNullOrEmpty(uri.Query))
           || not (String.IsNullOrEmpty(uri.Fragment))
           || uri.Port < 1 || uri.Port > 65535 then failure ()

    let private validateDomain allowWildcard (value: string) =
        if String.IsNullOrWhiteSpace value
           || value.Length > 253
           || value |> Seq.exists (fun character -> Char.IsControl(character) || Char.IsWhiteSpace(character)) then failure ()
        let trimmed = value.TrimEnd('.')
        let wildcard = allowWildcard && trimmed.StartsWith("*.", StringComparison.Ordinal)
        let name = if wildcard then trimmed.Substring(2) else trimmed
        if name.Contains('*') then failure ()
        try
            let idn = IdnMapping()
            idn.UseStd3AsciiRules <- true
            let ascii = idn.GetAscii(name)
            if Uri.CheckHostName(ascii) <> UriHostNameType.Dns then failure ()
        with _ -> failure ()

    let private validateDnsResolverAddress (value: string) =
        if String.IsNullOrWhiteSpace value
           || value.Length > 300
           || (value |> Seq.exists (fun character -> Char.IsControl(character) || Char.IsWhiteSpace(character) || character = '/' || character = '\\' || character = '@' || character = '?' || character = '#')) then failure ()
        let mutable uri = Unchecked.defaultof<Uri>
        if not (Uri.TryCreate("udp://" + value, UriKind.Absolute, &uri))
           || String.IsNullOrEmpty(uri.Host)
           || not (String.IsNullOrEmpty(uri.UserInfo))
           || (not uri.IsDefaultPort && (uri.Port < 1 || uri.Port > 65535)) then failure ()

    let private nativeEntryPoints (staticRoot: JsonObject) =
        match optional staticRoot "entryPoints" with
        | None -> Set.empty
        | Some node ->
            let entryPoints = requireObject node
            entryPoints |> Seq.map (fun property -> validateName property.Key) |> Set.ofSeq

    let private decodeEabHmac (encoded: string) =
        let firstPadding = encoded.IndexOf('=')
        let contentLength = if firstPadding < 0 then encoded.Length else firstPadding
        let padding = encoded.Length - contentLength
        let validCharacters =
            encoded
            |> Seq.take contentLength
            |> Seq.forall (fun character ->
                (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9')
                || character = '-'
                || character = '_')
        let validPadding =
            encoded
            |> Seq.skip contentLength
            |> Seq.forall ((=) '=')
        let requiredPadding = (4 - contentLength % 4) % 4
        if contentLength = 0
           || padding > 2
           || not validCharacters
           || not validPadding
           || (padding > 0 && padding <> requiredPadding)
           || contentLength % 4 = 1 then false
        else
            try
                let base64 = encoded.Substring(0, contentLength).Replace('-', '+').Replace('_', '/')
                Convert.FromBase64String(base64 + String('=', requiredPadding)).Length > 0
            with _ -> false

    let private validateEab (node: JsonNode) =
        let eab = requireObject node
        allowKeys eab (set [ "kid"; "hmacEncoded" ])
        let kid = requiredString eab "kid" |> safeText
        let encoded = requiredString eab "hmacEncoded" |> safeText
        if kid.Length > 1024 || not (decodeEabHmac encoded) then failure ()

    let private validatePropagation (node: JsonNode) =
        let propagation = requireObject node
        allowKeys propagation (set [ "disableChecks"; "disableANSChecks"; "requireAllRNS"; "delayBeforeChecks" ])
        for name in [ "disableChecks"; "disableANSChecks"; "requireAllRNS" ] do optionalBool propagation name
        optional propagation "delayBeforeChecks" |> Option.iter validateDuration

    let private validateDnsCredentials (configuration: JsonObject) (usedProviders: Set<string>) =
        let credentials =
            match optional configuration "dnsCredentials" with
            | None -> JsonObject()
            | Some node -> requireObject node

        if keys credentials <> usedProviders then failure ()
        let allNames = HashSet<string>(StringComparer.Ordinal)
        let result = ResizeArray<string * string>()

        for provider in usedProviders do
            let allowed =
                match Map.tryFind provider providerEnvironment with
                | Some values -> values
                | None -> failure ()
            let providerCredentials = required credentials provider |> requireObject
            allowKeys providerCredentials allowed
            if providerCredentials.Count = 0 then failure ()
            let values =
                providerCredentials
                |> Seq.map (fun property -> property.Key, stringValue property.Value)
                |> Seq.toList
            for name, value in values do
                if not (allNames.Add(name))
                   || String.IsNullOrEmpty(value)
                   || value.Length > 16384
                   || (value |> Seq.exists Char.IsControl) then failure ()
                result.Add(name, value)

            let has name = providerCredentials.ContainsKey(name)
            match provider with
            | "dnsupdate" ->
                if not (has "DNSUPDATE_NAMESERVER") then failure ()
                if has "DNSUPDATE_TSIG_KEY" <> has "DNSUPDATE_TSIG_SECRET" then failure ()
                if has "DNSUPDATE_TSIG_ALGORITHM" && not (has "DNSUPDATE_TSIG_KEY") then failure ()
                providerCredentials["DNSUPDATE_NAMESERVER"] |> stringValue |> validateDnsResolverAddress
            | "cloudflare" ->
                if not (has "CLOUDFLARE_DNS_API_TOKEN") then failure ()
            | "digitalocean" -> if not (has "DO_AUTH_TOKEN") then failure ()
            | "linode" -> if not (has "LINODE_TOKEN") then failure ()
            | "vultr" -> if not (has "VULTR_API_KEY") then failure ()
            | _ -> failure ()

        result |> Seq.sortWith (fun (left, _) (right, _) -> StringComparer.Ordinal.Compare(left, right)) |> Seq.toList

    let private validateAcme (entryPoints: Set<string>) (resolver: JsonObject) =
        allowKeys resolver (set [ "acme" ])
        let acme = required resolver "acme" |> requireObject
        allowKeys acme (set [
            "email"; "caServer"; "keyType"; "eab"; "certificatesDuration"
            "preferredChain"; "profile"; "emailAddresses"; "disableCommonName"
            "clientTimeout"; "clientResponseHeaderTimeout"; "certificateTimeout"
            "caSystemCertPool"; "caServerName"; "httpChallenge"; "dnsChallenge"; "tlsChallenge"
        ])

        optionalString acme "email" |> Option.iter (fun value -> if value <> "" then validateEmail value)
        optionalString acme "caServer" |> Option.iter validateUrl
        optionalString acme "preferredChain" |> Option.iter (safeText >> ignore)
        optionalString acme "profile" |> Option.iter (safeText >> ignore)
        optionalBool acme "disableCommonName"
        optionalBool acme "caSystemCertPool"
        optionalString acme "caServerName" |> Option.iter (validateDomain false)
        optional acme "certificatesDuration" |> Option.iter (fun value -> if intValue value < 1 then failure ())
        optionalString acme "keyType" |> Option.iter (fun value ->
            if not (Set.contains value (set [ "RSA2048"; "RSA4096"; "RSA8192"; "EC256"; "EC384" ])) then failure ())
        for field in [ "clientTimeout"; "clientResponseHeaderTimeout"; "certificateTimeout" ] do
            optional acme field |> Option.iter validateDuration
        optional acme "eab" |> Option.iter validateEab
        optional acme "emailAddresses"
        |> Option.iter (fun value -> stringArray value |> List.iter validateEmail)

        // ACME storage and CA certificate paths are never caller-selected host paths.
        if acme.ContainsKey("storage") || acme.ContainsKey("caCertificates") then failure ()

        let httpChallenge = optional acme "httpChallenge"
        let dnsChallenge = optional acme "dnsChallenge"
        let tlsChallenge = optional acme "tlsChallenge"
        let count = [ httpChallenge; dnsChallenge; tlsChallenge ] |> List.sumBy (function Some _ -> 1 | None -> 0)
        if count <> 1 then failure ()

        httpChallenge
        |> Option.iter (fun node ->
            let challenge = requireObject node
            allowKeys challenge (set [ "entryPoint"; "delay" ])
            let entryPoint = requiredString challenge "entryPoint" |> validateName
            if not (entryPoints.Contains(entryPoint)) then failure ()
            optional challenge "delay" |> Option.iter validateDuration)

        let usedProvider =
            dnsChallenge
            |> Option.map (fun node ->
                let challenge = requireObject node
                allowKeys challenge (set [ "provider"; "resolvers"; "propagation"; "delayBeforeCheck"; "disablePropagationCheck" ])
                let provider = requiredString challenge "provider"
                if not (providerEnvironment.ContainsKey(provider)) then failure ()
                optional challenge "resolvers"
                |> Option.iter (fun values -> stringArray values |> List.iter validateDnsResolverAddress)
                optional challenge "propagation" |> Option.iter validatePropagation
                optional challenge "delayBeforeCheck" |> Option.iter validateDuration
                optionalBool challenge "disablePropagationCheck"
                Some provider)
            |> Option.flatten

        tlsChallenge
        |> Option.iter (fun node ->
            let challenge = requireObject node
            allowKeys challenge (set [ "delay" ])
            optional challenge "delay" |> Option.iter validateDuration)

        usedProvider

    let private validateResolvers (entryPoints: Map<string, string>) (legacyResolvers: Set<string>) (staticRoot: JsonObject) =
        let entryPointNames = Set.union (entryPoints |> Map.toSeq |> Seq.map fst |> Set.ofSeq) (nativeEntryPoints staticRoot)
        let resolvers =
            match optional staticRoot "certificatesResolvers" with
            | None -> JsonObject()
            | Some node -> requireObject node
        let names = keys resolvers
        if not (Set.isEmpty (Set.intersect legacyResolvers names)) then failure ()
        let usedProviders = ResizeArray<string>()
        for resolver in resolvers do
            validateName resolver.Key |> ignore
            let resolverObject = requireObject resolver.Value
            match validateAcme entryPointNames resolverObject with
            | Some provider -> usedProviders.Add(provider)
            | None -> ()
        names, usedProviders |> Set.ofSeq

    let private certificateReference (legacyCertificates: Set<string>) (node: JsonNode) =
        let reference = requireObject node
        allowKeys reference (set [ "certificate" ])
        let name = requiredString reference "certificate" |> validateName
        if not (legacyCertificates.Contains(name)) then failure ()
        name

    let private validateTlsVersion (node: JsonNode) =
        let version = stringValue node
        let versions = [ "VersionTLS10"; "VersionTLS11"; "VersionTLS12"; "VersionTLS13" ]
        match versions |> List.tryFindIndex ((=) version) with
        | Some index -> index
        | None -> failure ()

    let private cipherSuites =
        set [
            "TLS_RSA_WITH_RC4_128_SHA"
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            "TLS_RSA_WITH_AES_128_CBC_SHA"
            "TLS_RSA_WITH_AES_256_CBC_SHA"
            "TLS_RSA_WITH_AES_128_CBC_SHA256"
            "TLS_RSA_WITH_AES_128_GCM_SHA256"
            "TLS_RSA_WITH_AES_256_GCM_SHA384"
            "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
            "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            "TLS_AES_128_GCM_SHA256"
            "TLS_AES_256_GCM_SHA384"
            "TLS_CHACHA20_POLY1305_SHA256"
            "TLS_FALLBACK_SCSV"
        ]

    let private validateTlsOption (certificateNames: Set<string>) (node: JsonNode) =
        let option = requireObject node
        allowKeys option (set [
            "minVersion"; "maxVersion"; "cipherSuites"; "curvePreferences"; "clientAuth"
            "sniStrict"; "alpnProtocols"; "disableSessionTickets"; "preferServerCipherSuites"
        ])
        let minVersion = optional option "minVersion" |> Option.map validateTlsVersion
        let maxVersion = optional option "maxVersion" |> Option.map validateTlsVersion
        match minVersion, maxVersion with
        | Some minimum, Some maximum when minimum > maximum -> failure ()
        | _ -> ()
        optional option "cipherSuites"
        |> Option.iter (fun values -> stringArray values |> List.iter (fun cipher -> if not (cipherSuites.Contains(cipher)) then failure ()))
        optional option "curvePreferences"
        |> Option.iter (fun values ->
            stringArray values
            |> List.iter (fun curve ->
                if not (Set.contains curve (set [ "CurveP256"; "CurveP384"; "CurveP521"; "X25519"; "X25519MLKEM768"; "SecP256r1MLKEM768"; "SecP384r1MLKEM1024" ])) then failure ()))
        optional option "alpnProtocols"
        |> Option.iter (fun values ->
            stringArray values
            |> List.iter (fun protocol ->
                if String.IsNullOrEmpty(protocol) || protocol.Length > 255 || protocol |> Seq.exists (fun character -> int character < 33 || int character > 126) then failure ()))
        optionalBool option "sniStrict"
        optionalBool option "disableSessionTickets"
        optionalBool option "preferServerCipherSuites"

        optional option "clientAuth"
        |> Option.iter (fun node ->
            let auth = requireObject node
            allowKeys auth (set [ "caFiles"; "clientAuthType" ])
            let caFiles =
                optional auth "caFiles"
                |> Option.map (validateCaArray certificateNames)
                |> Option.defaultValue []
            let authType = optionalString auth "clientAuthType"
            match authType with
            | Some value when not (Set.contains value (set [ "NoClientCert"; "RequestClientCert"; "RequireAnyClientCert"; "VerifyClientCertIfGiven"; "RequireAndVerifyClientCert" ])) -> failure ()
            | _ -> ()
            match authType with
            | Some("VerifyClientCertIfGiven" | "RequireAndVerifyClientCert") when caFiles.IsEmpty -> failure ()
            | _ -> ())

    let private validateTlsStore (legacyResolvers: Set<string>) (resolvers: Set<string>) (serverCertificates: Set<string>) (node: JsonNode) =
        let store = requireObject node
        allowKeys store (set [ "defaultCertificate"; "defaultGeneratedCert" ])
        let defaultCertificate = optional store "defaultCertificate"
        defaultCertificate |> Option.iter (certificateReference serverCertificates >> ignore)
        let generated = optional store "defaultGeneratedCert"
        if defaultCertificate.IsSome && generated.IsSome then failure ()
        generated
        |> Option.iter (fun value ->
            let generated = requireObject value
            allowKeys generated (set [ "resolver"; "domain" ])
            let resolver = requiredString generated "resolver" |> validateName
            if not (resolvers.Contains(resolver)) then failure ()
            let domain = required generated "domain" |> requireObject
            allowKeys domain (set [ "main"; "sans" ])
            requiredString domain "main" |> validateDomain false
            optional domain "sans"
            |> Option.iter (fun sans -> stringArray sans |> List.iter (validateDomain true)))

    let private tlsCertificateReference (serverCertificates: Set<string>) (node: JsonNode) =
        let item = requireObject node
        allowKeys item (set [ "certificate"; "stores" ])
        let name = requiredString item "certificate" |> validateName
        if not (serverCertificates.Contains(name)) then failure ()
        optional item "stores"
        |> Option.iter (fun stores ->
            stringArray stores
            |> List.iter (fun store -> if store <> "default" then failure ()))
        name
    let private validateCertificateReference (certificateNames: Set<string>) (node: JsonNode) =
        let reference = requireObject node
        allowKeys reference (set [ "certificate" ])
        let name = requiredString reference "certificate" |> validateName
        if not (certificateNames.Contains(name)) then failure ()

    let private validateCertificateReferences (certificateNames: Set<string>) (node: JsonNode) =
        let references = arrayValue node
        let mutable seen = Set.empty
        for reference in references do
            let name = requiredString (requireObject reference) "certificate"
            if seen.Contains(name) then failure ()
            validateCertificateReference certificateNames reference
            seen <- seen.Add(name)

    let private validateForwardAuthTls (certificateNames: Set<string>) (node: JsonNode) =
        let tls = requireObject node
        allowKeys tls (set [ "caCertificate"; "clientCertificate"; "insecureSkipVerify"; "caOptional" ])
        optional tls "caCertificate" |> Option.iter (validateCaMaterial certificateNames >> ignore)
        optionalString tls "clientCertificate"
        |> Option.iter (fun name ->
            validateName name |> ignore
            if not (certificateNames.Contains(name)) then failure ())
        optional tls "insecureSkipVerify" |> Option.iter (fun value -> if boolValue value then failure ())
        optionalBool tls "caOptional"

    let private validateProtectedTransportCertificates (certificateNames: Set<string>) (dynamicRoot: JsonObject) =
        let validateHttp () =
            match optional dynamicRoot "http" with
            | None -> ()
            | Some node ->
                let http = requireObject node
                match optional http "serversTransports" with
                | Some transports ->
                    for transport in requireObject transports do
                        let settings = requireObject transport.Value
                        optional settings "rootCAs" |> Option.iter (validateCaArray certificateNames >> ignore)
                        optional settings "certificates" |> Option.iter (validateCertificateReferences certificateNames)
                | None -> ()
                match optional http "middlewares" with
                | Some middlewares ->
                    for middleware in requireObject middlewares do
                        let settings = requireObject middleware.Value
                        match optional settings "forwardAuth" with
                        | Some forwardAuth ->
                            match optional (requireObject forwardAuth) "tls" with
                            | Some tls -> validateForwardAuthTls certificateNames tls
                            | None -> ()
                        | None -> ()
                | None -> ()

        let validateTcp () =
            match optional dynamicRoot "tcp" with
            | None -> ()
            | Some node ->
                let tcp = requireObject node
                match optional tcp "serversTransports" with
                | Some transports ->
                    for transport in requireObject transports do
                        let settings = requireObject transport.Value
                        match optional settings "tls" with
                        | Some tlsNode ->
                            let tls = requireObject tlsNode
                            optional tls "rootCAs" |> Option.iter (validateCaArray certificateNames >> ignore)
                            optional tls "certificates" |> Option.iter (validateCertificateReferences certificateNames)
                        | None -> ()
                | None -> ()

        validateHttp ()
        validateTcp ()

    let private validateDynamicTls (legacyResolvers: Set<string>) (resolvers: Set<string>) (serverCertificates: Set<string>) (certificateNames: Set<string>) (dynamicRoot: JsonObject) =
        let tls =
            match optional dynamicRoot "tls" with
            | None -> JsonObject()
            | Some node -> requireObject node
        allowKeys tls (set [ "certificates"; "options"; "stores" ])
        optional tls "certificates"
        |> Option.iter (fun node ->
            let certificates = arrayValue node
            let mutable seen = Set.empty
            for certificate in certificates do
                let name = tlsCertificateReference serverCertificates certificate
                if seen.Contains(name) then failure ()
                seen <- seen.Add(name))

        let options =
            match optional tls "options" with
            | None -> JsonObject()
            | Some node -> requireObject node
        for option in options do
            validateName option.Key |> ignore
            validateTlsOption certificateNames option.Value

        let stores =
            match optional tls "stores" with
            | None -> JsonObject()
            | Some node -> requireObject node
        for store in stores do
            if store.Key <> "default" then failure ()
            validateTlsStore legacyResolvers resolvers serverCertificates store.Value
    /// Validates TLS/ACME configuration against distinct server and outbound identity inventories.
    /// All diagnostics are fixed and never include user-supplied names or secret values.
    let validateWithCertificateUsage
        (entryPoints: Map<string, string>)
        (legacyResolvers: Set<string>)
        (serverCertificates: Set<string>)
        (clientCertificates: Set<string>)
        (configuration: JsonObject)
        : unit =
        if isNull configuration then failure ()
        let staticRoot =
            match optional configuration "static" with
            | None -> JsonObject()
            | Some value -> requireObject value
        let dynamicRoot =
            match optional configuration "dynamic" with
            | None -> JsonObject()
            | Some value -> requireObject value
        let resolverNames, usedProviders = validateResolvers entryPoints legacyResolvers staticRoot
        validateDnsCredentials configuration usedProviders |> ignore
        let allResolvers = Set.union legacyResolvers resolverNames
        let allCertificates = Set.union serverCertificates clientCertificates
        validateDynamicTls legacyResolvers allResolvers serverCertificates allCertificates dynamicRoot
        validateProtectedTransportCertificates allCertificates dynamicRoot

    /// Validates the TLS, ACME resolver, and protected DNS credential subsets of a config root.
    /// Certificates in this compatibility entrypoint are treated as server identities.
    let validate (entryPoints: Map<string, string>) (legacyResolvers: Set<string>) (legacyCertificates: Set<string>) (configuration: JsonObject) : unit =
        validateWithCertificateUsage entryPoints legacyResolvers legacyCertificates Set.empty configuration

    let private hashText (value: string) =
        SHA256.HashData(Encoding.UTF8.GetBytes(value))
        |> Convert.ToHexString
        |> fun hash -> hash.ToLowerInvariant()

    let private deepCopyObject (value: JsonObject) = value.DeepClone() :?> JsonObject

    let legacyAcmeStoragePath (stateDir: string) (name: string) =
        Path.Combine(stateDir, "acme-" + hashText name + ".json")

    /// Isolates each managed ACME account by resolver name and exact directory URL.
    let acmeStoragePath (stateDir: string) (name: string) (caServer: string) =
        Path.Combine(stateDir, "acme-" + hashText (name + "\n" + caServer) + ".json")

    /// Copies static native settings and replaces all ACME storage locations with issuer-keyed helper-owned paths.
    let staticSettings (stateDir: string) (staticRoot: JsonObject) : JsonObject =
        if String.IsNullOrWhiteSpace stateDir || not (Path.IsPathRooted stateDir) || isNull staticRoot then failure ()
        let result = deepCopyObject staticRoot
        match optional result "certificatesResolvers" with
        | None -> result
        | Some node ->
            let resolvers = requireObject node
            for resolver in resolvers do
                match resolver.Value with
                | :? JsonObject as resolverObject ->
                    match optional resolverObject "acme" with
                    | Some node ->
                        match node with
                        | :? JsonObject as acme ->
                            let caServer = optionalString acme "caServer" |> Option.defaultValue "https://acme-v02.api.letsencrypt.org/directory"
                            acme["storage"] <- JsonValue.Create(acmeStoragePath stateDir resolver.Key caServer)
                        | _ -> failure ()
                    | None -> ()
                | _ -> failure ()
            result

    let private resolveCertificate (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let name =
            match node with
            | :? JsonObject as reference ->
                allowKeys reference (set [ "certificate"; "stores" ])
                requiredString reference "certificate" |> validateName
            | _ -> failure ()
        match Map.tryFind name certificatePaths with
        | Some (certificatePath, keyPath) when not (String.IsNullOrWhiteSpace certificatePath || String.IsNullOrWhiteSpace keyPath) ->
            certificatePath, keyPath
        | _ -> failure ()

    let private nativeCertificate (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let reference = requireObject node
        let certificatePath, keyPath = resolveCertificate certificatePaths node
        let result = JsonObject()
        result["certFile"] <- JsonValue.Create(certificatePath)
        result["keyFile"] <- JsonValue.Create(keyPath)
        match optional reference "stores" with
        | Some (stores: JsonNode) -> result["stores"] <- stores.DeepClone()
        | None -> ()
        result

    let private resolveCaValue (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let value = stringValue node
        match Map.tryFind value certificatePaths with
        | Some (certificatePath, _) -> certificatePath
        | None ->
            validatePublicCertificatePem value
            value

    let private transformClientAuth (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let auth = requireObject node |> deepCopyObject
        match optional auth "caFiles" with
        | None -> auth
        | Some values ->
            let paths = JsonArray()
            for value in arrayValue values do
                paths.Add(JsonValue.Create(resolveCaValue certificatePaths value))
            auth["caFiles"] <- paths
            auth

    let private transformTlsOption (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let option = requireObject node |> deepCopyObject
        match optional option "clientAuth" with
        | Some auth -> option["clientAuth"] <- transformClientAuth certificatePaths auth
        | None -> ()
        option

    let private transformTlsStore (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let store = requireObject node |> deepCopyObject
        match optional store "defaultCertificate" with
        | Some certificate -> store["defaultCertificate"] <- nativeCertificate certificatePaths certificate
        | None -> ()
        store

    let private transformCaArray (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let result = JsonArray()
        for value in arrayValue node do result.Add(JsonValue.Create(resolveCaValue certificatePaths value))
        result

    let private transformCertificateArray (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let result = JsonArray()
        for value in arrayValue node do result.Add(nativeCertificate certificatePaths value)
        result

    let private transformHttpTransport (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let transport = requireObject node |> deepCopyObject
        match optional transport "rootCAs" with
        | Some values -> transport["rootCAs"] <- transformCaArray certificatePaths values
        | None -> ()
        match optional transport "certificates" with
        | Some values -> transport["certificates"] <- transformCertificateArray certificatePaths values
        | None -> ()
        transport

    let private transformTcpTransport (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let transport = requireObject node |> deepCopyObject
        match optional transport "tls" with
        | Some node ->
            let tls = requireObject node |> deepCopyObject
            match optional tls "rootCAs" with
            | Some values -> tls["rootCAs"] <- transformCaArray certificatePaths values
            | None -> ()
            match optional tls "certificates" with
            | Some values -> tls["certificates"] <- transformCertificateArray certificatePaths values
            | None -> ()
            transport["tls"] <- tls
        | None -> ()
        transport

    let private transformForwardAuthTls (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let input = requireObject node
        let output = JsonObject()
        match optional input "caCertificate" with
        | Some ca -> output["ca"] <- JsonValue.Create(resolveCaValue certificatePaths ca)
        | None -> ()
        match optional input "clientCertificate" with
        | Some value ->
            let name = stringValue value |> validateName
            match Map.tryFind name certificatePaths with
            | Some (certificatePath, keyPath) ->
                output["cert"] <- JsonValue.Create(certificatePath)
                output["key"] <- JsonValue.Create(keyPath)
            | None -> failure ()
        | None -> ()
        for field in [ "insecureSkipVerify"; "caOptional" ] do
            match optional input field with
            | Some value -> output[field] <- value.DeepClone()
            | None -> ()
        output

    let private transformHttpMiddleware (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let middleware = requireObject node |> deepCopyObject
        match optional middleware "forwardAuth" with
        | Some forwardAuthNode ->
            let forwardAuth = requireObject forwardAuthNode |> deepCopyObject
            match optional forwardAuth "tls" with
            | Some tls -> forwardAuth["tls"] <- transformForwardAuthTls certificatePaths tls
            | None -> ()
            middleware["forwardAuth"] <- forwardAuth
        | None -> ()
        middleware

    let private transformNamedObjects transform (node: JsonNode) =
        let source = requireObject node
        let output = JsonObject()
        for item in source do output[item.Key] <- transform item.Value
        output

    let private transformHttpRoot (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let http = requireObject node |> deepCopyObject
        match optional http "serversTransports" with
        | Some transports -> http["serversTransports"] <- transformNamedObjects (transformHttpTransport certificatePaths) transports
        | None -> ()
        match optional http "middlewares" with
        | Some middlewares -> http["middlewares"] <- transformNamedObjects (transformHttpMiddleware certificatePaths) middlewares
        | None -> ()
        http

    let private transformTcpRoot (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let tcp = requireObject node |> deepCopyObject
        match optional tcp "serversTransports" with
        | Some transports -> tcp["serversTransports"] <- transformNamedObjects (transformTcpTransport certificatePaths) transports
        | None -> ()
        tcp

    /// Copies dynamic native settings and resolves only logical names backed by protected legacy material.
    let private transformTlsRoot (certificatePaths: Map<string, string * string>) (node: JsonNode) =
        let tls = requireObject node |> deepCopyObject
        match optional tls "certificates" with
        | Some certificates -> tls["certificates"] <- transformCertificateArray certificatePaths certificates
        | None -> ()
        match optional tls "options" with
        | Some options ->
            tls["options"] <- transformNamedObjects (transformTlsOption certificatePaths) options
        | None -> ()
        match optional tls "stores" with
        | Some stores -> tls["stores"] <- transformNamedObjects (transformTlsStore certificatePaths) stores
        | None -> ()
        tls

    /// Copies dynamic native settings and resolves managed certificate/CA references to protected paths.
    let dynamicSettings (certificatePaths: Map<string, string * string>) (dynamicRoot: JsonObject) : JsonObject =
        if isNull dynamicRoot then failure ()
        let result = deepCopyObject dynamicRoot
        match optional result "tls" with
        | Some tls -> result["tls"] <- transformTlsRoot certificatePaths tls
        | None -> ()
        match optional result "http" with
        | Some http -> result["http"] <- transformHttpRoot certificatePaths http
        | None -> ()
        match optional result "tcp" with
        | Some tcp -> result["tcp"] <- transformTcpRoot certificatePaths tcp
        | None -> ()
        result

    /// Returns the validated, deterministic environment entries for the helper-owned credential file.
    let dnsEnvironment (configuration: JsonObject option) : (string * string) list =
        match configuration with
        | None -> []
        | Some root ->
            match optional root "dnsCredentials" with
            | None -> []
            | Some node ->
                let credentials = requireObject node
                credentials
                |> Seq.collect (fun provider ->
                    requireObject provider.Value
                    |> Seq.map (fun item -> item.Key, stringValue item.Value))
                |> Seq.sortWith (fun (left, _) (right, _) -> StringComparer.Ordinal.Compare(left, right))
                |> Seq.toList
