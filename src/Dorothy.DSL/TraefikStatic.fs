#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System
open System.Collections.Generic
open System.Globalization
open System.Net
open System.Net.Sockets
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Text.Json.Nodes

/// Bounded validation for native Traefik static configuration (v3.7.16).
module TraefikStatic =
    type private Bind =
        { Name: string
          Protocol: string
          Host: IPAddress option
          Port: int }

    let private fail () = invalidOp "Static Traefik configuration is invalid."
    let private privateAdminEntryPoint = "keroosha-admin"

    let private safeText (maxLength: int) (value: string) =
        if isNull value
           || value.Length > maxLength
           || value.Contains("{{", StringComparison.Ordinal)
           || (value |> Seq.exists Char.IsControl) then
            fail ()
        value

    let private isAsciiAlphaNumeric (character: char) =
        (character >= 'a' && character <= 'z')
        || (character >= 'A' && character <= 'Z')
        || (character >= '0' && character <= '9')

    let private isTraefikName (value: string) =
        not (String.IsNullOrWhiteSpace(value))
        && value.Length <= 63
        && isAsciiAlphaNumeric value[0]
        && (value
            |> Seq.forall (fun character ->
                isAsciiAlphaNumeric character || character = '.' || character = '_' || character = '-'))

    let private isReservedEntryPointName (value: string) =
        String.Equals(value, "traefik", StringComparison.OrdinalIgnoreCase)
        || String.Equals(value, "keroosha-admin", StringComparison.OrdinalIgnoreCase)

    let private requireName (value: string) =
        let value = safeText 63 value
        if not (isTraefikName value) then fail ()
        value

    let private requireEntryPointName (value: string) =
        let name = requireName value
        if isReservedEntryPointName name then fail ()
        name

    let private requireObject (node: JsonNode) =
        match node with
        | :? JsonObject as value -> value
        | _ -> fail ()

    let private requireValue (node: JsonNode) =
        if isNull node then fail ()
        node

    let private validateMembers (allowed: string list) (fields: JsonObject) =
        let allowedNames = HashSet<string>(allowed, StringComparer.Ordinal)
        let seenNames = HashSet<string>(StringComparer.OrdinalIgnoreCase)
        for field in fields do
            if not (seenNames.Add(field.Key)) || not (allowedNames.Contains(field.Key)) then
                fail ()
            requireValue field.Value |> ignore

    let private tryField (fields: JsonObject) (name: string) =
        let mutable value = Unchecked.defaultof<JsonNode>
        if fields.TryGetPropertyValue(name, &value) then
            Some(requireValue value)
        else
            None

    let private requiredField (fields: JsonObject) (name: string) =
        match tryField fields name with
        | Some value -> value
        | None -> fail ()

    let private stringValue (node: JsonNode) =
        match requireValue node with
        | :? JsonValue as value when value.GetValueKind() = JsonValueKind.String ->
            try
                value.GetValue<string>() |> safeText 4096
            with _ -> fail ()
        | _ -> fail ()

    let private booleanValue (node: JsonNode) =
        match requireValue node with
        | :? JsonValue as value when value.GetValueKind() = JsonValueKind.True -> true
        | :? JsonValue as value when value.GetValueKind() = JsonValueKind.False -> false
        | _ -> fail ()

    let private int64Value (node: JsonNode) =
        match requireValue node with
        | :? JsonValue as value when value.GetValueKind() = JsonValueKind.Number ->
            try
                value.GetValue<int64>()
            with _ -> fail ()
        | _ -> fail ()

    let private doubleValue (node: JsonNode) =
        match requireValue node with
        | :? JsonValue as value when value.GetValueKind() = JsonValueKind.Number ->
            try
                let number = value.GetValue<double>()
                if Double.IsFinite(number) then number else fail ()
            with _ -> fail ()
        | _ -> fail ()

    let private enumValue (allowed: string list) (node: JsonNode) =
        let value = stringValue node
        if not (List.contains value allowed) then fail ()
        value

    let private validateOptional (fields: JsonObject) (name: string) (validator: JsonNode -> unit) =
        match tryField fields name with
        | Some value -> validator value
        | None -> ()

    let private validateBoolean (node: JsonNode) = booleanValue node |> ignore

    let private validateBooleanMembers (fields: JsonObject) (names: string list) =
        validateMembers names fields
        for field in fields do booleanValue field.Value |> ignore

    let private validateBooleanObject (node: JsonNode) (names: string list) =
        let fields = requireObject node
        validateBooleanMembers fields names

    let private validateStringArray (node: JsonNode) (maximum: int) (validator: string -> unit) =
        match requireValue node with
        | :? JsonArray as items ->
            if items.Count > maximum then fail ()
            for item in items do
                stringValue item |> validator
        | _ -> fail ()

    let private validateStringMap
        (node: JsonNode)
        (maximum: int)
        (keyValidator: string -> unit)
        (valueValidator: string -> unit)
        =
        let fields = requireObject node
        if fields.Count > maximum then fail ()
        let seen = HashSet<string>(StringComparer.OrdinalIgnoreCase)
        for field in fields do
            let key = safeText 256 field.Key
            if not (seen.Add(key)) then fail ()
            keyValidator key
            stringValue field.Value |> valueValidator

    let private isHttpToken (value: string) =
        not (String.IsNullOrEmpty(value))
        && value.Length <= 256
        && (value
            |> Seq.forall (fun character ->
                isAsciiAlphaNumeric character
                || "!#$%&'*+-.^_`|~".IndexOf(character) >= 0))

    let private requireHttpToken value =
        if not (isHttpToken value) then fail ()

    let private tryDuration (value: string) =
        if String.IsNullOrEmpty(value) || value.Length > 64 then
            false
        elif value = "0" then
            true
        else
            let mutable index = 0
            let mutable sign = 1M
            if value[index] = '-' then
                sign <- -1M
                index <- index + 1
            elif value[index] = '+' then
                index <- index + 1

            let mutable totalNanoseconds = 0M
            let mutable partCount = 0
            let mutable valid = index < value.Length

            while valid && index < value.Length do
                let start = index
                let mutable hasDigit = false
                let mutable hasDot = false
                while index < value.Length
                      && ((value[index] >= '0' && value[index] <= '9') || value[index] = '.') do
                    if value[index] = '.' then
                        if hasDot then valid <- false
                        hasDot <- true
                    else
                        hasDigit <- true
                    index <- index + 1

                if not valid || not hasDigit || index = start || index >= value.Length then
                    valid <- false
                else
                    let amountText = value.Substring(start, index - start)
                    let mutable amount = 0M
                    if not (Decimal.TryParse(amountText, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, &amount)) then
                        valid <- false
                    else
                        let unit, nanoseconds =
                            if index + 1 < value.Length && value.Substring(index, 2) = "ns" then "ns", 1M
                            elif index + 1 < value.Length && value.Substring(index, 2) = "us" then "us", 1000M
                            elif index + 1 < value.Length && value.Substring(index, 2) = "µs" then "µs", 1000M
                            elif index + 1 < value.Length && value.Substring(index, 2) = "ms" then "ms", 1000000M
                            elif value[index] = 's' then "s", 1000000000M
                            elif value[index] = 'm' then "m", 60000000000M
                            elif value[index] = 'h' then "h", 3600000000000M
                            else "", 0M

                        if unit = "" then
                            valid <- false
                        else
                            try
                                totalNanoseconds <- totalNanoseconds + amount * nanoseconds
                            with _ -> valid <- false
                            index <- index + unit.Length
                            partCount <- partCount + 1

            valid
            && partCount > 0
            && totalNanoseconds * sign <= 9223372036854775807M
            && totalNanoseconds * sign >= -9223372036854775808M

    let private validateDuration (node: JsonNode) =
        if not (stringValue node |> tryDuration) then fail ()

    let private validateDurationObject (node: JsonNode) (names: string list) =
        let fields = requireObject node
        validateMembers names fields
        for field in fields do validateDuration field.Value

    let private validateBoundedInteger (minimum: int64) (maximum: int64) (node: JsonNode) =
        let value = int64Value node
        if value < minimum || value > maximum then fail ()

    let private parsePort (text: string) =
        if String.IsNullOrEmpty(text)
           || (text |> Seq.exists (fun character -> character < '0' || character > '9')) then
            fail ()
        let mutable port = 0
        if not (Int32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, &port))
           || port < 1
           || port > 65535 then
            fail ()
        port

    let private parseAddress (name: string) (address: string) =
        let address = safeText 255 address
        let slash = address.IndexOf('/')
        let socketAddress, protocol =
            if slash < 0 then
                address, "tcp"
            elif slash = 0 || address.IndexOf('/', slash + 1) >= 0 then
                fail ()
            else
                let selected = address.Substring(slash + 1).ToLowerInvariant()
                if selected <> "tcp" && selected <> "udp" then fail ()
                address.Substring(0, slash), selected

        let hostText, portText =
            if socketAddress.StartsWith("[", StringComparison.Ordinal) then
                let close = socketAddress.IndexOf(']')
                if close < 2 || close + 1 >= socketAddress.Length || socketAddress[close + 1] <> ':' then fail ()
                socketAddress.Substring(1, close - 1), socketAddress.Substring(close + 2)
            else
                let colon = socketAddress.LastIndexOf(':')
                if colon < 0 || socketAddress.IndexOf(':') <> colon then fail ()
                socketAddress.Substring(0, colon), socketAddress.Substring(colon + 1)

        let host =
            if hostText = "" then
                None
            else
                let mutable parsed = Unchecked.defaultof<IPAddress>
                if not (IPAddress.TryParse(hostText, &parsed)) then fail ()
                if socketAddress.StartsWith("[", StringComparison.Ordinal) then
                    if parsed.AddressFamily <> AddressFamily.InterNetworkV6 then fail ()
                else
                    if parsed.AddressFamily <> AddressFamily.InterNetwork
                       || not (String.Equals(parsed.ToString(), hostText, StringComparison.Ordinal)) then
                        fail ()
                if parsed.Equals(IPAddress.Any) || parsed.Equals(IPAddress.IPv6Any) then None else Some parsed

        { Name = name
          Protocol = protocol
          Host = host
          Port = parsePort portText }

    let private hostsOverlap (left: IPAddress option) (right: IPAddress option) =
        match left, right with
        | None, _
        | _, None -> true
        | Some first, Some second -> first.Equals(second)

    let private bindsOverlap (left: Bind) (right: Bind) =
        left.Protocol = right.Protocol
        && left.Port = right.Port
        && hostsOverlap left.Host right.Host

    let private validateIpOrCidr (value: string) =
        let slash = value.IndexOf('/')
        let addressText, prefixText =
            if slash < 0 then value, None
            elif slash = 0 || value.IndexOf('/', slash + 1) >= 0 then fail ()
            else value.Substring(0, slash), Some(value.Substring(slash + 1))
        let mutable address = Unchecked.defaultof<IPAddress>
        if not (IPAddress.TryParse(addressText, &address)) then fail ()
        match prefixText with
        | None -> ()
        | Some text ->
            let mutable prefix = 0
            let maximum = if address.AddressFamily = AddressFamily.InterNetwork then 32 else 128
            if not (Int32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, &prefix))
               || prefix < 1
               || prefix > maximum then
                fail ()

    let private validateTrustedAddresses (node: JsonNode) =
        validateStringArray node 64 validateIpOrCidr
    let private pemStringValue (node: JsonNode) =
        match requireValue node with
        | :? JsonValue as value when value.GetValueKind() = JsonValueKind.String ->
            try
                let pem = value.GetValue<string>()
                if isNull pem
                   || pem.Length > 4096
                   || pem.Contains("{{", StringComparison.Ordinal)
                   || (pem |> Seq.exists (fun character -> Char.IsControl(character) && character <> '\r' && character <> '\n')) then
                    fail ()
                pem
            with _ -> fail ()
        | _ -> fail ()

    let private validatePemAuthority (value: string) =
        if not (value.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
           || value.Contains("PRIVATE KEY", StringComparison.Ordinal) then
            fail ()
        let certificates = X509Certificate2Collection()
        try
            try
                certificates.ImportFromPem(value)
                if certificates.Count = 0 || certificates.Count > 16 then fail ()
                let now = DateTime.UtcNow
                for certificate in certificates do
                    if certificate.NotBefore.ToUniversalTime() > now
                       || certificate.NotAfter.ToUniversalTime() < now then
                        fail ()
                    let mutable isCertificateAuthority = false
                    for extension in certificate.Extensions do
                        match extension with
                        | :? X509BasicConstraintsExtension as constraints ->
                            isCertificateAuthority <- constraints.CertificateAuthority
                        | _ -> ()
                    if not isCertificateAuthority then fail ()
            with _ -> fail ()
        finally
            for certificate in certificates do certificate.Dispose()

    let private validatePemAuthorityValue (node: JsonNode) =
        pemStringValue node |> validatePemAuthority

    let private validatePemAuthorities (node: JsonNode) =
        match requireValue node with
        | :? JsonArray as values ->
            if values.Count > 16 then fail ()
            for value in values do validatePemAuthorityValue value
        | _ -> fail ()


    let private validateTrustObject (node: JsonNode) (allowConnection: bool) =
        let allowed =
            [ "insecure"; "trustedIPs" ]
            @ (if allowConnection then [ "connection"; "notAppendXForwardedFor" ] else [])
        let fields = requireObject node
        validateMembers allowed fields
        validateOptional fields "insecure" (fun value -> if booleanValue value then fail ())
        validateOptional fields "trustedIPs" validateTrustedAddresses
        validateOptional fields "connection" (fun value -> validateStringArray value 64 requireHttpToken)
        validateOptional fields "notAppendXForwardedFor" validateBoolean
    let private validateRedirect (node: JsonNode) (sourceName: string) (redirects: ResizeArray<string * string>) =
        let fields = requireObject node
        validateMembers [ "to"; "scheme"; "permanent"; "priority" ] fields
        let target = requiredField fields "to" |> stringValue |> requireName
        if String.Equals(sourceName, target, StringComparison.OrdinalIgnoreCase) then fail ()
        redirects.Add(sourceName, target)
        validateOptional fields "scheme" (fun value -> enumValue [ "http"; "https" ] value |> ignore)
        validateOptional fields "permanent" validateBoolean
        validateOptional fields "priority" (validateBoundedInteger 0L 2147483647L)

    let private validateTlsDefault (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "options"; "certResolver"; "domains" ] fields
        validateOptional fields "options" (fun value -> stringValue value |> safeText 128 |> ignore)
        validateOptional fields "certResolver" (fun value -> stringValue value |> requireName |> ignore)
        validateOptional fields "domains" (fun value ->
            match requireValue value with
            | :? JsonArray as domains ->
                if domains.Count > 128 then fail ()
                for domain in domains do
                    let domainFields = requireObject domain
                    validateMembers [ "main"; "sans" ] domainFields
                    let validateDomainName (name: string) =
                        let name = safeText 253 name
                        let candidate = if name.StartsWith("*.", StringComparison.Ordinal) then name.Substring(2) else name
                        if String.IsNullOrWhiteSpace(candidate)
                           || candidate.Contains("/", StringComparison.Ordinal)
                           || candidate.Contains(":", StringComparison.Ordinal)
                           || candidate.Contains(" ", StringComparison.Ordinal) then fail ()
                    validateOptional domainFields "main" (fun item -> stringValue item |> validateDomainName)
                    validateOptional domainFields "sans" (fun item -> validateStringArray item 128 validateDomainName)
                    if tryField domainFields "main" |> Option.isNone then fail ()
            | _ -> fail ())

    let private validateHttpConfig (node: JsonNode) (entryPointName: string) (redirects: ResizeArray<string * string>) =
        let fields = requireObject node
        validateMembers
            [ "redirections"; "middlewares"; "tls"; "encodedCharacters"; "encodeQuerySemicolons"; "sanitizePath"; "maxHeaderBytes"; "aliasHeadersStrategy"; "underscoreHeadersStrategy" ]
            fields
        validateOptional fields "redirections" (fun value ->
            let redirections = requireObject value
            validateMembers [ "entryPoint" ] redirections
            validateOptional redirections "entryPoint" (fun redirect -> validateRedirect redirect entryPointName redirects))
        validateOptional fields "middlewares" (fun value ->
            validateStringArray value 32 (fun name -> safeText 128 name |> ignore))
        validateOptional fields "tls" validateTlsDefault
        validateOptional fields "encodedCharacters" (fun value ->
            validateBooleanObject value
                [ "allowEncodedSlash"; "allowEncodedBackSlash"; "allowEncodedNullCharacter"; "allowEncodedSemicolon"; "allowEncodedPercent"; "allowEncodedQuestionMark"; "allowEncodedHash" ])
        validateOptional fields "encodeQuerySemicolons" validateBoolean
        validateOptional fields "sanitizePath" validateBoolean
        validateOptional fields "maxHeaderBytes" (validateBoundedInteger 0L (16L * 1024L * 1024L))
        if tryField fields "aliasHeadersStrategy" |> Option.isSome
           && tryField fields "underscoreHeadersStrategy" |> Option.isSome then
            fail ()
        validateOptional fields "aliasHeadersStrategy" (fun value -> enumValue [ "keep"; "delete"; "reject" ] value |> ignore)
        validateOptional fields "underscoreHeadersStrategy" (fun value -> enumValue [ "keep"; "delete"; "reject" ] value |> ignore)

    let private validateHttp2 (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "maxConcurrentStreams"; "maxDecoderHeaderTableSize"; "maxEncoderHeaderTableSize" ] fields
        validateOptional fields "maxConcurrentStreams" (validateBoundedInteger 0L 1000000L)
        validateOptional fields "maxDecoderHeaderTableSize" (validateBoundedInteger 0L 1048576L)
        validateOptional fields "maxEncoderHeaderTableSize" (validateBoundedInteger 0L 1048576L)

    let private validateHttp3 (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "advertisedPort" ] fields
        validateOptional fields "advertisedPort" (validateBoundedInteger 0L 65535L)

    let private validateUdp (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "timeout" ] fields
        validateOptional fields "timeout" validateDuration

    let private validateObservability (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "accessLogs"; "metrics"; "tracing"; "traceVerbosity" ] fields
        validateOptional fields "accessLogs" validateBoolean
        validateOptional fields "metrics" validateBoolean
        validateOptional fields "tracing" validateBoolean
        validateOptional fields "traceVerbosity" (fun value -> enumValue [ "minimal"; "detailed" ] value |> ignore)

    let private validateTransport (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "lifeCycle"; "respondingTimeouts"; "keepAliveMaxTime"; "keepAliveMaxRequests" ] fields
        validateOptional fields "lifeCycle" (fun value -> validateDurationObject value [ "requestAcceptGraceTimeout"; "graceTimeOut" ])
        validateOptional fields "respondingTimeouts" (fun value -> validateDurationObject value [ "readTimeout"; "writeTimeout"; "idleTimeout" ])
        validateOptional fields "keepAliveMaxTime" validateDuration
        validateOptional fields "keepAliveMaxRequests" (validateBoundedInteger 0L 1000000L)

    let private validateEntryPoint
        (name: string)
        (node: JsonNode)
        (redirects: ResizeArray<string * string>)
        =
        let fields = requireObject node
        validateMembers
            [ "address"; "allowACMEByPass"; "reusePort"; "asDefault"; "transport"; "proxyProtocol"; "forwardedHeaders"; "http"; "http2"; "http3"; "udp"; "observability" ]
            fields
        let address = requiredField fields "address" |> stringValue
        let bind = parseAddress name address
        validateOptional fields "allowACMEByPass" validateBoolean
        validateOptional fields "reusePort" (fun value -> if booleanValue value then fail ())
        validateOptional fields "asDefault" validateBoolean
        validateOptional fields "transport" validateTransport
        validateOptional fields "proxyProtocol" (fun value -> validateTrustObject value false)
        validateOptional fields "forwardedHeaders" (fun value -> validateTrustObject value true)
        validateOptional fields "http" (fun value ->
            if bind.Protocol <> "tcp" then fail ()
            validateHttpConfig value name redirects)
        validateOptional fields "http2" (fun value ->
            if bind.Protocol <> "tcp" then fail ()
            validateHttp2 value)
        let hasHttp3 =
            match tryField fields "http3" with
            | Some value ->
                if bind.Protocol <> "tcp" then fail ()
                validateHttp3 value
                true
            | None -> false
        validateOptional fields "udp" validateUdp
        validateOptional fields "observability" validateObservability
        bind, hasHttp3

    let private validateStatusCode (value: string) =
        let segments = value.Split('-')
        let parseCode (text: string) =
            if text.Length <> 3 || (text |> Seq.exists (fun character -> character < '0' || character > '9')) then fail ()
            let mutable code = 0
            if not (Int32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, &code)) || code < 100 || code > 599 then fail ()
            code
        if segments.Length = 1 then parseCode segments[0] |> ignore
        elif segments.Length = 2 then
            let first = parseCode segments[0]
            let last = parseCode segments[1]
            if first > last then fail ()
        else fail ()

    let private validateModeMap (node: JsonNode) (allowedModes: string list) =
        validateStringMap node 128 (fun key -> if String.IsNullOrWhiteSpace(key) then fail ()) (fun value -> if not (List.contains value allowedModes) then fail ())

    let private validateAccessLogFields (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "defaultMode"; "names"; "headers"; "queryParameters" ] fields
        validateOptional fields "defaultMode" (fun value -> enumValue [ "keep"; "drop" ] value |> ignore)
        validateOptional fields "names" (fun value -> validateModeMap value [ "keep"; "drop" ])
        validateOptional fields "headers" (fun value ->
            let headerFields = requireObject value
            validateMembers [ "defaultMode"; "names" ] headerFields
            validateOptional headerFields "defaultMode" (fun item -> enumValue [ "keep"; "drop"; "redact" ] item |> ignore)
            validateOptional headerFields "names" (fun item -> validateModeMap item [ "keep"; "drop"; "redact" ]))
        validateOptional fields "queryParameters" (fun value ->
            let queryFields = requireObject value
            validateMembers [ "defaultMode" ] queryFields
            validateOptional queryFields "defaultMode" (fun item -> enumValue [ "keep"; "drop" ] item |> ignore))


    let private validatePrometheus (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "buckets"; "addEntryPointsLabels"; "addRoutersLabels"; "addServicesLabels"; "entryPoint"; "manualRouting"; "headerLabels" ] fields
        validateOptional fields "buckets" (fun value ->
            match requireValue value with
            | :? JsonArray as buckets ->
                if buckets.Count > 128 then fail ()
                let mutable previous = 0.0
                for bucket in buckets do
                    let current = doubleValue bucket
                    if current <= previous then fail ()
                    previous <- current
            | _ -> fail ())
        if stringValue (requiredField fields "entryPoint") <> privateAdminEntryPoint then fail ()
        validateOptional fields "addEntryPointsLabels" validateBoolean
        validateOptional fields "addRoutersLabels" validateBoolean
        validateOptional fields "addServicesLabels" validateBoolean
        validateOptional fields "manualRouting" validateBoolean
        validateOptional fields "headerLabels" (fun value ->
            validateStringMap value 64
                (fun label ->
                    if String.IsNullOrEmpty(label)
                       || label.Length > 63
                       || not (isAsciiAlphaNumeric label[0] || label[0] = '_')
                       || not (label |> Seq.forall (fun character -> isAsciiAlphaNumeric character || character = '_')) then fail ())
                requireHttpToken)

    let private validateStringAttributeMap (node: JsonNode) =
        validateStringMap node 256 (fun key -> if String.IsNullOrWhiteSpace(key) then fail ()) (fun _ -> ())

    let private validateOtelHeaders (node: JsonNode) =
        validateStringMap node 128 requireHttpToken (fun _ -> ())

    let private isLoopbackHost (host: string) =
        if String.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) then
            true
        else
            let mutable address = Unchecked.defaultof<IPAddress>
            IPAddress.TryParse(host, &address) && IPAddress.IsLoopback(address)

    let private validateLocalHttpDestination (endpoint: string) (allowedPaths: string list) =
        let endpoint = safeText 4096 endpoint
        let mutable uri = Unchecked.defaultof<Uri>
        if endpoint.Trim() <> endpoint
           || not (Uri.TryCreate(endpoint, UriKind.Absolute, &uri))
           || (uri.Scheme <> "http" && uri.Scheme <> "https")
           || not (isLoopbackHost uri.IdnHost)
           || not (List.contains uri.AbsolutePath allowedPaths)
           || not (String.IsNullOrEmpty(uri.UserInfo))
           || not (String.IsNullOrEmpty(uri.Query))
           || not (String.IsNullOrEmpty(uri.Fragment)) then
            fail ()

    let private validateOtelHttp (signal: string) (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "endpoint"; "headers" ] fields
        validateOptional fields "endpoint" (fun value ->
            let endpoint = stringValue value
            if String.IsNullOrWhiteSpace(endpoint) then fail ()
            validateLocalHttpDestination endpoint [ "/"; "/" + signal ])
        validateOptional fields "headers" validateOtelHeaders

    let private validateLocalHostPort (scheme: string) (node: JsonNode) =
        let endpoint = stringValue node
        let mutable uri = Unchecked.defaultof<Uri>
        if String.IsNullOrWhiteSpace(endpoint)
           || endpoint.Trim() <> endpoint
           || endpoint.Contains("/", StringComparison.Ordinal)
           || endpoint.Contains("?", StringComparison.Ordinal)
           || endpoint.Contains("#", StringComparison.Ordinal)
           || endpoint.Contains("@", StringComparison.Ordinal)
           || not (Uri.TryCreate(scheme + "://" + endpoint, UriKind.Absolute, &uri))
           || uri.Scheme <> scheme
           || not (isLoopbackHost uri.IdnHost)
           || uri.Port < 1
           || uri.Port > 65535
           || not (String.IsNullOrEmpty(uri.UserInfo))
           || not (String.IsNullOrEmpty(uri.Query))
           || not (String.IsNullOrEmpty(uri.Fragment))
           || uri.AbsolutePath <> "/" then
            fail ()

    let private validateCollectorEndpoint (node: JsonNode) =
        validateLocalHostPort "tcp" node
    let private validateOtelGrpc (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "endpoint"; "insecure"; "headers" ] fields
        validateOptional fields "endpoint" validateCollectorEndpoint
        validateOptional fields "insecure" validateBoolean
        validateOptional fields "headers" validateOtelHeaders

    let private validateOtelTracing (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "grpc"; "http" ] fields
        if tryField fields "grpc" |> Option.isSome && tryField fields "http" |> Option.isSome then fail ()
        validateOptional fields "grpc" validateOtelGrpc
        validateOptional fields "http" (validateOtelHttp "v1/traces")

    let private validateTracing (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "serviceName"; "resourceAttributes"; "globalAttributes"; "capturedRequestHeaders"; "capturedResponseHeaders"; "safeQueryParams"; "sampleRate"; "addInternals"; "otlp" ] fields
        validateOptional fields "serviceName" (fun value -> stringValue value |> ignore)
        if tryField fields "resourceAttributes" |> Option.isSome
           && tryField fields "globalAttributes" |> Option.isSome then
            fail ()
        validateOptional fields "resourceAttributes" validateStringAttributeMap
        validateOptional fields "globalAttributes" validateStringAttributeMap
        validateOptional fields "capturedRequestHeaders" (fun value -> validateStringArray value 128 requireHttpToken)
        validateOptional fields "capturedResponseHeaders" (fun value -> validateStringArray value 128 requireHttpToken)
        validateOptional fields "safeQueryParams" (fun value ->
            validateStringArray value 128 (fun item -> if String.IsNullOrWhiteSpace(item) || item.Length > 256 then fail ()))
        validateOptional fields "sampleRate" (fun value ->
            let sample = doubleValue value
            if sample < 0.0 || sample > 1.0 then fail ())
        validateOptional fields "addInternals" validateBoolean
        validateOptional fields "otlp" validateOtelTracing
    let private validateOtelLog (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "serviceName"; "resourceAttributes"; "grpc"; "http" ] fields
        validateOptional fields "serviceName" (fun value -> stringValue value |> ignore)
        validateOptional fields "resourceAttributes" validateStringAttributeMap
        if tryField fields "grpc" |> Option.isSome && tryField fields "http" |> Option.isSome then fail ()
        validateOptional fields "grpc" validateOtelGrpc
        validateOptional fields "http" (validateOtelHttp "v1/logs")

    let private validateOtelMetrics (node: JsonNode) =
        let fields = requireObject node
        validateMembers
            [ "grpc"; "http"; "addEntryPointsLabels"; "addRoutersLabels"; "addServicesLabels"; "explicitBoundaries"; "pushInterval"; "serviceName"; "resourceAttributes" ]
            fields
        if tryField fields "grpc" |> Option.isSome && tryField fields "http" |> Option.isSome then fail ()
        validateOptional fields "grpc" validateOtelGrpc
        validateOptional fields "http" (validateOtelHttp "v1/metrics")
        validateOptional fields "addEntryPointsLabels" validateBoolean
        validateOptional fields "addRoutersLabels" validateBoolean
        validateOptional fields "addServicesLabels" validateBoolean
        validateOptional fields "explicitBoundaries" (fun value ->
            match requireValue value with
            | :? JsonArray as boundaries ->
                if boundaries.Count > 128 then fail ()
                let mutable previous = 0.0
                for boundary in boundaries do
                    let current = doubleValue boundary
                    if current <= previous then fail ()
                    previous <- current
            | _ -> fail ())
        validateOptional fields "pushInterval" validateDuration
        validateOptional fields "serviceName" (fun value -> stringValue value |> ignore)
        validateOptional fields "resourceAttributes" validateStringAttributeMap

    let private validateDatadogMetrics (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "address"; "pushInterval"; "addEntryPointsLabels"; "addRoutersLabels"; "addServicesLabels"; "prefix" ] fields
        validateLocalHostPort "udp" (requiredField fields "address")
        validateOptional fields "pushInterval" validateDuration
        validateOptional fields "addEntryPointsLabels" validateBoolean
        validateOptional fields "addRoutersLabels" validateBoolean
        validateOptional fields "addServicesLabels" validateBoolean
        validateOptional fields "prefix" (fun value -> stringValue value |> ignore)

    let private validateStatsDMetrics (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "address"; "pushInterval"; "addEntryPointsLabels"; "addRoutersLabels"; "addServicesLabels"; "prefix" ] fields
        validateOptional fields "address" (validateLocalHostPort "udp")
        validateOptional fields "pushInterval" validateDuration
        validateOptional fields "addEntryPointsLabels" validateBoolean
        validateOptional fields "addRoutersLabels" validateBoolean
        validateOptional fields "addServicesLabels" validateBoolean
        validateOptional fields "prefix" (fun value -> stringValue value |> ignore)

    let private validateInfluxDB2Metrics (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "address"; "pushInterval"; "org"; "bucket"; "addEntryPointsLabels"; "addRoutersLabels"; "addServicesLabels"; "additionalLabels" ] fields
        validateOptional fields "address" (fun value ->
            let endpoint = stringValue value
            if String.IsNullOrWhiteSpace(endpoint) then fail ()
            validateLocalHttpDestination endpoint [ "/" ])
        validateOptional fields "pushInterval" validateDuration
        validateOptional fields "org" (fun value -> stringValue value |> ignore)
        validateOptional fields "bucket" (fun value -> stringValue value |> ignore)
        validateOptional fields "addEntryPointsLabels" validateBoolean
        validateOptional fields "addRoutersLabels" validateBoolean
        validateOptional fields "addServicesLabels" validateBoolean
        validateOptional fields "additionalLabels" validateStringAttributeMap

    let private validateMetrics (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "addInternals"; "prometheus"; "datadog"; "statsD"; "influxDB2"; "otlp" ] fields
        validateOptional fields "addInternals" validateBoolean
        validateOptional fields "prometheus" validatePrometheus
        validateOptional fields "datadog" validateDatadogMetrics
        validateOptional fields "statsD" validateStatsDMetrics
        validateOptional fields "influxDB2" validateInfluxDB2Metrics
        validateOptional fields "otlp" validateOtelMetrics


    let private validateGlobal (node: JsonNode) =
        validateBooleanObject node [ "checkNewVersion"; "sendAnonymousUsage"; "notAppendXForwardedFor" ]

    let private validateCore (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "defaultRuleSyntax"; "strictTLSOptions" ] fields
        validateOptional fields "defaultRuleSyntax" (fun value -> enumValue [ "v2"; "v3" ] value |> ignore)
        validateOptional fields "strictTLSOptions" validateBoolean
    let private validateHostResolver (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "cnameFlattening"; "resolvDepth" ] fields
        validateOptional fields "cnameFlattening" validateBoolean
        validateOptional fields "resolvDepth" (validateBoundedInteger 0L 64L)

    let private validatePing (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "entryPoint"; "manualRouting"; "terminatingStatusCode" ] fields
        if stringValue (requiredField fields "entryPoint") <> privateAdminEntryPoint then fail ()
        validateOptional fields "manualRouting" validateBoolean
        validateOptional fields "terminatingStatusCode" (validateBoundedInteger 100L 599L)
    let private validateServerTransport (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "insecureSkipVerify"; "rootCAs"; "maxIdleConnsPerHost"; "forwardingTimeouts" ] fields
        validateOptional fields "insecureSkipVerify" (fun value -> if booleanValue value then fail ())
        validateOptional fields "rootCAs" validatePemAuthorities
        validateOptional fields "maxIdleConnsPerHost" (validateBoundedInteger 0L 1000000L)
        validateOptional fields "forwardingTimeouts" (fun value ->
            validateDurationObject value [ "dialTimeout"; "responseHeaderTimeout"; "idleConnTimeout" ])

    let private validateTcpServerTls (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "insecureSkipVerify"; "rootCAs" ] fields
        validateOptional fields "insecureSkipVerify" (fun value -> if booleanValue value then fail ())
        validateOptional fields "rootCAs" validatePemAuthorities

    let private validateTcpServerTransport (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "dialKeepAlive"; "dialTimeout"; "terminationDelay"; "tls" ] fields
        for field in fields do
            match field.Key with
            | "tls" -> validateTcpServerTls field.Value
            | _ -> validateDuration field.Value

    let private validateLog (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "level"; "format"; "noColor"; "otlp" ] fields
        validateOptional fields "level" (fun value -> enumValue [ "PANIC"; "FATAL"; "ERROR"; "WARN"; "INFO"; "DEBUG" ] value |> ignore)
        validateOptional fields "format" (fun value -> enumValue [ "common"; "json" ] value |> ignore)
        validateOptional fields "noColor" validateBoolean
        validateOptional fields "otlp" validateOtelLog

    let private validateAccessLog (node: JsonNode) =
        let fields = requireObject node
        validateMembers [ "format"; "filters"; "fields"; "bufferingSize"; "addInternals"; "dualOutput"; "otlp" ] fields
        validateOptional fields "format" (fun value -> enumValue [ "common"; "json"; "genericCLF" ] value |> ignore)
        validateOptional fields "filters" (fun value ->
            let filters = requireObject value
            validateMembers [ "statusCodes"; "retryAttempts"; "minDuration" ] filters
            validateOptional filters "statusCodes" (fun item -> validateStringArray item 128 validateStatusCode)
            validateOptional filters "retryAttempts" validateBoolean
            validateOptional filters "minDuration" validateDuration)
        validateOptional fields "fields" validateAccessLogFields
        validateOptional fields "bufferingSize" (validateBoundedInteger 0L 1000000L)
        validateOptional fields "addInternals" validateBoolean
        validateOptional fields "dualOutput" validateBoolean
        validateOptional fields "otlp" validateOtelLog

    /// Validate bounded native static fields, returning every user and legacy entrypoint protocol.
    /// EntryPoint.address defaults to TCP when its protocol suffix is omitted; HTTP/3 contributes
    /// an additional UDP socket on the same bind address and port.
    let validate (legacy: Map<string, int>) (adminPort: int) (settings: JsonObject) : Map<string, string> =
        if isNull settings || adminPort < 1 || adminPort > 65535 then fail ()
        let rootFields =
            [ "entryPoints"; "certificatesResolvers"; "global"; "core"; "log"; "accessLog"; "metrics"; "tracing"; "serversTransport"; "tcpServersTransport"; "ping"; "hostResolver" ]
        validateMembers rootFields settings

        let names = HashSet<string>(StringComparer.OrdinalIgnoreCase)
        let mutable protocols: Map<string, string> = Map.empty
        let binds = ResizeArray<Bind>()
        let redirects = ResizeArray<string * string>()

        if legacy.Count + (tryField settings "entryPoints" |> Option.map (requireObject >> fun item -> item.Count) |> Option.defaultValue 0) > 64 then fail ()
        for KeyValue(name, port) in legacy do
            let name = requireEntryPointName name
            if not (names.Add(name)) || port < 1 || port > 65535 then fail ()
            protocols <- Map.add name "tcp" protocols
            binds.Add({ Name = name; Protocol = "tcp"; Host = None; Port = port })

        validateOptional settings "entryPoints" (fun value ->
            let entryPoints = requireObject value
            if entryPoints.Count > 64 then fail ()
            for field in entryPoints do
                let name = requireEntryPointName field.Key
                if not (names.Add(name)) then fail ()
                let bind, hasHttp3 = validateEntryPoint name field.Value redirects
                protocols <- Map.add name bind.Protocol protocols
                binds.Add(bind)
                if hasHttp3 then
                    binds.Add({ bind with Protocol = "udp" }))

        validateOptional settings "global" validateGlobal
        validateOptional settings "core" validateCore
        validateOptional settings "hostResolver" validateHostResolver
        validateOptional settings "log" validateLog
        validateOptional settings "accessLog" validateAccessLog
        validateOptional settings "metrics" validateMetrics
        validateOptional settings "ping" validatePing
        validateOptional settings "tracing" validateTracing
        validateOptional settings "serversTransport" validateServerTransport
        validateOptional settings "tcpServersTransport" validateTcpServerTransport

        for index = 0 to binds.Count - 1 do
            let current = binds[index]
            let adminBind = { current with Name = "admin"; Protocol = "tcp"; Host = Some IPAddress.Loopback; Port = adminPort }
            if bindsOverlap current adminBind then fail ()
            for otherIndex = index + 1 to binds.Count - 1 do
                if bindsOverlap current binds[otherIndex] then fail ()

        for _, target in redirects do
            if isReservedEntryPointName target
               || not (names.Contains(target))
               || Map.tryFind target protocols <> Some "tcp" then
                fail ()

        protocols
    let private staticObject (root: JsonObject) (name: string) =
        match tryField root name with
        | Some value -> requireObject value
        | None -> JsonObject()

    let private fileReferenceName (value: string) =
        let value = safeText 128 value
        let separator = value.LastIndexOf('@')
        if separator <= 0 || separator = value.Length - 1 || value.Substring(separator + 1) <> "file" then fail ()
        let name = value.Substring(0, separator)
        if not (isTraefikName name) then fail ()
        name

    let private dynamicObject (root: JsonObject) (section: string) (name: string) =
        let sectionFields = staticObject root section
        staticObject sectionFields name

    let private ensurePrivateAdminEntryPoint (fields: JsonObject) =
        if stringValue (requiredField fields "entryPoint") <> privateAdminEntryPoint then fail ()

    /// Resolve static entrypoint references only to the operator-owned file-provider graph.
    /// `default` is the built-in TLS option; explicit option and middleware references must use @file.
    let validateReferences (settings: JsonObject) (dynamic: JsonObject) (resolvers: Set<string>) : unit =
        if isNull settings || isNull dynamic then fail ()
        let dynamicMiddlewares = dynamicObject dynamic "http" "middlewares"
        let dynamicTlsOptions = dynamicObject dynamic "tls" "options"
        let entryPoints = staticObject settings "entryPoints"

        for entryPoint in entryPoints do
            let entryPointFields = requireObject entryPoint.Value
            match tryField entryPointFields "http" with
            | None -> ()
            | Some httpNode ->
                let httpFields = requireObject httpNode
                validateOptional httpFields "middlewares" (fun node ->
                    validateStringArray node 32 (fun reference ->
                        let name = fileReferenceName reference
                        if not (dynamicMiddlewares.ContainsKey(name)) then fail ()))
                validateOptional httpFields "tls" (fun node ->
                    let tlsFields = requireObject node
                    validateOptional tlsFields "options" (fun value ->
                        let reference = stringValue value
                        if reference <> "default" then
                            let name = fileReferenceName reference
                            if not (dynamicTlsOptions.ContainsKey(name)) then fail ())
                    validateOptional tlsFields "certResolver" (fun value ->
                        let name = stringValue value |> requireName
                        if not (Set.contains name resolvers) then fail ()))

        match tryField settings "metrics" with
        | Some metricsNode ->
            let metricsFields = requireObject metricsNode
            match tryField metricsFields "prometheus" with
            | Some prometheusNode -> ensurePrivateAdminEntryPoint (requireObject prometheusNode)
            | None -> ()
        | None -> ()

        match tryField settings "ping" with
        | Some pingNode -> ensurePrivateAdminEntryPoint (requireObject pingNode)
        | None -> ()

        for entryPoint in entryPoints do
            let entryPointFields = requireObject entryPoint.Value
            match tryField entryPointFields "http" with
            | Some httpNode ->
                let httpFields = requireObject httpNode
                match tryField httpFields "redirections" with
                | Some redirectionsNode ->
                    let redirections = requireObject redirectionsNode
                    match tryField redirections "entryPoint" with
                    | Some redirectNode ->
                        let redirect = requireObject redirectNode
                        validateOptional redirect "to" (fun value -> if isReservedEntryPointName (stringValue value) then fail ())
                    | None -> ()
                | None -> ()
            | None -> ()

        ()
