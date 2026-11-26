#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System
open System.Collections.Generic
open System.Security.Cryptography.X509Certificates
open System.Text.Json.Nodes
open System.Text.RegularExpressions

/// Strict validation of the supported Traefik 3.7.16 file-provider HTTP, TCP, and UDP graphs.
/// Unknown fields fail closed so a version bump cannot silently expand host access.
module TraefikDynamic =
    let private reject () = invalidOp "Traefik dynamic configuration is invalid."

    let private safeString (value: string) =
        // Only an opening Go-template delimiter is executable. `${1}` is Traefik's
        // documented regexp replacement syntax, and a closing brace alone is literal.
        if isNull value || value.Contains("{{", StringComparison.Ordinal) then reject ()
        value

    let private validName (value: string) =
        let value = safeString value
        if value.Length = 0 || value.Length > 128 then reject ()
        for index = 0 to value.Length - 1 do
            let character = value[index]
            if not (Char.IsAsciiLetterOrDigit character || character = '_' || character = '-' || character = '.') then
                reject ()
        if not (Char.IsAsciiLetterOrDigit value[0]) then reject ()
        value
    let private localReference (value: string) =
        let value = safeString value
        if value.EndsWith("@file", StringComparison.Ordinal) then
            value.Substring(0, value.Length - 5) |> validName
        else
            validName value

    let private property (parent: JsonObject) (name: string) =
        let mutable value = Unchecked.defaultof<JsonNode>
        if parent.TryGetPropertyValue(name, &value) then
            if isNull value then reject ()
            Some value
        else
            None

    let private requireObject (node: JsonNode) =
        match node with
        | :? JsonObject as value -> value
        | _ -> reject ()

    let private requireArray (node: JsonNode) =
        match node with
        | :? JsonArray as value -> value
        | _ -> reject ()

    let private objectFields (node: JsonObject) (allowed: string list) =
        for KeyValue(name, _) in node do
            if not (List.contains name allowed) then reject ()

    let private stringValue (node: JsonNode) =
        let value =
            try node.GetValue<string>()
            with _ -> reject ()
        safeString value

    let private intValue (node: JsonNode) =
        try node.GetValue<int>()
        with _ -> reject ()

    let private int64Value (node: JsonNode) =
        try node.GetValue<int64>()
        with _ -> reject ()

    let private boolValue (node: JsonNode) =
        try node.GetValue<bool>()
        with _ -> reject ()

    let private optional (parent: JsonObject) (name: string) (validate: JsonNode -> unit) =
        property parent name |> Option.iter validate

    let private required (parent: JsonObject) (name: string) (validate: JsonNode -> 'T) =
        match property parent name with
        | Some node -> validate node
        | None -> reject ()

    let private optionalString (parent: JsonObject) (name: string) =
        property parent name |> Option.map stringValue

    let private requiredString (parent: JsonObject) (name: string) =
        required parent name stringValue

    let private strings (node: JsonNode) =
        requireArray node
        |> Seq.map (fun item ->
            if isNull item then reject ()
            stringValue item)
        |> Seq.toList


    let private requiredStrings (parent: JsonObject) (name: string) =
        required parent name strings

    let private integer (node: JsonNode) = intValue node |> ignore
    let private integer64 (node: JsonNode) = int64Value node |> ignore
    let private boolean (node: JsonNode) = boolValue node |> ignore
    let private stringArray (node: JsonNode) = strings node |> ignore

    let private nonNegativeInt (node: JsonNode) =
        if intValue node < 0 then reject ()

    let private positiveInt (node: JsonNode) =
        if intValue node <= 0 then reject ()

    let private nonNegativeInt64 (node: JsonNode) =
        if int64Value node < 0L then reject ()

    let private optionalInteger (parent: JsonObject) (name: string) = optional parent name integer
    let private optionalBoolean (parent: JsonObject) (name: string) = optional parent name boolean
    let private optionalStringArray (parent: JsonObject) (name: string) = optional parent name stringArray

    let private optionalStringField (parent: JsonObject) (name: string) =
        optional parent name (stringValue >> ignore)

    let private durationPattern = Regex(@"\A(?:0|[-+]?(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|μs|ms|s|m|h))+)\z", RegexOptions.CultureInvariant)

    let private duration (node: JsonNode) =
        let value = stringValue node
        if not (durationPattern.IsMatch(value)) then reject ()


    let private optionalDuration (parent: JsonObject) (name: string) = optional parent name duration

    let private validateStringMap (node: JsonNode) =
        let values = requireObject node
        for KeyValue(name, value) in values do
            safeString name |> ignore
            if isNull value then reject ()
            stringValue value |> ignore

    let private validateIntegerMap (values: JsonObject) =
        for KeyValue(name, value) in values do
            safeString name |> ignore
            if isNull value then reject ()
            intValue value |> ignore
    let private optionalStringMap (parent: JsonObject) (name: string) = optional parent name validateStringMap

    let private objectMap (node: JsonNode option) =
        match node with
        | None -> Map.empty
        | Some value ->
            let values = requireObject value
            values
            |> Seq.map (fun pair -> validName pair.Key, requireObject pair.Value)
            |> Map.ofSeq

    let private childObjects (parent: JsonObject option) (name: string) =
        match parent with
        | None -> Map.empty
        | Some value -> property value name |> objectMap

    let private optionalObject (parent: JsonObject) (name: string) (validate: JsonObject -> unit) =
        property parent name |> Option.iter (requireObject >> validate)
    let private rejectGeneratedPrefix (prefix: string) (values: Map<string, 'T>) =
        for KeyValue(name, _) in values do
            if name.StartsWith(prefix, StringComparison.Ordinal) then reject ()


    let private validateHttpUrl (node: JsonNode) =
        let address = stringValue node
        let mutable uri = Unchecked.defaultof<Uri>
        if not (Uri.TryCreate(address, UriKind.Absolute, &uri)) then reject ()
        if (uri.Scheme <> Uri.UriSchemeHttp && uri.Scheme <> Uri.UriSchemeHttps && uri.Scheme <> "h2c")
           || String.IsNullOrEmpty(uri.Host)
           || not (String.IsNullOrEmpty(uri.UserInfo))
           || not (String.IsNullOrEmpty(uri.Fragment)) then
            reject ()


    let private validateHostPortValue (address: string) =
        let address = safeString address
        let mutable uri = Unchecked.defaultof<Uri>
        if not (Uri.TryCreate("tcp://" + address, UriKind.Absolute, &uri))
           || String.IsNullOrEmpty(uri.Host)
           || uri.Port < 1
           || uri.Port > 65535
           || not (String.IsNullOrEmpty(uri.UserInfo))
           || uri.AbsolutePath <> "/"
           || not (String.IsNullOrEmpty(uri.Query))
           || not (String.IsNullOrEmpty(uri.Fragment)) then
            reject ()

    let private validateHostPort (node: JsonNode) = stringValue node |> validateHostPortValue

    let private certificatePemPattern =
        Regex(@"\A\s*(?:-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+\z", RegexOptions.CultureInvariant)

    let private validatePemText (pem: string) =
        let pem = safeString pem
        if not (certificatePemPattern.IsMatch(pem)) then reject ()
        let certificates = X509Certificate2Collection()
        try
            try
                certificates.ImportFromPem(pem)
                if certificates.Count = 0 then reject ()
            with _ -> reject ()
        finally
            for certificate in certificates do certificate.Dispose()

    let private validatePublicCertificateOrName (node: JsonNode) =
        let value = stringValue node
        if value.StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal) then
            validatePemText value
        else
            validName value |> ignore

    let private validatePublicCertificateArray (node: JsonNode) =
        requireArray node
        |> Seq.iter (fun value ->
            if isNull value then reject ()
            validatePublicCertificateOrName value)

    let private validateClientCertificateReference (node: JsonNode) =
        let reference = requireObject node
        objectFields reference [ "certificate" ]
        requiredString reference "certificate" |> validName |> ignore

    let private validateClientCertificateArray (node: JsonNode) =
        requireArray node
        |> Seq.iter (fun value ->
            if isNull value then reject ()
            validateClientCertificateReference value)

    let private validateForwardAuthTls (node: JsonObject) =
        objectFields node [ "caCertificate"; "clientCertificate"; "insecureSkipVerify"; "caOptional" ]
        optional node "caCertificate" validatePublicCertificateOrName
        optional node "clientCertificate" (fun value -> validName (stringValue value) |> ignore)
        optional node "insecureSkipVerify" (fun value -> if boolValue value then reject ())
        optional node "caOptional" (fun value -> if boolValue value then reject ())

    let private requireReference (values: Map<string, 'T>) (value: string) =
        let name = localReference value
        if not (Map.containsKey name values) then reject ()
        name

    let private requireSetReference (values: Set<string>) (value: string) =
        let name = validName value
        if not (Set.contains name values) then reject ()
        name

    let private validateEndpointReferences (entryPoints: Map<string, string>) (protocol: string) (router: JsonObject) =
        let names = requiredStrings router "entryPoints"
        if List.isEmpty names then reject ()
        let seen = HashSet<string>(StringComparer.Ordinal)
        for name in names do
            let name = validName name
            if name = "keroosha-admin" || not (seen.Add name) || Map.tryFind name entryPoints <> Some protocol then reject ()

    let private validateTlsDomains (node: JsonNode) =
        let domains = requireArray node
        if domains.Count = 0 then reject ()
        for domainNode in domains do
            if isNull domainNode then reject ()
            let domain = requireObject domainNode
            objectFields domain [ "main"; "sans" ]
            let main = requiredString domain "main"
            if String.IsNullOrWhiteSpace(main) then reject ()
            match property domain "sans" with
            | Some sans -> strings sans |> ignore
            | None -> ()

    let private validateHttpRouterTls (resolvers: Set<string>) (tlsOptions: Set<string>) (node: JsonObject) =
        objectFields node [ "options"; "certResolver"; "domains" ]

        optional node "domains" validateTlsDomains
        optionalStringField node "options"
        optionalStringField node "certResolver"
        optional node "options" (fun value ->
            let name = stringValue value |> localReference
            if name <> "default" && not (Set.contains name tlsOptions) then reject ())
        optional node "certResolver" (fun value -> requireSetReference resolvers (stringValue value) |> ignore)

    let private validateTcpRouterTls (resolvers: Set<string>) (tlsOptions: Set<string>) (node: JsonObject) =
        objectFields node [ "passthrough"; "options"; "certResolver"; "domains" ]
        optionalBoolean node "passthrough"
        optionalStringField node "options"
        optionalStringField node "certResolver"
        optional node "options" (fun value ->
            let name = stringValue value |> localReference
            if name <> "default" && not (Set.contains name tlsOptions) then reject ())
        optional node "certResolver" (fun value -> requireSetReference resolvers (stringValue value) |> ignore)
        optional node "domains" validateTlsDomains

    let private validateRouterObservability (node: JsonObject) =
        objectFields node [ "accessLogs"; "metrics"; "tracing"; "traceVerbosity" ]
        optionalBoolean node "accessLogs"
        optionalBoolean node "metrics"
        optionalBoolean node "tracing"
        optional node "traceVerbosity" (fun value ->
            match stringValue value with
            | "minimal"
            | "detailed" -> ()
            | _ -> reject ())

    let private validateEmptyObject (node: JsonNode) =
        let value = requireObject node
        if value.Count <> 0 then reject ()

    let private validateProxyProtocol (node: JsonNode) =
        let value = requireObject node
        objectFields value [ "version" ]
        optional value "version" (fun version ->
            let version = intValue version
            if version <> 1 && version <> 2 then reject ())

    let private validateHttpTransportTls (node: JsonObject) =
        objectFields node
            [ "serverName"; "insecureSkipVerify"; "rootCAs"; "certificates"; "cipherSuites"; "minVersion"; "maxVersion"
              "maxIdleConnsPerHost"; "forwardingTimeouts"; "disableHTTP2"; "peerCertURI" ]
        optionalStringField node "serverName"
        optional node "insecureSkipVerify" (fun value -> if boolValue value then reject ())
        optional node "rootCAs" validatePublicCertificateArray
        optional node "certificates" validateClientCertificateArray
        optionalStringArray node "cipherSuites"
        optionalStringField node "minVersion"
        optionalStringField node "maxVersion"
        optional node "minVersion" (fun value ->
            match stringValue value with
            | "VersionTLS12"
            | "VersionTLS13" -> ()
            | _ -> reject ())
        optional node "maxVersion" (fun value ->
            match stringValue value with
            | "VersionTLS12"
            | "VersionTLS13" -> ()
            | _ -> reject ())
        optionalInteger node "maxIdleConnsPerHost"
        optionalBoolean node "disableHTTP2"
        optionalStringField node "peerCertURI"
        optionalObject node "forwardingTimeouts" (fun timeouts ->
            objectFields timeouts [ "dialTimeout"; "responseHeaderTimeout"; "idleConnTimeout"; "readIdleTimeout"; "pingTimeout" ]
            optionalDuration timeouts "dialTimeout"
            optionalDuration timeouts "responseHeaderTimeout"
            optionalDuration timeouts "idleConnTimeout"
            optionalDuration timeouts "readIdleTimeout"
            optionalDuration timeouts "pingTimeout")
        match optionalString node "minVersion", optionalString node "maxVersion" with
        | Some "VersionTLS13", Some "VersionTLS12" -> reject ()
        | _ -> ()

    let private validateHttpTransport (node: JsonObject) =
        validateHttpTransportTls node

    let private validateTcpTransportTls (node: JsonObject) =
        objectFields node [ "serverName"; "insecureSkipVerify"; "rootCAs"; "certificates"; "peerCertURI" ]
        optionalStringField node "serverName"
        optional node "insecureSkipVerify" (fun value -> if boolValue value then reject ())
        optional node "rootCAs" validatePublicCertificateArray
        optional node "certificates" validateClientCertificateArray
        optionalStringField node "peerCertURI"

    let private validateTcpTransport (node: JsonObject) =
        objectFields node [ "dialKeepAlive"; "dialTimeout"; "proxyProtocol"; "terminationDelay"; "tls" ]
        optionalDuration node "dialKeepAlive"
        optionalDuration node "dialTimeout"
        optionalDuration node "terminationDelay"
        optionalObject node "proxyProtocol" (fun value -> validateProxyProtocol (value :> JsonNode))
        optionalObject node "tls" validateTcpTransportTls

    let private validateHealthCheck (node: JsonObject) =
        objectFields node
            [ "scheme"; "mode"; "path"; "method"; "status"; "port"; "interval"; "unhealthyInterval"; "timeout"
              "hostname"; "followRedirects"; "headers" ]
        optional node "scheme" (fun value ->
            match stringValue value with
            | "http"
            | "https" -> ()
            | _ -> reject ())
        optional node "mode" (fun value ->
            match stringValue value with
            | "http"
            | "tcp"
            | "grpc" -> ()
            | _ -> reject ())
        optionalStringField node "path"
        optionalStringField node "method"
        optional node "status" (fun value ->
            let status = intValue value
            if status < 100 || status > 599 then reject ())
        optional node "port" (fun value ->
            let port = intValue value
            if port < 1 || port > 65535 then reject ())
        optionalDuration node "interval"
        optionalDuration node "unhealthyInterval"
        optionalDuration node "timeout"
        optionalStringField node "hostname"
        optionalBoolean node "followRedirects"
        optionalStringMap node "headers"

    let private validateHttpServer (node: JsonObject) =
        objectFields node [ "url"; "weight"; "preservePath" ]
        required node "url" validateHttpUrl |> ignore
        optional node "weight" positiveInt
        optionalBoolean node "preservePath"

    let private validateCookie (node: JsonObject) =
        objectFields node [ "name"; "secure"; "httpOnly"; "sameSite"; "maxAge"; "path"; "domain" ]
        optionalStringField node "name"
        optionalBoolean node "secure"
        optionalBoolean node "httpOnly"
        optional node "sameSite" (fun value ->
            match stringValue value with
            | "none" | "lax" | "strict" | "None" | "Lax" | "Strict" -> ()
            | _ -> reject ())
        optionalInteger node "maxAge"
        optionalStringField node "path"
        optionalStringField node "domain"

    let private validateSticky (node: JsonObject) =
        objectFields node [ "cookie" ]
        optionalObject node "cookie" validateCookie

    let private validateWeightedServices (services: Map<string, JsonObject>) (graph: Dictionary<string, ResizeArray<string>>) (source: string) (node: JsonNode) =
        let values = requireArray node
        if values.Count = 0 then reject ()
        for item in values do
            if isNull item then reject ()
            let weighted = requireObject item
            objectFields weighted [ "name"; "weight" ]
            let target = requiredString weighted "name" |> requireReference services
            graph[source].Add("service:" + target)
            optional weighted "weight" nonNegativeInt

    let private validateHttpLoadBalancer (transports: Map<string, JsonObject>) (node: JsonObject) =
        objectFields node
            [ "sticky"; "servers"; "strategy"; "healthCheck"; "passiveHealthCheck"; "passHostHeader"
              "responseForwarding"; "serversTransport" ]
        optionalObject node "sticky" validateSticky
        let servers = required node "servers" requireArray
        if servers.Count = 0 then reject ()
        for server in servers do
            if isNull server then reject ()
            validateHttpServer (requireObject server)
        optional node "strategy" (fun value ->
            match stringValue value with
            | "wrr" | "p2c" | "hrw" | "leasttime" -> ()
            | _ -> reject ())
        optionalObject node "healthCheck" validateHealthCheck
        optionalObject node "passiveHealthCheck" (fun health ->
            objectFields health [ "failureWindow"; "maxFailedAttempts" ]
            optionalDuration health "failureWindow"
            optional health "maxFailedAttempts" positiveInt)
        optionalBoolean node "passHostHeader"
        optionalObject node "responseForwarding" (fun forwarding ->
            objectFields forwarding [ "flushInterval" ]
            optionalDuration forwarding "flushInterval")
        optional node "serversTransport" (fun value -> requireReference transports (stringValue value) |> ignore)

    let private validateHttpWeightedService (services: Map<string, JsonObject>) (graph: Dictionary<string, ResizeArray<string>>) (source: string) (node: JsonObject) (withSticky: bool) =
        if withSticky then
            objectFields node [ "services"; "sticky"; "healthCheck" ]
        else
            objectFields node [ "services"; "healthCheck" ]
        let values = required node "services" requireArray
        validateWeightedServices services graph source (values :> JsonNode)
        optionalObject node "healthCheck" (fun value -> validateEmptyObject (value :> JsonNode))
        if withSticky then optionalObject node "sticky" validateSticky

    let private validateHttpMirrorService (services: Map<string, JsonObject>) (graph: Dictionary<string, ResizeArray<string>>) (source: string) (node: JsonObject) =
        objectFields node [ "service"; "mirrorBody"; "maxBodySize"; "mirrors"; "healthCheck" ]
        let primary = requiredString node "service" |> requireReference services
        graph[source].Add("service:" + primary)
        optionalBoolean node "mirrorBody"
        optional node "maxBodySize" integer64
        optionalObject node "healthCheck" (fun value -> validateEmptyObject (value :> JsonNode))
        optional node "mirrors" (fun value ->
            let mirrors = requireArray value
            for item in mirrors do
                if isNull item then reject ()
                let mirror = requireObject item
                objectFields mirror [ "name"; "percent" ]
                let target = requiredString mirror "name" |> requireReference services
                graph[source].Add("service:" + target)
                optional mirror "percent" (fun percent ->
                    let value = intValue percent
                    if value < 0 || value > 100 then reject ()))

    let private validateHttpFailover (services: Map<string, JsonObject>) (graph: Dictionary<string, ResizeArray<string>>) (source: string) (node: JsonObject) =
        objectFields node [ "service"; "fallback"; "healthCheck"; "errors" ]
        for field in [ "service"; "fallback" ] do
            let target = requiredString node field |> requireReference services
            graph[source].Add("service:" + target)
        optionalObject node "healthCheck" (fun value -> validateEmptyObject (value :> JsonNode))
        optionalObject node "errors" (fun errors ->
            objectFields errors [ "maxRequestBodyBytes"; "status" ]
            optional errors "maxRequestBodyBytes" integer64
            optionalStringArray errors "status")

    let private validateHttpService (services: Map<string, JsonObject>) (transports: Map<string, JsonObject>) (graph: Dictionary<string, ResizeArray<string>>) (name: string) (node: JsonObject) =
        objectFields node [ "loadBalancer"; "highestRandomWeight"; "weighted"; "mirroring"; "failover" ]
        let source = "service:" + name
        let strategy = [ "loadBalancer"; "highestRandomWeight"; "weighted"; "mirroring"; "failover" ]
        let selected = strategy |> List.filter (fun field -> property node field |> Option.isSome)
        if selected.Length <> 1 then reject ()
        match selected.Head with
        | "loadBalancer" -> optionalObject node "loadBalancer" (validateHttpLoadBalancer transports)
        | "highestRandomWeight" -> optionalObject node "highestRandomWeight" (fun value -> validateHttpWeightedService services graph source value false)
        | "weighted" -> optionalObject node "weighted" (fun value -> validateHttpWeightedService services graph source value true)
        | "mirroring" -> optionalObject node "mirroring" (validateHttpMirrorService services graph source)
        | "failover" -> optionalObject node "failover" (validateHttpFailover services graph source)
        | _ -> reject ()

    let private validateIpStrategy (node: JsonObject) =
        objectFields node [ "depth"; "excludedIPs"; "ipv6Subnet" ]
        optional node "depth" nonNegativeInt
        optionalStringArray node "excludedIPs"
        optional node "ipv6Subnet" (fun value ->
            let subnet = intValue value
            if subnet < 1 || subnet > 128 then reject ())

    let private validateSourceCriterion (node: JsonObject) =
        objectFields node [ "ipStrategy"; "requestHeaderName"; "requestHost" ]
        optionalObject node "ipStrategy" validateIpStrategy
        optionalStringField node "requestHeaderName"
        optionalBoolean node "requestHost"
        let selected =
            [ property node "ipStrategy" |> Option.isSome
              optionalString node "requestHeaderName" |> Option.isSome
              property node "requestHost" |> Option.isSome ]
            |> List.filter id
        if selected.Length > 1 then reject ()

    let private validateHttpMiddlewareConfig
        (services: Map<string, JsonObject>)
        (graph: Dictionary<string, ResizeArray<string>>)
        (source: string)
        (node: JsonObject)
        =
        let kinds =
            [ "addPrefix"; "basicAuth"; "buffering"; "chain"; "circuitBreaker"; "compress"; "contentType"
              "digestAuth"; "errors"; "forwardAuth"; "grpcWeb"; "headers"; "ipAllowList"; "ipWhiteList"
              "inFlightReq"; "passTLSClientCert"; "rateLimit"; "redirectRegex"; "redirectScheme"; "replacePath"
              "replacePathRegex"; "retry"; "stripPrefix"; "stripPrefixRegex" ]
        objectFields node kinds
        if node.Count <> 1 then reject ()
        let field = node |> Seq.head |> fun pair -> pair.Key
        let validateIpList allowRejectStatus config =
            let fields =
                if allowRejectStatus then [ "sourceRange"; "ipStrategy"; "rejectStatusCode" ]
                else [ "sourceRange"; "ipStrategy" ]
            objectFields config fields
            optionalStringArray config "sourceRange"
            optionalObject config "ipStrategy" validateIpStrategy
            if allowRejectStatus then optional config "rejectStatusCode" nonNegativeInt
        let validateSource config =
            objectFields config [ "ipStrategy"; "requestHeaderName"; "requestHost" ]
            validateSourceCriterion config
        match field with
        | "addPrefix" -> optionalObject node field (fun config -> objectFields config [ "prefix" ]; optionalStringField config "prefix")
        | "basicAuth" -> optionalObject node field (fun config ->
            objectFields config [ "users"; "realm"; "removeHeader"; "headerField" ]
            let users = requiredStrings config "users"
            if List.isEmpty users then reject ()
            optionalStringField config "realm"
            optionalBoolean config "removeHeader"
            optionalStringField config "headerField")
        | "digestAuth" -> optionalObject node field (fun config ->
            objectFields config [ "users"; "removeHeader"; "realm"; "headerField" ]
            let users = requiredStrings config "users"
            if List.isEmpty users then reject ()
            optionalBoolean config "removeHeader"
            optionalStringField config "realm"
            optionalStringField config "headerField")
        | "buffering" -> optionalObject node field (fun config ->
            objectFields config [ "maxRequestBodyBytes"; "memRequestBodyBytes"; "maxResponseBodyBytes"; "memResponseBodyBytes"; "retryExpression" ]
            optional config "maxRequestBodyBytes" nonNegativeInt64
            optional config "memRequestBodyBytes" nonNegativeInt64
            optional config "maxResponseBodyBytes" nonNegativeInt64
            optional config "memResponseBodyBytes" nonNegativeInt64
            optionalStringField config "retryExpression")
        | "chain" -> optionalObject node field (fun config ->
            objectFields config [ "middlewares" ]
            let names = requiredStrings config "middlewares"
            if List.isEmpty names then reject ()
            for name in names do graph[source].Add("middleware:" + localReference name))
        | "circuitBreaker" -> optionalObject node field (fun config ->
            objectFields config [ "expression"; "checkPeriod"; "fallbackDuration"; "recoveryDuration"; "responseCode" ]
            optionalStringField config "expression"
            optionalDuration config "checkPeriod"
            optionalDuration config "fallbackDuration"
            optionalDuration config "recoveryDuration"
            optionalInteger config "responseCode")
        | "compress" -> optionalObject node field (fun config ->
            objectFields config [ "excludedContentTypes"; "includedContentTypes"; "minResponseBodyBytes"; "encodings"; "defaultEncoding" ]
            optionalStringArray config "excludedContentTypes"
            optionalStringArray config "includedContentTypes"
            optional config "minResponseBodyBytes" nonNegativeInt
            optionalStringArray config "encodings"
            optionalStringField config "defaultEncoding")
        | "contentType" -> optionalObject node field (fun config -> objectFields config [ "autoDetect" ]; optionalBoolean config "autoDetect")
        | "errors" -> optionalObject node field (fun config ->
            objectFields config [ "status"; "statusRewrites"; "service"; "query"; "errorRequestHeaders" ]
            optionalStringArray config "status"
            optionalObject config "statusRewrites" validateIntegerMap
            optionalStringField config "query"
            optionalStringArray config "errorRequestHeaders"
            let target = requiredString config "service" |> requireReference services
            graph[source].Add("service:" + target))
        | "forwardAuth" -> optionalObject node field (fun config ->
            objectFields config
                [ "address"; "tls"; "trustForwardHeader"; "authResponseHeaders"; "authResponseHeadersRegex"; "authRequestHeaders"
                  "addAuthCookiesToResponse"; "headerField"; "forwardBody"; "maxBodySize"; "maxResponseBodySize"
                  "preserveLocationHeader"; "preserveRequestMethod" ]
            required config "address" validateHttpUrl |> ignore
            optionalObject config "tls" validateForwardAuthTls
            optionalBoolean config "trustForwardHeader"
            optionalStringArray config "authResponseHeaders"
            optionalStringField config "authResponseHeadersRegex"
            optionalStringArray config "authRequestHeaders"
            optionalStringArray config "addAuthCookiesToResponse"
            optionalStringField config "headerField"
            optionalBoolean config "forwardBody"
            optional config "maxBodySize" integer64
            optional config "maxResponseBodySize" integer64
            optionalBoolean config "preserveLocationHeader"
            optionalBoolean config "preserveRequestMethod")
        | "grpcWeb" -> optionalObject node field (fun config -> objectFields config [ "allowOrigins" ]; optionalStringArray config "allowOrigins")
        | "headers" -> optionalObject node field (fun config ->
            objectFields config
                [ "customRequestHeaders"; "customResponseHeaders"; "accessControlAllowCredentials"; "accessControlAllowHeaders"
                  "accessControlAllowMethods"; "accessControlAllowOriginList"; "accessControlAllowOriginListRegex"
                  "accessControlExposeHeaders"; "accessControlMaxAge"; "addVaryHeader"; "allowedHosts"
                  "hostsProxyHeaders"; "sslProxyHeaders"; "stsSeconds"; "stsIncludeSubdomains"; "stsPreload"
                  "forceSTSHeader"; "frameDeny"; "customFrameOptionsValue"; "contentTypeNosniff"; "browserXssFilter"
                  "customBrowserXSSValue"; "contentSecurityPolicy"; "contentSecurityPolicyReportOnly"; "publicKey"
                  "referrerPolicy"; "permissionsPolicy"; "isDevelopment" ]
            optionalStringMap config "customRequestHeaders"
            optionalStringMap config "customResponseHeaders"
            optionalBoolean config "accessControlAllowCredentials"
            optionalStringArray config "accessControlAllowHeaders"
            optionalStringArray config "accessControlAllowMethods"
            optionalStringArray config "accessControlAllowOriginList"
            optionalStringArray config "accessControlAllowOriginListRegex"
            optionalStringArray config "accessControlExposeHeaders"
            optional config "accessControlMaxAge" nonNegativeInt64
            optionalBoolean config "addVaryHeader"
            optionalStringArray config "allowedHosts"
            optionalStringArray config "hostsProxyHeaders"
            optionalStringMap config "sslProxyHeaders"
            optional config "stsSeconds" nonNegativeInt64
            optionalBoolean config "stsIncludeSubdomains"
            optionalBoolean config "stsPreload"
            optionalBoolean config "forceSTSHeader"
            optionalBoolean config "frameDeny"
            optionalStringField config "customFrameOptionsValue"
            optionalBoolean config "contentTypeNosniff"
            optionalBoolean config "browserXssFilter"
            optionalStringField config "customBrowserXSSValue"
            optionalStringField config "contentSecurityPolicy"
            optionalStringField config "contentSecurityPolicyReportOnly"
            optionalStringField config "publicKey"
            optionalStringField config "referrerPolicy"
            optionalStringField config "permissionsPolicy"
            optionalBoolean config "isDevelopment")
        | "ipAllowList" -> optionalObject node field (validateIpList true)
        | "ipWhiteList" -> optionalObject node field (validateIpList false)
        | "inFlightReq" -> optionalObject node field (fun config ->
            objectFields config [ "amount"; "sourceCriterion" ]
            optional config "amount" nonNegativeInt64
            optionalObject config "sourceCriterion" validateSource)
        | "passTLSClientCert" -> optionalObject node field (fun config ->
            objectFields config [ "pem"; "info" ]
            optionalBoolean config "pem"
            optionalObject config "info" (fun info ->
                objectFields info [ "notAfter"; "notBefore"; "sans"; "serialNumber"; "subject"; "issuer" ]
                optionalBoolean info "notAfter"
                optionalBoolean info "notBefore"
                optionalBoolean info "sans"
                optionalBoolean info "serialNumber"
                let validateDn dn =
                    objectFields dn [ "country"; "province"; "locality"; "organization"; "organizationalUnit"; "commonName"; "serialNumber"; "domainComponent" ]
                    for name in [ "country"; "province"; "locality"; "organization"; "organizationalUnit"; "commonName"; "serialNumber"; "domainComponent" ] do optionalBoolean dn name
                optionalObject info "subject" validateDn
                optionalObject info "issuer" validateDn))
        | "rateLimit" -> optionalObject node field (fun config ->
            objectFields config [ "average"; "period"; "burst"; "sourceCriterion"; "redis" ]
            optional config "average" nonNegativeInt64
            optionalDuration config "period"
            optional config "burst" nonNegativeInt64
            optionalObject config "sourceCriterion" validateSource
            optionalObject config "redis" (fun redis ->
                objectFields redis [ "endpoints"; "username"; "password"; "db"; "poolSize"; "minIdleConns"; "maxActiveConns"; "readTimeout"; "writeTimeout"; "dialTimeout" ]
                optional redis "endpoints" (fun value ->
                    for endpoint in strings value do validateHostPortValue endpoint)
                optionalStringField redis "username"
                optionalStringField redis "password"
                optionalInteger redis "db"
                optionalInteger redis "poolSize"
                optionalInteger redis "minIdleConns"
                optionalInteger redis "maxActiveConns"
                optionalDuration redis "readTimeout"
                optionalDuration redis "writeTimeout"
                optionalDuration redis "dialTimeout"))
        | "redirectRegex" -> optionalObject node field (fun config ->
            objectFields config [ "regex"; "replacement"; "permanent" ]
            optionalStringField config "regex"
            optionalStringField config "replacement"
            optionalBoolean config "permanent")
        | "redirectScheme" -> optionalObject node field (fun config ->
            objectFields config [ "scheme"; "port"; "permanent" ]
            optionalStringField config "scheme"
            optionalStringField config "port"
            optionalBoolean config "permanent")
        | "replacePath" -> optionalObject node field (fun config -> objectFields config [ "path" ]; optionalStringField config "path")
        | "replacePathRegex" -> optionalObject node field (fun config ->
            objectFields config [ "regex"; "replacement" ]
            optionalStringField config "regex"
            optionalStringField config "replacement")
        | "retry" -> optionalObject node field (fun config ->
            objectFields config [ "attempts"; "initialInterval" ]
            optionalInteger config "attempts"
            optionalDuration config "initialInterval")
        | "stripPrefix" -> optionalObject node field (fun config ->
            objectFields config [ "prefixes"; "forceSlash" ]
            optionalStringArray config "prefixes"
            optionalBoolean config "forceSlash")
        | "stripPrefixRegex" -> optionalObject node field (fun config -> objectFields config [ "regex" ]; optionalStringArray config "regex")
        | _ -> reject ()

    let private validateHttpRouter (entryPoints: Map<string, string>) (resolvers: Set<string>) (tlsOptions: Set<string>) (services: Map<string, JsonObject>) (middlewares: Map<string, JsonObject>) (legacyRouters: Set<string>) (name: string) (node: JsonObject) =
        if name = "keroosha-admin" || Set.contains name legacyRouters then reject ()
        objectFields node [ "entryPoints"; "middlewares"; "service"; "rule"; "ruleSyntax"; "priority"; "tls"; "observability" ]
        validateEndpointReferences entryPoints "tcp" node
        requiredString node "service" |> requireReference services |> ignore
        let rule = requiredString node "rule"
        if String.IsNullOrWhiteSpace(rule) then reject ()
        optionalStringField node "ruleSyntax"
        optionalInteger node "priority"
        optional node "middlewares" (fun value ->
            for middleware in strings value do requireReference middlewares middleware |> ignore)
        optionalObject node "tls" (validateHttpRouterTls resolvers tlsOptions)
        optionalObject node "observability" validateRouterObservability

    let private validateAcyclic (graph: Dictionary<string, ResizeArray<string>>) =
        let colors = Dictionary<string, byte>(StringComparer.Ordinal)
        let stack = Stack<string * int>()
        for KeyValue(start, _) in graph do
            if not (colors.ContainsKey start) then
                colors[start] <- 1uy
                stack.Push((start, 0))
                while stack.Count > 0 do
                    let current, nextIndex = stack.Pop()
                    let edges = graph[current]
                    if nextIndex < edges.Count then
                        stack.Push((current, nextIndex + 1))
                        let target = edges[nextIndex]
                        match colors.TryGetValue target with
                        | true, 1uy -> reject ()
                        | true, 2uy -> ()
                        | _ ->
                            colors[target] <- 1uy
                            stack.Push((target, 0))
                    else
                        colors[current] <- 2uy

    let private validateHttp (entryPoints: Map<string, string>) (resolvers: Set<string>) (tlsOptions: Set<string>) (legacyRouters: Set<string>) (node: JsonObject) =
        objectFields node [ "routers"; "services"; "middlewares"; "serversTransports" ]
        let routers = childObjects (Some node) "routers"
        let services = childObjects (Some node) "services"
        let middlewares = childObjects (Some node) "middlewares"
        let transports = childObjects (Some node) "serversTransports"
        rejectGeneratedPrefix "keroosha-backend-" services
        rejectGeneratedPrefix "keroosha-redirect-" middlewares
        let graph = Dictionary<string, ResizeArray<string>>(StringComparer.Ordinal)
        for KeyValue(name, _) in services do graph.Add("service:" + name, ResizeArray())
        for KeyValue(name, _) in middlewares do graph.Add("middleware:" + name, ResizeArray())
        for KeyValue(name, transport) in transports do validateHttpTransport transport
        for KeyValue(name, service) in services do validateHttpService services transports graph name service
        for KeyValue(name, middleware) in middlewares do
            validateHttpMiddlewareConfig services graph ("middleware:" + name) middleware
        for edges in graph.Values do
            for index = 0 to edges.Count - 1 do
                let edge = edges[index]
                if not (graph.ContainsKey edge) then reject ()
        for KeyValue(name, router) in routers do
            validateHttpRouter entryPoints resolvers tlsOptions services middlewares legacyRouters name router
        validateAcyclic graph

    let private validateTcpRouter (entryPoints: Map<string, string>) (resolvers: Set<string>) (tlsOptions: Set<string>) (services: Map<string, JsonObject>) (middlewares: Map<string, JsonObject>) (node: JsonObject) =
        objectFields node [ "entryPoints"; "middlewares"; "service"; "rule"; "ruleSyntax"; "priority"; "tls" ]
        validateEndpointReferences entryPoints "tcp" node
        requiredString node "service" |> requireReference services |> ignore
        if String.IsNullOrWhiteSpace(requiredString node "rule") then reject ()
        optionalStringField node "ruleSyntax"
        optionalInteger node "priority"
        optional node "middlewares" (fun value ->
            for middleware in strings value do requireReference middlewares middleware |> ignore)
        optionalObject node "tls" (validateTcpRouterTls resolvers tlsOptions)

    let private validateTcpWeightedServices (services: Map<string, JsonObject>) (graph: Dictionary<string, ResizeArray<string>>) (source: string) (node: JsonNode) =
        let values = requireArray node
        if values.Count = 0 then reject ()
        for item in values do
            if isNull item then reject ()
            let weighted = requireObject item
            objectFields weighted [ "name"; "weight" ]
            let target = requiredString weighted "name" |> requireReference services
            graph[source].Add("service:" + target)
            optional weighted "weight" nonNegativeInt

    let private validateTcpService (services: Map<string, JsonObject>) (transports: Map<string, JsonObject>) (graph: Dictionary<string, ResizeArray<string>>) (name: string) (node: JsonObject) =
        objectFields node [ "loadBalancer"; "weighted" ]
        let source = "service:" + name
        let strategies = [ "loadBalancer"; "weighted" ] |> List.filter (fun field -> property node field |> Option.isSome)
        if strategies.Length <> 1 then reject ()
        match strategies.Head with
        | "loadBalancer" -> optionalObject node "loadBalancer" (fun loadBalancer ->
            objectFields loadBalancer [ "servers"; "serversTransport"; "proxyProtocol"; "terminationDelay" ]
            let servers = required loadBalancer "servers" requireArray
            if servers.Count = 0 then reject ()
            for server in servers do
                if isNull server then reject ()
                let value = requireObject server
                objectFields value [ "address"; "tls" ]
                required value "address" validateHostPort |> ignore
                optionalBoolean value "tls"
            optional loadBalancer "serversTransport" (fun value -> requireReference transports (stringValue value) |> ignore)
            optionalObject loadBalancer "proxyProtocol" validateProxyProtocol
            optional loadBalancer "terminationDelay" integer)
        | "weighted" -> optionalObject node "weighted" (fun weighted ->
            objectFields weighted [ "services" ]
            let children = required weighted "services" requireArray
            validateTcpWeightedServices services graph source (children :> JsonNode))
        | _ -> reject ()

    let private validateTcpMiddleware (node: JsonObject) =
        objectFields node [ "inFlightConn"; "ipAllowList"; "ipWhiteList" ]
        let fields = [ "inFlightConn"; "ipAllowList"; "ipWhiteList" ] |> List.filter (fun field -> property node field |> Option.isSome)
        if fields.Length <> 1 then reject ()
        match fields.Head with
        | "inFlightConn" -> optionalObject node "inFlightConn" (fun config ->
            objectFields config [ "amount" ]
            optional config "amount" nonNegativeInt64)
        | "ipAllowList"
        | "ipWhiteList" -> optionalObject node fields.Head (fun config ->
            objectFields config [ "sourceRange" ]
            optionalStringArray config "sourceRange")
        | _ -> reject ()

    let private validateTcp (entryPoints: Map<string, string>) (resolvers: Set<string>) (tlsOptions: Set<string>) (node: JsonObject) =
        objectFields node [ "routers"; "services"; "middlewares"; "serversTransports" ]
        let routers = childObjects (Some node) "routers"
        let services = childObjects (Some node) "services"
        let middlewares = childObjects (Some node) "middlewares"
        let transports = childObjects (Some node) "serversTransports"
        let graph = Dictionary<string, ResizeArray<string>>(StringComparer.Ordinal)
        for KeyValue(name, _) in services do graph.Add("service:" + name, ResizeArray())
        for KeyValue(name, transport) in transports do validateTcpTransport transport
        for KeyValue(name, service) in services do validateTcpService services transports graph name service
        for KeyValue(_, middleware) in middlewares do validateTcpMiddleware middleware
        for KeyValue(_, router) in routers do validateTcpRouter entryPoints resolvers tlsOptions services middlewares router
        validateAcyclic graph

    let private validateUdpRouter (entryPoints: Map<string, string>) (services: Map<string, JsonObject>) (node: JsonObject) =
        objectFields node [ "entryPoints"; "service" ]
        validateEndpointReferences entryPoints "udp" node
        requiredString node "service" |> requireReference services |> ignore

    let private validateUdpService (services: Map<string, JsonObject>) (graph: Dictionary<string, ResizeArray<string>>) (name: string) (node: JsonObject) =
        objectFields node [ "loadBalancer"; "weighted" ]
        let source = "service:" + name
        let strategies = [ "loadBalancer"; "weighted" ] |> List.filter (fun field -> property node field |> Option.isSome)
        if strategies.Length <> 1 then reject ()
        match strategies.Head with
        | "loadBalancer" -> optionalObject node "loadBalancer" (fun loadBalancer ->
            objectFields loadBalancer [ "servers" ]
            let servers = required loadBalancer "servers" requireArray
            if servers.Count = 0 then reject ()
            for server in servers do
                if isNull server then reject ()
                let value = requireObject server
                objectFields value [ "address" ]
                required value "address" validateHostPort |> ignore)
        | "weighted" -> optionalObject node "weighted" (fun weighted ->
            objectFields weighted [ "services" ]
            let children = required weighted "services" requireArray
            if children.Count = 0 then reject ()
            for item in children do
                if isNull item then reject ()
                let child = requireObject item
                objectFields child [ "name"; "weight" ]
                let target = requiredString child "name" |> requireReference services
                graph[source].Add("service:" + target)
                optional child "weight" nonNegativeInt)
        | _ -> reject ()

    let private validateUdp (entryPoints: Map<string, string>) (node: JsonObject) =
        objectFields node [ "routers"; "services" ]
        let routers = childObjects (Some node) "routers"
        let services = childObjects (Some node) "services"
        let graph = Dictionary<string, ResizeArray<string>>(StringComparer.Ordinal)
        for KeyValue(name, _) in services do graph.Add("service:" + name, ResizeArray())
        for KeyValue(name, service) in services do validateUdpService services graph name service
        for KeyValue(_, router) in routers do validateUdpRouter entryPoints services router
        validateAcyclic graph

    /// Validates local, typed references and cycles in an optional native dynamic configuration.
    /// Entry-point values are the configured listener protocol (`tcp` or `udp`); HTTP and TCP routers
    /// require TCP listeners and UDP routers require UDP listeners. Router entry points are explicit.
    /// `dynamic.tls` is intentionally left to TraefikTls validation.
    let validate
        (entryPoints: Map<string, string>)
        (resolvers: Set<string>)
        (tlsOptions: Set<string>)
        (legacyRouters: Set<string>)
        (dynamicRoot: JsonObject)
        : unit =
        objectFields dynamicRoot [ "http"; "tcp"; "udp"; "tls" ]
        optionalObject dynamicRoot "http" (validateHttp entryPoints resolvers tlsOptions legacyRouters)
        optionalObject dynamicRoot "tcp" (validateTcp entryPoints resolvers tlsOptions)
        optionalObject dynamicRoot "udp" (validateUdp entryPoints)
