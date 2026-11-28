#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System
open System.Text.Json
open System.Text.Json.Nodes

/// Common offline/host boundary for operator-owned fields. The resulting tree is never logged.
module TraefikSettings =
    type InvalidConfiguration(section: string) =
        inherit Exception("Invalid, unsafe or unsupported Traefik " + section + ".")

    let private checking section validate =
        try validate ()
        with
        | TraefikStatic.ValidationError TraefikStatic.ValidationFailure.SocketBind -> raise (InvalidConfiguration("listener socket conflict"))
        | TraefikStatic.ValidationError TraefikStatic.ValidationFailure.TrustNetwork -> raise (InvalidConfiguration("trusted proxy network"))
        | TraefikDynamic.ValidationError TraefikDynamic.ValidationFailure.UnresolvedReference -> raise (InvalidConfiguration("configuration reference"))
        | TraefikDynamic.ValidationError TraefikDynamic.ValidationFailure.ListenerProtocolMismatch -> raise (InvalidConfiguration("listener protocol"))
        | TraefikDynamic.ValidationError TraefikDynamic.ValidationFailure.UdpListenerOverlap -> raise (InvalidConfiguration("UDP listener ownership"))
        | TraefikDynamic.ValidationError TraefikDynamic.ValidationFailure.ProxyProtocolPlacement -> raise (InvalidConfiguration("TCP load-balancer transport field placement"))
        | TraefikHttpGraphModel.LoweringError TraefikHttpGraphModel.LoweringFailure.RouterNameCollision -> raise (InvalidConfiguration("router name conflict"))
        | TraefikHttpGraphModel.LoweringError TraefikHttpGraphModel.LoweringFailure.ServiceNameCollision -> raise (InvalidConfiguration("service name conflict"))
        | TraefikHttpGraphModel.LoweringError TraefikHttpGraphModel.LoweringFailure.MiddlewareNameCollision -> raise (InvalidConfiguration("middleware name conflict"))
        | TraefikHttpGraphModel.LoweringError TraefikHttpGraphModel.LoweringFailure.HttpSectionTypeMismatch -> raise (InvalidConfiguration("HTTP section type conflict"))
        | TraefikHttpGraphModel.LoweringError TraefikHttpGraphModel.LoweringFailure.ObjectMapTypeMismatch -> raise (InvalidConfiguration("HTTP object map type conflict"))
        | _ -> raise (InvalidConfiguration(section))

    let private lookup (root: JsonObject) (key: string) =
        let mutable value: JsonNode = null
        let found = root.TryGetPropertyValue(key, &value)
        struct (found, value)

    let section (root: JsonObject) (name: string) =
        match lookup root name with
        | struct (false, _) -> JsonObject()
        | struct (true, (:? JsonObject as value)) -> value
        | _ -> invalidOp "Expected a Traefik configuration object."

    let private keys (root: JsonObject) = root |> Seq.map (fun field -> field.Key) |> Set.ofSeq

    let parse (text: string) =
        if isNull text || text.Length > 4 * 1024 * 1024 then invalidOp "Traefik configuration exceeds its size limit."
        try
            let options = JsonDocumentOptions(MaxDepth = 40, AllowDuplicateProperties = false)
            match JsonNode.Parse(text, documentOptions = options) with
            | :? JsonObject as root -> root
            | _ -> invalidOp "Expected a Traefik configuration object."
        with :? JsonException -> invalidOp "Invalid or duplicate property in structured Traefik configuration."

    let private adminDestinationFailure () =
        invalidOp "A proxy destination must not reach the private Traefik administration port."

    let private guardAdminHostPort adminPort (host: string) port =
        if port = adminPort then
            let host = host.Trim([| '['; ']' |])
            let mutable address = Unchecked.defaultof<System.Net.IPAddress>
            if not (System.Net.IPAddress.TryParse(host, &address)) then
                adminDestinationFailure ()
            let address =
                if address.IsIPv4MappedToIPv6 then address.MapToIPv4()
                else address
            if System.Net.IPAddress.IsLoopback(address)
               || address.Equals(System.Net.IPAddress.Any)
               || address.Equals(System.Net.IPAddress.IPv6Any) then
                adminDestinationFailure ()

    let private guardAdminDestinationAtPort adminPort (destination: string) portOverride =
        let text = if destination.Contains("://", StringComparison.Ordinal) then destination else "tcp://" + destination
        let mutable uri = Unchecked.defaultof<Uri>
        if not (Uri.TryCreate(text, UriKind.Absolute, &uri)) then adminDestinationFailure ()
        let port =
            match portOverride with
            | Some value -> value
            | None when uri.Port < 0 && uri.Scheme = "h2c" -> 80
            | None -> uri.Port
        if port >= 1 && port <= 65535 then guardAdminHostPort adminPort uri.Host port

    /// Numeric non-loopback destinations are unambiguously remote; DNS names fail closed at the private port.
    let guardAdminDestination adminPort (destination: string) =
        guardAdminDestinationAtPort adminPort destination None

    let private rejectTemplate (value: string) =
        if value.Contains("{{", StringComparison.Ordinal) then invalidOp "File-provider template expressions are not supported."

    let private destinationText (value: JsonNode) =
        if isNull value then None else Some(value.GetValue<string>())

    let private healthCheckPort (loadBalancer: JsonObject) =
        match loadBalancer["healthCheck"] with
        | :? JsonObject as healthCheck ->
            match healthCheck["port"] with
            | :? JsonValue as port -> Some(port.GetValue<int>())
            | _ -> None
        | _ -> None

    let private guardProxyTargets adminPort (settings: JsonObject) (dynamic: JsonObject) =
        let check (value: JsonNode) =
            destinationText value |> Option.iter (guardAdminDestination adminPort)
        for resolver in section settings "certificatesResolvers" do
            match resolver.Value with
            | :? JsonObject as value ->
                match value["acme"] with
                | :? JsonObject as acme -> check acme["caServer"]
                | _ -> ()
            | _ -> ()
        for protocol in [ "http"; "tcp"; "udp" ] do
            let family = section dynamic protocol
            let endpoint = if protocol = "http" then "url" else "address"
            for service in section family "services" do
                match service.Value["loadBalancer"] with
                | :? JsonObject as balancer ->
                    let healthPort = if protocol = "http" then healthCheckPort balancer else None
                    match balancer["servers"] with
                    | :? JsonArray as servers ->
                        for server in servers do
                            let destination =
                                match server with
                                | :? JsonObject as value -> value[endpoint]
                                | _ -> null
                            check destination
                            match healthPort, destinationText destination with
                            | Some port, Some target -> guardAdminDestinationAtPort adminPort target (Some port)
                            | _ -> ()
                    | _ -> ()
                | _ -> ()
            if protocol = "http" then
                for middleware in section family "middlewares" do
                    match middleware.Value["forwardAuth"] with
                    | :? JsonObject as auth -> check auth["address"]
                    | _ -> ()

    let private validateCore
        forRead
        (loweredGraph: TraefikHttpGraphModel.LoweredGraph option)
        (loweredDynamic: JsonObject option)
        entryPoints
        adminPort
        legacyResolvers
        serverCertificates
        clientCertificates
        legacyRouters
        (root: JsonObject)
        =
        if not (Set.isSubset (keys root) (set [ "static"; "dynamic"; "dnsCredentials" ])) then
            invalidOp "Unexpected Traefik configuration section."
        let settings = section root "static"
        let userDynamic = section root "dynamic"
        if not (Set.isSubset (keys userDynamic) (set [ "http"; "tcp"; "udp"; "tls" ])) then
            invalidOp "Unexpected Traefik file-provider section."
        let dynamic = defaultArg loweredDynamic userDynamic
        // The file provider evaluates Go templates *before* YAML decoding, including in keys.
        let rec guard (node: JsonNode) =
            match node with
            | :? JsonObject as fields ->
                for field in fields do
                    rejectTemplate field.Key
                    guard field.Value
            | :? JsonArray as items -> for item in items do guard item
            | :? JsonValue as value when value.GetValueKind() = JsonValueKind.String -> rejectTemplate (value.GetValue<string>())
            | _ -> ()
        let validateConfiguration () =
            guard userDynamic
            let listeners =
                checking "static settings or listener socket" (fun () ->
                    if forRead then TraefikStatic.validateForRead entryPoints adminPort settings
                    else TraefikStatic.validate entryPoints adminPort settings)
            checking "TLS resolver, credentials or certificate settings" (fun () ->
                TraefikTlsSettings.validateWithCertificateUsage listeners legacyResolvers serverCertificates clientCertificates root)
            let resolvers = Set.union legacyResolvers (keys (section settings "certificatesResolvers"))
            let tlsOptions = section (section userDynamic "tls") "options" |> keys
            checking "file-provider object or reference" (fun () ->
                match loweredGraph with
                | Some trust -> TraefikDynamic.validateWithLegacy listeners resolvers tlsOptions trust dynamic
                | None -> TraefikDynamic.validate listeners resolvers tlsOptions legacyRouters dynamic)
            checking "static reference to a file-provider object" (fun () -> TraefikStatic.validateReferences settings dynamic resolvers)
        if forRead then
            let configurationSafe =
                try
                    validateConfiguration ()
                    true
                with _ -> false
            let destinationSafe =
                try
                    guardProxyTargets adminPort settings dynamic
                    true
                with _ -> false
            configurationSafe && destinationSafe
        else
            validateConfiguration ()
            checking "proxy destination" (fun () -> guardProxyTargets adminPort settings dynamic)
            true

    let validateWithCertificateUsage entryPoints adminPort legacyResolvers serverCertificates clientCertificates legacyRouters (root: JsonObject) =
        validateCore false None None entryPoints adminPort legacyResolvers serverCertificates clientCertificates legacyRouters root
        |> ignore

    let validateForReadWithCertificateUsage entryPoints adminPort legacyResolvers serverCertificates clientCertificates legacyRouters (root: JsonObject) =
        validateCore true None None entryPoints adminPort legacyResolvers serverCertificates clientCertificates legacyRouters root

    let private lowerLegacyRoutes (routes: seq<TraefikHttpGraphModel.LegacyRouter>) (root: JsonObject) =
        let mergedDynamic = (section root "dynamic").DeepClone() :?> JsonObject
        let loweredGraph =
            checking "legacy HTTP graph" (fun () -> TraefikHttpGraphModel.lowerLegacyGraph routes mergedDynamic)
        loweredGraph, mergedDynamic

    let validateWithLegacyRoutes entryPoints adminPort legacyResolvers serverCertificates clientCertificates (routes: seq<TraefikHttpGraphModel.LegacyRouter>) (root: JsonObject) =
        let loweredGraph, mergedDynamic = lowerLegacyRoutes routes root
        validateCore false (Some loweredGraph) (Some mergedDynamic) entryPoints adminPort legacyResolvers serverCertificates clientCertificates Set.empty root |> ignore
        loweredGraph, mergedDynamic

    let validateForReadWithLegacyRoutes entryPoints adminPort legacyResolvers serverCertificates clientCertificates (routes: seq<TraefikHttpGraphModel.LegacyRouter>) (root: JsonObject) =
        let loweredGraph, mergedDynamic = lowerLegacyRoutes routes root
        let probeSafe = validateCore true (Some loweredGraph) (Some mergedDynamic) entryPoints adminPort legacyResolvers serverCertificates clientCertificates Set.empty root
        loweredGraph, mergedDynamic, probeSafe

    let validate entryPoints adminPort legacyResolvers legacyCertificates legacyRouters (root: JsonObject) =
        validateWithCertificateUsage entryPoints adminPort legacyResolvers legacyCertificates Set.empty legacyRouters root

    /// Consume the transformed tree, moving rather than copying potentially large certificate values.
    /// Merge namespace maps only; a named object belongs to a single declaration.
    let merge (namespaceDepth: int) (generated: JsonObject) (declared: JsonObject) =
        let rec add depth (target: JsonObject) (source: JsonObject) =
            while source.Count > 0 do
                let index = source.Count - 1
                let field = source.GetAt(index)
                source.RemoveAt(index)
                match lookup target field.Key with
                | struct (false, _) -> target.Add(field.Key, field.Value)
                | struct (true, (:? JsonObject as existing)) when depth > 0 ->
                    match field.Value with
                    | :? JsonObject as incoming -> add (depth - 1) existing incoming
                    | _ -> invalidOp "Traefik configuration collides with a managed object."
                | _ -> invalidOp "Traefik configuration collides with a managed object."
        add namespaceDepth generated declared
