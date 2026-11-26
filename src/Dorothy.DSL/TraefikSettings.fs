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
        with _ -> raise (InvalidConfiguration(section))

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

    /// Compare the effective port, not the hostname: a DNS name can resolve to loopback.
    let guardAdminDestination adminPort (destination: string) =
        let mutable uri = Unchecked.defaultof<Uri>
        let text = if destination.Contains("://", StringComparison.Ordinal) then destination else "tcp://" + destination
        if Uri.TryCreate(text, UriKind.Absolute, &uri) then
            let port = if uri.Port < 0 && uri.Scheme = "h2c" then 80 else uri.Port
            if port = adminPort then invalidOp "A proxy destination must not use the private Traefik administration port."

    let private rejectTemplate (value: string) =
        if value.Contains("{{", StringComparison.Ordinal) then invalidOp "File-provider template expressions are not supported."

    let private guardProxyTargets adminPort (dynamic: JsonObject) =
        let check (value: JsonNode) =
            if not (isNull value) then guardAdminDestination adminPort (value.GetValue<string>())
        for protocol in [ "http"; "tcp"; "udp" ] do
            let family = section dynamic protocol
            let endpoint = if protocol = "http" then "url" else "address"
            for service in section family "services" do
                match service.Value["loadBalancer"] with
                | :? JsonObject as balancer ->
                    match balancer["servers"] with
                    | :? JsonArray as servers -> for server in servers do check server[endpoint]
                    | _ -> ()
                | _ -> ()
            if protocol = "http" then
                for middleware in section family "middlewares" do
                    match middleware.Value["forwardAuth"] with
                    | :? JsonObject as auth -> check auth["address"]
                    | _ -> ()

    let validate entryPoints adminPort legacyResolvers legacyCertificates legacyRouters (root: JsonObject) =
        if not (Set.isSubset (keys root) (set [ "static"; "dynamic"; "dnsCredentials" ])) then
            invalidOp "Unexpected Traefik configuration section."
        let settings = section root "static"
        let dynamic = section root "dynamic"
        if not (Set.isSubset (keys dynamic) (set [ "http"; "tcp"; "udp"; "tls" ])) then
            invalidOp "Unexpected Traefik file-provider section."
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
        guard dynamic
        let listeners = checking "static settings or listener socket" (fun () -> TraefikStatic.validate entryPoints adminPort settings)
        checking "TLS resolver, credentials or certificate settings" (fun () -> TraefikTlsSettings.validate listeners legacyResolvers legacyCertificates root)
        let resolvers = Set.union legacyResolvers (keys (section settings "certificatesResolvers"))
        let tlsOptions = section (section dynamic "tls") "options" |> keys
        checking "file-provider object or reference" (fun () -> TraefikDynamic.validate listeners resolvers tlsOptions legacyRouters dynamic)
        guardProxyTargets adminPort dynamic
        checking "static reference to a file-provider object" (fun () -> TraefikStatic.validateReferences settings dynamic resolvers)

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
