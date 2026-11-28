#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System
open System.Buffers
open System.Collections.Generic
open System.Globalization
open System.Net
open System.Net.Sockets
open System.Security.Cryptography
open System.Text
open System.Text.Json.Nodes

/// Shared pure HTTP rule and generated-graph lowering for the typed DSL and host helper.
[<RequireQualifiedAccess>]
module TraefikHttpGraphModel =
    /// Checks a Traefik identifier using the shared ASCII grammar and caller-specific maximum length.
    let internal isValidName (maximumLength: int) (value: string) =
        if isNull value || maximumLength < 1 || value.Length = 0 || value.Length > maximumLength then
            false
        elif not (Char.IsAsciiLetterOrDigit value[0]) then
            false
        else
            let mutable index = 1
            let mutable valid = true
            while index < value.Length && valid do
                let character = value[index]
                valid <-
                    Char.IsAsciiLetterOrDigit character
                    || character = '_'
                    || character = '-'
                    || character = '.'
                index <- index + 1
            valid

    [<RequireQualifiedAccess>]
    type internal Rule =
        | Host of string list
        | HostRegexp of string list
        | Path of string
        | PathPrefix of string
        | PathRegexp of string
        | Method of string
        | Header of string * string
        | HeaderRegexp of string * string
        | Query of string * string
        | QueryRegexp of string * string
        | ClientIp of string
        | And of Rule * Rule
        | Or of Rule * Rule
        | Not of Rule

    /// A normal legacy backend or permanent redirect target.
    [<RequireQualifiedAccess>]
    type LegacyTarget =
        | Backend of string
        | Redirect of origin: string

    /// Legacy router TLS selection; provided certificates are registered separately.
    [<RequireQualifiedAccess>]
    type LegacyTls =
        | None
        | Acme of resolver: string
        | Provided

    /// Validated legacy HTTP route input. It cannot express internal-service exemptions.
    type LegacyRouter =
        { Name: string
          Host: string
          EntryPoint: string
          ExcludedPathSubtree: string option
          Target: LegacyTarget
          Tls: LegacyTls }

    [<RequireQualifiedAccess>]
    type internal GeneratedInternalTarget =
        | AdminApi
        | RedirectNoop

    /// Opaque provenance for a legacy graph lowered by this module.
    [<Sealed>]
    type LoweredGraph internal (
        http: JsonObject,
        routerNames: Set<string>,
        backendServiceNames: Set<string>,
        redirectMiddlewareNames: Set<string>,
        internalTargets: Map<string, GeneratedInternalTarget>
    ) =
        member internal _.Http = http
        member internal _.RouterNames = routerNames
        member internal _.BackendServiceNames = backendServiceNames
        member internal _.RedirectMiddlewareNames = redirectMiddlewareNames
        member internal _.InternalTargets = internalTargets

    [<RequireQualifiedAccess>]
    type internal LoweringFailure =
        | RouterNameCollision
        | ServiceNameCollision
        | MiddlewareNameCollision
        | HttpSectionTypeMismatch
        | ObjectMapTypeMismatch

    exception internal LoweringError of LoweringFailure

    let private appendHexEscape (builder: StringBuilder) (marker: char) (format: string) (value: int) =
        builder.Append('\\').Append(marker) |> ignore
        builder.Append(value.ToString(format, CultureInfo.InvariantCulture)) |> ignore

    let internal quoteGoString (value: string) =
        if isNull value then invalidArg "rule" "A Traefik rule value cannot be null."
        let builder = StringBuilder(value.Length + 2)
        builder.Append('"') |> ignore
        let mutable offset = 0

        while offset < value.Length do
            let mutable rune = Unchecked.defaultof<Rune>
            let mutable consumed = 0
            if Rune.DecodeFromUtf16(value.AsSpan(offset), &rune, &consumed) <> OperationStatus.Done then
                invalidArg "rule" "A Traefik rule value must contain valid Unicode scalar values."
            offset <- offset + consumed

            match rune.Value with
            | 0x22 -> builder.Append("\\\"") |> ignore
            | 0x5C -> builder.Append("\\\\") |> ignore
            | 0x07 -> builder.Append("\\a") |> ignore
            | 0x08 -> builder.Append("\\b") |> ignore
            | 0x0C -> builder.Append("\\f") |> ignore
            | 0x0A -> builder.Append("\\n") |> ignore
            | 0x0D -> builder.Append("\\r") |> ignore
            | 0x09 -> builder.Append("\\t") |> ignore
            | 0x0B -> builder.Append("\\v") |> ignore
            | value when value < 0x20 || value = 0x7F -> appendHexEscape builder 'x' "X2" value
            | value when value <= 0x7E -> builder.Append(char value) |> ignore
            | value when value <= 0xFFFF -> appendHexEscape builder 'u' "X4" value
            | value -> appendHexEscape builder 'U' "X8" value

        builder.Append('"') |> ignore
        builder.ToString()

    let private requireRuleValues (items: seq<string>) =
        let values = Seq.toList items
        if values.IsEmpty || values |> List.exists String.IsNullOrWhiteSpace then
            invalidArg "rule" "A Traefik rule matcher requires one or more non-empty values."
        values

    let internal host values = Rule.Host(requireRuleValues values)
    let internal hostRegexp values = Rule.HostRegexp(requireRuleValues values)

    let private requireRuleValue (value: string) =
        if String.IsNullOrWhiteSpace(value) then
            invalidArg "rule" "A Traefik rule matcher requires one or more non-empty values."
        value

    let internal path value = Rule.Path(requireRuleValue value)
    let internal pathPrefix value = Rule.PathPrefix(requireRuleValue value)
    let internal pathRegexp value = Rule.PathRegexp(requireRuleValue value)
    let internal method' value = Rule.Method(requireRuleValue value)
    let internal header name value = Rule.Header(requireRuleValue name, requireRuleValue value)
    let internal headerRegexp name value = Rule.HeaderRegexp(requireRuleValue name, requireRuleValue value)
    let internal query name value = Rule.Query(requireRuleValue name, requireRuleValue value)
    let internal queryRegexp name value = Rule.QueryRegexp(requireRuleValue name, requireRuleValue value)
    let internal clientIp value = Rule.ClientIp(requireRuleValue value)
    let internal andAlso left right = Rule.And(left, right)
    let internal orElse left right = Rule.Or(left, right)
    let internal not rule = Rule.Not rule

    let private goMatcher name values =
        name + "(" + (values |> List.map quoteGoString |> String.concat ",") + ")"

    let rec internal renderGoRule rule =
        match rule with
        | Rule.Host values ->
            match values with
            | [ value ] -> goMatcher "Host" [ value ]
            | _ -> values |> List.map (fun value -> goMatcher "Host" [ value ]) |> String.concat " || " |> fun expression -> "(" + expression + ")"
        | Rule.HostRegexp values ->
            match values with
            | [ value ] -> goMatcher "HostRegexp" [ value ]
            | _ -> values |> List.map (fun value -> goMatcher "HostRegexp" [ value ]) |> String.concat " || " |> fun expression -> "(" + expression + ")"
        | Rule.Path value -> goMatcher "Path" [ value ]
        | Rule.PathPrefix value -> goMatcher "PathPrefix" [ value ]
        | Rule.PathRegexp value -> goMatcher "PathRegexp" [ value ]
        | Rule.Method value -> goMatcher "Method" [ value ]
        | Rule.Header(name, value) -> goMatcher "Header" [ name; value ]
        | Rule.HeaderRegexp(name, value) -> goMatcher "HeaderRegexp" [ name; value ]
        | Rule.Query(name, value) -> goMatcher "Query" [ name; value ]
        | Rule.QueryRegexp(name, value) -> goMatcher "QueryRegexp" [ name; value ]
        | Rule.ClientIp value -> goMatcher "ClientIP" [ value ]
        | Rule.And(left, right) -> "(" + renderGoRule left + ") && (" + renderGoRule right + ")"
        | Rule.Or(left, right) -> "(" + renderGoRule left + ") || (" + renderGoRule right + ")"
        | Rule.Not nested -> "!(" + renderGoRule nested + ")"

    let private quoteLegacyRuleValue (value: string) =
        if isNull value || value.Contains('`') || value.Contains("{{", StringComparison.Ordinal) then
            invalidArg "rule" "A legacy Traefik rule value is not safe for backtick quoting."
        "`" + value + "`"

    let private legacyMatcher name values =
        name + "(" + (values |> List.map quoteLegacyRuleValue |> String.concat ",") + ")"

    let private parenthesizeIfComposite rule expression =
        match rule with
        | Rule.Host _
        | Rule.HostRegexp _
        | Rule.Path _
        | Rule.PathPrefix _
        | Rule.PathRegexp _
        | Rule.Method _
        | Rule.Header _
        | Rule.HeaderRegexp _
        | Rule.Query _
        | Rule.QueryRegexp _
        | Rule.ClientIp _
        | Rule.Not _ -> expression
        | _ -> "(" + expression + ")"

    let rec internal renderLegacyRule rule =
        match rule with
        | Rule.Host values ->
            match values with
            | [ value ] -> legacyMatcher "Host" [ value ]
            | _ -> values |> List.map (fun value -> legacyMatcher "Host" [ value ]) |> String.concat " || " |> fun expression -> "(" + expression + ")"
        | Rule.HostRegexp values ->
            match values with
            | [ value ] -> legacyMatcher "HostRegexp" [ value ]
            | _ -> values |> List.map (fun value -> legacyMatcher "HostRegexp" [ value ]) |> String.concat " || " |> fun expression -> "(" + expression + ")"
        | Rule.Path value -> legacyMatcher "Path" [ value ]
        | Rule.PathPrefix value -> legacyMatcher "PathPrefix" [ value ]
        | Rule.PathRegexp value -> legacyMatcher "PathRegexp" [ value ]
        | Rule.Method value -> legacyMatcher "Method" [ value ]
        | Rule.Header(name, value) -> legacyMatcher "Header" [ name; value ]
        | Rule.HeaderRegexp(name, value) -> legacyMatcher "HeaderRegexp" [ name; value ]
        | Rule.Query(name, value) -> legacyMatcher "Query" [ name; value ]
        | Rule.QueryRegexp(name, value) -> legacyMatcher "QueryRegexp" [ name; value ]
        | Rule.ClientIp value -> legacyMatcher "ClientIP" [ value ]
        | Rule.And(left, right) ->
            parenthesizeIfComposite left (renderLegacyRule left)
            + " && "
            + parenthesizeIfComposite right (renderLegacyRule right)
        | Rule.Or(left, right) ->
            parenthesizeIfComposite left (renderLegacyRule left)
            + " || "
            + parenthesizeIfComposite right (renderLegacyRule right)
        | Rule.Not nested -> "!" + parenthesizeIfComposite nested (renderLegacyRule nested)

    let private sha256Text (value: string) =
        SHA256.HashData(Encoding.UTF8.GetBytes(value)) |> Convert.ToHexStringLower

    let private serviceNameForBackend backend = "keroosha-backend-" + sha256Text backend
    let private redirectMiddlewareName routerName origin = "keroosha-redirect-" + sha256Text (routerName + "\n" + origin)
    let private redirectRegex = "^https?://[^/?#]+(.*)$"

    let private redirectReplacement (origin: string) = origin.Replace("$", "$$") + "${1}"

    let private hostRuleValue (host: string) =
        let mutable address = Unchecked.defaultof<IPAddress>
        if IPAddress.TryParse(host, &address) && address.AddressFamily = AddressFamily.InterNetworkV6 then
            "[" + address.ToString().ToLowerInvariant() + "]"
        else
            host

    let private ensureObject (parent: JsonObject) (name: string) (failure: LoweringFailure) =
        if isNull parent then raise (LoweringError failure)
        let mutable value = Unchecked.defaultof<JsonNode>
        if parent.TryGetPropertyValue(name, &value) then
            match value with
            | :? JsonObject as fields -> fields
            | _ -> raise (LoweringError failure)
        else
            let fields = JsonObject()
            parent.Add(name, fields)
            fields

    let private addGeneratedObject (objects: JsonObject) (name: string) (value: JsonObject) (failure: LoweringFailure) =
        if objects.ContainsKey(name) then
            raise (LoweringError failure)
        objects.Add(name, value)

    let private stringNode (value: string) = JsonValue.Create(value)

    let private stringArray values =
        let result = JsonArray()
        for value in values do result.Add(stringNode value)
        result

    let internal adminRuleBase =
        renderLegacyRule (Rule.Or(pathPrefix "/api", pathPrefix "/dashboard"))

    let private generationPrefix = "(" + adminRuleBase + ") && !Path(`/.dorothy-generation/"
    let private generationSuffix = "`)"

    let internal generatedAdminRuleWithGeneration (generation: string) =
        let isLowerHex character =
            (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f')
        if isNull generation || (generation.Length <> 64 && generation.Length <> 128) || (generation |> Seq.exists (fun character -> Microsoft.FSharp.Core.Operators.not (isLowerHex character))) then
            invalidArg "generation" "A generated Traefik configuration digest must be lowercase SHA-256 hex."
        generationPrefix + generation + generationSuffix

    let internal isGeneratedAdminRule (rule: string) =
        if isNull rule then
            false
        elif String.Equals(rule, adminRuleBase, StringComparison.Ordinal) then
            true
        else
            let prefix = generationPrefix
            let suffix = generationSuffix
            let prefixLength = prefix.Length
            let generationLength = rule.Length - prefixLength - suffix.Length
            if (generationLength = 64 || generationLength = 128)
               && rule.StartsWith(prefix, StringComparison.Ordinal)
               && rule.EndsWith(suffix, StringComparison.Ordinal) then
                let mutable index = 0
                let mutable valid = true
                while index < generationLength && valid do
                    let character = rule[prefixLength + index]
                    valid <-
                        (character >= '0' && character <= '9')
                        || (character >= 'a' && character <= 'f')
                    index <- index + 1
                valid
            else
                false

    let private generatedAdminRouter () =
        let router = JsonObject()
        router["rule"] <- stringNode adminRuleBase
        router["entryPoints"] <- stringArray [ "keroosha-admin" ]
        router["service"] <- stringNode "api@internal"
        router["priority"] <- JsonValue.Create(1000000)
        router


    let private backendService backend =
        let server = JsonObject()
        server["url"] <- stringNode backend
        let servers = JsonArray()
        servers.Add(server)
        let loadBalancer = JsonObject()
        loadBalancer["servers"] <- servers
        let service = JsonObject()
        service["loadBalancer"] <- loadBalancer
        service

    let private redirectMiddleware origin =
        let redirectRegexConfig = JsonObject()
        redirectRegexConfig["regex"] <- stringNode redirectRegex
        redirectRegexConfig["replacement"] <- stringNode (redirectReplacement origin)
        redirectRegexConfig["permanent"] <- JsonValue.Create(true)
        let middleware = JsonObject()
        middleware["redirectRegex"] <- redirectRegexConfig
        middleware

    let private routeRule (router: LegacyRouter) =
        let host = host [ hostRuleValue router.Host ]
        match router.ExcludedPathSubtree with
        | None -> renderLegacyRule host
        | Some subtree when TraefikPathModel.isCanonicalSubtree subtree ->
            // Traefik preserves reserved escapes, including encoded slashes, in its routing path.
            let pathPattern = subtree.Replace("/", "(/|%2[fF])+", StringComparison.Ordinal)
            andAlso host (not (pathRegexp ("^" + pathPattern + "($|/|%2[fF])")))
            |> renderLegacyRule
        | Some _ -> invalidOp "Traefik HTTP graph configuration is invalid."

    /// Adds generated legacy objects directly into the named JSON maps and returns unforgeable provenance.
    let internal lowerLegacyGraph (routers: seq<LegacyRouter>) (dynamicRoot: JsonObject) =
        if isNull dynamicRoot then raise (LoweringError LoweringFailure.HttpSectionTypeMismatch)
        let http = ensureObject dynamicRoot "http" LoweringFailure.HttpSectionTypeMismatch
        let routerObjects = ensureObject http "routers" LoweringFailure.ObjectMapTypeMismatch
        let routerNames = HashSet<string>(StringComparer.Ordinal)
        let backendServiceNames = HashSet<string>(StringComparer.Ordinal)
        let redirectMiddlewareNames = HashSet<string>(StringComparer.Ordinal)
        let generatedBackends = Dictionary<string, string>(StringComparer.Ordinal)
        let internalTargets = Dictionary<string, GeneratedInternalTarget>(StringComparer.Ordinal)

        addGeneratedObject routerObjects "keroosha-admin" (generatedAdminRouter ()) LoweringFailure.RouterNameCollision
        routerNames.Add("keroosha-admin") |> ignore
        internalTargets.Add("keroosha-admin", GeneratedInternalTarget.AdminApi)

        for router in routers do
            if Microsoft.FSharp.Core.Operators.not (isValidName 63 router.Name)
               || Microsoft.FSharp.Core.Operators.not (isValidName 63 router.EntryPoint)
               || String.IsNullOrWhiteSpace(router.Host) then
                invalidOp "Traefik HTTP graph configuration is invalid."

            let dynamicRouter = JsonObject()
            dynamicRouter["rule"] <- stringNode (routeRule router)
            dynamicRouter["entryPoints"] <- stringArray [ router.EntryPoint ]

            match router.Target with
            | LegacyTarget.Backend backend ->
                if String.IsNullOrWhiteSpace(backend) then
                    invalidOp "Traefik HTTP graph configuration is invalid."
                let serviceName = serviceNameForBackend backend
                dynamicRouter["service"] <- stringNode serviceName
                match generatedBackends.TryGetValue(serviceName) with
                | true, existing when String.Equals(existing, backend, StringComparison.Ordinal) -> ()
                | true, _ -> raise (LoweringError LoweringFailure.ServiceNameCollision)
                | false, _ ->
                    let services = ensureObject http "services" LoweringFailure.ObjectMapTypeMismatch
                    addGeneratedObject services serviceName (backendService backend) LoweringFailure.ServiceNameCollision
                    generatedBackends.Add(serviceName, backend)
                    backendServiceNames.Add(serviceName) |> ignore
            | LegacyTarget.Redirect origin ->
                if String.IsNullOrWhiteSpace(origin) then
                    invalidOp "Traefik HTTP graph configuration is invalid."
                let middlewareName = redirectMiddlewareName router.Name origin
                let middlewares = ensureObject http "middlewares" LoweringFailure.ObjectMapTypeMismatch
                addGeneratedObject middlewares middlewareName (redirectMiddleware origin) LoweringFailure.MiddlewareNameCollision
                redirectMiddlewareNames.Add(middlewareName) |> ignore
                dynamicRouter["middlewares"] <- stringArray [ middlewareName ]
                dynamicRouter["service"] <- stringNode "noop@internal"
                internalTargets.Add(router.Name, GeneratedInternalTarget.RedirectNoop)

            match router.Tls with
            | LegacyTls.None -> ()
            | LegacyTls.Acme resolver ->
                let tls = JsonObject()
                tls["certResolver"] <- stringNode resolver
                dynamicRouter["tls"] <- tls
            | LegacyTls.Provided -> dynamicRouter["tls"] <- JsonObject()

            addGeneratedObject routerObjects router.Name dynamicRouter LoweringFailure.RouterNameCollision
            routerNames.Add(router.Name) |> ignore

        LoweredGraph(
            http,
            Set.ofSeq routerNames,
            Set.ofSeq backendServiceNames,
            Set.ofSeq redirectMiddlewareNames,
            internalTargets |> Seq.map (fun pair -> pair.Key, pair.Value) |> Map.ofSeq
        )
