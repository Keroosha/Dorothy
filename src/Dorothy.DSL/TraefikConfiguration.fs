namespace Dorothy.DSL

open System
open System.Net
open System.Globalization
open System.Buffers
open System.Collections.Generic
open System.Collections.Immutable
open System.Text
open System.Text.Json
open Pulumi

/// A native JSON value. Output-backed leaves retain their Pulumi dependency and secrecy metadata.
[<RequireQualifiedAccess>]
type TraefikNativeValue =
    internal
    | NullValue
    | Boolean of bool
    | BooleanOutput of Output<bool>
    | Integer of int64
    | IntegerOutput of Output<int64>
    | Integer32Output of Output<int>
    | Number of decimal
    | NumberOutput of Output<decimal>
    | String of TraefikStringInput
    | Array of TraefikNativeValue list
    | Object of ImmutableSortedDictionary<string, TraefikNativeValue>

/// One structured native field; its constructor is exposed through `nativeField`.
[<Sealed>]
type TraefikNativeField internal (name: string, value: TraefikNativeValue) =
    member internal _.Name = name
    member internal _.Value = value

/// One named object in a Traefik protocol's native map.
[<Sealed>]
type TraefikNamedNativeObject internal (name: string, value: TraefikNativeValue) =
    member _.Name = name
    member _.Value = value

/// Structured static, dynamic, or DNS-credential configuration for one Traefik resource.
/// Named references are local by default; external references are limited to the File provider (`name@file`).
[<Sealed>]
type TraefikConfigurationSpec internal (root: TraefikNativeValue) =
    member internal _.Root = root
    member internal _.HasStaticEntryPoints =
        match root with
        | TraefikNativeValue.Object sections ->
            match sections.TryGetValue("static") with
            | true, TraefikNativeValue.Object values -> values.ContainsKey("entryPoints")
            | _ -> false
        | _ -> false

[<RequireQualifiedAccess>]
type TraefikConfigurationPart =
    | Static of TraefikNativeValue
    | Dynamic of TraefikNativeValue
    | DnsCredentials of TraefikNativeValue

/// A named HTTP entry point reference. HTTP router builders accept only HTTP references.
[<Sealed>]
type TraefikHttpEntryPointRef internal (name: string) =
    member internal _.Name = name

/// A named TCP entry point reference. TCP router builders accept only TCP references.
[<Sealed>]
type TraefikTcpEntryPointRef internal (name: string) =
    member internal _.Name = name

/// A named UDP entry point reference. UDP router builders accept only UDP references.
[<Sealed>]
type TraefikUdpEntryPointRef internal (name: string) =
    member internal _.Name = name

/// A named HTTP service reference.
[<Sealed>]
type TraefikHttpServiceRef internal (name: string) =
    member internal _.Name = name
/// A named HTTP parent-router reference.
[<Sealed>]
type TraefikHttpRouterRef internal (name: string) =
    member internal _.Name = name

/// A named HTTP middleware reference.
[<Sealed>]
type TraefikHttpMiddlewareRef internal (name: string) =
    member internal _.Name = name

/// A named TCP service reference.
[<Sealed>]
type TraefikTcpServiceRef internal (name: string) =
    member internal _.Name = name

/// A named TCP middleware reference.
[<Sealed>]
type TraefikTcpMiddlewareRef internal (name: string) =
    member internal _.Name = name

/// A named UDP service reference.
[<Sealed>]
type TraefikUdpServiceRef internal (name: string) =
    member internal _.Name = name

/// A named HTTP servers-transport reference.
[<Sealed>]
type TraefikHttpServersTransportRef internal (name: string) =
    member internal _.Name = name

/// A named TCP servers-transport reference.
[<Sealed>]
type TraefikTcpServersTransportRef internal (name: string) =
    member internal _.Name = name

/// A named TLS options reference.
[<Sealed>]
type TraefikTlsOptionsRef internal (name: string) =
    member internal _.Name = name

/// A named certificate-resolver reference.
[<Sealed>]
type TraefikCertificateResolverRef internal (name: string) =
    member internal _.Name = name

/// A named protected certificate identity reference.
[<Sealed>]
type TraefikCertificateRef internal (name: string) =
    member internal _.Name = name

/// A composable, safely quoted HTTP router rule.
[<Sealed>]
type TraefikHttpRule internal (rule: TraefikHttpGraphModel.Rule) =
    let expression = TraefikHttpGraphModel.renderGoRule rule
    member internal _.Rule = rule
    member _.Expression = expression
    static member (&&&) (left: TraefikHttpRule, right: TraefikHttpRule) =
        TraefikHttpRule(TraefikHttpGraphModel.andAlso left.Rule right.Rule)
    static member (|||) (left: TraefikHttpRule, right: TraefikHttpRule) =
        TraefikHttpRule(TraefikHttpGraphModel.orElse left.Rule right.Rule)

/// A composable, safely quoted TCP router rule.
[<Sealed>]
type TraefikTcpRule internal (expression: string) =
    member _.Expression = expression

/// The network protocol suffix for a numeric Traefik entry-point listener address.
[<RequireQualifiedAccess>]
type TraefikListenerTransport =
    | Tcp
    | Udp

/// Typed DNS credential environment-variable declaration.
[<Sealed>]
type TraefikDnsCredentialProvider internal (name: string, fields: TraefikNativeValue) =
    member _.Name = name
    member _.Fields = fields

[<RequireQualifiedAccess>]
module internal TraefikNativeModel =
    let private failDuplicateFields () =
        invalidArg "configuration" "A Traefik configuration object cannot declare a field more than once."

    let private validateFieldName (name: string) =
        if String.IsNullOrWhiteSpace(name) || (name |> Seq.exists Char.IsControl) then
            invalidArg "configuration" "A Traefik configuration field name is invalid."

    let createObject (fields: seq<TraefikNativeField>) =
        let builder = ImmutableSortedDictionary.CreateBuilder<string, TraefikNativeValue>(StringComparer.Ordinal)
        for field in fields do
            validateFieldName field.Name
            if builder.ContainsKey(field.Name) then failDuplicateFields ()
            builder.Add(field.Name, field.Value)
        TraefikNativeValue.Object(builder.ToImmutable())

    let createNamedObjectMap (objects: seq<TraefikNamedNativeObject>) =
        let builder = ImmutableSortedDictionary.CreateBuilder<string, TraefikNativeValue>(StringComparer.Ordinal)
        for item in objects do
            if builder.ContainsKey(item.Name) then
                invalidArg "configuration" "A Traefik configuration object name cannot be declared more than once."
            builder.Add(item.Name, item.Value)
        TraefikNativeValue.Object(builder.ToImmutable())

    let field (name: string) (value: TraefikNativeValue) = TraefikNativeField(name, value)

    let private collectDeferredOutputs root =
        let mutable deferred: ResizeArray<Output<obj>> option = None

        let addOutput (output: Output<'T>) =
            let outputs =
                match deferred with
                | Some outputs -> outputs
                | None ->
                    let outputs = ResizeArray<Output<obj>>()
                    deferred <- Some outputs
                    outputs
            outputs.Add(output.Apply(Func<'T, obj>(fun value -> box value)))

        let rec visit value =
            match value with
            | TraefikNativeValue.BooleanOutput output -> addOutput output
            | TraefikNativeValue.IntegerOutput output -> addOutput output
            | TraefikNativeValue.Integer32Output output -> addOutput output
            | TraefikNativeValue.NumberOutput output -> addOutput output
            | TraefikNativeValue.String(OutputString output) -> addOutput output
            | TraefikNativeValue.Array values -> values |> List.iter visit
            | TraefikNativeValue.Object fields -> for KeyValue(_, value) in fields do visit value
            | TraefikNativeValue.NullValue
            | TraefikNativeValue.Boolean _
            | TraefikNativeValue.Integer _
            | TraefikNativeValue.Number _
            | TraefikNativeValue.String(LiteralString _) -> ()

        visit root
        deferred

    let private serialize root (deferredValues: ImmutableArray<obj>) =
        let buffer = ArrayBufferWriter<byte>()
        use writer = new Utf8JsonWriter(buffer)
        let mutable deferredIndex = 0
        let nextDeferredValue () =
            let value = deferredValues[deferredIndex]
            deferredIndex <- deferredIndex + 1
            value

        let rec write value =
            match value with
            | TraefikNativeValue.NullValue -> writer.WriteNullValue()
            | TraefikNativeValue.Boolean value -> writer.WriteBooleanValue(value)
            | TraefikNativeValue.BooleanOutput _ -> writer.WriteBooleanValue(unbox<bool>(nextDeferredValue ()))
            | TraefikNativeValue.Integer value -> writer.WriteNumberValue(value)
            | TraefikNativeValue.IntegerOutput _ -> writer.WriteNumberValue(unbox<int64>(nextDeferredValue ()))
            | TraefikNativeValue.Integer32Output _ -> writer.WriteNumberValue(unbox<int>(nextDeferredValue ()))
            | TraefikNativeValue.Number value -> writer.WriteNumberValue(value)
            | TraefikNativeValue.NumberOutput _ -> writer.WriteNumberValue(unbox<decimal>(nextDeferredValue ()))
            | TraefikNativeValue.String(LiteralString value) -> writer.WriteStringValue(value)
            | TraefikNativeValue.String(OutputString _) -> writer.WriteStringValue(unbox<string>(nextDeferredValue ()))
            | TraefikNativeValue.Array values ->
                writer.WriteStartArray()
                for value in values do write value
                writer.WriteEndArray()
            | TraefikNativeValue.Object fields ->
                writer.WriteStartObject()
                // Every object is built with the ordinal comparer, so its enumeration is canonical.
                for KeyValue(name, value) in fields do
                    writer.WritePropertyName(name)
                    write value
                writer.WriteEndObject()

        write root
        writer.Flush()
        Encoding.UTF8.GetString(buffer.WrittenSpan)

    let resolve (specification: TraefikConfigurationSpec) : Output<string> =
        match collectDeferredOutputs specification.Root with
        | None ->
            Output.CreateSecret<string>(serialize specification.Root ImmutableArray<obj>.Empty)
        | Some deferred ->
            let resolved =
                Output.All<obj>(deferred)
                    .Apply(Func<ImmutableArray<obj>, string>(fun values -> serialize specification.Root values))
            Output.CreateSecret<string>(resolved)

/// Sequence collection shared by the public native configuration computation-expression builders.
[<AbstractClass>]
type TraefikListBuilder<'T>() =
    member _.Yield(value: 'T) = [ value ]
    member _.YieldFrom(values: seq<'T>) = Seq.toList values
    member _.Zero() = []
    member _.Combine(left: 'T list, right: 'T list) = left @ right
    member _.Delay(generator: unit -> 'T list) = generator ()
    member _.For(values: seq<'U>, body: 'U -> 'T list) = values |> Seq.collect body |> Seq.toList

[<Sealed>]
type TraefikNativeObjectBuilder() =
    inherit TraefikListBuilder<TraefikNativeField>()
    member _.Run(fields: TraefikNativeField list) = TraefikNativeModel.createObject fields

[<Sealed>]
type TraefikNamedNativeObjectBuilder internal (name: string) =
    inherit TraefikListBuilder<TraefikNativeField>()
    member _.Run(fields: TraefikNativeField list) =
        TraefikNamedNativeObject(name, TraefikNativeModel.createObject fields)

[<Sealed>]
type TraefikNamedNativeObjectMapBuilder internal (propertyName: string) =
    inherit TraefikListBuilder<TraefikNamedNativeObject>()
    member _.Run(objects: TraefikNamedNativeObject list) =
        TraefikNativeModel.field propertyName (TraefikNativeModel.createNamedObjectMap objects)

[<Sealed>]
type TraefikStaticConfigurationBuilder() =
    inherit TraefikListBuilder<TraefikNativeField>()
    member _.Run(fields: TraefikNativeField list) =
        TraefikConfigurationPart.Static(TraefikNativeModel.createObject fields)

[<Sealed>]
type TraefikDynamicConfigurationBuilder() =
    inherit TraefikListBuilder<TraefikNativeField>()
    member _.Run(fields: TraefikNativeField list) =
        TraefikConfigurationPart.Dynamic(TraefikNativeModel.createObject fields)

[<Sealed>]
type TraefikProtocolConfigurationBuilder internal (name: string) =
    inherit TraefikListBuilder<TraefikNativeField>()
    member _.Run(fields: TraefikNativeField list) =
        TraefikNativeModel.field name (TraefikNativeModel.createObject fields)

[<Sealed>]
type TraefikDnsCredentialsBuilder() =
    inherit TraefikListBuilder<TraefikDnsCredentialProvider>()
    member _.Run(providers: TraefikDnsCredentialProvider list) =
        let fields =
            providers
            |> List.map (fun provider -> TraefikNativeModel.field provider.Name provider.Fields)
        TraefikConfigurationPart.DnsCredentials(TraefikNativeModel.createObject fields)

[<Sealed>]
type TraefikDnsCredentialsProviderBuilder internal (providerName: string) =
    inherit TraefikListBuilder<TraefikNativeField>()
    member _.Run(fields: TraefikNativeField list) =
        TraefikDnsCredentialProvider(providerName, TraefikNativeModel.createObject fields)
[<Sealed>]
type TraefikConfigurationBuilder() =
    inherit TraefikListBuilder<TraefikConfigurationPart>()
    member _.Run(parts: TraefikConfigurationPart list) =
        let selected select =
            let values = parts |> List.choose select
            if values.Length > 1 then
                invalidArg "configuration" "A Traefik static, dynamic, or DNS credential section may be declared only once."
            values |> List.tryHead

        let sections =
            [ selected (function TraefikConfigurationPart.Static value -> Some("static", value) | _ -> None)
              selected (function TraefikConfigurationPart.Dynamic value -> Some("dynamic", value) | _ -> None)
              selected (function TraefikConfigurationPart.DnsCredentials value -> Some("dnsCredentials", value) | _ -> None) ]
            |> List.choose id
            |> List.map (fun (name, value) -> TraefikNativeModel.field name value)

        if sections.IsEmpty then
            invalidArg "configuration" "A Traefik configuration must declare at least one section."
        TraefikConfigurationSpec(TraefikNativeModel.createObject sections)

[<RequireQualifiedAccess>]
module TraefikConfiguration =
    /// Resolves native values into canonical JSON. The complete configuration stays secret.
    let resolve (configuration: TraefikConfigurationSpec) = TraefikNativeModel.resolve configuration

[<RequireQualifiedAccess>]
module private TraefikRuleFormatting =
    let quoteGoString = TraefikHttpGraphModel.quoteGoString

[<RequireQualifiedAccess>]
module TraefikHttpRule =
    let host values = TraefikHttpRule(TraefikHttpGraphModel.host values)
    let hostRegexp values = TraefikHttpRule(TraefikHttpGraphModel.hostRegexp values)
    let path value = TraefikHttpRule(TraefikHttpGraphModel.path value)
    let pathPrefix value = TraefikHttpRule(TraefikHttpGraphModel.pathPrefix value)
    let pathRegexp value = TraefikHttpRule(TraefikHttpGraphModel.pathRegexp value)
    let method' value = TraefikHttpRule(TraefikHttpGraphModel.method' value)
    let header name value = TraefikHttpRule(TraefikHttpGraphModel.header name value)
    let headerRegexp name value = TraefikHttpRule(TraefikHttpGraphModel.headerRegexp name value)
    let query name value = TraefikHttpRule(TraefikHttpGraphModel.query name value)
    let queryRegexp name value = TraefikHttpRule(TraefikHttpGraphModel.queryRegexp name value)
    let clientIp value = TraefikHttpRule(TraefikHttpGraphModel.clientIp value)
    let andAlso (left: TraefikHttpRule) (right: TraefikHttpRule) = left &&& right
    let orElse (left: TraefikHttpRule) (right: TraefikHttpRule) = left ||| right
    let not (rule: TraefikHttpRule) = TraefikHttpRule(TraefikHttpGraphModel.not rule.Rule)
[<RequireQualifiedAccess>]
module TraefikTcpRule =
    let private matcher name (value: string) =
        if String.IsNullOrWhiteSpace(value) then
            invalidArg "rule" "A Traefik TCP rule matcher requires a non-empty value."
        name + "(" + TraefikRuleFormatting.quoteGoString value + ")"

    let hostSni value = TraefikTcpRule(matcher "HostSNI" value)
    let hostSniRegexp value = TraefikTcpRule(matcher "HostSNIRegexp" value)
    let andAlso (left: TraefikTcpRule) (right: TraefikTcpRule) =
        TraefikTcpRule("(" + left.Expression + ") && (" + right.Expression + ")")
    let orElse (left: TraefikTcpRule) (right: TraefikTcpRule) =
        TraefikTcpRule("(" + left.Expression + ") || (" + right.Expression + ")")
    let not (rule: TraefikTcpRule) = TraefikTcpRule("!(" + rule.Expression + ")")

[<RequireQualifiedAccess>]
module private TraefikConfigurationValidation =
    let private namePattern = System.Text.RegularExpressions.Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)
    let name value =
        if String.IsNullOrWhiteSpace(value) || not (namePattern.IsMatch(value)) then
            invalidArg "name" "Traefik names must be 1–63 ASCII letters, digits, dots, underscores, or hyphens and begin with a letter or digit."
        value

    let entryPointName value =
        let value = name value
        if String.Equals(value, "traefik", StringComparison.OrdinalIgnoreCase)
           || String.Equals(value, "keroosha-admin", StringComparison.OrdinalIgnoreCase) then
            invalidArg "name" "This Traefik entry-point name is reserved."
        value
[<AbstractClass; Sealed>]
type TraefikNative private () =
    static member String(value: string) = TraefikNativeValue.String(LiteralString value)
    static member String(value: Output<string>) = TraefikNativeValue.String(OutputString value)
    static member Integer(value: int) = TraefikNativeValue.Integer(int64 value)
    static member Integer(value: int64) = TraefikNativeValue.Integer value
    static member Integer(value: Output<int>) = TraefikNativeValue.Integer32Output value
    static member Integer(value: Output<int64>) = TraefikNativeValue.IntegerOutput value
    static member Number(value: decimal) = TraefikNativeValue.Number value
    static member Number(value: Output<decimal>) = TraefikNativeValue.NumberOutput value
    static member Boolean(value: bool) = TraefikNativeValue.Boolean value
    static member Boolean(value: Output<bool>) = TraefikNativeValue.BooleanOutput value
    static member Array(values: seq<TraefikNativeValue>) = TraefikNativeValue.Array(Seq.toList values)
    static member Object(fields: seq<TraefikNativeField>) = TraefikNativeModel.createObject fields
    static member Null = TraefikNativeValue.NullValue

[<AutoOpen>]
module TraefikConfigurationBuilders =
    /// Converts string, Output<string> into a secret-preserving native JSON value.
    let inline nativeString (value: ^T) : TraefikNativeValue =
        ((^T or TraefikNative) : (static member String : ^T -> TraefikNativeValue) value)

    /// Converts integer or Output<int>/Output<int64> into a native JSON integer.
    let inline nativeInteger (value: ^T) : TraefikNativeValue =
        ((^T or TraefikNative) : (static member Integer : ^T -> TraefikNativeValue) value)

    /// Converts bool or Output<bool> into a native JSON boolean.
    let inline nativeBoolean (value: ^T) : TraefikNativeValue =
        ((^T or TraefikNative) : (static member Boolean : ^T -> TraefikNativeValue) value)

    let nativeNumber (value: decimal) = TraefikNativeValue.Number value
    let nativeNumberOutput (value: Output<decimal>) = TraefikNativeValue.NumberOutput value
    let nativeNull = TraefikNativeValue.NullValue
    let nativeArray values = TraefikNativeValue.Array(Seq.toList values)
    let nativeField name value = TraefikNativeModel.field name value
    let nativeObject = TraefikNativeObjectBuilder()

    /// Starts the one structured static portion of a Traefik configuration.
    let staticConfiguration = TraefikStaticConfigurationBuilder()
    /// Starts the one structured dynamic portion of a Traefik configuration.
    let dynamicConfiguration = TraefikDynamicConfigurationBuilder()
    /// Combines static, dynamic, and DNS-credential sections into one optional resource input.
    let traefikConfiguration = TraefikConfigurationBuilder()

    let staticEntryPoint name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.entryPointName name)
    let staticEntryPoints = TraefikNamedNativeObjectMapBuilder("entryPoints")
    let staticCertificatesResolver name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let staticCertificatesResolvers = TraefikNamedNativeObjectMapBuilder("certificatesResolvers")

    let inline entryPointAddress value = nativeField "address" (nativeString value)
    /// Builds a static listener address from a numeric IP, port, and TCP/UDP network transport.
    let entryPointListener (address: IPAddress) (port: int) (transport: TraefikListenerTransport) =
        let message = "Invalid, unsafe or unsupported Traefik listener socket binding."
        if isNull address then invalidArg "address" message
        if port < 1 || port > 65535 then invalidArg "port" message
        if address.AddressFamily = System.Net.Sockets.AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6 then
            invalidArg "address" message
        let numericAddress = address.ToString().ToLowerInvariant()
        let numericAddress =
            if address.AddressFamily = System.Net.Sockets.AddressFamily.InterNetworkV6 then "[" + numericAddress + "]"
            elif address.AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork then numericAddress
            else invalidArg "address" message
        let protocol =
            match transport with
            | TraefikListenerTransport.Tcp -> "tcp"
            | TraefikListenerTransport.Udp -> "udp"
        nativeField
            "address"
            (nativeString (numericAddress + ":" + port.ToString(CultureInfo.InvariantCulture) + "/" + protocol))

    /// Parses a numeric IP address before building a static listener; use entryPointAddress for other address forms.
    let entryPointListenerAddress (address: string) (port: int) (transport: TraefikListenerTransport) =
        let mutable numericAddress = Unchecked.defaultof<IPAddress>
        if not (IPAddress.TryParse(address, &numericAddress)) then
            invalidArg "address" "Invalid, unsafe or unsupported Traefik listener socket binding."
        entryPointListener numericAddress port transport
    let inline entryPointReusePort value = nativeField "reusePort" (nativeBoolean value)
    let inline entryPointHttp3 value = nativeField "http3" (nativeObject { nativeField "advertisedPort" (nativeInteger value) })
    let entryPointForwardedHeaders fields = nativeField "forwardedHeaders" fields
    let entryPointProxyProtocol fields = nativeField "proxyProtocol" fields
    let entryPointTransport fields = nativeField "transport" fields
    let entryPointHttp fields = nativeField "http" fields
    let entryPointUdp fields = nativeField "udp" fields

    let staticLog fields = nativeField "log" fields
    let staticAccessLog fields = nativeField "accessLog" fields
    let staticMetrics fields = nativeField "metrics" fields
    let staticTracing fields = nativeField "tracing" fields
    let staticServersTransport fields = nativeField "serversTransport" fields

    let inline logLevel value = nativeField "level" (nativeString value)
    let inline logFormat value = nativeField "format" (nativeString value)
    let inline accessLogFormat value = nativeField "format" (nativeString value)

    let inline acmeEmail value = nativeField "email" (nativeString value)
    let inline acmeCaServer value = nativeField "caServer" (nativeString value)
    let inline acmeKeyType value = nativeField "keyType" (nativeString value)
    let acmeHttpChallenge (entryPoint: TraefikHttpEntryPointRef) =
        nativeField "httpChallenge" (nativeObject { nativeField "entryPoint" (nativeString entryPoint.Name) })
    let acmeHttpChallengeStatic (name: string) =
        nativeField "httpChallenge" (nativeObject { nativeField "entryPoint" (nativeString(TraefikConfigurationValidation.entryPointName name)) })
    let acmeDnsChallenge fields = nativeField "dnsChallenge" fields
    let acmeTlsChallenge = nativeField "tlsChallenge" (TraefikNative.Object Seq.empty)
    let acme fields = nativeField "acme" fields
    let inline acmeDnsProvider value = nativeField "provider" (nativeString value)
    let inline acmeDnsResolvers values = nativeField "resolvers" (nativeArray(values |> Seq.map nativeString))
    let inline acmeDnsPropagationDelayBeforeChecks value = nativeField "propagation" (nativeObject { nativeField "delayBeforeChecks" (nativeString value) })

    let httpConfiguration = TraefikProtocolConfigurationBuilder("http")
    let tcpConfiguration = TraefikProtocolConfigurationBuilder("tcp")
    let udpConfiguration = TraefikProtocolConfigurationBuilder("udp")
    let tlsConfiguration = TraefikProtocolConfigurationBuilder("tls")

    let httpRouters = TraefikNamedNativeObjectMapBuilder("routers")
    let httpServices = TraefikNamedNativeObjectMapBuilder("services")
    let httpMiddlewares = TraefikNamedNativeObjectMapBuilder("middlewares")
    let httpServersTransports = TraefikNamedNativeObjectMapBuilder("serversTransports")
    let tcpRouters = TraefikNamedNativeObjectMapBuilder("routers")
    let tcpServices = TraefikNamedNativeObjectMapBuilder("services")
    let tcpMiddlewares = TraefikNamedNativeObjectMapBuilder("middlewares")
    let tcpServersTransports = TraefikNamedNativeObjectMapBuilder("serversTransports")
    let udpRouters = TraefikNamedNativeObjectMapBuilder("routers")
    let udpServices = TraefikNamedNativeObjectMapBuilder("services")
    let tlsOptions = TraefikNamedNativeObjectMapBuilder("options")

    let httpRouter name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let httpService name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let httpMiddleware name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let httpServersTransport name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let tcpRouter name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let tcpService name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let tcpMiddleware name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let tcpServersTransport name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let udpRouter name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let udpService name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)
    let tlsOptionsSet name = TraefikNamedNativeObjectBuilder(TraefikConfigurationValidation.name name)

    let httpEntryPoint name = TraefikHttpEntryPointRef(TraefikConfigurationValidation.entryPointName name)
    let tcpEntryPoint name = TraefikTcpEntryPointRef(TraefikConfigurationValidation.entryPointName name)
    let udpEntryPoint name = TraefikUdpEntryPointRef(TraefikConfigurationValidation.entryPointName name)
    let httpRouterRef name = TraefikHttpRouterRef(TraefikConfigurationValidation.name name)
    let httpServiceRef name = TraefikHttpServiceRef(TraefikConfigurationValidation.name name)
    let httpMiddlewareRef name = TraefikHttpMiddlewareRef(TraefikConfigurationValidation.name name)
    let tcpServiceRef name = TraefikTcpServiceRef(TraefikConfigurationValidation.name name)
    let tcpMiddlewareRef name = TraefikTcpMiddlewareRef(TraefikConfigurationValidation.name name)
    let udpServiceRef name = TraefikUdpServiceRef(TraefikConfigurationValidation.name name)
    let httpServersTransportRef name = TraefikHttpServersTransportRef(TraefikConfigurationValidation.name name)
    let tcpServersTransportRef name = TraefikTcpServersTransportRef(TraefikConfigurationValidation.name name)
    let tlsOptionsRef name = TraefikTlsOptionsRef(TraefikConfigurationValidation.name name)
    let certificateResolverRef name = TraefikCertificateResolverRef(TraefikConfigurationValidation.name name)
    let certificateRef name = TraefikCertificateRef(TraefikConfigurationValidation.name name)

    let private certificateReference (value: TraefikCertificateRef) =
        nativeObject { nativeField "certificate" (nativeString value.Name) }

    let private certificateReferences (values: seq<TraefikCertificateRef>) =
        values |> Seq.map certificateReference |> nativeArray

    /// References server identities in native `tls.certificates`.
    let tlsCertificates (values: seq<TraefikCertificateRef>) =
        nativeField "certificates" (certificateReferences values)

    /// References outbound HTTP transport client identities.
    let httpServersTransportCertificates (values: seq<TraefikCertificateRef>) =
        nativeField "certificates" (certificateReferences values)

    /// References outbound TCP transport client identities.
    let tcpServersTransportCertificates (values: seq<TraefikCertificateRef>) =
        nativeField "certificates" (certificateReferences values)

    /// Selects a protected identity for ForwardAuth outbound TLS.
    let httpForwardAuthClientCertificate (value: TraefikCertificateRef) =
        nativeField "clientCertificate" (nativeString value.Name)

    let httpRule (rule: TraefikHttpRule) = nativeField "rule" (nativeString rule.Expression)
    let httpRouterEntryPoints (values: seq<TraefikHttpEntryPointRef>) =
        values |> Seq.map (fun value -> nativeString value.Name) |> nativeArray |> nativeField "entryPoints"
    let httpRouterService (value: TraefikHttpServiceRef) = nativeField "service" (nativeString value.Name)
    /// Stores native parentRefs without flattening the parent router's rule or middleware.
    let httpRouterParentRefs (values: seq<TraefikHttpRouterRef>) =
        values |> Seq.map (fun value -> nativeString value.Name) |> nativeArray |> nativeField "parentRefs"
    let httpRouterMiddlewares (values: seq<TraefikHttpMiddlewareRef>) =
        values |> Seq.map (fun value -> nativeString value.Name) |> nativeArray |> nativeField "middlewares"
    let inline httpRouterPriority value = nativeField "priority" (nativeInteger value)
    let httpRouterTls fields = nativeField "tls" fields
    let httpTlsResolver (value: TraefikCertificateResolverRef) = nativeField "certResolver" (nativeString value.Name)
    let httpTlsOptions (value: TraefikTlsOptionsRef) = nativeField "options" (nativeString value.Name)

    /// Adds HTTP middleware at the service level, distinct from router middlewares.
    let httpServiceMiddlewares (values: seq<TraefikHttpMiddlewareRef>) =
        values |> Seq.map (fun value -> nativeString value.Name) |> nativeArray |> nativeField "middlewares"

    let httpLoadBalancer fields = nativeField "loadBalancer" fields
    let inline httpServers (values: seq< ^T>) =
        values
        |> Seq.map (fun value -> nativeObject { nativeField "url" (nativeString value) })
        |> nativeArray
        |> nativeField "servers"
    let httpServiceServersTransport (value: TraefikHttpServersTransportRef) = nativeField "serversTransport" (nativeString value.Name)
    let inline httpPassHostHeader value = nativeField "passHostHeader" (nativeBoolean value)
    let httpHealthCheck fields = nativeField "healthCheck" fields
    let inline httpHealthCheckPath value = nativeField "path" (nativeString value)
    let inline httpHealthCheckInterval value = nativeField "interval" (nativeString value)
    let inline httpHealthCheckTimeout value = nativeField "timeout" (nativeString value)
    let inline httpHealthCheckFollowRedirects value = nativeField "followRedirects" (nativeBoolean value)
    let httpServiceSticky fields = nativeField "sticky" fields
    let httpStickyCookie fields = nativeField "cookie" fields
    let inline httpCookieName value = nativeField "name" (nativeString value)
    let inline httpCookieSecure value = nativeField "secure" (nativeBoolean value)
    let inline httpCookieHttpOnly value = nativeField "httpOnly" (nativeBoolean value)

    let inline httpMiddlewareStripPrefix (prefixes: seq< ^T>) =
        nativeField "stripPrefix" (nativeObject { nativeField "prefixes" (nativeArray(prefixes |> Seq.map nativeString)) })
    let inline httpMiddlewareAddPrefix prefix =
        nativeField "addPrefix" (nativeObject { nativeField "prefix" (nativeString prefix) })
    let inline httpMiddlewareRedirectScheme scheme permanent =
        nativeField "redirectScheme" (nativeObject { nativeField "scheme" (nativeString scheme); nativeField "permanent" (nativeBoolean permanent) })
    let httpMiddlewareCompress = nativeField "compress" (TraefikNative.Object Seq.empty)
    let httpMiddlewareHeaders fields = nativeField "headers" fields
    let inline httpMiddlewareBasicAuth (users: seq< ^T>) =
        nativeField "basicAuth" (nativeObject { nativeField "users" (nativeArray(users |> Seq.map nativeString)) })

    let tcpRule (rule: TraefikTcpRule) = nativeField "rule" (nativeString rule.Expression)
    let tcpRouterEntryPoints (values: seq<TraefikTcpEntryPointRef>) =
        values |> Seq.map (fun value -> nativeString value.Name) |> nativeArray |> nativeField "entryPoints"
    let tcpRouterService (value: TraefikTcpServiceRef) = nativeField "service" (nativeString value.Name)
    let tcpRouterMiddlewares (values: seq<TraefikTcpMiddlewareRef>) =
        values |> Seq.map (fun value -> nativeString value.Name) |> nativeArray |> nativeField "middlewares"
    let inline tcpRouterPriority value = nativeField "priority" (nativeInteger value)
    let tcpRouterTls fields = nativeField "tls" fields
    let inline tcpTlsPassthrough value = nativeField "passthrough" (nativeBoolean value)
    let tcpTlsResolver (value: TraefikCertificateResolverRef) = nativeField "certResolver" (nativeString value.Name)
    let tcpTlsOptions (value: TraefikTlsOptionsRef) = nativeField "options" (nativeString value.Name)
    let tcpLoadBalancer fields = nativeField "loadBalancer" fields
    let inline tcpServers (values: seq< ^T>) =
        values
        |> Seq.map (fun value -> nativeObject { nativeField "address" (nativeString value) })
        |> nativeArray
        |> nativeField "servers"
    let tcpServiceServersTransport (value: TraefikTcpServersTransportRef) = nativeField "serversTransport" (nativeString value.Name)
    let inline tcpProxyProtocolVersion value = nativeField "version" (nativeInteger value)
    let tcpProxyProtocol fields = nativeField "proxyProtocol" fields
    let tcpHealthCheck fields = nativeField "healthCheck" fields
    let inline tcpHealthCheckPort value = nativeField "port" (nativeInteger value)
    let inline tcpHealthCheckSend value = nativeField "send" (nativeString value)
    let inline tcpHealthCheckExpect value = nativeField "expect" (nativeString value)
    let inline tcpHealthCheckInterval value = nativeField "interval" (nativeString value)
    let inline tcpHealthCheckUnhealthyInterval value = nativeField "unhealthyInterval" (nativeString value)
    let inline tcpHealthCheckTimeout value = nativeField "timeout" (nativeString value)

    let udpRouterEntryPoints (values: seq<TraefikUdpEntryPointRef>) =
        values |> Seq.map (fun value -> nativeString value.Name) |> nativeArray |> nativeField "entryPoints"
    let udpRouterService (value: TraefikUdpServiceRef) = nativeField "service" (nativeString value.Name)
    let inline udpServers (values: seq< ^T>) =
        values
        |> Seq.map (fun value -> nativeObject { nativeField "address" (nativeString value) })
        |> nativeArray
        |> nativeField "servers"
    let udpLoadBalancer fields = nativeField "loadBalancer" fields

    let inline tlsMinVersion value = nativeField "minVersion" (nativeString value)
    let inline tlsMaxVersion value = nativeField "maxVersion" (nativeString value)
    let inline tlsCipherSuites (values: seq< ^T>) = nativeField "cipherSuites" (nativeArray(values |> Seq.map nativeString))
    let inline tlsCurvePreferences (values: seq< ^T>) = nativeField "curvePreferences" (nativeArray(values |> Seq.map nativeString))
    let inline tlsSniStrict value = nativeField "sniStrict" (nativeBoolean value)
    let tlsClientAuth fields = nativeField "clientAuth" fields
    let inline tlsClientAuthType value = nativeField "clientAuthType" (nativeString value)
    let inline tlsClientAuthCaFiles (values: seq< ^T>) = nativeField "caFiles" (nativeArray(values |> Seq.map nativeString))
    let tlsDefaultGeneratedCert fields = nativeField "defaultGeneratedCert" fields
    let tlsDefaultGeneratedCertResolver (value: TraefikCertificateResolverRef) = nativeField "resolver" (nativeString value.Name)
    let tlsDefaultGeneratedCertDomain fields = nativeField "domain" fields

    let dnsupdateCredentials = TraefikDnsCredentialsProviderBuilder("dnsupdate")
    let cloudflareCredentials = TraefikDnsCredentialsProviderBuilder("cloudflare")
    let digitalOceanCredentials = TraefikDnsCredentialsProviderBuilder("digitalocean")
    let linodeCredentials = TraefikDnsCredentialsProviderBuilder("linode")
    let vultrCredentials = TraefikDnsCredentialsProviderBuilder("vultr")
    let dnsCredentials = TraefikDnsCredentialsBuilder()
    let inline dnsupdateNameserver value = nativeField "DNSUPDATE_NAMESERVER" (nativeString value)
    let inline dnsupdateDnsTimeout value = nativeField "DNSUPDATE_DNS_TIMEOUT" (nativeString value)
    let inline dnsupdateZones value = nativeField "DNSUPDATE_ZONES" (nativeString value)
    let inline dnsupdateTtl value = nativeField "DNSUPDATE_TTL" (nativeString value)
    let inline dnsupdatePropagationTimeout value = nativeField "DNSUPDATE_PROPAGATION_TIMEOUT" (nativeString value)
    let inline dnsupdatePollingInterval value = nativeField "DNSUPDATE_POLLING_INTERVAL" (nativeString value)
    let inline dnsupdateSequenceInterval value = nativeField "DNSUPDATE_SEQUENCE_INTERVAL" (nativeString value)
    let inline dnsupdateTsigKey value = nativeField "DNSUPDATE_TSIG_KEY" (nativeString value)
    let inline dnsupdateTsigSecret value = nativeField "DNSUPDATE_TSIG_SECRET" (nativeString value)
    let inline dnsupdateTsigAlgorithm value = nativeField "DNSUPDATE_TSIG_ALGORITHM" (nativeString value)
    let inline cloudflareDnsApiToken value = nativeField "CLOUDFLARE_DNS_API_TOKEN" (nativeString value)
    let inline cloudflareZoneApiToken value = nativeField "CLOUDFLARE_ZONE_API_TOKEN" (nativeString value)
    let inline digitalOceanAuthToken value = nativeField "DO_AUTH_TOKEN" (nativeString value)
    let inline linodeToken value = nativeField "LINODE_TOKEN" (nativeString value)
    let inline vultrApiKey value = nativeField "VULTR_API_KEY" (nativeString value)

    let hostRule values = TraefikHttpRule.host values
    let hostRegexpRule values = TraefikHttpRule.hostRegexp values
    let pathRule value = TraefikHttpRule.path value
    let pathPrefixRule value = TraefikHttpRule.pathPrefix value
    let pathRegexpRule value = TraefikHttpRule.pathRegexp value
    let methodRule value = TraefikHttpRule.method' value
    let headerRule name value = TraefikHttpRule.header name value
    let headerRegexpRule name value = TraefikHttpRule.headerRegexp name value
    let queryRule name value = TraefikHttpRule.query name value
    let queryRegexpRule name value = TraefikHttpRule.queryRegexp name value
    let clientIpRule value = TraefikHttpRule.clientIp value
    let andRule left right = TraefikHttpRule.andAlso left right
    let orRule left right = TraefikHttpRule.orElse left right
    let notRule rule = TraefikHttpRule.not rule

    let tcpHostSniRule value = TraefikTcpRule.hostSni value
    let tcpHostSniRegexpRule value = TraefikTcpRule.hostSniRegexp value
    let andTcpRule left right = TraefikTcpRule.andAlso left right
    let orTcpRule left right = TraefikTcpRule.orElse left right
    let notTcpRule rule = TraefikTcpRule.not rule

    let nativeStaticField name value = nativeField name value
    let nativeHttpField name value = nativeField name value
    let nativeTcpField name value = nativeField name value
    let nativeUdpField name value = nativeField name value
    let nativeTlsField name value = nativeField name value
