namespace Dorothy.DSL

open System
open System.Collections.Immutable
open System.IO
open System.Net.Mail
open System.Threading
open System.Threading.Tasks
open Pulumi

/// ACME resolver settings translated directly to Traefik's file-provider model.
type TraefikResolver =
    { Email: string
      HttpChallengeEntryPoint: string
      CaServer: string }

/// A router's TLS selection. A provided certificate is an expected SAN match, not a router pin.
type TraefikRouterTls =
    { Kind: string
      Name: string }

/// One host-matched Traefik router and its backend URL.
type TraefikRouter =
    { Host: string
      EntryPoint: string
      Backend: string
      Tls: TraefikRouterTls }

/// Independently resolved provider maps preserve their Pulumi dependencies and secret boundaries.
type TraefikResolvedSpec =
    { EntryPoints: Output<ImmutableDictionary<string, int>>
      Resolvers: Output<ImmutableDictionary<string, TraefikResolver>>
      Routers: Output<ImmutableDictionary<string, TraefikRouter>>
      Certificates: Output<ImmutableDictionary<string, NormalizedCertificate>>
      AdminPort: int }

type EntryPointDefinition =
    { Name: string
      Listen: int }

type internal CertificateDefinition =
    | PemCertificateMaterial of chain: CertificateContent * privateKey: CertificateContent * password: TraefikStringInput option
    | Pkcs12CertificateMaterial of bundle: CertificateContent * password: TraefikStringInput option

/// One typed provided certificate declaration that can be referenced by a router.
[<Sealed>]
type TraefikCertificateSpec internal (name: string, definition: CertificateDefinition) =
    member _.Name = name
    member internal _.Definition = definition

/// One typed ACME resolver declaration that can be referenced by a router.
[<Sealed>]
type TraefikAcmeResolverSpec internal (
    name: string,
    email: TraefikStringInput,
    httpChallengeEntryPoint: TraefikStringInput,
    caServer: TraefikStringInput
) =
    member _.Name = name
    member internal _.Email = email
    member internal _.HttpChallengeEntryPoint = httpChallengeEntryPoint
    member internal _.CaServer = caServer

type TraefikTlsMode =
    | NoTls
    | Acme of resolver: TraefikAcmeResolverSpec
    | Provided of certificate: TraefikCertificateSpec
type AcmeChallenge =
    | Http01 of entryPoint: string
    | Http01Output of entryPoint: Output<string>

[<RequireQualifiedAccess>]
type EntryPointPart =
    | Listen of int

[<RequireQualifiedAccess>]
type RouterPart =
    | Host of TraefikStringInput
    | EntryPoint of TraefikStringInput
    | Backend of TraefikStringInput
    | Tls of TraefikTlsMode

[<RequireQualifiedAccess>]
type ResolverPart =
    | Email of TraefikStringInput
    | Challenge of AcmeChallenge
    | CaServer of TraefikStringInput

[<RequireQualifiedAccess>]
type CertificatePart =
    | Chain of CertificateContent
    | PrivateKey of CertificateContent
    | Bundle of CertificateContent
    | Password of TraefikStringInput

type RouterDefinition =
    { Name: string
      Host: TraefikStringInput
      EntryPoint: TraefikStringInput
      Backend: TraefikStringInput
      Tls: TraefikTlsMode }

[<RequireQualifiedAccess>]
type TraefikDeclaration =
    | EntryPoint of EntryPointDefinition
    | Router of RouterDefinition
    | Resolver of TraefikAcmeResolverSpec
    | Certificate of TraefikCertificateSpec
    | AdminPort of int

[<Sealed>]
type EntryPointBuilder internal (name: string) =
    member _.Name = name
    member _.Yield(part: EntryPointPart) = [ part ]
    member _.YieldFrom(parts: seq<EntryPointPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: EntryPointPart list, right: EntryPointPart list) = left @ right
    member _.Delay(generator: unit -> EntryPointPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> EntryPointPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: EntryPointPart list) =
        let listens = parts |> List.choose (function EntryPointPart.Listen port -> Some port)
        if listens.Length <> 1 then invalidArg "entryPoint" "An entry point must declare listen exactly once."
        let port = listens.Head
        if port < 1 || port > 65535 then invalidArg "entryPoint" "An entry point listen port must be between 1 and 65535."
        { Name = name; Listen = port }

[<Sealed>]
type RouterBuilder internal (name: string) =
    member _.Yield(part: RouterPart) = [ part ]
    member _.Yield(entryPoint: EntryPointBuilder) = [ RouterPart.EntryPoint(LiteralString entryPoint.Name) ]
    member _.YieldFrom(parts: seq<RouterPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: RouterPart list, right: RouterPart list) = left @ right
    member _.Delay(generator: unit -> RouterPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> RouterPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: RouterPart list) =
        let select name pick =
            let values = parts |> List.choose pick
            if values.Length > 1 then invalidArg "router" (sprintf "Router field '%s' may be declared only once." name)
            values |> List.tryHead

        let host = select "host" (function RouterPart.Host value -> Some value | _ -> None)
        let entryPoint = select "entryPoint" (function RouterPart.EntryPoint value -> Some value | _ -> None)
        let backend = select "backend" (function RouterPart.Backend value -> Some value | _ -> None)
        let tls = select "tls" (function RouterPart.Tls value -> Some value | _ -> None) |> Option.defaultValue TraefikTlsMode.NoTls

        match host, entryPoint, backend with
        | Some hostValue, Some entryPointValue, Some backendValue ->
            { Name = name
              Host = hostValue
              EntryPoint = entryPointValue
              Backend = backendValue
              Tls = tls }
        | _ -> invalidArg "router" "A router requires host, entryPoint, and backend."

[<Sealed>]
type AcmeResolverBuilder internal (name: string) =
    member _.Yield(part: ResolverPart) = [ part ]
    member _.YieldFrom(parts: seq<ResolverPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: ResolverPart list, right: ResolverPart list) = left @ right
    member _.Delay(generator: unit -> ResolverPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> ResolverPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: ResolverPart list) =
        let select name pick =
            let values = parts |> List.choose pick
            if values.Length > 1 then invalidArg "acmeResolver" (sprintf "Resolver field '%s' may be declared only once." name)
            values |> List.tryHead

        let email = select "email" (function ResolverPart.Email value -> Some value | _ -> None)
        let challenge = select "challenge" (function ResolverPart.Challenge value -> Some value | _ -> None)
        let caServer =
            select "caServer" (function ResolverPart.CaServer value -> Some value | _ -> None)
            |> Option.defaultValue (LiteralString "https://acme-v02.api.letsencrypt.org/directory")

        match email, challenge with
        | Some emailValue, Some challengeValue ->
            let challengeEntryPoint =
                match challengeValue with
                | AcmeChallenge.Http01 entryPoint -> LiteralString entryPoint
                | AcmeChallenge.Http01Output entryPoint -> OutputString entryPoint

            TraefikAcmeResolverSpec(name, emailValue, challengeEntryPoint, caServer)
        | _ -> invalidArg "acmeResolver" "An ACME resolver requires email and challenge."

[<Sealed>]
type PemCertificateBuilder internal (name: string) =
    member _.Yield(part: CertificatePart) = [ part ]
    member _.YieldFrom(parts: seq<CertificatePart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: CertificatePart list, right: CertificatePart list) = left @ right
    member _.Delay(generator: unit -> CertificatePart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> CertificatePart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: CertificatePart list) =
        let select fieldName pick =
            let values = parts |> List.choose pick
            if values.Length > 1 then invalidArg "pemCertificate" (sprintf "Certificate field '%s' may be declared only once." fieldName)
            values |> List.tryHead

        let chain = select "chain" (function CertificatePart.Chain value -> Some value | _ -> None)
        let privateKey = select "privateKey" (function CertificatePart.PrivateKey value -> Some value | _ -> None)
        let password = select "password" (function CertificatePart.Password value -> Some value | _ -> None)
        let bundle = select "bundle" (function CertificatePart.Bundle value -> Some value | _ -> None)

        match chain, privateKey, bundle with
        | Some chainValue, Some keyValue, None ->
            TraefikCertificateSpec(name, CertificateDefinition.PemCertificateMaterial(chainValue, keyValue, password))
        | _ -> invalidArg "pemCertificate" "A PEM certificate requires exactly one chain and privateKey and cannot declare bundle."

[<Sealed>]
type Pkcs12CertificateBuilder internal (name: string) =
    member _.Yield(part: CertificatePart) = [ part ]
    member _.YieldFrom(parts: seq<CertificatePart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: CertificatePart list, right: CertificatePart list) = left @ right
    member _.Delay(generator: unit -> CertificatePart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> CertificatePart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: CertificatePart list) =
        let bundles = parts |> List.choose (function CertificatePart.Bundle value -> Some value | _ -> None)
        let keys = parts |> List.choose (function CertificatePart.PrivateKey _ -> Some() | _ -> None)
        let chains = parts |> List.choose (function CertificatePart.Chain _ -> Some() | _ -> None)
        let passwords = parts |> List.choose (function CertificatePart.Password value -> Some value | _ -> None)

        if bundles.Length <> 1 || keys.Length > 0 || chains.Length > 0 || passwords.Length > 1 then
            invalidArg "pkcs12Certificate" "A PKCS#12 certificate requires exactly one bundle and at most one password."

        TraefikCertificateSpec(name, CertificateDefinition.Pkcs12CertificateMaterial(bundles.Head, List.tryHead passwords))

module private TraefikOutput =
    let outputOfInput = function
        | LiteralString value -> Output.Create(value)
        | OutputString value -> value

    let outputValues (inputs: TraefikStringInput list) =
        match inputs with
        | [] -> Output.Create(ImmutableArray<string>.Empty)
        | _ -> inputs |> List.map outputOfInput |> Output.All<string>

    let outputFromInputs (inputs: TraefikStringInput list) (create: ImmutableArray<string> -> 'T) =
        outputValues inputs
        |> fun values -> values.Apply(Func<ImmutableArray<string>, 'T>(create))

    let immutableDictionary (values: seq<string * 'T>) =
        let builder = ImmutableDictionary.CreateBuilder<string, 'T>(StringComparer.Ordinal)
        for key, value in values do builder.Add(key, value)
        builder.ToImmutable()

    let private contentInputs (content: CertificateContent) =
        match content.Kind with
        | CertificateContentKind.PemText input
        | CertificateContentKind.Base64Text input -> [ input ]
        | CertificateContentKind.FilePath _
        | CertificateContentKind.StreamFactory _ -> []

    let certificateInputs (certificate: TraefikCertificateSpec) =
        match certificate.Definition with
        | CertificateDefinition.PemCertificateMaterial(chain, privateKey, password) ->
            contentInputs chain @ contentInputs privateKey @ Option.toList password
        | CertificateDefinition.Pkcs12CertificateMaterial(bundle, password) ->
            contentInputs bundle @ Option.toList password

    let private readStream (factory: CancellationToken -> Task<Stream>) (cancellationToken: CancellationToken) =
        task {
            let! source = factory cancellationToken
            if isNull source then raise (InvalidOperationException("Certificate validation failed."))
            use source = source
            use destination = new MemoryStream()
            do! source.CopyToAsync(destination, 81920, cancellationToken)
            return destination.ToArray()
        }

    let resolveContent cancellationToken (consumeInput: unit -> string) (content: CertificateContent) =
        task {
            match content.Kind with
            | PemText _ ->
                return consumeInput () |> System.Text.Encoding.UTF8.GetBytes
            | Base64Text _ ->
                return consumeInput () |> Convert.FromBase64String
            | FilePath path ->
                try
                    return! File.ReadAllBytesAsync(path, cancellationToken)
                with
                | :? OperationCanceledException when cancellationToken.IsCancellationRequested -> return raise (OperationCanceledException cancellationToken)
                | _ -> return raise (InvalidOperationException("Certificate validation failed."))
            | StreamFactory factory ->
                try
                    return! readStream factory cancellationToken
                with
                | :? OperationCanceledException when cancellationToken.IsCancellationRequested -> return raise (OperationCanceledException cancellationToken)
                | _ -> return raise (InvalidOperationException("Certificate validation failed."))
        }

module private TraefikValidation =
    let private namePattern = System.Text.RegularExpressions.Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)

    let validateName parameterName (value: string) =
        if String.IsNullOrWhiteSpace value || not (namePattern.IsMatch value) then
            invalidArg parameterName "Traefik names must be 1–63 ASCII letters, digits, dots, underscores, or hyphens and begin with a letter or digit."

    let validateNameWithReserved parameterName (reserved: string list) (value: string) =
        validateName parameterName value
        if reserved |> List.exists (fun name -> String.Equals(name, value, StringComparison.OrdinalIgnoreCase)) then
            invalidArg parameterName "This name is reserved by the Traefik provider."

    let validateEmail (value: string) =
        try
            if String.IsNullOrWhiteSpace value then invalidArg "email" "An ACME email is required."
            let parsed = MailAddress(value)
            if not (String.Equals(parsed.Address, value, StringComparison.Ordinal)) then invalidArg "email" "An ACME email address is invalid."
        with
        | :? ArgumentException -> reraise ()
        | _ -> invalidArg "email" "An ACME email address is invalid."

    let validateUri parameterName (value: string) allowedSchemes =
        match Uri.TryCreate(value, UriKind.Absolute) with
        | true, uri ->
            let validScheme =
                allowedSchemes
                |> List.exists (fun scheme -> String.Equals(uri.Scheme, scheme, StringComparison.OrdinalIgnoreCase))
            let validPort = uri.IsDefaultPort || (uri.Port >= 1 && uri.Port <= 65535)
            if not validScheme
               || String.IsNullOrWhiteSpace uri.Host
               || not (String.IsNullOrEmpty uri.UserInfo)
               || not (String.IsNullOrEmpty uri.Query)
               || not (String.IsNullOrEmpty uri.Fragment)
               || not validPort then
                invalidArg parameterName "Traefik URLs must be absolute HTTP or HTTPS URLs without credentials, queries, or fragments."
        | _ -> invalidArg parameterName "Traefik URLs must be absolute HTTP or HTTPS URLs."

    let validateHost (value: string) =
        if String.IsNullOrWhiteSpace value
           || value.Contains('*')
           || (value |> Seq.exists Char.IsWhiteSpace)
           || (value |> Seq.exists Char.IsControl) then
            invalidArg "host" "A router host must be a single non-wildcard hostname."
        match Uri.CheckHostName(value.TrimEnd('.')) with
        | UriHostNameType.Dns | UriHostNameType.IPv4 | UriHostNameType.IPv6 -> ()
        | _ -> invalidArg "host" "A router host must be a valid DNS name or IP address."
type TraefikSpec internal (
    entryPoints: EntryPointDefinition list,
    resolvers: TraefikAcmeResolverSpec list,
    routers: RouterDefinition list,
    certificates: TraefikCertificateSpec list,
    adminPort: int
) =
    member _.Resolve(cancellationToken: CancellationToken) =
        let entryPointNames = entryPoints |> Seq.map (fun item -> item.Name) |> Set.ofSeq
        let resolverNames = resolvers |> Seq.map (fun item -> item.Name) |> Set.ofSeq
        let certificateNames = certificates |> Seq.map (fun certificate -> certificate.Name) |> Set.ofSeq

        let entryPointMap =
            entryPoints
            |> Seq.map (fun item -> item.Name, item.Listen)
            |> TraefikOutput.immutableDictionary
            |> Output.Create

        let resolverInputs =
            resolvers
            |> List.collect (fun resolver -> [ resolver.Email; resolver.HttpChallengeEntryPoint; resolver.CaServer ])

        let resolversOutput =
            TraefikOutput.outputFromInputs resolverInputs (fun values ->
                let mutable offset = 0
                let resolved =
                    resolvers
                    |> Seq.map (fun resolver ->
                        let email = values[offset]
                        let challenge = values[offset + 1]
                        let caServer = values[offset + 2]
                        offset <- offset + 3
                        TraefikValidation.validateEmail email
                        TraefikValidation.validateUri "caServer" caServer [ "http"; "https" ]
                        if not (Set.contains challenge entryPointNames) then
                            invalidArg "acmeResolver" "An ACME HTTP-01 challenge must reference a declared entry point."
                        resolver.Name,
                        { Email = email
                          HttpChallengeEntryPoint = challenge
                          CaServer = caServer })
                TraefikOutput.immutableDictionary resolved)

        let routerInputs =
            routers
            |> List.collect (fun router -> [ router.Host; router.EntryPoint; router.Backend ])

        let routersOutput =
            TraefikOutput.outputFromInputs routerInputs (fun values ->
                let mutable offset = 0
                let resolved =
                    routers
                    |> Seq.map (fun router ->
                        let host = values[offset]
                        let entryPoint = values[offset + 1]
                        let backend = values[offset + 2]
                        offset <- offset + 3

                        TraefikValidation.validateHost host
                        TraefikValidation.validateUri "backend" backend [ "http"; "https" ]
                        if not (Set.contains entryPoint entryPointNames) then
                            invalidArg "router" "A router must reference a declared entry point."

                        let tls =
                            match router.Tls with
                            | TraefikTlsMode.NoTls -> { Kind = "none"; Name = "" }
                            | TraefikTlsMode.Acme resolver ->
                                if not (Set.contains resolver.Name resolverNames) then
                                    invalidArg "router" "An ACME TLS router must reference a declared resolver."
                                { Kind = "acme"; Name = resolver.Name }
                            | TraefikTlsMode.Provided certificate ->
                                if not (Set.contains certificate.Name certificateNames) then
                                    invalidArg "router" "A provided TLS router must reference a declared certificate."
                                { Kind = "provided"; Name = certificate.Name }

                        router.Name,
                        { Host = host
                          EntryPoint = entryPoint
                          Backend = backend
                          Tls = tls })
                TraefikOutput.immutableDictionary resolved)

        let certificateInputs = certificates |> List.collect TraefikOutput.certificateInputs
        let certificateInputValues = TraefikOutput.outputValues certificateInputs
        let certificateMapOutput =
            certificateInputValues.Apply<ImmutableDictionary<string, NormalizedCertificate>>(
                Func<ImmutableArray<string>, Task<ImmutableDictionary<string, NormalizedCertificate>>>(fun values ->
                    task {
                        try
                            let mutable offset = 0
                            let consumeInput () =
                                let value = values[offset]
                                offset <- offset + 1
                                value

                            let normalizedCertificates = ResizeArray<NormalizedCertificate>()
                            for declaration in certificates do
                                match declaration.Definition with
                                | CertificateDefinition.PemCertificateMaterial(chainSource, keySource, passwordInput) ->
                                    let! chainBytes = TraefikOutput.resolveContent cancellationToken consumeInput chainSource
                                    let! keyBytes = TraefikOutput.resolveContent cancellationToken consumeInput keySource
                                    let password = passwordInput |> Option.map (fun _ -> consumeInput ())
                                    let chain = System.Text.Encoding.UTF8.GetString(chainBytes)
                                    let key = System.Text.Encoding.UTF8.GetString(keyBytes)
                                    normalizedCertificates.Add(CertificateMaterial.normalizePem declaration.Name chain key password)
                                | CertificateDefinition.Pkcs12CertificateMaterial(bundleSource, passwordInput) ->
                                    let! bundleBytes = TraefikOutput.resolveContent cancellationToken consumeInput bundleSource
                                    let password = passwordInput |> Option.map (fun _ -> consumeInput ())
                                    normalizedCertificates.Add(CertificateMaterial.normalizePkcs12 declaration.Name bundleBytes password)

                            let normalizedCertificates = normalizedCertificates |> Seq.toList
                            CertificateMaterial.validateNormalizedCertificates normalizedCertificates
                            return
                                normalizedCertificates
                                |> Seq.map (fun certificate -> certificate.Name, certificate)
                                |> TraefikOutput.immutableDictionary
                        with
                        | :? OperationCanceledException when cancellationToken.IsCancellationRequested -> return raise (OperationCanceledException cancellationToken)
                        | _ -> return raise (InvalidOperationException("Certificate validation failed."))
                    })
            )

        let certificateValuesOutput =
            Output.CreateSecret<ImmutableDictionary<string, NormalizedCertificate>>(certificateMapOutput)

        let mutable routerIndex = 0
        let providedRouters =
            routers
            |> List.choose (fun router ->
                let index = routerIndex
                routerIndex <- routerIndex + 1
                match router.Tls with
                | TraefikTlsMode.Provided certificate ->
                    let firstInput = index * 3
                    let hostOutput = routerInputs |> List.item firstInput |> TraefikOutput.outputOfInput
                    Some(hostOutput.Apply(Func<string, string * string * string>(fun host -> router.Name, host, certificate.Name)))
                | _ -> None)

        let certificatesOutput =
            if List.isEmpty providedRouters then
                certificateValuesOutput
            else
                let providedRoutersOutput = Output.All<string * string * string>(providedRouters)
                let validate = Func<struct (ImmutableDictionary<string, NormalizedCertificate> * ImmutableArray<string * string * string>), ImmutableDictionary<string, NormalizedCertificate>>(fun values ->
                    let struct (certificates, routerExpectations) = values
                    TraefikCertificateValidation.validateRouterCertificateCoverage routerExpectations certificates.Values
                    certificates)
                let validatedCertificateMapOutput =
                    Output.Tuple(certificateValuesOutput, providedRoutersOutput).Apply(validate)
                Output.CreateSecret<ImmutableDictionary<string, NormalizedCertificate>>(validatedCertificateMapOutput)

        { EntryPoints = entryPointMap
          Resolvers = resolversOutput
          Routers = routersOutput
          Certificates = certificatesOutput
          AdminPort = adminPort }
[<RequireQualifiedAccess>]
module TraefikSpec =
    /// Resolves deferred certificate content and Pulumi outputs without dropping metadata.
    let resolve (cancellationToken: CancellationToken) (spec: TraefikSpec) = spec.Resolve cancellationToken
[<RequireQualifiedAccess>]
type TraefikRootPart =
    | AdminPort of int
[<Sealed>]
type TraefikBuilder() =
    member _.Yield(declaration: TraefikDeclaration) = [ declaration ]
    member _.Yield(entryPoint: EntryPointDefinition) = [ TraefikDeclaration.EntryPoint entryPoint ]
    member _.Yield(router: RouterDefinition) = [ TraefikDeclaration.Router router ]
    member _.Yield(resolver: TraefikAcmeResolverSpec) = [ TraefikDeclaration.Resolver resolver ]
    member _.Yield(certificate: TraefikCertificateSpec) = [ TraefikDeclaration.Certificate certificate ]
    member _.YieldFrom(declarations: seq<TraefikDeclaration>) = Seq.toList declarations
    member _.YieldFrom(entryPoints: seq<EntryPointDefinition>) = entryPoints |> Seq.map TraefikDeclaration.EntryPoint |> Seq.toList
    member _.YieldFrom(routers: seq<RouterDefinition>) = routers |> Seq.map TraefikDeclaration.Router |> Seq.toList
    member _.YieldFrom(resolvers: seq<TraefikAcmeResolverSpec>) = resolvers |> Seq.map TraefikDeclaration.Resolver |> Seq.toList
    member _.YieldFrom(certificates: seq<TraefikCertificateSpec>) = certificates |> Seq.map TraefikDeclaration.Certificate |> Seq.toList
    member _.Yield(part: TraefikRootPart) = [ TraefikDeclaration.AdminPort(match part with TraefikRootPart.AdminPort port -> port) ]
    member _.Zero() = []
    member _.Combine(left: TraefikDeclaration list, right: TraefikDeclaration list) = left @ right
    member _.Delay(generator: unit -> TraefikDeclaration list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> TraefikDeclaration list) = values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: TraefikDeclaration list) =
        let entryPoints = declarations |> List.choose (function TraefikDeclaration.EntryPoint value -> Some value | _ -> None)
        let routers = declarations |> List.choose (function TraefikDeclaration.Router value -> Some value | _ -> None)
        let resolvers = declarations |> List.choose (function TraefikDeclaration.Resolver value -> Some value | _ -> None)
        let certificates = declarations |> List.choose (function TraefikDeclaration.Certificate value -> Some value | _ -> None)
        let adminPorts = declarations |> List.choose (function TraefikDeclaration.AdminPort value -> Some value | _ -> None)

        for entryPoint in entryPoints do
            TraefikValidation.validateNameWithReserved "entryPoint" [ "keroosha-admin"; "traefik" ] entryPoint.Name
        for router in routers do
            TraefikValidation.validateNameWithReserved "router" [ "keroosha-admin" ] router.Name
        for resolver in resolvers do TraefikValidation.validateName "acmeResolver" resolver.Name
        for certificate in certificates do TraefikValidation.validateName "certificate" certificate.Name
        let validateUnique fieldName (values: seq<string>) =
            let seen = System.Collections.Generic.HashSet<string>(StringComparer.Ordinal)
            for value in values do
                if String.IsNullOrWhiteSpace value || (value |> Seq.exists Char.IsControl) || not (seen.Add value) then
                    invalidArg "traefik" (sprintf "Traefik %s names must be non-empty and unique." fieldName)

        validateUnique "entryPoint" (entryPoints |> Seq.map (fun item -> item.Name))
        validateUnique "router" (routers |> Seq.map (fun item -> item.Name))
        validateUnique "resolver" (resolvers |> Seq.map (fun item -> item.Name))
        validateUnique "certificate" (certificates |> Seq.map (fun certificate -> certificate.Name))

        if entryPoints.IsEmpty then invalidArg "traefik" "At least one entry point is required."
        if adminPorts.Length > 1 then invalidArg "traefik" "Admin port may be declared only once."

        let listenPorts = entryPoints |> List.map (fun entryPoint -> entryPoint.Listen)
        if (listenPorts |> List.distinct |> List.length) <> listenPorts.Length then
            invalidArg "traefik" "Entry point listen ports must be unique."
        let adminPort = adminPorts |> List.tryHead |> Option.defaultValue 19080
        if adminPort < 1 || adminPort > 65535 || (entryPoints |> List.exists (fun entryPoint -> entryPoint.Listen = adminPort)) then
            invalidArg "traefik" "The loopback admin port must be between 1 and 65535 and differ from entry-point listen ports."

        TraefikSpec(entryPoints, resolvers, routers, certificates, adminPort)





[<AbstractClass; Sealed>]
type TraefikFields private () =
    static member Host(value: string) = RouterPart.Host(LiteralString value)
    static member Host(value: Output<string>) = RouterPart.Host(OutputString value)
    static member Backend(value: string) = RouterPart.Backend(LiteralString value)
    static member Backend(value: Output<string>) = RouterPart.Backend(OutputString value)
    static member EntryPoint(value: string) =
        TraefikValidation.validateNameWithReserved "entryPoint" [ "keroosha-admin"; "traefik" ] value
        EntryPointBuilder(value)
    static member EntryPoint(value: Output<string>) = RouterPart.EntryPoint(OutputString value)
    static member Email(value: string) = ResolverPart.Email(LiteralString value)
    static member Email(value: Output<string>) = ResolverPart.Email(OutputString value)
    static member CaServer(value: string) = ResolverPart.CaServer(LiteralString value)
    static member CaServer(value: Output<string>) = ResolverPart.CaServer(OutputString value)
    static member Password(value: string) = CertificatePart.Password(LiteralString value)
    static member Password(value: Output<string>) = CertificatePart.Password(OutputString value)


[<AutoOpen>]
module TraefikBuilders =
    let entryPoint (name: string) = TraefikFields.EntryPoint(name)
    let entryPointOutput (name: Output<string>) = TraefikFields.EntryPoint(name)

    /// Sets the TCP listen port for an entry point.
    let listen port = EntryPointPart.Listen port

    /// Begins a named host router declaration.
    let router name =
        TraefikValidation.validateNameWithReserved "router" [ "keroosha-admin" ] name
        RouterBuilder(name)

    /// Sets a router's Host rule value.
    let inline host (value: ^T) : RouterPart =
        ((^T or TraefikFields) : (static member Host : ^T -> RouterPart) value)

    /// Sets a router's backend server URL.
    let inline backend (value: ^T) : RouterPart =
        ((^T or TraefikFields) : (static member Backend : ^T -> RouterPart) value)

    /// Sets the router TLS mode.
    let tls mode = RouterPart.Tls mode

    /// Selects no router TLS.
    let noTls = TraefikTlsMode.NoTls


    /// Begins a named ACME resolver declaration.
    let acmeResolver name =
        TraefikValidation.validateName "acmeResolver" name
        AcmeResolverBuilder(name)

    /// Sets an ACME account email.
    let inline email (value: ^T) : ResolverPart =
        ((^T or TraefikFields) : (static member Email : ^T -> ResolverPart) value)

    /// Configures the HTTP-01 ACME challenge entry point.
    let challenge value = ResolverPart.Challenge value

    /// Configures an alternate ACME directory URL.
    let inline caServer (value: ^T) : ResolverPart =
        ((^T or TraefikFields) : (static member CaServer : ^T -> ResolverPart) value)

    /// Begins a PEM certificate and private-key declaration.
    let pemCertificate name =
        TraefikValidation.validateName "pemCertificate" name
        PemCertificateBuilder(name)

    /// Begins a PKCS#12 bundle declaration.
    let pkcs12Certificate name =
        TraefikValidation.validateName "pkcs12Certificate" name
        Pkcs12CertificateBuilder(name)

    /// Sets a PEM certificate chain source.
    let chain content = CertificatePart.Chain content

    /// Sets a PEM private-key source.
    let privateKey content = CertificatePart.PrivateKey content

    /// Sets a PKCS#12 bundle source.
    let bundle content = CertificatePart.Bundle content

    /// Supplies an optional decryption password; it is used only by local validation.
    let inline password (value: ^T) : CertificatePart =
        ((^T or TraefikFields) : (static member Password : ^T -> CertificatePart) value)

    /// Sets the loopback-only API/admin listener port (defaults to 19080).
    let adminPort port = TraefikRootPart.AdminPort port

    /// Collects entry points, ACME resolvers, routers, and certificates into a host Traefik spec.
    let traefik = TraefikBuilder()
