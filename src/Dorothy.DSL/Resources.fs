namespace Dorothy.DSL

open System
open System.Collections.Generic
open System.Collections.Immutable
open Pulumi

/// Typed arguments for the provider's SSH connection object.
type AptConnectionArgs() =
    inherit ResourceArgs()

    [<Input("address", true)>]
    member val Address: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("user", true)>]
    member val User: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("port")>]
    member val Port: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("identityFile")>]
    member val IdentityFile: Input<string> = Unchecked.defaultof<_> with get, set

/// Typed arguments for one requested package. An absent version means ensure presence without upgrading.
type AptPackageArgs() =
    inherit ResourceArgs()

    [<Input("version")>]
    member val Version: Input<string> = Unchecked.defaultof<_> with get, set

/// Native Pulumi arguments for keroosha:debian:AptPackageSet.
type AptPackageSetArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("packages", true)>]
    member val Packages: InputMap<AptPackageArgs> = InputMap<AptPackageArgs>() with get, set

/// Ensures the shared Docker daemon and SSH-user access after APT installs Docker.
type DockerEngineArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

/// Native Pulumi arguments for keroosha:debian:Swapfile.
type SwapfileArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("path", true)>]
    member val Path: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("sizeMiB", true)>]
    member val SizeMiB: Input<int> = Unchecked.defaultof<_> with get, set

/// Native Pulumi arguments for keroosha:debian:Ufw.
type UfwArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("rules", true)>]
    member val Rules: InputList<InputList<string>> = InputList<InputList<string>>() with get, set

    [<Input("enabled", true)>]
    member val Enabled: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("defaultIn", true)>]
    member val DefaultIn: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("defaultOut", true)>]
    member val DefaultOut: Input<string> = Unchecked.defaultof<_> with get, set
/// Native Pulumi arguments for keroosha:debian:SshdConfig.
type SshdConfigArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("settings", true)>]
    member val Settings: InputMap<string> = InputMap<string>() with get, set

/// Native Pulumi arguments for keroosha:debian:Fail2BanSshd.
type Fail2BanSshdArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("enabled", true)>]
    member val Enabled: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("maxRetry", true)>]
    member val MaxRetry: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("findTimeSeconds", true)>]
    member val FindTimeSeconds: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("banTimeSeconds", true)>]
    member val BanTimeSeconds: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("ignoreIps", true)>]
    member val IgnoreIps: InputList<string> = InputList<string>() with get, set

    [<Input("ports")>]
    member val Ports: InputList<int> = InputList<int>() with get, set


/// Resolver fields accepted by the native Traefik provider.
type TraefikResolverArgs() =
    inherit ResourceArgs()

    [<Input("email", true)>]
    member val Email: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("httpChallengeEntryPoint", true)>]
    member val HttpChallengeEntryPoint: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("caServer", true)>]
    member val CaServer: Input<string> = Unchecked.defaultof<_> with get, set

/// Router TLS declaration accepted by the native Traefik provider.
type TraefikRouterTlsArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("name", true)>]
    member val Name: Input<string> = Unchecked.defaultof<_> with get, set

/// Redirect target fields accepted by the native Traefik provider.
type TraefikRouterRedirectArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("origin", true)>]
    member val Origin: Input<string> = Unchecked.defaultof<_> with get, set

/// Router fields accepted by the native Traefik provider.
type TraefikRouterArgs() =
    inherit ResourceArgs()

    [<Input("host", true)>]
    member val Host: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("entryPoint", true)>]
    member val EntryPoint: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("backend")>]
    member val Backend: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("redirect")>]
    member val Redirect: Input<TraefikRouterRedirectArgs> = Unchecked.defaultof<_> with get, set

    [<Input("tls", true)>]
    member val Tls: Input<TraefikRouterTlsArgs> = Unchecked.defaultof<_> with get, set
/// Normalized certificate fields accepted by the native Traefik provider.
type TraefikCertificateArgs() =
    inherit ResourceArgs()

    [<Input("certificatePem", true)>]
    member val CertificatePem: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("privateKeyPem", true)>]
    member val PrivateKeyPem: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("fingerprint", true)>]
    member val Fingerprint: Input<string> = Unchecked.defaultof<_> with get, set


/// Native Pulumi arguments for keroosha:debian:Traefik.
type TraefikArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("entryPoints", true)>]
    member val EntryPoints: InputMap<int> = InputMap<int>() with get, set

    [<Input("resolvers", true)>]
    member val Resolvers: InputMap<TraefikResolverArgs> = InputMap<TraefikResolverArgs>() with get, set

    [<Input("routers", true)>]
    member val Routers: InputMap<TraefikRouterArgs> = InputMap<TraefikRouterArgs>() with get, set

    [<Input("certificates", true)>]
    member val Certificates: InputMap<TraefikCertificateArgs> = InputMap<TraefikCertificateArgs>() with get, set

    [<Input("adminPort")>]
    member val AdminPort: Input<int> = Unchecked.defaultof<_> with get, set

/// Native output DTO for one resolver.
[<OutputType>]
type TraefikResolverOutput [<OutputConstructor>] (email: string, httpChallengeEntryPoint: string, caServer: string) =
    member _.Email = email
    member _.HttpChallengeEntryPoint = httpChallengeEntryPoint
    member _.CaServer = caServer

/// Native output DTO for router TLS selection.
[<OutputType>]
type TraefikRouterTlsOutput [<OutputConstructor>] (kind: string, name: string) =
    member _.Kind = kind
    member _.Name = name

/// Native output DTO for one redirect target.
[<OutputType>]
type TraefikRouterRedirectOutput [<OutputConstructor>] (kind: string, origin: string) =
    member _.Kind = kind
    member _.Origin = origin

/// Native output DTO for one router.
[<OutputType>]
type TraefikRouterOutput [<OutputConstructor>] (
    host: string,
    entryPoint: string,
    backend: string,
    redirect: TraefikRouterRedirectOutput,
    tls: TraefikRouterTlsOutput
) =
    member _.Host = host
    member _.EntryPoint = entryPoint
    member _.Backend = backend
    member _.Redirect = redirect
    member _.Tls = tls

/// Native output DTO for one normalized certificate; the map key carries its name.
[<OutputType>]
type TraefikCertificateOutput [<OutputConstructor>] (certificatePem: string, privateKeyPem: string, fingerprint: string) =
    member _.CertificatePem = certificatePem
    member _.PrivateKeyPem = privateKeyPem
    member _.Fingerprint = fingerprint



module private ProviderContract =
    [<Literal>]
    let ResourceToken = "keroosha:debian:AptPackageSet"

    [<Literal>]
    let PackageVersion = "0.1.0"
    [<Literal>]
    let UfwResourceToken = "keroosha:debian:Ufw"

    [<Literal>]
    let TraefikResourceToken = "keroosha:debian:Traefik"

    [<Literal>]
    let DockerEngineResourceToken = "keroosha:debian:DockerEngine"

    [<Literal>]
    let SwapfileResourceToken = "keroosha:debian:Swapfile"

    [<Literal>]
    let SshdConfigResourceToken = "keroosha:debian:SshdConfig"

    [<Literal>]
    let Fail2BanSshdResourceToken = "keroosha:debian:Fail2BanSshd"


    let resourceOptions () =
        let options = CustomResourceOptions()
        options.Version <- PackageVersion
        options

    let resourceOptionsWithDependencies (dependencies: Resource list) =
        let options = resourceOptions ()
        options.DependsOn <- InputList<Resource>.op_Implicit (dependencies |> List.toArray)
        options

/// A non-destructive shared host prerequisite; deletion retains the daemon and group membership.
type DockerEngine(name: string, args: DockerEngineArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.DockerEngineResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value


/// Manages one owned swap file and its persistent systemd swap unit.
type Swapfile(name: string, args: SwapfileArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.SwapfileResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    new(name: string, args: SwapfileArgs) =
        Swapfile(name, args, ProviderContract.resourceOptions ())

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value
/// Manages the owned APT package set on one SSH host.
type AptPackageSet(name: string, args: AptPackageSetArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.ResourceToken, name, args, options)

    // Pulumi initializes outputs in its base constructor. DefaultValue avoids
    // F# auto-property initializers overwriting those outputs after base returns.
    [<DefaultValue>]
    val mutable private installedVersions: Output<ImmutableDictionary<string, string>>

    [<DefaultValue>]
    val mutable private managedPackages: Output<ImmutableArray<string>>

    new(name: string, args: AptPackageSetArgs) =
        AptPackageSet(name, args, ProviderContract.resourceOptions ())

    [<Output("installedVersions")>]
    member this.InstalledVersions
        with get () = this.installedVersions
        and private set value = this.installedVersions <- value

    [<Output("managedPackages")>]
    member this.ManagedPackages
        with get () = this.managedPackages
        and private set value = this.managedPackages <- value

/// Manages the owned UFW firewall on one SSH host.
type UfwFirewall(name: string, args: UfwArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.UfwResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private rules: Output<ImmutableArray<ImmutableArray<string>>>

    [<DefaultValue>]
    val mutable private enabled: Output<bool>

    [<DefaultValue>]
    val mutable private defaultIn: Output<string>

    [<DefaultValue>]
    val mutable private defaultOut: Output<string>

    [<DefaultValue>]
    val mutable private actualRules: Output<ImmutableArray<string>>

    [<DefaultValue>]
    val mutable private actualEnabled: Output<bool>

    [<DefaultValue>]
    val mutable private actualDefaultIn: Output<string>

    [<DefaultValue>]
    val mutable private actualDefaultOut: Output<string>

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    new(name: string, args: UfwArgs) =
        UfwFirewall(name, args, ProviderContract.resourceOptions ())

    [<Output("rules")>]
    member this.Rules
        with get () = this.rules
        and private set value = this.rules <- value

    [<Output("enabled")>]
    member this.Enabled
        with get () = this.enabled
        and private set value = this.enabled <- value

    [<Output("defaultIn")>]
    member this.DefaultIn
        with get () = this.defaultIn
        and private set value = this.defaultIn <- value

    [<Output("defaultOut")>]
    member this.DefaultOut
        with get () = this.defaultOut
        and private set value = this.defaultOut <- value

    [<Output("actualRules")>]
    member this.ActualRules
        with get () = this.actualRules
        and private set value = this.actualRules <- value

    [<Output("actualEnabled")>]
    member this.ActualEnabled
        with get () = this.actualEnabled
        and private set value = this.actualEnabled <- value

    [<Output("actualDefaultIn")>]
    member this.ActualDefaultIn
        with get () = this.actualDefaultIn
        and private set value = this.actualDefaultIn <- value

    [<Output("actualDefaultOut")>]
    member this.ActualDefaultOut
        with get () = this.actualDefaultOut
        and private set value = this.actualDefaultOut <- value

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value

/// Manages only the explicitly declared sshd overrides on one SSH host.
type SshdConfigResource(name: string, args: SshdConfigArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.SshdConfigResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private settings: Output<ImmutableDictionary<string, string>>

    [<DefaultValue>]
    val mutable private owned: Output<bool>

    [<DefaultValue>]
    val mutable private actualSettings: Output<ImmutableDictionary<string, string>>

    [<DefaultValue>]
    val mutable private ports: Output<ImmutableArray<int>>

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    new(name: string, args: SshdConfigArgs) =
        SshdConfigResource(name, args, ProviderContract.resourceOptions ())

    [<Output("settings")>]
    member this.Settings
        with get () = this.settings
        and private set value = this.settings <- value

    [<Output("owned")>]
    member this.Owned
        with get () = this.owned
        and private set value = this.owned <- value

    [<Output("actualSettings")>]
    member this.ActualSettings
        with get () = this.actualSettings
        and private set value = this.actualSettings <- value

    [<Output("ports")>]
    member this.Ports
        with get () = this.ports
        and private set value = this.ports <- value

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value

/// Manages the Fail2Ban sshd jail independently from sshd's own configuration.
type Fail2BanSshd(name: string, args: Fail2BanSshdArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.Fail2BanSshdResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private enabled: Output<bool>

    [<DefaultValue>]
    val mutable private maxRetry: Output<int>

    [<DefaultValue>]
    val mutable private findTimeSeconds: Output<int>

    [<DefaultValue>]
    val mutable private banTimeSeconds: Output<int>

    [<DefaultValue>]
    val mutable private ignoreIps: Output<ImmutableArray<string>>

    [<DefaultValue>]
    val mutable private ports: Output<ImmutableArray<int>>

    [<DefaultValue>]
    val mutable private owned: Output<bool>

    [<DefaultValue>]
    val mutable private active: Output<bool>

    [<DefaultValue>]
    val mutable private actualPorts: Output<ImmutableArray<int>>

    [<DefaultValue>]
    val mutable private actualMaxRetry: Output<int>

    [<DefaultValue>]
    val mutable private actualFindTimeSeconds: Output<int>

    [<DefaultValue>]
    val mutable private actualBanTimeSeconds: Output<int>

    [<DefaultValue>]
    val mutable private actualIgnoreIps: Output<ImmutableArray<string>>

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    new(name: string, args: Fail2BanSshdArgs) =
        Fail2BanSshd(name, args, ProviderContract.resourceOptions ())

    [<Output("enabled")>]
    member this.Enabled
        with get () = this.enabled
        and private set value = this.enabled <- value

    [<Output("maxRetry")>]
    member this.MaxRetry
        with get () = this.maxRetry
        and private set value = this.maxRetry <- value

    [<Output("findTimeSeconds")>]
    member this.FindTimeSeconds
        with get () = this.findTimeSeconds
        and private set value = this.findTimeSeconds <- value

    [<Output("banTimeSeconds")>]
    member this.BanTimeSeconds
        with get () = this.banTimeSeconds
        and private set value = this.banTimeSeconds <- value

    [<Output("ignoreIps")>]
    member this.IgnoreIps
        with get () = this.ignoreIps
        and private set value = this.ignoreIps <- value

    [<Output("ports")>]
    member this.Ports
        with get () = this.ports
        and private set value = this.ports <- value
    [<Output("owned")>]
    member this.Owned
        with get () = this.owned
        and private set value = this.owned <- value

    [<Output("active")>]
    member this.Active
        with get () = this.active
        and private set value = this.active <- value

    [<Output("actualPorts")>]
    member this.ActualPorts
        with get () = this.actualPorts
        and private set value = this.actualPorts <- value

    [<Output("actualMaxRetry")>]
    member this.ActualMaxRetry
        with get () = this.actualMaxRetry
        and private set value = this.actualMaxRetry <- value

    [<Output("actualFindTimeSeconds")>]
    member this.ActualFindTimeSeconds
        with get () = this.actualFindTimeSeconds
        and private set value = this.actualFindTimeSeconds <- value

    [<Output("actualBanTimeSeconds")>]
    member this.ActualBanTimeSeconds
        with get () = this.actualBanTimeSeconds
        and private set value = this.actualBanTimeSeconds <- value

    [<Output("actualIgnoreIps")>]
    member this.ActualIgnoreIps
        with get () = this.actualIgnoreIps
        and private set value = this.actualIgnoreIps <- value

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value

/// Manages the dedicated native Traefik service and its file-provider configuration on one SSH host.
type TraefikInstance(name: string, args: TraefikArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.TraefikResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private entryPoints: Output<ImmutableDictionary<string, int>>

    [<DefaultValue>]
    val mutable private resolvers: Output<ImmutableDictionary<string, TraefikResolverOutput>>

    [<DefaultValue>]
    val mutable private routers: Output<ImmutableDictionary<string, TraefikRouterOutput>>

    [<DefaultValue>]
    val mutable private certificates: Output<ImmutableDictionary<string, TraefikCertificateOutput>>
    [<DefaultValue>]
    val mutable private adminPort: Output<int>

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    [<DefaultValue>]
    val mutable private actualConfigHash: Output<string>

    [<DefaultValue>]
    val mutable private certificateFingerprints: Output<ImmutableDictionary<string, string>>

    new(name: string, args: TraefikArgs) =
        TraefikInstance(name, args, ProviderContract.resourceOptions ())

    [<Output("entryPoints")>]
    member this.EntryPoints
        with get () = this.entryPoints
        and private set value = this.entryPoints <- value

    [<Output("resolvers")>]
    member this.Resolvers
        with get () = this.resolvers
        and private set value = this.resolvers <- value

    [<Output("routers")>]
    member this.Routers
        with get () = this.routers
        and private set value = this.routers <- value

    [<Output("certificates")>]
    member this.Certificates
        with get () = this.certificates
        and private set value = this.certificates <- value

    [<Output("adminPort")>]
    member this.AdminPort
        with get () = this.adminPort
        and private set value = this.adminPort <- value

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value

    [<Output("actualConfigHash")>]
    member this.ActualConfigHash
        with get () = this.actualConfigHash
        and private set value = this.actualConfigHash <- value

    [<Output("certificateFingerprints")>]
    member this.CertificateFingerprints
        with get () = this.certificateFingerprints
        and private set value = this.certificateFingerprints <- value

module private TraefikResourceMappings =
    let private mapImmutableOutput
        (source: Output<ImmutableDictionary<string, 'T>>)
        (convert: 'T -> 'U)
        : Output<ImmutableDictionary<string, 'U>> =
        source.Apply(Func<ImmutableDictionary<string, 'T>, ImmutableDictionary<string, 'U>>(fun values ->
            let builder = ImmutableDictionary.CreateBuilder<string, 'U>(StringComparer.Ordinal)
            for KeyValue(key, value) in values do
                builder.Add(key, convert value)
            builder.ToImmutable()))

    let resolver (value: TraefikResolver) =
        let args = TraefikResolverArgs()
        args.Email <- Input<string>.op_Implicit value.Email
        args.HttpChallengeEntryPoint <- Input<string>.op_Implicit value.HttpChallengeEntryPoint
        args.CaServer <- Input<string>.op_Implicit value.CaServer
        args

    let router (value: TraefikRouter) =
        let tls = TraefikRouterTlsArgs()
        tls.Kind <- Input<string>.op_Implicit value.Tls.Kind
        tls.Name <- Input<string>.op_Implicit value.Tls.Name
        let args = TraefikRouterArgs()
        args.Host <- Input<string>.op_Implicit value.Host
        args.EntryPoint <- Input<string>.op_Implicit value.EntryPoint
        match value.Target with
        | TraefikRouterTarget.Backend backend ->
            args.Backend <- Input<string>.op_Implicit backend
        | TraefikRouterTarget.PermanentToOrigin origin ->
            let redirect = TraefikRouterRedirectArgs()
            redirect.Kind <- Input<string>.op_Implicit "permanentToOrigin"
            redirect.Origin <- Input<string>.op_Implicit origin
            args.Redirect <- Input<TraefikRouterRedirectArgs>.op_Implicit redirect
        args.Tls <- Input<TraefikRouterTlsArgs>.op_Implicit tls
        args

    let certificate (value: NormalizedCertificate) =
        let args = TraefikCertificateArgs()
        args.CertificatePem <- Input<string>.op_Implicit value.CertificatePem
        args.PrivateKeyPem <- Input<string>.op_Implicit value.PrivateKeyPem
        args.Fingerprint <- Input<string>.op_Implicit value.Fingerprint
        args

    let resolvers values = mapImmutableOutput values resolver
    let routers values = mapImmutableOutput values router
    let certificates values = mapImmutableOutput values certificate
module Host =
    let deploy (host: HostSpec) =
        DomainValidation.validateHostSpec host

        let connection = AptConnectionArgs()
        connection.Address <- Input<string>.op_Implicit host.Address
        connection.User <- Input<string>.op_Implicit host.User
        connection.Port <- Input<int>.op_Implicit host.Port
        host.IdentityFile
        |> Option.iter (fun identityFile -> connection.IdentityFile <- Input<string>.op_Implicit identityFile)

        let createAptPackageSet (name: string) (packageMap: Map<string, string option>) (dependencies: Resource list) retainOnDelete =
            let packages = Dictionary<string, AptPackageArgs>()
            for KeyValue(packageName, version) in packageMap do
                let package = AptPackageArgs()
                version |> Option.iter (fun value -> package.Version <- Input<string>.op_Implicit value)
                packages.Add(packageName, package)

            let args = AptPackageSetArgs()
            args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
            args.Packages <- InputMap<AptPackageArgs>.op_Implicit packages
            let options =
                if List.isEmpty dependencies then
                    ProviderContract.resourceOptions ()
                else
                    ProviderContract.resourceOptionsWithDependencies dependencies
            options.RetainOnDelete <- Nullable retainOnDelete
            AptPackageSet(name, args, options)

        let mainPackages =
            let declared = Map.remove "ufw" host.Packages
            match host.Traefik with
            | Some _ ->
                // Only add runtime packages missing from the shared base prerequisites.
                [ "ca-certificates"; "openssl" ]
                |> List.fold (fun packages packageName ->
                    if Map.containsKey packageName packages then packages
                    else Map.add packageName None packages) declared
            | None -> declared
        let mainApt = createAptPackageSet host.Name mainPackages [] false

        let fail2banPackages =
            match host.Sshd with
            | Some specification when specification.Fail2Ban.IsSome ->
                [ "fail2ban"; "nftables" ]
                |> List.choose (fun packageName ->
                    // Explicit declarations remain owned by mainApt. Switching an existing package from
                    // explicit to implicit ownership has no automatic zero-gap handoff.
                    if Map.containsKey packageName host.Packages then
                        None
                    else
                        // Retain each implicit package independently so removing one prerequisite never
                        // shrinks another package owner's desired set.
                        Some(
                            createAptPackageSet
                                (host.Name + "-" + packageName + "-package")
                                (Map.ofList [ packageName, None ])
                                [ mainApt :> Resource ]
                                true
                        ))
            | _ -> []

        let swapfilePackage =
            if host.Swapfile.IsSome && not (Map.containsKey "util-linux" host.Packages) then
                // Keep the helper's util-linux prerequisite installed after swapfile removal.
                Some(createAptPackageSet (host.Name + "-swapfile-package") (Map.ofList [ "util-linux", None ]) [ mainApt :> Resource ] true)
            else
                None

        match host.Swapfile with
        | Some specification ->
            let packageSet = defaultArg swapfilePackage mainApt
            let args = SwapfileArgs()
            args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
            args.Path <- Input<string>.op_Implicit specification.Path
            args.SizeMiB <- Input<int>.op_Implicit (int specification.Size)
            Swapfile(host.Name + "-swapfile", args, ProviderContract.resourceOptionsWithDependencies [ packageSet :> Resource ]) |> ignore
        | None -> ()

        let dockerPackage =
            if host.Docker.IsSome && not (Map.containsKey "docker.io" host.Packages) then
                // Explicit APT declarations keep their original owner and removal semantics.
                // An implicit Docker prerequisite is retained with the shared daemon.
                Some(createAptPackageSet (host.Name + "-docker-package") (Map.ofList [ "docker.io", None ]) [ mainApt :> Resource ] true)
            else
                None

        let dockerContainers =
            match host.Docker with
            | Some specification ->
                let packageSet = defaultArg dockerPackage mainApt
                let args = DockerEngineArgs()
                args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
                let engine = DockerEngine(host.Name, args, ProviderContract.resourceOptionsWithDependencies [ packageSet :> Resource ])
                DockerDeployment.deploy host engine specification
            | None -> []

        let firewallPackage =
            if host.Ufw.IsSome || Map.containsKey "ufw" host.Packages then
                let version = host.Packages |> Map.tryFind "ufw" |> Option.defaultValue None
                Some(createAptPackageSet (host.Name + "-ufw-package") (Map.ofList [ "ufw", version ]) [ mainApt :> Resource ] false)
            else
                None

        let firewallResource =
            match host.Ufw, firewallPackage with
            | Some firewall, Some packageSet ->
                let args = UfwArgs()
                args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
                let ruleInputs =
                    firewall.Rules
                    |> List.map (fun rule -> InputList<string>.op_Implicit (rule |> List.toArray))
                    |> List.toArray
                args.Rules <- InputList<InputList<string>>.op_Implicit ruleInputs
                args.Enabled <- Input<bool>.op_Implicit firewall.Enabled
                let policyToken = function
                    | UfwPolicy.Allow -> "allow"
                    | UfwPolicy.Deny -> "deny"
                    | UfwPolicy.Reject -> "reject"
                args.DefaultIn <- Input<string>.op_Implicit (policyToken firewall.DefaultIn)
                args.DefaultOut <- Input<string>.op_Implicit (policyToken firewall.DefaultOut)
                Some(UfwFirewall(host.Name, args, ProviderContract.resourceOptionsWithDependencies [ mainApt :> Resource; packageSet :> Resource ]))
            | None, _ -> None
            | Some _, None -> invalidOp "A UFW declaration must have its APT prerequisite resource."

        let sshdConfigResource =
            match host.Sshd |> Option.bind (fun specification -> specification.Config) with
            | Some specification ->
                let settings = Dictionary<string, string>(StringComparer.Ordinal)
                for KeyValue(keyword, value) in specification.Settings do
                    settings.Add(keyword, value)

                let args = SshdConfigArgs()
                args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
                args.Settings <- InputMap<string>.op_Implicit settings

                let options =
                    ProviderContract.resourceOptionsWithDependencies [ mainApt :> Resource ]
                Some(SshdConfigResource(host.Name + "-sshd-config", args, options))
            | None -> None

        match host.Sshd |> Option.bind (fun specification -> specification.Fail2Ban) with
        | Some specification ->
            let args = Fail2BanSshdArgs()
            args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
            args.Enabled <- Input<bool>.op_Implicit specification.Enabled
            args.MaxRetry <- Input<int>.op_Implicit specification.MaxRetry
            args.FindTimeSeconds <- Input<int>.op_Implicit specification.FindTimeSeconds
            args.BanTimeSeconds <- Input<int>.op_Implicit specification.BanTimeSeconds
            args.IgnoreIps <- InputList<string>.op_Implicit (specification.IgnoreIps |> List.toArray)

            args.Ports <-
                match sshdConfigResource with
                | Some resource -> InputList<int>.op_Implicit resource.Ports
                | None -> InputList<int>.op_Implicit (Array.empty<int>)

            let dependencies =
                [ mainApt :> Resource ]
                @ (fail2banPackages |> List.map (fun resource -> resource :> Resource))
                @ (sshdConfigResource |> Option.map (fun resource -> resource :> Resource) |> Option.toList)
            let options = ProviderContract.resourceOptionsWithDependencies dependencies
            Fail2BanSshd(host.Name + "-fail2ban-sshd", args, options) |> ignore
        | None -> ()

        match host.Traefik with
        | Some specification ->
            let resolved = specification.Resolve(System.Threading.CancellationToken.None)
            let args = TraefikArgs()
            args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
            args.EntryPoints <- InputMap<int>.op_Implicit resolved.EntryPoints
            args.Resolvers <- InputMap<TraefikResolverArgs>.op_Implicit (TraefikResourceMappings.resolvers resolved.Resolvers)
            args.Routers <- InputMap<TraefikRouterArgs>.op_Implicit (TraefikResourceMappings.routers resolved.Routers)
            args.Certificates <- InputMap<TraefikCertificateArgs>.op_Implicit (TraefikResourceMappings.certificates resolved.Certificates)
            args.AdminPort <- Input<int>.op_Implicit resolved.AdminPort
            let dependencies =
                [ mainApt :> Resource ]
                @ (firewallPackage |> Option.map (fun resource -> resource :> Resource) |> Option.toList)
                @ (firewallResource |> Option.map (fun resource -> resource :> Resource) |> Option.toList)
                @ dockerContainers
            let options = ProviderContract.resourceOptionsWithDependencies dependencies
            TraefikInstance(host.Name, args, options) |> ignore
        | None -> ()

        mainApt
