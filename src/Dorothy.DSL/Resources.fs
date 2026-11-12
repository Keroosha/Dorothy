namespace Dorothy.DSL

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.Globalization
open Pulumi
open System.Text.Json

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


/// A user-group declaration passed to the native users provider.
type UserGroupArgs() =
    inherit ResourceArgs()

    [<Input("gid")>]
    member val Gid: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("kind")>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("existing")>]
    member val Existing: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("state")>]
    member val State: Input<string> = Unchecked.defaultof<_> with get, set

/// A primary group selection for one user.
type UserPrimaryGroupArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("name")>]
    member val Name: Input<string> = Unchecked.defaultof<_> with get, set

/// A managed or exclusive supplementary-group declaration.
type UserSupplementaryGroupsArgs() =
    inherit ResourceArgs()

    [<Input("mode", true)>]
    member val Mode: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("names", true)>]
    member val Names: InputList<string> = InputList<string>() with get, set

/// One requested home-directory lifecycle.
type UserHomeArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("path")>]
    member val Path: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("mode")>]
    member val Mode: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("skeleton")>]
    member val Skeleton: Input<string> = Unchecked.defaultof<_> with get, set

/// Locked or hashed password input. Hash remains an Input to preserve secrecy/dependencies.
type UserPasswordArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("hash")>]
    member val Hash: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("update")>]
    member val Update: Input<string> = Unchecked.defaultof<_> with get, set

/// Calendar-date account expiry.
type UserAccountExpiryArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("date")>]
    member val Date: Input<string> = Unchecked.defaultof<_> with get, set

/// Optional shadow password-aging policy.
type UserPasswordPolicyArgs() =
    inherit ResourceArgs()

    [<Input("minDays")>]
    member val MinDays: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("maxDays")>]
    member val MaxDays: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("warnDays")>]
    member val WarnDays: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("inactiveDays")>]
    member val InactiveDays: Input<int> = Unchecked.defaultof<_> with get, set

/// One subordinate UID or GID range.
type UserSubordinateIdRangeArgs() =
    inherit ResourceArgs()

    [<Input("start", true)>]
    member val Start: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("count", true)>]
    member val Count: Input<int> = Unchecked.defaultof<_> with get, set

/// One structured OpenSSH authorized key.
type UserAuthorizedKeyArgs() =
    inherit ResourceArgs()

    [<Input("id", true)>]
    member val Id: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("publicKey", true)>]
    member val PublicKey: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("comment")>]
    member val Comment: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("restrict")>]
    member val Restrict: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("allowPty")>]
    member val AllowPty: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("allowAgentForwarding")>]
    member val AllowAgentForwarding: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("allowPortForwarding")>]
    member val AllowPortForwarding: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("allowX11Forwarding")>]
    member val AllowX11Forwarding: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("allowUserRc")>]
    member val AllowUserRc: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("allowFrom")>]
    member val AllowFrom: InputList<string> = Unchecked.defaultof<_> with get, set

    [<Input("command")>]
    member val Command: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("expires")>]
    member val Expires: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("permitOpen")>]
    member val PermitOpen: InputList<string> = Unchecked.defaultof<_> with get, set

    [<Input("permitListen")>]
    member val PermitListen: InputList<string> = Unchecked.defaultof<_> with get, set

    [<Input("verifyRequired")>]
    member val VerifyRequired: Input<bool> = Unchecked.defaultof<_> with get, set

/// The complete managed or exclusive authorized-key collection.
type UserAuthorizedKeysArgs() =
    inherit ResourceArgs()

    [<Input("mode", true)>]
    member val Mode: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("keys", true)>]
    member val Keys: InputList<UserAuthorizedKeyArgs> = InputList<UserAuthorizedKeyArgs>() with get, set

/// Native input for one user; the map key supplies its stable account name.
type UserAccountArgs() =
    inherit ResourceArgs()

    [<Input("state")>]
    member val State: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("kind")>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("existing")>]
    member val Existing: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("uid")>]
    member val Uid: Input<int> = Unchecked.defaultof<_> with get, set

    [<Input("description")>]
    member val Description: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("primaryGroup")>]
    member val PrimaryGroup: Input<UserPrimaryGroupArgs> = Unchecked.defaultof<_> with get, set

    [<Input("supplementaryGroups")>]
    member val SupplementaryGroups: Input<UserSupplementaryGroupsArgs> = Unchecked.defaultof<_> with get, set

    [<Input("home")>]
    member val Home: Input<UserHomeArgs> = Unchecked.defaultof<_> with get, set

    [<Input("shell")>]
    member val Shell: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("password")>]
    member val Password: Input<UserPasswordArgs> = Unchecked.defaultof<_> with get, set

    [<Input("accountExpiry")>]
    member val AccountExpiry: Input<UserAccountExpiryArgs> = Unchecked.defaultof<_> with get, set

    [<Input("passwordPolicy")>]
    member val PasswordPolicy: Input<UserPasswordPolicyArgs> = Unchecked.defaultof<_> with get, set

    [<Input("subordinateUids")>]
    member val SubordinateUids: InputList<UserSubordinateIdRangeArgs> = Unchecked.defaultof<_> with get, set

    [<Input("subordinateGids")>]
    member val SubordinateGids: InputList<UserSubordinateIdRangeArgs> = Unchecked.defaultof<_> with get, set

    [<Input("onDelete")>]
    member val OnDelete: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("authorizedKeys")>]
    member val AuthorizedKeys: Input<UserAuthorizedKeysArgs> = Unchecked.defaultof<_> with get, set

/// Native input for the owned users resource.
type UsersArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("groups", true)>]
    member val Groups: InputMap<UserGroupArgs> = InputMap<UserGroupArgs>() with get, set

    [<Input("users", true)>]
    member val Users: InputMap<UserAccountArgs> = InputMap<UserAccountArgs>() with get, set

/// One sudo policy subject.
type SudoSubjectArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("name", true)>]
    member val Name: Input<string> = Unchecked.defaultof<_> with get, set

/// Run-as identity for one sudo grant.
type SudoRunAsArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("user")>]
    member val User: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("group")>]
    member val Group: Input<string> = Unchecked.defaultof<_> with get, set

/// Explicit sudo command argument restriction.
type SudoArgumentsArgs() =
    inherit ResourceArgs()

    [<Input("kind", true)>]
    member val Kind: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("value")>]
    member val Value: Input<string> = Unchecked.defaultof<_> with get, set

/// One sudo command path and argument restriction.
type SudoCommandArgs() =
    inherit ResourceArgs()

    [<Input("path", true)>]
    member val Path: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("arguments", true)>]
    member val Arguments: Input<SudoArgumentsArgs> = Unchecked.defaultof<_> with get, set

/// One named sudo grant; its map key supplies the native grant name.
type SudoGrantArgs() =
    inherit ResourceArgs()

    [<Input("subjects", true)>]
    member val Subjects: InputList<SudoSubjectArgs> = InputList<SudoSubjectArgs>() with get, set

    [<Input("runAs", true)>]
    member val RunAs: Input<SudoRunAsArgs> = Unchecked.defaultof<_> with get, set

    [<Input("authentication")>]
    member val Authentication: Input<string> = Unchecked.defaultof<_> with get, set

    [<Input("allCommands")>]
    member val AllCommands: Input<bool> = Unchecked.defaultof<_> with get, set

    [<Input("commands", true)>]
    member val Commands: InputList<SudoCommandArgs> = InputList<SudoCommandArgs>() with get, set

/// Native input for the owned sudo policy resource.
type SudoArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("grants", true)>]
    member val Grants: InputMap<SudoGrantArgs> = InputMap<SudoGrantArgs>() with get, set
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

/// Arguments shared by an independently owned firewalld zone or policy.
type FirewalldArgs() =
    inherit ResourceArgs()
    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set
    [<Input("configuration", true)>]
    member val Configuration: Input<string> = Unchecked.defaultof<_> with get, set

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

    [<Input("configuration", true)>]
    member val Configuration: Input<string> = Unchecked.defaultof<_> with get, set

/// Native Pulumi arguments for keroosha:debian:Fail2Ban.
type Fail2BanConfigurationArgs() =
    inherit ResourceArgs()

    [<Input("connection", true)>]
    member val Connection: Input<AptConnectionArgs> = Unchecked.defaultof<_> with get, set

    [<Input("files", true)>]
    member val Files: InputMap<string> = InputMap<string>() with get, set

    [<Input("manageSshdPorts")>]
    member val ManageSshdPorts: Input<bool> = Input<bool>.op_Implicit false with get, set

    [<Input("sshdPorts")>]
    member val SshdPorts: InputList<int> = InputList<int>.op_Implicit(Array.empty<int>) with get, set

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
type TraefikRouterOutput
    [<OutputConstructor>]
    (
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
type TraefikCertificateOutput [<OutputConstructor>] (certificatePem: string, privateKeyPem: string, fingerprint: string)
    =
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
    let UsersResourceToken = "keroosha:debian:Users"

    [<Literal>]
    let SudoResourceToken = "keroosha:debian:Sudo"

    [<Literal>]
    let SshdConfigResourceToken = "keroosha:debian:SshdConfig"

    [<Literal>]
    let Fail2BanResourceToken = "keroosha:debian:Fail2Ban"


    let resourceOptions () =
        let options = CustomResourceOptions()
        options.Version <- PackageVersion
        options

    let resourceOptionsWithDependencies (dependencies: Resource list) =
        let options = resourceOptions ()
        options.DependsOn <- InputList<Resource>.op_Implicit(dependencies |> List.toArray)
        options

/// Manages one complete firewalld permanent zone or policy.
type FirewalldResource(token: string, name: string, args: FirewalldArgs, options: CustomResourceOptions) =
    inherit CustomResource(token, name, args, options)
    [<DefaultValue>]
    val mutable private exists: Output<bool>
    [<DefaultValue>]
    val mutable private inSync: Output<bool>
    [<DefaultValue>]
    val mutable private actual: Output<string>
    [<Output("exists")>]
    member this.Exists
        with get () = this.exists
        and private set value = this.exists <- value
    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value
    [<Output("actual")>]
    member this.Actual
        with get () = this.actual
        and private set value = this.actual <- value

/// Manages the owned users and groups on one SSH host; deletion retains identities and revokes owned access.
type UsersResource(name: string, args: UsersArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.UsersResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private exists: Output<bool>

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    [<DefaultValue>]
    val mutable private actual: Output<JsonElement>

    new(name: string, args: UsersArgs) =
        UsersResource(name, args, ProviderContract.resourceOptions ())

    [<Output("exists")>]
    member this.Exists
        with get () = this.exists
        and private set value = this.exists <- value

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value

    [<Output("actual")>]
    member this.Actual
        with get () = this.actual
        and private set value = this.actual <- value

/// Manages one owned sudo policy file; deletion removes only its grants.
type SudoResource(name: string, args: SudoArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.SudoResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private exists: Output<bool>

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    [<DefaultValue>]
    val mutable private actual: Output<JsonElement>

    new(name: string, args: SudoArgs) =
        SudoResource(name, args, ProviderContract.resourceOptions ())

    [<Output("exists")>]
    member this.Exists
        with get () = this.exists
        and private set value = this.exists <- value

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value

    [<Output("actual")>]
    member this.Actual
        with get () = this.actual
        and private set value = this.actual <- value

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

    new(name: string, args: SwapfileArgs) = Swapfile(name, args, ProviderContract.resourceOptions ())

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

    new(name: string, args: AptPackageSetArgs) = AptPackageSet(name, args, ProviderContract.resourceOptions ())

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

    new(name: string, args: UfwArgs) = UfwFirewall(name, args, ProviderContract.resourceOptions ())

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

/// Manages the complete ordered native sshd configuration body on one SSH host.
type SshdConfigResource(name: string, args: SshdConfigArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.SshdConfigResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private configuration: Output<string>

    [<DefaultValue>]
    val mutable private owned: Output<bool>

    [<DefaultValue>]
    val mutable private actualConfiguration: Output<string>

    [<DefaultValue>]
    val mutable private actualConnectionConfiguration: Output<string>

    [<DefaultValue>]
    val mutable private ports: Output<ImmutableArray<int>>

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    new(name: string, args: SshdConfigArgs) = SshdConfigResource(name, args, ProviderContract.resourceOptions ())

    [<Output("configuration")>]
    member this.Configuration
        with get () = this.configuration
        and private set value = this.configuration <- value

    [<Output("owned")>]
    member this.Owned
        with get () = this.owned
        and private set value = this.owned <- value

    [<Output("actualConfiguration")>]
    member this.ActualConfiguration
        with get () = this.actualConfiguration
        and private set value = this.actualConfiguration <- value

    [<Output("actualConnectionConfiguration")>]
    member this.ActualConnectionConfiguration
        with get () = this.actualConnectionConfiguration
        and private set value = this.actualConnectionConfiguration <- value

    [<Output("ports")>]
    member this.Ports
        with get () = this.ports
        and private set value = this.ports <- value

    [<Output("inSync")>]
    member this.InSync
        with get () = this.inSync
        and private set value = this.inSync <- value

/// Manages caller-selected native Fail2Ban files and optional sshd-listener synchronization.
type Fail2BanConfiguration(name: string, args: Fail2BanConfigurationArgs, options: CustomResourceOptions) =
    inherit CustomResource(ProviderContract.Fail2BanResourceToken, name, args, options)

    [<DefaultValue>]
    val mutable private files: Output<ImmutableDictionary<string, string>>

    [<DefaultValue>]
    val mutable private manageSshdPorts: Output<bool>

    [<DefaultValue>]
    val mutable private sshdPorts: Output<ImmutableArray<int>>

    [<DefaultValue>]
    val mutable private owned: Output<bool>

    [<DefaultValue>]
    val mutable private actualFiles: Output<ImmutableDictionary<string, string>>

    [<DefaultValue>]
    val mutable private active: Output<bool>

    [<DefaultValue>]
    val mutable private activeJails: Output<ImmutableArray<string>>

    [<DefaultValue>]
    val mutable private socket: Output<string>

    [<DefaultValue>]
    val mutable private inSync: Output<bool>

    new(name: string, args: Fail2BanConfigurationArgs) =
        Fail2BanConfiguration(name, args, ProviderContract.resourceOptions ())

    [<Output("files")>]
    member this.Files
        with get () = this.files
        and private set value = this.files <- value

    [<Output("manageSshdPorts")>]
    member this.ManageSshdPorts
        with get () = this.manageSshdPorts
        and private set value = this.manageSshdPorts <- value

    [<Output("sshdPorts")>]
    member this.SshdPorts
        with get () = this.sshdPorts
        and private set value = this.sshdPorts <- value

    [<Output("owned")>]
    member this.Owned
        with get () = this.owned
        and private set value = this.owned <- value

    [<Output("actualFiles")>]
    member this.ActualFiles
        with get () = this.actualFiles
        and private set value = this.actualFiles <- value

    [<Output("active")>]
    member this.Active
        with get () = this.active
        and private set value = this.active <- value

    [<Output("activeJails")>]
    member this.ActiveJails
        with get () = this.activeJails
        and private set value = this.activeJails <- value

    [<Output("socket")>]
    member this.Socket
        with get () = this.socket
        and private set value = this.socket <- value

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

    new(name: string, args: TraefikArgs) = TraefikInstance(name, args, ProviderContract.resourceOptions ())

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
        source.Apply(
            Func<ImmutableDictionary<string, 'T>, ImmutableDictionary<string, 'U>>(fun values ->
                let builder = ImmutableDictionary.CreateBuilder<string, 'U>(StringComparer.Ordinal)

                for KeyValue(key, value) in values do
                    builder.Add(key, convert value)

                builder.ToImmutable())
        )

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
        | TraefikRouterTarget.Backend backend -> args.Backend <- Input<string>.op_Implicit backend
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

module internal AccessResourceMappings =
    let private input (value: 'T) : Input<'T> = Input<'T>.op_Implicit value
    let private identityString = Func<string, string>(fun value -> value)

    let private strings (values: string list) =
        InputList<string>.op_Implicit (values |> List.toArray)

    let private setOptional (setter: Input<'T> -> unit) (value: 'T option) =
        value |> Option.iter (fun item -> setter (input item))
    let formatUtcTimestamp (value: DateTimeOffset) =
        value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)

    let private identity = function
        | ExistingIdentity.Reject -> "reject"
        | ExistingIdentity.Adopt -> "adopt"

    let private state = function
        | UserState.Present -> "present"
        | UserState.Absent -> "absent"

    let private kind = function
        | UserKind.Human -> "human"
        | UserKind.System -> "system"

    let private group (specification: UserGroupSpec) =
        let args = UserGroupArgs()
        setOptional (fun value -> args.Gid <- value) specification.Gid
        specification.Kind |> Option.map kind |> setOptional (fun value -> args.Kind <- value)
        specification.Existing |> Option.map identity |> setOptional (fun value -> args.Existing <- value)
        specification.State |> Option.map state |> setOptional (fun value -> args.State <- value)
        args

    let private primaryGroup (value: PrimaryGroup) =
        let args = UserPrimaryGroupArgs()
        match value with
        | PrimaryGroup.PrivateGroup -> args.Kind <- input "private"
        | PrimaryGroup.ExistingGroup name ->
            args.Kind <- input "existing"
            args.Name <- input name
        args

    let private supplementaryGroups (value: SupplementaryGroups) =
        let mode, names =
            match value with
            | SupplementaryGroups.Managed names -> "managed", names
            | SupplementaryGroups.Exclusive names -> "exclusive", names
        let args = UserSupplementaryGroupsArgs()
        args.Mode <- input mode
        args.Names <- strings names
        args

    let private home (value: Home) =
        let args = UserHomeArgs()
        match value with
        | Home.Create(path, mode) ->
            args.Kind <- input "create"
            args.Path <- input path
            args.Mode <- input mode
        | Home.CreateWithSkeleton(path, mode, skeleton) ->
            args.Kind <- input "create"
            args.Path <- input path
            args.Mode <- input mode
            args.Skeleton <- input skeleton
        | Home.Existing path ->
            args.Kind <- input "existing"
            args.Path <- input path
        | Home.None -> args.Kind <- input "none"
        args

    let private password (specification: UserSpec) =
        let args = UserPasswordArgs()
        match specification.Password with
        | Some Password.Locked -> args.Kind <- input "locked"
        | Some (Password.Hash hash) ->
            args.Kind <- input "hash"
            let secretHash =
                InputExtensions.Apply<string, string>(hash, identityString)
                |> Output.CreateSecret<string>
            args.Hash <- Input<string>.op_Implicit secretHash
            let update =
                specification.PasswordUpdate
                |> Option.defaultValue PasswordUpdate.OnCreate
                |> function
                    | PasswordUpdate.Always -> "always"
                    | PasswordUpdate.OnCreate -> "onCreate"
            args.Update <- input update
        | None -> ()
        args

    let private accountExpiry (value: AccountExpiry) =
        let args = UserAccountExpiryArgs()
        match value with
        | AccountExpiry.Never -> args.Kind <- input "never"
        | AccountExpiry.On date ->
            args.Kind <- input "on"
            args.Date <- input (date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))
        args

    let private passwordPolicy (value: PasswordPolicySpec) =
        let args = UserPasswordPolicyArgs()
        setOptional (fun item -> args.MinDays <- item) value.MinDays
        setOptional (fun item -> args.MaxDays <- item) value.MaxDays
        setOptional (fun item -> args.WarnDays <- item) value.WarnDays
        setOptional (fun item -> args.InactiveDays <- item) value.InactiveDays
        args

    let private subordinateRange (value: SubordinateIdRange) =
        let args = UserSubordinateIdRangeArgs()
        args.Start <- input value.Start
        args.Count <- input value.Count
        args

    let authorizedKey (value: AuthorizedKeySpec) =
        let args = UserAuthorizedKeyArgs()
        args.Id <- input value.Id
        args.PublicKey <- input value.PublicKey
        setOptional (fun item -> args.Comment <- item) value.Comment
        setOptional (fun item -> args.Restrict <- item) value.Restrict
        setOptional (fun item -> args.AllowPty <- item) value.AllowPty
        setOptional (fun item -> args.AllowAgentForwarding <- item) value.AllowAgentForwarding
        setOptional (fun item -> args.AllowPortForwarding <- item) value.AllowPortForwarding
        setOptional (fun item -> args.AllowX11Forwarding <- item) value.AllowX11Forwarding
        setOptional (fun item -> args.AllowUserRc <- item) value.AllowUserRc
        value.AllowFrom |> Option.iter (fun names -> args.AllowFrom <- strings names)
        setOptional (fun item -> args.Command <- item) value.Command
        value.Expires
        |> Option.map formatUtcTimestamp
        |> setOptional (fun item -> args.Expires <- item)
        value.PermitOpen |> Option.iter (fun names -> args.PermitOpen <- strings names)
        value.PermitListen |> Option.iter (fun names -> args.PermitListen <- strings names)
        setOptional (fun item -> args.VerifyRequired <- item) value.VerifyRequired
        args

    let private authorizedKeys (value: AuthorizedKeysSpec) =
        let args = UserAuthorizedKeysArgs()
        args.Mode <-
            input (
                match value.Mode with
                | AuthorizedKeysMode.Managed -> "managed"
                | AuthorizedKeysMode.Exclusive -> "exclusive"
            )
        args.Keys <-
            value.Keys
            |> List.map authorizedKey
            |> List.toArray
            |> InputList<UserAuthorizedKeyArgs>.op_Implicit
        args

    let user (specification: UserSpec) =
        let args = UserAccountArgs()
        specification.State |> Option.map state |> setOptional (fun value -> args.State <- value)
        specification.Kind |> Option.map kind |> setOptional (fun value -> args.Kind <- value)
        specification.Existing |> Option.map identity |> setOptional (fun value -> args.Existing <- value)
        setOptional (fun value -> args.Uid <- value) specification.Uid
        setOptional (fun value -> args.Description <- value) specification.Description
        specification.PrimaryGroup
        |> Option.iter (primaryGroup >> input >> fun value -> args.PrimaryGroup <- value)
        specification.SupplementaryGroups
        |> Option.iter (supplementaryGroups >> input >> fun value -> args.SupplementaryGroups <- value)
        specification.Home |> Option.iter (home >> input >> fun value -> args.Home <- value)
        setOptional (fun value -> args.Shell <- value) specification.Shell
        specification.Password
        |> Option.iter (fun _ -> args.Password <- input (password specification))
        specification.AccountExpiry
        |> Option.iter (accountExpiry >> input >> fun value -> args.AccountExpiry <- value)
        specification.PasswordPolicy
        |> Option.iter (passwordPolicy >> input >> fun value -> args.PasswordPolicy <- value)
        specification.SubordinateUids
        |> Option.iter (fun ranges ->
            args.SubordinateUids <- ranges |> List.map subordinateRange |> List.toArray |> InputList<UserSubordinateIdRangeArgs>.op_Implicit)
        specification.SubordinateGids
        |> Option.iter (fun ranges ->
            args.SubordinateGids <- ranges |> List.map subordinateRange |> List.toArray |> InputList<UserSubordinateIdRangeArgs>.op_Implicit)
        specification.OnDelete
        |> Option.iter (function
            | UserDeleteBehavior.RetainIdentity -> args.OnDelete <- input "retainIdentity")
        specification.AuthorizedKeys
        |> Option.iter (authorizedKeys >> input >> fun value -> args.AuthorizedKeys <- value)
        args

    let users (specification: UsersSpec) =
        let groups = Dictionary<string, UserGroupArgs>(StringComparer.Ordinal)
        for KeyValue(name, value) in specification.Groups do groups.Add(name, group value)
        let users = Dictionary<string, UserAccountArgs>(StringComparer.Ordinal)
        for KeyValue(name, value) in specification.Users do users.Add(name, user value)
        groups, users

    let private sudoSubject (value: SudoSubject) =
        let args = SudoSubjectArgs()
        match value with
        | SudoSubject.User name ->
            args.Kind <- input "user"
            args.Name <- input name
        | SudoSubject.Group name ->
            args.Kind <- input "group"
            args.Name <- input name
        args

    let private sudoRunAs (value: SudoRunAs) =
        let args = SudoRunAsArgs()
        match value with
        | SudoRunAs.AllUsersAndGroups -> args.Kind <- input "all"
        | SudoRunAs.SpecificRunAs(user, group) ->
            args.Kind <- input "specific"
            args.User <- input user
            setOptional (fun item -> args.Group <- item) group
        args

    let private sudoArguments (value: SudoArguments) =
        let args = SudoArgumentsArgs()
        match value with
        | SudoArguments.NoArguments -> args.Kind <- input "none"
        | SudoArguments.Exact value ->
            args.Kind <- input "exact"
            args.Value <- input value
        | SudoArguments.AnyArguments -> args.Kind <- input "any"
        args

    let private sudoCommand (value: SudoCommandSpec) =
        let args = SudoCommandArgs()
        args.Path <- input value.Path
        args.Arguments <- sudoArguments value.Arguments |> input
        args

    let private sudoGrant (value: SudoGrantSpec) =
        let args = SudoGrantArgs()
        args.Subjects <-
            value.Subjects
            |> List.map sudoSubject
            |> List.toArray
            |> InputList<SudoSubjectArgs>.op_Implicit
        args.RunAs <- sudoRunAs value.RunAs |> input
        args.Authentication <-
            input (
                match value.Authentication with
                | SudoAuthentication.Required -> "required"
                | SudoAuthentication.Passwordless -> "passwordless"
            )
        args.AllCommands <- input value.AllCommands
        args.Commands <-
            value.Commands
            |> List.map sudoCommand
            |> List.toArray
            |> InputList<SudoCommandArgs>.op_Implicit
        args

    let sudo (specification: SudoSpec) =
        let grants = Dictionary<string, SudoGrantArgs>(StringComparer.Ordinal)
        for KeyValue(name, value) in specification.Grants do grants.Add(name, sudoGrant value)
        grants
module Host =
    let deploy (host: HostSpec) =
        DomainValidation.validateHostSpec host

        let connection = AptConnectionArgs()
        connection.Address <- Input<string>.op_Implicit host.Address
        connection.User <- Input<string>.op_Implicit host.User
        connection.Port <- Input<int>.op_Implicit host.Port

        host.IdentityFile
        |> Option.iter (fun identityFile -> connection.IdentityFile <- Input<string>.op_Implicit identityFile)

        let createAptPackageSet
            (name: string)
            (packageMap: Map<string, string option>)
            (dependencies: Resource list)
            retainOnDelete
            =
            let packages = Dictionary<string, AptPackageArgs>()

            for KeyValue(packageName, version) in packageMap do
                let package = AptPackageArgs()

                version
                |> Option.iter (fun value -> package.Version <- Input<string>.op_Implicit value)

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
            let declared = host.Packages |> Map.remove "ufw" |> Map.remove "firewalld"
            // Docker's maintainer script can start the daemon. Move even an explicitly
            // versioned docker.io into the ordered prerequisite when firewalld is declared.
            let declared =
                if host.Firewalld.IsSome && host.Docker.IsSome then Map.remove "docker.io" declared
                else declared

            match host.Traefik with
            | Some _ ->
                // Only add runtime packages missing from the shared base prerequisites.
                [ "ca-certificates"; "openssl" ]
                |> List.fold
                    (fun packages packageName ->
                        if Map.containsKey packageName packages then
                            packages
                        else
                            Map.add packageName None packages)
                    declared
            | None -> declared

        let mainApt = createAptPackageSet host.Name mainPackages [] false
        let firewalldPackage =
            if host.Firewalld.IsSome || Map.containsKey "firewalld" host.Packages then
                let version = host.Packages |> Map.tryFind "firewalld" |> Option.defaultValue None
                Some(createAptPackageSet (host.Name + "-firewalld-package") (Map.ofList [ "firewalld", version ]) [ mainApt :> Resource ] false)
            else None

        let fail2banPackages =
            if host.Fail2Ban.IsSome then
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
            else
                []

        let dockerPackage =
            if host.Docker.IsSome && (host.Firewalld.IsSome || not (Map.containsKey "docker.io" host.Packages)) then
                // firewalld must be running before Docker's first startup registers its zone.
                let version = host.Packages |> Map.tryFind "docker.io" |> Option.defaultValue None
                let dependencies =
                    [ mainApt :> Resource ]
                    @ (firewalldPackage |> Option.map (fun resource -> resource :> Resource) |> Option.toList)
                Some(createAptPackageSet (host.Name + "-docker-package") (Map.ofList [ "docker.io", version ]) dependencies true)
            else
                None
        let usersResource =
            host.Users
            |> Option.map (fun specification ->
                let groups, users = AccessResourceMappings.users specification
                let args = UsersArgs()
                args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
                args.Groups <- InputMap<UserGroupArgs>.op_Implicit groups
                args.Users <- InputMap<UserAccountArgs>.op_Implicit users
                let dependencies =
                    [ mainApt :> Resource ]
                    @ (dockerPackage |> Option.map (fun resource -> resource :> Resource) |> Option.toList)
                let options = ProviderContract.resourceOptionsWithDependencies dependencies
                UsersResource(host.Name + "-users", args, options))

        let sudoPackage =
            match host.Sudo with
            | None -> None
            | Some _ ->
                let prerequisiteResources =
                    [ mainApt :> Resource ]
                    @ (usersResource |> Option.map (fun resource -> resource :> Resource) |> Option.toList)
                let packageSet =
                    if Map.containsKey "sudo" host.Packages then
                        mainApt
                    else
                        // Keep sudo installed after the owned grants are removed.
                        createAptPackageSet
                            (host.Name + "-sudo-package")
                            (Map.ofList [ "sudo", None ])
                            prerequisiteResources
                            true
                Some packageSet

        match host.Sudo, sudoPackage with
        | Some specification, Some packageSet ->
            let args = SudoArgs()
            args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
            args.Grants <- InputMap<SudoGrantArgs>.op_Implicit (AccessResourceMappings.sudo specification)
            let dependencies =
                [ packageSet :> Resource ]
                @ (usersResource |> Option.map (fun resource -> resource :> Resource) |> Option.toList)
            let options = ProviderContract.resourceOptionsWithDependencies dependencies
            SudoResource(host.Name + "-sudo", args, options) |> ignore
        | None, None -> ()
        | _ -> invalidOp "A sudo declaration must have its APT prerequisite resource."

        let swapfilePackage =
            if host.Swapfile.IsSome && not (Map.containsKey "util-linux" host.Packages) then
                // Keep the helper's util-linux prerequisite installed after swapfile removal.
                Some(
                    createAptPackageSet
                        (host.Name + "-swapfile-package")
                        (Map.ofList [ "util-linux", None ])
                        [ mainApt :> Resource ]
                        true
                )
            else
                None

        match host.Swapfile with
        | Some specification ->
            let packageSet = defaultArg swapfilePackage mainApt
            let args = SwapfileArgs()
            args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
            args.Path <- Input<string>.op_Implicit specification.Path
            args.SizeMiB <- Input<int>.op_Implicit(int specification.Size)

            Swapfile(
                host.Name + "-swapfile",
                args,
                ProviderContract.resourceOptionsWithDependencies [ packageSet :> Resource ]
            )
            |> ignore
        | None -> ()



        let dockerEngine, dockerContainers =
            match host.Docker with
            | Some specification ->
                let packageSet = defaultArg dockerPackage mainApt
                let args = DockerEngineArgs()
                args.Connection <- Input<AptConnectionArgs>.op_Implicit connection

                let engine =
                    DockerEngine(
                        host.Name,
                        args,
                        ProviderContract.resourceOptionsWithDependencies [ packageSet :> Resource ]
                    )

                Some(engine :> Resource), DockerDeployment.deploy host engine specification
            | None -> None, []

        let firewallPackage =
            if host.Ufw.IsSome || Map.containsKey "ufw" host.Packages then
                let version = host.Packages |> Map.tryFind "ufw" |> Option.defaultValue None

                Some(
                    createAptPackageSet
                        (host.Name + "-ufw-package")
                        (Map.ofList [ "ufw", version ])
                        [ mainApt :> Resource ]
                        false
                )
            else
                None

        let firewallResource =
            match host.Ufw, firewallPackage with
            | Some firewall, Some packageSet ->
                let args = UfwArgs()
                args.Connection <- Input<AptConnectionArgs>.op_Implicit connection

                let ruleInputs =
                    firewall.Rules
                    |> List.map (fun rule -> InputList<string>.op_Implicit(rule |> List.toArray))
                    |> List.toArray

                args.Rules <- InputList<InputList<string>>.op_Implicit ruleInputs
                args.Enabled <- Input<bool>.op_Implicit firewall.Enabled

                let policyToken =
                    function
                    | UfwPolicy.Allow -> "allow"
                    | UfwPolicy.Deny -> "deny"
                    | UfwPolicy.Reject -> "reject"

                args.DefaultIn <- Input<string>.op_Implicit(policyToken firewall.DefaultIn)
                args.DefaultOut <- Input<string>.op_Implicit(policyToken firewall.DefaultOut)

                Some(
                    UfwFirewall(
                        host.Name,
                        args,
                        ProviderContract.resourceOptionsWithDependencies [ mainApt :> Resource; packageSet :> Resource ]
                    )
                )
            | None, _ -> None
            | Some _, None -> invalidOp "A UFW declaration must have its APT prerequisite resource."


        match host.Firewalld, firewalldPackage with
        | Some firewall, Some packageSet ->
            let zones = Collections.Generic.Dictionary<string, Resource>(StringComparer.Ordinal)
            let create (specification: FirewalldObjectSpec) dependencies =
                let args = FirewalldArgs()
                args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
                args.Configuration <- Input<string>.op_Implicit specification.Configuration
                let token = if specification.Kind = "zone" then "keroosha:debian:FirewalldZone" else "keroosha:debian:FirewalldPolicy"
                FirewalldResource(token, host.Name + "-firewalld-" + specification.Kind + "-" + specification.Name,
                                  args, ProviderContract.resourceOptionsWithDependencies dependencies) :> Resource
            // Zones are serialized so an interface transfer cannot race another managed zone.
            let mutable prior = packageSet :> Resource
            for specification in firewall.Objects |> List.filter (fun value -> value.Kind = "zone") do
                let resource = create specification [ prior ]
                zones.Add(specification.Name, resource)
                prior <- resource
            for specification in firewall.Objects |> List.filter (fun value -> value.Kind = "policy") do
                let referenced = specification.Value.Ingress @ specification.Value.Egress
                let dependencies =
                    referenced
                    |> List.choose (fun name -> match zones.TryGetValue name with true, resource -> Some resource | _ -> None)
                let referencesUnmanagedZone =
                    referenced |> List.exists (fun name -> name <> "ANY" && name <> "HOST" && not (zones.ContainsKey name))
                let ownerDependencies = if referencesUnmanagedZone then Option.toList dockerEngine else []
                // Missing unmanaged references still fail explicitly on hosts without Docker.
                create specification (prior :: dependencies @ ownerDependencies) |> ignore
        | _, None | None, _ -> ()

        let sshdConfigResource =
            match host.Sshd |> Option.bind (fun specification -> specification.Config) with
            | Some specification ->
                let args = SshdConfigArgs()
                args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
                args.Configuration <- Input<string>.op_Implicit specification.Configuration

                let options =
                    ProviderContract.resourceOptionsWithDependencies [ mainApt :> Resource ]

                Some(SshdConfigResource(host.Name + "-sshd-config", args, options))
            | None -> None

        match host.Fail2Ban with
        | Some specification ->
            let files = Dictionary<string, string>(StringComparer.Ordinal)

            for KeyValue(path, contents) in specification.Files do
                files.Add(path, contents)

            let args = Fail2BanConfigurationArgs()
            args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
            args.Files <- InputMap<string>.op_Implicit files
            args.ManageSshdPorts <- Input<bool>.op_Implicit specification.ManageSshdPorts

            args.SshdPorts <-
                if specification.ManageSshdPorts then
                    match sshdConfigResource with
                    | Some resource -> InputList<int>.op_Implicit resource.Ports
                    | None -> InputList<int>.op_Implicit(Array.empty<int>)
                else
                    InputList<int>.op_Implicit(Array.empty<int>)

            let dependencies =
                [ mainApt :> Resource ]
                @ (fail2banPackages |> List.map (fun resource -> resource :> Resource))
                @ (if specification.ManageSshdPorts then
                       sshdConfigResource
                       |> Option.map (fun resource -> resource :> Resource)
                       |> Option.toList
                   else
                       [])

            let options = ProviderContract.resourceOptionsWithDependencies dependencies
            Fail2BanConfiguration(host.Name + "-fail2ban", args, options) |> ignore
        | None -> ()

        match host.Traefik with
        | Some specification ->
            let resolved = specification.Resolve(System.Threading.CancellationToken.None)
            let args = TraefikArgs()
            args.Connection <- Input<AptConnectionArgs>.op_Implicit connection
            args.EntryPoints <- InputMap<int>.op_Implicit resolved.EntryPoints

            args.Resolvers <-
                InputMap<TraefikResolverArgs>.op_Implicit(TraefikResourceMappings.resolvers resolved.Resolvers)

            args.Routers <- InputMap<TraefikRouterArgs>.op_Implicit(TraefikResourceMappings.routers resolved.Routers)

            args.Certificates <-
                InputMap<TraefikCertificateArgs>.op_Implicit(TraefikResourceMappings.certificates resolved.Certificates)

            args.AdminPort <- Input<int>.op_Implicit resolved.AdminPort

            let dependencies =
                [ mainApt :> Resource ]
                @ (firewallPackage
                   |> Option.map (fun resource -> resource :> Resource)
                   |> Option.toList)
                @ (firewallResource
                   |> Option.map (fun resource -> resource :> Resource)
                   |> Option.toList)
                @ dockerContainers

            let options = ProviderContract.resourceOptionsWithDependencies dependencies
            TraefikInstance(host.Name, args, options) |> ignore
        | None -> ()

        mainApt
