namespace Dorothy.DSL

open System

/// One requested Debian package and its optional exact version constraint.
type PackageSpec =
    { Name: string
      Version: string option }

/// The merged package declarations for one Debian environment.
type AptSpec =
    { Packages: Map<string, string option> }

/// The package declarations and optional host services contributed by a Debian environment.
type DebianSpec =
    { Packages: Map<string, string option>
      Ufw: UfwSpec option
      Traefik: TraefikSpec option
      Docker: DockerSpec option
      Swapfile: SwapfileSpec option }

[<RequireQualifiedAccess>]
type DebianDeclaration =
    | AptPackages of AptSpec
    | UfwConfiguration of UfwSpec
    | TraefikConfiguration of TraefikSpec
    | DockerConfiguration of DockerSpec
    | SwapfileConfiguration of SwapfileSpec

/// A complete immutable description of one named SSH host.
///
/// The constructor is assembly-local so callers receive a valid host from the DSL rather than
/// bypassing its required-environment checks.
type HostSpec internal (
    name: string,
    address: string,
    user: string,
    port: int,
    identityFile: string option,
    packages: Map<string, string option>,
    ufw: UfwSpec option,
    traefik: TraefikSpec option,
    docker: DockerSpec option,
    swapfile: SwapfileSpec option
) =
    member _.Name = name
    member _.Address = address
    member _.User = user
    member _.Port = port
    member _.IdentityFile = identityFile
    member _.Packages = packages
    member _.Ufw = ufw
    member _.Traefik = traefik
    member _.Docker = docker
    member _.Swapfile = swapfile
type HostDeclaration =
    | Address of string
    | User of string
    | Port of int
    | IdentityFile of string
    | Debian of DebianSpec

module internal DomainValidation =
    let private isAsciiLetterOrDigit (value: char) =
        (value >= 'a' && value <= 'z')
        || (value >= 'A' && value <= 'Z')
        || (value >= '0' && value <= '9')

    let private isAsciiLowerOrDigit (value: char) =
        (value >= 'a' && value <= 'z')
        || (value >= '0' && value <= '9')

    let private isAsciiDigit (value: char) = value >= '0' && value <= '9'

    let validatePackageName (name: string) =
        let validCharacter value =
            isAsciiLowerOrDigit value || value = '+' || value = '.' || value = '-'

        let valid =
            not (isNull name)
            && name.Length >= 2
            && name.Length <= 255
            && isAsciiLowerOrDigit name[0]
            && (name |> Seq.forall validCharacter)

        if not valid then
            invalidArg "name" (sprintf "Invalid Debian package name '%s'." name)

    let validatePackageVersion (version: string) =
        let allowedCharacter value =
            isAsciiLetterOrDigit value || value = '.' || value = '+' || value = '~' || value = '-'

        if String.IsNullOrEmpty version || version.Length > 255 then
            invalidArg "version" "A package version must be a non-empty exact Debian version of at most 255 characters."

        let epochSeparator = version.IndexOf(':')
        let epoch, upstream =
            if epochSeparator < 0 then
                None, version
            else
                let epochText = version.Substring(0, epochSeparator)
                if epochText.Length = 0 || not (epochText |> Seq.forall isAsciiDigit) then
                    invalidArg "version" (sprintf "Invalid exact Debian package version '%s'." version)
                Some epochText, version.Substring(epochSeparator + 1)

        let hasAnotherSeparator =
            match epoch with
            | Some _ -> upstream.Contains(':')
            | None -> false

        if upstream.Length = 0
           || not (isAsciiDigit upstream[0])
           || hasAnotherSeparator
           || not (upstream |> Seq.forall allowedCharacter) then
            invalidArg "version" (sprintf "Invalid exact Debian package version '%s'." version)

    let validatePackages (packages: Map<string, string option>) =
        for KeyValue(name, version) in packages do
            validatePackageName name
            version |> Option.iter validatePackageVersion

    let validateHostSpec (host: HostSpec) =
        if String.IsNullOrWhiteSpace host.Name then
            invalidArg "host" "A stable, non-empty logical host name is required."
        if String.IsNullOrWhiteSpace host.Address then
            invalidArg "host" "An SSH address is required."
        if String.IsNullOrWhiteSpace host.User then
            invalidArg "host" "An SSH user is required."
        if host.Port < 1 || host.Port > 65535 then
            invalidArg "host" "The SSH port must be between 1 and 65535."
        host.IdentityFile
        |> Option.iter (fun identityFile ->
            if String.IsNullOrWhiteSpace identityFile then
                invalidArg "host" "An identity file path, when supplied, cannot be empty.")
        validatePackages host.Packages
        host.Ufw
        |> Option.iter (fun ufw ->
            if ufw.Enabled && ufw.DefaultOut <> UfwPolicy.Allow then
                invalidArg "host" "An enabled UFW firewall must allow outbound traffic so the SSH connection can be maintained.")

    let mergePackages (packages: seq<PackageSpec>) =
        packages
        |> Seq.fold (fun merged package ->
            validatePackageName package.Name
            package.Version |> Option.iter validatePackageVersion
            match Map.tryFind package.Name merged with
            | None -> Map.add package.Name package.Version merged
            | Some previous when previous = package.Version -> merged
            | Some previous ->
                invalidArg "packages" (sprintf "Package '%s' has conflicting version constraints '%A' and '%A'." package.Name previous package.Version))
            Map.empty

/// Adds package names or exact-version package declarations to an immutable APT block.
type AptBuilder() =
    member _.Yield(name: string) =
        [ { Name = name; Version = None } ]

    member _.Yield(package: PackageSpec) = [ package ]

    member _.YieldFrom(names: seq<string>) =
        names |> Seq.map (fun name -> { Name = name; Version = None }) |> Seq.toList

    member _.YieldFrom(packages: seq<PackageSpec>) = Seq.toList packages

    member _.Zero() = []

    member _.Combine(left: PackageSpec list, right: PackageSpec list) = left @ right

    member _.Delay(generator: unit -> PackageSpec list) = generator()

    member _.For(values: seq<'T>, body: 'T -> PackageSpec list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(packages: PackageSpec list) : AptSpec =
        { Packages = DomainValidation.mergePackages packages }

/// Merges APT blocks and optional UFW, Traefik, Docker, and swapfile declarations into one Debian environment.
type DebianBuilder() =
    member _.Yield(aptBlock: AptSpec) = [ DebianDeclaration.AptPackages aptBlock ]
    member _.Yield(firewall: UfwSpec) = [ DebianDeclaration.UfwConfiguration firewall ]
    member _.Yield(proxy: TraefikSpec) = [ DebianDeclaration.TraefikConfiguration proxy ]
    member _.Yield(containers: DockerSpec) = [ DebianDeclaration.DockerConfiguration containers ]
    member _.Yield(swapfile: SwapfileSpec) = [ DebianDeclaration.SwapfileConfiguration swapfile ]

    member _.YieldFrom(aptBlocks: seq<AptSpec>) =
        aptBlocks |> Seq.map DebianDeclaration.AptPackages |> Seq.toList

    member _.YieldFrom(firewalls: seq<UfwSpec>) =
        firewalls |> Seq.map DebianDeclaration.UfwConfiguration |> Seq.toList

    member _.YieldFrom(proxies: seq<TraefikSpec>) =
        proxies |> Seq.map DebianDeclaration.TraefikConfiguration |> Seq.toList

    member _.YieldFrom(configurations: seq<DockerSpec>) =
        configurations |> Seq.map DebianDeclaration.DockerConfiguration |> Seq.toList
    member _.YieldFrom(swapfiles: seq<SwapfileSpec>) =
        swapfiles |> Seq.map DebianDeclaration.SwapfileConfiguration |> Seq.toList

    member _.YieldFrom(declarations: seq<DebianDeclaration>) = Seq.toList declarations
    member _.Zero() = []
    member _.Combine(left: DebianDeclaration list, right: DebianDeclaration list) = left @ right
    member _.Delay(generator: unit -> DebianDeclaration list) = generator()

    member _.For(values: seq<'T>, body: 'T -> DebianDeclaration list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: DebianDeclaration list) : HostDeclaration =
        let aptBlocks =
            declarations
            |> List.choose (function
                | DebianDeclaration.AptPackages block -> Some block
                | DebianDeclaration.UfwConfiguration _
                | DebianDeclaration.DockerConfiguration _
                | DebianDeclaration.TraefikConfiguration _
                | DebianDeclaration.SwapfileConfiguration _ -> None)

        let firewall =
            declarations
            |> List.choose (function
                | DebianDeclaration.UfwConfiguration value -> Some value
                | DebianDeclaration.AptPackages _
                | DebianDeclaration.DockerConfiguration _
                | DebianDeclaration.TraefikConfiguration _
                | DebianDeclaration.SwapfileConfiguration _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare UFW only once."

        let traefik =
            declarations
            |> List.choose (function
                | DebianDeclaration.TraefikConfiguration value -> Some value
                | DebianDeclaration.AptPackages _
                | DebianDeclaration.DockerConfiguration _
                | DebianDeclaration.UfwConfiguration _
                | DebianDeclaration.SwapfileConfiguration _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare Traefik only once."

        let docker =
            declarations
            |> List.choose (function
                | DebianDeclaration.DockerConfiguration value -> Some value
                | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare Docker only once."
        let swapfile =
            declarations
            |> List.choose (function
                | DebianDeclaration.SwapfileConfiguration value -> Some value
                | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare a swapfile only once."

        let packages =
            aptBlocks
            |> Seq.collect (fun block ->
                block.Packages
                |> Map.toSeq
                |> Seq.map (fun (name, version) -> { Name = name; Version = version }))

        Debian
            { Packages = DomainValidation.mergePackages packages
              Ufw = firewall
              Traefik = traefik
              Docker = docker
              Swapfile = swapfile }
/// Collects the singleton SSH settings and the required Debian environment.
type HostBuilder(name: string) =
    member _.Yield(declaration: HostDeclaration) = [ declaration ]
    member _.YieldFrom(declarations: seq<HostDeclaration>) = Seq.toList declarations

    member _.Zero() = []

    member _.Combine(left: HostDeclaration list, right: HostDeclaration list) = left @ right

    member _.Delay(generator: unit -> HostDeclaration list) = generator()

    member _.For(values: seq<'T>, body: 'T -> HostDeclaration list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: HostDeclaration list) =
        let markSeen field seen =
            if Set.contains field seen then
                invalidArg "host" (sprintf "The host property '%s' may only be declared once." field)
            Set.add field seen

        let initial = None, None, None, None, None, Set.empty
        let address, user, port, identityFile, debianEnvironment, _ =
            declarations
            |> List.fold (fun (address, user, port, identityFile, debianEnvironment, seen) declaration ->
                match declaration with
                | Address value ->
                    let seen = markSeen "Address" seen
                    Some value, user, port, identityFile, debianEnvironment, seen
                | User value ->
                    let seen = markSeen "User" seen
                    address, Some value, port, identityFile, debianEnvironment, seen
                | Port value ->
                    let seen = markSeen "Port" seen
                    address, user, Some value, identityFile, debianEnvironment, seen
                | IdentityFile value ->
                    let seen = markSeen "IdentityFile" seen
                    address, user, port, Some value, debianEnvironment, seen
                | Debian value ->
                    let seen = markSeen "Debian" seen
                    address, user, port, identityFile, Some value, seen) initial

        let address =
            match address with
            | Some value when not (String.IsNullOrWhiteSpace value) -> value
            | _ -> invalidArg "host" "An SSH address is required."

        let user =
            match user with
            | Some value when not (String.IsNullOrWhiteSpace value) -> value
            | _ -> invalidArg "host" "An SSH user is required."

        let port = defaultArg port 22
        let identityFile =
            identityFile
            |> Option.bind (fun value ->
                if String.IsNullOrWhiteSpace value then
                    invalidArg "host" "An identity file path, when supplied, cannot be empty."
                Some value)

        if port < 1 || port > 65535 then
            invalidArg "host" "The SSH port must be between 1 and 65535."

        let debian =
            match debianEnvironment with
            | Some value -> value
            | None -> invalidArg "host" "A Debian environment is required."

        let result = HostSpec(name, address, user, port, identityFile, debian.Packages, debian.Ufw, debian.Traefik, debian.Docker, debian.Swapfile)
        result

[<AutoOpen>]
module DomainBuilders =
    let apt = AptBuilder()
    let debian = DebianBuilder()

    /// Declares an exact Debian package version rather than merely requiring presence.
    let packageVersion (name: string) (version: string) =
        DomainValidation.validatePackageName name
        DomainValidation.validatePackageVersion version
        { Name = name; Version = Some version }

    /// Starts an immutable host declaration with the caller-supplied stable Pulumi logical name.
    let sshHost (logicalName: string) = HostBuilder(logicalName)
