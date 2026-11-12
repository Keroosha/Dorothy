namespace Dorothy.DSL

open System

/// One requested Debian package and its optional exact version constraint.
type PackageSpec =
    { Name: string; Version: string option }

/// The merged package declarations for one Debian environment.
type AptSpec =
    { Packages: Map<string, string option> }

/// The merged package and optional host service declarations for a Debian environment.
type DebianSpec =
    {
        Packages: Map<string, string option>
        Ufw: UfwSpec option
        Firewalld: FirewalldSpec option
        Traefik: TraefikSpec option
        Docker: DockerSpec option
        Swapfile: SwapfileSpec option
        Sshd: SshdSpec option
        Fail2Ban: Fail2BanSpec option
        Users: UsersSpec option
        Sudo: SudoSpec option
        Content: HostContentSpec option
        Services: HostServiceSpec list
    }

[<RequireQualifiedAccess>]
type DebianDeclaration =
    | AptPackages of AptSpec
    | UfwConfiguration of UfwSpec
    | FirewalldConfiguration of FirewalldSpec
    | TraefikConfiguration of TraefikSpec
    | DockerConfiguration of DockerSpec
    | SwapfileConfiguration of SwapfileSpec
    | SshdConfiguration of SshdSpec
    | Fail2BanConfiguration of Fail2BanInputSpec
    | UsersConfiguration of UsersSpec
    | SudoConfiguration of SudoSpec
    | ContentConfiguration of HostContentSpec
    | ServiceConfiguration of HostServiceSpec

/// A complete immutable description of one named SSH host.
///
/// The constructor is assembly-local so callers receive a valid host from the DSL rather than
/// bypassing its required-environment checks.
type HostSpec
    internal
    (
        name: string,
        address: string,
        user: string,
        port: int,
        identityFile: string option,
        packages: Map<string, string option>,
        ufw: UfwSpec option,
        firewalld: FirewalldSpec option,
        traefik: TraefikSpec option,
        docker: DockerSpec option,
        swapfile: SwapfileSpec option,
        sshd: SshdSpec option,
        fail2ban: Fail2BanSpec option,
        users: UsersSpec option,
        sudo: SudoSpec option,
        content: HostContentSpec option,
        services: HostServiceSpec list
    ) =
    member _.Name = name
    member _.Address = address
    member _.User = user
    member _.Port = port
    member _.IdentityFile = identityFile
    member _.Packages = packages
    member _.Ufw = ufw
    member _.Firewalld = firewalld
    member _.Traefik = traefik
    member _.Docker = docker
    member _.Swapfile = swapfile
    member _.Sshd = sshd
    member _.Fail2Ban = fail2ban
    member _.Users = users
    member _.Sudo = sudo
    member _.Content = content
    member _.Services = services

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
        (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')

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
            isAsciiLetterOrDigit value
            || value = '.'
            || value = '+'
            || value = '~'
            || value = '-'

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

        if
            upstream.Length = 0
            || not (isAsciiDigit upstream[0])
            || hasAnotherSeparator
            || not (upstream |> Seq.forall allowedCharacter)
        then
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
                invalidArg
                    "host"
                    "An enabled UFW firewall must allow outbound traffic so the SSH connection can be maintained.")

    let mergePackages (packages: seq<PackageSpec>) =
        packages
        |> Seq.fold
            (fun merged package ->
                validatePackageName package.Name
                package.Version |> Option.iter validatePackageVersion

                match Map.tryFind package.Name merged with
                | None -> Map.add package.Name package.Version merged
                | Some previous when previous = package.Version -> merged
                | Some previous ->
                    invalidArg
                        "packages"
                        (sprintf
                            "Package '%s' has conflicting version constraints '%A' and '%A'."
                            package.Name
                            previous
                            package.Version))
            Map.empty

/// Adds package names or exact-version package declarations to an immutable APT block.
type AptBuilder() =
    member _.Yield(name: string) = [ { Name = name; Version = None } ]

    member _.Yield(package: PackageSpec) = [ package ]

    member _.YieldFrom(names: seq<string>) =
        names |> Seq.map (fun name -> { Name = name; Version = None }) |> Seq.toList

    member _.YieldFrom(packages: seq<PackageSpec>) = Seq.toList packages

    member _.Zero() = []

    member _.Combine(left: PackageSpec list, right: PackageSpec list) = left @ right

    member _.Delay(generator: unit -> PackageSpec list) = generator ()

    member _.For(values: seq<'T>, body: 'T -> PackageSpec list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(packages: PackageSpec list) : AptSpec =
        {
            Packages = DomainValidation.mergePackages packages
        }

/// Merges packages, host services, SSH/Fail2Ban, users, and sudo into one Debian environment.
type DebianBuilder() =
    member _.Yield(aptBlock: AptSpec) =
        [ DebianDeclaration.AptPackages aptBlock ]

    member _.Yield(firewall: UfwSpec) =
        [ DebianDeclaration.UfwConfiguration firewall ]

    member _.Yield(firewall: FirewalldSpec) =
        [ DebianDeclaration.FirewalldConfiguration firewall ]

    member _.Yield(proxy: TraefikSpec) =
        [ DebianDeclaration.TraefikConfiguration proxy ]

    member _.Yield(containers: DockerSpec) =
        [ DebianDeclaration.DockerConfiguration containers ]

    member _.Yield(swapfile: SwapfileSpec) =
        [ DebianDeclaration.SwapfileConfiguration swapfile ]

    member _.Yield(sshd: SshdSpec) =
        [ DebianDeclaration.SshdConfiguration sshd ]

    member _.Yield(fail2ban: Fail2BanInputSpec) =
        [ DebianDeclaration.Fail2BanConfiguration fail2ban ]

    member _.Yield(users: UsersSpec) =
        [ DebianDeclaration.UsersConfiguration users ]

    member _.Yield(sudo: SudoSpec) =
        [ DebianDeclaration.SudoConfiguration sudo ]

    member _.Yield(content: HostContentSpec) = [ DebianDeclaration.ContentConfiguration content ]
    member _.Yield(service: HostServiceSpec) = [ DebianDeclaration.ServiceConfiguration service ]
    member _.YieldFrom(services: seq<HostServiceSpec>) = services |> Seq.map DebianDeclaration.ServiceConfiguration |> Seq.toList

    member _.YieldFrom(aptBlocks: seq<AptSpec>) =
        aptBlocks |> Seq.map DebianDeclaration.AptPackages |> Seq.toList

    member _.YieldFrom(firewalls: seq<UfwSpec>) =
        firewalls |> Seq.map DebianDeclaration.UfwConfiguration |> Seq.toList

    member _.YieldFrom(firewalls: seq<FirewalldSpec>) =
        firewalls |> Seq.map DebianDeclaration.FirewalldConfiguration |> Seq.toList

    member _.YieldFrom(proxies: seq<TraefikSpec>) =
        proxies |> Seq.map DebianDeclaration.TraefikConfiguration |> Seq.toList

    member _.YieldFrom(configurations: seq<DockerSpec>) =
        configurations |> Seq.map DebianDeclaration.DockerConfiguration |> Seq.toList

    member _.YieldFrom(swapfiles: seq<SwapfileSpec>) =
        swapfiles |> Seq.map DebianDeclaration.SwapfileConfiguration |> Seq.toList
    member _.YieldFrom(users: seq<UsersSpec>) = users |> Seq.map DebianDeclaration.UsersConfiguration |> Seq.toList
    member _.YieldFrom(sudos: seq<SudoSpec>) = sudos |> Seq.map DebianDeclaration.SudoConfiguration |> Seq.toList

    member _.YieldFrom(configurations: seq<SshdSpec>) =
        configurations |> Seq.map DebianDeclaration.SshdConfiguration |> Seq.toList

    member _.YieldFrom(configurations: seq<Fail2BanInputSpec>) =
        configurations |> Seq.map DebianDeclaration.Fail2BanConfiguration |> Seq.toList

    member _.YieldFrom(declarations: seq<DebianDeclaration>) = Seq.toList declarations
    member _.Zero() = []
    member _.Combine(left: DebianDeclaration list, right: DebianDeclaration list) = left @ right
    member _.Delay(generator: unit -> DebianDeclaration list) = generator ()

    member _.For(values: seq<'T>, body: 'T -> DebianDeclaration list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: DebianDeclaration list) : HostDeclaration =
        let aptBlocks =
            declarations
            |> List.choose (function
                | DebianDeclaration.AptPackages block -> Some block
                | _ -> None)

        let firewall =
            declarations
            |> List.choose (function
                | DebianDeclaration.UfwConfiguration value -> Some value
                | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare UFW only once."

        let firewalld =
            declarations
            |> List.choose (function DebianDeclaration.FirewalldConfiguration value -> Some value | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare firewalld only once."
        if firewall.IsSome && firewalld.IsSome then
            invalidArg "debian" "UFW and firewalld cannot be declared in the same Debian environment."

        let traefik =
            declarations
            |> List.choose (function
                | DebianDeclaration.TraefikConfiguration value -> Some value
                | _ -> None)
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

        let sshd =
            declarations
            |> List.choose (function
                | DebianDeclaration.SshdConfiguration value -> Some value
                | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare sshd only once."

        let fail2banDeclarations =
            declarations
            |> List.collect (function
                | DebianDeclaration.SshdConfiguration value ->
                    value.Fail2Ban
                    |> Option.map (fun specification -> [ specification, true ])
                    |> Option.defaultValue []
                | DebianDeclaration.Fail2BanConfiguration value -> [ value, false ]
                | _ -> [])

        let fail2ban =
            match fail2banDeclarations with
            | [] -> None
            | values -> Some(Fail2BanConfigurationMerge.combine values)

        let users =
            declarations
            |> List.choose (function
                | DebianDeclaration.UsersConfiguration value -> Some value
                | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare users only once."

        let sudo =
            declarations
            |> List.choose (function
                | DebianDeclaration.SudoConfiguration value -> Some value
                | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "debian" "A Debian environment may declare sudo only once."

        let content =
            declarations
            |> List.choose (function DebianDeclaration.ContentConfiguration value -> Some value | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "content" "A Debian environment may declare content only once."
        let services =
            declarations |> List.choose (function DebianDeclaration.ServiceConfiguration value -> Some value | _ -> None)
        HostContentValidation.unique "services" (services |> List.map _.Name)
        let contentItems = content |> Option.map _.Items |> Option.defaultValue []
        let targetPaths = contentItems |> List.collect (fun item -> item.Targets |> List.map _.Path)
        for service in services do
            for item in service.Uses do
                if not (contentItems |> List.exists (fun declared -> Object.ReferenceEquals(declared, item))) then
                    invalidArg "uses" "Every referenced content item must be declared in this environment's content block."
            if service.Managed && List.contains ("/etc/systemd/system/" + service.Name) targetPaths then
                invalidArg "content" "Content and service cannot own the same unit file."

        let packages =
            aptBlocks
            |> Seq.collect (fun block ->
                block.Packages
                |> Map.toSeq
                |> Seq.map (fun (name, version) -> { Name = name; Version = version }))

        Debian
            {
                Packages = DomainValidation.mergePackages packages
                Ufw = firewall
                Firewalld = firewalld
                Traefik = traefik
                Docker = docker
                Swapfile = swapfile
                Sshd = sshd
                Fail2Ban = fail2ban
                Users = users
                Sudo = sudo
                Content = content
                Services = services
            }

/// Collects the singleton SSH settings and the required Debian environment.
type HostBuilder(name: string) =
    member _.Yield(declaration: HostDeclaration) = [ declaration ]
    member _.YieldFrom(declarations: seq<HostDeclaration>) = Seq.toList declarations

    member _.Zero() = []

    member _.Combine(left: HostDeclaration list, right: HostDeclaration list) = left @ right

    member _.Delay(generator: unit -> HostDeclaration list) = generator ()

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
            |> List.fold
                (fun (address, user, port, identityFile, debianEnvironment, seen) declaration ->
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
                        address, user, port, identityFile, Some value, seen)
                initial

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

        let result =
            HostSpec(
                name,
                address,
                user,
                port,
                identityFile,
                debian.Packages,
                debian.Ufw,
                debian.Firewalld,
                debian.Traefik,
                debian.Docker,
                debian.Swapfile,
                debian.Sshd,
                debian.Fail2Ban,
                debian.Users,
                debian.Sudo,
                debian.Content,
                debian.Services
            )

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
