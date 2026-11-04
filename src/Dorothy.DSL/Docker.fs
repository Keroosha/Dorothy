namespace Dorothy.DSL

open System
open System.Collections.Generic
open System.Globalization
open System.IO
open System.Net
open System.Net.Sockets
open System.Text
open System.Threading
open System.Threading.Tasks
open Pulumi

type DockerNetworkDriver =
    | Bridge

[<Sealed>]
type DockerNetworkSpec internal (name: string, driver: DockerNetworkDriver) =
    member _.Name = name
    member _.Driver = driver

[<Sealed>]
type DockerVolumeSpec internal (name: string, protect: bool) =
    member _.Name = name
    member _.Protect = protect

[<Sealed>]
type DockerExistingNetwork internal (name: string) =
    member _.Name = name

[<Sealed>]
type DockerExistingVolume internal (name: string) =
    member _.Name = name

type DockerStringInput =
    | LiteralDockerString of string
    | OutputDockerString of Output<string>

[<RequireQualifiedAccess>]
module DockerStringInput =
    let resolve = function
        | LiteralDockerString value -> Output.Create(value)
        | OutputDockerString value -> value

    let private requiredValue description (value: string) =
        if String.IsNullOrWhiteSpace value || (value |> Seq.exists Char.IsControl) then
            invalidArg "value" (sprintf "A non-empty %s without control characters is required." description)
        value

    let resolveRequired description input =
        input
        |> resolve
        |> fun output -> output.Apply(Func<string, string>(requiredValue description))

    let resolveSecret input =
        input
        |> resolve
        |> Output.CreateSecret<string>

    let resolveSecretRequired description input =
        input
        |> resolveRequired description
        |> Output.CreateSecret<string>

type internal DockerContentKind =
    | DockerText of DockerStringInput
    | DockerBase64 of DockerStringInput
    | DockerFilePath of string
    | DockerStreamFactory of (CancellationToken -> Task<Stream>)

type DockerContent internal (kind: DockerContentKind) =
    member internal _.Kind = kind
    static member text(value: string) = DockerContent(DockerText(LiteralDockerString value))
    static member text(value: Output<string>) = DockerContent(DockerText(OutputDockerString value))
    static member base64(value: string) = DockerContent(DockerBase64(LiteralDockerString value))
    static member base64(value: Output<string>) = DockerContent(DockerBase64(OutputDockerString value))
    static member file(path: string) =
        if String.IsNullOrWhiteSpace path then invalidArg "path" "A Docker content file path cannot be empty."
        DockerContent(DockerFilePath path)
    static member stream(factory: CancellationToken -> Task<Stream>) =
        if isNull (box factory) then nullArg "factory"
        DockerContent(DockerStreamFactory factory)

[<RequireQualifiedAccess>]
module DockerContent =

    let private genericFailure<'T> () : 'T =
        raise (InvalidOperationException("Docker content resolution failed."))

    let private readStream (factory: CancellationToken -> Task<Stream>) (cancellationToken: CancellationToken) =
        task {
            let! source = factory cancellationToken
            if isNull source then genericFailure ()
            use source = source
            use destination = new MemoryStream()
            do! source.CopyToAsync(destination, 81920, cancellationToken)
            return destination.ToArray()
        }

    let private resolveFile (path: string) (cancellationToken: CancellationToken) =
        task {
            try
                let! bytes = File.ReadAllBytesAsync(path, cancellationToken)
                return Convert.ToBase64String(bytes)
            with
            | :? OperationCanceledException when cancellationToken.IsCancellationRequested ->
                return raise (OperationCanceledException cancellationToken)
            | _ -> return genericFailure ()
        }

    let private resolveStream (factory: CancellationToken -> Task<Stream>) (cancellationToken: CancellationToken) =
        task {
            try
                let! bytes = readStream factory cancellationToken
                return Convert.ToBase64String(bytes)
            with
            | :? OperationCanceledException when cancellationToken.IsCancellationRequested ->
                return raise (OperationCanceledException cancellationToken)
            | _ -> return genericFailure ()
        }

    /// Resolves content to Docker's base64 upload representation. File and stream IO is deferred
    /// until this function is invoked; Pulumi Output dependencies and secret metadata are retained.
    let resolve (cancellationToken: CancellationToken) (content: DockerContent) (secret: bool) : Output<string> =
        let resolved =
            match content.Kind with
            | DockerText input ->
                input
                |> DockerStringInput.resolve
                |> fun value -> value.Apply(Func<string, string>(fun text -> Encoding.UTF8.GetBytes(text) |> Convert.ToBase64String))
            | DockerBase64 input ->
                input
                |> DockerStringInput.resolve
                |> fun value -> value.Apply(Func<string, string>(fun encoded ->
                    try
                        encoded |> Convert.FromBase64String |> Convert.ToBase64String
                    with _ -> genericFailure ()))
            | DockerFilePath path -> Output.Create<string>(resolveFile path cancellationToken)
            | DockerStreamFactory factory -> Output.Create<string>(resolveStream factory cancellationToken)

        if secret then Output.CreateSecret<string>(resolved) else resolved

type DockerRestartPolicy =
    | NoRestart
    | Always
    | UnlessStopped
    | OnFailure of retries: int option

type DockerNetworkMode =
    | HostNetwork

type DockerNetworkAttachment =
    | ManagedNetwork of network: DockerNetworkSpec * aliases: string list
    | ExistingNetwork of network: DockerExistingNetwork * aliases: string list

type DockerTmpfs =
    | DockerTmpfs of size: int<MiB> option

type DockerMountSource =
    | ManagedVolume of volume: DockerVolumeSpec
    | ExistingVolume of volume: DockerExistingVolume
    | Bind of hostPath: string
    | Tmpfs of DockerTmpfs

type DockerMountAccess =
    | ReadOnly
    | ReadWrite

type DockerMountSpec =
    { Source: DockerMountSource
      Target: string
      Access: DockerMountAccess }

type DockerPublishedPort =
    { HostAddress: string
      HostPort: int
      ContainerPort: int
      Protocol: UfwProtocol }

type DockerHealthcheckCommand =
    | DockerExec of argv: string list
    | DockerShell of command: string

type DockerHealthcheckSpec =
    { Command: DockerHealthcheckCommand
      Interval: TimeSpan option
      Timeout: TimeSpan option
      StartPeriod: TimeSpan option
      Retries: int option }

type DockerFileSpec =
    { Path: string
      Content: DockerContent
      Permissions: string
      Secret: bool }

type DockerRegistryCredentialKind =
    | RegistryPassword
    | RegistryToken

[<Sealed>]
type DockerRegistrySpec internal (
    server: string,
    username: DockerStringInput,
    credential: DockerStringInput,
    credentialKind: DockerRegistryCredentialKind
) =
    member _.Server = server
    member _.Username = username
    member _.Credential = credential
    member _.CredentialKind = credentialKind

type DockerContainerSpec internal (
    name: string,
    image: DockerStringInput,
    restart: DockerRestartPolicy,
    cpu: float<cpu> option,
    memory: int<MiB> option,
    environment: Map<string, DockerStringInput>,
    command: string list option,
    entrypoint: string list option,
    workingDirectory: string option,
    runAs: string option,
    readOnlyRootFilesystem: bool option,
    init: bool option,
    labels: Map<string, string>,
    networks: DockerNetworkAttachment list,
    networkMode: DockerNetworkMode option,
    mounts: DockerMountSpec list,
    publishedPorts: DockerPublishedPort list,
    healthcheck: DockerHealthcheckSpec option,
    waitHealthy: TimeSpan option,
    files: DockerFileSpec list
) =
    member _.Name = name
    member _.Image = image
    member _.Restart = restart
    member _.Cpu = cpu
    member _.Memory = memory
    member _.Environment = environment
    member _.Command = command
    member _.Entrypoint = entrypoint
    member _.WorkingDirectory = workingDirectory
    member _.RunAs = runAs
    member _.ReadOnlyRootFilesystem = readOnlyRootFilesystem
    member _.Init = init
    member _.Labels = labels
    member _.Networks = networks
    member _.NetworkMode = networkMode
    member _.Mounts = mounts
    member _.PublishedPorts = publishedPorts
    member _.Healthcheck = healthcheck
    member _.WaitHealthy = waitHealthy
    member _.Files = files

type DockerSpec internal (
    networks: DockerNetworkSpec list,
    volumes: DockerVolumeSpec list,
    containers: DockerContainerSpec list,
    registries: DockerRegistrySpec list
) =
    member _.Networks = networks
    member _.Volumes = volumes
    member _.Containers = containers
    member _.Registries = registries

[<RequireQualifiedAccess>]
type DockerNetworkPart =
    | Driver of DockerNetworkDriver

[<RequireQualifiedAccess>]
type DockerVolumePart =
    | Protect of bool

[<RequireQualifiedAccess>]
type DockerMountPart =
    | Source of DockerMountSource
    | Target of string
    | Access of DockerMountAccess

[<RequireQualifiedAccess>]
type DockerPublishPart =
    | HostAddress of string
    | HostPort of int
    | ContainerPort of int
    | Protocol of ProtocolSpec

[<RequireQualifiedAccess>]
type DockerHealthcheckPart =
    | Command of DockerHealthcheckCommand
    | Interval of TimeSpan
    | Timeout of TimeSpan
    | StartPeriod of TimeSpan
    | Retries of int

[<RequireQualifiedAccess>]
type DockerFilePart =
    | Content of DockerContent
    | Permissions of string
    | Secret of bool

[<RequireQualifiedAccess>]
type DockerRegistryPart =
    | Username of DockerStringInput
    | Password of DockerStringInput
    | Token of DockerStringInput

[<RequireQualifiedAccess>]
type DockerContainerPart =
    | Image of DockerStringInput
    | Restart of DockerRestartPolicy
    | Cpu of float<cpu>
    | Memory of int<MiB>
    | Environment of string * DockerStringInput
    | Command of string list
    | Entrypoint of string list
    | WorkingDirectory of string
    | RunAs of string
    | ReadOnlyRootFilesystem of bool
    | Init of bool
    | Label of string * string
    | Network of DockerNetworkAttachment
    | NetworkMode of DockerNetworkMode
    | Mount of DockerMountSpec
    | PublishedPort of DockerPublishedPort
    | Healthcheck of DockerHealthcheckSpec
    | WaitHealthy of TimeSpan
    | File of DockerFileSpec

[<RequireQualifiedAccess>]
type DockerDeclaration =
    | Network of DockerNetworkSpec
    | Volume of DockerVolumeSpec
    | Container of DockerContainerSpec
    | Registry of DockerRegistrySpec

module internal DockerValidation =
    let validateName parameterName kind (value: string) =
        let isAsciiAlphaNumeric character =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')

        let valid =
            not (String.IsNullOrWhiteSpace value)
            && value.Length <= 63
            && isAsciiAlphaNumeric value[0]
            && (value |> Seq.forall (fun character ->
                isAsciiAlphaNumeric character || character = '-' || character = '_' || character = '.'))

        if not valid then invalidArg parameterName (sprintf "Invalid Docker %s name '%s'." kind value)

    let validateText parameterName description (value: string) =
        if String.IsNullOrWhiteSpace value || value |> Seq.exists Char.IsControl then
            invalidArg parameterName (sprintf "A non-empty %s without control characters is required." description)
        value

    let validateAbsolutePath parameterName description (value: string) =
        validateText parameterName description value |> ignore
        if not (Path.IsPathRooted value)
           || (value.Split('/', StringSplitOptions.RemoveEmptyEntries) |> Array.exists ((=) "..")) then
            invalidArg parameterName (sprintf "The %s must be an absolute path without parent-directory segments." description)
        value

    let validateDuration parameterName description (value: TimeSpan) =
        if value <= TimeSpan.Zero || value.Ticks > Int64.MaxValue / 100L then
            invalidArg parameterName (sprintf "Docker %s must be positive and fit in the Docker duration range." description)
        value

    let waitHealthySeconds (value: TimeSpan) =
        if value <= TimeSpan.Zero then
            invalidArg "waitHealthy" "Docker health wait duration must be positive."
        let ticks = value.Ticks
        let wholeSeconds = ticks / int64 TimeSpan.TicksPerSecond
        let roundedUpSeconds =
            if ticks % int64 TimeSpan.TicksPerSecond = 0L then wholeSeconds
            else wholeSeconds + 1L
        if roundedUpSeconds > int64 Int32.MaxValue then
            invalidArg "waitHealthy" "Docker health wait duration ceiling must fit in Int32 seconds."
        int roundedUpSeconds

    let validatePositiveRetries parameterName description (value: int) =
        if value < 1 then invalidArg parameterName (sprintf "Docker %s must be positive." description)
        value

    let validateHostAddress (value: string) =
        let mutable address = Unchecked.defaultof<IPAddress>
        if String.IsNullOrWhiteSpace value || not (IPAddress.TryParse(value, &address)) then
            invalidArg "hostAddress" "A published Docker port requires a literal IP host address."
        address.ToString()

    let validateRegistryServer (value: string) =
        validateText "registry" "Docker registry server" value |> ignore
        if value.Contains('/') || value.Contains('\\') || value.Contains('@') || value.Contains('?') || value.Contains('#') then
            invalidArg "registry" "A Docker registry server must be a host with an optional port, not a URL or credential."
        let mutable uri = Unchecked.defaultof<Uri>
        if not (Uri.TryCreate("https://" + value, UriKind.Absolute, &uri))
           || not (String.IsNullOrEmpty uri.UserInfo)
           || uri.AbsolutePath <> "/" then
            invalidArg "registry" "A Docker registry server must be a valid host with an optional port."
        value.ToLowerInvariant()

    let private addressOverlaps (left: string) (right: string) =
        let leftAddress = IPAddress.Parse(left)
        let rightAddress = IPAddress.Parse(right)
        let isWildcard (address: IPAddress) =
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
        isWildcard leftAddress || isWildcard rightAddress || leftAddress.Equals(rightAddress)

    let private protocolsOverlap left right =
        left = right || left = UfwProtocol.TcpAndUdp || right = UfwProtocol.TcpAndUdp

    let publishedPortsOverlap (left: DockerPublishedPort) (right: DockerPublishedPort) =
        left.HostPort = right.HostPort
        && addressOverlaps left.HostAddress right.HostAddress
        && protocolsOverlap left.Protocol right.Protocol

    let validateNoOverlappingPorts (ports: seq<DockerPublishedPort>) =
        let ports = ports |> Seq.toArray
        for leftIndex in 0 .. ports.Length - 1 do
            for rightIndex in leftIndex + 1 .. ports.Length - 1 do
                if publishedPortsOverlap ports[leftIndex] ports[rightIndex] then
                    invalidArg "docker" "Docker published host ports overlap by address, port, and protocol."

    let validateUniqueNames parameterName kind (names: seq<string>) (comparer: StringComparer) =
        let seen = HashSet<string>(comparer)
        for name in names do
            if not (seen.Add name) then invalidArg parameterName (sprintf "Docker %s names must be unique." kind)

    let private validateArgument parameterName description (value: string) =
        if isNull value || value.Contains(char 0) then
            invalidArg parameterName (sprintf "A Docker %s argument cannot be null or contain NUL." description)
        value

    let validateStringList parameterName description (values: string list) =
        values |> List.map (validateArgument parameterName description)

[<Sealed>]
type DockerNetworkBuilder internal (name: string) =
    member _.Yield(part: DockerNetworkPart) = [ part ]
    member _.YieldFrom(parts: seq<DockerNetworkPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: DockerNetworkPart list, right: DockerNetworkPart list) = left @ right
    member _.Delay(generator: unit -> DockerNetworkPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerNetworkPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: DockerNetworkPart list) =
        let drivers = parts |> List.choose (function DockerNetworkPart.Driver value -> Some value)
        if drivers.Length > 1 then invalidArg "network" "The Docker network driver may be declared only once."
        let driver = drivers |> List.tryHead |> Option.defaultValue DockerNetworkDriver.Bridge
        match driver with
        | DockerNetworkDriver.Bridge -> DockerNetworkSpec(name, driver)

[<Sealed>]
type DockerVolumeBuilder internal (name: string) =
    member _.Yield(part: DockerVolumePart) = [ part ]
    member _.YieldFrom(parts: seq<DockerVolumePart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: DockerVolumePart list, right: DockerVolumePart list) = left @ right
    member _.Delay(generator: unit -> DockerVolumePart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerVolumePart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: DockerVolumePart list) =
        let protections = parts |> List.choose (function DockerVolumePart.Protect value -> Some value)
        if protections.Length > 1 then invalidArg "volume" "Volume protection may be declared only once."
        DockerVolumeSpec(name, protections |> List.tryHead |> Option.defaultValue true)

[<Sealed>]
type DockerMountBuilder() =
    member _.Yield(part: DockerMountPart) = [ part ]
    member _.YieldFrom(parts: seq<DockerMountPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: DockerMountPart list, right: DockerMountPart list) = left @ right
    member _.Delay(generator: unit -> DockerMountPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerMountPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: DockerMountPart list) =
        let select fieldName pick =
            let values = parts |> List.choose pick
            if values.Length > 1 then invalidArg "mount" (sprintf "Mount field '%s' may be declared only once." fieldName)
            values |> List.tryHead

        let source = select "source" (function DockerMountPart.Source value -> Some value | _ -> None)
        let target = select "target" (function DockerMountPart.Target value -> Some value | _ -> None)
        let access = select "access" (function DockerMountPart.Access value -> Some value | _ -> None) |> Option.defaultValue DockerMountAccess.ReadWrite

        let source =
            match source with
            | Some (DockerMountSource.Bind path) ->
                DockerMountSource.Bind(DockerValidation.validateAbsolutePath "source" "Docker bind source path" path)
            | Some (DockerMountSource.Tmpfs (DockerTmpfs(Some size))) when size <= 0<MiB> || size > 2047<MiB> ->
                invalidArg "source" "A Docker tmpfs size must be between 1 and 2047 MiB."
            | Some value -> value
            | None -> invalidArg "mount" "A Docker mount requires a source."

        let target =
            match target with
            | Some path -> DockerValidation.validateAbsolutePath "target" "Docker container mount target" path
            | None -> invalidArg "mount" "A Docker mount requires a target."

        { Source = source; Target = target; Access = access }

[<Sealed>]
type DockerPublishBuilder() =
    member _.Yield(part: DockerPublishPart) = [ part ]
    member _.Yield(protocol: ProtocolSpec) = [ DockerPublishPart.Protocol protocol ]
    member _.YieldFrom(parts: seq<DockerPublishPart>) = Seq.toList parts
    member _.YieldFrom(protocols: seq<ProtocolSpec>) = protocols |> Seq.map DockerPublishPart.Protocol |> Seq.toList
    member _.Zero() = []
    member _.Combine(left: DockerPublishPart list, right: DockerPublishPart list) = left @ right
    member _.Delay(generator: unit -> DockerPublishPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerPublishPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: DockerPublishPart list) =
        let select fieldName pick =
            let values = parts |> List.choose pick
            if values.Length > 1 then invalidArg "publish" (sprintf "Published port field '%s' may be declared only once." fieldName)
            values |> List.tryHead

        let address = select "hostAddress" (function DockerPublishPart.HostAddress value -> Some value | _ -> None)
        let hostPort = select "hostPort" (function DockerPublishPart.HostPort value -> Some value | _ -> None)
        let containerPort = select "containerPort" (function DockerPublishPart.ContainerPort value -> Some value | _ -> None)
        let protocol = select "proto" (function DockerPublishPart.Protocol value -> Some value.Value | _ -> None)

        match address, hostPort, containerPort, protocol with
        | Some address, Some hostPort, Some containerPort, Some protocol ->
            let address = DockerValidation.validateHostAddress address
            if hostPort < 1 || hostPort > 65535 then invalidArg "hostPort" "A published host port must be between 1 and 65535."
            if containerPort < 1 || containerPort > 65535 then invalidArg "containerPort" "A published container port must be between 1 and 65535."
            { HostAddress = address; HostPort = hostPort; ContainerPort = containerPort; Protocol = protocol }
        | _ -> invalidArg "publish" "A published Docker port requires hostAddress, hostPort, containerPort, and proto exactly once."

[<Sealed>]
type DockerHealthcheckBuilder() =
    member _.Yield(part: DockerHealthcheckPart) = [ part ]
    member _.YieldFrom(parts: seq<DockerHealthcheckPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: DockerHealthcheckPart list, right: DockerHealthcheckPart list) = left @ right
    member _.Delay(generator: unit -> DockerHealthcheckPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerHealthcheckPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: DockerHealthcheckPart list) =
        let select fieldName pick =
            let values = parts |> List.choose pick
            if values.Length > 1 then invalidArg "healthcheck" (sprintf "Healthcheck field '%s' may be declared only once." fieldName)
            values |> List.tryHead

        let command = select "command" (function DockerHealthcheckPart.Command value -> Some value | _ -> None)
        let interval = select "interval" (function DockerHealthcheckPart.Interval value -> Some value | _ -> None) |> Option.map (DockerValidation.validateDuration "interval" "healthcheck interval")
        let timeout = select "timeout" (function DockerHealthcheckPart.Timeout value -> Some value | _ -> None) |> Option.map (DockerValidation.validateDuration "timeout" "healthcheck timeout")
        let startPeriod = select "startPeriod" (function DockerHealthcheckPart.StartPeriod value -> Some value | _ -> None) |> Option.map (DockerValidation.validateDuration "startPeriod" "healthcheck start period")
        let retries = select "retries" (function DockerHealthcheckPart.Retries value -> Some value | _ -> None) |> Option.map (DockerValidation.validatePositiveRetries "retries" "healthcheck retries")

        let command =
            match command with
            | Some (DockerExec []) -> invalidArg "healthcheck" "A Docker exec healthcheck requires an executable argument."
            | Some (DockerExec ((program :: _) as argv)) when String.IsNullOrWhiteSpace program ->
                invalidArg "healthcheck" "A Docker exec healthcheck requires a non-empty executable argument."
            | Some (DockerExec argv) ->
                DockerExec(DockerValidation.validateStringList "healthcheck" "healthcheck executable argument" argv)
            | Some (DockerShell value) ->
                DockerShell(DockerValidation.validateText "healthcheck" "healthcheck shell command" value)
            | None -> invalidArg "healthcheck" "A Docker healthcheck requires an explicit exec or shell command."

        { Command = command; Interval = interval; Timeout = timeout; StartPeriod = startPeriod; Retries = retries }

[<Sealed>]
type DockerContainerFileBuilder internal (path: string) =
    member _.Yield(part: DockerFilePart) = [ part ]
    member _.YieldFrom(parts: seq<DockerFilePart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: DockerFilePart list, right: DockerFilePart list) = left @ right
    member _.Delay(generator: unit -> DockerFilePart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerFilePart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: DockerFilePart list) =
        let select fieldName pick =
            let values = parts |> List.choose pick
            if values.Length > 1 then invalidArg "containerFile" (sprintf "File field '%s' may be declared only once." fieldName)
            values |> List.tryHead

        let content = select "content" (function DockerFilePart.Content value -> Some value | _ -> None)
        let permissions = select "permissions" (function DockerFilePart.Permissions value -> Some value | _ -> None) |> Option.defaultValue "0644"
        let secret = select "secret" (function DockerFilePart.Secret value -> Some value | _ -> None) |> Option.defaultValue false

        let content =
            match content with
            | Some value -> value
            | None -> invalidArg "containerFile" "A Docker container file requires content."

        let permissions =
            if String.IsNullOrWhiteSpace permissions
               || permissions.Length <> 4
               || (permissions |> Seq.exists (fun character -> character < '0' || character > '7')) then
                invalidArg "permissions" "Docker upload permissions must be a four-digit octal mode such as 0400 or 0644."
            permissions

        { Path = DockerValidation.validateAbsolutePath "containerFile" "Docker container file path" path
          Content = content
          Permissions = permissions
          Secret = secret }

[<Sealed>]
type DockerRegistryBuilder internal (server: string) =
    member _.Yield(part: DockerRegistryPart) = [ part ]
    member _.YieldFrom(parts: seq<DockerRegistryPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: DockerRegistryPart list, right: DockerRegistryPart list) = left @ right
    member _.Delay(generator: unit -> DockerRegistryPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerRegistryPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: DockerRegistryPart list) =
        let usernames = parts |> List.choose (function DockerRegistryPart.Username value -> Some value | _ -> None)
        let passwords = parts |> List.choose (function DockerRegistryPart.Password value -> Some value | _ -> None)
        let tokens = parts |> List.choose (function DockerRegistryPart.Token value -> Some value | _ -> None)
        if usernames.Length <> 1 then invalidArg "registry" "A Docker registry requires username exactly once."
        if passwords.Length + tokens.Length <> 1 then invalidArg "registry" "A Docker registry requires exactly one registryPassword or registryToken."

        let credential, kind =
            match passwords, tokens with
            | [ value ], [] -> value, DockerRegistryCredentialKind.RegistryPassword
            | [], [ value ] -> value, DockerRegistryCredentialKind.RegistryToken
            | _ -> invalidArg "registry" "A Docker registry requires exactly one credential."

        let username = List.head usernames
        match username with
        | LiteralDockerString value -> DockerValidation.validateText "username" "Docker registry username" value |> ignore
        | OutputDockerString _ -> ()
        DockerRegistrySpec(server, username, credential, kind)

[<Sealed>]
type DockerContainerBuilder internal (name: string) =
    member _.Yield(part: DockerContainerPart) = [ part ]
    member _.Yield(attachment: DockerNetworkAttachment) = [ DockerContainerPart.Network attachment ]
    member _.Yield(mount: DockerMountSpec) = [ DockerContainerPart.Mount mount ]
    member _.Yield(port: DockerPublishedPort) = [ DockerContainerPart.PublishedPort port ]
    member _.Yield(healthcheck: DockerHealthcheckSpec) = [ DockerContainerPart.Healthcheck healthcheck ]
    member _.Yield(file: DockerFileSpec) = [ DockerContainerPart.File file ]
    member _.YieldFrom(parts: seq<DockerContainerPart>) = Seq.toList parts
    member _.YieldFrom(attachments: seq<DockerNetworkAttachment>) = attachments |> Seq.map DockerContainerPart.Network |> Seq.toList
    member _.YieldFrom(mounts: seq<DockerMountSpec>) = mounts |> Seq.map DockerContainerPart.Mount |> Seq.toList
    member _.YieldFrom(ports: seq<DockerPublishedPort>) = ports |> Seq.map DockerContainerPart.PublishedPort |> Seq.toList
    member _.YieldFrom(files: seq<DockerFileSpec>) = files |> Seq.map DockerContainerPart.File |> Seq.toList
    member _.Zero() = []
    member _.Combine(left: DockerContainerPart list, right: DockerContainerPart list) = left @ right
    member _.Delay(generator: unit -> DockerContainerPart list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerContainerPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: DockerContainerPart list) =
        let select fieldName pick =
            let values = parts |> List.choose pick
            if values.Length > 1 then invalidArg "container" (sprintf "Container field '%s' may be declared only once." fieldName)
            values |> List.tryHead

        let image = select "image" (function DockerContainerPart.Image value -> Some value | _ -> None)
        let restart = select "restart" (function DockerContainerPart.Restart value -> Some value | _ -> None)
        let cpu = select "cpu" (function DockerContainerPart.Cpu value -> Some value | _ -> None)
        let memory = select "memory" (function DockerContainerPart.Memory value -> Some value | _ -> None)
        let command = select "command" (function DockerContainerPart.Command value -> Some value | _ -> None)
        let entrypoint = select "entrypoint" (function DockerContainerPart.Entrypoint value -> Some value | _ -> None)
        let workingDirectory = select "workingDir" (function DockerContainerPart.WorkingDirectory value -> Some value | _ -> None)
        let runAs = select "runAs" (function DockerContainerPart.RunAs value -> Some value | _ -> None)
        let readOnlyRootFilesystem = select "readOnlyRootFs" (function DockerContainerPart.ReadOnlyRootFilesystem value -> Some value | _ -> None)
        let init = select "init" (function DockerContainerPart.Init value -> Some value | _ -> None)
        let networkMode = select "networkMode" (function DockerContainerPart.NetworkMode value -> Some value | _ -> None)
        let healthcheck = select "healthcheck" (function DockerContainerPart.Healthcheck value -> Some value | _ -> None)
        let waitHealthy = select "waitHealthy" (function DockerContainerPart.WaitHealthy value -> Some value | _ -> None)

        let image =
            match image with
            | Some (LiteralDockerString value) ->
                DockerValidation.validateText "image" "Docker image reference" value |> ignore
                LiteralDockerString value
            | Some (OutputDockerString _) as value -> value.Value
            | None -> invalidArg "container" "A Docker service container requires an image."

        let restart =
            match restart with
            | Some (OnFailure retries) ->
                retries |> Option.iter (fun value -> DockerValidation.validatePositiveRetries "restart" "on-failure retry count" value |> ignore)
                OnFailure retries
            | Some value -> value
            | None -> invalidArg "container" "A Docker service container requires an explicit restart policy."

        let cpu =
            cpu
            |> Option.map (fun value ->
                if Double.IsNaN(float value) || Double.IsInfinity(float value) || value <= 0.0<cpu> then
                    invalidArg "cpu" "A Docker CPU reservation must be positive and finite."
                value)

        let memory =
            memory
            |> Option.map (fun value ->
                let maximumMiB = (Int32.MaxValue / 2) * 1<MiB>
                if value <= 0<MiB> || value > maximumMiB then
                    invalidArg "memory" "A Docker memory reservation must be positive and at most Int32.MaxValue/2 MiB so both memory and default swap inputs fit."
                value)

        let environment =
            parts
            |> List.choose (function DockerContainerPart.Environment(key, value) -> Some(key, value) | _ -> None)
            |> List.fold (fun values (key, value) ->
                if String.IsNullOrWhiteSpace key
                   || key.Contains('=')
                   || (key |> Seq.exists Char.IsControl) then
                    invalidArg "env" "A Docker environment key must be non-empty and cannot contain '=' or control characters."
                if Map.containsKey key values then invalidArg "env" (sprintf "Docker environment key '%s' is declared more than once." key)
                match value with
                | LiteralDockerString text when isNull text -> invalidArg "env" "A Docker environment value cannot be null."
                | LiteralDockerString _
                | OutputDockerString _ -> ()
                Map.add key value values)
                Map.empty

        let command = command |> Option.map (DockerValidation.validateStringList "command" "command argument")
        let entrypoint = entrypoint |> Option.map (DockerValidation.validateStringList "entrypoint" "entrypoint argument")
        let workingDirectory = workingDirectory |> Option.map (DockerValidation.validateAbsolutePath "workingDir" "Docker container working directory")
        let runAs = runAs |> Option.map (DockerValidation.validateText "runAs" "Docker container user")

        let labels =
            parts
            |> List.choose (function DockerContainerPart.Label(key, value) -> Some(key, value) | _ -> None)
            |> List.fold (fun values (key, value) ->
                DockerValidation.validateText "label" "Docker label key" key |> ignore
                if isNull value then invalidArg "label" "A Docker label value cannot be null."
                if Map.containsKey key values then invalidArg "label" (sprintf "Docker label '%s' is declared more than once." key)
                Map.add key value values)
                Map.empty

        let normalizeAliases aliases =
            for alias in aliases do
                DockerValidation.validateName "attachAs" "network alias" alias
            let aliases = aliases |> List.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
            if List.length aliases <> (aliases |> List.distinct |> List.length) then
                invalidArg "attachAs" "Network aliases must be unique."
            aliases
        let networks =
            parts
            |> List.choose (function DockerContainerPart.Network value -> Some value | _ -> None)
            |> List.map (function
                | ManagedNetwork(network, aliases) -> ManagedNetwork(network, normalizeAliases aliases)
                | ExistingNetwork(network, aliases) -> ExistingNetwork(network, normalizeAliases aliases))
            |> List.sortBy (function ManagedNetwork(network, _) -> network.Name | ExistingNetwork(network, _) -> network.Name)

        let attachedNames =
            networks |> List.map (function ManagedNetwork(network, _) -> network.Name | ExistingNetwork(network, _) -> network.Name)
        DockerValidation.validateUniqueNames "container" "attached network" attachedNames StringComparer.Ordinal

        let mounts =
            parts
            |> List.choose (function DockerContainerPart.Mount value -> Some value | _ -> None)
            |> List.sortBy (fun mount -> mount.Target)
        DockerValidation.validateUniqueNames "container" "mount target" (mounts |> Seq.map (fun mount -> mount.Target)) StringComparer.Ordinal

        let publishedPorts =
            parts
            |> List.choose (function DockerContainerPart.PublishedPort value -> Some value | _ -> None)
            |> List.sortBy (fun port ->
                let protocolOrder =
                    match port.Protocol with
                    | UfwProtocol.Tcp -> 0
                    | UfwProtocol.Udp -> 1
                    | UfwProtocol.TcpAndUdp -> 2
                port.HostAddress, port.HostPort, protocolOrder, port.ContainerPort)
        DockerValidation.validateNoOverlappingPorts publishedPorts

        let waitHealthy =
            waitHealthy
            |> Option.map (fun value ->
                DockerValidation.waitHealthySeconds value |> ignore
                value)
        if waitHealthy.IsSome && healthcheck.IsNone then
            invalidArg "waitHealthy" "waitHealthy requires an explicitly declared healthcheck."

        if networkMode = Some DockerNetworkMode.HostNetwork && (not networks.IsEmpty || not publishedPorts.IsEmpty) then
            invalidArg "networkMode" "Host network mode cannot be combined with network attachments or published ports."

        let files =
            parts
            |> List.choose (function DockerContainerPart.File value -> Some value | _ -> None)
            |> List.sortBy (fun file -> file.Path)
        DockerValidation.validateUniqueNames "container" "uploaded file path" (files |> Seq.map (fun file -> file.Path)) StringComparer.Ordinal

        DockerContainerSpec(
            name,
            image,
            restart,
            cpu,
            memory,
            environment,
            command,
            entrypoint,
            workingDirectory,
            runAs,
            readOnlyRootFilesystem,
            init,
            labels,
            networks,
            networkMode,
            mounts,
            publishedPorts,
            healthcheck,
            waitHealthy,
            files
        )

[<Sealed>]
type DockerBuilder() =
    member _.Yield(declaration: DockerDeclaration) = [ declaration ]
    member _.Yield(network: DockerNetworkSpec) = [ DockerDeclaration.Network network ]
    member _.Yield(volume: DockerVolumeSpec) = [ DockerDeclaration.Volume volume ]
    member _.Yield(container: DockerContainerSpec) = [ DockerDeclaration.Container container ]
    member _.Yield(registry: DockerRegistrySpec) = [ DockerDeclaration.Registry registry ]
    member _.YieldFrom(declarations: seq<DockerDeclaration>) = Seq.toList declarations
    member _.YieldFrom(networks: seq<DockerNetworkSpec>) = networks |> Seq.map DockerDeclaration.Network |> Seq.toList
    member _.YieldFrom(volumes: seq<DockerVolumeSpec>) = volumes |> Seq.map DockerDeclaration.Volume |> Seq.toList
    member _.YieldFrom(containers: seq<DockerContainerSpec>) = containers |> Seq.map DockerDeclaration.Container |> Seq.toList
    member _.YieldFrom(registries: seq<DockerRegistrySpec>) = registries |> Seq.map DockerDeclaration.Registry |> Seq.toList
    member _.Zero() = []
    member _.Combine(left: DockerDeclaration list, right: DockerDeclaration list) = left @ right
    member _.Delay(generator: unit -> DockerDeclaration list) = generator ()
    member _.For(values: seq<'T>, body: 'T -> DockerDeclaration list) = values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: DockerDeclaration list) =
        let networks = declarations |> List.choose (function DockerDeclaration.Network value -> Some value | _ -> None) |> List.sortBy (fun value -> value.Name)
        let volumes = declarations |> List.choose (function DockerDeclaration.Volume value -> Some value | _ -> None) |> List.sortBy (fun value -> value.Name)
        let containers = declarations |> List.choose (function DockerDeclaration.Container value -> Some value | _ -> None) |> List.sortBy (fun value -> value.Name)
        let registries = declarations |> List.choose (function DockerDeclaration.Registry value -> Some value | _ -> None) |> List.sortBy (fun value -> value.Server)

        for network in networks do DockerValidation.validateName "docker" "network" network.Name
        for volume in volumes do DockerValidation.validateName "docker" "volume" volume.Name
        for container in containers do DockerValidation.validateName "docker" "container" container.Name

        DockerValidation.validateUniqueNames "docker" "network" (networks |> Seq.map (fun value -> value.Name)) StringComparer.Ordinal
        DockerValidation.validateUniqueNames "docker" "volume" (volumes |> Seq.map (fun value -> value.Name)) StringComparer.Ordinal
        DockerValidation.validateUniqueNames "docker" "container" (containers |> Seq.map (fun value -> value.Name)) StringComparer.Ordinal
        DockerValidation.validateUniqueNames "docker" "registry" (registries |> Seq.map (fun value -> value.Server)) StringComparer.OrdinalIgnoreCase

        let isRegisteredNetwork (reference: DockerNetworkSpec) =
            networks |> List.exists (fun declared -> Object.ReferenceEquals(reference, declared))
        let isRegisteredVolume (reference: DockerVolumeSpec) =
            volumes |> List.exists (fun declared -> Object.ReferenceEquals(reference, declared))

        for container in containers do
            for network in container.Networks do
                match network with
                | ManagedNetwork(reference, _) when not (isRegisteredNetwork reference) ->
                    invalidArg "docker" (sprintf "Container '%s' references a managed network that is not registered in this Docker block." container.Name)
                | _ -> ()

            for mount in container.Mounts do
                match mount.Source with
                | ManagedVolume(reference) when not (isRegisteredVolume reference) ->
                    invalidArg "docker" (sprintf "Container '%s' references a managed volume that is not registered in this Docker block." container.Name)
                | _ -> ()

        let allPublishedPorts = containers |> Seq.collect (fun container -> container.PublishedPorts)
        DockerValidation.validateNoOverlappingPorts allPublishedPorts

        DockerSpec(networks, volumes, containers, registries)

[<AbstractClass; Sealed>]
type DockerFields private () =
    static member Image(value: string) = DockerContainerPart.Image(LiteralDockerString value)
    static member Image(value: Output<string>) = DockerContainerPart.Image(OutputDockerString value)
    static member Env(key: string, value: string) = DockerContainerPart.Environment(key, LiteralDockerString value)
    static member Env(key: string, value: Output<string>) = DockerContainerPart.Environment(key, OutputDockerString value)
    static member Username(value: string) = DockerRegistryPart.Username(LiteralDockerString value)
    static member Username(value: Output<string>) = DockerRegistryPart.Username(OutputDockerString value)
    static member RegistryPassword(value: string) = DockerRegistryPart.Password(LiteralDockerString value)
    static member RegistryPassword(value: Output<string>) = DockerRegistryPart.Password(OutputDockerString value)
    static member RegistryToken(value: string) = DockerRegistryPart.Token(LiteralDockerString value)
    static member RegistryToken(value: Output<string>) = DockerRegistryPart.Token(OutputDockerString value)
    static member Source(value: DockerMountSource) = DockerMountPart.Source value
    static member Source(value: DockerVolumeSpec) = DockerMountPart.Source(DockerMountSource.ManagedVolume value)
    static member Source(value: DockerExistingVolume) = DockerMountPart.Source(DockerMountSource.ExistingVolume value)
    static member Source(value: string) = DockerMountPart.Source(DockerMountSource.Bind value)
    static member Attach(value: DockerNetworkAttachment) = DockerContainerPart.Network value
    static member Attach(value: DockerNetworkSpec) = DockerContainerPart.Network(ManagedNetwork(value, []))
    static member Attach(value: DockerExistingNetwork) = DockerContainerPart.Network(ExistingNetwork(value, []))
    static member AttachAs(value: DockerNetworkAttachment, aliases: string list) =
        match value with
        | ManagedNetwork(network, _) -> DockerContainerPart.Network(ManagedNetwork(network, aliases))
        | ExistingNetwork(network, _) -> DockerContainerPart.Network(ExistingNetwork(network, aliases))
    static member AttachAs(value: DockerNetworkSpec, aliases: string list) = DockerContainerPart.Network(ManagedNetwork(value, aliases))
    static member AttachAs(value: DockerExistingNetwork, aliases: string list) = DockerContainerPart.Network(ExistingNetwork(value, aliases))

[<AutoOpen>]
module DockerBuilders =
    let network name =
        DockerValidation.validateName "network" "network" name
        DockerNetworkBuilder(name)

    let driver value = DockerNetworkPart.Driver value
    let bridge = DockerNetworkDriver.Bridge

    let volume name =
        DockerValidation.validateName "volume" "volume" name
        DockerVolumeBuilder(name)

    let protect value = DockerVolumePart.Protect value
    let existingNetwork name =
        DockerValidation.validateName "existingNetwork" "existing network" name
        DockerExistingNetwork name

    let existingVolume name =
        DockerValidation.validateName "existingVolume" "existing volume" name
        DockerExistingVolume name

    let container name =
        DockerValidation.validateName "container" "container" name
        DockerContainerBuilder(name)

    let inline image (value: ^T) : DockerContainerPart =
        ((^T or DockerFields) : (static member Image : ^T -> DockerContainerPart) value)

    let restart value = DockerContainerPart.Restart value
    let noRestart = DockerRestartPolicy.NoRestart
    let always = DockerRestartPolicy.Always
    let unlessStopped = DockerRestartPolicy.UnlessStopped
    let onFailure retryCount = DockerRestartPolicy.OnFailure retryCount

    let cpu value = DockerContainerPart.Cpu value
    let memory value = DockerContainerPart.Memory value

    let inline env key (value: ^T) : DockerContainerPart =
        ((^T or DockerFields) : (static member Env : string * ^T -> DockerContainerPart) (key, value))

    let command argv = DockerContainerPart.Command argv
    let entrypoint argv = DockerContainerPart.Entrypoint argv
    let workingDir value = DockerContainerPart.WorkingDirectory value
    let runAs value = DockerContainerPart.RunAs value
    let readOnlyRootFs value = DockerContainerPart.ReadOnlyRootFilesystem value
    let init value = DockerContainerPart.Init value
    let label key value = DockerContainerPart.Label(key, value)

    let inline attach (value: ^T) : DockerContainerPart =
        ((^T or DockerFields) : (static member Attach : ^T -> DockerContainerPart) value)

    let inline attachAs (value: ^T) (aliases: string list) : DockerContainerPart =
        ((^T or DockerFields) : (static member AttachAs : ^T * string list -> DockerContainerPart) (value, aliases))

    let networkMode mode = DockerContainerPart.NetworkMode mode

    let mount = DockerMountBuilder()
    let inline source (value: ^T) : DockerMountPart =
        ((^T or DockerFields) : (static member Source : ^T -> DockerMountPart) value)

    let target value = DockerMountPart.Target value
    let access value = DockerMountPart.Access value
    let bind path = DockerMountSource.Bind path
    let tmpfs = DockerMountSource.Tmpfs(DockerTmpfs None)
    let tmpfsSize (size: int<MiB>) = DockerMountSource.Tmpfs(DockerTmpfs(Some size))

    let publish = DockerPublishBuilder()
    let hostAddress value = DockerPublishPart.HostAddress value
    let hostPort value = DockerPublishPart.HostPort value
    let containerPort value = DockerPublishPart.ContainerPort value

    let healthcheck = DockerHealthcheckBuilder()
    let healthExec argv = DockerHealthcheckPart.Command(DockerExec argv)
    let healthShell command = DockerHealthcheckPart.Command(DockerShell command)
    let interval value = DockerHealthcheckPart.Interval value
    let timeout value = DockerHealthcheckPart.Timeout value
    let startPeriod value = DockerHealthcheckPart.StartPeriod value
    let retries value = DockerHealthcheckPart.Retries value
    let waitHealthy value = DockerContainerPart.WaitHealthy value

    let containerFile path =
        DockerValidation.validateAbsolutePath "containerFile" "Docker container file path" path |> ignore
        DockerContainerFileBuilder(path)

    let content value = DockerFilePart.Content value
    let permissions value = DockerFilePart.Permissions value
    let secret value = DockerFilePart.Secret value

    let registry server =
        let server = DockerValidation.validateRegistryServer server
        DockerRegistryBuilder(server)

    let inline username (value: ^T) : DockerRegistryPart =
        ((^T or DockerFields) : (static member Username : ^T -> DockerRegistryPart) value)

    let inline registryPassword (value: ^T) : DockerRegistryPart =
        ((^T or DockerFields) : (static member RegistryPassword : ^T -> DockerRegistryPart) value)

    let inline registryToken (value: ^T) : DockerRegistryPart =
        ((^T or DockerFields) : (static member RegistryToken : ^T -> DockerRegistryPart) value)

    let docker = DockerBuilder()
