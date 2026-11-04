namespace Dorothy.DSL

open System
open System.Globalization
open System.Net

/// The supported sshd PermitRootLogin values.
[<RequireQualifiedAccess>]
type SshdRootLogin =
    | Yes
    | No
    | ProhibitPassword
    | ForcedCommandsOnly

/// Explicitly supplied sshd scalar settings; absent keywords remain unmanaged.
[<Sealed>]
type SshdConfigSpec internal (settings: Map<string, string>) =
    member _.Settings = settings

/// One Fail2Ban sshd jail declaration with validated whole-second durations.
[<Sealed>]
type Fail2BanSpec internal (enabled: bool, maxRetry: int, findTimeSeconds: int, banTimeSeconds: int, ignoreIps: string list) =
    member _.Enabled = enabled
    member _.MaxRetry = maxRetry
    member _.FindTimeSeconds = findTimeSeconds
    member _.BanTimeSeconds = banTimeSeconds
    member _.IgnoreIps = ignoreIps

/// Independent optional sshd configuration and Fail2Ban jail declarations.
[<Sealed>]
type SshdSpec internal (config: SshdConfigSpec option, fail2ban: Fail2BanSpec option) =
    member _.Config = config
    member _.Fail2Ban = fail2ban

type SshdConfigPart =
    | PasswordAuthentication of bool
    | KbdInteractiveAuthentication of bool
    | PubkeyAuthentication of bool
    | PermitRootLogin of SshdRootLogin
    | SshdPort of int
    | MaxAuthTries of int

type Fail2BanPart =
    | Fail2BanEnabled of bool
    | MaxRetry of int
    | FindTime of TimeSpan
    | BanTime of TimeSpan
    | IgnoreIp of string

type SshdDeclaration =
    | SshdConfigDeclaration of SshdConfigSpec
    | Fail2BanDeclaration of Fail2BanSpec

module private SshdValidation =
    let port (value: int) =
        if value < 1 || value > 65535 then
            invalidArg "port" "An sshd port must be between 1 and 65535."
        value.ToString(CultureInfo.InvariantCulture)

    let positiveInt parameterName fieldName (value: int) =
        if value <= 0 then
            invalidArg parameterName (sprintf "%s must be a positive integer." fieldName)
        value

    let formatInt (value: int) = value.ToString(CultureInfo.InvariantCulture)

    let seconds parameterName fieldName (duration: TimeSpan) =
        let ticks = duration.Ticks
        if ticks <= 0L || ticks % TimeSpan.TicksPerSecond <> 0L then
            invalidArg parameterName (sprintf "%s must be a positive whole number of seconds." fieldName)
        let total = ticks / TimeSpan.TicksPerSecond
        if total > int64 Int32.MaxValue then
            invalidArg parameterName (sprintf "%s must fit in a positive Int32 number of seconds." fieldName)
        int total

    let ignoreIp (value: string) =
        let rejectBroadOrUnspecified () =
            invalidArg
                "ignoreIp"
                "Unspecified host addresses and /0 CIDRs cannot be ignored; set enabled false to disable the jail or use narrower administrator CIDRs."

        if String.IsNullOrWhiteSpace value then
            invalidArg "ignoreIp" "An ignored address must be a valid IP address or CIDR."

        let parts = value.Split('/')
        if parts.Length > 2 || parts |> Array.exists String.IsNullOrEmpty then
            invalidArg "ignoreIp" (sprintf "Invalid ignored IP address or CIDR '%s'." value)

        let addressText = parts[0]
        let mutable address = IPAddress.Loopback
        if addressText.Contains('%') || not (IPAddress.TryParse(addressText, &address)) then
            invalidArg "ignoreIp" (sprintf "Invalid ignored IP address or CIDR '%s'." value)

        if parts.Length = 1 then
            let normalized = if address.IsIPv4MappedToIPv6 then address.MapToIPv4() else address
            if normalized.Equals(IPAddress.Any) || normalized.Equals(IPAddress.IPv6Any) then
                rejectBroadOrUnspecified ()
            normalized.ToString().ToLowerInvariant()
        else
            let mutable prefixLength = 0
            let maximumPrefix = if address.AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork then 32 else 128
            if not (Int32.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, &prefixLength))
               || prefixLength > maximumPrefix then
                invalidArg "ignoreIp" (sprintf "Invalid ignored IP address or CIDR '%s'." value)

            if prefixLength = 0 then
                rejectBroadOrUnspecified ()
            elif address.IsIPv4MappedToIPv6 then
                invalidArg "ignoreIp" "IPv4-mapped IPv6 CIDRs are ambiguous; use an IPv4 CIDR instead."
            elif prefixLength = maximumPrefix
                 && (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) then
                rejectBroadOrUnspecified ()
            else
                let bytes = address.GetAddressBytes()
                let fullBytes = prefixLength / 8
                let remainingBits = prefixLength % 8
                if remainingBits > 0 then
                    let mask = byte (0xff <<< (8 - remainingBits))
                    bytes[fullBytes] <- bytes[fullBytes] &&& mask
                let firstHostByte = fullBytes + (if remainingBits > 0 then 1 else 0)
                for index = firstHostByte to bytes.Length - 1 do
                    bytes[index] <- 0uy

                let network = IPAddress(bytes).ToString().ToLowerInvariant()
                network + "/" + prefixLength.ToString(CultureInfo.InvariantCulture)

/// Builds explicit sshd overrides without introducing server defaults.
type SshdConfigBuilder() =
    member _.Yield(part: SshdConfigPart) = [ part ]
    member _.YieldFrom(parts: seq<SshdConfigPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: SshdConfigPart list, right: SshdConfigPart list) = left @ right
    member _.Delay(generator: unit -> SshdConfigPart list) = generator()

    member _.For(values: seq<'T>, body: 'T -> SshdConfigPart list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(parts: SshdConfigPart list) =
        let mutable settings = Map.empty
        let add key value =
            if Map.containsKey key settings then
                invalidArg "config" (sprintf "The sshd setting '%s' may only be declared once." key)
            settings <- Map.add key value settings

        for part in parts do
            match part with
            | PasswordAuthentication value -> add "PasswordAuthentication" (if value then "yes" else "no")
            | KbdInteractiveAuthentication value -> add "KbdInteractiveAuthentication" (if value then "yes" else "no")
            | PubkeyAuthentication value -> add "PubkeyAuthentication" (if value then "yes" else "no")
            | PermitRootLogin value ->
                let token =
                    match value with
                    | SshdRootLogin.Yes -> "yes"
                    | SshdRootLogin.No -> "no"
                    | SshdRootLogin.ProhibitPassword -> "prohibit-password"
                    | SshdRootLogin.ForcedCommandsOnly -> "forced-commands-only"
                add "PermitRootLogin" token
            | SshdPort value -> add "Port" (SshdValidation.port value)
            | MaxAuthTries value ->
                add "MaxAuthTries" (SshdValidation.positiveInt "maxAuthTries" "MaxAuthTries" value |> SshdValidation.formatInt)

        SshdConfigSpec(settings)

/// Builds one validated Fail2Ban sshd jail declaration.
type Fail2BanBuilder() =
    member _.Yield(part: Fail2BanPart) = [ part ]
    member _.YieldFrom(parts: seq<Fail2BanPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: Fail2BanPart list, right: Fail2BanPart list) = left @ right
    member _.Delay(generator: unit -> Fail2BanPart list) = generator()

    member _.For(values: seq<'T>, body: 'T -> Fail2BanPart list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(parts: Fail2BanPart list) =
        let mutable enabled = None
        let mutable maxRetry = None
        let mutable findTime = None
        let mutable banTime = None
        let ignoreIps = ResizeArray<string>()

        let duplicate fieldName =
            invalidArg "fail2ban" (sprintf "Fail2Ban '%s' may only be declared once." fieldName)

        for part in parts do
            match part with
            | Fail2BanEnabled value ->
                if Option.isSome enabled then duplicate "enabled"
                enabled <- Some value
            | MaxRetry value ->
                if Option.isSome maxRetry then duplicate "maxRetry"
                maxRetry <- Some(SshdValidation.positiveInt "maxRetry" "maxRetry" value)
            | FindTime value ->
                if Option.isSome findTime then duplicate "findTime"
                findTime <- Some(SshdValidation.seconds "findTime" "findTime" value)
            | BanTime value ->
                if Option.isSome banTime then duplicate "banTime"
                banTime <- Some(SshdValidation.seconds "banTime" "banTime" value)
            | IgnoreIp value -> ignoreIps.Add(SshdValidation.ignoreIp value)

        let defaultIgnoreIps = [ "127.0.0.0/8"; "::1" ]
        let configuredIgnoreIps =
            Seq.append defaultIgnoreIps ignoreIps
            |> Seq.distinct
            |> Seq.toList

        Fail2BanSpec(
            defaultArg enabled true,
            defaultArg maxRetry 5,
            defaultArg findTime 600,
            defaultArg banTime 3600,
            configuredIgnoreIps
        )

/// Combines independently optional sshd config and Fail2Ban declarations.
type SshdBuilder() =
    member _.Yield(config: SshdConfigSpec) = [ SshdDeclaration.SshdConfigDeclaration config ]
    member _.Yield(fail2ban: Fail2BanSpec) = [ SshdDeclaration.Fail2BanDeclaration fail2ban ]

    member _.YieldFrom(configurations: seq<SshdConfigSpec>) =
        configurations |> Seq.map SshdDeclaration.SshdConfigDeclaration |> Seq.toList

    member _.YieldFrom(configurations: seq<Fail2BanSpec>) =
        configurations |> Seq.map SshdDeclaration.Fail2BanDeclaration |> Seq.toList

    member _.YieldFrom(declarations: seq<SshdDeclaration>) = Seq.toList declarations
    member _.Zero() = []
    member _.Combine(left: SshdDeclaration list, right: SshdDeclaration list) = left @ right
    member _.Delay(generator: unit -> SshdDeclaration list) = generator()

    member _.For(values: seq<'T>, body: 'T -> SshdDeclaration list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: SshdDeclaration list) =
        let config =
            declarations
            |> List.choose (function
                | SshdDeclaration.SshdConfigDeclaration value -> Some value
                | SshdDeclaration.Fail2BanDeclaration _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "sshd" "An sshd declaration may contain a config block only once."

        let fail2ban =
            declarations
            |> List.choose (function
                | SshdDeclaration.Fail2BanDeclaration value -> Some value
                | SshdDeclaration.SshdConfigDeclaration _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "sshd" "An sshd declaration may contain a fail2ban block only once."

        SshdSpec(config, fail2ban)

[<AutoOpen>]
module SshdBuilders =
    let config = SshdConfigBuilder()
    let fail2ban = Fail2BanBuilder()
    let sshd = SshdBuilder()

    let passwordAuthentication value = SshdConfigPart.PasswordAuthentication value
    let kbdInteractiveAuthentication value = SshdConfigPart.KbdInteractiveAuthentication value
    let pubkeyAuthentication value = SshdConfigPart.PubkeyAuthentication value
    let permitRootLogin value = SshdConfigPart.PermitRootLogin value
    let port value = SshdConfigPart.SshdPort value
    let maxAuthTries value = SshdConfigPart.MaxAuthTries value

    let enabled value = Fail2BanPart.Fail2BanEnabled value
    let maxRetry value = Fail2BanPart.MaxRetry value
    let findTime value = Fail2BanPart.FindTime value
    let banTime value = Fail2BanPart.BanTime value
    let ignoreIp value = Fail2BanPart.IgnoreIp value

    let Yes = SshdRootLogin.Yes
    let No = SshdRootLogin.No
    let ProhibitPassword = SshdRootLogin.ProhibitPassword
    let ForcedCommandsOnly = SshdRootLogin.ForcedCommandsOnly
