namespace Dorothy.DSL

open System
open System.Globalization
open System.Text

[<RequireQualifiedAccess>]
type SshdRootLogin =
    | Yes
    | No
    | ProhibitPassword
    | ForcedCommandsOnly

[<RequireQualifiedAccess>]
type SshdAddressFamily =
    | Any
    | IPv4
    | IPv6

[<RequireQualifiedAccess>]
type SshdForwardingMode =
    | Yes
    | All
    | No
    | Local
    | Remote

[<RequireQualifiedAccess>]
type SshdCompression =
    | Yes
    | Delayed
    | No

[<RequireQualifiedAccess>]
type SshdFingerprintHash =
    | Md5
    | Sha256

[<RequireQualifiedAccess>]
type SshdGatewayPorts =
    | No
    | Yes
    | ClientSpecified

[<RequireQualifiedAccess>]
type SshdIgnoreRhosts =
    | Yes
    | No
    | ShostsOnly

[<RequireQualifiedAccess>]
type SshdLogLevel =
    | Quiet
    | Fatal
    | Error
    | Info
    | Verbose
    | Debug
    | Debug1
    | Debug2
    | Debug3

[<RequireQualifiedAccess>]
type SshdPermitTunnel =
    | Yes
    | PointToPoint
    | Ethernet
    | No

[<RequireQualifiedAccess>]
type SshdSyslogFacility =
    | Daemon
    | User
    | Auth
    | AuthPriv
    | Local0
    | Local1
    | Local2
    | Local3
    | Local4
    | Local5
    | Local6
    | Local7

[<RequireQualifiedAccess>]
type SshdPermitUserEnvironment =
    | Yes
    | No
    | Patterns of string

[<RequireQualifiedAccess>]
type SshdLoginGraceTime =
    | NoLimit
    | LimitedTo of TimeSpan

[<RequireQualifiedAccess>]
type SshdClientAliveInterval =
    | Disabled
    | Every of TimeSpan

[<RequireQualifiedAccess>]
type SshdUnusedConnectionTimeout =
    | Never
    | After of TimeSpan

[<RequireQualifiedAccess>]
type SshdChannel =
    | Global
    | AgentConnection
    | DirectTcpip
    | DirectStreamLocal
    | ForwardedTcpip
    | ForwardedStreamLocal
    | Session
    | Shell
    | Command
    | TunConnection
    | X11Connection
    | Subsystem
    | Pattern of string

type SshdChannelTimeoutEntry =
    { Channel: SshdChannel
      InactiveFor: TimeSpan }

[<RequireQualifiedAccess>]
type SshdChannelTimeout =
    | Disabled
    | Timeouts of SshdChannelTimeoutEntry list

[<RequireQualifiedAccess>]
type SshdRekeyDataLimit =
    | Default
    | Bytes of int64<B>

type SshdRekeyLimit =
    { DataLimit: SshdRekeyDataLimit
      TimeLimit: TimeSpan option }

type SshdRandomEarlyDrop =
    { Start: int
      Rate: int
      Full: int }

[<RequireQualifiedAccess>]
type SshdMaxStartups =
    | Limit of int
    | RandomEarlyDrop of SshdRandomEarlyDrop

[<RequireQualifiedAccess>]
type SshdPerSourceMaxStartups =
    | Unlimited
    | Limit of int

type SshdPerSourceNetBlockSize =
    { IPv4Prefix: int
      IPv6Prefix: int option }

[<RequireQualifiedAccess>]
type SshdPerSourceOverflowMode =
    | DenyAll
    | Permissive

[<RequireQualifiedAccess>]
type SshdPerSourcePenalty =
    | Crash of TimeSpan
    | AuthFail of TimeSpan
    | NoAuth of TimeSpan
    | GraceExceeded of TimeSpan
    | RefuseConnection of TimeSpan
    | Max of TimeSpan
    | Min of TimeSpan
    | MaxSources4 of int
    | MaxSources6 of int
    | Overflow of SshdPerSourceOverflowMode
    | Overflow6 of SshdPerSourceOverflowMode

[<RequireQualifiedAccess>]
type SshdPerSourcePenalties =
    | Disabled
    | Enabled
    | Configured of SshdPerSourcePenalty list

[<RequireQualifiedAccess>]
type SshdForwardPort =
    | Any
    | Number of int
    | ServiceName of string

type SshdPermitOpenDestination =
    { Host: string
      Port: SshdForwardPort }

[<RequireQualifiedAccess>]
type SshdPermitOpen =
    | Any
    | None
    | Destinations of SshdPermitOpenDestination list

type SshdPermitListenAddress =
    { Host: string option
      Port: SshdForwardPort }

[<RequireQualifiedAccess>]
type SshdPermitListen =
    | Any
    | None
    | Addresses of SshdPermitListenAddress list

type SshdListenAddress =
    { Address: string
      Port: SshdForwardPort option
      RoutingDomain: string option }

[<RequireQualifiedAccess>]
type SshdIpQosValue =
    | OsDefault
    | Af11
    | Af12
    | Af13
    | Af21
    | Af22
    | Af23
    | Af31
    | Af32
    | Af33
    | Af41
    | Af42
    | Af43
    | Cs0
    | Cs1
    | Cs2
    | Cs3
    | Cs4
    | Cs5
    | Cs6
    | Cs7
    | Ef
    | Le
    | LowDelay
    | Throughput
    | Reliability
    | Numeric of int

type SshdIpQos =
    { Interactive: SshdIpQosValue
      Bulk: SshdIpQosValue option }

[<RequireQualifiedAccess>]
type SshdPubkeyAuthOption =
    | TouchRequired
    | VerifyRequired

[<RequireQualifiedAccess>]
type SshdPubkeyAuthOptions =
    | None
    | Options of SshdPubkeyAuthOption list

type SshdConfigPart =
    | Directive of keyword: string * arguments: string
    | NativeText of string
    | Match of criteria: string * body: SshdConfigPart list

[<Sealed>]
type SshdConfigSpec internal (configuration: string) =
    member _.Configuration = configuration

[<Sealed>]
type SshdSpec internal (config: SshdConfigSpec option, fail2ban: Fail2BanInputSpec option) =
    member _.Config = config
    member _.Fail2Ban = fail2ban

type SshdDeclaration =
    | SshdConfigDeclaration of SshdConfigSpec
    | Fail2BanDeclaration of Fail2BanInputSpec

module private SshdNative =
    let rec render (parts: SshdConfigPart list) =
        let builder = StringBuilder()

        let appendFragment (text: string) =
            if text.Length > 0 then
                builder.Append(text) |> ignore

                if text[text.Length - 1] <> '\n' then
                    builder.Append('\n') |> ignore

        let appendDirective keyword arguments =
            if String.IsNullOrEmpty arguments then
                appendFragment keyword
            else
                appendFragment (keyword + " " + arguments)

        for part in parts do
            match part with
            | SshdConfigPart.Directive(keyword, arguments) -> appendDirective keyword arguments
            | SshdConfigPart.NativeText text -> appendFragment text
            | SshdConfigPart.Match(criteria, body) ->
                appendDirective "Match" criteria
                appendFragment (render body)

        builder.ToString()

    let private validateKeyword (keyword: string) =
        if
            String.IsNullOrWhiteSpace keyword
            || (keyword
                |> Seq.exists (fun character ->
                    Char.IsWhiteSpace character
                    || character = '\r'
                    || character = '\n'
                    || character = '\u0000'))
        then
            invalidArg "keyword" "An OpenSSH directive name must be one non-empty token."

        keyword

    let directive (keyword: string) (arguments: string) =
        if isNull arguments then
            invalidArg "arguments" "Native OpenSSH directive arguments cannot be null."

        SshdConfigPart.Directive(validateKeyword keyword, arguments)

    let boolean keyword value =
        directive keyword (if value then "yes" else "no")

    let integer keyword (value: int) =
        directive keyword (value.ToString(CultureInfo.InvariantCulture))

    let list keyword (values: seq<string>) =
        directive keyword (String.concat " " values)

[<RequireQualifiedAccess>]
module SshdOptions =
    let private directive = SshdNative.directive
    let private boolean = SshdNative.boolean
    let private integer = SshdNative.integer
    let private list = SshdNative.list

    let private validateSingleToken (parameterName: string) (value: string) =
        if
            String.IsNullOrWhiteSpace value
            || (value
                |> Seq.exists (fun character ->
                    Char.IsWhiteSpace character
                    || character = '\u0000'
                    || character = '#'
                    || character = '"'
                    || character = '\u0027'))
        then
            invalidArg parameterName "The value cannot contain whitespace, comments, quotes, or NUL."

        value
    let private validateInteger (parameterName: string) (minimum: int) (maximum: int) (value: int) =
        if value < minimum || value > maximum then
            invalidArg parameterName $"The value must be in the range {minimum} through {maximum}."

        value.ToString(CultureInfo.InvariantCulture)

    let private integerInRange keyword minimum maximum value =
        validateInteger keyword minimum maximum value |> ignore
        integer keyword value

    let private renderSeconds parameterName allowZero (duration: TimeSpan) =
        let ticksPerSecond = TimeSpan.TicksPerSecond

        if duration.Ticks % ticksPerSecond <> 0L then
            invalidArg parameterName "OpenSSH time values must be an exact whole number of seconds."

        let seconds = duration.Ticks / ticksPerSecond

        if
            seconds < 0L
            || (seconds = 0L && not allowZero)
            || seconds > int64 Int32.MaxValue
        then
            invalidArg parameterName $"OpenSSH time values must be between {(if allowZero then 0 else 1)} and {Int32.MaxValue} whole seconds."

        seconds.ToString(CultureInfo.InvariantCulture)

    let private renderForwardPort (port: SshdForwardPort) =
        match port with
        | SshdForwardPort.Any -> "*"
        | SshdForwardPort.Number value -> validateInteger "Port" 1 65535 value
        | SshdForwardPort.ServiceName name -> validateSingleToken "Port" name

    let private renderEndpointHost parameterName (host: string) =
        let host = validateSingleToken parameterName host

        if host.Contains(':')
           && not (host.StartsWith("[", StringComparison.Ordinal) && host.EndsWith("]", StringComparison.Ordinal)) then
            "[" + host + "]"
        else
            host

    let private renderChannel (channel: SshdChannel) =
        match channel with
        | SshdChannel.Global -> "global"
        | SshdChannel.AgentConnection -> "agent-connection"
        | SshdChannel.DirectTcpip -> "direct-tcpip"
        | SshdChannel.DirectStreamLocal -> "direct-streamlocal@openssh.com"
        | SshdChannel.ForwardedTcpip -> "forwarded-tcpip"
        | SshdChannel.ForwardedStreamLocal -> "forwarded-streamlocal@openssh.com"
        | SshdChannel.Session -> "session*"
        | SshdChannel.Shell -> "session:shell"
        | SshdChannel.Command -> "session:command"
        | SshdChannel.TunConnection -> "tun"
        | SshdChannel.X11Connection -> "x11-connection"
        | SshdChannel.Subsystem -> "session:subsystem:*"
        | SshdChannel.Pattern pattern ->
            let pattern = validateSingleToken "Channel" pattern

            if pattern.Contains('=') then
                invalidArg "Channel" "A channel pattern cannot contain '='."

            pattern

    let private renderIpQosValue (value: SshdIpQosValue) =
        match value with
        | SshdIpQosValue.OsDefault -> "none"
        | SshdIpQosValue.Af11 -> "af11"
        | SshdIpQosValue.Af12 -> "af12"
        | SshdIpQosValue.Af13 -> "af13"
        | SshdIpQosValue.Af21 -> "af21"
        | SshdIpQosValue.Af22 -> "af22"
        | SshdIpQosValue.Af23 -> "af23"
        | SshdIpQosValue.Af31 -> "af31"
        | SshdIpQosValue.Af32 -> "af32"
        | SshdIpQosValue.Af33 -> "af33"
        | SshdIpQosValue.Af41 -> "af41"
        | SshdIpQosValue.Af42 -> "af42"
        | SshdIpQosValue.Af43 -> "af43"
        | SshdIpQosValue.Cs0 -> "cs0"
        | SshdIpQosValue.Cs1 -> "cs1"
        | SshdIpQosValue.Cs2 -> "cs2"
        | SshdIpQosValue.Cs3 -> "cs3"
        | SshdIpQosValue.Cs4 -> "cs4"
        | SshdIpQosValue.Cs5 -> "cs5"
        | SshdIpQosValue.Cs6 -> "cs6"
        | SshdIpQosValue.Cs7 -> "cs7"
        | SshdIpQosValue.Ef -> "ef"
        | SshdIpQosValue.Le -> "le"
        | SshdIpQosValue.LowDelay -> "lowdelay"
        | SshdIpQosValue.Throughput -> "throughput"
        | SshdIpQosValue.Reliability -> "reliability"
        | SshdIpQosValue.Numeric value -> validateInteger "IPQoS" 0 255 value

    let private renderPerSourcePenalty (penalty: SshdPerSourcePenalty) =
        let duration name value = name + ":" + renderSeconds name true value
        let count name value = name + ":" + validateInteger name 0 Int32.MaxValue value

        match penalty with
        | SshdPerSourcePenalty.Crash value -> duration "crash" value
        | SshdPerSourcePenalty.AuthFail value -> duration "authfail" value
        | SshdPerSourcePenalty.NoAuth value -> duration "noauth" value
        | SshdPerSourcePenalty.GraceExceeded value -> duration "grace-exceeded" value
        | SshdPerSourcePenalty.RefuseConnection value -> duration "refuseconnection" value
        | SshdPerSourcePenalty.Max value -> duration "max" value
        | SshdPerSourcePenalty.Min value -> duration "min" value
        | SshdPerSourcePenalty.MaxSources4 value -> count "max-sources4" value
        | SshdPerSourcePenalty.MaxSources6 value -> count "max-sources6" value
        | SshdPerSourcePenalty.Overflow SshdPerSourceOverflowMode.DenyAll -> "overflow:deny-all"
        | SshdPerSourcePenalty.Overflow SshdPerSourceOverflowMode.Permissive -> "overflow:permissive"
        | SshdPerSourcePenalty.Overflow6 SshdPerSourceOverflowMode.DenyAll -> "overflow6:deny-all"
        | SshdPerSourcePenalty.Overflow6 SshdPerSourceOverflowMode.Permissive -> "overflow6:permissive"

    let private renderForwardingAddress host port =
        let renderedPort = renderForwardPort port

        match host with
        | None -> renderedPort
        | Some value -> renderEndpointHost "Host" value + ":" + renderedPort

    let private renderListenAddress (address: SshdListenAddress) =
        let host = validateSingleToken "Address" address.Address

        let endpoint =
            match address.Port with
            | None -> host
            | Some SshdForwardPort.Any ->
                invalidArg "Port" "ListenAddress requires a numeric port or service name."
            | Some port -> renderEndpointHost "Address" host + ":" + renderForwardPort port

        match address.RoutingDomain with
        | None -> endpoint
        | Some routingDomain -> endpoint + " rdomain " + validateSingleToken "RoutingDomain" routingDomain

    let private renderPermitOpenDestination (destination: SshdPermitOpenDestination) =
        renderEndpointHost "Host" destination.Host
        + ":"
        + renderForwardPort destination.Port

    let acceptEnv value = directive "AcceptEnv" value
    let acceptEnvList values = list "AcceptEnv" values

    let addressFamily (value: SshdAddressFamily) =
        let token =
            match value with
            | SshdAddressFamily.Any -> "any"
            | SshdAddressFamily.IPv4 -> "inet"
            | SshdAddressFamily.IPv6 -> "inet6"

        directive "AddressFamily" token

    let allowAgentForwarding value = boolean "AllowAgentForwarding" value
    let allowGroups value = directive "AllowGroups" value
    let allowGroupsList values = list "AllowGroups" values

    let allowStreamLocalForwarding (value: SshdForwardingMode) =
        let token =
            match value with
            | SshdForwardingMode.Yes -> "yes"
            | SshdForwardingMode.All -> "all"
            | SshdForwardingMode.No -> "no"
            | SshdForwardingMode.Local -> "local"
            | SshdForwardingMode.Remote -> "remote"

        directive "AllowStreamLocalForwarding" token

    let allowTcpForwarding (value: SshdForwardingMode) =
        let token =
            match value with
            | SshdForwardingMode.Yes -> "yes"
            | SshdForwardingMode.All -> "all"
            | SshdForwardingMode.No -> "no"
            | SshdForwardingMode.Local -> "local"
            | SshdForwardingMode.Remote -> "remote"

        directive "AllowTcpForwarding" token

    let allowUsers value = directive "AllowUsers" value
    let allowUsersList values = list "AllowUsers" values
    let authenticationMethods value = directive "AuthenticationMethods" value
    let authorizedKeysCommand value = directive "AuthorizedKeysCommand" value

    let authorizedKeysCommandUser value =
        directive "AuthorizedKeysCommandUser" value

    let authorizedKeysFile value = directive "AuthorizedKeysFile" value

    let authorizedPrincipalsCommand value =
        directive "AuthorizedPrincipalsCommand" value

    let authorizedPrincipalsCommandUser value =
        directive "AuthorizedPrincipalsCommandUser" value

    let authorizedPrincipalsFile value =
        directive "AuthorizedPrincipalsFile" value

    let banner value = directive "Banner" value
    let caSignatureAlgorithms value = directive "CASignatureAlgorithms" value

    let channelTimeout (value: SshdChannelTimeout) =
        match value with
        | SshdChannelTimeout.Disabled -> directive "ChannelTimeout" "none"
        | SshdChannelTimeout.Timeouts [] ->
            invalidArg "value" "ChannelTimeout requires at least one timeout entry."
        | SshdChannelTimeout.Timeouts entries ->
            entries
            |> List.map (fun entry ->
                renderChannel entry.Channel
                + "="
                + renderSeconds "InactiveFor" true entry.InactiveFor)
            |> String.concat " "
            |> directive "ChannelTimeout"

    let chrootDirectory value = directive "ChrootDirectory" value
    let ciphers value = directive "Ciphers" value

    let clientAliveCountMax value =
        integerInRange "ClientAliveCountMax" 0 Int32.MaxValue value

    let clientAliveInterval (value: SshdClientAliveInterval) =
        let seconds =
            match value with
            | SshdClientAliveInterval.Disabled -> "0"
            | SshdClientAliveInterval.Every interval ->
                renderSeconds "ClientAliveInterval" false interval

        directive "ClientAliveInterval" seconds

    let compression (value: SshdCompression) =
        let token =
            match value with
            | SshdCompression.Yes -> "yes"
            | SshdCompression.Delayed -> "delayed"
            | SshdCompression.No -> "no"

        directive "Compression" token

    let debianBanner value = boolean "DebianBanner" value
    let denyGroups value = directive "DenyGroups" value
    let denyGroupsList values = list "DenyGroups" values
    let denyUsers value = directive "DenyUsers" value
    let denyUsersList values = list "DenyUsers" values
    let disableForwarding value = boolean "DisableForwarding" value
    let exposeAuthInfo value = boolean "ExposeAuthInfo" value

    let fingerprintHash (value: SshdFingerprintHash) =
        let token =
            match value with
            | SshdFingerprintHash.Md5 -> "md5"
            | SshdFingerprintHash.Sha256 -> "sha256"

        directive "FingerprintHash" token

    let forceCommand value = directive "ForceCommand" value

    let gatewayPorts (value: SshdGatewayPorts) =
        let token =
            match value with
            | SshdGatewayPorts.No -> "no"
            | SshdGatewayPorts.Yes -> "yes"
            | SshdGatewayPorts.ClientSpecified -> "clientspecified"

        directive "GatewayPorts" token

    let gssapiAuthentication value = boolean "GSSAPIAuthentication" value

    let gssapiCleanupCredentials value =
        boolean "GSSAPICleanupCredentials" value

    let gssapiKeyExchange value = boolean "GSSAPIKeyExchange" value

    let gssapiStrictAcceptorCheck value =
        boolean "GSSAPIStrictAcceptorCheck" value

    let gssapiStoreCredentialsOnRekey value =
        boolean "GSSAPIStoreCredentialsOnRekey" value

    let gssapiKexAlgorithms value = directive "GSSAPIKexAlgorithms" value

    let hostbasedAcceptedAlgorithms value =
        directive "HostbasedAcceptedAlgorithms" value

    let hostbasedAuthentication value = boolean "HostbasedAuthentication" value

    let hostbasedUsesNameFromPacketOnly value =
        boolean "HostbasedUsesNameFromPacketOnly" value

    let hostCertificate value = directive "HostCertificate" value

    let hostCertificateList values =
        values |> Seq.map (directive "HostCertificate") |> Seq.toList

    let hostKey value = directive "HostKey" value

    let hostKeyList values =
        values |> Seq.map (directive "HostKey") |> Seq.toList

    let hostKeyAgent value = directive "HostKeyAgent" value
    let hostKeyAlgorithms value = directive "HostKeyAlgorithms" value

    let ignoreRhosts (value: SshdIgnoreRhosts) =
        let token =
            match value with
            | SshdIgnoreRhosts.Yes -> "yes"
            | SshdIgnoreRhosts.No -> "no"
            | SshdIgnoreRhosts.ShostsOnly -> "shosts-only"

        directive "IgnoreRhosts" token

    let ignoreUserKnownHosts value = boolean "IgnoreUserKnownHosts" value
    let includePath value = directive "Include" value
    let includePaths values = list "Include" values

    let ipQos (value: SshdIpQos) =
        let interactive = renderIpQosValue value.Interactive

        let arguments =
            match value.Bulk with
            | None -> interactive
            | Some bulk -> interactive + " " + renderIpQosValue bulk

        directive "IPQoS" arguments

    let kbdInteractiveAuthentication value =
        boolean "KbdInteractiveAuthentication" value

    let kerberosAuthentication value = boolean "KerberosAuthentication" value
    let kerberosGetAFSToken value = boolean "KerberosGetAFSToken" value
    let kerberosOrLocalPasswd value = boolean "KerberosOrLocalPasswd" value
    let kerberosTicketCleanup value = boolean "KerberosTicketCleanup" value
    let kexAlgorithms value = directive "KexAlgorithms" value

    let listenAddress (address: SshdListenAddress) =
        renderListenAddress address |> directive "ListenAddress"

    let listenAddresses (addresses: seq<SshdListenAddress>) =
        addresses
        |> Seq.map (fun address -> renderListenAddress address |> directive "ListenAddress")
        |> Seq.toList

    let loginGraceTime (value: SshdLoginGraceTime) =
        let seconds =
            match value with
            | SshdLoginGraceTime.NoLimit -> "0"
            | SshdLoginGraceTime.LimitedTo duration ->
                renderSeconds "LoginGraceTime" false duration

        directive "LoginGraceTime" seconds

    let logLevel (value: SshdLogLevel) =
        let token =
            match value with
            | SshdLogLevel.Quiet -> "QUIET"
            | SshdLogLevel.Fatal -> "FATAL"
            | SshdLogLevel.Error -> "ERROR"
            | SshdLogLevel.Info -> "INFO"
            | SshdLogLevel.Verbose -> "VERBOSE"
            | SshdLogLevel.Debug -> "DEBUG"
            | SshdLogLevel.Debug1 -> "DEBUG1"
            | SshdLogLevel.Debug2 -> "DEBUG2"
            | SshdLogLevel.Debug3 -> "DEBUG3"

        directive "LogLevel" token

    let logVerbose value = directive "LogVerbose" value
    let macs value = directive "MACs" value

    let maxAuthTries value =
        integerInRange "MaxAuthTries" 0 Int32.MaxValue value

    let maxSessions value =
        integerInRange "MaxSessions" 0 Int32.MaxValue value

    let maxStartups (value: SshdMaxStartups) =
        let arguments =
            match value with
            | SshdMaxStartups.Limit count ->
                validateInteger "MaxStartups" 1 Int32.MaxValue count
            | SshdMaxStartups.RandomEarlyDrop limits ->
                let start = validateInteger "Start" 1 Int32.MaxValue limits.Start
                let rate = validateInteger "Rate" 1 100 limits.Rate
                let full = validateInteger "Full" 1 Int32.MaxValue limits.Full

                if limits.Start > limits.Full then
                    invalidArg "Full" "MaxStartups start must not exceed full."

                start + ":" + rate + ":" + full

        directive "MaxStartups" arguments

    let moduliFile value = directive "ModuliFile" value
    let pamServiceName value = directive "PAMServiceName" value
    let passwordAuthentication value = boolean "PasswordAuthentication" value
    let permitEmptyPasswords value = boolean "PermitEmptyPasswords" value

    let permitListen (value: SshdPermitListen) =
        let arguments =
            match value with
            | SshdPermitListen.Any -> "any"
            | SshdPermitListen.None -> "none"
            | SshdPermitListen.Addresses [] ->
                invalidArg "value" "PermitListen requires at least one address."
            | SshdPermitListen.Addresses addresses ->
                addresses
                |> List.map (fun address -> renderForwardingAddress address.Host address.Port)
                |> String.concat " "

        directive "PermitListen" arguments

    let permitOpen (value: SshdPermitOpen) =
        let arguments =
            match value with
            | SshdPermitOpen.Any -> "any"
            | SshdPermitOpen.None -> "none"
            | SshdPermitOpen.Destinations [] ->
                invalidArg "value" "PermitOpen requires at least one destination."
            | SshdPermitOpen.Destinations destinations ->
                destinations
                |> List.map renderPermitOpenDestination
                |> String.concat " "

        directive "PermitOpen" arguments

    let permitRootLogin (value: SshdRootLogin) =
        let token =
            match value with
            | SshdRootLogin.Yes -> "yes"
            | SshdRootLogin.No -> "no"
            | SshdRootLogin.ProhibitPassword -> "prohibit-password"
            | SshdRootLogin.ForcedCommandsOnly -> "forced-commands-only"

        directive "PermitRootLogin" token

    let permitTTY value = boolean "PermitTTY" value

    let permitTunnel (value: SshdPermitTunnel) =
        let token =
            match value with
            | SshdPermitTunnel.Yes -> "yes"
            | SshdPermitTunnel.PointToPoint -> "point-to-point"
            | SshdPermitTunnel.Ethernet -> "ethernet"
            | SshdPermitTunnel.No -> "no"

        directive "PermitTunnel" token

    let permitUserEnvironment (value: SshdPermitUserEnvironment) =
        let arguments =
            match value with
            | SshdPermitUserEnvironment.Yes -> "yes"
            | SshdPermitUserEnvironment.No -> "no"
            | SshdPermitUserEnvironment.Patterns patterns ->
                let patterns = validateSingleToken "Patterns" patterns

                if
                    String.Equals(patterns, "yes", StringComparison.Ordinal)
                    || String.Equals(patterns, "no", StringComparison.Ordinal)
                then
                    invalidArg "Patterns" "Use the explicit Yes or No case for these native sentinel values."

                patterns

        directive "PermitUserEnvironment" arguments

    let permitUserRC value = boolean "PermitUserRC" value

    let perSourceMaxStartups (value: SshdPerSourceMaxStartups) =
        let arguments =
            match value with
            | SshdPerSourceMaxStartups.Unlimited -> "none"
            | SshdPerSourceMaxStartups.Limit count ->
                validateInteger "PerSourceMaxStartups" 0 Int32.MaxValue count

        directive "PerSourceMaxStartups" arguments

    let perSourceNetBlockSize (value: SshdPerSourceNetBlockSize) =
        let ipv4 = validateInteger "IPv4Prefix" 0 32 value.IPv4Prefix
        let ipv6 = validateInteger "IPv6Prefix" 0 128 (defaultArg value.IPv6Prefix 128)
        directive "PerSourceNetBlockSize" (ipv4 + ":" + ipv6)

    let perSourcePenalties (value: SshdPerSourcePenalties) =
        let arguments =
            match value with
            | SshdPerSourcePenalties.Disabled -> "no"
            | SshdPerSourcePenalties.Enabled -> "yes"
            | SshdPerSourcePenalties.Configured [] ->
                invalidArg "value" "PerSourcePenalties requires at least one setting."
            | SshdPerSourcePenalties.Configured settings ->
                settings |> List.map renderPerSourcePenalty |> String.concat " "

        directive "PerSourcePenalties" arguments

    let perSourcePenaltyExemptList value =
        directive "PerSourcePenaltyExemptList" value

    let pidFile value = directive "PidFile" value

    let port value =
        integerInRange "Port" 1 65535 value

    let ports values =
        values |> Seq.map port |> Seq.toList

    let printLastLog value = boolean "PrintLastLog" value
    let printMotd value = boolean "PrintMotd" value

    let pubkeyAcceptedAlgorithms value =
        directive "PubkeyAcceptedAlgorithms" value

    let pubkeyAuthOptions (value: SshdPubkeyAuthOptions) =
        let arguments =
            match value with
            | SshdPubkeyAuthOptions.None -> "none"
            | SshdPubkeyAuthOptions.Options [] ->
                invalidArg "value" "PubkeyAuthOptions requires at least one option."
            | SshdPubkeyAuthOptions.Options options ->
                options
                |> List.map (function
                    | SshdPubkeyAuthOption.TouchRequired -> "touch-required"
                    | SshdPubkeyAuthOption.VerifyRequired -> "verify-required")
                |> String.concat " "

        directive "PubkeyAuthOptions" arguments

    let pubkeyAuthentication value = boolean "PubkeyAuthentication" value
    let refuseConnection value = boolean "RefuseConnection" value

    let rekeyLimit (value: SshdRekeyLimit) =
        let data =
            match value.DataLimit with
            | SshdRekeyDataLimit.Default -> "default"
            | SshdRekeyDataLimit.Bytes bytes ->
                if bytes < 16L<B> then
                    invalidArg "DataLimit" "RekeyLimit bytes must be at least 16."

                (int64 bytes).ToString(CultureInfo.InvariantCulture)

        let interval =
            match value.TimeLimit with
            | None -> "none"
            | Some duration -> renderSeconds "TimeLimit" false duration

        directive "RekeyLimit" (data + " " + interval)

    let requiredRsaSize value =
        integerInRange "RequiredRSASize" 1024 Int32.MaxValue value

    let revokedKeys value = directive "RevokedKeys" value
    let securityKeyProvider value = directive "SecurityKeyProvider" value
    let setEnv value = directive "SetEnv" value
    let setEnvList values = list "SetEnv" values
    let sshdAuthPath value = directive "SshdAuthPath" value
    let sshdSessionPath value = directive "SshdSessionPath" value

    let streamLocalBindMask value =
        validateInteger "StreamLocalBindMask" 0 0o777 value |> ignore
        let octal = Convert.ToString(value, 8).PadLeft(3, '0')
        directive "StreamLocalBindMask" ("0" + octal)

    let streamLocalBindUnlink value = boolean "StreamLocalBindUnlink" value
    let strictModes value = boolean "StrictModes" value
    let subsystem value = directive "Subsystem" value

    let syslogFacility (value: SshdSyslogFacility) =
        let token =
            match value with
            | SshdSyslogFacility.Daemon -> "DAEMON"
            | SshdSyslogFacility.User -> "USER"
            | SshdSyslogFacility.Auth -> "AUTH"
            | SshdSyslogFacility.AuthPriv -> "AUTHPRIV"
            | SshdSyslogFacility.Local0 -> "LOCAL0"
            | SshdSyslogFacility.Local1 -> "LOCAL1"
            | SshdSyslogFacility.Local2 -> "LOCAL2"
            | SshdSyslogFacility.Local3 -> "LOCAL3"
            | SshdSyslogFacility.Local4 -> "LOCAL4"
            | SshdSyslogFacility.Local5 -> "LOCAL5"
            | SshdSyslogFacility.Local6 -> "LOCAL6"
            | SshdSyslogFacility.Local7 -> "LOCAL7"

        directive "SyslogFacility" token

    let tcpKeepAlive value = boolean "TCPKeepAlive" value
    let trustedUserCAKeys value = directive "TrustedUserCAKeys" value

    let unusedConnectionTimeout (value: SshdUnusedConnectionTimeout) =
        let seconds =
            match value with
            | SshdUnusedConnectionTimeout.Never -> "none"
            | SshdUnusedConnectionTimeout.After duration ->
                renderSeconds "UnusedConnectionTimeout" false duration

        directive "UnusedConnectionTimeout" seconds

    let useDns value = boolean "UseDNS" value
    let usePam value = boolean "UsePAM" value
    let versionAddendum value = directive "VersionAddendum" value

    let x11DisplayOffset value =
        integerInRange "X11DisplayOffset" 0 Int32.MaxValue value

    let x11Forwarding value = boolean "X11Forwarding" value
    let x11UseLocalhost value = boolean "X11UseLocalhost" value
    let xAuthLocation value = directive "XAuthLocation" value

    /// Represents any native or future OpenSSH directive without a closed key allowlist.
    let extension keyword arguments = directive keyword arguments

[<Sealed>]
type SshdMatchBuilder(criteria: string) =
    member _.Yield(part: SshdConfigPart) = [ part ]
    member _.YieldFrom(parts: seq<SshdConfigPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: SshdConfigPart list, right: SshdConfigPart list) = left @ right
    member _.Delay(generator: unit -> SshdConfigPart list) = generator ()

    member _.For(values: seq<'T>, body: 'T -> SshdConfigPart list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(parts: SshdConfigPart list) = SshdConfigPart.Match(criteria, parts)

[<Sealed>]
type SshdConfigBuilder() =
    member _.Yield(part: SshdConfigPart) = [ part ]
    member _.YieldFrom(parts: seq<SshdConfigPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: SshdConfigPart list, right: SshdConfigPart list) = left @ right
    member _.Delay(generator: unit -> SshdConfigPart list) = generator ()

    member _.For(values: seq<'T>, body: 'T -> SshdConfigPart list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(parts: SshdConfigPart list) = SshdConfigSpec(SshdNative.render parts)

[<Sealed>]
type SshdBuilder() =
    member _.Yield(config: SshdConfigSpec) =
        [ SshdDeclaration.SshdConfigDeclaration config ]

    member _.Yield(fail2ban: Fail2BanInputSpec) =
        [ SshdDeclaration.Fail2BanDeclaration fail2ban ]

    member _.YieldFrom(configurations: seq<SshdConfigSpec>) =
        configurations |> Seq.map SshdDeclaration.SshdConfigDeclaration |> Seq.toList

    member _.YieldFrom(configurations: seq<Fail2BanInputSpec>) =
        configurations |> Seq.map SshdDeclaration.Fail2BanDeclaration |> Seq.toList

    member _.YieldFrom(declarations: seq<SshdDeclaration>) = Seq.toList declarations
    member _.Zero() = []
    member _.Combine(left: SshdDeclaration list, right: SshdDeclaration list) = left @ right
    member _.Delay(generator: unit -> SshdDeclaration list) = generator ()

    member _.For(values: seq<'T>, body: 'T -> SshdDeclaration list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: SshdDeclaration list) =
        let config =
            declarations
            |> List.choose (function
                | SshdDeclaration.SshdConfigDeclaration value -> Some value
                | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "sshd" "An sshd declaration may contain a config block only once."

        let fail2ban =
            declarations
            |> List.choose (function
                | SshdDeclaration.Fail2BanDeclaration value -> Some value
                | _ -> None)
            |> function
                | [] -> None
                | [ value ] -> Some value
                | _ -> invalidArg "sshd" "An sshd declaration may contain a fail2ban block only once."

        SshdSpec(config, fail2ban)

[<AutoOpen>]
module SshdBuilders =
    let config = SshdConfigBuilder()
    let sshd = SshdBuilder()
    let matchBlock criteria = SshdMatchBuilder(criteria)
    let nativeText text = SshdConfigPart.NativeText text
    let directive keyword arguments = SshdNative.directive keyword arguments
    let includeConfig paths = SshdOptions.includePaths paths

    let passwordAuthentication value =
        SshdOptions.passwordAuthentication value

    let kbdInteractiveAuthentication value =
        SshdOptions.kbdInteractiveAuthentication value

    let pubkeyAuthentication value = SshdOptions.pubkeyAuthentication value

    let permitRootLogin value =
        SshdOptions.permitRootLogin value

    let port value = SshdOptions.port value
    let maxAuthTries value = SshdOptions.maxAuthTries value

    let Yes = SshdRootLogin.Yes
    let No = SshdRootLogin.No
    let ProhibitPassword = SshdRootLogin.ProhibitPassword
    let ForcedCommandsOnly = SshdRootLogin.ForcedCommandsOnly
