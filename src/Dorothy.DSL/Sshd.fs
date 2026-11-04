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

    let acceptEnv value = directive "AcceptEnv" value
    let acceptEnvList values = list "AcceptEnv" values
    let addressFamily value = directive "AddressFamily" value
    let allowAgentForwarding value = boolean "AllowAgentForwarding" value
    let allowGroups value = directive "AllowGroups" value
    let allowGroupsList values = list "AllowGroups" values

    let allowStreamLocalForwarding value =
        directive "AllowStreamLocalForwarding" value

    let allowTcpForwarding value = directive "AllowTcpForwarding" value
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
    let channelTimeout value = directive "ChannelTimeout" value
    let chrootDirectory value = directive "ChrootDirectory" value
    let ciphers value = directive "Ciphers" value
    let clientAliveCountMax value = integer "ClientAliveCountMax" value
    let clientAliveInterval value = directive "ClientAliveInterval" value
    let compression value = directive "Compression" value
    let debianBanner value = boolean "DebianBanner" value
    let denyGroups value = directive "DenyGroups" value
    let denyGroupsList values = list "DenyGroups" values
    let denyUsers value = directive "DenyUsers" value
    let denyUsersList values = list "DenyUsers" values
    let disableForwarding value = boolean "DisableForwarding" value
    let exposeAuthInfo value = boolean "ExposeAuthInfo" value
    let fingerprintHash value = directive "FingerprintHash" value
    let forceCommand value = directive "ForceCommand" value
    let gatewayPorts value = directive "GatewayPorts" value
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
    let ignoreRhosts value = directive "IgnoreRhosts" value
    let ignoreUserKnownHosts value = boolean "IgnoreUserKnownHosts" value
    let includePath value = directive "Include" value
    let includePaths values = list "Include" values
    let ipQos value = directive "IPQoS" value

    let kbdInteractiveAuthentication value =
        boolean "KbdInteractiveAuthentication" value

    let kerberosAuthentication value = boolean "KerberosAuthentication" value
    let kerberosGetAFSToken value = boolean "KerberosGetAFSToken" value
    let kerberosOrLocalPasswd value = boolean "KerberosOrLocalPasswd" value
    let kerberosTicketCleanup value = boolean "KerberosTicketCleanup" value
    let kexAlgorithms value = directive "KexAlgorithms" value
    let listenAddress value = directive "ListenAddress" value

    let listenAddresses values =
        values |> Seq.map (directive "ListenAddress") |> Seq.toList

    let loginGraceTime value = directive "LoginGraceTime" value
    let logLevel value = directive "LogLevel" value
    let logVerbose value = directive "LogVerbose" value
    let macs value = directive "MACs" value
    let maxAuthTries value = integer "MaxAuthTries" value
    let maxSessions value = integer "MaxSessions" value
    let maxStartups value = directive "MaxStartups" value
    let moduliFile value = directive "ModuliFile" value
    let pamServiceName value = directive "PAMServiceName" value
    let passwordAuthentication value = boolean "PasswordAuthentication" value
    let permitEmptyPasswords value = boolean "PermitEmptyPasswords" value
    let permitListen value = directive "PermitListen" value
    let permitOpen value = directive "PermitOpen" value
    let permitRootLogin value = directive "PermitRootLogin" value
    let permitTTY value = boolean "PermitTTY" value
    let permitTunnel value = directive "PermitTunnel" value
    let permitUserEnvironment value = directive "PermitUserEnvironment" value
    let permitUserEnvironmentEnabled value = boolean "PermitUserEnvironment" value
    let permitUserRC value = boolean "PermitUserRC" value
    let perSourceMaxStartups value = directive "PerSourceMaxStartups" value
    let perSourceNetBlockSize value = directive "PerSourceNetBlockSize" value
    let perSourcePenalties value = directive "PerSourcePenalties" value

    let perSourcePenaltyExemptList value =
        directive "PerSourcePenaltyExemptList" value

    let pidFile value = directive "PidFile" value
    let port value = integer "Port" value

    let ports values =
        values |> Seq.map (integer "Port") |> Seq.toList

    let printLastLog value = boolean "PrintLastLog" value
    let printMotd value = boolean "PrintMotd" value

    let pubkeyAcceptedAlgorithms value =
        directive "PubkeyAcceptedAlgorithms" value

    let pubkeyAuthOptions value = directive "PubkeyAuthOptions" value
    let pubkeyAuthentication value = boolean "PubkeyAuthentication" value
    let refuseConnection value = boolean "RefuseConnection" value
    let rekeyLimit value = directive "RekeyLimit" value
    let requiredRsaSize value = integer "RequiredRSASize" value
    let revokedKeys value = directive "RevokedKeys" value
    let securityKeyProvider value = directive "SecurityKeyProvider" value
    let setEnv value = directive "SetEnv" value
    let setEnvList values = list "SetEnv" values
    let sshdAuthPath value = directive "SshdAuthPath" value
    let sshdSessionPath value = directive "SshdSessionPath" value
    let streamLocalBindMask value = directive "StreamLocalBindMask" value
    let streamLocalBindUnlink value = boolean "StreamLocalBindUnlink" value
    let strictModes value = boolean "StrictModes" value
    let subsystem value = directive "Subsystem" value
    let syslogFacility value = directive "SyslogFacility" value
    let tcpKeepAlive value = boolean "TCPKeepAlive" value
    let trustedUserCAKeys value = directive "TrustedUserCAKeys" value

    let unusedConnectionTimeout value =
        directive "UnusedConnectionTimeout" value

    let useDns value = boolean "UseDNS" value
    let usePam value = boolean "UsePAM" value
    let versionAddendum value = directive "VersionAddendum" value
    let x11DisplayOffset value = integer "X11DisplayOffset" value
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
        let token =
            match value with
            | SshdRootLogin.Yes -> "yes"
            | SshdRootLogin.No -> "no"
            | SshdRootLogin.ProhibitPassword -> "prohibit-password"
            | SshdRootLogin.ForcedCommandsOnly -> "forced-commands-only"

        SshdOptions.permitRootLogin token

    let port value = SshdOptions.port value
    let maxAuthTries value = SshdOptions.maxAuthTries value

    let Yes = SshdRootLogin.Yes
    let No = SshdRootLogin.No
    let ProhibitPassword = SshdRootLogin.ProhibitPassword
    let ForcedCommandsOnly = SshdRootLogin.ForcedCommandsOnly
