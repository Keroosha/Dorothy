# SSH directive catalogue

The catalogue follows the [Debian 13 sshd_config manual](https://manpages.debian.org/trixie/openssh-server/sshd_config.5.en.html): all 106 canonical directives remain available. These examples are not one combined deployable configuration; referenced files/accounts and build-dependent features must exist on the target. `SshdOptions` is qualified to avoid colliding with proxy/container option names. Named options use `TimeSpan`, measured byte sizes, integer counts, closed discriminated unions, or structured records where the native grammar has those semantics. Open-ended lists, patterns, commands, and algorithm expressions remain strings. Repeatable directives preserve call order; `Match` is structural and `Include` has dedicated path helpers. Every example is valid inside `config { ... }`.

| Canonical directive | Public API / argument shape / sample |
|---|---|
| `AcceptEnv` | `SshdOptions.acceptEnv : string -> SshdConfigPart` (also `acceptEnvList : seq<string> -> SshdConfigPart`); `SshdOptions.acceptEnv "LANG LC_*"` |
| `AddressFamily` | `addressFamily : SshdAddressFamily`; `SshdOptions.addressFamily SshdAddressFamily.IPv6` |
| `AllowAgentForwarding` | `allowAgentForwarding : bool`; `SshdOptions.allowAgentForwarding false` |
| `AllowGroups` | `allowGroups : string` (also `allowGroupsList`); `SshdOptions.allowGroups "admins ssh-ops"` |
| `AllowStreamLocalForwarding` | `allowStreamLocalForwarding : SshdForwardingMode`; `SshdOptions.allowStreamLocalForwarding SshdForwardingMode.Local` |
| `AllowTcpForwarding` | `allowTcpForwarding : SshdForwardingMode`; `SshdOptions.allowTcpForwarding SshdForwardingMode.Remote` |
| `AllowUsers` | `allowUsers : string` (also `allowUsersList`); `SshdOptions.allowUsers "deploy@192.0.2.*"` |
| `AuthenticationMethods` | `authenticationMethods : string`; `SshdOptions.authenticationMethods "publickey,password publickey,keyboard-interactive"` |
| `AuthorizedKeysCommand` | `authorizedKeysCommand : string`; `SshdOptions.authorizedKeysCommand "/usr/local/bin/keys %u"` |
| `AuthorizedKeysCommandUser` | `authorizedKeysCommandUser : string`; `SshdOptions.authorizedKeysCommandUser "nobody"` |
| `AuthorizedKeysFile` | `authorizedKeysFile : string`; `SshdOptions.authorizedKeysFile ".ssh/authorized_keys .ssh/authorized_keys2"` |
| `AuthorizedPrincipalsCommand` | `authorizedPrincipalsCommand : string`; `SshdOptions.authorizedPrincipalsCommand "/usr/local/bin/principals %u"` |
| `AuthorizedPrincipalsCommandUser` | `authorizedPrincipalsCommandUser : string`; `SshdOptions.authorizedPrincipalsCommandUser "nobody"` |
| `AuthorizedPrincipalsFile` | `authorizedPrincipalsFile : string`; `SshdOptions.authorizedPrincipalsFile ".ssh/principals"` |
| `CASignatureAlgorithms` | `caSignatureAlgorithms : string`; `SshdOptions.caSignatureAlgorithms "+ssh-ed25519"` |
| `ChannelTimeout` | `channelTimeout : SshdChannelTimeout`; `SshdOptions.channelTimeout (SshdChannelTimeout.Timeouts [ { Channel = SshdChannel.Session; InactiveFor = TimeSpan.FromMinutes 5.0 } ])` |
| `ChrootDirectory` | `chrootDirectory : string`; `SshdOptions.chrootDirectory "/srv/%u"` |
| `Ciphers` | `ciphers : string`; `SshdOptions.ciphers "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"` |
| `ClientAliveCountMax` | `clientAliveCountMax : int`; `SshdOptions.clientAliveCountMax 3` |
| `ClientAliveInterval` | `clientAliveInterval : SshdClientAliveInterval`; `SshdOptions.clientAliveInterval (SshdClientAliveInterval.Every(TimeSpan.FromSeconds 45.0))` |
| `Compression` | `compression : SshdCompression`; `SshdOptions.compression SshdCompression.Delayed` |
| `DebianBanner` | `debianBanner : bool`; `SshdOptions.debianBanner false` |
| `DenyGroups` | `denyGroups : string` (also `denyGroupsList`); `SshdOptions.denyGroups "retired-accounts"` |
| `DenyUsers` | `denyUsers : string` (also `denyUsersList`); `SshdOptions.denyUsers "guest"` |
| `DisableForwarding` | `disableForwarding : bool`; `SshdOptions.disableForwarding true` |
| `ExposeAuthInfo` | `exposeAuthInfo : bool`; `SshdOptions.exposeAuthInfo true` |
| `FingerprintHash` | `fingerprintHash : SshdFingerprintHash`; `SshdOptions.fingerprintHash SshdFingerprintHash.Sha256` |
| `ForceCommand` | `forceCommand : string`; `SshdOptions.forceCommand "internal-sftp -d /srv/files"` |
| `GatewayPorts` | `gatewayPorts : SshdGatewayPorts`; `SshdOptions.gatewayPorts SshdGatewayPorts.ClientSpecified` |
| `GSSAPIAuthentication` | `gssapiAuthentication : bool`; `SshdOptions.gssapiAuthentication false` |
| `GSSAPICleanupCredentials` | `gssapiCleanupCredentials : bool`; `SshdOptions.gssapiCleanupCredentials true` |
| `GSSAPIKeyExchange` | `gssapiKeyExchange : bool`; `SshdOptions.gssapiKeyExchange false` |
| `GSSAPIStrictAcceptorCheck` | `gssapiStrictAcceptorCheck : bool`; `SshdOptions.gssapiStrictAcceptorCheck true` |
| `GSSAPIStoreCredentialsOnRekey` | `gssapiStoreCredentialsOnRekey : bool`; `SshdOptions.gssapiStoreCredentialsOnRekey false` |
| `GSSAPIKexAlgorithms` | `gssapiKexAlgorithms : string`; `SshdOptions.gssapiKexAlgorithms "gss-curve25519-sha256-"` |
| `HostbasedAcceptedAlgorithms` | `hostbasedAcceptedAlgorithms : string`; `SshdOptions.hostbasedAcceptedAlgorithms "ssh-ed25519"` |
| `HostbasedAuthentication` | `hostbasedAuthentication : bool`; `SshdOptions.hostbasedAuthentication false` |
| `HostbasedUsesNameFromPacketOnly` | `hostbasedUsesNameFromPacketOnly : bool`; `SshdOptions.hostbasedUsesNameFromPacketOnly true` |
| `HostCertificate` | `hostCertificate : string` (also `hostCertificateList`, which emits repeated lines); `SshdOptions.hostCertificate "/etc/ssh/host-cert.pub"` |
| `HostKey` | `hostKey : string` (also `hostKeyList`, which emits repeated lines); `SshdOptions.hostKey "/etc/ssh/ssh_host_ed25519_key"` |
| `HostKeyAgent` | `hostKeyAgent : string`; `SshdOptions.hostKeyAgent "SSH_AUTH_SOCK"` |
| `HostKeyAlgorithms` | `hostKeyAlgorithms : string`; `SshdOptions.hostKeyAlgorithms "ssh-ed25519,rsa-sha2-512"` |
| `IgnoreRhosts` | `ignoreRhosts : SshdIgnoreRhosts`; `SshdOptions.ignoreRhosts SshdIgnoreRhosts.ShostsOnly` |
| `IgnoreUserKnownHosts` | `ignoreUserKnownHosts : bool`; `SshdOptions.ignoreUserKnownHosts true` |
| `Include` | `includePath : string` and `includePaths : seq<string>`; `SshdOptions.includePath "/etc/ssh/extra/*.conf"` |
| `IPQoS` | `ipQos : SshdIpQos` (one value or an interactive/bulk pair); `SshdOptions.ipQos { Interactive = SshdIpQosValue.Af21; Bulk = Some SshdIpQosValue.Cs1 }` |
| `KbdInteractiveAuthentication` | `kbdInteractiveAuthentication : bool`; `SshdOptions.kbdInteractiveAuthentication false` |
| `KerberosAuthentication` | `kerberosAuthentication : bool`; `SshdOptions.kerberosAuthentication false` |
| `KerberosGetAFSToken` | `kerberosGetAFSToken : bool`; `SshdOptions.kerberosGetAFSToken false` |
| `KerberosOrLocalPasswd` | `kerberosOrLocalPasswd : bool`; `SshdOptions.kerberosOrLocalPasswd true` |
| `KerberosTicketCleanup` | `kerberosTicketCleanup : bool`; `SshdOptions.kerberosTicketCleanup true` |
| `KexAlgorithms` | `kexAlgorithms : string`; `SshdOptions.kexAlgorithms "+curve25519-sha256"` |
| `ListenAddress` | `listenAddress : SshdListenAddress` (also `listenAddresses : seq<SshdListenAddress>`, which emits repeated lines); `SshdOptions.listenAddress { Address = "192.0.2.10"; Port = Some(SshdForwardPort.Number 2222); RoutingDomain = None }` |
| `LoginGraceTime` | `loginGraceTime : SshdLoginGraceTime`; `SshdOptions.loginGraceTime (SshdLoginGraceTime.LimitedTo(TimeSpan.FromSeconds 30.0))` |
| `LogLevel` | `logLevel : SshdLogLevel`; `SshdOptions.logLevel SshdLogLevel.Verbose` |
| `LogVerbose` | `logVerbose : string`; `SshdOptions.logVerbose "kex.c:*:100"` |
| `MACs` | `macs : string`; `SshdOptions.macs "hmac-sha2-512-etm@openssh.com"` |
| `Match` | Structural `matchBlock : string -> SshdMatchBuilder`; `matchBlock "User deploy" { SshdOptions.passwordAuthentication false }` |
| `MaxAuthTries` | `maxAuthTries : int`; `SshdOptions.maxAuthTries 6` |
| `MaxSessions` | `maxSessions : int`; `SshdOptions.maxSessions 10` |
| `MaxStartups` | `maxStartups : SshdMaxStartups`; `SshdOptions.maxStartups (SshdMaxStartups.RandomEarlyDrop { Start = 10; Rate = 30; Full = 60 })` (also `Limit 25`) |
| `ModuliFile` | `moduliFile : string`; `SshdOptions.moduliFile "/etc/ssh/moduli"` |
| `PAMServiceName` | `pamServiceName : string`; `SshdOptions.pamServiceName "sshd"` |
| `PasswordAuthentication` | `passwordAuthentication : bool`; `SshdOptions.passwordAuthentication false` |
| `PermitEmptyPasswords` | `permitEmptyPasswords : bool`; `SshdOptions.permitEmptyPasswords false` |
| `PermitListen` | `permitListen : SshdPermitListen`; `SshdOptions.permitListen (SshdPermitListen.Addresses [ { Host = None; Port = SshdForwardPort.Number 8080 } ])` |
| `PermitOpen` | `permitOpen : SshdPermitOpen`; `SshdOptions.permitOpen (SshdPermitOpen.Destinations [ { Host = "db.internal"; Port = SshdForwardPort.Number 5432 } ])` |
| `PermitRootLogin` | `permitRootLogin : SshdRootLogin`; `SshdOptions.permitRootLogin SshdRootLogin.ProhibitPassword` |
| `PermitTTY` | `permitTTY : bool`; `SshdOptions.permitTTY false` |
| `PermitTunnel` | `permitTunnel : SshdPermitTunnel`; `SshdOptions.permitTunnel SshdPermitTunnel.PointToPoint` |
| `PermitUserEnvironment` | `permitUserEnvironment : SshdPermitUserEnvironment`; `SshdOptions.permitUserEnvironment (SshdPermitUserEnvironment.Patterns "LANG,LC_*")` |
| `PermitUserRC` | `permitUserRC : bool`; `SshdOptions.permitUserRC false` |
| `PerSourceMaxStartups` | `perSourceMaxStartups : SshdPerSourceMaxStartups`; `SshdOptions.perSourceMaxStartups SshdPerSourceMaxStartups.Unlimited` |
| `PerSourceNetBlockSize` | `perSourceNetBlockSize : SshdPerSourceNetBlockSize`; `SshdOptions.perSourceNetBlockSize { IPv4Prefix = 32; IPv6Prefix = Some 128 }` |
| `PerSourcePenalties` | `perSourcePenalties : SshdPerSourcePenalties`; `SshdOptions.perSourcePenalties (SshdPerSourcePenalties.Configured [ SshdPerSourcePenalty.AuthFail(TimeSpan.FromSeconds 5.0) ])` |
| `PerSourcePenaltyExemptList` | `perSourcePenaltyExemptList : string`; `SshdOptions.perSourcePenaltyExemptList "192.0.2.0/24,2001:db8::/32"` |
| `PidFile` | `pidFile : string`; `SshdOptions.pidFile "/run/sshd.pid"` |
| `Port` | `port : int` (also `ports`, which emits repeated lines); `SshdOptions.port 2222` |
| `PrintLastLog` | `printLastLog : bool`; `SshdOptions.printLastLog true` |
| `PrintMotd` | `printMotd : bool`; `SshdOptions.printMotd false` |
| `PubkeyAcceptedAlgorithms` | `pubkeyAcceptedAlgorithms : string`; `SshdOptions.pubkeyAcceptedAlgorithms "+ssh-ed25519"` |
| `PubkeyAuthOptions` | `pubkeyAuthOptions : SshdPubkeyAuthOptions`; `SshdOptions.pubkeyAuthOptions (SshdPubkeyAuthOptions.Options [ SshdPubkeyAuthOption.TouchRequired; SshdPubkeyAuthOption.VerifyRequired ])` |
| `PubkeyAuthentication` | `pubkeyAuthentication : bool`; `SshdOptions.pubkeyAuthentication true` |
| `RefuseConnection` | `refuseConnection : bool`; `SshdOptions.refuseConnection false` |
| `RekeyLimit` | `rekeyLimit : SshdRekeyLimit`; `SshdOptions.rekeyLimit { DataLimit = SshdRekeyDataLimit.Bytes 3_221_225_472L<B>; TimeLimit = Some(TimeSpan.FromHours 1.0) }` |
| `RequiredRSASize` | `requiredRsaSize : int`; `SshdOptions.requiredRsaSize 3072` |
| `RevokedKeys` | `revokedKeys : string`; `SshdOptions.revokedKeys "/etc/ssh/revoked.krl"` |
| `SecurityKeyProvider` | `securityKeyProvider : string`; `SshdOptions.securityKeyProvider "internal"` |
| `SetEnv` | `setEnv : string` (also `setEnvList`); `SshdOptions.setEnv "LANG=en_US.UTF-8"` |
| `SshdAuthPath` | `sshdAuthPath : string`; `SshdOptions.sshdAuthPath "/usr/lib/openssh/sshd-auth"` |
| `SshdSessionPath` | `sshdSessionPath : string`; `SshdOptions.sshdSessionPath "/usr/lib/openssh/sshd-session"` |
| `StreamLocalBindMask` | `streamLocalBindMask : int` (numeric mode value rendered in octal); `SshdOptions.streamLocalBindMask 0o177` |
| `StreamLocalBindUnlink` | `streamLocalBindUnlink : bool`; `SshdOptions.streamLocalBindUnlink true` |
| `StrictModes` | `strictModes : bool`; `SshdOptions.strictModes true` |
| `Subsystem` | `subsystem : string`; `SshdOptions.subsystem "sftp internal-sftp"` |
| `SyslogFacility` | `syslogFacility : SshdSyslogFacility`; `SshdOptions.syslogFacility SshdSyslogFacility.Auth` |
| `TCPKeepAlive` | `tcpKeepAlive : bool`; `SshdOptions.tcpKeepAlive true` |
| `TrustedUserCAKeys` | `trustedUserCAKeys : string`; `SshdOptions.trustedUserCAKeys "/etc/ssh/user-ca.pub"` |
| `UnusedConnectionTimeout` | `unusedConnectionTimeout : SshdUnusedConnectionTimeout`; `SshdOptions.unusedConnectionTimeout (SshdUnusedConnectionTimeout.After(TimeSpan.FromMinutes 5.0))` |
| `UseDNS` | `useDns : bool`; `SshdOptions.useDns false` |
| `UsePAM` | `usePam : bool`; `SshdOptions.usePam true` |
| `VersionAddendum` | `versionAddendum : string`; `SshdOptions.versionAddendum "build-42"` |
| `X11DisplayOffset` | `x11DisplayOffset : int`; `SshdOptions.x11DisplayOffset 10` |
| `X11Forwarding` | `x11Forwarding : bool`; `SshdOptions.x11Forwarding false` |
| `X11UseLocalhost` | `x11UseLocalhost : bool`; `SshdOptions.x11UseLocalhost true` |
| `XAuthLocation` | `xAuthLocation : string`; `SshdOptions.xAuthLocation "/usr/bin/xauth"` |

For completely native text, `nativeText "VendorOption argument-tail\n"` preserves a fragment in the same ordered stream. `SshdOptions.extension keyword argumentTail` emits an arbitrary one-line directive without a supported-name allowlist. The target daemon remains the syntax and build-feature authority.

## Typed values and native bounds

Assume `open System` for `TimeSpan` and `open Dorothy.DSL` for the public types. Finite OpenSSH times are exact whole seconds, serialized as invariant decimal seconds, and bounded by the native parser's `Int32.MaxValue` seconds. Sub-second values are rejected rather than rounded. Option-specific cases express native sentinels: `SshdLoginGraceTime.NoLimit` emits `0`, `SshdClientAliveInterval.Disabled` emits `0`, `SshdUnusedConnectionTimeout.Never` emits `none`, and `SshdChannelTimeout.Disabled` emits `none`. `ChannelTimeout` entries accept a zero interval to disable that channel's timeout. `SshdChannel.Session` renders `session*` to cover session, shell, command, and subsystem channels; `Shell`, `Command`, `Subsystem`, and `TunConnection` render `session:shell`, `session:command`, `session:subsystem:*`, and `tun`. Use `Pattern "session:subsystem:sftp"` for a specific subsystem.

`SshdRekeyLimit` separates data and time: `SshdRekeyDataLimit.Default` or `Bytes of int64<B>`, plus `TimeLimit : TimeSpan option`. `None` emits native `none`; a finite time must be whole seconds. Byte counts below 16 are rejected. For example, `SshdOptions.rekeyLimit { DataLimit = SshdRekeyDataLimit.Default; TimeLimit = Some(TimeSpan.FromHours 1.0) }` renders `RekeyLimit default 3600`.

`SshdMaxStartups` is either `Limit count` or `RandomEarlyDrop { Start; Rate; Full }`; the latter validates positive start/full values, a 1–100 rate, and `Start <= Full`. `SshdPerSourceMaxStartups.Unlimited` renders `none`. `SshdPerSourceNetBlockSize` validates IPv4 prefixes in 0–32 and IPv6 prefixes in 0–128; an omitted IPv6 prefix uses Debian 13's native default of 128. `SshdPerSourcePenalties` supports explicit `Disabled`/`Enabled` values and every native duration, source-count, and overflow-mode setting.

`SshdPermitOpen` and `SshdPermitListen` model native `Any`, `None`, and lists of structured endpoints. `SshdForwardPort.Number` accepts 1–65535, `ServiceName` accepts a native service token, and (for forwarding permissions) `Any` renders `*`. Permit-list host strings remain open so wildcard host patterns and IPv6 literals are expressible; IPv6 literals are bracketed by the renderer. In `PermitListen`, a missing host means the native port-only/localhost form. `SshdListenAddress` models address, optional numeric or service port, and optional routing domain.

Closed-mode unions cover address family, forwarding, compression, fingerprint hash, gateway binding, rhosts handling, log level, root login, tunnel, public-key authentication options, syslog facility, and IPQoS values. Native numeric inputs remain integers and are range-checked: listener ports are 1–65535, socket umasks 0–0o777, DSCP values 0–255, and source network prefixes match their address-family widths. `RequiredRSASize` is at least 1024 bits; zero is supported only for native count options where it has defined semantics. Counts are rendered with invariant culture. OpenSSH remains authoritative for hostnames, routing-domain validity, native build features, and all untyped extension arguments.
On Debian's Linux build, `SshdSyslogFacility.AuthPriv` is available when native headers define `LOG_AUTHPRIV`; optional facilities remain subject to the target platform build.
`IPQoS` also supports the native `LowDelay`, `Throughput`, and `Reliability` aliases, alongside AF/CS classes, `Ef`, `Le`, `OsDefault`, and numeric values 0–255.
Typed single-token fields reject whitespace, `#`, quotes, and NUL so native comment or quoting syntax cannot truncate generated directives. `PermitUserEnvironment.Patterns` preserves an open pattern-list string, except exact `yes`/`no` (case-sensitive), which are native sentinels represented by the explicit `Yes` and `No` cases.
