# SSH directive catalogue

The catalogue follows the [Debian 13 sshd_config manual](https://manpages.debian.org/trixie/openssh-server/sshd_config.5.en.html): 106 canonical directives. These are syntax examples, not one combined deployable configuration; referenced files/accounts and build-dependent features must exist on the target. `SshdOptions` is qualified to avoid colliding with proxy/container option names. String arguments are complete native argument tails: no enum allowlist or scalar-key map is applied. Repeatable directives can be called repeatedly in the same order; collection helpers are shown where useful. `Match` is a structural block and `Include` has dedicated path helpers. Every example is an expression valid inside `config { ... }`.

| Canonical directive | Public API / argument shape / sample |
|---|---|
| `AcceptEnv` | `SshdOptions.acceptEnv : string -> SshdConfigPart` (also `acceptEnvList : seq<string> -> SshdConfigPart`); `SshdOptions.acceptEnv "LANG LC_*"` |
| `AddressFamily` | `addressFamily : string`; `SshdOptions.addressFamily "inet6"` |
| `AllowAgentForwarding` | `allowAgentForwarding : bool`; `SshdOptions.allowAgentForwarding false` |
| `AllowGroups` | `allowGroups : string` (also `allowGroupsList`); `SshdOptions.allowGroups "admins ssh-ops"` |
| `AllowStreamLocalForwarding` | `allowStreamLocalForwarding : string`; `SshdOptions.allowStreamLocalForwarding "local"` |
| `AllowTcpForwarding` | `allowTcpForwarding : string`; `SshdOptions.allowTcpForwarding "remote"` |
| `AllowUsers` | `allowUsers : string` (also `allowUsersList`); `SshdOptions.allowUsers "deploy@192.0.2.*"` |
| `AuthenticationMethods` | `authenticationMethods : string`; `SshdOptions.authenticationMethods "publickey,password publickey,keyboard-interactive"` |
| `AuthorizedKeysCommand` | `authorizedKeysCommand : string`; `SshdOptions.authorizedKeysCommand "/usr/local/bin/keys %u"` |
| `AuthorizedKeysCommandUser` | `authorizedKeysCommandUser : string`; `SshdOptions.authorizedKeysCommandUser "nobody"` |
| `AuthorizedKeysFile` | `authorizedKeysFile : string`; `SshdOptions.authorizedKeysFile ".ssh/authorized_keys .ssh/authorized_keys2"` |
| `AuthorizedPrincipalsCommand` | `authorizedPrincipalsCommand : string`; `SshdOptions.authorizedPrincipalsCommand "/usr/local/bin/principals %u"` |
| `AuthorizedPrincipalsCommandUser` | `authorizedPrincipalsCommandUser : string`; `SshdOptions.authorizedPrincipalsCommandUser "nobody"` |
| `AuthorizedPrincipalsFile` | `authorizedPrincipalsFile : string`; `SshdOptions.authorizedPrincipalsFile ".ssh/principals"` |
| `CASignatureAlgorithms` | `caSignatureAlgorithms : string`; `SshdOptions.caSignatureAlgorithms "+ssh-ed25519"` |
| `ChannelTimeout` | `channelTimeout : string`; `SshdOptions.channelTimeout "session=5m"` |
| `ChrootDirectory` | `chrootDirectory : string`; `SshdOptions.chrootDirectory "/srv/%u"` |
| `Ciphers` | `ciphers : string`; `SshdOptions.ciphers "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"` |
| `ClientAliveCountMax` | `clientAliveCountMax : int`; `SshdOptions.clientAliveCountMax 3` |
| `ClientAliveInterval` | `clientAliveInterval : string`; `SshdOptions.clientAliveInterval "45s"` |
| `Compression` | `compression : string`; `SshdOptions.compression "delayed"` |
| `DebianBanner` | `debianBanner : bool`; `SshdOptions.debianBanner false` |
| `DenyGroups` | `denyGroups : string` (also `denyGroupsList`); `SshdOptions.denyGroups "retired-accounts"` |
| `DenyUsers` | `denyUsers : string` (also `denyUsersList`); `SshdOptions.denyUsers "guest"` |
| `DisableForwarding` | `disableForwarding : bool`; `SshdOptions.disableForwarding true` |
| `ExposeAuthInfo` | `exposeAuthInfo : bool`; `SshdOptions.exposeAuthInfo true` |
| `FingerprintHash` | `fingerprintHash : string`; `SshdOptions.fingerprintHash "sha256"` |
| `ForceCommand` | `forceCommand : string`; `SshdOptions.forceCommand "internal-sftp -d /srv/files"` |
| `GatewayPorts` | `gatewayPorts : string`; `SshdOptions.gatewayPorts "clientspecified"` |
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
| `IgnoreRhosts` | `ignoreRhosts : string`; `SshdOptions.ignoreRhosts "shosts-only"` |
| `IgnoreUserKnownHosts` | `ignoreUserKnownHosts : bool`; `SshdOptions.ignoreUserKnownHosts true` |
| `Include` | `includePath : string` and `includePaths : seq<string>`; `SshdOptions.includePath "/etc/ssh/extra/*.conf"` |
| `IPQoS` | `ipQos : string`; `SshdOptions.ipQos "af21 cs1"` |
| `KbdInteractiveAuthentication` | `kbdInteractiveAuthentication : bool`; `SshdOptions.kbdInteractiveAuthentication false` |
| `KerberosAuthentication` | `kerberosAuthentication : bool`; `SshdOptions.kerberosAuthentication false` |
| `KerberosGetAFSToken` | `kerberosGetAFSToken : bool`; `SshdOptions.kerberosGetAFSToken false` |
| `KerberosOrLocalPasswd` | `kerberosOrLocalPasswd : bool`; `SshdOptions.kerberosOrLocalPasswd true` |
| `KerberosTicketCleanup` | `kerberosTicketCleanup : bool`; `SshdOptions.kerberosTicketCleanup true` |
| `KexAlgorithms` | `kexAlgorithms : string`; `SshdOptions.kexAlgorithms "+curve25519-sha256"` |
| `ListenAddress` | `listenAddress : string` (also `listenAddresses`, which emits repeated lines); `SshdOptions.listenAddress "192.0.2.10:2222"` |
| `LoginGraceTime` | `loginGraceTime : string`; `SshdOptions.loginGraceTime "30s"` |
| `LogLevel` | `logLevel : string`; `SshdOptions.logLevel "VERBOSE"` |
| `LogVerbose` | `logVerbose : string`; `SshdOptions.logVerbose "kex.c:*:100"` |
| `MACs` | `macs : string`; `SshdOptions.macs "hmac-sha2-512-etm@openssh.com"` |
| `Match` | Structural `matchBlock : string -> SshdMatchBuilder`; `matchBlock "User deploy" { SshdOptions.passwordAuthentication false }` |
| `MaxAuthTries` | `maxAuthTries : int`; `SshdOptions.maxAuthTries 6` |
| `MaxSessions` | `maxSessions : int`; `SshdOptions.maxSessions 10` |
| `MaxStartups` | `maxStartups : string`; `SshdOptions.maxStartups "10:30:60"` |
| `ModuliFile` | `moduliFile : string`; `SshdOptions.moduliFile "/etc/ssh/moduli"` |
| `PAMServiceName` | `pamServiceName : string`; `SshdOptions.pamServiceName "sshd"` |
| `PasswordAuthentication` | `passwordAuthentication : bool`; `SshdOptions.passwordAuthentication false` |
| `PermitEmptyPasswords` | `permitEmptyPasswords : bool`; `SshdOptions.permitEmptyPasswords false` |
| `PermitListen` | `permitListen : string`; `SshdOptions.permitListen "localhost:8080"` |
| `PermitOpen` | `permitOpen : string`; `SshdOptions.permitOpen "db.internal:5432"` |
| `PermitRootLogin` | `permitRootLogin : string`; `SshdOptions.permitRootLogin "prohibit-password"` |
| `PermitTTY` | `permitTTY : bool`; `SshdOptions.permitTTY false` |
| `PermitTunnel` | `permitTunnel : string`; `SshdOptions.permitTunnel "point-to-point"` |
| `PermitUserEnvironment` | `permitUserEnvironment : string` (also `permitUserEnvironmentEnabled : bool`); `SshdOptions.permitUserEnvironment "LANG_*"` |
| `PermitUserRC` | `permitUserRC : bool`; `SshdOptions.permitUserRC false` |
| `PerSourceMaxStartups` | `perSourceMaxStartups : string`; `SshdOptions.perSourceMaxStartups "none"` |
| `PerSourceNetBlockSize` | `perSourceNetBlockSize : string`; `SshdOptions.perSourceNetBlockSize "32:128"` |
| `PerSourcePenalties` | `perSourcePenalties : string`; `SshdOptions.perSourcePenalties "authfail:5s"` |
| `PerSourcePenaltyExemptList` | `perSourcePenaltyExemptList : string`; `SshdOptions.perSourcePenaltyExemptList "192.0.2.0/24,2001:db8::/32"` |
| `PidFile` | `pidFile : string`; `SshdOptions.pidFile "/run/sshd.pid"` |
| `Port` | `port : int` (also `ports`, which emits repeated lines); `SshdOptions.port 2222` |
| `PrintLastLog` | `printLastLog : bool`; `SshdOptions.printLastLog true` |
| `PrintMotd` | `printMotd : bool`; `SshdOptions.printMotd false` |
| `PubkeyAcceptedAlgorithms` | `pubkeyAcceptedAlgorithms : string`; `SshdOptions.pubkeyAcceptedAlgorithms "+ssh-ed25519"` |
| `PubkeyAuthOptions` | `pubkeyAuthOptions : string`; `SshdOptions.pubkeyAuthOptions "touch-required verify-required"` |
| `PubkeyAuthentication` | `pubkeyAuthentication : bool`; `SshdOptions.pubkeyAuthentication true` |
| `RefuseConnection` | `refuseConnection : bool`; `SshdOptions.refuseConnection false` |
| `RekeyLimit` | `rekeyLimit : string`; `SshdOptions.rekeyLimit "1G 1h"` |
| `RequiredRSASize` | `requiredRsaSize : int`; `SshdOptions.requiredRsaSize 3072` |
| `RevokedKeys` | `revokedKeys : string`; `SshdOptions.revokedKeys "/etc/ssh/revoked.krl"` |
| `SecurityKeyProvider` | `securityKeyProvider : string`; `SshdOptions.securityKeyProvider "internal"` |
| `SetEnv` | `setEnv : string` (also `setEnvList`); `SshdOptions.setEnv "LANG=en_US.UTF-8"` |
| `SshdAuthPath` | `sshdAuthPath : string`; `SshdOptions.sshdAuthPath "/usr/lib/openssh/sshd-auth"` |
| `SshdSessionPath` | `sshdSessionPath : string`; `SshdOptions.sshdSessionPath "/usr/lib/openssh/sshd-session"` |
| `StreamLocalBindMask` | `streamLocalBindMask : string`; `SshdOptions.streamLocalBindMask "0177"` |
| `StreamLocalBindUnlink` | `streamLocalBindUnlink : bool`; `SshdOptions.streamLocalBindUnlink true` |
| `StrictModes` | `strictModes : bool`; `SshdOptions.strictModes true` |
| `Subsystem` | `subsystem : string`; `SshdOptions.subsystem "sftp internal-sftp"` |
| `SyslogFacility` | `syslogFacility : string`; `SshdOptions.syslogFacility "AUTH"` |
| `TCPKeepAlive` | `tcpKeepAlive : bool`; `SshdOptions.tcpKeepAlive true` |
| `TrustedUserCAKeys` | `trustedUserCAKeys : string`; `SshdOptions.trustedUserCAKeys "/etc/ssh/user-ca.pub"` |
| `UnusedConnectionTimeout` | `unusedConnectionTimeout : string`; `SshdOptions.unusedConnectionTimeout "5m"` |
| `UseDNS` | `useDns : bool`; `SshdOptions.useDns false` |
| `UsePAM` | `usePam : bool`; `SshdOptions.usePam true` |
| `VersionAddendum` | `versionAddendum : string`; `SshdOptions.versionAddendum "build-42"` |
| `X11DisplayOffset` | `x11DisplayOffset : int`; `SshdOptions.x11DisplayOffset 10` |
| `X11Forwarding` | `x11Forwarding : bool`; `SshdOptions.x11Forwarding false` |
| `X11UseLocalhost` | `x11UseLocalhost : bool`; `SshdOptions.x11UseLocalhost true` |
| `XAuthLocation` | `xAuthLocation : string`; `SshdOptions.xAuthLocation "/usr/bin/xauth"` |

For completely native text, `nativeText "VendorOption argument-tail\n"` preserves a fragment in the same ordered stream. `SshdOptions.extension keyword argumentTail` emits an arbitrary one-line directive without a supported-name allowlist. The target daemon remains the syntax and build-feature authority.
