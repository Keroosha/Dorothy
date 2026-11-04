namespace Dorothy.Tests

open System
open Dorothy.DSL
open NUnit.Framework

[<TestFixture>]
type SshdDslTests() =
    [<Test>]
    member _.``SSH builder preserves order repetitions match scope and explicit native escape``() =
        let generated =
            config {
                SshdOptions.port 2222
                SshdOptions.port 2200
                SshdOptions.acceptEnvList [ "LANG"; "LC_*" ]

                matchBlock "User deploy" {
                    SshdOptions.forceCommand "internal-sftp"
                    SshdOptions.includePath "/etc/ssh/sshd_config.d/custom-match.conf"
                }

                SshdOptions.extension "VendorFutureOption" "one \"quoted argument\""
                nativeText "# caller-owned native fragment\nUsePAM yes\n"
            }

        Assert.That(
            generated.Configuration,
            Is.EqualTo(
                "Port 2222\n"
                + "Port 2200\n"
                + "AcceptEnv LANG LC_*\n"
                + "Match User deploy\n"
                + "ForceCommand internal-sftp\n"
                + "Include /etc/ssh/sshd_config.d/custom-match.conf\n"
                + "VendorFutureOption one \"quoted argument\"\n"
                + "# caller-owned native fragment\nUsePAM yes\n"
            )
        )

    [<Test>]
    member _.``SSH duration options serialize finite seconds and their distinct native sentinels``() =
        let values =
            config {
                SshdOptions.loginGraceTime SshdLoginGraceTime.NoLimit
                SshdOptions.clientAliveInterval SshdClientAliveInterval.Disabled
                SshdOptions.unusedConnectionTimeout SshdUnusedConnectionTimeout.Never
                SshdOptions.channelTimeout SshdChannelTimeout.Disabled
            }

        let finite =
            config {
                SshdOptions.loginGraceTime (SshdLoginGraceTime.LimitedTo(TimeSpan.FromSeconds 30.0))
                SshdOptions.clientAliveInterval (SshdClientAliveInterval.Every(TimeSpan.FromSeconds 45.0))
                SshdOptions.unusedConnectionTimeout (SshdUnusedConnectionTimeout.After(TimeSpan.FromMinutes 5.0))

                SshdOptions.channelTimeout (
                    SshdChannelTimeout.Timeouts
                        [ { Channel = SshdChannel.Session
                            InactiveFor = TimeSpan.FromMinutes 5.0 }
                          { Channel = SshdChannel.Global
                            InactiveFor = TimeSpan.Zero }
                          { Channel = SshdChannel.Subsystem
                            InactiveFor = TimeSpan.FromMinutes 10.0 }
                          { Channel = SshdChannel.Pattern "session:subsystem:sftp"
                            InactiveFor = TimeSpan.FromSeconds 20.0 }
                          { Channel = SshdChannel.TunConnection
                            InactiveFor = TimeSpan.FromSeconds 30.0 }
                          { Channel = SshdChannel.Shell
                            InactiveFor = TimeSpan.FromSeconds 45.0 }
                          { Channel = SshdChannel.Command
                            InactiveFor = TimeSpan.FromSeconds 90.0 } ]
                )
            }

        Assert.That(
            values.Configuration,
            Is.EqualTo(
                "LoginGraceTime 0\n"
                + "ClientAliveInterval 0\n"
                + "UnusedConnectionTimeout none\n"
                + "ChannelTimeout none\n"
            )
        )

        Assert.That(
            finite.Configuration,
            Is.EqualTo(
                "LoginGraceTime 30\n"
                + "ClientAliveInterval 45\n"
                + "UnusedConnectionTimeout 300\n"
                + "ChannelTimeout session*=300 global=0 session:subsystem:*=600 session:subsystem:sftp=20 tun=30 session:shell=45 session:command=90\n"
            )
        )

    [<Test>]
    member _.``SSH startup rekey and source penalty grammar preserves native compound forms``() =
        let defaultsAndLimits =
            config {
                SshdOptions.maxStartups (SshdMaxStartups.Limit 25)

                SshdOptions.maxStartups (
                    SshdMaxStartups.RandomEarlyDrop
                        { Start = 10
                          Rate = 30
                          Full = 60 }
                )

                SshdOptions.rekeyLimit
                    { DataLimit = SshdRekeyDataLimit.Default
                      TimeLimit = Some(TimeSpan.FromHours 1.0) }

                SshdOptions.rekeyLimit
                    { DataLimit = SshdRekeyDataLimit.Bytes 3_221_225_472L<B>
                      TimeLimit = None }

                SshdOptions.perSourceMaxStartups SshdPerSourceMaxStartups.Unlimited

                SshdOptions.perSourceNetBlockSize
                    { IPv4Prefix = 24
                      IPv6Prefix = Some 64 }

                SshdOptions.perSourcePenalties (
                    SshdPerSourcePenalties.Configured
                        [ SshdPerSourcePenalty.Crash(TimeSpan.FromSeconds 90.0)
                          SshdPerSourcePenalty.AuthFail(TimeSpan.FromSeconds 5.0)
                          SshdPerSourcePenalty.NoAuth(TimeSpan.FromSeconds 1.0)
                          SshdPerSourcePenalty.GraceExceeded(TimeSpan.FromSeconds 10.0)
                          SshdPerSourcePenalty.RefuseConnection(TimeSpan.FromSeconds 10.0)
                          SshdPerSourcePenalty.Max(TimeSpan.FromMinutes 10.0)
                          SshdPerSourcePenalty.Min(TimeSpan.FromSeconds 15.0)
                          SshdPerSourcePenalty.MaxSources4 4096
                          SshdPerSourcePenalty.MaxSources6 8192
                          SshdPerSourcePenalty.Overflow SshdPerSourceOverflowMode.DenyAll
                          SshdPerSourcePenalty.Overflow6 SshdPerSourceOverflowMode.Permissive ]
                )
            }

        Assert.That(
            defaultsAndLimits.Configuration,
            Is.EqualTo(
                "MaxStartups 25\n"
                + "MaxStartups 10:30:60\n"
                + "RekeyLimit default 3600\n"
                + "RekeyLimit 3221225472 none\n"
                + "PerSourceMaxStartups none\n"
                + "PerSourceNetBlockSize 24:64\n"
                + "PerSourcePenalties crash:90 authfail:5 noauth:1 grace-exceeded:10 refuseconnection:10 "
                + "max:600 min:15 max-sources4:4096 max-sources6:8192 overflow:deny-all overflow6:permissive\n"
            )
        )

    [<Test>]
    member _.``SSH closed modes and structured forward endpoints render canonical native tokens``() =
        let generated =
            config {
                SshdOptions.addressFamily SshdAddressFamily.IPv6
                SshdOptions.allowTcpForwarding SshdForwardingMode.Remote
                SshdOptions.allowStreamLocalForwarding SshdForwardingMode.Local
                SshdOptions.compression SshdCompression.Delayed
                SshdOptions.fingerprintHash SshdFingerprintHash.Sha256
                SshdOptions.gatewayPorts SshdGatewayPorts.ClientSpecified
                SshdOptions.ignoreRhosts SshdIgnoreRhosts.ShostsOnly
                SshdOptions.logLevel SshdLogLevel.Debug2
                SshdOptions.permitRootLogin SshdRootLogin.ProhibitPassword
                SshdOptions.permitTunnel SshdPermitTunnel.Yes
                SshdOptions.permitUserEnvironment (SshdPermitUserEnvironment.Patterns "LANG,LC_*")

                SshdOptions.permitOpen (
                    SshdPermitOpen.Destinations
                        [ { Host = "db.internal"
                            Port = SshdForwardPort.Number 5432 }
                          { Host = "2001:db8::1"
                            Port = SshdForwardPort.Any } ]
                )

                SshdOptions.permitListen (
                    SshdPermitListen.Addresses
                        [ { Host = None
                            Port = SshdForwardPort.Number 2022 }
                          { Host = Some "localhost"
                            Port = SshdForwardPort.Number 2222 } ]
                )

                SshdOptions.listenAddress
                    { Address = "::1"
                      Port = Some(SshdForwardPort.Number 2222)
                      RoutingDomain = Some "blue" }

                SshdOptions.ipQos
                    { Interactive = SshdIpQosValue.Ef
                      Bulk = Some SshdIpQosValue.Cs1 }
                SshdOptions.ipQos
                    { Interactive = SshdIpQosValue.LowDelay
                      Bulk = None }

                SshdOptions.pubkeyAuthOptions (
                    SshdPubkeyAuthOptions.Options
                        [ SshdPubkeyAuthOption.TouchRequired
                          SshdPubkeyAuthOption.VerifyRequired ]
                )

                SshdOptions.streamLocalBindMask 0o177
                SshdOptions.syslogFacility SshdSyslogFacility.AuthPriv
                SshdOptions.syslogFacility SshdSyslogFacility.Local7
            }

        Assert.That(
            generated.Configuration,
            Is.EqualTo(
                "AddressFamily inet6\n"
                + "AllowTcpForwarding remote\n"
                + "AllowStreamLocalForwarding local\n"
                + "Compression delayed\n"
                + "FingerprintHash sha256\n"
                + "GatewayPorts clientspecified\n"
                + "IgnoreRhosts shosts-only\n"
                + "LogLevel DEBUG2\n"
                + "PermitRootLogin prohibit-password\n"
                + "PermitTunnel yes\n"
                + "PermitUserEnvironment LANG,LC_*\n"
                + "PermitOpen db.internal:5432 [2001:db8::1]:*\n"
                + "PermitListen 2022 localhost:2222\n"
                + "ListenAddress [::1]:2222 rdomain blue\n"
                + "IPQoS ef cs1\n"
                + "IPQoS lowdelay\n"
                + "PubkeyAuthOptions touch-required verify-required\n"
                + "StreamLocalBindMask 0177\n"
                + "SyslogFacility AUTHPRIV\n"
                + "SyslogFacility LOCAL7\n"
            )
        )

    [<Test>]
    member _.``SSH native integer and duration upper boundaries serialize without rounding``() =
        let accepted =
            config {
                SshdOptions.loginGraceTime (
                    SshdLoginGraceTime.LimitedTo(TimeSpan.FromSeconds(float Int32.MaxValue))
                )

                SshdOptions.rekeyLimit
                    { DataLimit = SshdRekeyDataLimit.Bytes 16L<B>
                      TimeLimit = None }

                SshdOptions.maxStartups (
                    SshdMaxStartups.RandomEarlyDrop
                        { Start = 1
                          Rate = 100
                          Full = 1 }
                )

                SshdOptions.perSourceNetBlockSize
                    { IPv4Prefix = 0
                      IPv6Prefix = None }

                SshdOptions.clientAliveCountMax Int32.MaxValue
                SshdOptions.requiredRsaSize 1024
                SshdOptions.port 1
                SshdOptions.port 65535
                SshdOptions.streamLocalBindMask 0o777

                SshdOptions.ipQos
                    { Interactive = SshdIpQosValue.Numeric 255
                      Bulk = None }
            }

        Assert.That(
            accepted.Configuration,
            Is.EqualTo(
                "LoginGraceTime 2147483647\n"
                + "RekeyLimit 16 none\n"
                + "MaxStartups 1:100:1\n"
                + "PerSourceNetBlockSize 0:128\n"
                + "ClientAliveCountMax 2147483647\n"
                + "RequiredRSASize 1024\n"
                + "Port 1\n"
                + "Port 65535\n"
                + "StreamLocalBindMask 0777\n"
                + "IPQoS 255\n"
            )
        )

    [<Test>]
    member _.``SSH typed time size count and mode validators reject inexact or out-of-range inputs``() =
        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.loginGraceTime (SshdLoginGraceTime.LimitedTo(TimeSpan.FromMilliseconds 1500.0))
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.loginGraceTime (
                SshdLoginGraceTime.LimitedTo(TimeSpan.FromSeconds(float Int32.MaxValue + 1.0))
            )
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.rekeyLimit
                { DataLimit = SshdRekeyDataLimit.Bytes 15L<B>
                  TimeLimit = None }
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.maxStartups (
                SshdMaxStartups.RandomEarlyDrop
                    { Start = 11
                      Rate = 30
                      Full = 10 }
            )
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.perSourceNetBlockSize
                { IPv4Prefix = 33
                  IPv6Prefix = Some 64 }
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.streamLocalBindMask 0o1000 |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.port 0 |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.channelTimeout (SshdChannelTimeout.Timeouts []) |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.permitOpen (
                SshdPermitOpen.Destinations
                    [ { Host = "db.internal"
                        Port = SshdForwardPort.Number 0 } ]
            )
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.permitListen (
                SshdPermitListen.Addresses
                    [ { Host = None
                        Port = SshdForwardPort.Number 0 } ]
            )
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.channelTimeout (
                SshdChannelTimeout.Timeouts
                    [ { Channel = SshdChannel.Pattern "#ignored"
                        InactiveFor = TimeSpan.FromSeconds 1.0 } ]
            )
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.channelTimeout (
                SshdChannelTimeout.Timeouts
                    [ { Channel = SshdChannel.Pattern "session\""
                        InactiveFor = TimeSpan.FromSeconds 1.0 } ]
            )
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.permitUserEnvironment (SshdPermitUserEnvironment.Patterns "yes")
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.permitUserEnvironment (SshdPermitUserEnvironment.Patterns "no")
            |> ignore)
        |> ignore

        Assert.Throws<ArgumentException>(fun () ->
            SshdOptions.permitUserEnvironment (SshdPermitUserEnvironment.Patterns "'yes'")
            |> ignore)
        |> ignore

    [<Test>]
    member _.``PermitUserEnvironment patterns retain case-sensitive sentinel-like names``() =
        let generated =
            config {
                SshdOptions.permitUserEnvironment (SshdPermitUserEnvironment.Patterns "YES")
                SshdOptions.permitUserEnvironment (SshdPermitUserEnvironment.Patterns "NO")
            }

        Assert.That(
            generated.Configuration,
            Is.EqualTo("PermitUserEnvironment YES\nPermitUserEnvironment NO\n")
        )