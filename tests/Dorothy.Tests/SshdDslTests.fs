namespace Dorothy.Tests

open Dorothy.DSL
open NUnit.Framework

[<TestFixture>]
type SshdDslTests() =
    [<Test>]
    member _.``SSHD native builder preserves directive ordering repetitions Match Include and extensions``() =
        let config =
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
            config.Configuration,
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
    member _.``Host SSH declaration retains native configuration as one string and keeps absent groups unmanaged``() =
        let host =
            sshHost "native-sshd" {
                Address "192.0.2.10"
                User "debian"
                debian { sshd { config { SshdOptions.passwordAuthentication false } } }
            }

        Assert.That(host.Sshd.Value.Config.Value.Configuration, Is.EqualTo("PasswordAuthentication no\n"))
        Assert.That(host.Fail2Ban.IsNone, Is.True)

    [<Test>]
    member _.``SSHD and nested Fail2Ban groups remain independently optional``() =
        let sshOnly = sshd { config { SshdOptions.port 2222 } }
        let fail2banOnly = sshd { fail2ban { Fail2BanOptions.enabled true } }

        Assert.That(sshOnly.Config.Value.Configuration, Is.EqualTo("Port 2222\n"))
        Assert.That(sshOnly.Fail2Ban.IsNone, Is.True)
        Assert.That(fail2banOnly.Config.IsNone, Is.True)
        Assert.That(fail2banOnly.Fail2Ban.Value.Parts.Length, Is.EqualTo(1))
