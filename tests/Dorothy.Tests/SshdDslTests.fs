namespace Dorothy.Tests

open System
open Dorothy.DSL
open NUnit.Framework

[<TestFixture>]
type SshdDslTests() =
    let expectArgumentException operation =
        Assert.Throws<ArgumentException>(TestDelegate(fun () -> operation () |> ignore)) |> ignore

    [<Test>]
    member _.``SSHD config exposes only explicit settings using canonical OpenSSH keys and values``() =
        let host =
            sshHost "sshd-host" {
                Address "192.0.2.10"
                User "debian"
                debian {
                    sshd {
                        config {
                            passwordAuthentication false
                            kbdInteractiveAuthentication false
                            pubkeyAuthentication true
                            permitRootLogin No
                            port 2222
                            maxAuthTries 4
                        }
                    }
                }
            }

        let settings = host.Sshd.Value.Config.Value.Settings
        let expected =
            Map.ofList [
                "PasswordAuthentication", "no"
                "KbdInteractiveAuthentication", "no"
                "PubkeyAuthentication", "yes"
                "PermitRootLogin", "no"
                "Port", "2222"
                "MaxAuthTries", "4"
            ]

        Assert.That(settings, Is.EqualTo(box expected))

    [<Test>]
    member _.``SSHD and Fail2Ban groups are independent and absent configuration remains unmanaged``() =
        let noSshdBlock =
            sshHost "without-sshd" {
                Address "192.0.2.11"
                User "debian"
                debian { apt { "curl" } }
            }

        let configOnly = sshd { config { port 2222 } }
        let fail2banOnly = sshd { fail2ban {} }
        let configOnlySettings = configOnly.Config.Value.Settings

        Assert.That(noSshdBlock.Sshd.IsNone, Is.True)
        Assert.That(configOnly.Fail2Ban.IsNone, Is.True)
        Assert.That(configOnlySettings, Is.EqualTo(box (Map.ofList [ "Port", "2222" ])))
        Assert.That(fail2banOnly.Config.IsNone, Is.True)
        Assert.That(fail2banOnly.Fail2Ban.Value.Enabled, Is.True)
        Assert.That(fail2banOnly.Fail2Ban.Value.MaxRetry, Is.EqualTo(5))
        Assert.That(fail2banOnly.Fail2Ban.Value.FindTimeSeconds, Is.EqualTo(600))
        Assert.That(fail2banOnly.Fail2Ban.Value.BanTimeSeconds, Is.EqualTo(3600))
        Assert.That(fail2banOnly.Fail2Ban.Value.IgnoreIps, Is.EqualTo(box [ "127.0.0.0/8"; "::1" ]))

    [<Test>]
    member _.``Fail2Ban accepts explicit options and repeated normalized IP or CIDR ignores``() =
        let specification =
            fail2ban {
                enabled false
                maxRetry 7
                findTime (TimeSpan.FromMinutes 10.)
                banTime (TimeSpan.FromHours 1.)
                ignoreIp "192.0.2.10/24"
                ignoreIp "192.0.2.10/24"
                ignoreIp "2001:DB8::1/64"
            }

        Assert.That(specification.Enabled, Is.False)
        Assert.That(specification.MaxRetry, Is.EqualTo(7))
        Assert.That(specification.FindTimeSeconds, Is.EqualTo(600))
        Assert.That(specification.BanTimeSeconds, Is.EqualTo(3600))
        Assert.That(
            specification.IgnoreIps,
            Is.EqualTo(box [ "127.0.0.0/8"; "::1"; "192.0.2.0/24"; "2001:db8::/64" ])
        )

    [<Test>]
    member _.``SSHD rejects duplicate scalar settings and duplicate optional groups``() =
        expectArgumentException (fun () -> config { passwordAuthentication true; passwordAuthentication false })
        expectArgumentException (fun () -> sshd { config {}; config {} })
        expectArgumentException (fun () -> sshd { fail2ban {}; fail2ban {} })
        expectArgumentException (fun () ->
            debian {
                sshd { config {} }
                sshd { fail2ban {} }
            })
        expectArgumentException (fun () -> fail2ban { maxRetry 3; maxRetry 4 })
        expectArgumentException (fun () -> fail2ban { enabled true; enabled false })

    [<Test>]
    member _.``SSHD scalar values and Fail2Ban durations and addresses are validated``() =
        expectArgumentException (fun () -> config { port 0 })
        expectArgumentException (fun () -> config { port 65536 })
        expectArgumentException (fun () -> config { maxAuthTries 0 })
        expectArgumentException (fun () -> fail2ban { maxRetry 0 })
        expectArgumentException (fun () -> fail2ban { findTime TimeSpan.Zero })
        expectArgumentException (fun () -> fail2ban { banTime (TimeSpan.FromMilliseconds 1500.) })
        expectArgumentException (fun () ->
            fail2ban {
                findTime (TimeSpan.FromTicks((int64 Int32.MaxValue + 1L) * TimeSpan.TicksPerSecond))
            })
        expectArgumentException (fun () -> fail2ban { ignoreIp "not-an-ip" })
        expectArgumentException (fun () -> fail2ban { ignoreIp "192.0.2.1/33" })
        expectArgumentException (fun () -> fail2ban { ignoreIp "2001:db8::1/129" })

    [<Test>]
    member _.``Fail2Ban normalizes bare IPv4-mapped addresses and rejects mapped CIDRs``() =
        let bareAddress = fail2ban { ignoreIp "::ffff:192.0.2.1" }

        Assert.That(
            bareAddress.IgnoreIps,
            Is.EqualTo(box [ "127.0.0.0/8"; "::1"; "192.0.2.1" ])
        )
        expectArgumentException (fun () -> fail2ban { ignoreIp "::ffff:192.0.2.1/24" })
        expectArgumentException (fun () -> fail2ban { ignoreIp "::ffff:192.0.2.1/120" })
        expectArgumentException (fun () -> fail2ban { ignoreIp "::ffff:192.0.2.1/128" })

    [<Test>]
    member _.``Fail2Ban rejects catch-all CIDRs and unspecified host addresses``() =
        for value in [ "0.0.0.0"; "0.0.0.0/0"; "0.0.0.0/32"; "::"; "::/0"; "::/128" ] do
            expectArgumentException (fun () -> fail2ban { ignoreIp value })

        let error =
            Assert.Throws<ArgumentException>(
                TestDelegate(fun () -> fail2ban { ignoreIp "0.0.0.0/0" } |> ignore)
            )
        Assert.That(error.Message, Does.Contain("enabled false"))
