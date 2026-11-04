namespace Dorothy.Tests

open System
open Dorothy.DSL
open NUnit.Framework

[<TestFixture>]
type FullConfigDslTests() =
    let sshdConfiguration =
        config {
            SshdOptions.port 2222
            SshdOptions.port 2200

            matchBlock "User deploy" {
                SshdOptions.acceptEnvList [ "LANG"; "LC_*" ]
                SshdOptions.passwordAuthentication false
            }

            SshdOptions.extension "VendorDirective" "opaque tail"
        }


    [<Test>]
    member _.``SSHD option catalogue composes complete native text without scalar-map loss``() =
        Assert.That(
            sshdConfiguration.Configuration,
            Is.EqualTo(
                "Port 2222\n"
                + "Port 2200\n"
                + "Match User deploy\n"
                + "AcceptEnv LANG LC_*\n"
                + "PasswordAuthentication no\n"
                + "VendorDirective opaque tail\n"
            )
        )

    [<Test>]
    member _.``Nested Fail2Ban options target sshd while standalone options target DEFAULT``() =
        let specification =
            sshHost "nested-fail2ban" {
                Address "192.0.2.21"
                User "debian"

                debian {
                    sshd {
                        fail2ban {
                            Fail2BanOptions.enabled true
                            Fail2BanOptions.maxretry 6
                        }
                    }

                    fail2ban {
                        Fail2BanOptions.destemail "security@example.test"

                        Fail2BanSections.jail "sshd" {
                            Fail2BanOptions.enabled true
                            Fail2BanOptions.action "nftables"
                        }
                    }
                }
            }

        let files = specification.Fail2Ban.Value.Files
        Assert.That(specification.Fail2Ban.Value.ManageSshdPorts, Is.True)

        Assert.That(
            files["jail.d/90-dorothy.local"],
            Does.Contain("[sshd]\nenabled = true\nmaxretry = 6\naction = nftables\n")
        )

        Assert.That(
            files["jail.d/90-dorothy.local"].Split("[sshd]", StringSplitOptions.None).Length
            - 1,
            Is.EqualTo(1)
        )

        Assert.That(files["jail.d/90-dorothy.local"], Does.Contain("[DEFAULT]\ndestemail = security@example.test\n"))

    [<Test>]
    member _.``Fail2Ban catalogue preserves daemon jail filter action Python and include files``() =
        let host =
            sshHost "full-fail2ban" {
                Address "192.0.2.25"
                User "debian"

                debian {
                    fail2ban {
                        Fail2BanSections.daemon {
                            Fail2BanDaemonOptions.socket "/run/fail2ban/custom.sock"
                            Fail2BanDaemonOptions.dbfile "/var/lib/fail2ban/custom.sqlite3"
                        }

                        Fail2BanSections.thread { Fail2BanDaemonOptions.stacksize "0" }

                        Fail2BanSections.defaults {
                            Fail2BanOptions.ignoreipList [ "127.0.0.0/8"; "::1" ]
                            Fail2BanOptions.bantimeIncrement true
                            Fail2BanOptions.bantimeFormula "ban.Time * (1 << ban.Count)"
                        }

                        Fail2BanSections.jail "custom" {
                            Fail2BanOptions.enabled true
                            Fail2BanOptions.backend "systemd[journalpath=/run/log/journal]"
                            Fail2BanOptions.logpath "/var/log/custom.log"
                            Fail2BanOptions.action "custom[port=22]"
                        }

                        Fail2BanSections.filterIncludes "custom" {
                            Fail2BanIncludeOptions.before "common.conf"
                            Fail2BanIncludeOptions.after "local-common.conf"
                        }

                        Fail2BanSections.filterDefaults "custom" { Fail2BanFilterOptions.custom "mode" "normal" }

                        Fail2BanSections.filter "custom" {
                            Fail2BanFilterOptions.failregex
                                "^Failed login from <HOST>\\s+$\n^Other failure from <HOST>$"

                            Fail2BanFilterOptions.ignoreregex "^Ignored <HOST>$"
                            Fail2BanFilterOptions.datepattern "%%Y-%%m-%%d"
                        }

                        Fail2BanSections.filterInit "custom" { Fail2BanFilterOptions.custom "application" "demo" }
                        Fail2BanSections.actionIncludes "custom" { Fail2BanIncludeOptions.before "base.conf" }

                        Fail2BanSections.action "custom" {
                            Fail2BanActionOptions.actionstart "create-chain"
                            Fail2BanActionOptions.actionban "ban <ip>\nlog <ip>"
                            Fail2BanActionOptions.actionunban "unban <ip>"
                            Fail2BanActionOptions.actionflush "flush custom state"
                        }

                        Fail2BanSections.actionInit "custom" { Fail2BanActionOptions.init "family" "inet" }
                        Fail2BanFiles.pythonAction "python-custom" "class Action:\n    pass\n"
                        Fail2BanFiles.file "filter.d/shared.local" "[Definition]\nfailregex = ^shared <HOST>$\n"
                        Fail2BanFiles.manageSshdPorts false
                    }
                }
            }

        let configuration = host.Fail2Ban.Value
        let files = configuration.Files

        Assert.That(
            files["filter.d/custom.local"],
            Does.Contain("failregex = ^Failed login from <HOST>\\s+$\n    ^Other failure from <HOST>$\n")
        )

        Assert.That(configuration.ManageSshdPorts, Is.False)
        Assert.That(files["fail2ban.d/90-dorothy.local"], Does.Contain("socket = /run/fail2ban/custom.sock"))
        Assert.That(files["fail2ban.d/90-dorothy.local"], Does.Contain("[Thread]\nstacksize = 0\n"))
        Assert.That(files["jail.d/90-dorothy.local"], Does.Contain("bantime.increment = true"))
        Assert.That(files["jail.d/90-dorothy.local"], Does.Contain("backend = systemd[journalpath=/run/log/journal]"))

        Assert.That(
            files["filter.d/custom.local"],
            Does.Contain("[INCLUDES]\nbefore = common.conf\nafter = local-common.conf\n")
        )

        Assert.That(files["filter.d/custom.local"], Does.Contain("datepattern = %%Y-%%m-%%d"))
        Assert.That(files["action.d/custom.local"], Does.Contain("actionflush = flush custom state"))
        Assert.That(files["action.d/custom.local"], Does.Contain("actionban = ban <ip>\n    log <ip>\n"))
        Assert.That(files["action.d/custom.local"], Does.Contain("[Init]\nfamily = inet\n"))
        Assert.That(files["action.d/python-custom.py"], Is.EqualTo("class Action:\n    pass\n"))
        Assert.That(files["filter.d/shared.local"], Is.EqualTo("[Definition]\nfailregex = ^shared <HOST>$\n"))


    [<Test>]
    member _.``Repeated typed jail actions merge into one native multiline option``() =
        let host =
            sshHost "multi-action" {
                Address "192.0.2.31"
                User "debian"

                debian {
                    fail2ban {
                        Fail2BanSections.jail "dorothy-app" { Fail2BanOptions.action "command[name=outside]" }
                        Fail2BanSections.jail "dorothy-app" { Fail2BanOptions.action "python[name=inside]" }
                    }
                }
            }

        let jailFile = host.Fail2Ban.Value.Files["jail.d/90-dorothy.local"]
        Assert.That(jailFile, Does.Contain("[dorothy-app]\naction = command[name=outside]\n    python[name=inside]\n"))
        Assert.That(jailFile.Split("[dorothy-app]", StringSplitOptions.None).Length - 1, Is.EqualTo(1))
        Assert.That(jailFile.Split("action =", StringSplitOptions.None).Length - 1, Is.EqualTo(1))

    [<Test>]
    member _.``Native explicit sshd port and explicit opt-out disable dynamic listener linking``() =
        let defaultPort =
            sshHost "default-port" {
                Address "192.0.2.22"
                User "debian"
                debian { fail2ban { Fail2BanOptions.port "sshd" } }
            }

        let optedOut =
            sshHost "opt-out" {
                Address "192.0.2.23"
                User "debian"

                debian {
                    sshd {
                        fail2ban {
                            Fail2BanOptions.enabled true
                            Fail2BanFiles.manageSshdPorts false
                        }
                    }
                }
            }

        Assert.That(defaultPort.Fail2Ban.Value.ManageSshdPorts, Is.False)
        Assert.That(optedOut.Fail2Ban.Value.ManageSshdPorts, Is.False)


    [<Test>]
    member _.``Raw Fail2Ban port detection respects separators comments continuations and section identity``() =
        let continuationAndCase =
            sshHost "raw-port-not-explicit" {
                Address "192.0.2.27"
                User "debian"

                debian {
                    sshd { fail2ban { Fail2BanOptions.enabled true } }

                    fail2ban {
                        Fail2BanFiles.file
                            "jail.d/native.local"
                            "[SSHD]\nport: 2000\n[ sshd ]\nport=2100\n[DEFAULT]\ncustom = value\n    port=2200\n# port=2300\n; port=2400\n"

                        Fail2BanSections.nativeSection "jail.d/structured.local" "SSHD" { Fail2BanOptions.port "2000" }

                        Fail2BanSections.nativeSection "jail.d/structured.local" "default" {
                            Fail2BanOptions.port "2100"
                        }
                    }
                }
            }

        let colonPort =
            sshHost "colon-port" {
                Address "192.0.2.28"
                User "debian"

                debian {
                    sshd { fail2ban { Fail2BanOptions.enabled true } }
                    fail2ban { Fail2BanFiles.file "jail.d/native.local" "[sshd] ; comment\n  port: 2200\n" }
                }
            }

        let continuationHeader =
            sshHost "continued-section-header" {
                Address "192.0.2.30"
                User "debian"

                debian {
                    sshd { fail2ban { Fail2BanOptions.enabled true } }

                    fail2ban {
                        Fail2BanFiles.file "jail.d/native.local" "[sshd]\naction = first\n    [other]\nport = 2200\n"
                    }
                }
            }

        Assert.That(continuationAndCase.Fail2Ban.Value.ManageSshdPorts, Is.True)
        Assert.That(colonPort.Fail2Ban.Value.ManageSshdPorts, Is.False)
        Assert.That(continuationHeader.Fail2Ban.Value.ManageSshdPorts, Is.False)

        Assert.That(
            continuationAndCase.Fail2Ban.Value.Files["jail.d/native.local"],
            Is.EqualTo(
                "[SSHD]\nport: 2000\n[ sshd ]\nport=2100\n[DEFAULT]\ncustom = value\n    port=2200\n# port=2300\n; port=2400\n"
            )
        )

    [<Test>]
    member _.``Nested and standalone conflicting sshd options are rejected``() =
        Assert.Throws<ArgumentException>(
            TestDelegate(fun () ->
                sshHost "conflicting-fail2ban" {
                    Address "192.0.2.24"
                    User "debian"

                    debian {
                        sshd { fail2ban { Fail2BanOptions.enabled true } }
                        fail2ban { Fail2BanSections.jail "sshd" { Fail2BanOptions.enabled false } }
                    }
                }
                |> ignore)
        )
        |> ignore

    [<Test>]
    member _.``Separate standalone Fail2Ban declarations cannot silently override each other``() =
        Assert.Throws<ArgumentException>(
            TestDelegate(fun () ->
                sshHost "conflicting-standalone-fail2ban" {
                    Address "192.0.2.26"
                    User "debian"

                    debian {
                        fail2ban { Fail2BanSections.jail "sshd" { Fail2BanOptions.enabled true } }
                        fail2ban { Fail2BanSections.jail "sshd" { Fail2BanOptions.enabled false } }
                    }
                }
                |> ignore)
        )
        |> ignore

    [<Test>]
    member _.``Conflicting duplicate options in one native section are rejected``() =
        Assert.Throws<ArgumentException>(
            TestDelegate(fun () ->
                sshHost "conflicting-same-file-fail2ban" {
                    Address "192.0.2.29"
                    User "debian"

                    debian {
                        fail2ban {
                            Fail2BanSections.jail "sshd" { Fail2BanOptions.enabled true }
                            Fail2BanSections.jail "sshd" { Fail2BanOptions.enabled false }
                        }
                    }
                }
                |> ignore)
        )
        |> ignore

    [<Test>]
    member _.``Fail2Ban native paths reject traversal``() =
        Assert.Throws<ArgumentException>(
            TestDelegate(fun () -> Fail2BanFiles.file "../outside.local" "[DEFAULT]\n" |> ignore)
        )
        |> ignore
