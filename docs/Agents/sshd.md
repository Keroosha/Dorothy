# Native SSHD and Fail2Ban configuration

Dorothy configures existing Debian hosts through native drop-ins. It does not replace `/etc/ssh/sshd_config`, rewrite vendor configuration, or run sshd against a separate generated main file.

The public SSH catalogue covers all **106 canonical directives** documented for Debian 13/OpenSSH 10, including `Match` and `Include`. Fail2Ban supports daemon settings, defaults, arbitrary named jails, filters, command actions, Python actions and native include/interpolation variables. There is no fixed sshd-option or packaged-filter/action allowlist in the provider/helper protocol.

- [SSH directive catalogue](sshd-options.md)
- [Fail2Ban option and file catalogue](fail2ban-options.md)
- Native authorities: [Debian sshd_config(5)](https://manpages.debian.org/trixie/openssh-server/sshd_config.5.en.html), [Debian jail.conf(5)](https://manpages.debian.org/trixie/fail2ban/jail.conf.5.en.html).

## SSH configuration and its jail

```fsharp
open System
open Dorothy.DSL

let server =
    sshHost "server" {
        Address "192.0.2.10"
        User "debian"
        IdentityFile "/home/operator/.ssh/id_ed25519"
        debian {
            sshd {
                config {
                    SshdOptions.passwordAuthentication false
                    SshdOptions.kbdInteractiveAuthentication false
                    SshdOptions.pubkeyAuthentication true
                    SshdOptions.permitRootLogin SshdRootLogin.No
                    SshdOptions.clientAliveInterval (SshdClientAliveInterval.Every(TimeSpan.FromSeconds 45.))
                    SshdOptions.maxSessions 4
                    SshdOptions.allowTcpForwarding SshdForwardingMode.Local
                    SshdOptions.acceptEnv "APP_ENV"
                    SshdOptions.acceptEnv "DEPLOYMENT_ID"
                    matchBlock "User transfer" {
                        SshdOptions.forceCommand "internal-sftp"
                        SshdOptions.allowTcpForwarding SshdForwardingMode.No
                        SshdOptions.permitTTY false
                    }
                }
                fail2ban {
                    Fail2BanOptions.enabled true
                    Fail2BanOptions.filter "sshd[mode=extra]"
                    Fail2BanOptions.banaction "nftables[type=multiport]"
                    Fail2BanOptions.maxretry 5
                    Fail2BanOptions.bantime (Fail2BanBanTime.Finite(TimeSpan.FromHours 1.))
                }
            }
        }
    }

Host.deploy server |> ignore
```

Replace example addresses, account names and paths with existing host prerequisites. Both nested blocks are optional. Unspecified native settings remain inherited: Dorothy does not copy defaults or impose a hardening preset.

### Native semantics, not a custom merge language

SSH declarations form an **ordered native configuration body**. Named helpers use typed durations, sizes, modes and compound settings; text remains appropriate for commands, patterns and other open grammars. Use `SshdOptions.extension keyword argumentTail` for an explicitly native value (including vendor/new options), or `nativeText` for a complete native fragment. Typed helpers do not change directive ordering, inheritance or native precedence.

The drop-in is `/etc/ssh/sshd_config.d/00-dorothy.conf`. It must participate in the host's native Include topology; the helper verifies participation using sshd's own loader trace. Its basename does not outrank a directive already read before it.

OpenSSH generally uses the **first obtained value**. Some settings accumulate, including ports, listener addresses and allow/deny lists; a duplicate subsystem name can be an error. Dorothy deliberately preserves those rules. Declaring every setting is supported, but a drop-in is not a universal way to replace an inherited list or conflicting subsystem. Native conflicts must be resolved in the configuration's ownership/source, not by silently rewriting vendor files.

Put global directives before native `Match` sections. A `matchBlock` represents a native section, not a language-level reset to global scope: subsequent rows follow OpenSSH's scope rules until the next `Match` or end of that file. Included files and conditional includes retain their native scope behavior. Installed sshd is authoritative for build-dependent directives, algorithm availability and valid values.

## Complete Fail2Ban configuration

A standalone `fail2ban` block configures the shared daemon and any number of jails. It can coexist with the nested SSH block; both lower to **one host configuration resource**. Unscoped nested options target `[sshd]`; unscoped standalone options target `[DEFAULT]`.

```fsharp
fail2ban {
    Fail2BanSections.daemon {
        Fail2BanDaemonOptions.logtarget Fail2BanLogTarget.Stdout
        Fail2BanDaemonOptions.socket "/run/fail2ban/site.sock"
        Fail2BanDaemonOptions.dbpurgeage (TimeSpan.FromDays 7.)
    }
    Fail2BanSections.thread {
        Fail2BanDaemonOptions.stacksize (Fail2BanStackSize.Size 256<KiB>)
    }
    Fail2BanSections.defaults {
        Fail2BanOptions.ignoreself true
        Fail2BanOptions.ignoreip "127.0.0.0/8 ::1"
        Fail2BanOptions.findtime (TimeSpan.FromMinutes 10.)
    }
    Fail2BanSections.jail "app-auth" {
        Fail2BanOptions.enabled true
        Fail2BanOptions.backend Fail2BanBackend.Polling
        Fail2BanOptions.filter "app-auth"
        Fail2BanOptions.logpath "/var/log/app/auth.log"
        Fail2BanOptions.maxretry 3
        Fail2BanOptions.bantime Fail2BanBanTime.Permanent
        Fail2BanOptions.action "nftables[name=app-auth,port=443]"
        Fail2BanOptions.action "app-notify"
    }
    Fail2BanSections.filter "app-auth" {
        Fail2BanFilterOptions.failregex "^Failed login from <HOST>$"
    }
    Fail2BanSections.action "app-notify" {
        Fail2BanActionOptions.actionban "logger -t fail2ban -- 'ban <ip> in <name>'"
        Fail2BanActionOptions.actionunban "logger -t fail2ban -- 'unban <ip> in <name>'"
    }
    Fail2BanSections.actionInit "app-notify" {
        Fail2BanActionOptions.timeout (TimeSpan.FromSeconds 30.)
    }
}
```

This block belongs inside `debian { ... }`. The application log must exist and contain events matching the declared filter. The notification action supplements the nftables action; it does not itself block traffic.

### Sections, definitions and extension values

- `Fail2BanSections.daemon` / `thread`: daemon `[Definition]` / `[Thread]` in `fail2ban.d/90-dorothy.local`.
- `defaults` / `jail name`: `[DEFAULT]` / named jails in `jail.d/90-dorothy.local`.
- `filter`, `filterDefaults`, `filterIncludes`, `filterInit`: native sections in `filter.d/<name>.local`.
- `action`, `actionIncludes`, `actionInit`: native sections in `action.d/<name>.local`.
- `nativeSection relativePath sectionName`: arbitrary native INI sections, including `Init?family=inet6`.
- `Fail2BanFiles.file relativePath contents`: complete native files/include assets beneath `/etc/fail2ban`.
- `Fail2BanFiles.pythonAction name source`: an `action.d/<name>.py` module exporting the native `Action` implementation.
- `Fail2BanOptions.custom` and the qualified modules' `custom` functions: explicitly native values, installation-specific parameters and arbitrary interpolation variables, including native expressions for otherwise typed options.

Compatible structured contributions to the same file/section merge into one native section. Section names remain case-sensitive; option names follow native case-insensitive matching. Identical scalar declarations deduplicate and conflicting scalars are rejected. Repeated typed `Fail2BanOptions.action` declarations append to a single multiline native action option. Raw file contents are never rewritten by this composition layer; their duplicate/precedence behavior remains the native parser's responsibility.

Values preserve regex escapes, `<tags>` and multiline continuations. Interpolation forms `%(name)s`, `%(section/parameter)s`, `%(known/parameter)s`, and `<known/parameter>` retain their native meanings. Literal percent characters must be escaped as `%%` where native INI interpolation requires it. Native `before`/`after` includes and conditional family sections are supported. New `.local`-only filter/action definitions work without fabricating `.conf` companions.

Named helpers validate the supported domain before deployment. Explicit native/custom values remain available for native time expressions, interpolation, future enum values and installation-specific backends/actions; they are not constrained by the typed helper model. Native permanent bans, incremental policies, DNS allowlists and action parameters remain supported. Dependencies and side effects of custom commands/Python code remain the author's responsibility; installed version/build support and native validation still apply.

### Automatic SSH port linking

A nested SSH jail without an explicit port uses resolved local `listenaddress` ports from sshd, not `sshHost.Port` (which may be a forwarded endpoint). When `config` is present, its observed port output is an actual Pulumi input dependency, so port changes update the jail.

The helper owns `jail.d/99-dorothy-sshd-ports.local` for this automatic link. Explicit `[sshd]` or `[DEFAULT]` port declarations disable it, including native `:`-delimited options. `Fail2BanFiles.manageSshdPorts false` opts out for include-driven policies. Standalone full configuration has no implicit SSH-server dependency. The generated port file is reserved and cannot also be declared as a user file.

## Applying changes, recovery and deletion

### SSHD

Only the owned drop-in and private recovery state are written. `sshd -t` validates the candidate; plain `sshd -T` and `sshd -T -C` report global and deployment-context configuration. A separate private debug trace checks Include participation without changing the reported effective LogLevel.

Before mutation, the helper durably records prior file/state and arms an independent systemd rollback timer. It validates before reload, then requires privileged confirmation through a **fresh, non-multiplexed SSH connection**. The configured connection endpoint remains unchanged. A change that loses access is not confirmed; the host watchdog restores the previous configuration after approximately two minutes, including after reboot. Recovery reloads an active daemon or starts a restored daemon that failed/stopped; it does not restart a healthy daemon unnecessarily.

Delete removes the owned drop-in, restores native inheritance and requires the same fresh confirmation. It does not disable/uninstall SSH or modify firewall rules. Recovery state is under `/var/lib/keroosha-iac/sshd`; temporary units are `keroosha-iac-sshd-rollback.service` and `.timer`. Keep the immutable helper cache and pending state until recovery completes.

### Fail2Ban

The helper stages the resulting configuration tree—including removals—and validates it with the installed Fail2Ban parser. Multi-file writes use a durable ownership/mutation journal. Another owner's file, out-of-band file edits, unsafe paths and insecure owned-file permission drift are refused rather than silently overwritten.

Ordinary jail/filter/command-action changes use native `reload --restart --all`. Startup changes (including socket, PID file, database and thread settings) and Python-source changes restart the daemon. The old service/endpoint is stopped before installing startup changes; the new endpoint and native state must become ready within a bounded deadline. Failed changes restore attributable previous files and daemon availability; interrupted mutation retries recover from the journal.

This is shared-daemon configuration: reload/restart can affect all configured jails, including those in preserved foreign files. No `--unban` is requested, but ban persistence follows native DB/restart behavior. Changing `dbfile` does not migrate or delete a database. Setting `dbfile=None` is supported.

Delete removes only journaled files and reloads/restarts the inherited configuration. **An inherited distro/operator jail can become enabled again.** Other configuration files, database files and retained prerequisite packages remain. The shared service is not uninstalled or globally disabled merely because the resource disappears. State is `/var/lib/keroosha-iac/fail2ban/configuration.json`.

Config rollback cannot undo arbitrary external effects of command/Python actions. Such actions execute with the daemon's privileges; test them on an isolated host and maintain independent recovery access.

## Observation and security boundaries

Check, Diff and preview do not connect or mutate the host. External changes require refresh, for example `pulumi preview --refresh --diff`. Read never repairs or rolls back a pending configuration. An interrupted/invalid tree is reported as owned/out-of-sync with available file observations; endpoint/jail observations can be unavailable while that tree is incomplete. Do not infer a healthy empty daemon from such a pending snapshot.

Native effective configuration, service/jail presence and observable runtime settings are checked. Dynamic bans/counters do not cause diffs. A getter that cannot expose the original declaration is not guessed: for example `logencoding=auto` is selected in the daemon's environment, not the SSH client's forced locale. This is not an audit of arbitrary Python behavior, every possible `Match` context, external executables or the whole kernel firewall.

Owned configuration/Python files and journals are root-private (`0600`); staging/state directories are private. Full SSH effective configuration, Fail2Ban file observations and control-socket outputs are Pulumi secrets because inherited settings can contain sensitive arguments. Native validation errors do not echo configuration bodies. Native daemon logs and custom actions still obey their own logging behavior.

For secret/dynamic input contents, use the Input-typed `SshdConfigArgs.Configuration` and `Fail2BanConfigurationArgs.Files` rather than unwrapping a Pulumi secret into a plain string. Public native resource tokens are `keroosha:debian:SshdConfig` and `keroosha:debian:Fail2Ban`.

## Typed API migration

This is a source-breaking DSL migration. Update callers before changing their Dorothy dependency; there are no compatibility string overloads for typed options.

- Use `TimeSpan` for finite elapsed time, not `TimeSpan.ToString()`. Each native consumer has its own formatting, precision and range rules.
- SSH time values and finite Fail2Ban `bantime` require whole seconds; fractional values are rejected rather than truncated. Other Fail2Ban duration helpers preserve fractional seconds in native text.
- Use explicit domain cases for permanent bans, disabled/default limits and closed modes. Do not simulate them with `TimeSpan.MaxValue` or negative durations.
- Use measured sizes: SSH data limits are `int64<B>`, Fail2Ban thread stack sizes are `int<KiB>`, and Docker/swapfile sizes remain `int<MiB>`. `cpu`, `B`, `KiB` and `MiB` belong to the shared `Dorothy.DSL` namespace.
- Preserve expressions such as Fail2Ban `1mo`, formulas and `%(default/findtime)s` through the explicit native/custom surface. A native month is not a fixed 30-day `TimeSpan`.
- Provider resource tokens and string/file-map schemas are unchanged. Canonical typed serialization can still produce a textual Pulumi diff (`1w` versus `604800`) without changing effective policy; inspect preview before applying.

Docker `waitHealthy` remains `TimeSpan`: positive fractional seconds round up to the next whole second, and values exceeding `Int32.MaxValue` seconds are rejected before deployment. Healthcheck durations retain their separate Docker/Go duration range. Docker container memory inputs remain provider-native MB values; only byte-valued fields such as tmpfs perform a bytes conversion.

## Prerequisites and adoption

- Existing Debian 13/systemd, trusted SSH host keys, root or noninteractive sudo, and a compatible native helper/ICU runtime. Existing provider ICU bootstrap remains an exception to otherwise observational Read.
- SSH configuration requires an existing active OpenSSH service and native Include topology. It does not implicitly install/take ownership of `openssh-server`. SSH socket activation and transparent endpoint/firewall migration are not managed by this resource.
- Implicit `fail2ban`/`nftables` prerequisites use separate retained package resources. Other action executables/packages belong in the caller's APT declarations. Explicit package ownership is preserved; switching explicit/implicit ownership requires deliberate migration, not an assumed zero-gap handoff.
- Keep vendor `.conf` files as the baseline and inspect existing `.local` precedence before adoption. Reserved managed-path collisions require an explicit ownership transition. Do not erase foreign config or ban DBs to make an apply pass.
- Declare administrator allowlists explicitly; the deployment address is not silently trusted. Verify out-of-band console access before changing authentication, listeners or ban policy. Native-drop-in semantics intentionally preserve upstream conflicts and inheritance.
