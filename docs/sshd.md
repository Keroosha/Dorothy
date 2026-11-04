# SSHD overrides and Fail2Ban

Dorothy supports an existing Debian 13 OpenSSH server through two independent resources:

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
                    passwordAuthentication false
                    kbdInteractiveAuthentication false
                    pubkeyAuthentication true
                    permitRootLogin No
                    maxAuthTries 6
                }
                fail2ban {
                    maxRetry 5
                    findTime (TimeSpan.FromMinutes 10.)
                    banTime (TimeSpan.FromHours 1.)
                }
            }
        }
    }

Host.deploy server |> ignore
```

Replace the example address and identity path. Declare administrator IPs/networks explicitly with repeated `ignoreIp` entries inside `fail2ban`; the current deployment address is not automatically trusted. Maintain tested out-of-band console access before changing authentication or ban policy.

Both nested blocks are optional. Omission means unmanaged; a Fail2Ban-only declaration does not configure sshd. Each block may occur only once. The resource tokens retain the existing provider namespace: `keroosha:debian:SshdConfig` and `keroosha:debian:Fail2BanSshd`.

## `config`: explicit overrides, not a replacement configuration

Only declared settings are written to `/etc/ssh/sshd_config.d/00-dorothy.conf`. Removing a setting restores inheritance from the remaining system configuration. Dorothy does not copy built-in defaults, edit `/etc/ssh/sshd_config`, rewrite cloud-init files, manage authorized keys, or change UFW rules.

| Declaration | Accepted values |
| --- | --- |
| `passwordAuthentication` | `bool` |
| `kbdInteractiveAuthentication` | `bool` |
| `pubkeyAuthentication` | `bool` |
| `permitRootLogin` | `Yes`, `No`, `ProhibitPassword`, `ForcedCommandsOnly` |
| `port` | Integer 1–65535 |
| `maxAuthTries` | Positive integer |

The root-login cases are also available as `SshdRootLogin.*`. Duplicate settings are rejected. Raw configuration text, `Match` declarations and accumulating lists such as `AllowUsers` are not exposed.

OpenSSH normally uses the **first obtained value**, not the last. An early filename is insufficient if another directive occurs before the include. The helper checks syntax with `sshd -t`, global effective values with `sshd -T`, and effective values for the deployment connection with `sshd -T -C`. Conflicting precedence is an error; foreign files are not rewritten. This does not prove policy for every possible existing `Match` context.

`Port` can accumulate in OpenSSH, and an explicitly port-qualified `ListenAddress` can override listener selection. A requested port is accepted only when the effective configuration and resolved listener ports agree with that single port. Outputs derive local ports from resolved `listenaddress` entries, not from the provider's connection port.

### SSH change confirmation and recovery

Before changing its file, the helper records the previous file/ownership state and arms an independent systemd rollback timer. It validates the candidate before reloading `ssh.service`. The provider then establishes a **new** SSH connection with multiplexing disabled, executes the privileged confirmation operation, and reads back finalized state. Explicit identity files use `IdentitiesOnly=yes`.

If confirmation fails or the client disconnects, the host-owned timer restores the prior configuration after approximately two minutes. Recovery reloads an active daemon or starts the restored daemon if it failed or stopped; a healthy daemon is not restarted. The timer is enabled so a pending transaction can recover after reboot. This is recoverable reconciliation, not an atomic network transaction or a substitute for a recovery console. Independent file changes during recovery are refused rather than overwritten.

The connection endpoint is unchanged during confirmation. There is no automatic NAT inference, SSH port migration or firewall adjustment: a change that makes the configured endpoint inaccessible is not confirmed and is rolled back. Manage firewall and endpoint migrations deliberately.

The resource owns one file and one host-wide SSH ownership record. Delete removes only its override, validates/reloads the inherited configuration, and requires fresh SSH confirmation too. It does not uninstall OpenSSH or disable the SSH service.

Recovery state lives under `/var/lib/keroosha-iac/sshd`; the temporary units are `keroosha-iac-sshd-rollback.service` and `.timer`. Do not delete these files or the immutable helper cache while recovery is pending. Retry with the same resource identity after resolving an error.

## `fail2ban`: the existing sshd jail

This resource manages `/etc/fail2ban/jail.d/90-dorothy-sshd.local`, using the existing `sshd` jail rather than adding a parallel jail.

| Declaration | Default / constraint |
| --- | --- |
| `enabled` | `true` |
| `maxRetry` | `5`; positive integer |
| `findTime` | 10 minutes |
| `banTime` | 1 hour |
| `ignoreIp` | Repeatable IP/CIDR; loopback `127.0.0.0/8` and `::1` are included |

Durations must be positive whole seconds fitting Int32. DNS allowlist entries are not supported. Bare IPv4-mapped IPv6 hosts normalize to IPv4; mapped IPv6 CIDRs are rejected because their native interpretation is ambiguous. `/0` networks and unspecified hosts (`0.0.0.0`, `::`, including full-width host masks) are rejected: native Fail2Ban observations cannot distinguish these representations reliably. Use `enabled false` to disable the managed jail rather than ignoring all addresses.

The fixed policy uses:

- `backend = systemd`, without a file log path;
- the packaged `sshd[mode=normal]` filter and `usedns = no`;
- the native nftables multiport action, separate from UFW user chains;
- local listener ports discovered from `sshd -T`.

When both blocks are present, the jail depends on the SSH resource and consumes its observed ports as a Pulumi input. A port-output change therefore updates the jail; `DependsOn` alone would not do this. Without `config`, the helper discovers local ports itself.

The helper validates the complete configuration before applying it and compares managed policy with native runtime observations, including action commands and ignored-regex behavior. It requires the packaged `sshd.conf`, `common.conf` and `nftables.conf` definitions to match Debian's conffile checksums; local overrides of those filters/actions are unsupported. This is not a complete firewall audit or protection against arbitrary out-of-band changes to the daemon or its environment. Dynamic ban addresses and counters are not stored as desired state and do not cause Pulumi diffs.

`enabled false` disables only the sshd jail. **Deleting the resource removes its override and reloads the remaining configuration. That may re-enable a distro or pre-existing sshd jail.** Delete preserves other jail files, the shared daemon and the ban database. Ownership/recovery state is `/var/lib/keroosha-iac/fail2ban/sshd.json`. An edited or foreign managed-path file is refused rather than overwritten or deleted blindly.

## Prerequisites and package ownership

An already reachable OpenSSH server, active Debian `ssh.service`, working systemd, trusted SSH host keys, and root or noninteractive sudo are required. SSH socket activation and custom SSH command-line/configuration paths are unsupported. Fail2Ban requires the stock Debian service invocation with empty `SSHD_OPTS`. The native helper needs compatible ICU libraries; existing provider bootstrap behavior applies.

Dorothy does **not** implicitly install or take ownership of `openssh-server`: removing/reinstalling the active transport is unsafe. Explicit user APT declarations remain unchanged.

Missing implicit `fail2ban` and `nftables` declarations get separate, stable, retained package resources. Removing the jail does not uninstall these packages. Explicit APT declarations retain their existing ownership and deletion semantics. Moving a package between explicit and implicit ownership is not an automatic zero-gap handoff: retain the existing declaration or perform a deliberate state/ownership migration. In particular, an explicit-to-implicit transition can remove the old owner's package before its new owner installs it.

Check, Diff and preview do not connect to the host. External changes require refresh, for example `pulumi preview --refresh --diff`. Read observes policy without applying or rolling back pending SSH/jail changes; mutation retries handle recovery. SSH/command failures are errors, not absent resources. The existing helper ICU bootstrap remains an exception to read-only host inspection.

## Adopting an existing machine

1. Record effective SSH policy, service invocation, current jail policy and an out-of-band recovery path.
2. Declare only the intended SSH overrides. Confirm administrator access before disabling authentication methods.
3. Preserve existing ban thresholds during adoption unless a policy change is intentional. An existing `jail.local` remains a source of inherited settings and can become effective again after resource deletion.
4. Resolve ownership collisions at Dorothy's reserved file paths explicitly. Do not erase unrelated configuration or the ban database.
5. Apply in a maintenance window, verify a fresh login and the effective jail, then exercise ban/unban from a separate disposable source address.

Publish/install the native helper and provider using the repository's existing workflow before deploying these new resource types. No existing host is migrated merely by adding these declarations to the library.
