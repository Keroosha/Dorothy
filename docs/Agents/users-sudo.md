# Local users, SSH keys, and sudo

`users` and `sudo` are independent, optional blocks inside `debian`. They build immutable specifications; only `Host.deploy` registers resources. Each block may appear once per host. Their declarations support the existing `for`, `if`, and `yield!` composition style.

## Passwordless administration

For an existing account, no `users` declaration or membership in the distribution's `sudo` group is required:

```fsharp
open Dorothy.DSL

let server =
    sshHost "server" {
        Address "192.0.2.10"
        User "debian"
        debian {
            sudo {
                grant "alice-admin" {
                    subjects [ SudoSubject.User "alice" ]
                    runAs AllUsersAndGroups
                    authentication Passwordless
                    allCommands
                }
            }
        }
    }

Host.deploy server |> ignore
```

This grants arbitrary commands as any user/group without sudo authentication. It is full administrative authority, not a sandbox.

The SSH connection account is a separate role. Dorothy requires root or existing noninteractive sudo for privileged shell bootstrap and its immutable native helper. A grant permitting only `apt update` cannot run Dorothy, and a non-root connection cannot bootstrap a missing `sudo` executable.

The native helper is root-equivalent management software. Do not expose it to untrusted users as a supposedly restricted sudo command.

## Creating accounts and installing public keys

```fsharp
open System.IO
open Dorothy.DSL

let aliceKey = File.ReadAllText("./keys/alice.pub").Trim()

let accounts =
    users {
        group "operators" {
            gid 2200
        }
        user "alice" {
            kind Human
            description "Operations account"
            primaryGroup PrivateGroup
            supplementaryGroups (Managed [ "operators" ])
            home (Home.Create("/home/alice", 0o700))
            shell "/bin/bash"
            password Password.Locked
            onDelete RetainIdentity
            authorizedKeys {
                mode AuthorizedKeysMode.Exclusive
                key "workstation" {
                    publicKey aliceKey
                    restrict
                    allowPty true
                }
            }
        }
        user "application" {
            kind UserKind.System
            home Home.None
            shell "/usr/sbin/nologin"
            password Password.Locked
        }
    }
```

Yield `accounts` inside the host's `debian` block. The deployment account must remain outside this Users resource; use an independent administrator to manage other accounts.

### Account fields

| Declaration | Meaning |
| --- | --- |
| `kind Human` / `kind UserKind.System` | Creation policy, including automatic identifier allocation |
| `uid`, group `gid` | Explicit numeric identifiers; existing identifiers are not migrated |
| `existing Adopt` | Explicitly adopt an existing local identity; default is reject |
| `description` | GECOS description |
| `primaryGroup PrivateGroup` | Private same-name primary group |
| `primaryGroup (ExistingGroup "name")` | Reference an existing or declared group |
| `supplementaryGroups (Managed names)` | Reconcile Dorothy's additions while preserving foreign memberships |
| `supplementaryGroups (Exclusive names)` | Reconcile the complete supplementary membership list |
| `home (Home.Create(path, mode))` | Create/manage the declared home directory without recursive data migration |
| `Home.CreateWithSkeleton(path, mode, skeleton)` | Supply a skeleton for home creation |
| `home (Home.Existing path)` | Use an existing home path |
| `home Home.None` | Do not create a home; use Debian's `/nonexistent` |
| `shell` | Absolute login-shell path; install its package first |
| `password Password.Locked` | Disable Unix password authentication, not every authentication method |
| `password (Password.Hash hashInput)` | A crypt-format password hash, never plaintext |
| `passwordUpdate PasswordUpdate.Always` / `OnCreate` | Hash reconciliation or creation-only seeding |
| `accountExpiry Never` / `accountExpiry (On date)` | Account expiration using `System.DateOnly` |
| `passwordPolicy { minDays ...; maxDays ...; warnDays ...; inactiveDays ... }` | Explicit native password-aging controls |
| `subordinateUids [ subordinateIdRange start count ]` | Declared subordinate UID ranges |
| `subordinateGids [ subordinateIdRange start count ]` | Declared subordinate GID ranges |
| `state Absent` | Explicit account deletion, subject to ownership and safety checks |

New human accounts default to a private group, locked password, `/home/<name>` with mode `0700`, and `/bin/bash`. New system accounts default to a private group, locked password, `/nonexistent`, and `/usr/sbin/nologin`. Creation defaults are not applied when adopting an existing account.

`Password.Hash` accepts `Pulumi.Input<string>`. `Host.deploy` marks hashes secret even when a caller supplies a literal input; provider state preserves secret metadata. Native password updates use stdin, and observed outputs/diagnostics do not contain password hashes. Prefer obtaining the hash from Pulumi secret configuration rather than committing it to source.

Hash updates default to `PasswordUpdate.OnCreate`. Set `passwordUpdate PasswordUpdate.Always` when password rotation and hash drift repair should be declarative.

Password locking, password aging, account expiration, and the login shell are different controls. In particular, on Debian with `UsePAM yes`, a locked Unix password can coexist with working SSH public-key authentication. No password rotation schedule is imposed unless declared.

### Ownership and removal

- Adoption of an identity does not automatically acquire all its existing memberships or keys.
- `Managed` tracks additions actually made by this resource. A coincidentally existing matching entry remains foreign.
- `Exclusive` controls the selected collection completely. Apply repairs content drift in a safely owned key file; it is not an exclusive policy for every login mechanism on the host.
- Omitted scalar settings are not reset to distribution defaults. Removing managed access declarations revokes the resource's tracked access rather than restoring historical credentials.
- A concurrent edit during a pending key transaction is a conflict. Releasing an Exclusive key declaration also refuses a changed file rather than erasing unrecognized credentials: reconcile it under the explicit declaration before removing that declaration.
- Removing an account declaration or deleting the resource retains identities and home data, and removes tracked keys, memberships, and subordinate-ID grants. Passwords and unrelated grants may remain. This is not complete offboarding.
- `state Absent` deletes the local account without purging its home. Active accounts, identity collisions, implicit UID/GID migrations, and protected deployment identities are rejected.
- `userdel` can also remove an unused same-name private group. Authorize that group deletion explicitly; an unowned group also needs `existing Adopt`:

```fsharp
users {
    group "retired" {
        existing Adopt
        state Absent
    }
    user "retired" {
        existing Adopt
        state Absent
    }
}
```

An existing primary group still used by another account cannot be deleted. Retained files keep their numeric owners; review orphaned data before reusing a deleted UID/GID. No recursive `chown`, home relocation, or process termination is performed.

The native helper keeps root-only ownership and recovery records under `/var/lib/keroosha-iac/users`. Mutation guards cover the current deployment identity even when cleanup is implicit or that identity is omitted from the new declaration. Read does not complete pending mutations. Use the same resource identity when retrying interrupted work.

## Authorized keys

Only public keys belong here. Each `key` has a stable declaration ID and one public-key value. Supported typed controls include `comment`, `restrict`, `restrictKey`, `allowPty`, `allowAgentForwarding`, `allowPortForwarding`, `allowX11Forwarding`, `allowUserRc`, `allowFrom`, `authorizedCommand`, `keyExpires`, `permitOpen`, `permitListen`, and `verifyRequired`.

`keyExpires` accepts `System.DateTimeOffset`; expiry is rendered in UTC. Forwarding destinations are emitted as separate OpenSSH options. Both existing and generated `authorized_keys` files are limited to **1 MiB**.

The helper manages the conventional home `.ssh/authorized_keys` file. It refuses unsafe filesystem objects, foreign directory ownership, symlinks, and non-regular key files. It does not take ownership of an existing root-managed `.ssh` directory to make an operation succeed.

`restrict` disables forwarding, PTY, and user rc; `allowPty true` re-enables PTY. It does **not** prohibit an ordinary shell. Use `authorizedCommand` when a key should execute a forced command.

These are user-owned key files: their owner can change them. They are not an enforcement boundary against that user. Other key files, certificate authorities, `AuthorizedKeysCommand`, and PAM/sshd policies remain independent. This resource does not modify sshd configuration or introduce a second owner for it.

## Selective sudo permissions

To give only package-maintenance permissions instead of the full administrator grant:

```fsharp
sudo {
    grant "package-maintenance" {
        subjects [ SudoSubject.Group "operators" ]
        runAsUser "root"
        authentication Passwordless
        (command "/usr/bin/apt") {
            arguments (Exact "update")
        }
        (command "/usr/bin/apt") {
            arguments (Exact "upgrade")
        }
    }
}
```

The parentheses around the overloaded `command` builder are required. Docker's existing `command [ ... ]` syntax remains supported, as do its `runAs` and Traefik's `password` declarations through the shared dispatchers.

A grant requires subjects, an explicit run-as choice, and either `allCommands` or a nonempty command list. `authentication` defaults to `Required`; `Passwordless` is explicit. `runAsGroup` may accompany `runAsUser`.

Every command requires an argument restriction:

- `NoArguments`: only a call with no arguments. This renders sudoers' special empty-argument restriction.
- `Exact "..."`: a literal sudo argument-string match, not an `argv`-array comparison. Metacharacters are escaped, not interpreted as user-supplied glob/regex syntax.
- `AnyArguments`: arbitrary arguments, explicitly requested.

Omitting arguments in native sudoers means **any arguments**, so the DSL never silently chooses that behavior. Exact values accept ASCII letters/digits and spaces plus `_ - . / : = + @ % , * ? [ ] \\ ^ $`; empty values, leading/trailing spaces, controls, quotes, `#`, and other unsupported characters are rejected. Paths must be absolute supported executable paths; raw sudoers directives, aliases, negative command lists, and regex policies are not exposed.

`Required` follows native sudo/PAM authentication and timestamp semantics; it is not a promise to prompt on every invocation. Generated rules explicitly use `NOSETENV`. Broad shell, interpreter, package-manager, Docker, and writable-script privileges are not sandboxes. Exact APT calls still execute trusted repository packages, maintainer scripts, and configured hooks.

### Native policy validation and coverage

Each Sudo resource owns one deterministic `90-keroosha-iac-<digest>` file in `/etc/sudoers.d` and a root-only journal under `/var/lib/keroosha-iac/sudoers`. It leaves foreign policy and the sudo package intact on deletion. A foreign edit to the owned sudoers file is a conflict, not permission to overwrite another administrator's policy.

Before publication, the helper validates the actual include graph in a private mount namespace with the candidate directory bound at `/etc/sudoers.d`. It uses `visudo`, native verbose sudo policy observations, and fresh deployment-user probes without a cached authentication timestamp. Failure restores the previous owned policy. Read observes ownership, native policy, and pending state without applying recovery.

For current relevant principals, later foreign entries in the verbose policy listing are conservatively rejected rather than assumed disjoint based on path or run-as spelling. Conflicting owned authentication grants are rejected too. Keep a principal's Dorothy grants together instead of splitting overlapping policies across owners.

Actual grant observations distinguish `effectiveVerified` from coverage. Empty existing groups can have structurally installed grants without a current-user authorization proof; unresolved principals are reported as drift. This is not a whole-host least-privilege audit or a guarantee about future NSS members. A narrower grant does not withdraw privileges supplied elsewhere.

## Host prerequisites and operational limits

The target is a reachable Debian 13 Linux host with the normal local account databases, shadow utilities, NSS tools, `procps`, and util-linux. OpenSSH public-key login must already be available. Sudo validation additionally requires `sudo`/`visudo` and working private mount namespaces (`unshare`, `mount`, and the necessary privileges, including `CAP_SYS_ADMIN`). Restricted containers without those capabilities fail closed.

`Host.deploy` orders package prerequisites before Users and Users before Sudo. When needed, it creates a retained implicit sudo-package resource; removing the Sudo block does not uninstall that package. Explicit APT declarations keep their existing ownership semantics. Moving `sudo` from an explicit APT declaration to implicit ownership is **not** an automatic safe handoff: the old owner can uninstall the transport prerequisite during the transition. Preserve explicit ownership or perform a deliberate migration with independent administration.

Check, Diff, and ordinary preview do not contact the host. Discover external drift with `pulumi refresh` or `pulumi preview --refresh --diff`; native Read observes without repair. The existing helper bootstrap behavior still applies.

No batch-wide transaction spans users, keys, groups, packages, and sudo. A failed apply can leave recoverable partial work recorded in the journals. Keep an independently tested recovery account/console. Key removal, group changes, and account expiration do not terminate existing sessions or already privileged processes.
