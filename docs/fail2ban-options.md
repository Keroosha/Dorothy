# Fail2Ban configuration catalogue

The API targets the shared Debian/Fail2Ban 1.1.0 native grammar. Values use native strings unless a true boolean/integer shape is unambiguous; no value whitelist, positive-duration policy, IP-only rule, stock action/filter restriction, or interpolation rewrite is imposed. `Fail2BanOptions` is the common jail/default/custom-variable catalog; daemon, filter, action, and include keys have qualified modules. All examples are inside `fail2ban { ... }` unless shown as a nested SSH jail.

Structured section contributions targeting the same file and case-sensitive section are coalesced into one native section. Option names compare case-insensitively: identical values are emitted once, while conflicting same-file values are rejected. Raw file contents remain byte-for-byte caller supplied.

## Daemon: `fail2ban.d/90-dorothy.local`

Use `Fail2BanSections.daemon { ... }` for `[Definition]`, and `Fail2BanSections.thread { ... }` for `[Thread]`.

| Native option | Public API / argument shape / sample |
|---|---|
| `loglevel` | `Fail2BanDaemonOptions.loglevel : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.loglevel "INFO" }` |
| `logtarget` | `Fail2BanDaemonOptions.logtarget : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.logtarget "STDOUT" }` |
| `syslogsocket` | `Fail2BanDaemonOptions.syslogsocket : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.syslogsocket "auto" }` |
| `socket` | `Fail2BanDaemonOptions.socket : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.socket "/run/fail2ban/custom.sock" }` |
| `pidfile` | `Fail2BanDaemonOptions.pidfile : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.pidfile "/run/fail2ban/custom.pid" }` |
| `allowipv6` | `Fail2BanDaemonOptions.allowipv6 : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.allowipv6 "auto" }` |
| `dbfile` | `Fail2BanDaemonOptions.dbfile : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.dbfile "/var/lib/fail2ban/custom.sqlite3" }` |
| `dbmaxmatches` | `Fail2BanDaemonOptions.dbmaxmatches : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.dbmaxmatches "20" }` |
| `dbpurgeage` | `Fail2BanDaemonOptions.dbpurgeage : string`; `Fail2BanSections.daemon { Fail2BanDaemonOptions.dbpurgeage "1d" }` |
| `stacksize` | `Fail2BanDaemonOptions.stacksize : string`; `Fail2BanSections.thread { Fail2BanDaemonOptions.stacksize "0" }` |

## Jail `[DEFAULT]` and named jail options

`Fail2BanOptions` is reusable in `Fail2BanSections.defaults { ... }`, `Fail2BanSections.jail "sshd" { ... }`, and any named jail. Unscoped options inside `sshd { fail2ban { ... } }` render in `[sshd]`; standalone unscoped options render in `[DEFAULT]`.

| Native option | Public API / argument shape / sample |
|---|---|
| `filter` | `Fail2BanOptions.filter : string`; `Fail2BanOptions.filter "sshd[mode=aggressive]"` |
| `backend` | `Fail2BanOptions.backend : string`; `Fail2BanOptions.backend "systemd[journalpath=/run/log/journal]"` |
| `logpath` | `Fail2BanOptions.logpath : string` (also `logpathList : seq<string>`); `Fail2BanOptions.logpath "/var/log/auth.log"` |
| `logencoding` | `Fail2BanOptions.logencoding : string`; `Fail2BanOptions.logencoding "auto"` |
| `logtimezone` | `Fail2BanOptions.logtimezone : string`; `Fail2BanOptions.logtimezone "UTC+0200"` |
| `enabled` | `Fail2BanOptions.enabled : bool`; `Fail2BanOptions.enabled true` |
| `bantime` | `Fail2BanOptions.bantime : string`; `Fail2BanOptions.bantime "1d12h"` |
| `findtime` | `Fail2BanOptions.findtime : string`; `Fail2BanOptions.findtime "10m"` |
| `maxretry` | `Fail2BanOptions.maxretry : int`; `Fail2BanOptions.maxretry 5` |
| `maxmatches` | `Fail2BanOptions.maxmatches : int`; `Fail2BanOptions.maxmatches 10` |
| `bantime.increment` | `Fail2BanOptions.bantimeIncrement : bool`; `Fail2BanOptions.bantimeIncrement true` |
| `bantime.factor` | `Fail2BanOptions.bantimeFactor : string`; `Fail2BanOptions.bantimeFactor "1.5"` |
| `bantime.formula` | `Fail2BanOptions.bantimeFormula : string`; `Fail2BanOptions.bantimeFormula "ban.Time * (1 << ban.Count)"` |
| `bantime.multipliers` | `Fail2BanOptions.bantimeMultipliers : string`; `Fail2BanOptions.bantimeMultipliers "1 2 4 8"` |
| `bantime.maxtime` | `Fail2BanOptions.bantimeMaxtime : string`; `Fail2BanOptions.bantimeMaxtime "30d"` |
| `bantime.rndtime` | `Fail2BanOptions.bantimeRndtime : string`; `Fail2BanOptions.bantimeRndtime "5m"` |
| `bantime.overalljails` | `Fail2BanOptions.bantimeOveralljails : bool`; `Fail2BanOptions.bantimeOveralljails false` |
| `ignoreself` | `Fail2BanOptions.ignoreself : bool`; `Fail2BanOptions.ignoreself true` |
| `ignoreip` | `Fail2BanOptions.ignoreip : string` (also `ignoreipList : seq<string>`); `Fail2BanOptions.ignoreip "127.0.0.0/8 ::1"` |
| `ignorecommand` | `Fail2BanOptions.ignorecommand : string`; `Fail2BanOptions.ignorecommand "check-ip <ip>"` |
| `ignorecache` | `Fail2BanOptions.ignorecache : string`; `Fail2BanOptions.ignorecache "key=ip max-count=100 max-time=5m"` |
| `usedns` | `Fail2BanOptions.usedns : string`; `Fail2BanOptions.usedns "warn"` |
| `destemail` | `Fail2BanOptions.destemail : string`; `Fail2BanOptions.destemail "security@example.test"` |
| `sender` | `Fail2BanOptions.sender : string`; `Fail2BanOptions.sender "fail2ban@example.test"` |
| `mta` | `Fail2BanOptions.mta : string`; `Fail2BanOptions.mta "sendmail"` |
| `protocol` | `Fail2BanOptions.protocol : string`; `Fail2BanOptions.protocol "tcp"` |
| `chain` | `Fail2BanOptions.chain : string`; `Fail2BanOptions.chain "INPUT"` |
| `port` | `Fail2BanOptions.port : string`; `Fail2BanOptions.port "ssh,http,https"` |
| `fail2ban_agent` | `Fail2BanOptions.fail2banAgent : string`; `Fail2BanOptions.fail2banAgent "site policy"` |
| `banaction` | `Fail2BanOptions.banaction : string`; `Fail2BanOptions.banaction "nftables[type=multiport]"` |
| `banaction_allports` | `Fail2BanOptions.banactionAllports : string`; `Fail2BanOptions.banactionAllports "nftables[type=allports]"` |
| `action` | `Fail2BanOptions.action : string`; repeated typed `action` entries append in order into one native multiline option; `Fail2BanOptions.action "custom[name=outside]"`; explicit `actionList : seq<string>` is also available for multiple actions. |
| Stock/custom `action_*` interpolation variables | `Fail2BanOptions.actionShortcut name value`, plus named helpers `actionMw`, `actionMwl`, `actionXarf`, `actionCfMwl`, `actionBlocklistDe`, and `actionAbuseipdb`; `Fail2BanOptions.actionShortcut "custom" "%(action_)s"` |
| Any native/custom jail interpolation key | `Fail2BanOptions.custom name value`; `Fail2BanOptions.custom "tenant" "prod"` |

No convenience helper is restricted to packaged action names; action executables and their dependencies remain caller-managed.

## Filter files: `filter.d/<name>.local`

`Fail2BanSections.filterIncludes`, `filterDefaults`, `filter`, and `filterInit` target `[INCLUDES]`, `[DEFAULT]`, `[Definition]`, and `[Init]` respectively. Every value remains native text, preserving percent escapes, tags, regex syntax, and multiline content.

| Native option | Public API / argument shape / sample |
|---|---|
| `prefregex` | `Fail2BanFilterOptions.prefregex : string`; `Fail2BanFilterOptions.prefregex "^sshd\\["` |
| `failregex` | `Fail2BanFilterOptions.failregex : string` (also `failregexList : seq<string>`); `Fail2BanFilterOptions.failregex "^Failed login from <HOST>$"` |
| `ignoreregex` | `Fail2BanFilterOptions.ignoreregex : string` (also `ignoreregexList : seq<string>`); `Fail2BanFilterOptions.ignoreregex "^ignored <HOST>$"` |
| `maxlines` | `Fail2BanFilterOptions.maxlines : int`; `Fail2BanFilterOptions.maxlines 10` |
| `datepattern` | `Fail2BanFilterOptions.datepattern : string`; `Fail2BanFilterOptions.datepattern "%%Y-%%m-%%d"` |
| `journalmatch` | `Fail2BanFilterOptions.journalmatch : string`; `Fail2BanFilterOptions.journalmatch "_SYSTEMD_UNIT=ssh.service"` |
| `before`, `after` includes | `Fail2BanIncludeOptions.before/after : string`; `Fail2BanSections.filterIncludes "custom" { Fail2BanIncludeOptions.before "common.conf" }` |
| Custom `[DEFAULT]`, `[Definition]`, `[Init]` values | `Fail2BanFilterOptions.custom name value`; e.g. `Fail2BanSections.filterInit "custom" { Fail2BanFilterOptions.custom "mode" "aggressive" }` |

## Command action files: `action.d/<name>.local`

`Fail2BanSections.actionIncludes`, `action`, and `actionInit` target `[INCLUDES]`, `[Definition]`, and `[Init]`. The normal and additional 1.1.0 action hooks and engine properties have named helpers.

| Native option/property | Public API / argument shape / sample |
|---|---|
| `actionstart` | `Fail2BanActionOptions.actionstart : string`; `Fail2BanActionOptions.actionstart "create-chain"` |
| `actionstop` | `Fail2BanActionOptions.actionstop : string`; `Fail2BanActionOptions.actionstop "delete-chain"` |
| `actioncheck` | `Fail2BanActionOptions.actioncheck : string`; `Fail2BanActionOptions.actioncheck "chain-exists"` |
| `actionban` | `Fail2BanActionOptions.actionban : string`; `Fail2BanActionOptions.actionban "ban <ip>"` |
| `actionunban` | `Fail2BanActionOptions.actionunban : string`; `Fail2BanActionOptions.actionunban "unban <ip>"` |
| `actionflush` | `Fail2BanActionOptions.actionflush : string`; `Fail2BanActionOptions.actionflush "flush <name>"` |
| `actionrepair` | `Fail2BanActionOptions.actionrepair : string`; `Fail2BanActionOptions.actionrepair "restore-chain"` |
| `actionreload` | `Fail2BanActionOptions.actionreload : string`; `Fail2BanActionOptions.actionreload "reload-map"` |
| `actionreban` | `Fail2BanActionOptions.actionreban : string`; `Fail2BanActionOptions.actionreban "ban <ip>"` |
| `actionprolong` | `Fail2BanActionOptions.actionprolong : string`; `Fail2BanActionOptions.actionprolong "refresh <ip>"` |
| `timeout` | `Fail2BanActionOptions.timeout : string`; `Fail2BanActionOptions.timeout "30"` |
| `actionstart_on_demand` | `Fail2BanActionOptions.actionstartOnDemand : string`; `Fail2BanActionOptions.actionstartOnDemand "true"` |
| `actionrepair_on_unban` | `Fail2BanActionOptions.actionrepairOnUnban : string`; `Fail2BanActionOptions.actionrepairOnUnban "true"` |
| `families` | `Fail2BanActionOptions.families : string`; `Fail2BanActionOptions.families "inet4 inet6"` |
| `norestored` | `Fail2BanActionOptions.norestored : string`; `Fail2BanActionOptions.norestored "true"` |
| Arbitrary `[Init]`, `[Definition]`, or custom action key | `Fail2BanActionOptions.init/definition/custom name value`; e.g. `Fail2BanSections.actionInit "custom" { Fail2BanActionOptions.init "table" "filter" }` |
| `before`, `after` includes | `Fail2BanIncludeOptions.before/after : string`; `Fail2BanSections.actionIncludes "custom" { Fail2BanIncludeOptions.before "base.conf" }` |

## Native sections and files

- `Fail2BanSections.nativeSection relativePath sectionName { Fail2BanOptions.custom key value }` emits any native INI section in a caller-selected file beneath `/etc/fail2ban`.
- `Fail2BanFiles.file relativePath completeContents` owns complete native `.conf`/`.local`/other include assets; path segments are checked against absolute/traversal escapes, values are not allowlisted.
- `Fail2BanFiles.pythonAction "name" source` owns `action.d/name.py` as executable caller-provided Python action source.
- `Fail2BanFiles.manageSshdPorts false` explicitly opts out of nested sshd listener synchronization; automatically generated `jail.d/99-dorothy-sshd-ports.local` is reserved and cannot be user-owned.
- `Fail2BanOptions.custom`, module-specific `custom`, and raw `file`/`nativeSection` paths preserve installation/vendor options not in the standard inventories.

## Native authority

- [Debian 13 Fail2Ban configuration manual](https://manpages.debian.org/trixie/fail2ban/jail.conf.5.en.html).
- [Fail2Ban 1.1.0 command-action implementation](https://github.com/fail2ban/fail2ban/blob/1.1.0/fail2ban/server/action.py) supplies hooks omitted from the older manual, including `actionflush`, `actionrepair`, `actionreload`, `actionreban`, and optional `actionprolong`.

These examples illustrate native syntax and option placement; custom commands/files must exist and be suitable for the target. The installed native implementation remains authoritative for version-specific extensions.
