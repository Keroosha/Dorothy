# Permanent firewalld configuration

Target: Debian 13, firewalld 2.3.1. This is the implementation and acceptance plan, **not an assertion that any row has passed**. Authorities: the [2.3.1 object parsers](https://github.com/firewalld/firewalld/tree/v2.3.1/src/firewall/core/io), [rich language](https://github.com/firewalld/firewalld/blob/v2.3.1/src/firewall/core/rich.py), [daemon configuration reader](https://github.com/firewalld/firewalld/blob/v2.3.1/src/firewall/core/io/firewalld_conf.py), and [Debian manual](https://manpages.debian.org/trixie/firewalld/firewalld.1.en.html). If an XSD predates the implementation, the installed daemon decides.

## Resource and migration contract

Each named definition, zone, policy, and daemon key has one owner. A reference within a declaration resolves to its declared owner or to an existing external definition; external references create no ownership. Detect cycles and multi-owner bindings before deploying. Preserve existing resource tokens/names, IDs, journal owners, legacy port and strict-setting serialization. Preview is offline. An unchanged legacy configuration must not request a replacement, reload or restart. An identity-changing replacement cannot reuse another generation's journal.

A port range belongs to its transport; a service describes traffic, not a listener. For example, a service admitting TCP 8440–8443 can be attached to a named source zone → `HOST` policy without granting traffic from that zone to any other zone. DNAT has an independent original transport/port and a destination address and/or port. Neither implies general forwarding. Rich-rule ordering and restrictions must survive wire and native round trips. A closed native vocabulary is not arbitrary XML, shell, paths or direct rules.

```fsharp
open Dorothy.DSL
open Dorothy.DSL.Firewalld

let api = service "example-api" {
    transportPorts [portRange 8440 8443 FirewalldTransport.Tcp]
}
let firewall = firewalld {
    api
    zone "clients" { interfaces ["vpn0"] }
    policy "clients-to-host" {
        ingressZones ["clients"]
        egressZones ["HOST"]
        services [api.Name]
        priority -2
    }
}
```

`services ["ssh"]` references an external definition if the host does not declare `service "ssh"`. In contrast, `services [api.Name]` above finds the declared definition. Removing `api` while leaving a reference is not a safe way to change owners: remove references first or explicitly provision the external definition. For transitions between bindings, keep a working management path at every step, not just in the final declaration.

The implicit `firewalld` package is a retained prerequisite. Removing the firewall configuration restores its objects and keys; it must not uninstall the daemon that enforces the remaining policy. An explicit APT `firewalld` declaration keeps its original package ownership and removal semantics. **Existing stacks:** apply the new DSL once while the firewalld block is still present, and verify `retainOnDelete: true` on the implicit package in the exported checkpoint before removing the block or destroying the stack. A destroy using only an old checkpoint cannot pick up a new resource option.

## Implementation and acceptance matrix

| Native capability | Public declaration / wire | Helper and Read contract | Required evidence |
|---|---|---|---|
| Zone and policy identity, version, short, description, target, priorities | Existing zone/policy objects plus explicit typed fields; preserve existing inputs | Validate object-specific fields; compare complete permanent override, separately observe live packet selectors | Old checkpoint preview; metadata drift; native input rejection |
| Interfaces; address/CIDR, MAC and ipset source bindings | Zone interfaces and source selectors; separate named ipset | Check source and interface conflicts, effective management path and live bindings | IPv4 and IPv6 source isolation; unrelated source succeeds; conflicting binding refused |
| Policy ingress, egress, `HOST`, `ANY`, priority, masquerade; zone forward | Directional policy, zone forward unchanged | Distinguish inbound local traffic from forwarding and replies; enforce each intermediate transition | Host-only permitted service, denied sibling port, other-zone traffic remains dropped |
| Service/port/protocol/source-port; service include, destination, helper and module | Named service object and references from both consumers; port/range + TCP/UDP/SCTP/DCCP | Definition before reference, reverse order on removal; reject unresolved/cyclic include; external service read only | Shared service used twice, missing dependency fails before reload |
| Rich family, priority, inverted source/destination, service, port, source-port, protocol, ICMP, NAT, logging/NFLOG, audit, limits and actions | Structured constrained rule parts (no raw XML); preserve branch and sequence | Compare full rule and provenance; refuse an ambiguous change affecting actual management, allow provably disjoint changes | Matching/nonmatching ingress; management interception refused before write |
| Forward-port and masquerade | Separate original port/transport and destination; zone or policy scope | Verify native rules after activation; strict forwarding independent of service allowance | Declared translation works, adjacent port remains closed, strict mode survives reboot |
| ICMP block, inversion, ICMP type and conntrack helper | Named definitions and references, ICMP destinations and helper module/family/ports | Only valid kinds can use each field; definition lifetimes independent of references | Native catalogue and load; no deletion of vendor definitions |
| Ipset type, options and entries | Named set, explicit typed native options and entries | Manage one set, not foreign/dynamic membership; reject ambiguity rather than claiming external changes | Bound set directs expected sources; foreign sets remain unchanged |
| `DefaultZone`, `LogDenied`, `StrictForwardPorts`, `ReloadPolicy`, `FlushAllOnReload` | One settings resource per key; old strict resource identity unchanged | Edit only owned key, distinguish missing vs explicit; preflight candidate default zone and confirm a fresh SSH connection | Observe daemon state and traffic after activation and reboot; delete restores key baseline |
| `CleanupOnExit`, `CleanupModulesOnExit`, `IPv6_rpfilter`, `IndividualCalls`, `FirewallBackend`, `RFC3964_IPv4`, `NftablesFlowtable`, `NftablesCounters`, `NftablesTableOwner`; compatibility keys `MinimalMark`, `AutomaticHelpers`, `AllowZoneDrifting`, `Lockdown` | Closed catalogue, native value grammar; document ineffectual/deprecated keys rather than invent behavior | Stage settings; choose appropriate daemon activation; preserve unrelated text; filesystem alone does not establish runtime behavior | Per-key native catalogue, restart-only setting, unrelated key edit and restoration |
| Takeover, drift, rollback and delete | Existing generation and journal plus guarded activation | Never silently erase unrepresented baseline, never capture runtime-to-permanent; read does not repair. Independently armed recovery before mutations and fresh SSH confirmation after apply/delete | Original override restored including bindings, no foreign deletes; disconnect/reboot recovery; runtime-only vs permanent drift |

Out of scope: legacy direct/passthrough rules, arbitrary nftables or shell commands, sysctls and management of other software's runtime rules. They are not an extension mechanism. The acceptance environment is a disposable guest and file backend; transport and traffic checks must not change the workstation firewall. A compiled catalogue, native load, runtime read and packet probe are different evidence. Record each separately; unsupported or untested behavior is not a pass.

### Native catalogue notes

* The filename identifies a definition. The old root `name` and zone `immutable` attributes have no authority in 2.3.1. A split zone is a merge of several files, not several independently removable owners of one live zone. Do not discard unrecognized fragments when adopting an existing configuration.
* Zone attributes `ingress-priority` and `egress-priority` classify traffic; policy `priority` orders policies. Rich-rule `priority` orders rules. Equal rich priorities do not imply source-file order on the wire. A trailing `+` on an interface is a kernel prefix match (`eth+` matches `eth0`), not the literal interface name `eth+`.
* Native rich selectors are `source` (`address`, `mac` or `ipset`) and `destination` (`address` or `ipset`), optionally inverted. A rule has at most one service, protocol, port, source-port, ICMP block/type, masquerade, forward-port or `tcp-mss-clamp` element. Actions include accept, reject with optional type, drop, or mark with optional mask. `log` and `nflog` are alternatives; NFLOG has group, prefix and queue-size. An action, log or audit can have its own limit (`value`, optional `burst`). Ordinary zone MAC bindings use the native `source address=` form; rich rules use `source mac=`.
* The 2.3.1 ipset catalogue has `hash:ip`, `hash:ip,port`, `hash:ip,port,ip`, `hash:ip,port,net`, `hash:ip,mark`, `hash:net`, `hash:net,net`, `hash:net,port`, `hash:net,port,net`, `hash:net,iface` and `hash:mac`. Its create options are `family`, `hashsize`, `maxelem` and `timeout`. Kernel/backend support and the ability to use a set as a zone source are narrower than the catalogue. A timeout-backed runtime set is not a declaration of expiring entries.
* A service's old `<port port="" protocol="…"/>` notation maps to a protocol, not port zero. An ICMP type's `destination` activates address families; a service's `destination` constrains addresses. The helper `module` identifies a kernel conntrack helper (`nf_conntrack_…`); arbitrary module paths or module installation are not part of the API.
* `MinimalMark`, `AutomaticHelpers`, `AllowZoneDrifting` and `Lockdown` are compatibility settings, not controls to rely on for traffic enforcement. `FlushAllOnReload` selects native reload semantics: an operator cannot rely on ephemeral entries surviving a reload or reboot. Dorothy must not use `--runtime-to-permanent` to make a comparison pass.

### What a refresh can establish

`actual` remains the permanent object XML or effective setting value. `permanentInSync` includes the permanent comparison and the resource's ownership record. `runtimeObserved` and `runtimeInSync` describe the native runtime check separately. `inSync` is the provider's repair signal; a pending transaction is never in sync. Preview does not attempt any observation.

| Daemon key | Runtime evidence or limit on 2.3.1 |
|---|---|
| `DefaultZone`, `LogDenied` | Their `firewall-cmd --get-*` answers come from the running daemon. |
| `FirewallBackend`, `StrictForwardPorts` | Identify the loaded backend and its own rules. In strict nftables mode, input, forward and output DNAT each jump to a scoped chain ending in rejection; in non-strict mode the generic DNAT acceptance is present. A setting in the file alone is not evidence. |
| `NftablesCounters`, `NftablesTableOwner`, `NftablesFlowtable` | Inspect counters on rules, flags on `inet firewalld` and flowtable interfaces. These checks concern the nftables backend, not iptables. |
| `IPv6_rpfilter` | The public boolean cannot distinguish the native strict/loose and forwarding-only modes. |
| `IndividualCalls`, `CleanupOnExit`, `CleanupModulesOnExit`, `FlushAllOnReload`, `ReloadPolicy`, `RFC3964_IPv4` | Key-specific ownership and successful activation can be recorded. There is no exact public live value to assert. |
| Deprecated/ignored keys | A persisted spelling does not create a traffic or security guarantee. |

For a key without an exact getter, `runtimeObserved=false` and `runtimeInSync=false` distinguish a confirmed activation from a measured live value. Failure to query an observable setting must not silently count as a successful observation. A named object's live query concerns firewalld's selectors, not every rule in the kernel. In particular, independently administered policies and other packet filters may change actual reachability; use packet probes for that claim.

## Acceptance evidence

Debian 13 amd64, firewalld `2.3.1-1+deb13u1`, a dedicated SSH identity, a local Pulumi file backend and network namespaces used as independent packet sources. No workstation or production firewall was used.

| Scope | Observed result | Limit |
|---|---|---|
| Wire and native catalogue (F2–F4) | Compiled consumer/provider/helper tests; the installed `firewall-offline-cmd --check-config` accepted seven objects covering the six XML kinds, rich selectors/actions, both families and DNAT. A second catalogue exercised all eleven native hash ipset types with entries. A forward-port with neither destination field was rejected by the daemon. | Parser acceptance is not packet proof for every address, transport, ICMP name, helper or ipset tuple. In particular, a user-chosen ICMP definition name does not add a kernel ICMP type. |
| State compatibility and ordering (F1/F2) | Applied the previous release's zone, policy and strict setting on the disposable guest. An offline preview against its real checkpoint reported **six unchanged resources and no SSH calls**. One named service was observed in both a zone and a `HOST` policy. | No real operator checkpoint was imported. External references do not become managed resources. |
| Packet behavior (F2/F3) | IPv4 and IPv6: the intended client could connect to the declared host service and a rich-rule port; an unlisted port and the other client were denied. Direct forwarding was denied. Scoped DNAT reached a separately listening target; the adjacent port and the other source were denied. ICMP echo was source-dependent. | These are specific TCP/ICMP packet probes, not a test of all protocols. The Docker readiness unit was tested under actual systemd against a live DROP policy, **not** by deploying containers. A live port exception prevented the gate starting. |
| Refresh and repair (F1) | A runtime-only service removal and a separate permanent change survived read-only refresh; apply restored the named object's live and permanent service membership and packet behavior. | Independent filters outside firewalld remain outside the observation boundary. |
| SSH safety and ownership (F1/F3) | A rich drop matching the actual SSH management tuple was refused with configuration, journals and loaded rules unchanged. A competing stack could not acquire the active zone. An undeclared rich baseline was refused before overwrite. | Ambiguous management paths, split zone directories, and an old adopted override with unrecorded original mode on deletion are refused rather than guessed. |
| Daemon settings (F4) | Used a new default DROP zone that explicitly permitted management SSH. Changing `FirewallBackend` from nftables to iptables and back changed systemd invocation IDs/PIDs. Fresh SSH, strict DNAT, both IP families and negative controls passed under both backends. The iptables checkpoint refreshed without drift. | The remaining daemon keys were covered by compiled validation; not every knob received a separate kernel/packet test. See per-key getter limits above. |
| Independent recovery (F1/F4) | With fresh confirmation denied, refresh did not alter the pending files or journals. The two-minute timer restored the previous setting; reapply from the stale checkpoint converged. In a separate pending transaction the guest rebooted: the old SSH channel died, the boot ID changed, fresh SSH and the packet probes worked, and refresh plus no-op preview reported **19 unchanged resources**. | Rollback requires systemd and a writable, attributable saved baseline. Concurrent foreign edits to the transaction file are not silently overwritten. |
| Destroy, including a migrated checkpoint (F1/F2/F4) | Verified two independent stacks on a guest with firewalld already installed. A fresh stack exported `retainOnDelete=true`. The old DSL instead exported no retention flag; an ordinary `pulumi up --refresh=false` with the new DSL and identical configuration reported six unchanged resources, opened no SSH connections, **and persisted `retainOnDelete=true`**. Both subsequent destroys retained the daemon. The service consumers were removed before their definitions; a representable adopted override was restored byte-for-byte. | The new DSL must actually register the resource: merely upgrading the provider executable or running preview does not rewrite the checkpoint. Explicit package owners still control package deletion. |

After destroy, fresh SSH succeeded, the preinstalled `firewalld` package was still `2.3.1-1+deb13u1`, and its public zone again allowed `ssh` and `dhcpv6-client` with no custom ports or rich rules. `DefaultZone`, `LogDenied`, `FirewallBackend` and `StrictForwardPorts` returned to baseline. All 338 vendor files and both independently created zone files matched their saved hashes. No managed overrides or transaction journals remained. The host-level systemd watchdog units and helper cache remain installed: without a pending journal they do not change firewall policy.
