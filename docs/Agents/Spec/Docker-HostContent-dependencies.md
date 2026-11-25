# Docker container dependencies on host content directories and firewalld

## Contract

- `HostContentItem.Directory` exposes a typed `HostContentDirectory` for a declared `directory`.
- Docker bind mounts can reference that identity; `usesDirectory` adds an explicit dependency without a mount. The Debian host builder rejects a directory reference that is not reference-identical to a directory in the same host's `content` block.
- Each container's Pulumi `DependsOn` contains only its mount/`usesDirectory` directory resources, its declared container dependencies, and explicitly selected firewalld policy resources.
- `DockerBuilders.dependsOnFirewalld` is a typed policy dependency. The host builder rejects undeclared/non-policy references. It never infers a container dependency from all policies with Docker egress, preserving existing graphs on hosts that do not opt in.
- `Firewalld.strictForwardPorts true` owns the host-wide `StrictForwardPorts` setting through a journaled `FirewalldSettings` resource. A strict host with Docker containers must explicitly bind each container to a declared `DROP` policy whose egress includes `docker`; the setting and policy precede container creation. The setting is installed before Docker package installation/start and restored to its captured baseline on resource deletion.
- Firewalld global-setting changes preserve unrelated lines in `firewalld.conf`, refuse conflicting edits to the owned setting, and roll back failed config validation/reload before releasing first-create ownership.

## Implementation

- Docker directory dependencies, firewalld policy dependencies, and container-to-container dependencies remain distinct typed edges.
- Generic tests capture actual Pulumi resource options, verify bind-mount access and per-container directory/policy dependencies, reject undeclared directory/policy references, and ensure unrelated firewalld policies do not enter a container graph.
- Firewalld tests exercise global setting serialization, provider Check/preview, apply/read/delete baseline restoration, conflicting external changes, and rollback on reload failure.
- No `Compose`, global file/container dependency, resource rename, or change to non-opted-in Docker host graphs.

## Verification

Runtime packet-path behavior must be proved separately on an isolated Debian 13 guest with the packaged Docker engine. This specification does not treat a loopback bind, firewalld zone priority, or a successful Pulumi graph test as evidence that Docker published-port DNAT is blocked.

## Disposable runtime evidence

- A consumer graph was applied to a disposable Debian 13.8 amd64 VM with local Pulumi state, a local-only test certificate, and no manually prepared declared content paths. The first apply created the graph and its immediate no-op reported all resources unchanged; replacement and targeted delete/recreate retained writable state. This is not a pristine stock-host result: before this smoke, cloud-init had been removed from that disposable guest.
- The packaged Docker engine was 26.1.5 and Firewalld 2.3.1. A same-L2 veth peer reached an allowed host-side control service but not loopback-published backends; matching Docker DNAT counters advanced and Firewalld logged the `public → docker` DROP. Distinct user-defined bridges passed same-bridge positive controls and isolated cross-bridge attempts.
- After Firewalld reload, Docker restart, and VM reboot, the strict setting and DNAT reject chain remained effective. A one-shot injected Firewalld reload failure during policy replacement made apply fail while retaining the prior reject path; a subsequent unmodified apply reconciled to no-op.
- IPv6 external reachability was not exercised. A separate cloud-init-intact Debian 13.8 package simulation showed that installing `firewalld` would remove the unmanaged `cloud-init` package; the package safety guard was not bypassed. These checks do not prove the package transition or network behavior on an unmodified provider image.