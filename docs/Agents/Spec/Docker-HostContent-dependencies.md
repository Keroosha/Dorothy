# Docker container dependencies on host content directories and firewalld

## Contract

- `HostContentItem.Directory` exposes a typed `HostContentDirectory` for a declared `directory`.
- Docker bind mounts can reference that identity; `usesDirectory` adds an explicit dependency without a mount. The Debian host builder rejects a directory reference that is not reference-identical to a directory in the same host's `content` block.
- Each container's Pulumi `DependsOn` contains only its mount/`usesDirectory` directory resources, declared container dependencies, explicitly selected firewalld policy resources, and the strict-host boot guard service when opted in.
- `DockerBuilders.dependsOnFirewalld` is a typed policy dependency. The host builder rejects undeclared/non-policy references and never infers a dependency from all Docker-egress policies, preserving non-opted-in graphs.
- `Firewalld.strictForwardPorts true` owns only the `StrictForwardPorts` key through a journaled `FirewalldSettings` resource. Strict Docker hosts require each container to select a negative-priority `DROP` policy with Docker egress.
- With a declared strict engine, a recovery/panic readiness check precedes the package owner that may first start Docker. The full policy guard follows Docker and its declared fence policies; it does not require a Docker-created zone to exist before initial installation. Each installs a scoped `docker.service` pre-start check that runs on every systemd invocation, including socket activation. See the [ownership and recovery runbook](Firewalld-Permanent-Configuration.md#operator-recovery-without-adopting-someone-elses-rules).

## Implementation

- Docker directory, policy, admission, and container-to-container dependencies remain distinct typed edges. The early readiness prerequisite does not call Docker; the final guard depends on the engine and declared policies. Firewalld without a declared engine registers neither guard.
- Generic tests assert Pulumi resource dependencies, reject undeclared mount/policy references and nonnegative-priority strict guards, and leave non-opted-in host graphs independent.
- Firewalld uses unique Create-generation owners and create-before-delete replacement. A same-object replacement fails closed against the old journal owner; settings restore only the inherited `StrictForwardPorts` value/absence while preserving unrelated edits during apply, rollback, and delete.
- No `Compose`, global file/container dependency, resource rename, or change to non-opted-in Docker host graphs.

## Verification

Runtime packet-path behavior must be proved separately on an isolated Debian 13 guest with the packaged Docker engine. This specification does not treat a loopback bind, firewalld zone priority, or a successful Pulumi graph test as evidence that Docker published-port DNAT is blocked.

## Disposable runtime evidence

- A consumer graph was applied to a disposable Debian 13.8 amd64 VM with local Pulumi state, a local-only test certificate, and no manually prepared declared content paths. The first apply created the graph and its immediate no-op reported all resources unchanged; replacement and targeted delete/recreate retained writable state. This is not a pristine stock-host result: before this smoke, cloud-init had been removed from that disposable guest.
- The packaged Docker engine was 26.1.5 and Firewalld 2.3.1. A same-L2 veth peer reached an allowed host-side control service but not loopback-published backends; matching Docker DNAT counters advanced and Firewalld logged the `public → docker` DROP. Distinct user-defined bridges passed same-bridge positive controls and isolated cross-bridge attempts.
- After Firewalld reload, Docker restart, and VM reboot, the strict setting and DNAT reject chain remained effective. A one-shot injected Firewalld reload failure during policy replacement made apply fail while retaining the prior reject path; a subsequent unmodified apply reconciled to no-op.
- IPv6 external reachability was not exercised. A separate cloud-init-intact Debian 13.8 package simulation showed that installing `firewalld` would remove the unmanaged `cloud-init` package; the package safety guard was not bypassed. These checks do not prove the package transition or network behavior on an unmodified provider image.

## Replacement and boot lifecycle evidence

- On an isolated Debian 13.8 guest with Docker 26.1.5 and Firewalld 2.3.1, the combined fixture package install left the permanent Docker zone absent; a Docker restart after Firewalld created it, after which the strict graph applied. This is not a clean package-order proof.
- Forced replacement previews showed `create replacement` followed by `delete original`. Actual `pulumi up --replace` attempts for both settings and the declared Docker `DROP` policy failed during replacement Create with the existing-journal owner error; the old configuration remained active and the loopback backend stayed available.
- A normal reboot changed boot ID and restored Firewalld, Docker, the guard service, and the loopback-only backend. Masking Firewalld before reboot left its unit masked/inactive, the guard and Docker inactive, and the backend listener absent while SSH stayed reachable; unmasking Firewalld and starting Docker restored the backend.
- This test image's package simulation included `Remv cloud-init [25.1.4-1+deb13u1]`; the disposable fixture installed prerequisites manually and cloud-init was removed. No provider APT guard or production host was bypassed. IPv6 and provider-specific package/interface baselines remain unverified.