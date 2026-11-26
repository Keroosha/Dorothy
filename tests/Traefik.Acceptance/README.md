# Traefik acceptance runner

Run from the repository root on a Linux x86-64 host with KVM access, QEMU, xorriso, .NET 10 with a Linux Native AOT toolchain, Pulumi, jq, OpenSSL and OpenSSH. The harness downloads pinned public fixtures. No cloud API token, external CA or DNS account is needed. Root commands run inside the owned guest, not on the workstation.

```bash
fixture=tests/Traefik.Acceptance
bash "$fixture/prepare.sh"
# Set STATE_DIR to the private directory printed by prepare.sh.
bash "$fixture/prepare-services.sh" "$STATE_DIR"
bash "$fixture/bootstrap-legacy.sh" "$STATE_DIR"
bash scripts/publish-host-helper.sh linux-x64
dotnet publish src/Dorothy.DSL.Providers/Dorothy.DSL.Providers.fsproj \
  -c Release -o "$STATE_DIR/candidate-provider"
bash "$fixture/run.sh" "$STATE_DIR" "$STATE_DIR/candidate-provider" full
bash "$fixture/cleanup.sh" "$STATE_DIR"
```

`run.sh` sources `$STATE_DIR/handle.env` and uses the existing Pulumi stack and Traefik resource. It exports the legacy and SNI certificate fixture paths from `$STATE_DIR`; the CA and DNS credential paths come from `handle.env`.

Modes:

- `full` (default): starts from the frozen legacy checkpoint, keeps the same resource, runs the certificate-backed SNI proof and drift repair before the full structured configuration, then runs the full lifecycle acceptance.
- `sni-proof-only`: starts from an existing structured checkpoint, applies the certificate-backed SNI proof configuration and drift checks, then stops with that configuration active.
- `resume-after-sni`: after an external SNI proof, validates the existing structured resource, applies or confirms full configuration, and continues through the full lifecycle acceptance. It supports both the SNI-only state and a full structured update already applied by the caller.

Example split SNI run:

```bash
tests/Traefik.Acceptance/run.sh "$STATE_DIR" "$CANDIDATE_PROVIDER_DIR" sni-proof-only
# Perform the external SNI proof against the disposable guest.
TRAEFIK_ACCEPTANCE_EXPECTED_HELPER_SHA256="$EXPECTED_HELPER_SHA256" \
  tests/Traefik.Acceptance/run.sh "$STATE_DIR" "$CANDIDATE_PROVIDER_DIR" resume-after-sni
```

`TRAEFIK_ACCEPTANCE_EXPECTED_HELPER_SHA256` is optional; when set, it must match the candidate NativeAOT helper. The runner records the observed digest as private evidence even when no pin is supplied.
`TRAEFIK_ACCEPTANCE_RESOLVER_EPOCH` is optional and defaults to `v2`, preserving the historical resolver names. Set a new epoch after a Pebble test-CA reset to use fresh resolver names and ACME accounts while retaining the old helper-owned storage files.

Checkpoint exports are write-once. Each mode refuses to overwrite an existing checkpoint; use the matching continuation mode or a fresh private acceptance state instead of rerunning a completed phase. The full lifecycle ends at **Traefik** deletion: the unit and DNS credential file must be gone, and issued ACME data must remain intact. The APT bootstrap resources are not an uninstall test. `cleanup.sh` discards the owned VM, private backend, credentials and test evidence together.
