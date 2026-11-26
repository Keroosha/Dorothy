# Traefik acceptance runner

Run from the repository root on a Linux x86-64 host with KVM access, QEMU, xorriso, .NET 10 with a Linux Native AOT toolchain, Pulumi, jq, OpenSSL and OpenSSH. The harness downloads pinned public fixtures. No cloud API token, external CA or DNS account is needed. Root commands run inside the owned guest, not on the workstation.

```bash
fixture=tests/Traefik.Acceptance
bash "$fixture/prepare.sh"
# Set STATE_DIR to the private directory printed by prepare.sh.
bash "$fixture/prepare-services.sh" "$STATE_DIR"

# Every publish and Pulumi command uses private per-run caches and state.
mkdir -m 700 -p "$STATE_DIR/home" "$STATE_DIR/dotnet-home" "$STATE_DIR/nuget-packages"
export HOME="$STATE_DIR/home"
export DOTNET_CLI_HOME="$STATE_DIR/dotnet-home"
export NUGET_PACKAGES="$STATE_DIR/nuget-packages"
export NUGET_HTTP_CACHE_PATH="$STATE_DIR/nuget-http" XDG_CACHE_HOME="$STATE_DIR/cache"
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
export DOTNET_ROOT="$(dirname "$(readlink -f "$(command -v dotnet)")")"
export DOTNET_ROOT_X64="$DOTNET_ROOT"
export PULUMI_HOME="$STATE_DIR/pulumi-home"
export PULUMI_BACKEND_URL="file://$STATE_DIR/backend"
export PULUMI_CONFIG_PASSPHRASE="$(<"$STATE_DIR/pulumi-passphrase")"
export PULUMI_SKIP_UPDATE_CHECK=1
export PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=1
export PULUMI_EXPERIMENTAL=false
export PATH="$STATE_DIR/bin:$PATH"

bash "$fixture/bootstrap-legacy.sh" "$STATE_DIR"
build_source=$(mktemp -d "$STATE_DIR/revision-build.XXXXXXXX")
git archive HEAD | tar -x -C "$build_source"
(cd "$build_source" && bash scripts/publish-host-helper.sh linux-x64)
dotnet publish "$build_source/src/Dorothy.DSL.Providers/Dorothy.DSL.Providers.fsproj" \
  -c Release -o "$STATE_DIR/candidate-provider"
export TRAEFIK_ACCEPTANCE_EVIDENCE_FILE="${TRAEFIK_ACCEPTANCE_EVIDENCE_FILE:-$STATE_DIR.evidence.json}"
bash "$fixture/run.sh" "$STATE_DIR" "$STATE_DIR/candidate-provider" full
bash "$fixture/cleanup.sh" "$STATE_DIR"
```

To verify both provider/helper skew directions against the same owned legacy guest before the lifecycle run, set `FROZEN_PROVIDER_DIR` to the cfd5b41 provider bundle and run:

```bash
bash "$fixture/helper-skew.sh" "$STATE_DIR" "$FROZEN_PROVIDER_DIR" "$STATE_DIR/candidate-provider"
```

The check requires the legacy-only checkpoint, asserts the exact Traefik capability envelope, and records private evidence while verifying that failed operations leave the Pulumi checkpoint and Traefik service/configuration unchanged.

The full run writes a redacted machine-readable closure record outside the disposable state directory: `"$STATE_DIR.evidence.json"` by default, or `TRAEFIK_ACCEPTANCE_EVIDENCE_FILE` when set. It contains tested Git HEADs, source/artifact digests, stage results and counts; it does not contain checkpoint payloads, secret ciphertext/plaintext, private keys or raw logs. Copy this sanitized JSON to durable review storage before cleanup.

`TRAEFIK_REVIEW_FROZEN_PROVIDER_DIR` optionally supplies the frozen cfd5b41 provider to the full-run pagination and 17-target legacy TLS comparisons. Without it, those checks use the candidate provider only. The full runner also performs a copied-checkpoint preview with refresh disabled and a deny-SSH sentinel before the first active-stack refresh.

The parent-owned offline/runtime comparison tools are separate from the ordinary lifecycle:

```bash
# On the owned guest, capture only the selected effective Traefik graphs.
bash "$fixture/capture-effective-graph.sh" "$GUEST_ROOT"

# On the host, compare a named phase against one provider/helper bundle.
bash "$fixture/compare-provider.sh" before "$CANDIDATE_PROVIDER_DIR" \
  "$MANAGED_HELPER_DLL" "$CAPTURE_ROOT" "$RESULT_BEFORE_JSON"
bash "$fixture/compare-provider.sh" after "$CANDIDATE_PROVIDER_DIR" \
  "$MANAGED_HELPER_DLL" "$CAPTURE_ROOT" "$RESULT_AFTER_JSON"

# Separate destructive stored-state fixture; never point it at the active full-run stack.
bash "$fixture/check-stored-lifecycle.sh" "$STATE_DIR" \
  "$CANDIDATE_PROVIDER_DIR" "$FROZEN_PROVIDER_DIR"
```

The ordinary `full` run invokes the frozen copied-checkpoint preview, legacy pagination/17-target checks, reviewed route/TLS/transaction hooks, reboot protocol checks, static rollback, foreign-owner Delete refusal and final Delete on the dedicated guest. The stored-lifecycle comparison is intentionally separate because it creates and deletes its own fixture.

`run.sh` sources `$STATE_DIR/handle.env` and uses the existing Pulumi stack and Traefik resource. It exports the legacy and SNI certificate fixture paths from `$STATE_DIR`; the CA and DNS credential paths come from `handle.env`.

Modes:

- `full` (default): proves a no-SSH copied-checkpoint preview before refresh, checks frozen legacy pagination and 17-target TLS Read, repairs the certificate-backed SNI drift, runs the reviewed route/TLS/transaction controls, then exercises post-reboot protocols, drift, UDP/static rollback, foreign-owner Delete refusal and final Delete on the same resource.
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

Checkpoint exports are write-once. Each mode refuses to overwrite an existing checkpoint; use the matching continuation mode or a fresh private acceptance state instead of rerunning a completed phase. The full lifecycle ends at **Traefik** deletion: the unit and DNS credential file must be gone, and issued ACME data must remain intact. The APT bootstrap resources are not an uninstall test. `cleanup.sh` discards the owned VM, private backend, credentials and detailed logs; the sanitized closure JSON is written separately and remains after cleanup.
