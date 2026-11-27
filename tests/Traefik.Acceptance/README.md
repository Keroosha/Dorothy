# Traefik acceptance runner

The host prepares dependencies before starting a fresh Debian 13 guest. Guest acceptance requires an outbound deny boundary **above** the guest from first boot; a loopback SSH forward or loopback-only Traefik listener is not that boundary. Do not reuse a guest from earlier runs or open egress to make a missing package, release archive, DNS lookup or ACME challenge succeed.

Use an unprivileged Linux x86-64 account with KVM, user/network namespaces, QEMU, xorriso, socat, dnsmasq, dig, iproute2, OpenSSH, OpenSSL and jq. Building the provider also requires .NET 10, a linux-x64 Native AOT toolchain and Pulumi. To replay without even host-side artifact downloads, set `DOROTHY_ACCEPTANCE_PUBLIC_ASSET_CACHE` to the four pinned public release/image files and `DOROTHY_ACCEPTANCE_DEB_CACHE` to the flat `.deb` directory matching [`offline-deps.manifest`](offline-deps.manifest). A missing or mismatched cached artifact fails staging; it does not fall back to the Internet.

```bash
fixture=tests/Traefik.Acceptance
bash "$fixture/prepare.sh"
# Set STATE_DIR to the private directory printed by prepare.sh.
bash "$fixture/prepare-services.sh" "$STATE_DIR"
bash "$fixture/guest-barrier-check.sh" receipt "$STATE_DIR"
```

**Stop here.** Review the fresh `$STATE_DIR/barrier-receipt.json` with Traefik inactive, verified reachability of the local CA, and a controlled negative path that uses no public service. Continue only after independent approval of the barrier and the historical artifact acquisition method. The stock frozen helper's first install requires a GitHub release download; an offline variant must be labelled as such and must retain the original archive digest/installation checks. Never manufacture owner markers or enable a proxy.

```bash
# Set REVIEWED_RECEIPT_SHA256 only from the independent review decision for this guest.
bash "$fixture/guest-barrier-check.sh" authorize "$STATE_DIR" "${REVIEWED_RECEIPT_SHA256:?approval required}"

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

The full run writes a redacted machine-readable closure record outside the disposable state directory: `"$STATE_DIR.evidence.json"` by default, or `TRAEFIK_ACCEPTANCE_EVIDENCE_FILE` when set. It contains tested Git HEADs, source/artifact digests, stage results and counts; it does not contain checkpoint payloads, secret ciphertext/plaintext, private keys, raw process cmdlines or raw logs. Copy this sanitized JSON to durable review storage before cleanup.

Secret checks are scoped to the Pulumi file backend, exported checkpoint JSON, Pulumi project files, harness logs, each provider SSH argv (compared against every original/rotated DNS fixture token), and the running guest Traefik MainPID cmdline plus its configuration files, unit and timestamp-bounded unit journal. They do not scan unrelated host processes or the guest disk image. Root-only Traefik rollback snapshots may contain reversible credentials; keep the entire detailed state directory private and do not share it. Only the sanitized closure record is intended for review sharing.

Before any Traefik lifecycle start, `run.sh` calls `guest-barrier-check.sh acceptance` and refuses to proceed unless the live guest matches the fresh barrier receipt and its separate mode-0600 authorization marker. The runner never creates or authorizes the receipt; the sanitized closure record includes only their digests.

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
