#!/usr/bin/env bash
set -euo pipefail

if [[ $# < 2 || $# > 3 ]]; then
    printf 'Usage: %s /tmp/dorothy-traefik-acceptance.XXXXXXXX <candidate-provider-directory> [full|sni-proof-only|resume-after-sni]\nSet TRAEFIK_ACCEPTANCE_EXPECTED_HELPER_SHA256 to pin the optional helper digest; TRAEFIK_ACCEPTANCE_RESOLVER_EPOCH defaults to v2.\n' "$0" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(realpath -e -- "$script_dir/../..")
state_dir=$(realpath -e -- "$1")
provider_dir=$(realpath -e -- "$2")
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to run outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" && "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || {
    printf 'Private acceptance ownership marker is missing.\n' >&2
    exit 2
}
[[ -f "$state_dir/legacy-checkpoint.json" && -s "$state_dir/legacy-resource-id.txt" ]] || {
    printf 'The frozen-base legacy checkpoint has not been created.\n' >&2
    exit 2
}
[[ -x "$provider_dir/pulumi-resource-keroosha" && -x "$provider_dir/helper/linux-x64/keroosha-iac-helper" ]] || {
    printf 'Candidate provider directory is missing its provider or linux-x64 native helper.\n' >&2
    exit 2
}
source "$state_dir/handle.env"
run_mode=${3:-full}
case "$run_mode" in
    full|sni-proof-only|resume-after-sni) ;;
    *) printf 'Unknown acceptance mode.\n' >&2; exit 2 ;;
esac
resolver_epoch=${TRAEFIK_ACCEPTANCE_RESOLVER_EPOCH:-v2}
export TRAEFIK_ACCEPTANCE_RESOLVER_EPOCH="$resolver_epoch"
actual_helper_sha=$(sha256sum "$provider_dir/helper/linux-x64/keroosha-iac-helper" | awk '{print $1}')
[[ "$actual_helper_sha" =~ ^[a-f0-9]{64}$ ]] || {
    printf 'Candidate helper digest could not be computed.\n' >&2
    exit 2
}
expected_helper_sha=${TRAEFIK_ACCEPTANCE_EXPECTED_HELPER_SHA256:-}
if [[ -n "$expected_helper_sha" ]]; then
    [[ "$expected_helper_sha" =~ ^[a-f0-9]{64}$ ]] || {
        printf 'Expected helper SHA256 must be 64 lowercase hexadecimal characters.\n' >&2
        exit 2
    }
    [[ "$actual_helper_sha" == "$expected_helper_sha" ]] || {
        printf 'Candidate NativeAOT helper does not match TRAEFIK_ACCEPTANCE_EXPECTED_HELPER_SHA256.\n' >&2
        exit 2
    }
fi
for command in dotnet pulumi jq sha256sum scp ssh openssl mktemp ln; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done
if [[ "$run_mode" != sni-proof-only ]]; then
    [[ -f "$UPSTREAM_CA_FILE" && -f "$CLIENT_CA_FILE" && -s "$DNS_TSIG_SECRET_FILE" ]] || {
        printf 'Private protocol and credential fixtures are incomplete.\n' >&2
        exit 2
    }
fi
[[ -s "$state_dir/legacy-example.pem" && -s "$state_dir/legacy-example.key" ]] || {
    printf 'The frozen legacy certificate fixtures are missing.\n' >&2
    exit 2
}
if [[ ! -s "$state_dir/sni-proof.pem" || ! -s "$state_dir/sni-proof.key" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$state_dir/sni-proof.key" -out "$state_dir/sni-proof.pem" \
        -subj '/CN=sni-proof.acceptance.test' -days 365 \
        -addext 'basicConstraints=critical,CA:FALSE' \
        -addext 'keyUsage=critical,digitalSignature' \
        -addext 'extendedKeyUsage=serverAuth' \
        -addext 'subjectAltName=DNS:sni-proof.acceptance.test' \
        > "$state_dir/logs/sni-certificate-generation.log" 2>&1
fi
chmod 600 "$state_dir/sni-proof.pem" "$state_dir/sni-proof.key"
openssl x509 -in "$state_dir/sni-proof.pem" -noout -checkhost sni-proof.acceptance.test \
    > "$state_dir/logs/sni-certificate-san.log" 2>&1

mkdir -m 700 -p "$state_dir/logs" "$state_dir/home" "$state_dir/dotnet-home" "$state_dir/nuget-packages" "$state_dir/candidate-program"
chmod 700 "$state_dir/logs" "$state_dir/home" "$state_dir/dotnet-home" "$state_dir/nuget-packages" "$state_dir/candidate-program"
helper_evidence="$state_dir/candidate-helper-$run_mode.sha256"
if [[ -e "$helper_evidence" || -L "$helper_evidence" ]]; then
    [[ "$(<"$helper_evidence")" == "$actual_helper_sha" ]] || {
        printf 'Candidate helper digest changed since the first %s run.\n' "$run_mode" >&2
        exit 2
    }
else
    (umask 077; printf '%s\n' "$actual_helper_sha" > "$helper_evidence")
fi
candidate_source="$state_dir/candidate-source"
if [[ -e "$candidate_source" ]]; then
    [[ -d "$candidate_source" && -f "$candidate_source/.owner" && "$(<"$candidate_source/.owner")" == dorothy-traefik-candidate-source-v1 ]] || {
        printf 'An unmarked candidate source already occupies the private path.\n' >&2
        exit 2
    }
    rm -rf -- "$candidate_source"
fi
mkdir -m 700 -p "$candidate_source/src" "$candidate_source/tests"
cp -a "$repo_root/src/Dorothy.DSL" "$candidate_source/src/Dorothy.DSL"
cp -a "$script_dir" "$candidate_source/tests/Traefik.Acceptance"
printf '%s\n' dorothy-traefik-candidate-source-v1 > "$candidate_source/.owner"
chmod 600 "$candidate_source/.owner"
if ! dotnet publish "$candidate_source/tests/Traefik.Acceptance/Traefik.Acceptance.fsproj" \
    --configuration Release --output "$state_dir/candidate-program" \
    > "$state_dir/logs/candidate-program-publish.log" 2>&1; then
    printf 'Private candidate acceptance-program publish failed; see %s/logs/candidate-program-publish.log\n' "$state_dir" >&2
    exit 1
fi

export HOME="$state_dir/home"
export DOTNET_CLI_HOME="$state_dir/dotnet-home"
export NUGET_PACKAGES="$state_dir/nuget-packages"
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_NOLOGO=1
export DOTNET_ROOT="$(dirname "$(readlink -f "$(command -v dotnet)")")"
export DOTNET_ROOT_X64="$DOTNET_ROOT"
export PULUMI_HOME="$state_dir/pulumi-home"
export PULUMI_BACKEND_URL="file://$state_dir/backend"
export PULUMI_CONFIG_PASSPHRASE="$(<"$PULUMI_PASSPHRASE_FILE")"
export PULUMI_SKIP_UPDATE_CHECK=1
export PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=1
export PULUMI_EXPERIMENTAL=false
export DOROTHY_ACCEPTANCE_SSH_CONFIG="$SSH_CONFIG"
export DOROTHY_ACCEPTANCE_SSH_PORT="$SSH_PORT"
export TRAEFIK_ACCEPTANCE_LEGACY_CERT_FILE="$state_dir/legacy-example.pem"
export TRAEFIK_ACCEPTANCE_LEGACY_KEY_FILE="$state_dir/legacy-example.key"
export TRAEFIK_ACCEPTANCE_SNI_CERT_FILE="$state_dir/sni-proof.pem"
export TRAEFIK_ACCEPTANCE_SNI_KEY_FILE="$state_dir/sni-proof.key"
export UPSTREAM_CA_FILE="$UPSTREAM_CA_FILE"
export CLIENT_CA_FILE="$CLIENT_CA_FILE"
export DNS_TSIG_SECRET_FILE="$DNS_TSIG_SECRET_FILE"
export PATH="$state_dir/bin:$PATH"
remote() {
    /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$1"
}
scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$state_dir/sni-proof.pem" "$SSH_USER@$SSH_HOST:$GUEST_ROOT/certs/sni-proof.pem" \
    > "$state_dir/logs/sni-proof-certificate-copy.log" 2>&1
remote "chmod 644 '$GUEST_ROOT/certs/sni-proof.pem'" \
    > "$state_dir/logs/sni-proof-certificate-mode.log" 2>&1

pulumi_project="$state_dir/pulumi-project"
[[ -d "$pulumi_project" && -f "$pulumi_project/Pulumi.acceptance.yaml" ]] || {
    printf 'Private Pulumi project state from the legacy bootstrap is missing.\n' >&2
    exit 2
}
cat > "$pulumi_project/Pulumi.yaml" <<EOF
name: traefik-acceptance
runtime:
  name: dotnet
  options:
    binary: $state_dir/candidate-program/Traefik.Acceptance.dll
description: Private real-VM Traefik lifecycle acceptance
EOF
chmod 600 "$pulumi_project/Pulumi.yaml"

if ! pulumi plugin install resource keroosha 0.1.0 --file "$provider_dir" --reinstall \
    > "$state_dir/logs/candidate-plugin-install.log" 2>&1; then
    printf 'Candidate provider plugin install failed; see %s/logs/candidate-plugin-install.log\n' "$state_dir" >&2
    exit 1
fi
if ! pulumi login "file://$state_dir/backend" --non-interactive \
    > "$state_dir/logs/candidate-pulumi-login.log" 2>&1; then
    printf 'Private Pulumi file-backend login failed; see %s/logs/candidate-pulumi-login.log\n' "$state_dir" >&2
    exit 1
fi

run_pulumi() {
    local phase=$1
    local log_name=$2
    shift 2
    if ! (cd "$pulumi_project" && TRAEFIK_ACCEPTANCE_PHASE="$phase" pulumi "$@") \
        > "$state_dir/logs/$log_name" 2>&1; then
        printf 'Pulumi command failed; see %s/logs/%s\n' "$state_dir" "$log_name" >&2
        return 1
    fi
}

expect_pulumi_failure() {
    local phase=$1
    local log_name=$2
    shift 2
    if (cd "$pulumi_project" && TRAEFIK_ACCEPTANCE_PHASE="$phase" pulumi "$@") \
        > "$state_dir/logs/$log_name" 2>&1; then
        printf 'The invalid runtime candidate unexpectedly succeeded.\n' >&2
        return 1
    fi
}

traefik_query='[.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))]'
resource_id() {
    jq -r "$traefik_query | if length == 1 then .[0].id else empty end" "$1"
}
resource_urn() {
    jq -r "$traefik_query | if length == 1 then .[0].urn else empty end" "$1"
}
export_checkpoint() {
    local destination=$1
    local export_log="$state_dir/logs/checkpoint-export-${destination##*/}.log"
    local temporary
    [[ ! -e "$destination" && ! -L "$destination" ]] || {
        printf 'Refusing to overwrite existing Pulumi checkpoint: %s\n' "$destination" >&2
        return 1
    }
    temporary=$(mktemp "${destination}.tmp.XXXXXXXX") || return 1
    if ! (cd "$pulumi_project" && pulumi stack export --stack acceptance) > "$temporary" 2> "$export_log"; then
        rm -f -- "$temporary"
        printf 'Pulumi checkpoint export failed; see %s\n' "$export_log" >&2
        return 1
    fi
    chmod 600 "$temporary"
    if ! ln -- "$temporary" "$destination"; then
        rm -f -- "$temporary"
        printf 'Could not preserve exported Pulumi checkpoint at %s\n' "$destination" >&2
        return 1
    fi
    rm -- "$temporary"
}
assert_checkpoint() {
    local checkpoint=$1
    local description=$2
    local require_configuration=$3
    [[ "$(resource_id "$checkpoint")" == "$legacy_id" ]] || {
        printf '%s changed the logical Traefik resource ID.\n' "$description" >&2
        return 1
    }
    [[ "$(resource_urn "$checkpoint")" == "$legacy_urn" ]] || {
        printf '%s changed the Traefik resource URN.\n' "$description" >&2
        return 1
    }
    if [[ "$require_configuration" == true ]]; then
        jq -e "$traefik_query[0].inputs | has(\"configuration\")" "$checkpoint" > /dev/null || {
            printf '%s checkpoint does not contain native configuration.\n' "$description" >&2
            return 1
        }
    fi
}
capture_pebble_root() {
    local management_port=$1
    local certificate_name=$2
    local guest_certificate="$GUEST_ROOT/certs/$certificate_name"
    local evidence_certificate="$state_dir/$run_mode-$certificate_name"
    local log_file="$state_dir/logs/$run_mode-$certificate_name.log"
    [[ ! -e "$evidence_certificate" && ! -L "$evidence_certificate" ]] || {
        printf 'Refusing to overwrite captured Pebble issuer evidence: %s\n' "$evidence_certificate" >&2
        return 1
    }
    remote "curl --fail --silent --show-error --cacert '$GUEST_ROOT/certs/pebble.minica.pem' 'https://localhost:$management_port/roots/0' --output '$guest_certificate' && chmod 644 '$guest_certificate' && openssl x509 -in '$guest_certificate' -noout -checkend 0" \
        > "$log_file" 2>&1
    scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$SSH_USER@$SSH_HOST:$guest_certificate" "$evidence_certificate" \
        >> "$log_file" 2>&1
    chmod 600 "$evidence_certificate"
    sha256sum "$evidence_certificate" >> "$log_file"
}
apply_full_configuration() {
    local before_checkpoint=$1
    local checkpoint=$2
    local log_prefix=$3
    local before_pid before_hash after_pid after_hash
    before_pid=$(remote_service_pid)
    assert_checkpoint "$before_checkpoint" "Full update baseline" true
    before_hash=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml')
    run_pulumi structured "${log_prefix}-refresh.log" refresh --stack acceptance --yes --non-interactive
    run_pulumi structured "${log_prefix}-preview.log" preview --stack acceptance --diff --non-interactive --color=never
    run_pulumi structured "${log_prefix}-update.log" up --stack acceptance --yes --non-interactive --parallel 1
    after_pid=$(remote_service_pid)
    export_checkpoint "$checkpoint"
    assert_checkpoint "$checkpoint" "Full structured update" true
    after_hash=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml')
    if [[ "$before_hash" != "$after_hash" ]]; then
        [[ "$after_pid" != "$before_pid" ]] || {
            printf 'Full static configuration changed without restarting the Traefik process.\n' >&2
            return 1
        }
    else
        [[ "$after_pid" == "$before_pid" ]] || {
            printf 'Unchanged full static configuration unexpectedly restarted Traefik.\n' >&2
            return 1
        }
    fi
    run_pulumi structured "${log_prefix}-noop-preview.log" preview --stack acceptance --expect-no-changes --non-interactive --color=never
    run_pulumi structured "${log_prefix}-noop-up.log" up --stack acceptance --yes --non-interactive --skip-preview --expect-no-changes --parallel 1
}
remote_service_pid() {
    remote 'systemctl show --property=MainPID --value keroosha-traefik.service'
}
reboot_guest() {
    local before=$1
    local after_file="$state_dir/logs/boot-id-after.txt"
    local after=''
    if ! remote 'systemctl reboot' > "$state_dir/logs/reboot-request.log" 2>&1; then
        :
    fi
    for _ in $(seq 1 240); do
        if /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" \
            'cat /proc/sys/kernel/random/boot_id' > "$after_file" 2>/dev/null; then
            after=$(<"$after_file")
            if [[ -n "$after" && "$after" != "$before" ]]; then break; fi
        fi
        sleep 2
    done
    chmod 600 "$after_file" 2>/dev/null || true
    [[ -n "$after" && "$after" != "$before" ]] || { printf 'The guest boot ID did not change after reboot.\n' >&2; return 1; }
    remote 'systemctl is-active ssh dorothy-traefik-acceptance-dns.service dorothy-traefik-acceptance-pebble.service dorothy-traefik-acceptance-pebble-rotated.service dorothy-traefik-acceptance-otelcol.service dorothy-traefik-acceptance-backends.service dorothy-traefik-acceptance-tcp.service dorothy-traefik-acceptance-udp.service keroosha-traefik.service' \
        > "$state_dir/logs/rebooted-services.log"
    printf '%s\n' "$after"
}
run_guest_client() {
    local mode=$1
    scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$script_dir/client-checks.sh" "$SSH_USER@$SSH_HOST:$GUEST_ROOT/client-checks.sh" \
        > "$state_dir/logs/client-script-copy.log" 2>&1
    remote "chmod 700 '$GUEST_ROOT/client-checks.sh'; bash '$GUEST_ROOT/client-checks.sh' '$GUEST_ROOT' '$mode'"
}
run_sni_drift() {
    scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$script_dir/sni-drift.sh" "$SSH_USER@$SSH_HOST:$GUEST_ROOT/sni-drift.sh" \
        > "$state_dir/logs/sni-script-copy.log" 2>&1
    remote "chmod 700 '$GUEST_ROOT/sni-drift.sh'" > "$state_dir/logs/sni-script-install.log" 2>&1
    remote "bash '$GUEST_ROOT/sni-drift.sh' prepare '$GUEST_ROOT'" > "$state_dir/logs/sni-positive-before.log" 2>&1
    remote "bash '$GUEST_ROOT/sni-drift.sh' inject '$GUEST_ROOT'" > "$state_dir/logs/sni-inject.log" 2>&1
    run_pulumi sni-proof-only sni-read-refresh.log refresh --stack acceptance --yes --non-interactive
    remote "bash '$GUEST_ROOT/sni-drift.sh' assert-drift '$GUEST_ROOT'" > "$state_dir/logs/sni-drift-after-refresh.log" 2>&1
    run_pulumi sni-proof-only sni-repair-preview.log preview --stack acceptance --diff --non-interactive --color=never
    run_pulumi sni-proof-only sni-repair-up.log up --stack acceptance --yes --non-interactive --parallel 1
    remote "bash '$GUEST_ROOT/sni-drift.sh' assert-positive '$GUEST_ROOT'" > "$state_dir/logs/sni-positive-after-repair.log" 2>&1
}
apply_sni_proof_only() {
    run_pulumi sni-proof-only sni-proof-only-preview.log preview --stack acceptance --diff --non-interactive --color=never
    run_pulumi sni-proof-only sni-proof-only-update.log up --stack acceptance --yes --non-interactive --parallel 1
    export_checkpoint "$state_dir/sni-proof-only-checkpoint.json"
    [[ "$(resource_id "$state_dir/sni-proof-only-checkpoint.json")" == "$legacy_id" ]] || {
        printf 'SNI-only phase replaced the existing logical Traefik resource.\n' >&2
        return 1
    }
    [[ "$(resource_urn "$state_dir/sni-proof-only-checkpoint.json")" == "$legacy_urn" ]] || {
        printf 'SNI-only phase changed the existing Traefik URN.\n' >&2
        return 1
    }
    jq -e "$traefik_query[0].inputs | has(\"configuration\")" \
        "$state_dir/sni-proof-only-checkpoint.json" > /dev/null || {
        printf 'SNI-only proof phase did not checkpoint its native configuration.\n' >&2
        return 1
    }
    run_sni_drift
}

legacy_id=$(<"$state_dir/legacy-resource-id.txt")
legacy_urn=$(resource_urn "$state_dir/legacy-checkpoint.json")
[[ -n "$legacy_urn" ]] || { printf 'Frozen-base checkpoint has no sandbox Traefik URN.\n' >&2; exit 1; }
if [[ "$run_mode" == sni-proof-only ]]; then
    export_checkpoint "$state_dir/before-sni-proof-only-checkpoint.json"
    assert_checkpoint "$state_dir/before-sni-proof-only-checkpoint.json" "SNI-only starting state" true
    apply_sni_proof_only
    printf 'SNI proof-only configuration is active; checkpoint: %s/sni-proof-only-checkpoint.json\n' "$state_dir"
    exit 0
elif [[ "$run_mode" == resume-after-sni ]]; then
    export_checkpoint "$state_dir/before-resume-after-sni-checkpoint.json"
    assert_checkpoint "$state_dir/before-resume-after-sni-checkpoint.json" "Resume-after-SNI starting state" true
    apply_full_configuration \
        "$state_dir/before-resume-after-sni-checkpoint.json" \
        "$state_dir/resume-structured-checkpoint.json" \
        resume-structured
else
    legacy_pid_before_candidate=$(remote_service_pid)

run_pulumi legacy candidate-legacy-refresh.log refresh --stack acceptance --yes --non-interactive
run_pulumi legacy candidate-legacy-noop-preview.log preview --stack acceptance --expect-no-changes --non-interactive --color=never
run_pulumi legacy candidate-legacy-noop-up.log up --stack acceptance --yes --non-interactive --skip-preview --expect-no-changes --parallel 1
export_checkpoint "$state_dir/newer-legacy-checkpoint.json"
[[ "$(resource_id "$state_dir/newer-legacy-checkpoint.json")" == "$legacy_id" ]] || {
    printf 'New provider changed the legacy Traefik resource ID.\n' >&2
    exit 1
}
[[ "$(resource_urn "$state_dir/newer-legacy-checkpoint.json")" == "$legacy_urn" ]] || {
    printf 'New provider changed the legacy Traefik resource URN.\n' >&2
    exit 1
}
jq -e "$traefik_query[0].inputs | (has(\"configuration\") | not)" \
    "$state_dir/newer-legacy-checkpoint.json" > /dev/null || {
    printf 'New provider no-op added a configuration input to the legacy checkpoint.\n' >&2
    exit 1
}
legacy_noop_pid=$(remote_service_pid)
[[ "$legacy_noop_pid" == "$legacy_pid_before_candidate" ]] || {
    printf 'The newer provider no-op changed the legacy Traefik process.\\n' >&2
    exit 1
}

boot_before=$(remote 'cat /proc/sys/kernel/random/boot_id')
boot_after=$(reboot_guest "$boot_before")
[[ -n "$boot_after" ]] || { printf 'The guest reboot phase did not return a boot ID.\n' >&2; exit 1; }
run_pulumi legacy post-reboot-legacy-refresh.log refresh --stack acceptance --yes --non-interactive
run_pulumi legacy post-reboot-legacy-noop-preview.log preview --stack acceptance --expect-no-changes --non-interactive --color=never
run_pulumi legacy post-reboot-legacy-noop-up.log up --stack acceptance --yes --non-interactive --skip-preview --expect-no-changes --parallel 1
export_checkpoint "$state_dir/post-reboot-legacy-checkpoint.json"
[[ "$(resource_id "$state_dir/post-reboot-legacy-checkpoint.json")" == "$legacy_id" ]] || {
    printf 'Legacy resource identity changed after reboot.\\n' >&2
    exit 1
}

export_checkpoint "$state_dir/before-sni-proof-checkpoint.json"
assert_checkpoint "$state_dir/before-sni-proof-checkpoint.json" "SNI proof starting state" false
jq -e "$traefik_query[0].inputs | (has(\"configuration\") | not)" \
    "$state_dir/before-sni-proof-checkpoint.json" > /dev/null || {
    printf 'Full acceptance SNI proof must start from the frozen legacy resource.\n' >&2
    exit 1
}
apply_sni_proof_only
apply_full_configuration \
    "$state_dir/sni-proof-only-checkpoint.json" \
    "$state_dir/structured-checkpoint.json" \
    structured
fi
capture_pebble_root 15000 pebble-issued-root.pem
run_guest_client protocols > "$state_dir/logs/protocol-clients.log" 2>&1 || {
    printf 'Real protocol/ACME client checks failed; see %s/logs/protocol-clients.log\n' "$state_dir" >&2
    exit 1
}

static_pid_before_route=$(remote_service_pid)
run_pulumi route-update route-only-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi route-update route-only-update.log up --stack acceptance --yes --non-interactive --parallel 1
static_pid_after_route=$(remote_service_pid)
[[ "$static_pid_after_route" == "$static_pid_before_route" ]] || {
    printf 'Dynamic-only route update unexpectedly restarted the static Traefik process.\n' >&2
    exit 1
}
run_guest_client route-update > "$state_dir/logs/route-update-client.log" 2>&1 || {
    printf 'Route-only client check failed; see %s/logs/route-update-client.log\n' "$state_dir" >&2
    exit 1
}

old_resolver_name="acceptance-$resolver_epoch"
old_resolver_hash=$(printf '%s' "$old_resolver_name" | sha256sum | awk '{print $1}')
old_resolver_storage="/var/lib/keroosha-traefik/acme-$old_resolver_hash.json"
remote "test -s '$old_resolver_storage' && sha256sum '$old_resolver_storage'" \
    > "$state_dir/old-resolver-storage-before-rotation.txt"
[[ -s "$state_dir/old-resolver-storage-before-rotation.txt" ]] || {
    printf 'The old DNS resolver did not leave readable ACME storage before rotation.\n' >&2
    exit 1
}
static_pid_before_rotation=$(remote_service_pid)
run_pulumi rotate resolver-rotation-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi rotate resolver-rotation-update.log up --stack acceptance --yes --non-interactive --parallel 1
remote "test -s '$old_resolver_storage' && sha256sum '$old_resolver_storage'" \
    > "$state_dir/old-resolver-storage-after-rotation.txt"
cmp -s "$state_dir/old-resolver-storage-before-rotation.txt" "$state_dir/old-resolver-storage-after-rotation.txt" || {
    printf 'Resolver rotation changed or removed the prior DNS resolver ACME storage.\n' >&2
    exit 1
}
static_pid_after_rotation=$(remote_service_pid)
[[ "$static_pid_after_rotation" != "$static_pid_before_rotation" ]] || {
    printf 'Replacing the active DNS resolver did not restart the static Traefik process.\n' >&2
    exit 1
}
capture_pebble_root 15001 pebble-rotated-issued-root.pem
run_guest_client rotation > "$state_dir/logs/resolver-rotation-client.log" 2>&1 || {
    printf 'Independent CA resolver rotation check failed; see %s/logs/resolver-rotation-client.log\n' "$state_dir" >&2
    exit 1
}
export_checkpoint "$state_dir/rotated-checkpoint.json"
[[ "$(resource_id "$state_dir/rotated-checkpoint.json")" == "$legacy_id" ]] || {
    printf 'Resolver rotation replaced the existing logical resource.\n' >&2
    exit 1
}

boot_before=$(remote 'cat /proc/sys/kernel/random/boot_id')
boot_after=$(reboot_guest "$boot_before")
[[ -n "$boot_after" ]] || { printf 'The structured configuration reboot phase did not return a boot ID.\n' >&2; exit 1; }
run_pulumi rotate post-reboot-refresh.log refresh --stack acceptance --yes --non-interactive
run_pulumi rotate post-reboot-preview.log preview --stack acceptance --expect-no-changes --non-interactive --color=never
run_pulumi rotate post-reboot-noop-up.log up --stack acceptance --yes --non-interactive --skip-preview --expect-no-changes --parallel 1
capture_pebble_root 15001 pebble-reboot-issued-root.pem
run_guest_client after-reboot > "$state_dir/logs/post-reboot-clients.log" 2>&1 || {
    printf 'Post-reboot real client check failed; see %s/logs/post-reboot-clients.log\n' "$state_dir" >&2
    exit 1
}

scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$script_dir/drift.sh" "$SSH_USER@$SSH_HOST:$GUEST_ROOT/drift.sh" \
    > "$state_dir/logs/drift-script-copy.log" 2>&1
remote "chmod 700 '$GUEST_ROOT/drift.sh'; bash '$GUEST_ROOT/drift.sh' '$GUEST_ROOT'" \
    > "$state_dir/logs/drift-injection.log" 2>&1
hash_before_refresh=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
run_pulumi rotate drift-read-refresh.log refresh --stack acceptance --yes --non-interactive
hash_after_refresh=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
[[ "$hash_after_refresh" == "$hash_before_refresh" ]] || {
    printf 'Pulumi Read/refresh repaired drift instead of leaving files untouched.\n' >&2
    exit 1
}
# A failed dial is 502; after the health checker removes the sole upstream it is 503.
for attempt in $(seq 1 12); do
    drift_status=$(remote 'curl --max-time 2 --silent --show-error --resolve shop.acceptance.test:18081:127.0.0.1 --output /dev/null --write-out "%{http_code}" http://shop.acceptance.test:18081/items/drift')
    if [[ "$drift_status" == 502 || "$drift_status" == 503 ]]; then break; fi
    sleep 0.25
done
[[ "$drift_status" == 502 || "$drift_status" == 503 ]] || { printf 'Injected HTTP drift did not remain active after Read/refresh.\n' >&2; exit 1; }
run_pulumi rotate drift-repair-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi rotate drift-repair-up.log up --stack acceptance --yes --non-interactive --parallel 1
hash_after_repair=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
[[ "$hash_after_repair" != "$hash_before_refresh" ]] || { printf 'Pulumi Update did not repair the owned dynamic configuration drift.\n' >&2; exit 1; }
run_guest_client after-reboot > "$state_dir/logs/post-drift-repair-clients.log" 2>&1 || {
    printf 'Protocol route was not restored after drift repair; see %s/logs/post-drift-repair-clients.log\n' "$state_dir" >&2
    exit 1
}

remote "bash '$GUEST_ROOT/drift.sh' inject '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-drift-injection.log" 2>&1
udp_drift_hash_before_refresh=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
run_pulumi rotate udp-drift-read-refresh.log refresh --stack acceptance --yes --non-interactive
udp_drift_hash_after_refresh=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
[[ "$udp_drift_hash_after_refresh" == "$udp_drift_hash_before_refresh" ]] || {
    printf 'Pulumi Read/refresh repaired UDP drift instead of leaving files untouched.\n' >&2
    exit 1
}
remote "bash '$GUEST_ROOT/drift.sh' assert-drift '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-drift-after-refresh.log" 2>&1
run_guest_client udp-drift > "$state_dir/logs/udp-drift-client.log" 2>&1 || {
    printf 'UDP drift data-plane assertions failed; see %s/logs/udp-drift-client.log\n' "$state_dir" >&2
    exit 1
}
run_pulumi rotate udp-drift-repair-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi rotate udp-drift-repair-up.log up --stack acceptance --yes --non-interactive --parallel 1
remote "bash '$GUEST_ROOT/drift.sh' assert-repaired '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-drift-after-repair.log" 2>&1
run_guest_client udp-repaired > "$state_dir/logs/udp-repaired-client.log" 2>&1 || {
    printf 'UDP route was not repaired; see %s/logs/udp-repaired-client.log\n' "$state_dir" >&2
    exit 1
}

static_pid_before_udp_withdraw=$(remote_service_pid)
run_pulumi withdraw-udp udp-withdraw-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi withdraw-udp udp-withdraw-up.log up --stack acceptance --yes --non-interactive --parallel 1
static_pid_after_udp_withdraw=$(remote_service_pid)
[[ "$static_pid_after_udp_withdraw" != "$static_pid_before_udp_withdraw" ]] || {
    printf 'Withdrawing the last udp-entrypoint handler did not restart Traefik.\n' >&2
    exit 1
}
export_checkpoint "$state_dir/after-udp-withdraw-checkpoint.json"
assert_checkpoint "$state_dir/after-udp-withdraw-checkpoint.json" "UDP withdrawal" true
run_guest_client udp-drift > "$state_dir/logs/udp-withdraw-client.log" 2>&1 || {
    printf 'UDP withdrawal data-plane assertions failed; see %s/logs/udp-withdraw-client.log\n' "$state_dir" >&2
    exit 1
}

export_checkpoint "$state_dir/before-udp-rollback-checkpoint.json"
udp_rollback_config_hash=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
udp_rollback_pid_before=$(remote_service_pid)
run_pulumi rollback-udp udp-rollback-preview.log preview --stack acceptance --diff --non-interactive --color=never
expect_pulumi_failure rollback-udp udp-rollback-up.log up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
grep -Fq 'Traefik activation did not satisfy the bounded readiness checks' "$state_dir/logs/udp-rollback-up.log" || {
    printf 'UDP rollback failure did not report the bounded activation rollback diagnostic.\n' >&2
    exit 1
}
udp_rollback_pid_after=$(remote_service_pid)
[[ "$udp_rollback_pid_after" != "$udp_rollback_pid_before" ]] || {
    printf 'UDP withdrawal rollback did not restart Traefik to restore the prior route set.\n' >&2
    exit 1
}
udp_rollback_config_hash_after=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
[[ "$udp_rollback_config_hash_after" == "$udp_rollback_config_hash" ]] || {
    printf 'Rejected UDP rollback candidate did not restore the withdrawn configuration files.\n' >&2
    exit 1
}
export_checkpoint "$state_dir/after-udp-rollback-checkpoint.json"
assert_checkpoint "$state_dir/after-udp-rollback-checkpoint.json" "UDP rollback" true
run_pulumi withdraw-udp udp-rollback-noop.log preview --stack acceptance --refresh=false --expect-no-changes --non-interactive
run_guest_client udp-drift > "$state_dir/logs/udp-rollback-client.log" 2>&1 || {
    printf 'UDP rollback did not retain the withdrawn route state; see %s/logs/udp-rollback-client.log\n' "$state_dir" >&2
    exit 1
}
run_pulumi rotate udp-restore-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi rotate udp-restore-up.log up --stack acceptance --yes --non-interactive --parallel 1
export_checkpoint "$state_dir/after-udp-restore-checkpoint.json"
assert_checkpoint "$state_dir/after-udp-restore-checkpoint.json" "Restored UDP routes" true
run_guest_client udp-repaired > "$state_dir/logs/udp-restored-client.log" 2>&1 || {
    printf 'Full UDP routes were not restored after the rollback test; see %s/logs/udp-restored-client.log\n' "$state_dir" >&2
    exit 1
}
export_checkpoint "$state_dir/before-rollback-checkpoint.json"
config_hash_before_rollback=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
expect_pulumi_failure rollback rollback-up.log up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
config_hash_after_rollback=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
[[ "$config_hash_after_rollback" == "$config_hash_before_rollback" ]] || {
    printf 'Rejected static socket activation did not restore the prior configuration files.\n' >&2
    exit 1
}
remote 'systemctl is-active keroosha-traefik.service' > "$state_dir/logs/rollback-service-active.log"
export_checkpoint "$state_dir/after-rollback-checkpoint.json"
assert_checkpoint "$state_dir/after-rollback-checkpoint.json" "Static rollback" true
run_pulumi rotate rollback-noop.log preview --stack acceptance --refresh=false --expect-no-changes --non-interactive
run_guest_client after-reboot > "$state_dir/logs/post-rollback-clients.log" 2>&1 || {
    printf 'Prior configuration was not restored after rejection; see %s/logs/post-rollback-clients.log\n' "$state_dir" >&2
    exit 1
}

remote 'find /var/lib/keroosha-traefik -maxdepth 1 -type f -name "acme-*.json" -size +0c -print | sort' \
    > "$state_dir/acme-stores-before-delete.txt"
[[ -s "$state_dir/acme-stores-before-delete.txt" ]] || { printf 'No issued ACME storage files exist before Delete.\\n' >&2; exit 1; }
remote 'find /var/lib/keroosha-traefik -maxdepth 1 -type f -name "acme-*.json" -size +0c -print | sort | xargs -r sha256sum' \
    > "$state_dir/acme-store-hashes-before-delete.txt"
[[ -s "$state_dir/acme-store-hashes-before-delete.txt" ]] || { printf 'ACME storage hash manifest is empty before Delete.\\n' >&2; exit 1; }
acme_store_before_delete=$(sha256sum "$state_dir/acme-store-hashes-before-delete.txt" | awk '{ print $1 }')
run_pulumi delete delete-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi delete delete-up.log up --stack acceptance --yes --non-interactive --parallel 1
export_checkpoint "$state_dir/deleted-checkpoint.json"
deleted_count=$(jq "$traefik_query | length" "$state_dir/deleted-checkpoint.json")
[[ "$deleted_count" == 0 ]] || { printf 'Pulumi did not delete the Traefik resource.\n' >&2; exit 1; }
if remote 'systemctl is-active keroosha-traefik.service' > "$state_dir/logs/deleted-service-active.log" 2>&1; then
    printf 'Traefik service remained active after Delete.\n' >&2
    exit 1
fi
remote 'find /var/lib/keroosha-traefik -maxdepth 1 -type f -name "acme-*.json" -size +0c -print | sort' \
    > "$state_dir/acme-stores-after-delete.txt"
remote 'find /var/lib/keroosha-traefik -maxdepth 1 -type f -name "acme-*.json" -size +0c -print | sort | xargs -r sha256sum' \
    > "$state_dir/acme-store-hashes-after-delete.txt"
[[ -s "$state_dir/acme-store-hashes-after-delete.txt" ]] || { printf 'ACME storage disappeared during Delete.\n' >&2; exit 1; }
acme_store_after_delete=$(sha256sum "$state_dir/acme-store-hashes-after-delete.txt" | awk '{ print $1 }')
cmp -s "$state_dir/acme-stores-before-delete.txt" "$state_dir/acme-stores-after-delete.txt" || {
    printf 'ACME storage file names changed during Delete.\n' >&2
    exit 1
}
[[ "$acme_store_after_delete" == "$acme_store_before_delete" ]] || {
    printf 'ACME certificate storage changed during Delete.\n' >&2
    exit 1
}
# Do not uninstall the guest's bootstrap packages: they are shared with the test CA and
# SSH. The acceptance boundary is the Traefik resource; cleanup.sh discards this VM/backend.
remote 'test ! -e /etc/systemd/system/keroosha-traefik.service && test ! -e /etc/keroosha-iac/traefik/dns-credentials.env' || {
    printf 'Delete left the owned service unit or credential file behind.\n' >&2
    exit 1
}

printf 'Real VM acceptance passed.\n'
printf 'Legacy checkpoint: %s/legacy-checkpoint.json\n' "$state_dir"
printf 'Final evidence/logs remain private under: %s\n' "$state_dir"
printf 'Guest: %s@%s:%s\n' "$SSH_USER" "$SSH_HOST" "$SSH_PORT"
printf 'Cleanup: tests/Traefik.Acceptance/cleanup.sh %q\n' "$state_dir"
