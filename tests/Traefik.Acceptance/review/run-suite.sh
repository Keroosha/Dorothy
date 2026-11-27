#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 2 ]]; then
    printf 'Usage: %s /tmp/dorothy-traefik-acceptance.XXXXXXXX <candidate-provider-directory>\n' "$0" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
state_dir=$(realpath -e -- "$1")
provider_dir=$(realpath -e -- "$2")
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to run outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" && -f "$state_dir/.owner" \
   && "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || {
    printf 'Private acceptance ownership marker is missing.\n' >&2
    exit 2
}
bash "$script_dir/../guest-barrier-check.sh" acceptance "$state_dir"
source "$state_dir/handle.env"
for command in pulumi scp ssh realpath sha256sum grep jq; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done
[[ -f "$script_dir/../native-dynamic-graph-check.sh" \
   && -f "$script_dir/../review-client-identity.sh" \
   && -f "$script_dir/../review-listeners.sh" ]] || {
    printf 'A coordinated guest review client is missing.\n' >&2
    exit 2
}
mkdir -m 700 -p "$state_dir/logs" "$state_dir/review-home" "$state_dir/pulumi-home"
: > "$state_dir/logs/review-client-checks.log"
chmod 600 "$state_dir/logs/review-client-checks.log"
export HOME="$state_dir/review-home"
export PULUMI_HOME="$state_dir/pulumi-home"
export PULUMI_BACKEND_URL="file://$state_dir/backend"
export PULUMI_CONFIG_PASSPHRASE="$(<"$PULUMI_PASSPHRASE_FILE")"
export PULUMI_SKIP_UPDATE_CHECK=1
export PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=1
export PULUMI_EXPERIMENTAL=false
export PATH="$state_dir/bin:$PATH"
[[ -s "$state_dir/legacy-checkpoint.json" ]] || {
    printf 'Frozen-baseline checkpoint is required for review Read assertions.\n' >&2
    exit 2
}
traefik_query='[.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))]'
legacy_id=$(jq -r "$traefik_query | if length == 1 then .[0].id else empty end" "$state_dir/legacy-checkpoint.json")
legacy_urn=$(jq -r "$traefik_query | if length == 1 then .[0].urn else empty end" "$state_dir/legacy-checkpoint.json")
[[ -n "$legacy_id" && -n "$legacy_urn" ]] || { printf 'Frozen-baseline checkpoint has no sandbox Traefik resource.\n' >&2; exit 2; }
export DOTNET_CLI_HOME="$state_dir/review-dotnet-home"
export NUGET_PACKAGES="$state_dir/review-nuget-packages"
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_NOLOGO=1
export PULUMI_SKIP_UPDATE_CHECK=1
export PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=1
export PULUMI_EXPERIMENTAL=false


remote() {
    /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$1"
}
copy_script() {
    local source_path=$1 guest_path=$2 log_path=$3
    if ! /usr/bin/scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$source_path" "$SSH_USER@$SSH_HOST:$guest_path" \
        > "$log_path" 2>&1; then
        printf 'Guest review script copy failed; see %s.\n' "$log_path" >&2
        return 1
    fi
    remote "chmod 700 '$guest_path'" > "$log_path.mode" 2>&1
}
run_phase() {
    local phase=$1 operation=$2 log="$state_dir/logs/review-suite-$1-$2.log"
    shift 2
    if ! "$script_dir/run-review.sh" "$state_dir" "$provider_dir" "$phase" "$operation" "$@" \
        > "$log" 2>&1; then
        printf 'Review phase %s failed; see %s.\n' "$phase" "$log" >&2
        return 1
    fi
}
export_checkpoint() {
    local destination=$1 log="$state_dir/logs/review-checkpoint-export-${1##*/}.log"
    local temporary="$destination.tmp.$$"
    [[ ! -e "$destination" && ! -L "$destination" && ! -e "$temporary" ]] || {
        printf 'Refusing to overwrite a review checkpoint.\n' >&2
        return 1
    }
    if ! (cd "$state_dir/pulumi-project" && pulumi stack export --stack acceptance --non-interactive) \
        > "$temporary" 2> "$log"; then
        rm -f -- "$temporary"
        printf 'Review checkpoint export failed; see %s.\n' "$log" >&2
        return 1
    fi
    chmod 600 "$temporary"
    mv -- "$temporary" "$destination"
}
assert_read_checkpoint() {
    local checkpoint=$1 expected_sync=$2 description=$3
    jq -e --arg expectedSync "$expected_sync" --arg expectedId "$legacy_id" --arg expectedUrn "$legacy_urn" '
        [.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))]
        | length == 1
          and .[0].id == $expectedId
          and .[0].urn == $expectedUrn
          and .[0].outputs.inSync == ($expectedSync == "true")
          and (.[0].outputs.tlsProbeSummary | type == "object")
          and (.[0].outputs.tlsProbeSummary.legacyProbesAttempted | type == "number" and . >= 0 and floor == .)
          and (.[0].outputs.tlsProbeSummary.nativeProbesAttempted | type == "number" and . >= 0 and floor == .)
          and (.[0].outputs.tlsProbeSummary.unprobedCount | type == "number" and . >= 0 and floor == .)
          and (.[0].outputs.tlsProbeSummary.opaqueRouterCount | type == "number" and . >= 0 and floor == .)
          and (.[0].outputs.tlsProbeSummary.truncated | type == "number" and (. == 0 or . == 1))
    ' "$checkpoint" >/dev/null || {
        printf '%s Read checkpoint has an unexpected inSync result or incomplete probe summary.\n' "$description" >&2
        return 1
    }
}
# Keep show-secrets output in the pipeline; only the configuration digest leaves it.
checkpoint_input_hash() {
    (
        cd "$state_dir/pulumi-project"
        pulumi stack export --stack acceptance --show-secrets --non-interactive
    ) | jq -cS "$traefik_query[0].inputs.configuration" | sha256sum | cut -d' ' -f1
}
config_hash() {
    remote "sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml | sha256sum | cut -d' ' -f1"
}
assert_config_hash() {
    local description=$1 expected=$2 actual
    actual=$(config_hash)
    [[ "$actual" == "$expected" ]] || {
        printf '%s changed static or dynamic configuration bytes.\n' "$description" >&2
        return 1
    }
}
assert_input_hash() {
    local description=$1 expected=$2 actual
    actual=$(checkpoint_input_hash)
    [[ "$actual" == "$expected" ]] || {
        printf '%s changed the structured Traefik configuration input.\n' "$description" >&2
        return 1
    }
}
assert_preview_updates_one_resource() {
    local description=$1 preview_log="$state_dir/logs/review-structured-preview.log"
    grep -Eiq '1 (to update|updated)' "$preview_log" || {
        printf '%s preview did not plan the live-state repair update.\n' "$description" >&2
        return 1
    }
}
run_guest_client() {
    local mode=$1 log="$state_dir/logs/review-client-$1.log"
    if ! remote "bash '$GUEST_ROOT/review-client-checks.sh' '$GUEST_ROOT' '$mode'" > "$log" 2>&1; then
        printf 'Review guest client mode %s failed; see %s.\n' "$mode" "$log" >&2
        return 1
    fi
    cat "$log" >> "$state_dir/logs/review-client-checks.log"
    printf '\n' >> "$state_dir/logs/review-client-checks.log"
}
run_client_identity() {
    local mode=$1 log="$state_dir/logs/review-client-identity-$1.log"
    if ! remote "bash '$GUEST_ROOT/review-client-identity.sh' '$GUEST_ROOT' '$mode' 18451 sni-proof.acceptance.test" \
        > "$log" 2>&1; then
        printf 'Outbound client-identity mode %s failed; see %s.\n' "$mode" "$log" >&2
        return 1
    fi
}
assert_unchanged() {
    local label=$1 expected_hash=$2 expected_pid=$3 actual_hash actual_pid
    actual_hash=$(remote "sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml | sha256sum | cut -d' ' -f1")
    actual_pid=$(remote 'systemctl show keroosha-traefik.service --property=MainPID --value')
    [[ "$actual_hash" == "$expected_hash" && "$actual_pid" == "$expected_pid" ]] || {
        printf 'Rejected review input %s changed runtime configuration or process state.\n' "$label" >&2
        return 1
    }
}
expect_check_rejection() {
    local phase=$1 message=$2 before_hash before_pid
    before_hash=$(remote "sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml | sha256sum | cut -d' ' -f1")
    before_pid=$(remote 'systemctl show keroosha-traefik.service --property=MainPID --value')
    if run_phase "$phase" up --yes --skip-preview --parallel 1; then
        printf 'Invalid review input %s unexpectedly passed Check.\n' "$phase" >&2
        return 1
    fi
    grep -Fq -- "$message" "$state_dir/logs/review-$phase-up.log" || {
        printf 'Review input %s failed without its targeted Check diagnostic.\n' "$phase" >&2
        return 1
    }
    assert_unchanged "$phase" "$before_hash" "$before_pid"
}
run_listener_stage() {
    local mode=$1 log="$state_dir/logs/review-listeners-$1.log"
    if ! remote "bash '$GUEST_ROOT/review-listeners.sh' '$mode' '$GUEST_ROOT'" > "$log" 2>&1; then
        printf 'Listener review stage %s failed; see %s.\n' "$mode" "$log" >&2
        return 1
    fi
}
listener_forwarded_pending=0
listener_proxy_pending=0
cleanup_listener_drift() {
    local status=$?
    trap - EXIT
    if [[ "$listener_proxy_pending" == 1 ]]; then
        if ! run_listener_stage restore-proxy; then
            printf 'Could not restore injected proxy policy; inspect private review logs.\n' >&2
        fi
    fi
    if [[ "$listener_forwarded_pending" == 1 ]]; then
        if ! run_listener_stage restore-forwarded; then
            printf 'Could not restore injected forwarded-header policy; inspect private review logs.\n' >&2
        fi
    fi
    exit "$status"
}
trap cleanup_listener_drift EXIT


copy_script "$script_dir/client-checks.sh" "$GUEST_ROOT/review-client-checks.sh" \
    "$state_dir/logs/review-client-script-copy.log"
copy_script "$script_dir/../native-dynamic-graph-check.sh" "$GUEST_ROOT/native-dynamic-graph-check.sh" \
    "$state_dir/logs/review-graph-script-copy.log"
copy_script "$script_dir/../review-client-identity.sh" "$GUEST_ROOT/review-client-identity.sh" \
    "$state_dir/logs/review-client-identity-script-copy.log"
copy_script "$script_dir/../review-listeners.sh" "$GUEST_ROOT/review-listeners.sh" \
    "$state_dir/logs/review-listener-script-copy.log"


run_phase structured up --yes --skip-preview --parallel 1
run_guest_client positive
if ! remote "bash '$GUEST_ROOT/native-dynamic-graph-check.sh' '$GUEST_ROOT' 18445" \
    > "$state_dir/logs/review-native-dynamic-graph.log" 2>&1; then
    printf 'Native parent/service middleware graph check failed; see %s/logs/review-native-dynamic-graph.log.\n' "$state_dir" >&2
    exit 1
fi
cat "$state_dir/logs/review-native-dynamic-graph.log" >> "$state_dir/logs/review-client-checks.log"
printf '\n' >> "$state_dir/logs/review-client-checks.log"
run_listener_stage prepare
export_checkpoint "$state_dir/review-trust-baseline-checkpoint.json"
assert_read_checkpoint "$state_dir/review-trust-baseline-checkpoint.json" true "Trust-drift baseline"
# Both modeled root routers inherit TLS only on review-secure and share one SNI/socket.
# The cleartext review-front bind must not count as a handshake.
jq -e --arg u "$legacy_urn" '.deployment.resources[] | select(.urn==$u) | .outputs.tlsProbeSummary |
    .legacyProbesAttempted==1 and .nativeProbesAttempted==1 and .unprobedCount==0 and .truncated==0' \
    "$state_dir/review-trust-baseline-checkpoint.json" >/dev/null
structured_inputs_hash=$(checkpoint_input_hash)
structured_config_hash=$(config_hash)

listener_forwarded_pending=1
run_listener_stage inject-forwarded
run_listener_stage assert-forwarded-drift
run_listener_stage restore-forwarded
run_listener_stage assert-forwarded-restored
listener_forwarded_pending=0
assert_config_hash "forwarded policy restoration" "$structured_config_hash"
run_phase structured refresh --yes
export_checkpoint "$state_dir/review-forwarded-drift-checkpoint.json"
assert_read_checkpoint "$state_dir/review-forwarded-drift-checkpoint.json" false "Forwarded-policy drift"
assert_input_hash "forwarded-policy Read" "$structured_inputs_hash"
run_phase structured preview --diff
assert_preview_updates_one_resource "Forwarded-policy drift"
run_phase structured up --yes --skip-preview --parallel 1
export_checkpoint "$state_dir/review-forwarded-repair-checkpoint.json"
assert_read_checkpoint "$state_dir/review-forwarded-repair-checkpoint.json" true "Forwarded-policy repair"
assert_input_hash "forwarded-policy repair" "$structured_inputs_hash"
assert_config_hash "forwarded policy repair" "$structured_config_hash"
run_listener_stage assert-forwarded-repaired

listener_proxy_pending=1
run_listener_stage inject-proxy
run_listener_stage assert-proxy-drift
run_listener_stage restore-proxy
run_listener_stage assert-proxy-restored
listener_proxy_pending=0
assert_config_hash "proxy policy restoration" "$structured_config_hash"
run_phase structured refresh --yes
export_checkpoint "$state_dir/review-proxy-drift-checkpoint.json"
assert_read_checkpoint "$state_dir/review-proxy-drift-checkpoint.json" false "Proxy-policy drift"
assert_input_hash "proxy-policy Read" "$structured_inputs_hash"
run_phase structured preview --diff
assert_preview_updates_one_resource "Proxy-policy drift"
run_phase structured up --yes --skip-preview --parallel 1
export_checkpoint "$state_dir/review-proxy-repair-checkpoint.json"
assert_read_checkpoint "$state_dir/review-proxy-repair-checkpoint.json" true "Proxy-policy repair"
assert_input_hash "proxy-policy repair" "$structured_inputs_hash"
assert_config_hash "proxy policy repair" "$structured_config_hash"
run_listener_stage assert-proxy-repaired
run_listener_stage assert-otlp-current

run_phase review-client-auth-absent up --yes --skip-preview --parallel 1
run_client_identity absent
run_phase review-client-auth-wrong up --yes --skip-preview --parallel 1
run_client_identity wrong
run_phase structured up --yes --skip-preview --parallel 1
run_client_identity accepted

run_phase review-no-tcp up --yes --skip-preview --parallel 1
run_guest_client no-tcp
run_phase structured up --yes --skip-preview --parallel 1

run_phase review-udp-conflict-control up --yes --skip-preview --parallel 1
run_guest_client udp-conflict-control
expect_check_rejection review-udp-conflict 'Invalid, unsafe or unsupported Traefik UDP listener ownership.'
run_guest_client positive
run_phase structured up --yes --skip-preview --parallel 1

run_phase review-proxy-placement-control up --yes --skip-preview --parallel 1
run_guest_client proxy-placement
expect_check_rejection review-proxy-misplaced 'Invalid, unsafe or unsupported Traefik TCP load-balancer transport field placement.'
run_phase structured up --yes --skip-preview --parallel 1
run_guest_client positive

printf 'Review HTTP/TCP/UDP routing, PROXY framing, backend identity and outbound client-auth checks passed.\n'
printf 'Private evidence remains under %s/logs.\n' "$state_dir"
