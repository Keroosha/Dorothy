#!/usr/bin/env bash
# Run against the disposable guest's *existing* Pulumi project during its legacy phase.
set -euo pipefail
umask 077
[[ $# == 2 || $# == 3 ]] || { echo 'usage: check-pagination.sh STATE_DIR CANDIDATE_PROVIDER [FROZEN_REVIEW_PROVIDER]' >&2; exit 2; }
state=$(realpath -e -- "$1"); candidate=$(realpath -e -- "$2"); frozen=${3:-}
[[ "$state" == /tmp/dorothy-traefik-acceptance.* && $(<"$state/.owner") == dorothy-traefik-acceptance-owned-state-v1 ]]
[[ "${PULUMI_HOME:-}" == "$state/pulumi-home" && "${PULUMI_BACKEND_URL:-}" == "file://$state/backend" ]]
bash "$(dirname "$(realpath "$0")")/guest-barrier-check.sh" acceptance "$state"
source "$state/handle.env"
project="$state/pulumi-project"; log="$state/logs/review-pagination.log"; : > "$log"
urn=$(jq -er '.deployment.resources[] | select(.type=="keroosha:debian:Traefik") | .urn' "$state/legacy-checkpoint.json")
p(){ pulumi -C "$project" "$@"; }
install_provider(){ [[ -x "$1/pulumi-resource-keroosha" ]] && p plugin install resource keroosha 0.1.0 --file "$1" --reinstall >>"$log" 2>&1; }
snapshot(){ p stack export --stack acceptance | jq -ce --arg urn "$urn" '.deployment.resources[]|select(.urn==$urn)|{inSync:.outputs.inSync,legacyInputs:(.inputs|has("configuration")|not),listeners:(.inputs.entryPoints|length)}'; }
refresh(){ p refresh --target "$urn" --stack acceptance --yes --non-interactive >>"$log" 2>&1; }
restore(){ install_provider "$candidate"; }; trap restore EXIT
# Use the real historical schema and writer, so the old Read is tested independently of any new path/marker.
export TRAEFIK_ACCEPTANCE_PHASE=review-pagination
install_provider "$state/legacy-provider"
p up --target "$urn" --stack acceptance --yes --non-interactive >>"$log" 2>&1
pages=$(/usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" 'set -eu; for p in 1 2; do curl -fsS --max-time 3 "http://127.0.0.1:19080/api/entrypoints?page=$p" | jq length; done' | jq -sce 'select(. == [100,2])')
old=null
if [[ -n "$frozen" ]]; then
    install_provider "$frozen"; refresh; old=$(snapshot)
    jq -e '.legacyInputs and (.inSync|not) and .listeners==101' <<< "$old" >/dev/null
    jq -n --argjson snapshot "$old" --argjson pages "$pages" '{baseline:$snapshot,observedNativePageSizes:$pages}' > "$state/pagination-frozen.json"
fi
install_provider "$candidate"; refresh; current=$(snapshot)
jq -e '.legacyInputs and .inSync and .listeners==101' <<< "$current" >/dev/null
p preview --target "$urn" --stack acceptance --refresh=false --expect-no-changes --non-interactive >>"$log" 2>&1
export TRAEFIK_ACCEPTANCE_PHASE=legacy
[[ "$GUEST_ROOT" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]]
control(){ /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "bash '$GUEST_ROOT/review-transactions.sh' '$1' '$GUEST_ROOT'"; }
control legacy-static-inject
control legacy-witness > "$state/legacy-refusal-before.txt"
if p up --target "$urn" --stack acceptance --skip-preview --yes --non-interactive > "$state/logs/legacy-static-refusal.log" 2>&1; then
    echo "Unknown historical static preimage was overwritten" >&2; exit 1
fi
grep -Fq 'restart requires a confirmed static file' "$state/logs/legacy-static-refusal.log"
control legacy-witness > "$state/legacy-refusal-after.txt"
cmp "$state/legacy-refusal-before.txt" "$state/legacy-refusal-after.txt"
control legacy-static-reconcile
# Keep the historical writer through its final multi-SNI fixture. No trusted
# static receipt exists until the explicit stopped-service transition.
install_provider "$state/legacy-provider"
p up --target "$urn" --stack acceptance --yes --non-interactive >>"$log" 2>&1
trap - EXIT
jq -n --argjson before "$old" --argjson after "$current" --argjson apiPages "$pages" '{baseline:$before,candidate:$after,observedNativePageSizes:$apiPages}' > "$state/pagination-evidence.json"
echo 'Read observed all 101 legacy listeners and the private listener; unchanged offline preview passed.'
