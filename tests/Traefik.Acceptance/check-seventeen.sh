#!/usr/bin/env bash
# Compare Read on exactly the same on-wire material, not two different simulated router arrays.
set -euo pipefail
umask 077
[[ $# == 2 || $# == 3 ]] || { echo 'usage: check-seventeen.sh STATE_DIR CANDIDATE_PROVIDER [FROZEN_REVIEW_PROVIDER]' >&2; exit 2; }
state=$(realpath -e -- "$1"); candidate=$(realpath -e -- "$2"); frozen=${3:-}
[[ "$state" == /tmp/dorothy-traefik-acceptance.* && $(<"$state/.owner") == dorothy-traefik-acceptance-owned-state-v1 ]]
[[ "${PULUMI_HOME:-}" == "$state/pulumi-home" && "${PULUMI_BACKEND_URL:-}" == "file://$state/backend" ]]
bash "$(dirname "$(realpath "$0")")/guest-barrier-check.sh" acceptance "$state"
source "$state/handle.env"
script_dir=$(dirname "$(realpath "$0")")
project="$state/pulumi-project"; log="$state/logs/review-seventeen.log"; : > "$log"
urn=$(jq -er '.deployment.resources[] | select(.type=="keroosha:debian:Traefik") | .urn' "$state/legacy-checkpoint.json")
p(){ pulumi -C "$project" "$@"; }
install_provider(){ [[ -x "$1/pulumi-resource-keroosha" ]] && p plugin install resource keroosha 0.1.0 --file "$1" --reinstall >>"$log" 2>&1; }
refresh(){ p refresh --target "$urn" --stack acceptance --yes --non-interactive >>"$log" 2>&1; }
snapshot(){ p stack export --stack acceptance | jq -ce --arg urn "$urn" '.deployment.resources[]|select(.urn==$urn)|{inSync:.outputs.inSync,summary:.outputs.tlsProbeSummary,routers:(.inputs.routers|length),legacyOnly:(.inputs|has("configuration")|not)}'; }
remote(){ /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$@"; }
[[ "$GUEST_ROOT" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]]
control(){ remote "bash '$GUEST_ROOT/sni-drift.sh' '$1' '$GUEST_ROOT' legacy-many" >>"$log" 2>&1; }
recovery=false
restore(){ local rc=$?; trap - EXIT; if [[ "$recovery" == true ]]; then control restore || true; fi; install_provider "$candidate"; exit "$rc"; }; trap restore EXIT
scp -q -F "$SSH_CONFIG" -P "$SSH_PORT" "$script_dir/sni-drift.sh" "$SSH_USER@$SSH_HOST:$GUEST_ROOT/sni-drift.sh"
export TRAEFIK_ACCEPTANCE_PHASE=review-seventeen
install_provider "$state/legacy-provider"
p up --target "$urn" --stack acceptance --yes --non-interactive >>"$log" 2>&1
control prepare
install_provider "$candidate"; refresh; healthy=$(snapshot)
jq -e '.inSync and .routers==17 and .legacyOnly' <<< "$healthy" >/dev/null
control inject; recovery=true
old=null
if [[ -n "$frozen" ]]; then
    install_provider "$frozen"; refresh; old=$(snapshot)
    jq -e '.inSync and .routers==17 and .legacyOnly and .summary==null' <<< "$old" >/dev/null
    control assert-drift
    printf '%s\n' "$old" > "$state/sni-seventeen-frozen.json"
fi
install_provider "$candidate"; refresh; detected=$(snapshot)
jq -e '.summary.legacyProbesAttempted==17 and .summary.nativeProbesAttempted==0 and .summary.truncated==0' <<< "$healthy" >/dev/null
jq -e '(.inSync|not) and .routers==17 and .legacyOnly and .summary.legacyProbesAttempted==17 and .summary.truncated==0' <<< "$detected" >/dev/null
control assert-drift
remote "bash '$GUEST_ROOT/review-transactions.sh' maintenance-stop '$GUEST_ROOT'"
p up --target "$urn" --stack acceptance --yes --non-interactive >>"$log" 2>&1; control assert-positive
remote "bash '$GUEST_ROOT/review-transactions.sh' verify-receipt '$GUEST_ROOT'"
recovery=false; repaired=$(snapshot); jq -e '.inSync and .routers==17 and .legacyOnly' <<< "$repaired" >/dev/null
# The historical limit was shared; verify the non-legacy half of the summary against a distinct
# population too. Never use a static router count as the observed handshake count.
export TRAEFIK_ACCEPTANCE_PHASE=review-seventeen-native
p up --target "$urn" --stack acceptance --yes --non-interactive >>"$log" 2>&1
refresh; native=$(snapshot)
jq -e '.inSync and (.legacyOnly|not) and .summary.legacyProbesAttempted==1 and .summary.nativeProbesAttempted==17 and .summary.unprobedCount==0 and .summary.truncated==0' <<< "$native" >/dev/null
export TRAEFIK_ACCEPTANCE_PHASE=legacy; p up --target "$urn" --stack acceptance --yes --non-interactive >>"$log" 2>&1
trap - EXIT
jq -n --argjson before "$old" --argjson healthy "$healthy" --argjson bad "$detected" --argjson repaired "$repaired" --argjson native "$native" '{fixture:"17 distinct mandatory legacy TLS targets; desired hashes restored while later same-SAN substitute remains on wire",frozenWithWrongLeaf:$before,candidateHealthy:$healthy,candidateWithWrongLeaf:$bad,candidateRepaired:$repaired,seventeenNativeAndOneLegacy:$native}' > "$state/sni-seventeen.json"
echo 'Seventeenth legacy SNI: substituted wire leaf detected without changing desired files, then repaired.'
