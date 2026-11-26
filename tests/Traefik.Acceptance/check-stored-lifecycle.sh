#!/usr/bin/env bash
# Destructive Traefik-only gate on a disposable acceptance stack. This is separate from the
# unchanged-checkpoint migration: it deliberately destroys the historical resources under test.
set -euo pipefail
umask 077
[[ $# == 3 ]] || { echo 'usage: check-stored-lifecycle.sh STATE_DIR CANDIDATE_PROVIDER FROZEN_REVIEW_PROVIDER' >&2; exit 2; }
state=$(realpath -e "$1"); current=$(realpath -e "$2"); old=$(realpath -e "$3")
[[ "$state" == /tmp/dorothy-traefik-acceptance.* && $(<"$state/.owner") == dorothy-traefik-acceptance-owned-state-v1 ]]
[[ "${PULUMI_HOME:-}" == "$state/pulumi-home" && "${PULUMI_BACKEND_URL:-}" == "file://$state/backend" ]]
source "$state/handle.env"
fixture=$(dirname "$(realpath "$0")"); log="$state/logs/review-stored.log"; : > "$log"
urn=$(jq -er '.deployment.resources[]|select(.type=="keroosha:debian:Traefik")|.urn' "$state/legacy-checkpoint.json")
p(){ pulumi -C "$state/pulumi-project" "$@"; }
install_provider(){ [[ -x "$1/pulumi-resource-keroosha" ]] && p plugin install resource keroosha 0.1.0 --file "$1" --reinstall >> "$log" 2>&1; }
refresh(){ p refresh --stack acceptance --target "$urn" --yes --non-interactive >> "$log" 2>&1; }
destroy(){ p destroy --stack acceptance --target "$urn" --yes --skip-preview --non-interactive >> "$log" 2>&1; }
state_summary(){ p stack export --stack acceptance | jq -ce --arg urn "$urn" '[.deployment.resources[]|select(.urn==$urn)|{inSync:.outputs.inSync}]'; }
live_stamp(){ /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" 'set -eu; systemctl show --property=MainPID --value keroosha-traefik.service; sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml'; }
run_case(){
    local creation_provider=$1 case_name=$2 initial stamp seen final reason diagnostic
    install_provider "$creation_provider"
    p up --stack acceptance --target "$urn" --yes --non-interactive >> "$log" 2>&1
    initial=$(state_summary); jq -e 'length==1 and .[0].inSync' <<< "$initial" >/dev/null
    if [[ "$case_name" == expired ]]; then
        for _ in $(seq 1 55); do openssl x509 -noout -checkend 0 -in "$TRAEFIK_REVIEW_CA_FILE" >/dev/null || break; sleep 1; done
        if openssl x509 -noout -checkend 0 -in "$TRAEFIK_REVIEW_CA_FILE" >/dev/null; then echo 'CA did not expire' >&2; return 1; fi
    fi
    stamp=$(live_stamp)
    install_provider "$old"
    case "$case_name" in
        expired) reason='Invalid, unsafe or unsupported Traefik static settings or listener socket.' ;;
        distinctNumericAdminPort) reason='A proxy destination must not use the private Traefik administration port.' ;;
        *) return 2 ;;
    esac
    for operation in refresh destroy; do
        diagnostic="$state/logs/review-stored-$case_name-$operation.log"
        if p "$operation" --stack acceptance --target "$urn" --yes --skip-preview --non-interactive > "$diagnostic" 2>&1; then
            echo "Frozen $operation unexpectedly accepted $case_name" >&2; return 1
        fi
        grep -Fq "$reason" "$diagnostic" || { echo "Unexpected frozen $operation failure" >&2; return 1; }
    done
    [[ $(live_stamp) == "$stamp" ]] || { echo 'Frozen resource unexpectedly mutated.' >&2; return 1; }
    install_provider "$current"; refresh
    # Both controls have unchanged desired files and a healthy process. Neither retained input
    # is by itself evidence of runtime drift: expiry is not an ownership or decoding failure.
    seen=$(state_summary); jq -e 'length==1 and .[0].inSync==true' <<< "$seen" >/dev/null
    [[ $(live_stamp) == "$stamp" ]] || { echo 'Read mutated the guest' >&2; return 1; }
    destroy; final=$(state_summary); jq -e 'length==0' <<< "$final" >/dev/null
    jq -n --arg name "$case_name" --argjson before "$initial" --argjson after "$seen" '{case:$name,initial:$before,oldReadRefused:true,oldDeleteRefused:true,unchangedOnRead:true,candidateRead:$after,deleted:true}'
}
trap 'install_provider "$current"' EXIT
export TRAEFIK_ACCEPTANCE_PHASE=legacy
p config set backend http://192.0.2.31:19080 --stack acceptance --non-interactive >> "$log" 2>&1
run_case "$state/legacy-provider" distinctNumericAdminPort > "$state/stored-numeric.json"
export TRAEFIK_ACCEPTANCE_PHASE=review-expiring-ca TRAEFIK_REVIEW_CA_FILE="$state/expiring-ca.pem"
p config set backend http://127.0.0.1:8080 --stack acceptance --non-interactive >> "$log" 2>&1
dotnet fsi --nologo "$fixture/expiring-ca.fsx" "$TRAEFIK_REVIEW_CA_FILE" >> "$log" 2>&1
run_case "$old" expired > "$state/stored-expiry.json"
trap - EXIT
jq -s '.' "$state/stored-numeric.json" "$state/stored-expiry.json" > "$state/stored-lifecycle-evidence.json"
echo 'Real historical same-port and expired-trust resources both refreshed and deleted without the old admission failures.'
