#!/usr/bin/env bash
# Cross-pair released executables on an existing live, marked *legacy* disposable instance.
# Bootstrap may populate its content-addressed helper cache. The Traefik resource must not change.
set -euo pipefail
umask 077
[[ $# == 3 ]] || { echo 'usage: helper-skew.sh STATE_DIR FROZEN_PROVIDER CURRENT_PROVIDER' >&2; exit 2; }
state=$(realpath -e "$1"); old=$(realpath -e "$2"); current=$(realpath -e "$3")
[[ "$state" == /tmp/dorothy-traefik-acceptance.* && $(<"$state/.owner") == dorothy-traefik-acceptance-owned-state-v1 ]]
source "$state/handle.env"
[[ "$SSH_USER" == root && "$GUEST_ROOT" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]]
for bundle in "$old" "$current"; do
    [[ -x "$bundle/pulumi-resource-keroosha" && -f "$bundle/pulumi-resource-keroosha.dll" && -x "$bundle/helper/linux-x64/keroosha-iac-helper" ]]
done
work=$(mktemp -d "$state/helper-skew.XXXXXXXX"); log="$state/logs/helper-skew.log"; : > "$log"
project=$work/project; mkdir "$project"; cp "$state/pulumi-project/Pulumi.acceptance.yaml" "$project/"
[[ -f "$state/legacy-program/Traefik.Acceptance.dll" ]]
printf 'name: traefik-acceptance\nruntime:\n  name: dotnet\n  options:\n    binary: %s/legacy-program/Traefik.Acceptance.dll\n' "$state" > "$project/Pulumi.yaml"
export HOME="$state/home" DOTNET_CLI_HOME="$state/dotnet-home" NUGET_PACKAGES="$state/nuget-packages" PULUMI_HOME="$state/pulumi-home" PULUMI_BACKEND_URL="file://$state/backend"
export PULUMI_CONFIG_PASSPHRASE="$(<"$PULUMI_PASSPHRASE_FILE")" PULUMI_SKIP_UPDATE_CHECK=1 PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=1
export DOTNET_ROOT=$(dirname "$(readlink -f "$(command -v dotnet)")"); export DOTNET_ROOT_X64="$DOTNET_ROOT"
export DOROTHY_ACCEPTANCE_SSH_CONFIG="$SSH_CONFIG" DOROTHY_ACCEPTANCE_SSH_PORT="$SSH_PORT" PATH="$state/bin:$PATH"
export TRAEFIK_ACCEPTANCE_LEGACY_CERT_FILE="$state/legacy-example.pem" TRAEFIK_ACCEPTANCE_LEGACY_KEY_FILE="$state/legacy-example.key"
p(){ pulumi -C "$project" "$@"; }
install_provider(){ p plugin install resource keroosha 0.1.0 --file "$1" --reinstall >>"$log" 2>&1; }
cleanup(){ local rc=$?; trap - EXIT; install_provider "$current" || rc=1; rm -rf "$work"; exit "$rc"; }; trap cleanup EXIT
sha(){ sha256sum "$1" | cut -d' ' -f1; }
resource_digest(){
    # Hash the resource's semantic state inside a pipe. Ciphertext can change between exports.
    p stack export --stack acceptance --show-secrets | jq -ceS --arg u "$urn" '.deployment.resources[] | select(.urn==$u) | {urn,id,inputs,outputs}' | sha256sum | cut -d' ' -f1
}
guest(){ /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$@"; }
live_digest(){
    guest 'set -eu; systemctl is-active --quiet keroosha-traefik.service; systemctl show -p MainPID --value keroosha-traefik.service; for p in /etc/keroosha-iac/traefik /usr/local/libexec/keroosha-iac/traefik /var/lib/keroosha-traefik /etc/systemd/system/keroosha-traefik.service; do find "$p" -xdev -printf "%y %p %m %u %g %i %T@\n" | LC_ALL=C sort; find "$p" -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0r sha256sum; done' | sha256sum | cut -d' ' -f1
}
urn=$(jq -er '.deployment.resources[]|select(.type=="keroosha:debian:Traefik")|.urn' "$state/legacy-checkpoint.json")
[[ $(sha "$old/pulumi-resource-keroosha.dll") != $(sha "$current/pulumi-resource-keroosha.dll") ]]
old_sha=$(sha "$old/helper/linux-x64/keroosha-iac-helper"); new_sha=$(sha "$current/helper/linux-x64/keroosha-iac-helper"); [[ "$old_sha" != "$new_sha" ]]
initial_state=$(resource_digest); initial_guest=$(live_digest)
p config set backend http://127.0.0.1:18080 --stack acceptance --non-interactive >>"$log" 2>&1
for pair in old-provider new-provider; do
    if [[ "$pair" == old-provider ]]; then
        provider=$old; helper=$current; reason='legacy Traefik command is disabled'
    else
        provider=$current; helper=$old; reason="required Traefik capability 'traefik-v2'"
    fi
    mkdir "$work/$pair"; cp -a "$provider/." "$work/$pair/"; cp "$helper/helper/linux-x64/keroosha-iac-helper" "$work/$pair/helper/linux-x64/keroosha-iac-helper"
    install_provider "$work/$pair"
    if p up --stack acceptance --target "$urn" --yes --skip-preview --non-interactive > "$work/$pair.log" 2>&1; then echo "Unexpected successful $pair update" >&2; exit 1; fi
    grep -Fq "$reason" "$work/$pair.log" || { echo "Missing $pair capability refusal" >&2; exit 1; }
    [[ $(resource_digest) == "$initial_state" && $(live_digest) == "$initial_guest" ]] || { echo "$pair changed managed state" >&2; exit 1; }
done
guest "/var/cache/keroosha-iac/helper/linux-x64/$new_sha traefik-capabilities" | jq -e '. == {protocol:"dorothy-traefik",version:2,capabilities:["traefik-v2"]}' >/dev/null
jq -n --arg old "$old_sha" --arg new "$new_sha" '{frozenHelper:$old,candidateHelper:$new,bothMismatchDirectionsRefused:true,checkpointUnchanged:true,liveFilesAndPidUnchanged:true}' > "$state/helper-skew-evidence.json"
echo 'Both incompatible provider/helper pairs refused before Traefik mutation.'
