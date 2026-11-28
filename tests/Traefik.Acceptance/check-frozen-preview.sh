#!/usr/bin/env bash
# Run after installing the candidate and before refreshing the original historical stack.
set -euo pipefail
umask 077
[[ $# == 1 ]] || { echo 'usage: check-frozen-preview.sh STATE_DIR' >&2; exit 2; }
state=$(realpath -e -- "$1")
[[ "$state" == /tmp/dorothy-traefik-acceptance.* && -f "$state/.owner" && $(<"$state/.owner") == dorothy-traefik-acceptance-owned-state-v1 ]] || exit 2
checkpoint="$state/legacy-checkpoint.json"
project="$state/pulumi-project"
[[ -s "$checkpoint" && -f "$project/Pulumi.yaml" && -f "$project/Pulumi.acceptance.yaml" && -d "$state/pulumi-home/plugins" ]] || exit 2
: "${PULUMI_CONFIG_PASSPHRASE:?private fixture passphrase must be set}"
urn=$(jq -er '[.deployment.resources[] | select(.type == "keroosha:debian:Traefik")] | select(length == 1 and (.[0].inputs | has("configuration") | not)) | .[0].urn' "$checkpoint")
work=$(mktemp -d "$state/offline-preview.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/backend" "$work/project" "$work/home" "$work/bin"
cp "$project/Pulumi.yaml" "$project/Pulumi.acceptance.yaml" "$work/project/"
ln -s "$state/pulumi-home/plugins" "$work/home/plugins"
export PULUMI_BACKEND_URL="file://$work/backend" PULUMI_HOME="$work/home" PULUMI_SKIP_UPDATE_CHECK=1 PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=1
export TRAEFIK_ACCEPTANCE_PHASE=legacy SSH_SENTINEL_FILE="$work/ssh-attempts" PATH="$work/bin:$PATH"
printf '#!/bin/sh\nprintf "x\\n" >> "$SSH_SENTINEL_FILE"\nexit 77\n' > "$work/bin/ssh"
chmod 700 "$work/bin/ssh"
: > "$SSH_SENTINEL_FILE"
log="$state/logs/offline-frozen-preview.log"
if ! pulumi -C "$work/project" stack init acceptance --secrets-provider passphrase --non-interactive > "$log" 2>&1 ||
   ! pulumi -C "$work/project" stack import --stack acceptance --file "$checkpoint" --non-interactive >> "$log" 2>&1 ||
   ! pulumi -C "$work/project" preview --stack acceptance --target "$urn" --refresh=false --expect-no-changes --non-interactive --color=never >> "$log" 2>&1; then
    echo 'The copied default-branch checkpoint did not produce an unchanged offline Traefik preview.' >&2; exit 1
fi
[[ ! -s "$SSH_SENTINEL_FILE" ]] || { echo 'Offline preview attempted SSH.' >&2; exit 1; }
jq -n --arg base 2d486e33fc8cdae60c6a7571f8ba6f07b5b5ebf3 '{frozenBase:$base,status:"unchanged",targetResourceCount:1,refresh:false,sshInvocations:0}' > "$state/offline-preview.json"
echo 'Copied frozen checkpoint: Traefik unchanged; zero SSH invocations.'
