#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# < 4 )); then
    printf 'Usage: %s /tmp/dorothy-traefik-acceptance.XXXXXXXX <candidate-provider-directory> <phase> <up|preview|refresh|destroy> [pulumi args...]\n' "$0" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(realpath -e -- "$script_dir/../../..")
state_dir=$(realpath -e -- "$1")
provider_dir=$(realpath -e -- "$2")
phase=$3
pulumi_command=$4
shift 4
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to run outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" && -f "$state_dir/.owner" \
   && "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || {
    printf 'Private acceptance ownership marker is missing.\n' >&2
    exit 2
}
[[ "$phase" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || { printf 'Invalid review phase name.\n' >&2; exit 2; }
case "$pulumi_command" in
    up|preview|refresh|destroy) ;;
    *) printf 'Unsupported Pulumi command.\n' >&2; exit 2 ;;
esac
[[ -x "$provider_dir/pulumi-resource-keroosha" && -x "$provider_dir/helper/linux-x64/keroosha-iac-helper" ]] || {
    printf 'Candidate provider directory is missing its provider or NativeAOT helper.\n' >&2
    exit 2
}
source "$state_dir/handle.env"
traefik_urn=$(jq -er '[.deployment.resources[] | select(.type=="keroosha:debian:Traefik")] | select(length==1) | .[0].urn' "$state_dir/legacy-checkpoint.json")
[[ -f "$state_dir/pulumi-project/Pulumi.acceptance.yaml" && -f "$state_dir/pulumi-project/Pulumi.yaml" ]] || {
    printf 'Existing private acceptance Pulumi project state is missing.\n' >&2
    exit 2
}
[[ -s "$state_dir/legacy-example.pem" && -s "$state_dir/legacy-example.key" \
   && -s "$state_dir/sni-proof.pem" && -s "$state_dir/sni-proof.key" \
   && -s "$UPSTREAM_CA_FILE" && -s "$CLIENT_CA_FILE" && -s "$DNS_TSIG_SECRET_FILE" ]] || {
    printf 'Required private review fixtures are incomplete.\n' >&2
    exit 2
}
for command in dotnet pulumi jq sha256sum scp ssh realpath; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done
mkdir -m 700 -p "$state_dir/logs" "$state_dir/review-home" "$state_dir/review-dotnet-home" \
    "$state_dir/review-nuget-packages" "$state_dir/review-program"
chmod 700 "$state_dir/logs" "$state_dir/review-home" "$state_dir/review-dotnet-home" \
    "$state_dir/review-nuget-packages" "$state_dir/review-program"
export HOME="$state_dir/review-home"
export DOTNET_CLI_HOME="$state_dir/review-dotnet-home"
export NUGET_PACKAGES="$state_dir/review-nuget-packages"
export NUGET_HTTP_CACHE_PATH="$state_dir/review-nuget-http" XDG_CACHE_HOME="$state_dir/review-cache"
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
export TRAEFIK_ACCEPTANCE_REVIEW_CLIENT_CERT_FILE="$state_dir/review-client.pem"
export TRAEFIK_ACCEPTANCE_REVIEW_CLIENT_KEY_FILE="$state_dir/review-client.key"
export TRAEFIK_ACCEPTANCE_REVIEW_WRONG_CLIENT_CERT_FILE="$state_dir/review-wrong-client.pem"
export TRAEFIK_ACCEPTANCE_REVIEW_WRONG_CLIENT_KEY_FILE="$state_dir/review-wrong-client.key"
export TRAEFIK_ACCEPTANCE_CLIENT_IDENTITY_HOST=sni-proof.acceptance.test
export TRAEFIK_ACCEPTANCE_CLIENT_IDENTITY_PORT=18451
export UPSTREAM_CA_FILE
export CLIENT_CA_FILE
export DNS_TSIG_SECRET_FILE
export TRAEFIK_ACCEPTANCE_REVIEW_PHASE="$phase"
export PATH="$state_dir/bin:$PATH"

remote() {
    /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$1"
}
copy_to_guest() {
    /usr/bin/scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$1" "$SSH_USER@$SSH_HOST:$2"
}
copy_from_guest() {
    local source=$1 destination=$2 log_path=$3
    local temporary="$destination.tmp"
    [[ ! -e "$temporary" && ! -L "$temporary" ]] || { printf 'A private fixture transfer is already in progress.\n' >&2; return 1; }
    if ! /usr/bin/scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$SSH_USER@$SSH_HOST:$source" "$temporary" > "$log_path" 2>&1; then
        rm -f -- "$temporary"
        printf 'Private guest fixture transfer failed; see %s.\n' "$log_path" >&2
        return 1
    fi
    chmod 600 "$temporary"
    mv -f -- "$temporary" "$destination"
}

review_head=$(git -C "$repo_root" rev-parse HEAD)
review_stamp="$state_dir/review-prepared-head"
if [[ ! -e "$review_stamp" ]]; then
copy_to_guest "$state_dir/sni-proof.pem" "$GUEST_ROOT/certs/sni-proof.pem" \
    > "$state_dir/logs/review-sni-certificate-copy.log" 2>&1
remote "chmod 644 '$GUEST_ROOT/certs/sni-proof.pem'" > "$state_dir/logs/review-sni-certificate-mode.log" 2>&1
copy_to_guest "$script_dir/guest-fixtures.sh" "$GUEST_ROOT/review-guest-fixtures.sh" \
    > "$state_dir/logs/review-guest-fixtures-copy.log" 2>&1
remote "chmod 700 '$GUEST_ROOT/review-guest-fixtures.sh'; bash '$GUEST_ROOT/review-guest-fixtures.sh' '$GUEST_ROOT'" \
    > "$state_dir/logs/review-guest-fixtures-prepare.log" 2>&1 || {
    printf 'Guest review fixtures did not start; see %s/logs/review-guest-fixtures-prepare.log.\n' "$state_dir" >&2
    exit 1
}
copy_from_guest "$GUEST_ROOT/certs/client.pem" "$state_dir/review-client.pem" "$state_dir/logs/review-client-cert-copy.log"
copy_from_guest "$GUEST_ROOT/certs/client.key" "$state_dir/review-client.key" "$state_dir/logs/review-client-key-copy.log"
copy_from_guest "$GUEST_ROOT/certs/review-wrong-client.pem" "$state_dir/review-wrong-client.pem" "$state_dir/logs/review-wrong-client-cert-copy.log"
copy_from_guest "$GUEST_ROOT/certs/review-wrong-client.key" "$state_dir/review-wrong-client.key" "$state_dir/logs/review-wrong-client-key-copy.log"

ipv6=0
if remote 'ip -6 addr show dev lo 2>/dev/null | grep -Eq "inet6 ::1/128"' > "$state_dir/logs/review-ipv6-probe.log" 2>&1; then
    ipv6=1
fi
printf '%s\n' "$ipv6" > "$state_dir/review-ipv6-enabled"
remote "printf '%s\\n' '$ipv6' > '$GUEST_ROOT/review-ipv6-enabled'" \
    > "$state_dir/logs/review-ipv6-marker.log" 2>&1

candidate_source="$state_dir/review-source"
if [[ -e "$candidate_source" ]]; then
    [[ -d "$candidate_source" && -f "$candidate_source/.owner" \
       && "$(<"$candidate_source/.owner")" == dorothy-traefik-review-source-v1 ]] || {
        printf 'An unmarked source tree already occupies the private review path.\n' >&2
        exit 2
    }
    rm -rf -- "$candidate_source"
fi
mkdir -m 700 -p "$candidate_source"
git -C "$repo_root" archive "$review_head" -- src/Dorothy.DSL tests/Traefik.Acceptance/review \
    | tar -x -C "$candidate_source"
printf '%s\n' dorothy-traefik-review-source-v1 > "$candidate_source/.owner"
chmod 600 "$candidate_source/.owner"
if ! dotnet publish "$candidate_source/tests/Traefik.Acceptance/review/Traefik.Review.Acceptance.fsproj" \
    --configuration Release --output "$state_dir/review-program" \
    > "$state_dir/logs/review-program-publish.log" 2>&1; then
    printf 'Private review-program publish failed; see %s/logs/review-program-publish.log.\n' "$state_dir" >&2
    exit 1
fi
printf '%s\n' "$review_head" > "$review_stamp"
fi
[[ "$(<"$review_stamp")" == "$review_head" ]] || { echo 'Reusing a review fixture with a different source revision is not supported.' >&2; exit 2; }
export TRAEFIK_ACCEPTANCE_REVIEW_IPV6="$(<"$state_dir/review-ipv6-enabled")"
for material in "$TRAEFIK_ACCEPTANCE_REVIEW_CLIENT_CERT_FILE" "$TRAEFIK_ACCEPTANCE_REVIEW_CLIENT_KEY_FILE" "$TRAEFIK_ACCEPTANCE_REVIEW_WRONG_CLIENT_CERT_FILE" "$TRAEFIK_ACCEPTANCE_REVIEW_WRONG_CLIENT_KEY_FILE"; do
    [[ -s "$material" && ! -L "$material" ]] || { echo 'A staged client credential fixture is missing.' >&2; exit 2; }
done
[[ -s "$state_dir/review-program/Traefik.Review.Acceptance.dll" ]] || {
    printf 'Private review-program output is missing.\n' >&2
    exit 1
}
if ! pulumi plugin install resource keroosha 0.1.0 --file "$provider_dir" --reinstall \
    > "$state_dir/logs/review-provider-plugin-install.log" 2>&1; then
    printf 'Candidate provider installation failed; see %s/logs/review-provider-plugin-install.log.\n' "$state_dir" >&2
    exit 1
fi
if ! pulumi login "$PULUMI_BACKEND_URL" --non-interactive \
    > "$state_dir/logs/review-pulumi-login.log" 2>&1; then
    printf 'Private Pulumi backend login failed; see %s/logs/review-pulumi-login.log.\n' "$state_dir" >&2
    exit 1
fi

pulumi_project="$state_dir/pulumi-project"
manifest="$pulumi_project/Pulumi.yaml"
manifest_backup="$state_dir/review-Pulumi.yaml.backup"
[[ ! -e "$manifest_backup" && ! -L "$manifest_backup" ]] || { printf 'A review manifest backup already exists.\n' >&2; exit 2; }
cp -p "$manifest" "$manifest_backup"
restore_manifest() {
    if [[ -f "$manifest_backup" && -f "$manifest" ]]; then
        cp -p "$manifest_backup" "$manifest"
        rm -f -- "$manifest_backup"
    fi
}
trap restore_manifest EXIT
cat > "$manifest" <<EOF
name: traefik-acceptance
runtime:
  name: dotnet
  options:
    binary: $state_dir/review-program/Traefik.Review.Acceptance.dll
description: Private review acceptance phase on the existing sandbox resource
EOF
chmod 600 "$manifest"
log_path="$state_dir/logs/review-${phase}-${pulumi_command}.log"
if ! (cd "$pulumi_project" && pulumi "$pulumi_command" "$@" --target "$traefik_urn" --stack acceptance --non-interactive --color=never) \
    > "$log_path" 2>&1; then
    printf 'Review Pulumi command failed; see %s.\n' "$log_path" >&2
    exit 1
fi
printf 'Review phase %s completed with Pulumi %s; evidence: %s\n' "$phase" "$pulumi_command" "$log_path"
