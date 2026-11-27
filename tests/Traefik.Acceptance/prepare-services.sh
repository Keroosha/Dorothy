#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
    printf 'Usage: %s /tmp/dorothy-traefik-acceptance.XXXXXXXX\n' "$0" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
state_dir=$(realpath -e -- "$1")
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to provision outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" && "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || {
    printf 'Private acceptance ownership marker is missing.\n' >&2
    exit 2
}
bash "$script_dir/guest-barrier-check.sh" precondition "$state_dir"
source "$state_dir/handle.env"
for command in scp ssh openssl jq; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done

bash "$script_dir/stage-fixture-assets.sh" "$state_dir" verify

if [[ ! -s "$state_dir/dns-tsig-secret" ]]; then
    openssl rand -base64 32 > "$state_dir/dns-tsig-secret"
fi
chmod 600 "$state_dir/dns-tsig-secret"
if [[ ! -s "$state_dir/pulumi-passphrase" ]]; then
    openssl rand -base64 32 > "$state_dir/pulumi-passphrase"
fi
chmod 600 "$state_dir/pulumi-passphrase"

guest_root=$(/usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" \
    'mktemp -d /var/tmp/dorothy-traefik-acceptance.XXXXXXXX')
[[ "$guest_root" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]] || {
    printf 'Could not create a private persistent guest temp path.\n' >&2
    exit 1
}
/usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" \
    "install -d -m 700 '$guest_root/bin' '$guest_root/certs' '$guest_root/config' '$guest_root/dns' '$guest_root/logs' '$guest_root/units'"
for file in pebble otelcol-contrib traefik; do
    scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$state_dir/guest-files/$file" "$SSH_USER@$SSH_HOST:$guest_root/bin/$file"
done
for file in pebble.minica.pem cert.pem key.pem; do
    scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$state_dir/guest-files/$file" "$SSH_USER@$SSH_HOST:$guest_root/certs/$file"
done
scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$state_dir/dns-tsig-secret" "$SSH_USER@$SSH_HOST:$guest_root/dns/tsig-secret"
scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$script_dir/guest-services.sh" "$SSH_USER@$SSH_HOST:$guest_root/guest-services.sh"
scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$script_dir/guest-local-issuers.sh" "$SSH_USER@$SSH_HOST:$guest_root/guest-local-issuers.sh"
scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$script_dir/guest-activate-fixtures.sh" "$SSH_USER@$SSH_HOST:$guest_root/guest-activate-fixtures.sh"
/usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "chmod 700 '$guest_root/guest-services.sh' '$guest_root/guest-local-issuers.sh' '$guest_root/guest-activate-fixtures.sh' && bash '$guest_root/guest-services.sh' '$guest_root'"
for file in upstream-ca.pem client-ca.pem; do
    scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$SSH_USER@$SSH_HOST:$guest_root/certs/$file" "$state_dir/$file"
done
scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$SSH_USER@$SSH_HOST:$guest_root/logs/barrier-fixtures.log" "$state_dir/barrier-fixtures.log"

cat >> "$state_dir/handle.env" <<EOF
GUEST_ROOT=$guest_root
DNS_TSIG_KEY=traefik-acceptance.
DNS_TSIG_ALGORITHM=hmac-sha256.
DNS_NAMESERVER=127.0.0.1:1053
DNS_TSIG_SECRET_FILE=$state_dir/dns-tsig-secret
PULUMI_HOME=$state_dir/pulumi-home
PULUMI_BACKEND_URL=file://$state_dir/backend
PULUMI_PASSPHRASE_FILE=$state_dir/pulumi-passphrase
UPSTREAM_CA_FILE=$state_dir/upstream-ca.pem
CLIENT_CA_FILE=$state_dir/client-ca.pem
BASELINE_RUNTIME_LOG=$state_dir/baseline-runtime.log
SSH_WRAPPER_DIR=$state_dir/bin
EOF
chmod 600 "$state_dir/handle.env"

{
    printf 'Pinned Debian image: 13.8, build 20261123-2671\n'
    cat "$state_dir/fixture-versions.txt"
    printf 'Preapproval: loopback Pebble endpoints only; Traefik and protocol acceptance have not started.\n'
} > "$state_dir/preapproval-fixtures.txt"
chmod 600 "$state_dir/preapproval-fixtures.txt"
printf 'Local CA fixture prepared. Record and review the isolation receipt before proceeding.\n'
printf 'State directory: %s\nGuest root: %s\n' "$state_dir" "$guest_root"
printf 'Saved handle: %s/handle.env\n' "$state_dir"
