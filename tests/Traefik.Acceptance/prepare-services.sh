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
source "$state_dir/handle.env"
for command in curl sha256sum tar scp ssh openssl jq; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done

mkdir -m 700 -p "$state_dir/downloads" "$state_dir/guest-files"
chmod 700 "$state_dir/downloads" "$state_dir/guest-files"

pebble_version=v2.10.3
otelcol_version=0.166.0
traefik_version=3.7.16
pebble_archive="$state_dir/downloads/pebble-linux-amd64.tar.gz"
otelcol_archive="$state_dir/downloads/otelcol-contrib_${otelcol_version}_linux_amd64.tar.gz"
traefik_archive="$state_dir/downloads/traefik_v${traefik_version}_linux_amd64.tar.gz"

if [[ ! -s "$pebble_archive" ]]; then
    curl --fail --location --silent --show-error --retry 3 \
        "https://github.com/letsencrypt/pebble/releases/download/${pebble_version}/pebble-linux-amd64.tar.gz" \
        -o "$pebble_archive"
fi
[[ "$(sha256sum "$pebble_archive" | awk '{ print $1 }')" == 7e33cf3e426b67e9e647c44e8cc91683caa8ab331f7a99e5e27fcee291c4c7e2 ]] || {
    printf 'Pinned Pebble release digest mismatch.\n' >&2
    exit 1
}

if [[ ! -s "$otelcol_archive" ]]; then
    curl --fail --location --silent --show-error --retry 3 \
        "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${otelcol_version}/$(basename "$otelcol_archive")" \
        -o "$otelcol_archive"
fi
if [[ ! -s "$otelcol_archive.sha256" ]]; then
    curl --fail --location --silent --show-error --retry 3 \
        "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${otelcol_version}/$(basename "$otelcol_archive").sha256" \
        -o "$otelcol_archive.sha256"
fi
otelcol_hash=$(awk 'NR == 1 { print $1 }' "$otelcol_archive.sha256")
[[ "$otelcol_hash" =~ ^[0-9a-f]{64}$ ]] || { printf 'Pinned OpenTelemetry Collector checksum is malformed.\n' >&2; exit 1; }
[[ "$(sha256sum "$otelcol_archive" | awk '{ print $1 }')" == "$otelcol_hash" ]] || {
    printf 'Pinned OpenTelemetry Collector release digest mismatch.\n' >&2
    exit 1
}

if [[ ! -s "$traefik_archive" ]]; then
    curl --fail --location --silent --show-error --retry 3 \
        "https://github.com/traefik/traefik/releases/download/v${traefik_version}/traefik_v${traefik_version}_linux_amd64.tar.gz" \
        -o "$traefik_archive"
fi
[[ "$(sha256sum "$traefik_archive" | awk '{ print $1 }')" == 759a7bc0d66b74c588255ed9e41c7f9d4aba60bdb7bce9dde551b1268a55eb07 ]] || {
    printf 'Pinned Traefik release digest mismatch.\n' >&2
    exit 1
}

extract_binary() {
    archive=$1
    binary=$2
    destination=$3
    member=$(tar -tzf "$archive" | awk -v name="$binary" '$0 == name || $0 ~ ("/" name "$" ) { print; exit }')
    [[ -n "$member" && "$member" != /* && "$member" != *../* ]] || {
        printf 'Pinned archive does not contain the expected binary.\n' >&2
        exit 1
    }
    tar -xOzf "$archive" "$member" > "$destination"
    chmod 700 "$destination"
}
extract_binary "$pebble_archive" pebble "$state_dir/guest-files/pebble"
extract_binary "$otelcol_archive" otelcol-contrib "$state_dir/guest-files/otelcol-contrib"
extract_binary "$traefik_archive" traefik "$state_dir/guest-files/traefik"

for name in pebble.minica.pem cert.pem key.pem; do
    case "$name" in
        pebble.minica.pem) source_name=test/certs/pebble.minica.pem ;;
        cert.pem) source_name=test/certs/localhost/cert.pem ;;
        key.pem) source_name=test/certs/localhost/key.pem ;;
    esac
    if [[ ! -s "$state_dir/guest-files/$name" ]]; then
        curl --fail --location --silent --show-error --retry 3 \
            "https://raw.githubusercontent.com/letsencrypt/pebble/${pebble_version}/${source_name}" \
            -o "$state_dir/guest-files/$name"
    fi
done
chmod 600 "$state_dir/guest-files/key.pem"

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
/usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "chmod 700 '$guest_root/guest-services.sh' && bash '$guest_root/guest-services.sh' '$guest_root'"
for file in upstream-ca.pem client-ca.pem; do
    scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$SSH_USER@$SSH_HOST:$guest_root/certs/$file" "$state_dir/$file"
done
scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$SSH_USER@$SSH_HOST:$guest_root/logs/baseline-observations.log" "$state_dir/baseline-runtime.log"

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
    printf 'Pinned Traefik upstream: v%s\n' "$traefik_version"
    printf 'Pinned Pebble ACME test CA: %s\n' "$pebble_version"
    printf 'Pinned OTel Collector: v%s\n' "$otelcol_version"
    printf 'Guest DNS zone: acceptance.test, RFC2136 DNSUPDATE_* TSIG\n'
    printf 'Guest loopback services: DNS 127.0.0.1:1053, ACME 127.0.0.1:14000, telemetry 127.0.0.1:4317/4318, HTTP backends 127.0.0.1:8080/8081, TCP/UDP 127.0.0.1:19001/19002\n'
} > "$state_dir/baseline-observations.txt"
chmod 600 "$state_dir/baseline-observations.txt"
printf 'Private test endpoints and collectors are ready in the isolated Debian guest.\n'
printf 'State directory: %s\nGuest root: %s\n' "$state_dir" "$guest_root"
printf 'Saved handle: %s/handle.env\n' "$state_dir"
