#!/usr/bin/env bash
# Host-side only. Fetch public release artifacts before QEMU starts; verify mode never downloads.
set -euo pipefail
umask 077
[[ $# == 1 || ( $# == 2 && $2 == verify ) ]] || exit 2
state=$(realpath -e -- "$1"); mode=${2:-stage}
[[ "$state" =~ ^/tmp/dorothy-traefik-acceptance\.[[:alnum:]]{8}$ && $(stat -c '%a:%u' "$state") == "700:$(id -u)" && -f "$state/.owner" && ! -L "$state/.owner" && $(<"$state/.owner") == dorothy-traefik-acceptance-owned-state-v1 ]] || exit 2
if [[ "$mode" == stage && ( -e "$state/guest.qcow2" || -e "$state/qemu.pid" ) ]]; then
    echo 'Refusing to stage inputs into a previously launched guest.' >&2; exit 2
fi
files=$state/guest-files; downloads=$state/downloads
if [[ "$mode" == stage ]]; then mkdir -m 700 -p "$files" "$downloads"; fi
[[ -d "$files" && ! -L "$files" && -d "$downloads" && ! -L "$downloads" ]] || exit 2
scratch=$(mktemp -d "$state/fixture-stage.XXXXXXXX"); trap 'rm -rf -- "$scratch"' EXIT
verified(){ [[ -f "$1" && ! -L "$1" && $(sha256sum -- "$1" | cut -d' ' -f1) == "$2" ]]; }
fetch_public() {
    if [[ -n ${DOROTHY_ACCEPTANCE_PUBLIC_ASSET_CACHE:-} ]]; then
        local cached="$DOROTHY_ACCEPTANCE_PUBLIC_ASSET_CACHE/${1##*/}"
        [[ -f "$cached" && ! -L "$cached" ]] || { echo 'Pinned asset missing from explicit offline cache.' >&2; return 1; }
        cp --reflink=auto -- "$cached" "$2"
    else
        curl --disable --noproxy '*' --proto '=https' --proto-redir '=https' --fail --location --silent --show-error "$1" -o "$2"
    fi
}
image=debian-13-generic-amd64-20261123-2671.qcow2
if [[ "$mode" == stage && ! -e "$state/$image" && ! -L "$state/$image" ]]; then
    fetch_public "https://cloud.debian.org/images/cloud/trixie/20261123-2671/$image" "$scratch/image"
    mv -T "$scratch/image" "$state/$image"
fi
[[ -f "$state/$image" && ! -L "$state/$image" && $(sha512sum "$state/$image" | cut -d' ' -f1) == 562a4614952657a6ab8a89cda56eaf1bc85c8dfea51155184267bb6b6361eff215baf6afa2f8c2c8c2bad328ac6c30eead80664286ef4c8538368aeb7f87104f ]] || {
    echo 'Pinned Debian backing image digest mismatch.' >&2; exit 1;
}
asset(){
    local url=$1 archive_sha=$2 member=$3 binary=$4 binary_sha=$5 archive="$downloads/${1##*/}"
    if [[ ! -e "$archive" && ! -L "$archive" && "$mode" == stage ]]; then
        fetch_public "$url" "$scratch/archive"
        verified "$scratch/archive" "$archive_sha"; mv -T "$scratch/archive" "$archive"
    fi
    verified "$archive" "$archive_sha" || { echo 'Pinned public release archive missing or invalid.' >&2; return 1; }
    if [[ ! -e "$files/$binary" && ! -L "$files/$binary" && "$mode" == stage ]]; then
        tar -xzOf "$archive" -- "$member" > "$scratch/bin"
        verified "$scratch/bin" "$binary_sha"; chmod 700 "$scratch/bin"; mv -T "$scratch/bin" "$files/$binary"
    fi
    verified "$files/$binary" "$binary_sha" || { echo 'Staged fixture binary digest mismatch.' >&2; return 1; }
}
for name in pebble.minica.pem cert.pem key.pem; do [[ ! -L "$files/$name" ]] || exit 1; done
asset https://github.com/letsencrypt/pebble/releases/download/v2.10.3/pebble-linux-amd64.tar.gz \
    7e33cf3e426b67e9e647c44e8cc91683caa8ab331f7a99e5e27fcee291c4c7e2 pebble-linux-amd64/linux/amd64/pebble pebble \
    8578a9b335afb8ead81b2b536116010b65f27fee2fb32dbf5288aa7e91e2d203
asset https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.166.0/otelcol-contrib_0.166.0_linux_amd64.tar.gz \
    928cb39c115d428c53211818b7e33cd8b26810b8896dc74e0bd13b8d1457c391 otelcol-contrib otelcol-contrib \
    036082c2c2f777abcaa7a29d73440bf4818bf4277436303b147d63e7938a4e27
asset https://github.com/traefik/traefik/releases/download/v3.7.16/traefik_v3.7.16_linux_amd64.tar.gz \
    759a7bc0d66b74c588255ed9e41c7f9d4aba60bdb7bce9dde551b1268a55eb07 traefik traefik \
    86ee2b427888d24475051fc5f5bcca94cf4fa033b6fa54205b7eb0de6914f31e

# Transport certificates for the two local Pebble API endpoints. Their issuance roots
# are *different* and are obtained through these authenticated management endpoints.
if [[ "$mode" == stage && ! -e "$files/pebble.minica.pem" && ! -e "$files/cert.pem" && ! -e "$files/key.pem" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 3 \
        -subj '/CN=Disposable fixture transport CA' -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout "$scratch/ca.key" -out "$scratch/ca.pem" 2>/dev/null
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -subj '/CN=localhost' \
        -keyout "$scratch/server.key" -out "$scratch/server.csr" 2>/dev/null
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
        'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1' > "$scratch/server.ext"
    openssl x509 -req -in "$scratch/server.csr" -CA "$scratch/ca.pem" -CAkey "$scratch/ca.key" -CAcreateserial \
        -sha256 -days 2 -extfile "$scratch/server.ext" -out "$scratch/server.pem" 2>/dev/null
    install -m 600 "$scratch/ca.pem" "$files/pebble.minica.pem"; install -m 600 "$scratch/server.pem" "$files/cert.pem"
    install -m 600 "$scratch/server.key" "$files/key.pem"
fi
for name in pebble.minica.pem cert.pem key.pem; do [[ -s "$files/$name" && ! -L "$files/$name" ]] || exit 1; done
openssl verify -no-CAfile -no-CApath -no-CAstore -trusted "$files/pebble.minica.pem" -purpose sslserver -verify_hostname localhost "$files/cert.pem" >/dev/null
cmp -s <(openssl x509 -in "$files/cert.pem" -noout -pubkey) <(openssl pkey -in "$files/key.pem" -pubout)
if [[ "$mode" == stage ]]; then
    printf '%s\n' 'Pinned guest fixtures: Traefik 3.7.16; Pebble v2.10.3; otelcol-contrib 0.166.0.' > "$state/fixture-versions.txt"
fi
printf 'Verified pre-staged public archives, executable digests and isolated localhost TLS identity.\n'
