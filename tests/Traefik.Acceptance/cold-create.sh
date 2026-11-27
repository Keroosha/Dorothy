#!/usr/bin/env bash
# Authorized, fresh Debian guest only. No frozen provider or preinstalled release.
set -euo pipefail
umask 077
[[ $# == 3 ]]
s=$(realpath -e "$1"); provider=$(realpath -e "$2"); archive=$(realpath -e "$3")
f=$(dirname "$(realpath "$0")"); repo=$(realpath "$f/../..")
[[ $s == /tmp/dorothy-traefik-acceptance.* && $(<"$s/.owner") == dorothy-traefik-acceptance-owned-state-v1 ]]
bash "$f/guest-barrier-check.sh" acceptance "$s"
. "$s/handle.env"
remote(){ /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$@"; }
log="$s/logs"; project="$s/cold-project"; mkdir -m700 -p "$log" "$project" "$s/home" "$s/dotnet-home" "$s/nuget-packages"
export HOME="$s/home" DOTNET_CLI_HOME="$s/dotnet-home" NUGET_PACKAGES="$s/nuget-packages" NUGET_HTTP_CACHE_PATH="$s/nuget-http" XDG_CACHE_HOME="$s/cache" PULUMI_HOME="$s/pulumi-home" PULUMI_BACKEND_URL="file://$s/backend" PULUMI_CONFIG_PASSPHRASE="$(<"$PULUMI_PASSPHRASE_FILE")" PULUMI_SKIP_UPDATE_CHECK=1 PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=1 DOTNET_PROCESSOR_COUNT=1 MSBUILDDISABLENODEREUSE=1 DOTNET_CLI_USE_MSBUILD_SERVER=0
export DOTNET_ROOT=$(dirname "$(readlink -f "$(command -v dotnet)")"); export DOTNET_ROOT_X64="$DOTNET_ROOT" DOROTHY_ACCEPTANCE_SSH_CONFIG="$SSH_CONFIG" DOROTHY_ACCEPTANCE_SSH_PORT="$SSH_PORT" PATH="$s/bin:$PATH" UPSTREAM_CA_FILE CLIENT_CA_FILE DNS_TSIG_SECRET_FILE
install -m700 "$f/ssh-wrapper.sh" "$s/bin/ssh"
for spec in 'legacy-example example.org' 'sni-proof sni-proof.acceptance.test'; do read -r name host <<< "$spec"; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$host" -addext "subjectAltName=DNS:$host" -addext 'basicConstraints=critical,CA:FALSE' -addext 'extendedKeyUsage=serverAuth' -keyout "$s/$name.key" -out "$s/$name.pem" 2> "$log/$name-cert.log"; done
export TRAEFIK_ACCEPTANCE_LEGACY_CERT_FILE="$s/legacy-example.pem" TRAEFIK_ACCEPTANCE_LEGACY_KEY_FILE="$s/legacy-example.key" TRAEFIK_ACCEPTANCE_SNI_CERT_FILE="$s/sni-proof.pem" TRAEFIK_ACCEPTANCE_SNI_KEY_FILE="$s/sni-proof.key"
mkdir -m700 "$s/cold-source"; git -C "$repo" archive HEAD src/Dorothy.DSL tests/Traefik.Acceptance | tar -x -C "$s/cold-source"; dotnet publish "$s/cold-source/tests/Traefik.Acceptance/Traefik.Acceptance.fsproj" -c Release -m:1 --disable-build-servers -o "$s/cold-program" > "$log/cold-build.log" 2>&1
printf 'name: traefik-acceptance\nruntime:\n  name: dotnet\n  options:\n    binary: %s/Traefik.Acceptance.dll\n' "$s/cold-program" > "$project/Pulumi.yaml"
p(){ pulumi -C "$project" "$@"; }; p login "$PULUMI_BACKEND_URL" --non-interactive; p plugin install resource keroosha 0.1.0 --file "$provider" --reinstall; p stack init acceptance --secrets-provider passphrase --non-interactive
export TRAEFIK_ACCEPTANCE_PHASE=rotate
up(){ p up --stack acceptance --skip-preview --parallel 1 --yes --non-interactive; }
absent(){ remote 'set -eu; if getent passwd keroosha-traefik || getent group keroosha-traefik; then exit 1; fi; for path in /etc/keroosha-iac/traefik /var/lib/keroosha-traefik /usr/local/libexec/keroosha-iac/traefik /etc/systemd/system/keroosha-traefik.service; do test ! -e "$path" && test ! -L "$path"; done; test "$(systemctl show keroosha-traefik.service -p LoadState --value)" = not-found'; }
remote "bash '$GUEST_ROOT/guest-activate-fixtures.sh' '$GUEST_ROOT'" > "$log/cold-backends.log" 2>&1
absent
sha=759a7bc0d66b74c588255ed9e41c7f9d4aba60bdb7bce9dde551b1268a55eb07
[[ $(sha256sum "$archive"|cut -d' ' -f1) == "$sha" ]]
cache=/var/cache/keroosha-iac/traefik/$sha.tar.gz
remote "set -eu; install -d -m755 /var/cache/keroosha-iac/traefik; test ! -e '$cache'; ln -s /nonexistent '$cache'"
if up > "$log/cold-unsafe.log" 2>&1; then exit 1; fi; grep -Fq 'unsafe or inaccessible pinned archive cache' "$log/cold-unsafe.log"; absent
remote "set -eu; test -L '$cache'; rm '$cache'; truncate -s 51045831 '$cache'; chmod 644 '$cache'"
if up > "$log/cold-corrupt.log" 2>&1; then exit 1; fi; grep -Fq 'archive checksum does not match' "$log/cold-corrupt.log"; absent
remote "set -eu; cat > '$cache'; echo '$sha  $cache' |sha256sum -c -" < "$archive"
stores(){ remote 'set -euo pipefail; files=(/var/lib/keroosha-traefik/acme-*.json); test ${#files[@]} -eq 3; for f in "${files[@]}"; do test -s "$f"; sha256sum "$f"; done'; }
proof(){ remote "set -eu; exe=/usr/local/libexec/keroosha-iac/traefik/3.7.16/traefik; echo '86ee2b427888d24475051fc5f5bcca94cf4fa033b6fa54205b7eb0de6914f31e  '\"\$exe\" | sha256sum -c -; \"\$exe\" version |grep '3.7.16'; for path in /etc/keroosha-iac/traefik/{,dynamic/,dynamic/certificates/}.keroosha-owner /usr/local/libexec/keroosha-iac/traefik/.keroosha-owner; do cmp \"\$path\" /var/lib/keroosha-traefik/.keroosha-owner; done; curl -fsS --cacert '$GUEST_ROOT/certs/pebble.minica.pem' https://localhost:15001/roots/0 > '$GUEST_ROOT/cold-root.pem'; curl -fsS --noproxy '*' --resolve shop.acceptance.test:18443:127.0.0.1 --cacert '$GUEST_ROOT/cold-root.pem' https://shop.acceptance.test:18443/secure/health |grep -F tls-backend:/secure/health; echo '$sha  $cache' |sha256sum -c -"; }
control(){ remote "bash -s -- '$GUEST_ROOT' '$1'" < "$f/cold-controls.sh"; }
for pass in first recreated; do
    up > "$log/cold-$pass-up.log" 2>&1
    proof > "$log/cold-$pass-proof.log"
    p refresh --yes --non-interactive > "$log/cold-$pass-refresh.log"
    p preview --expect-no-changes --non-interactive > "$log/cold-$pass-preview.log"
    if [[ $pass == first ]]; then
        control http-inject; control http-witness > "$log/http-before"
        if TRAEFIK_ACCEPTANCE_PHASE=withdraw-udp up > "$log/http-refusal" 2>&1; then exit 1; fi
        grep -Fq 'cannot establish that the dynamic rollback file represents the running graph' "$log/http-refusal"
        control http-witness > "$log/http-after"; cmp "$log/http-before" "$log/http-after"; control http-restore
        control nojob-arm
        if TRAEFIK_ACCEPTANCE_PHASE=withdraw-udp up > "$log/nojob-refusal" 2>&1; then exit 1; fi
        grep -Fq 'rollback sample=stopped; no automatic stop, restore or journal retirement' "$log/nojob-refusal"
        control nojob-assert > "$log/nojob-live"
    else
        control race-arm
        if TRAEFIK_ACCEPTANCE_PHASE=withdraw-udp up > "$log/independent-refusal" 2>&1; then exit 1; fi
        grep -Fq 'service invocation changed since admission' "$log/independent-refusal"
        control race-assert
    fi
    stores > "$s/$pass-before-delete.txt"
    TRAEFIK_ACCEPTANCE_PHASE=delete up > "$log/cold-$pass-delete.log" 2>&1
    stores > "$s/$pass-after-delete.txt"; cmp "$s/$pass-before-delete.txt" "$s/$pass-after-delete.txt"
    remote "set -eu; test ! -e /usr/local/libexec/keroosha-iac/traefik; test ! -e /etc/keroosha-iac/traefik; echo '$sha  $cache' |sha256sum -c -"
done
cmp "$s/first-after-delete.txt" "$s/recreated-before-delete.txt"
