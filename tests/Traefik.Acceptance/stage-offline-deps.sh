#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
manifest="$script_dir/offline-deps.manifest"
image_name=debian-13-generic-amd64-20261123-2671.qcow2
image_sha512=562a4614952657a6ab8a89cda56eaf1bc85c8dfea51155184267bb6b6361eff215baf6afa2f8c2c8c2bad328ac6c30eead80664286ef4c8538368aeb7f87104f
snapshot=20261123T000000Z
oci_index=sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
oci_amd64_manifest=sha256:ab3b3c8c5159eebfca4376430132d53c4d425f869c765ecbe47177a030da575d
main_signer=04B54C3CDCA79751B16BC6B5225629DF75B188BD
security_signer=5E04A1E3223A19A20706E20F9904613D4CCE68C6

usage() {
    printf 'Usage: %s STATE_DIR\n' "$0" >&2
    exit 2
}
fail() {
    printf 'Offline dependency staging failed: %s\n' "$1" >&2
    exit 1
}
require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required host command: $1"
}

[[ $# == 1 ]] || usage
[[ $EUID -ne 0 ]] || fail 'run as an unprivileged workstation user, never root'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'requires a Linux x86_64 workstation'
for command in sha256sum sha512sum realpath mktemp stat cp mkdir awk grep; do
    require_command "$command"
done
[[ -f "$manifest" && ! -L "$manifest" ]] || fail 'pinned offline dependency manifest is missing or unsafe'
[[ -d "$1" && ! -L "$1" ]] || fail 'STATE_DIR must be a real directory, not a symlink'
state_dir=$(realpath -e -- "$1") || fail 'STATE_DIR does not exist'
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) fail 'STATE_DIR is outside the private acceptance state root' ;;
esac
[[ -f "$state_dir/.owner" && ! -L "$state_dir/.owner" && -O "$state_dir/.owner" && -O "$state_dir" ]] || fail 'STATE_DIR has no private regular ownership marker'
[[ "$(stat -c '%a' -- "$state_dir")" == 700 ]] || fail 'STATE_DIR must be private (mode 0700)'
[[ "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || fail 'STATE_DIR ownership marker does not match'
[[ -f "$state_dir/$image_name" && ! -L "$state_dir/$image_name" ]] || fail "pinned Debian 13 image must already be staged as $image_name"
printf '%s  %s\n' "$image_sha512" "$state_dir/$image_name" | sha512sum --check --status || fail 'staged VM image does not match the pinned Debian 13 amd64 image'

output="$state_dir/offline-deps"
[[ ! -e "$output" && ! -L "$output" ]] || fail 'offline-deps already exists; refusing to overwrite private staged state'
cache_dir=${DOROTHY_ACCEPTANCE_DEB_CACHE:-}
if [[ -n "$cache_dir" ]]; then
    [[ -d "$cache_dir" && ! -L "$cache_dir" ]] || fail 'DOROTHY_ACCEPTANCE_DEB_CACHE must be a read-only real directory'
    cache_dir=$(realpath -e -- "$cache_dir") || fail 'could not resolve DOROTHY_ACCEPTANCE_DEB_CACHE'
else
    for command in curl gpg gpgv; do
        require_command "$command"
    done
fi

work=$(mktemp -d "$state_dir/.offline-deps-staging.XXXXXXXX") || fail 'could not create private staging workspace'
chmod 700 "$work"
cleanup() {
    status=$?
    [[ -z "${work:-}" || ! -d "$work" ]] || rm -rf -- "$work" || true
    if (( status != 0 )); then
        printf 'No VM-side package installation was attempted; staging workspace removed.\n' >&2
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

result="$work/offline-deps"
mkdir -m 700 "$work/downloads" "$work/gpg-home" "$result" "$result/repo" "$result/repo/pool"
chmod 700 "$work/gpg-home"
cp -- "$manifest" "$result/manifest.tsv"

declare -A seen_files seen_packages seen_releases
package_rows=()
package_count=0
image_count=0
bootstrap_count=0
while IFS=$'\t' read -r kind field1 field2 field3 field4 field5 field6 field7 field8; do
    [[ -n "$kind" ]] || continue
    [[ "$kind" == \#* ]] && continue
    case "$kind" in
        image)
            ((image_count == 0)) || fail 'manifest repeats its pinned VM image'
            [[ "$field1" == "$image_name" && "$field2" == "$image_sha512" ]] || fail 'manifest VM image does not match the pinned Debian 13 image'
            image_count=1
            ;;
        bootstrap)
            ((bootstrap_count == 0)) || fail 'manifest repeats its bootstrap image'
            [[ "$field1" == docker.io/library/debian && "$field2" == "$oci_index" && "$field3" == "$oci_amd64_manifest" ]] || fail 'manifest bootstrap identity is not the pinned Debian 13 amd64 rootfs'
            bootstrap_count=1
            ;;
        release)
            archive=$field1
            release_snapshot=$field2
            release_hash=$field3
            release_signer=$field4
            [[ "$release_snapshot" == "$snapshot" && "$release_hash" =~ ^[0-9a-f]{64}$ ]] || fail "invalid pinned $archive release record"
            case "$archive" in
                debian) expected_signer=$main_signer ;;
                debian-security) expected_signer=$security_signer ;;
                *) fail "unexpected Debian archive: $archive" ;;
            esac
            [[ "$release_signer" == "$expected_signer" && -z "${seen_releases[$archive]+x}" ]] || fail "invalid or duplicate $archive release signer"
            seen_releases[$archive]=1
            ;;
        package)
            [[ "$field1" == archive ]] && continue
            archive=$field1
            pool_path=$field2
            package=$field3
            version=$field4
            architecture=$field5
            size=$field6
            sha256=$field7
            filename=$field8
            [[ "$archive" == debian || "$archive" == debian-security ]] || fail "invalid package archive for $package"
            [[ "$pool_path" =~ ^pool/[A-Za-z0-9._+:%~/-]+$ && "/$pool_path/" != *"/../"* ]] || fail "unsafe Debian pool path for $package"
            [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || fail "invalid Debian package name: $package"
            [[ "$version" =~ ^[A-Za-z0-9.+:~_-]+$ ]] || fail "invalid Debian package version: $package"
            [[ "$architecture" == amd64 || "$architecture" == all ]] || fail "non-amd64 package in closure: $package"
            [[ "$size" =~ ^[1-9][0-9]*$ && "$sha256" =~ ^[0-9a-f]{64}$ ]] || fail "invalid package size or digest: $package"
            [[ "$filename" =~ ^[A-Za-z0-9._+:%~-]+\.deb$ && -z "${seen_files[$filename]+x}" ]] || fail "invalid or duplicate package archive filename: $filename"
            [[ -z "${seen_packages[$package]+x}" ]] || fail "duplicate package identity in manifest: $package"
            seen_files[$filename]=1
            seen_packages[$package]=1
            package_rows+=( "$archive"$'\t'"$pool_path"$'\t'"$package"$'\t'"$version"$'\t'"$architecture"$'\t'"$size"$'\t'"$sha256"$'\t'"$filename" )
            package_count=$((package_count + 1))
            ;;
        *) fail "unexpected offline manifest record: $kind" ;;
    esac
done < "$manifest"
(( image_count == 1 && bootstrap_count == 1 && package_count == 109 && ${#seen_releases[@]} == 2 )) || fail 'offline dependency manifest is incomplete'
for package in bind9 bind9-utils ca-certificates curl dnsutils jq nginx openssl socat netcat-openbsd iproute2 tcpdump coreutils perl; do
    if [[ -z "${seen_packages[$package]+x}" ]]; then
        [[ "$package" == dnsutils && -n "${seen_packages[bind9-dnsutils]+x}" ]] || fail "dependency manifest omitted requested package: $package"
    fi
done

if [[ -z "$cache_dir" ]]; then
    fetch_key() {
        local archive=$1 signer=$2 key_url=$3 key_file=$4 keyring=$5 fingerprint
        curl --fail --location --silent --show-error --retry 3 --proto '=https' --tlsv1.2 "$key_url" -o "$key_file" || fail "could not fetch the official $archive archive key"
        fingerprint=$(gpg --batch --no-options --show-keys --with-colons "$key_file" | awk -F: '$1 == "fpr" { print $10; exit }')
        [[ "$fingerprint" == "$signer" ]] || fail "official $archive key fingerprint did not match the pinned rootfs key"
        gpg --batch --no-options --yes --homedir "$work/gpg-home" --dearmor --output "$keyring" "$key_file" || fail "could not prepare the official $archive keyring"
    }
    verify_release() {
        local archive=$1 suite=$2 signer=$3 release_hash=$4 keyring=$5 inrelease status_file gpg_log
        inrelease="$work/downloads/$archive-InRelease"
        status_file="$work/downloads/$archive-gpg-status"
        gpg_log="$work/downloads/$archive-gpgv.log"
        curl --fail --location --silent --show-error --retry 3 --proto '=https' --tlsv1.2 \
            "https://snapshot.debian.org/archive/$archive/$snapshot/dists/$suite/InRelease" -o "$inrelease" || fail "could not fetch signed Debian $archive metadata"
        printf '%s  %s\n' "$release_hash" "$inrelease" | sha256sum --check --status || fail "Debian $archive InRelease digest mismatch"
        set +e
        gpgv --status-fd=1 --keyring "$keyring" "$inrelease" > "$status_file" 2> "$gpg_log"
        set -e
        if ! awk -v expected="$signer" '
            /^\[GNUPG:\] (BADSIG|EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|KEYEXPIRED|SIGEXPIRED|NODATA|FAILURE|ERROR)( |$)/ { bad=1 }
            /^\[GNUPG:\] VALIDSIG / && (toupper($3) == expected || toupper($NF) == expected) { valid=1 }
            END { exit !(valid && !bad) }
        ' "$status_file"; then
            cat "$gpg_log" >&2
            fail "Debian $archive InRelease did not authenticate with its pinned Trixie key"
        fi
    }
    fetch_key debian "$main_signer" https://ftp-master.debian.org/keys/archive-key-13.asc "$work/downloads/debian-archive-key.asc" "$work/downloads/debian-archive-key.gpg"
    fetch_key debian-security "$security_signer" https://ftp-master.debian.org/keys/archive-key-13-security.asc "$work/downloads/debian-security-archive-key.asc" "$work/downloads/debian-security-archive-key.gpg"
    while IFS=$'\t' read -r kind archive release_snapshot release_hash release_signer _; do
        [[ "$kind" == release ]] || continue
        case "$archive" in
            debian) verify_release "$archive" trixie "$release_signer" "$release_hash" "$work/downloads/debian-archive-key.gpg" ;;
            debian-security) verify_release "$archive" trixie-security "$release_signer" "$release_hash" "$work/downloads/debian-security-archive-key.gpg" ;;
        esac
    done < "$manifest"
fi

for row in "${package_rows[@]}"; do
    IFS=$'\t' read -r archive pool_path package version architecture size sha256 filename <<< "$row"
    destination="$result/repo/pool/$filename"
    if [[ -n "$cache_dir" ]]; then
        cached_file="$cache_dir/$filename"
        [[ -f "$cached_file" && ! -L "$cached_file" ]] || fail "preverified package cache is missing $filename; network fallback is disabled"
        cp -- "$cached_file" "$destination"
    else
        url="https://snapshot.debian.org/archive/$archive/$snapshot/$pool_path"
        curl --fail --location --silent --show-error --retry 3 --proto '=https' --tlsv1.2 "$url" -o "$destination" || fail "could not fetch pinned package $package"
    fi
    [[ "$(stat -c '%s' -- "$destination")" == "$size" ]] || fail "package size mismatch for $package"
    printf '%s  %s\n' "$sha256" "$destination" | sha256sum --check --status || fail "package digest mismatch for $package"
done

(
    cd "$result"
    sha256sum manifest.tsv > SHA256SUMS
    for row in "${package_rows[@]}"; do
        IFS=$'\t' read -r _ _ _ _ _ _ _ filename <<< "$row"
        sha256sum "repo/pool/$filename" >> SHA256SUMS
    done
)
sums_hash=$(sha256sum "$result/SHA256SUMS")
sums_hash=${sums_hash%% *}
printf 'dorothy-offline-deps-ready-v1\n%s\n' "$sums_hash" > "$result/.ready"
chmod -R go-rwx "$result"
mv -- "$result" "$output"
printf 'Staged %d pinned Debian 13 packages in %s%s\n' "$package_count" "$output" \
    "$([[ -n "$cache_dir" ]] && printf ' (read-only offline cache)' || true)"
