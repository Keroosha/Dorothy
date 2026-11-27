#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# < 2 || $# > 3 )); then
    printf 'Usage: %s /tmp/dorothy-traefik-acceptance.XXXXXXXX <candidate-provider-directory> [full|sni-proof-only|resume-after-sni]\nSet TRAEFIK_ACCEPTANCE_EXPECTED_HELPER_SHA256 to pin the optional helper digest; TRAEFIK_ACCEPTANCE_RESOLVER_EPOCH defaults to v2.\n' "$0" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(realpath -e -- "$script_dir/../..")
state_dir=$(realpath -e -- "$1")
provider_dir=$(realpath -e -- "$2")
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to run outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" && "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || {
    printf 'Private acceptance ownership marker is missing.\n' >&2
    exit 2
}
[[ -f "$state_dir/legacy-checkpoint.json" && -s "$state_dir/legacy-resource-id.txt" ]] || {
    printf 'The frozen-base legacy checkpoint has not been created.\n' >&2
    exit 2
}
[[ -x "$provider_dir/pulumi-resource-keroosha" && -x "$provider_dir/helper/linux-x64/keroosha-iac-helper" ]] || {
    printf 'Candidate provider directory is missing its provider or linux-x64 native helper.\n' >&2
    exit 2
}
mkdir -m 700 -p "$state_dir/logs"
if ! bash "$script_dir/guest-barrier-check.sh" acceptance "$state_dir" \
    > "$state_dir/logs/guest-barrier-acceptance.log" 2>&1; then
    printf 'Guest isolation barrier acceptance failed; see %s/logs/guest-barrier-acceptance.log\n' "$state_dir" >&2
    exit 1
fi
barrier_receipt="$state_dir/barrier-receipt.json"
barrier_authorization="$state_dir/barrier-authorization.json"
for barrier_marker in "$barrier_receipt" "$barrier_authorization"; do
    [[ -f "$barrier_marker" && ! -L "$barrier_marker" && -s "$barrier_marker" \
        && "$(stat -c %a "$barrier_marker")" == 600 && "$(stat -c %u "$barrier_marker")" == "$(id -u)" ]] || {
        printf 'The fresh guest barrier receipt or separate authorization marker is missing or unsafe.\n' >&2
        exit 1
    }
done
source "$state_dir/handle.env"
[[ "$GUEST_ROOT" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]] || {
    printf 'Guest fixture path is not the private acceptance root.\n' >&2
    exit 2
}
run_mode=${3:-full}
case "$run_mode" in
    full|sni-proof-only|resume-after-sni) ;;
    *) printf 'Unknown acceptance mode.\n' >&2; exit 2 ;;
esac
unset TRAEFIK_ACCEPTANCE_LOG_LEVEL
resolver_epoch=${TRAEFIK_ACCEPTANCE_RESOLVER_EPOCH:-v2}
export TRAEFIK_ACCEPTANCE_RESOLVER_EPOCH="$resolver_epoch"
actual_helper_sha=$(sha256sum "$provider_dir/helper/linux-x64/keroosha-iac-helper" | awk '{print $1}')
[[ "$actual_helper_sha" =~ ^[a-f0-9]{64}$ ]] || {
    printf 'Candidate helper digest could not be computed.\n' >&2
    exit 2
}
expected_helper_sha=${TRAEFIK_ACCEPTANCE_EXPECTED_HELPER_SHA256:-}
if [[ -n "$expected_helper_sha" ]]; then
    [[ "$expected_helper_sha" =~ ^[a-f0-9]{64}$ ]] || {
        printf 'Expected helper SHA256 must be 64 lowercase hexadecimal characters.\n' >&2
        exit 2
    }
    [[ "$actual_helper_sha" == "$expected_helper_sha" ]] || {
        printf 'Candidate NativeAOT helper does not match TRAEFIK_ACCEPTANCE_EXPECTED_HELPER_SHA256.\n' >&2
        exit 2
    }
fi
for command in dotnet pulumi jq sha256sum scp ssh openssl mktemp ln git tr install awk find realpath stat id; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done
git -C "$repo_root" rev-parse HEAD > "$state_dir/git-head-before.txt"
chmod 600 "$state_dir/git-head-before.txt"
if [[ "$run_mode" != sni-proof-only ]]; then
    [[ -f "$UPSTREAM_CA_FILE" && -f "$CLIENT_CA_FILE" && -s "$DNS_TSIG_SECRET_FILE" ]] || {
        printf 'Private protocol and credential fixtures are incomplete.\n' >&2
        exit 2
    }
fi
[[ -s "$state_dir/legacy-example.pem" && -s "$state_dir/legacy-example.key" ]] || {
    printf 'The frozen legacy certificate fixtures are missing.\n' >&2
    exit 2
}
if [[ ! -s "$state_dir/sni-proof.pem" || ! -s "$state_dir/sni-proof.key" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$state_dir/sni-proof.key" -out "$state_dir/sni-proof.pem" \
        -subj '/CN=sni-proof.acceptance.test' -days 365 \
        -addext 'basicConstraints=critical,CA:FALSE' \
        -addext 'keyUsage=critical,digitalSignature' \
        -addext 'extendedKeyUsage=serverAuth' \
        -addext 'subjectAltName=DNS:sni-proof.acceptance.test' \
        > "$state_dir/logs/sni-certificate-generation.log" 2>&1
fi
chmod 600 "$state_dir/sni-proof.pem" "$state_dir/sni-proof.key"
openssl x509 -in "$state_dir/sni-proof.pem" -noout -checkhost sni-proof.acceptance.test \
    > "$state_dir/logs/sni-certificate-san.log" 2>&1

mkdir -m 700 -p "$state_dir/logs" "$state_dir/home" "$state_dir/dotnet-home" "$state_dir/nuget-packages" "$state_dir/candidate-program"
chmod 700 "$state_dir/logs" "$state_dir/home" "$state_dir/dotnet-home" "$state_dir/nuget-packages" "$state_dir/candidate-program"
guest_process_snapshot_file="$state_dir/logs/guest-traefik-process-snapshot-$run_mode.log"
[[ ! -e "$guest_process_snapshot_file" && ! -L "$guest_process_snapshot_file" ]] || {
    printf 'Refusing to overwrite the private Traefik process snapshot.\n' >&2
    exit 2
}
: > "$guest_process_snapshot_file"
chmod 600 "$guest_process_snapshot_file"
guest_process_snapshot_count=0
guest_mainpid_cmdline_snapshot_count=0
traefik_pid_before_delete=
helper_evidence="$state_dir/candidate-helper-$run_mode.sha256"
if [[ -e "$helper_evidence" || -L "$helper_evidence" ]]; then
    [[ "$(<"$helper_evidence")" == "$actual_helper_sha" ]] || {
        printf 'Candidate helper digest changed since the first %s run.\n' "$run_mode" >&2
        exit 2
    }
else
    (umask 077; printf '%s\n' "$actual_helper_sha" > "$helper_evidence")
fi
candidate_source="$state_dir/candidate-source"
if [[ -e "$candidate_source" ]]; then
    [[ -d "$candidate_source" && -f "$candidate_source/.owner" && "$(<"$candidate_source/.owner")" == dorothy-traefik-candidate-source-v1 ]] || {
        printf 'An unmarked candidate source already occupies the private path.\n' >&2
        exit 2
    }
    rm -rf -- "$candidate_source"
fi
export HOME="$state_dir/home"
export DOTNET_CLI_HOME="$state_dir/dotnet-home"
export NUGET_PACKAGES="$state_dir/nuget-packages"
export NUGET_HTTP_CACHE_PATH="$state_dir/nuget-http" XDG_CACHE_HOME="$state_dir/cache"
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
export UPSTREAM_CA_FILE="$UPSTREAM_CA_FILE"
export CLIENT_CA_FILE="$CLIENT_CA_FILE"
export DNS_TSIG_SECRET_FILE="$DNS_TSIG_SECRET_FILE"
[[ -d "$state_dir/bin" && ! -L "$state_dir/bin" ]] || {
    printf 'Private SSH wrapper directory is missing or unsafe.\n' >&2
    exit 2
}
if [[ -e "$state_dir/bin/ssh" || -L "$state_dir/bin/ssh" ]]; then
    [[ -f "$state_dir/bin/ssh" && ! -L "$state_dir/bin/ssh" ]] || {
        printf 'Private SSH wrapper path is not a regular file.\n' >&2
        exit 2
    }
fi
install -m 700 "$script_dir/ssh-wrapper.sh" "$state_dir/bin/ssh"
ssh_argv_audit_file="$state_dir/ssh-argv-audit-$run_mode.counts"
[[ ! -e "$ssh_argv_audit_file" && ! -L "$ssh_argv_audit_file" ]] || {
    printf 'Refusing to overwrite private SSH argv audit counts.\n' >&2
    exit 2
}
: > "$ssh_argv_audit_file"
chmod 600 "$ssh_argv_audit_file"
export DOROTHY_ACCEPTANCE_DNS_TOKEN_FILES="$DNS_TSIG_SECRET_FILE:$state_dir/dns-tsig-secret-rotated"
export DOROTHY_ACCEPTANCE_SSH_AUDIT_FILE="$ssh_argv_audit_file"
export PATH="$state_dir/bin:$PATH"
mkdir -m 700 -p "$candidate_source"
git -C "$repo_root" archive "$(<"$state_dir/git-head-before.txt")" -- src/Dorothy.DSL tests/Traefik.Acceptance \
    | tar -x -C "$candidate_source"
printf '%s\n' dorothy-traefik-candidate-source-v1 > "$candidate_source/.owner"
chmod 600 "$candidate_source/.owner"
if ! dotnet publish "$candidate_source/tests/Traefik.Acceptance/Traefik.Acceptance.fsproj" \
    --configuration Release --output "$state_dir/candidate-program" \
    > "$state_dir/logs/candidate-program-publish.log" 2>&1; then
    printf 'Private candidate acceptance-program publish failed; see %s/logs/candidate-program-publish.log\n' "$state_dir" >&2
    exit 1
fi

remote() {
    [[ $# == 1 ]] || { printf 'Internal acceptance SSH call requires one fixed command.\n' >&2; return 2; }
    /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$1"
}
assert_guest_secret_isolation() {
    local credential_state=$1
    local snapshot_sequence
    guest_process_snapshot_count=$((guest_process_snapshot_count + 1))
    snapshot_sequence=$guest_process_snapshot_count

    case "$credential_state" in
        present)
            guest_mainpid_cmdline_snapshot_count=$((guest_mainpid_cmdline_snapshot_count + 1))
            if ! remote "set -eu
secret_file='$GUEST_ROOT/dns/tsig-secret'
credentials_file='/etc/keroosha-iac/traefik/dns-credentials.env'
[ -f \"\$secret_file\" ] || exit 20
pid=\$(systemctl show --property=MainPID --value keroosha-traefik.service)
[ \"\$pid\" -gt 0 ] 2>/dev/null || exit 29
cmdline_file=/proc/\$pid/cmdline
[ -r \"\$cmdline_file\" ] || exit 30
if grep -aFq -f \"\$secret_file\" \"\$cmdline_file\"; then exit 21; else code=\$?; [ \$code -eq 1 ] || exit 22; fi
for path in /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml /etc/systemd/system/keroosha-traefik.service; do
    [ -f \"\$path\" ] || exit 31
    if grep -aFq -f \"\$secret_file\" \"\$path\"; then exit 23; else code=\$?; [ \$code -eq 1 ] || exit 24; fi
done
grep -aFq -f \"\$secret_file\" \"\$credentials_file\" || exit 25
started=\$(systemctl show --property=ActiveEnterTimestamp --value keroosha-traefik.service)
[ -n \"\$started\" ] || exit 32
ended=\$(date --iso-8601=seconds)
journal=\$(journalctl --no-pager --unit=keroosha-traefik.service --since \"\$started\" --until \"\$ended\" --output=cat --lines=1000 2>/dev/null) || exit 26
if printf '%s\\n' \"\$journal\" | grep -aFq -f \"\$secret_file\"; then exit 27; else code=\$?; [ \$code -eq 1 ] || exit 28; fi
cmdline=\$(tr '\\000' ' ' < \"\$cmdline_file\")
journal_lines=\$(printf '%s' \"\$journal\" | awk 'END { print NR }')
journal_sha=\$(printf '%s' \"\$journal\" | sha256sum | awk '{print \$1}')
printf 'snapshot=%s\\ncredentialState=present\\nMainPID=%s\\ncmdline=%s\\njournalUnit=keroosha-traefik.service\\njournalSince=%s\\njournalUntil=%s\\njournalLines=%s\\njournalSha256=%s\\n' '$snapshot_sequence' \"\$pid\" \"\$cmdline\" \"\$started\" \"\$ended\" \"\$journal_lines\" \"\$journal_sha\"
for path in /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml /etc/systemd/system/keroosha-traefik.service; do
    printf 'file=%s ' \"\$path\"
    stat -c 'mode=%a uid=%u gid=%g size=%s mtime=%y' \"\$path\"
    sha256sum \"\$path\"
done
stat -c 'credentialEnvFile=present mode=%a uid=%u gid=%g size=%s mtime=%y' \"\$credentials_file\""
            then
                printf 'Guest secret hygiene check failed without exposing secret contents.\n' >&2
                return 1
            fi
            ;;
        absent)
            if ! remote "set -eu
credentials_file='/etc/keroosha-iac/traefik/dns-credentials.env'
pid=\$(systemctl show --property=MainPID --value keroosha-traefik.service)
[ "\$pid" = 0 ] || [ -z "\$pid" ] || exit 33
[ ! -e '/proc/$traefik_pid_before_delete' ] || exit 34
[ ! -e \"\$credentials_file\" ] || exit 35
printf 'snapshot=%s\\ncredentialState=absent\\nMainPID=%s\\npriorMainPIDAbsent=true\\ncredentialEnvFileAbsent=true\\n' '$snapshot_sequence' \"\$pid\""
            then
                printf 'Post-delete Traefik process or credential environment remained present.\n' >&2
                return 1
            fi
            ;;
        *)
            printf 'Invalid internal credential-state expectation.\n' >&2
            return 2
            ;;
    esac >> "$guest_process_snapshot_file"
}
assert_local_secret_absent() {
    local candidate secret_path file target duplicate grep_status audit_summary
    local -a secret_files=() scan_files=() checkpoint_files=()
    for candidate in "$DNS_TSIG_SECRET_FILE" "$state_dir"/dns-tsig-secret-*; do
        if [[ ! -e "$candidate" && ! -L "$candidate" ]]; then
            continue
        fi
        [[ -f "$candidate" && ! -L "$candidate" ]] || {
            printf 'A DNS credential fixture is not a regular private file.\n' >&2
            return 1
        }
        secret_path=$(realpath -e -- "$candidate") || return 1
        [[ "$secret_path" == "$state_dir"/* ]] || {
            printf 'DNS credential fixtures are outside the owned acceptance state.\n' >&2
            return 1
        }
        duplicate=false
        for file in "${secret_files[@]}"; do
            [[ "$file" == "$secret_path" ]] && duplicate=true
        done
        [[ "$duplicate" == true ]] || secret_files+=("$secret_path")
    done
    ((${#secret_files[@]} > 0)) || {
        printf 'No owned DNS credential fixture was available for secret checks.\n' >&2
        return 1
    }

    for target in "$state_dir/backend" "$state_dir/pulumi-project" "$state_dir/logs"; do
        [[ -d "$target" && ! -L "$target" ]] || {
            printf 'An exposed Pulumi or harness artifact directory is missing or unsafe.\n' >&2
            return 1
        }
        while IFS= read -r -d '' file; do
            scan_files+=("$file")
        done < <(find "$target" -type f -print0)
    done
    shopt -s nullglob
    checkpoint_files=("$state_dir"/*checkpoint*.json)
    shopt -u nullglob
    for file in "${checkpoint_files[@]}"; do
        [[ -f "$file" && ! -L "$file" ]] || {
            printf 'A Pulumi checkpoint path is not a regular file.\n' >&2
            return 1
        }
        scan_files+=("$file")
    done
    local -a audited_artifacts=("$state_dir/barrier-receipt.json" "$state_dir/barrier-authorization.json")
    if [[ ${1:-final} == final ]]; then audited_artifacts+=("$state_dir/post-reboot-journal-window.json"); fi
    for file in "${audited_artifacts[@]}"; do
        [[ -f "$file" && ! -L "$file" ]] || {
            printf 'An exposed guest-barrier or journal-window artifact is missing or unsafe.\n' >&2
            return 1
        }
        scan_files+=("$file")
    done
    [[ -f "$ssh_argv_audit_file" && ! -L "$ssh_argv_audit_file" ]] || {
        printf 'The private SSH argv audit counts are missing or unsafe.\n' >&2
        return 1
    }
    scan_files+=("$ssh_argv_audit_file")
    for file in "${scan_files[@]}"; do
        for secret_path in "${secret_files[@]}"; do
            if grep -aFq -f "$secret_path" "$file"; then
                printf 'DNS TSIG plaintext was found in an exposed Pulumi/project/log artifact: %s\n' "${file##*/}" >&2
                return 1
            else
                grep_status=$?
                [[ "$grep_status" == 1 ]] || {
                    printf 'Could not inspect an exposed Pulumi/project/log artifact.\n' >&2
                    return 1
                }
            fi
        done
    done

    audit_summary=$(awk '
        {
            if (NF != 3 || split($1, a, "=") != 2 || split($2, t, "=") != 2 || split($3, c, "=") != 2 ||
                a[1] != "argv" || t[1] != "tokens" || c[1] != "comparisons" ||
                a[2] !~ /^[0-9]+$/ || t[2] !~ /^[0-9]+$/ || c[2] !~ /^[0-9]+$/ ||
                a[2] < 1 || t[2] < 1 || c[2] != a[2] * t[2]) {
                invalid = 1
                next
            }
            invocations++
            argv += a[2]
            tokens += t[2]
            comparisons += c[2]
        }
        END {
            if (NR == 0 || invalid || invocations == 0) exit 1
            printf "%d %d %d %d\n", invocations, argv, tokens, comparisons
        }
    ' "$ssh_argv_audit_file") || {
        printf 'SSH argv audit counts are malformed or incomplete.\n' >&2
        return 1
    }
    read -r ssh_argv_audit_invocations ssh_argv_audit_entries ssh_argv_audit_tokens ssh_argv_audit_comparisons \
        <<< "$audit_summary"
}
copy_to_guest() {
    local source_path=$1 remote_path=$2 log_path=$3
    [[ -f "$source_path" && ! -L "$source_path" ]] || {
        printf 'Refusing to copy a missing or unsafe acceptance fixture.\n' >&2
        return 1
    }
    if ! scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$source_path" "$SSH_USER@$SSH_HOST:$remote_path" \
        > "$log_path" 2>&1; then
        printf 'SCP upload failed; see %s\n' "$log_path" >&2
        return 1
    fi
}
copy_from_guest() {
    local remote_path=$1 destination=$2 log_path=$3
    [[ ! -e "$destination" && ! -L "$destination" ]] || {
        printf 'Refusing to overwrite private acceptance evidence: %s\n' "$destination" >&2
        return 1
    }
    if ! scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$SSH_USER@$SSH_HOST:$remote_path" "$destination" \
        > "$log_path" 2>&1; then
        rm -f -- "$destination"
        printf 'SCP download failed; see %s\n' "$log_path" >&2
        return 1
    fi
    chmod 600 "$destination"
}
remote_systemctl_is_active() {
    local result marker
    if ! result=$(remote 'set +e; state=$(systemctl is-active keroosha-traefik.service 2>&1); code=$?; printf "%s\n__DOROTHY_SYSTEMCTL_EXIT__=%s\n" "$state" "$code"; exit 0'); then
        return 1
    fi
    marker=${result##*$'\n'}
    [[ "$marker" =~ ^__DOROTHY_SYSTEMCTL_EXIT__=(0|3|4)$ ]] || return 1
    REMOTE_SYSTEMCTL_STATE=${result%$'\n'*}
    REMOTE_SYSTEMCTL_EXIT=${marker#*=}
    [[ "$REMOTE_SYSTEMCTL_STATE" == active && "$REMOTE_SYSTEMCTL_EXIT" == 0 \
       || "$REMOTE_SYSTEMCTL_STATE" == inactive && "$REMOTE_SYSTEMCTL_EXIT" == 3 \
       || "$REMOTE_SYSTEMCTL_STATE" == unknown && "$REMOTE_SYSTEMCTL_EXIT" == 4 ]]
}
review_interposer_active=0
foreign_owner_marker_active=0
foreign_owner_backup="$GUEST_ROOT/logs/foreign-owner-original.marker"
restore_foreign_owner_marker() {
    [[ "$foreign_owner_marker_active" == 1 ]] || return 0
    if ! remote "if [ -e '$foreign_owner_backup' ]; then [ -f '$foreign_owner_backup' ] && [ ! -L '$foreign_owner_backup' ] || exit 31; cp --preserve=mode,ownership,timestamps '$foreign_owner_backup' /etc/keroosha-iac/traefik/.keroosha-owner && rm -f -- '$foreign_owner_backup' || exit 32; fi; exit 0"; then
        return 1
    fi
    foreign_owner_marker_active=0
}
cleanup_acceptance_mutations() {
    local status=$?
    trap - EXIT
    if [[ "$review_interposer_active" == 1 ]] \
       && ! remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-remove '$GUEST_ROOT'"; then
        printf 'Could not remove the private systemctl interposer from the disposable guest.\n' >&2
        status=1
    fi
    if ! restore_foreign_owner_marker; then
        printf 'Could not restore the owned guest marker; preserve the disposable guest for recovery.\n' >&2
        status=1
    fi
    exit "$status"
}
trap cleanup_acceptance_mutations EXIT
copy_to_guest "$state_dir/sni-proof.pem" "$GUEST_ROOT/certs/sni-proof.pem" \
    "$state_dir/logs/sni-proof-certificate-copy.log"
remote "chmod 644 '$GUEST_ROOT/certs/sni-proof.pem'" \
    > "$state_dir/logs/sni-proof-certificate-mode.log" 2>&1
copied_sni_certificate_sha=$(remote "sha256sum '$GUEST_ROOT/certs/sni-proof.pem'" | awk '{print $1}')
[[ "$copied_sni_certificate_sha" == "$(sha256sum "$state_dir/sni-proof.pem" | awk '{print $1}')" ]] || {
    printf 'Guest SNI certificate copy does not match the host fixture.\n' >&2
    exit 1
}

pulumi_project="$state_dir/pulumi-project"
[[ -d "$pulumi_project" && -f "$pulumi_project/Pulumi.acceptance.yaml" ]] || {
    printf 'Private Pulumi project state from the legacy bootstrap is missing.\n' >&2
    exit 2
}
cat > "$pulumi_project/Pulumi.yaml" <<EOF
name: traefik-acceptance
runtime:
  name: dotnet
  options:
    binary: $state_dir/candidate-program/Traefik.Acceptance.dll
description: Private real-VM Traefik lifecycle acceptance
EOF
chmod 600 "$pulumi_project/Pulumi.yaml"

if ! pulumi plugin install resource keroosha 0.1.0 --file "$provider_dir" --reinstall \
    > "$state_dir/logs/candidate-plugin-install.log" 2>&1; then
    printf 'Candidate provider plugin install failed; see %s/logs/candidate-plugin-install.log\n' "$state_dir" >&2
    exit 1
fi
if ! pulumi login "file://$state_dir/backend" --non-interactive \
    > "$state_dir/logs/candidate-pulumi-login.log" 2>&1; then
    printf 'Private Pulumi file-backend login failed; see %s/logs/candidate-pulumi-login.log\n' "$state_dir" >&2
    exit 1
fi

run_pulumi() {
    local phase=$1
    local log_name=$2
    shift 2
    if ! (cd "$pulumi_project" && TRAEFIK_ACCEPTANCE_PHASE="$phase" pulumi "$@") \
        > "$state_dir/logs/$log_name" 2>&1; then
        printf 'Pulumi command failed; see %s/logs/%s\n' "$state_dir" "$log_name" >&2
        return 1
    fi
}

expect_pulumi_failure() {
    local phase=$1
    local log_name=$2
    shift 2
    if (cd "$pulumi_project" && TRAEFIK_ACCEPTANCE_PHASE="$phase" pulumi "$@") \
        > "$state_dir/logs/$log_name" 2>&1; then
        printf 'The invalid runtime candidate unexpectedly succeeded.\n' >&2
        return 1
    fi
}

traefik_query='[.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))]'
resource_id() {
    jq -r "$traefik_query | if length == 1 then .[0].id else empty end" "$1"
}
resource_urn() {
    jq -r "$traefik_query | if length == 1 then .[0].urn else empty end" "$1"
}
export_checkpoint() {
    local destination=$1
    local export_log="$state_dir/logs/checkpoint-export-${destination##*/}.log"
    local temporary
    [[ ! -e "$destination" && ! -L "$destination" ]] || {
        printf 'Refusing to overwrite existing Pulumi checkpoint: %s\n' "$destination" >&2
        return 1
    }
    temporary=$(mktemp "${destination}.tmp.XXXXXXXX") || return 1
    if ! (cd "$pulumi_project" && pulumi stack export --stack acceptance) > "$temporary" 2> "$export_log"; then
        rm -f -- "$temporary"
        printf 'Pulumi checkpoint export failed; see %s\n' "$export_log" >&2
        return 1
    fi
    chmod 600 "$temporary"
    if ! ln -- "$temporary" "$destination"; then
        rm -f -- "$temporary"
        printf 'Could not preserve exported Pulumi checkpoint at %s\n' "$destination" >&2
        return 1
    fi
    rm -- "$temporary"
}
assert_secret_checkpoint() {
    local checkpoint=$1 secret_file=${2:-$DNS_TSIG_SECRET_FILE}
    local candidate secret_path existing duplicate=false grep_status
    local -a secret_files=()
    jq -e --arg expectedUrn "$legacy_urn" '
        def pulumiSecretEnvelope:
            type == "object"
            and .["4dabf18193072939515e22adb298388d"] == "1b47061264138c4ac30d75fd1eb44270"
            and (.ciphertext | type == "string" and length > 0);
        [
            .deployment.resources[]
            | select(.type == "keroosha:debian:Traefik" and .urn == $expectedUrn)
            | {input:.inputs.configuration, output:.outputs.configuration}
        ] as $matches
        | ($matches | length) == 1
          and ($matches[0].input | pulumiSecretEnvelope)
          and ($matches[0].output | pulumiSecretEnvelope)
    ' "$checkpoint" >/dev/null || {
        printf 'Traefik configuration input/output are not stored as Pulumi ciphertext envelopes.\n' >&2
        return 1
    }
    for candidate in "$DNS_TSIG_SECRET_FILE" "$state_dir"/dns-tsig-secret-* "$secret_file"; do
        if [[ ! -e "$candidate" && ! -L "$candidate" ]]; then
            continue
        fi
        [[ -n "$candidate" && -f "$candidate" && ! -L "$candidate" ]] || {
            printf 'A DNS credential fixture is not a regular private file.\n' >&2
            return 1
        }
        candidate=$(realpath -e -- "$candidate") || return 1
        [[ "$candidate" == "$state_dir"/* ]] || {
            printf 'DNS credential fixture is outside the owned acceptance state.\n' >&2
            return 1
        }
        duplicate=false
        for existing in "${secret_files[@]}"; do
            [[ "$existing" == "$candidate" ]] && duplicate=true
        done
        [[ "$duplicate" == true ]] || secret_files+=("$candidate")
    done
    ((${#secret_files[@]} > 0)) || {
        printf 'No owned DNS credential fixture was available for checkpoint checks.\n' >&2
        return 1
    }
    for secret_path in "${secret_files[@]}"; do
        if grep -aFq -f "$secret_path" "$checkpoint"; then
            printf 'Pulumi checkpoint contains DNS TSIG plaintext.\n' >&2
            return 1
        else
            grep_status=$?
            [[ "$grep_status" == 1 ]] || {
                printf 'Could not inspect Pulumi checkpoint secret storage.\n' >&2
                return 1
            }
        fi
    done
}
secret_value_sha() {
    tr -d '\r\n' < "$1" | sha256sum | awk '{print $1}'
}
assert_read_checkpoint() {
    local checkpoint=$1 expected_sync=$2 description=$3
    jq -e --arg expectedSync "$expected_sync" '
        [.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))]
        | length == 1
          and .[0].outputs.inSync == ($expectedSync == "true")
          and (.[0].outputs.tlsProbeSummary | type == "object")
          and (.[0].outputs.tlsProbeSummary.legacyProbesAttempted | type == "number" and . >= 0 and floor == .)
          and (.[0].outputs.tlsProbeSummary.nativeProbesAttempted | type == "number" and . >= 0 and floor == .)
          and (.[0].outputs.tlsProbeSummary.unprobedCount | type == "number" and . >= 0 and floor == .)
          and (.[0].outputs.tlsProbeSummary.opaqueRouterCount | type == "number" and . >= 0 and floor == .)
          and (.[0].outputs.tlsProbeSummary.truncated | type == "number" and (. == 0 or . == 1))
    ' "$checkpoint" >/dev/null || {
        printf '%s checkpoint has an unexpected Read result or incomplete TLS probe counts.\n' "$description" >&2
        return 1
    }
}
assert_checkpoint() {
    local checkpoint=$1
    local description=$2
    local require_configuration=$3
    [[ "$(resource_id "$checkpoint")" == "$legacy_id" ]] || {
        printf '%s changed the logical Traefik resource ID.\n' "$description" >&2
        return 1
    }
    [[ "$(resource_urn "$checkpoint")" == "$legacy_urn" ]] || {
        printf '%s changed the Traefik resource URN.\n' "$description" >&2
        return 1
    }
    if [[ "$require_configuration" == true ]]; then
        jq -e "$traefik_query[0].inputs | has(\"configuration\")" "$checkpoint" > /dev/null || {
            printf '%s checkpoint does not contain native configuration.\n' "$description" >&2
            return 1
        }
    fi
}
run_review_command() {
    local phase=$1 log_name=$2 pulumi_command=$3
    shift 3
    case "$phase" in
        review-tls-mtls|review-tls-issuer-switch) ;;
        *) printf 'Unsupported internal reviewed acceptance phase.\n' >&2; return 2 ;;
    esac
    case "$pulumi_command" in
        up|refresh) ;;
        *) printf 'Unsupported internal reviewed Pulumi command.\n' >&2; return 2 ;;
    esac
    if ! bash "$script_dir/review/run-review.sh" "$state_dir" "$provider_dir" \
        "$phase" "$pulumi_command" "$@" > "$state_dir/logs/$log_name" 2>&1; then
        printf 'Reviewed Pulumi phase failed; see %s/logs/%s\n' "$state_dir" "$log_name" >&2
        return 1
    fi
}
run_review_tls_coverage() {
    local missing_unprobed incomplete_unprobed
    copy_to_guest "$script_dir/review-tls.sh" "$GUEST_ROOT/review-tls.sh" \
        "$state_dir/logs/review-tls-script-copy.log"
    remote "chmod 700 '$GUEST_ROOT/review-tls.sh'" \
        > "$state_dir/logs/review-tls-script-install.log" 2>&1
    run_review_command review-tls-mtls review-tls-mtls-up.log up --yes --skip-preview --parallel 1
    remote "bash '$GUEST_ROOT/review-tls.sh' snapshot '$GUEST_ROOT'" \
        > "$state_dir/logs/review-tls-snapshot.log" 2>&1

    remote "bash '$GUEST_ROOT/review-tls.sh' remove '$GUEST_ROOT'" \
        > "$state_dir/logs/review-tls-remove.log" 2>&1
    run_review_command review-tls-mtls review-tls-missing-refresh.log refresh --yes
    export_checkpoint "$state_dir/review-tls-missing-store-checkpoint.json"
    assert_checkpoint "$state_dir/review-tls-missing-store-checkpoint.json" "Missing ACME store Read" true
    assert_read_checkpoint "$state_dir/review-tls-missing-store-checkpoint.json" false "Missing ACME store Read"
    missing_unprobed=$(jq -er "$traefik_query[0].outputs.tlsProbeSummary.unprobedCount | select(type == \"number\" and . > 0)" \
        "$state_dir/review-tls-missing-store-checkpoint.json")

    remote "bash '$GUEST_ROOT/review-tls.sh' restore '$GUEST_ROOT'" \
        > "$state_dir/logs/review-tls-restore-after-missing.log" 2>&1
    run_review_command review-tls-mtls review-tls-restored-refresh.log refresh --yes
    export_checkpoint "$state_dir/review-tls-restored-after-missing-checkpoint.json"
    assert_checkpoint "$state_dir/review-tls-restored-after-missing-checkpoint.json" "Restored ACME store Read" true
    assert_read_checkpoint "$state_dir/review-tls-restored-after-missing-checkpoint.json" true "Restored ACME store Read"

    remote "bash '$GUEST_ROOT/review-tls.sh' incomplete '$GUEST_ROOT'" \
        > "$state_dir/logs/review-tls-incomplete.log" 2>&1
    run_review_command review-tls-mtls review-tls-incomplete-refresh.log refresh --yes
    export_checkpoint "$state_dir/review-tls-incomplete-store-checkpoint.json"
    assert_checkpoint "$state_dir/review-tls-incomplete-store-checkpoint.json" "Incomplete ACME store Read" true
    assert_read_checkpoint "$state_dir/review-tls-incomplete-store-checkpoint.json" false "Incomplete ACME store Read"
    incomplete_unprobed=$(jq -er "$traefik_query[0].outputs.tlsProbeSummary.unprobedCount | select(type == \"number\" and . > 0)" \
        "$state_dir/review-tls-incomplete-store-checkpoint.json")
    remote "bash '$GUEST_ROOT/review-tls.sh' restore '$GUEST_ROOT'" \
        > "$state_dir/logs/review-tls-restore-after-incomplete.log" 2>&1
    run_review_command review-tls-mtls review-tls-incomplete-restored-refresh.log refresh --yes
    export_checkpoint "$state_dir/review-tls-restored-after-incomplete-checkpoint.json"
    assert_checkpoint "$state_dir/review-tls-restored-after-incomplete-checkpoint.json" "Restored incomplete ACME store Read" true
    assert_read_checkpoint "$state_dir/review-tls-restored-after-incomplete-checkpoint.json" true "Restored incomplete ACME store Read"

    run_review_command review-tls-issuer-switch review-tls-issuer-switch-up.log up --yes --skip-preview --parallel 1
    remote "bash '$GUEST_ROOT/review-tls.sh' assert-switch '$GUEST_ROOT'" \
        > "$state_dir/logs/review-tls-issuer-switch-assert.log" 2>&1
    export_checkpoint "$state_dir/review-tls-issuer-switch-checkpoint.json"
    assert_checkpoint "$state_dir/review-tls-issuer-switch-checkpoint.json" "Same-name issuer switch" true
    jq -n \
        --argjson missingStoreUnprobed "$missing_unprobed" \
        --argjson incompleteStoreUnprobed "$incomplete_unprobed" \
        '{
            missingStoreReadInSync: false,
            missingStoreUnprobedCount: $missingStoreUnprobed,
            missingStoreRestoredReadInSync: true,
            incompleteStoreReadInSync: false,
            incompleteStoreUnprobedCount: $incompleteStoreUnprobed,
            incompleteStoreRestoredReadInSync: true,
            sameNameIssuerStorageSwitchVerified: true
        }' > "$state_dir/review-tls-metrics.json"
    chmod 600 "$state_dir/review-tls-metrics.json"
}
capture_pebble_root() {
    local management_port=$1
    local certificate_name=$2
    local guest_certificate="$GUEST_ROOT/certs/$certificate_name"
    local evidence_certificate="$state_dir/$run_mode-$certificate_name"
    local log_file="$state_dir/logs/$run_mode-$certificate_name.log"
    [[ ! -e "$evidence_certificate" && ! -L "$evidence_certificate" ]] || {
        printf 'Refusing to overwrite captured Pebble issuer evidence: %s\n' "$evidence_certificate" >&2
        return 1
    }
    remote "curl --fail --silent --show-error --cacert '$GUEST_ROOT/certs/pebble.minica.pem' 'https://localhost:$management_port/roots/0' --output '$guest_certificate' && chmod 644 '$guest_certificate' && openssl x509 -in '$guest_certificate' -noout -checkend 0" \
        > "$log_file" 2>&1
    copy_from_guest "$guest_certificate" "$evidence_certificate" \
        "$state_dir/logs/${run_mode}-${certificate_name}-copy.log"
    sha256sum "$evidence_certificate" >> "$log_file"
}
apply_full_configuration() {
    local before_checkpoint=$1
    local checkpoint=$2
    local log_prefix=$3
    local before_pid before_hash after_pid after_hash
    before_pid=$(remote_service_pid)
    assert_checkpoint "$before_checkpoint" "Full update baseline" true
    before_hash=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml')
    run_pulumi structured "${log_prefix}-refresh.log" refresh --stack acceptance --yes --non-interactive
    run_pulumi structured "${log_prefix}-preview.log" preview --stack acceptance --diff --non-interactive --color=never
    run_pulumi structured "${log_prefix}-update.log" up --stack acceptance --yes --non-interactive --parallel 1
    after_pid=$(remote_service_pid)
    export_checkpoint "$checkpoint"
    assert_checkpoint "$checkpoint" "Full structured update" true
    assert_secret_checkpoint "$checkpoint"
    assert_guest_secret_isolation present
    after_hash=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml')
    if [[ "$before_hash" != "$after_hash" ]]; then
        [[ "$after_pid" != "$before_pid" ]] || {
            printf 'Full static configuration changed without restarting the Traefik process.\n' >&2
            return 1
        }
    else
        [[ "$after_pid" == "$before_pid" ]] || {
            printf 'Unchanged full static configuration unexpectedly restarted Traefik.\n' >&2
            return 1
        }
    fi
    run_pulumi structured "${log_prefix}-noop-preview.log" preview --stack acceptance --expect-no-changes --non-interactive --color=never
    run_pulumi structured "${log_prefix}-noop-up.log" up --stack acceptance --yes --non-interactive --skip-preview --expect-no-changes --parallel 1
}
remote_service_pid() {
    local pid
    pid=$(remote 'systemctl show --property=MainPID --value keroosha-traefik.service') || return 1
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || {
        printf 'Owned Traefik service did not report a live MainPID.\n' >&2
        return 1
    }
    printf '%s\n' "$pid"
}
run_transaction_review() {
    local new_secret_file="$state_dir/dns-tsig-secret-rotated"
    local old_secret_sha new_secret_sha credential_pid_before credential_pid_after
    local restore_pid_before restore_pid_after static_pid_before static_pid_after
    local debug_pid_before debug_pid_after
    [[ ! -e "$new_secret_file" && ! -L "$new_secret_file" ]] || {
        printf 'Refusing to overwrite the private rotated-secret fixture.\n' >&2
        return 1
    }
    openssl rand -base64 32 > "$new_secret_file"
    chmod 600 "$new_secret_file"
    old_secret_sha=$(secret_value_sha "$DNS_TSIG_SECRET_FILE")
    new_secret_sha=$(secret_value_sha "$new_secret_file")
    [[ "$old_secret_sha" =~ ^[a-f0-9]{64}$ && "$new_secret_sha" =~ ^[a-f0-9]{64}$ \
       && "$old_secret_sha" != "$new_secret_sha" ]] || {
        printf 'Credential rotation fixture did not produce distinct SHA-256 values.\n' >&2
        return 1
    }
    copy_to_guest "$script_dir/review-transactions.sh" "$GUEST_ROOT/review-transactions.sh" \
        "$state_dir/logs/review-transactions-copy.log"
    remote "chmod 700 '$GUEST_ROOT/review-transactions.sh'" \
        > "$state_dir/logs/review-transactions-install.log" 2>&1

    export_checkpoint "$state_dir/before-credential-interruption-checkpoint.json"
    assert_checkpoint "$state_dir/before-credential-interruption-checkpoint.json" "Credential interruption baseline" true
    assert_secret_checkpoint "$state_dir/before-credential-interruption-checkpoint.json" "$DNS_TSIG_SECRET_FILE"
    credential_pid_before=$(remote_service_pid)
    review_interposer_active=1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-install '$GUEST_ROOT'" \
        > "$state_dir/logs/credential-interrupt-install.log" 2>&1
    DNS_TSIG_SECRET_FILE="$new_secret_file" expect_pulumi_failure rotate credential-interrupt-up.log \
        up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-assert-staged '$GUEST_ROOT' '$credential_pid_before' '$old_secret_sha' '$new_secret_sha'" \
        > "$state_dir/logs/credential-interrupt-staged.log" 2>&1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-downgrade-v2 '$GUEST_ROOT'" \
        > "$state_dir/logs/credential-interrupt-v2-migration.log" 2>&1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-remove '$GUEST_ROOT'" \
        > "$state_dir/logs/credential-interrupt-remove.log" 2>&1
    review_interposer_active=0
    DNS_TSIG_SECRET_FILE="$new_secret_file" run_pulumi rotate credential-interrupt-retry-up.log \
        up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-assert-restarted '$GUEST_ROOT' '$credential_pid_before' '$new_secret_sha'" \
        > "$state_dir/logs/credential-interrupt-restarted.log" 2>&1
    credential_pid_after=$(remote_service_pid)
    export_checkpoint "$state_dir/after-credential-interruption-checkpoint.json"
    assert_checkpoint "$state_dir/after-credential-interruption-checkpoint.json" "Credential interruption retry" true
    assert_secret_checkpoint "$state_dir/after-credential-interruption-checkpoint.json" "$new_secret_file"
    assert_read_checkpoint "$state_dir/after-credential-interruption-checkpoint.json" true "Credential interruption retry"

    remote "bash '$GUEST_ROOT/review-transactions.sh' binary-stage-inject '$GUEST_ROOT'" \
        > "$state_dir/logs/binary-stage-inject.log" 2>&1
    restore_pid_before=$(remote_service_pid)
    run_pulumi rotate credential-fixture-restore-up.log up --stack acceptance --yes --non-interactive --parallel 1
    remote "bash '$GUEST_ROOT/review-transactions.sh' binary-stage-assert-clean '$GUEST_ROOT'" \
        > "$state_dir/logs/binary-stage-clean.log" 2>&1
    restore_pid_after=$(remote_service_pid)
    [[ "$restore_pid_after" != "$restore_pid_before" ]] || {
        printf 'Restoring the private DNS credential fixture did not restart Traefik.\n' >&2
        return 1
    }
    export_checkpoint "$state_dir/after-credential-fixture-restore-checkpoint.json"
    assert_checkpoint "$state_dir/after-credential-fixture-restore-checkpoint.json" "Credential fixture restoration" true
    assert_secret_checkpoint "$state_dir/after-credential-fixture-restore-checkpoint.json" "$DNS_TSIG_SECRET_FILE"

    export_checkpoint "$state_dir/before-static-log-info-checkpoint.json"
    assert_checkpoint "$state_dir/before-static-log-info-checkpoint.json" "Static log-level interruption baseline" true
    static_pid_before=$(remote_service_pid)
    review_interposer_active=1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-install '$GUEST_ROOT'" \
        > "$state_dir/logs/static-info-interrupt-install.log" 2>&1
    TRAEFIK_ACCEPTANCE_LOG_LEVEL=INFO expect_pulumi_failure rotate static-info-interrupt-up.log \
        up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-assert-static-staged '$GUEST_ROOT' '$static_pid_before' '$old_secret_sha'" \
        > "$state_dir/logs/static-info-interrupt-staged.log" 2>&1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-remove '$GUEST_ROOT'" \
        > "$state_dir/logs/static-info-interrupt-remove.log" 2>&1
    review_interposer_active=0
    TRAEFIK_ACCEPTANCE_LOG_LEVEL=INFO run_pulumi rotate static-info-interrupt-retry-up.log \
        up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
    remote "bash '$GUEST_ROOT/review-transactions.sh' restart-interrupt-assert-static-restarted '$GUEST_ROOT' '$static_pid_before' '$old_secret_sha'" \
        > "$state_dir/logs/static-info-interrupt-restarted.log" 2>&1
    static_pid_after=$(remote_service_pid)
    export_checkpoint "$state_dir/after-static-log-info-checkpoint.json"
    assert_checkpoint "$state_dir/after-static-log-info-checkpoint.json" "Static log-level retry" true
    assert_secret_checkpoint "$state_dir/after-static-log-info-checkpoint.json" "$DNS_TSIG_SECRET_FILE"

    debug_pid_before=$(remote_service_pid)
    TRAEFIK_ACCEPTANCE_LOG_LEVEL=DEBUG run_pulumi rotate static-log-info-restore-up.log \
        up --stack acceptance --yes --non-interactive --parallel 1
    debug_pid_after=$(remote_service_pid)
    [[ "$debug_pid_after" != "$debug_pid_before" ]] || {
        printf 'Restoring the original static log level did not restart Traefik.\n' >&2
        return 1
    }
    remote "jq -e '.log.level == \"DEBUG\"' /etc/keroosha-iac/traefik/static.yml >/dev/null"
    export_checkpoint "$state_dir/after-static-log-info-restore-checkpoint.json"
    assert_checkpoint "$state_dir/after-static-log-info-restore-checkpoint.json" "Static log-level fixture restoration" true
    assert_secret_checkpoint "$state_dir/after-static-log-info-restore-checkpoint.json" "$DNS_TSIG_SECRET_FILE"
    assert_guest_secret_isolation present
    assert_local_secret_absent before-reboot
    jq -n \
        --arg oldSecretSha256 "$old_secret_sha" \
        --arg newSecretSha256 "$new_secret_sha" \
        --arg credentialPidBefore "$credential_pid_before" \
        --arg credentialPidAfter "$credential_pid_after" \
        --arg restorePidBefore "$restore_pid_before" \
        --arg restorePidAfter "$restore_pid_after" \
        --arg staticPidBefore "$static_pid_before" \
        --arg staticPidAfter "$static_pid_after" \
        --arg debugRestorePidBefore "$debug_pid_before" \
        --arg debugRestorePidAfter "$debug_pid_after" \
        '{
            credentialOnlyRestart: {
                stagedJournalObserved: true,
                v2RestartIntentMigrated: true,
                retryRestartedProcess: ($credentialPidBefore != $credentialPidAfter),
                oldSecretSha256: $oldSecretSha256,
                newSecretSha256: $newSecretSha256
            },
            credentialFixtureRestored: ($restorePidBefore != $restorePidAfter),
            staticLogInfoRestart: {
                stagedPidUnchanged: true,
                retryRestartedProcess: ($staticPidBefore != $staticPidAfter),
                logLevelRestored: ($debugRestorePidBefore != $debugRestorePidAfter)
            }
        }' > "$state_dir/transaction-review-metrics.json"
    chmod 600 "$state_dir/transaction-review-metrics.json"
}
reboot_guest() {
    local before=$1
    local after_file="$state_dir/logs/boot-id-after.txt"
    local after=''
    if ! remote 'systemctl reboot' > "$state_dir/logs/reboot-request.log" 2>&1; then
        :
    fi
    for _ in $(seq 1 240); do
        if /usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" \
            'cat /proc/sys/kernel/random/boot_id' > "$after_file" 2>/dev/null; then
            after=$(<"$after_file")
            if [[ -n "$after" && "$after" != "$before" ]]; then break; fi
        fi
        sleep 2
    done
    chmod 600 "$after_file" 2>/dev/null || true
    [[ -n "$after" && "$after" != "$before" ]] || { printf 'The guest boot ID did not change after reboot.\n' >&2; return 1; }
    bash "$script_dir/guest-barrier-check.sh" acceptance "$state_dir" > "$state_dir/logs/post-guest-reboot-barrier.log" || return 1
    remote 'systemctl is-active ssh dorothy-traefik-acceptance-dns.service dorothy-traefik-acceptance-pebble.service dorothy-traefik-acceptance-pebble-rotated.service dorothy-traefik-acceptance-otelcol.service dorothy-traefik-acceptance-backends.service dorothy-traefik-acceptance-tcp.service dorothy-traefik-acceptance-udp.service keroosha-traefik.service' \
        > "$state_dir/logs/rebooted-services.log"
    printf '%s\n' "$after"
}
client_run_index=0
run_guest_client() {
    local mode=$1
    client_run_index=$((client_run_index + 1))
    local metrics_name="client-metrics-$client_run_index.json"
    copy_to_guest "$script_dir/client-checks.sh" "$GUEST_ROOT/client-checks.sh" \
        "$state_dir/logs/client-script-copy-$client_run_index.log"
    remote "chmod 700 '$GUEST_ROOT/client-checks.sh'; bash '$GUEST_ROOT/client-checks.sh' '$GUEST_ROOT' '$mode' '$client_run_index'" \
        || return 1
    copy_from_guest "$GUEST_ROOT/logs/$metrics_name" "$state_dir/$metrics_name" \
        "$state_dir/logs/client-metrics-copy-$client_run_index.log"
    if [[ "$mode" == after-reboot ]]; then
        copy_from_guest "$GUEST_ROOT/logs/otel-after-reboot-evidence.txt" \
            "$state_dir/otel-after-reboot-evidence-$client_run_index.txt" \
            "$state_dir/logs/post-reboot-otel-evidence-copy-$client_run_index.log"
    fi
}
run_sni_drift() {
    copy_to_guest "$script_dir/sni-drift.sh" "$GUEST_ROOT/sni-drift.sh" "$state_dir/logs/sni-script-copy.log"
    remote "chmod 700 '$GUEST_ROOT/sni-drift.sh'" > "$state_dir/logs/sni-script-install.log" 2>&1
    remote "bash '$GUEST_ROOT/sni-drift.sh' prepare '$GUEST_ROOT'" > "$state_dir/logs/sni-positive-before.log" 2>&1
    remote "bash '$GUEST_ROOT/sni-drift.sh' inject '$GUEST_ROOT'" > "$state_dir/logs/sni-inject.log" 2>&1
    run_pulumi sni-proof-only sni-read-refresh.log refresh --stack acceptance --yes --non-interactive
    export_checkpoint "$state_dir/sni-drift-checkpoint.json"
    assert_checkpoint "$state_dir/sni-drift-checkpoint.json" "SNI drift Read" true
    assert_read_checkpoint "$state_dir/sni-drift-checkpoint.json" false "SNI drift Read"
    remote "bash '$GUEST_ROOT/sni-drift.sh' assert-drift '$GUEST_ROOT'" > "$state_dir/logs/sni-drift-after-refresh.log" 2>&1
    run_pulumi sni-proof-only sni-repair-preview.log preview --stack acceptance --diff --non-interactive --color=never
    run_pulumi sni-proof-only sni-repair-up.log up --stack acceptance --yes --non-interactive --parallel 1
    export_checkpoint "$state_dir/sni-repaired-checkpoint.json"
    assert_checkpoint "$state_dir/sni-repaired-checkpoint.json" "SNI repair" true
    assert_read_checkpoint "$state_dir/sni-repaired-checkpoint.json" true "SNI repair"
    remote "bash '$GUEST_ROOT/sni-drift.sh' assert-positive '$GUEST_ROOT'" > "$state_dir/logs/sni-positive-after-repair.log" 2>&1
}
apply_sni_proof_only() {
    run_pulumi sni-proof-only sni-proof-only-preview.log preview --stack acceptance --diff --non-interactive --color=never
    run_pulumi sni-proof-only sni-proof-only-update.log up --stack acceptance --yes --non-interactive --parallel 1
    export_checkpoint "$state_dir/sni-proof-only-checkpoint.json"
    [[ "$(resource_id "$state_dir/sni-proof-only-checkpoint.json")" == "$legacy_id" ]] || {
        printf 'SNI-only phase replaced the existing logical Traefik resource.\n' >&2
        return 1
    }
    [[ "$(resource_urn "$state_dir/sni-proof-only-checkpoint.json")" == "$legacy_urn" ]] || {
        printf 'SNI-only phase changed the existing Traefik URN.\n' >&2
        return 1
    }
    jq -e "$traefik_query[0].inputs | has(\"configuration\")" \
        "$state_dir/sni-proof-only-checkpoint.json" > /dev/null || {
        printf 'SNI-only proof phase did not checkpoint its native configuration.\n' >&2
        return 1
    }
    run_sni_drift
}

legacy_id=$(<"$state_dir/legacy-resource-id.txt")
legacy_urn=$(resource_urn "$state_dir/legacy-checkpoint.json")
[[ -n "$legacy_urn" ]] || { printf 'Frozen-base checkpoint has no sandbox Traefik URN.\n' >&2; exit 1; }
if [[ "$run_mode" == sni-proof-only ]]; then
    export_checkpoint "$state_dir/before-sni-proof-only-checkpoint.json"
    assert_checkpoint "$state_dir/before-sni-proof-only-checkpoint.json" "SNI-only starting state" true
    apply_sni_proof_only
    printf 'SNI proof-only configuration is active; checkpoint: %s/sni-proof-only-checkpoint.json\n' "$state_dir"
    exit 0
elif [[ "$run_mode" == resume-after-sni ]]; then
    export_checkpoint "$state_dir/before-resume-after-sni-checkpoint.json"
    assert_checkpoint "$state_dir/before-resume-after-sni-checkpoint.json" "Resume-after-SNI starting state" true
    apply_full_configuration \
        "$state_dir/before-resume-after-sni-checkpoint.json" \
        "$state_dir/resume-structured-checkpoint.json" \
        resume-structured
else
    legacy_pid_before_candidate=$(remote_service_pid)

if ! bash "$script_dir/check-frozen-preview.sh" "$state_dir" \
    > "$state_dir/logs/frozen-checkpoint-preview.log" 2>&1; then
    printf 'Frozen copied-checkpoint preview failed; see %s/logs/frozen-checkpoint-preview.log\n' "$state_dir" >&2
    exit 1
fi
jq -e '.status == "unchanged" and .targetResourceCount == 1 and .sshInvocations == 0 and .refresh == false' \
    "$state_dir/offline-preview.json" >/dev/null || {
    printf 'Frozen copied-checkpoint preview did not report its no-SSH unchanged result.\n' >&2
    exit 1
}
run_pulumi legacy candidate-legacy-refresh.log refresh --stack acceptance --yes --non-interactive
run_pulumi legacy candidate-legacy-noop-preview.log preview --stack acceptance --expect-no-changes --non-interactive --color=never
run_pulumi legacy candidate-legacy-noop-up.log up --stack acceptance --yes --non-interactive --skip-preview --expect-no-changes --parallel 1
export_checkpoint "$state_dir/newer-legacy-checkpoint.json"
[[ "$(resource_id "$state_dir/newer-legacy-checkpoint.json")" == "$legacy_id" ]] || {
    printf 'New provider changed the legacy Traefik resource ID.\n' >&2
    exit 1
}
[[ "$(resource_urn "$state_dir/newer-legacy-checkpoint.json")" == "$legacy_urn" ]] || {
    printf 'New provider changed the legacy Traefik resource URN.\n' >&2
    exit 1
}
jq -e "$traefik_query[0].inputs | (has(\"configuration\") | not)" \
    "$state_dir/newer-legacy-checkpoint.json" > /dev/null || {
    printf 'New provider no-op added a configuration input to the legacy checkpoint.\n' >&2
    exit 1
}
legacy_noop_pid=$(remote_service_pid)
[[ "$legacy_noop_pid" == "$legacy_pid_before_candidate" ]] || {
    printf 'The newer provider no-op changed the legacy Traefik process.\\n' >&2
    exit 1
}
pagination_args=( "$state_dir" "$provider_dir" )
if [[ -n "${TRAEFIK_REVIEW_FROZEN_PROVIDER_DIR:-}" ]]; then
    frozen_provider_dir=$(realpath -e -- "$TRAEFIK_REVIEW_FROZEN_PROVIDER_DIR")
    [[ -x "$frozen_provider_dir/pulumi-resource-keroosha" \
       && -x "$frozen_provider_dir/helper/linux-x64/keroosha-iac-helper" ]] || {
        printf 'Frozen review provider is missing its provider or linux-x64 helper.\n' >&2
        exit 2
    }
    pagination_args+=( "$frozen_provider_dir" )
fi
if ! bash "$script_dir/check-pagination.sh" "${pagination_args[@]}" \
    > "$state_dir/logs/legacy-pagination-review.log" 2>&1; then
    printf 'Legacy listener pagination review failed; see %s/logs/legacy-pagination-review.log\n' "$state_dir" >&2
    exit 1
fi
[[ -s "$state_dir/pagination-evidence.json" ]] || {
    printf 'Legacy listener pagination review emitted no sanitized evidence.\n' >&2
    exit 1
}
if ! bash "$script_dir/check-seventeen.sh" "${pagination_args[@]}" \
    > "$state_dir/logs/legacy-tls-seventeen-review.log" 2>&1; then
    printf 'Legacy TLS 17-target review failed; see %s/logs/legacy-tls-seventeen-review.log\n' "$state_dir" >&2
    exit 1
fi
[[ -s "$state_dir/sni-seventeen.json" ]] || {
    printf 'Legacy TLS 17-target review emitted no sanitized evidence.\n' >&2
    exit 1
}

boot_before=$(remote 'cat /proc/sys/kernel/random/boot_id')
boot_after=$(reboot_guest "$boot_before")
[[ -n "$boot_after" ]] || { printf 'The guest reboot phase did not return a boot ID.\n' >&2; exit 1; }
run_pulumi legacy post-reboot-legacy-refresh.log refresh --stack acceptance --yes --non-interactive
run_pulumi legacy post-reboot-legacy-noop-preview.log preview --stack acceptance --expect-no-changes --non-interactive --color=never
run_pulumi legacy post-reboot-legacy-noop-up.log up --stack acceptance --yes --non-interactive --skip-preview --expect-no-changes --parallel 1
export_checkpoint "$state_dir/post-reboot-legacy-checkpoint.json"
[[ "$(resource_id "$state_dir/post-reboot-legacy-checkpoint.json")" == "$legacy_id" ]] || {
    printf 'Legacy resource identity changed after reboot.\\n' >&2
    exit 1
}

export_checkpoint "$state_dir/before-sni-proof-checkpoint.json"
assert_checkpoint "$state_dir/before-sni-proof-checkpoint.json" "SNI proof starting state" false
jq -e "$traefik_query[0].inputs | (has(\"configuration\") | not)" \
    "$state_dir/before-sni-proof-checkpoint.json" > /dev/null || {
    printf 'Full acceptance SNI proof must start from the frozen legacy resource.\n' >&2
    exit 1
}
apply_sni_proof_only
apply_full_configuration \
    "$state_dir/sni-proof-only-checkpoint.json" \
    "$state_dir/structured-checkpoint.json" \
    structured
fi
if ! bash "$script_dir/review/run-suite.sh" "$state_dir" "$provider_dir" \
    > "$state_dir/logs/review-suite-runner.log" 2>&1; then
    printf 'Reviewed route/client scenario suite failed; see %s/logs/review-suite-runner.log\n' "$state_dir" >&2
    exit 1
fi
[[ -f "$pulumi_project/Pulumi.yaml" \
   && $(<"$pulumi_project/Pulumi.yaml") == *"$state_dir/candidate-program/Traefik.Acceptance.dll"* ]] || {
    printf 'Reviewed suite did not restore the original candidate program manifest.\n' >&2
    exit 1
}
run_review_tls_coverage
[[ -f "$pulumi_project/Pulumi.yaml" \
   && $(<"$pulumi_project/Pulumi.yaml") == *"$state_dir/candidate-program/Traefik.Acceptance.dll"* ]] || {
    printf 'Reviewed TLS hooks did not restore the original candidate program manifest.\n' >&2
    exit 1
}
run_pulumi structured review-suite-original-restore-up.log up --stack acceptance --yes --non-interactive --parallel 1
export_checkpoint "$state_dir/after-review-suite-checkpoint.json"
assert_checkpoint "$state_dir/after-review-suite-checkpoint.json" "Restored full acceptance graph" true
assert_secret_checkpoint "$state_dir/after-review-suite-checkpoint.json"
assert_read_checkpoint "$state_dir/after-review-suite-checkpoint.json" true "Restored full acceptance graph"
assert_guest_secret_isolation present
jq -n '{
    routeClientScenarioSuitePassed: true,
    clientIdentityAccepted: true,
    clientWithoutCertificateRejected: true,
    independentlyIssuedClientCertificateRejected: true,
    originalStructuredGraphRestored: true
}' > "$state_dir/review-suite-metrics.json"
chmod 600 "$state_dir/review-suite-metrics.json"
capture_pebble_root 15000 pebble-issued-root.pem
run_guest_client protocols > "$state_dir/logs/protocol-clients.log" 2>&1 || {
    printf 'Real protocol/ACME client checks failed; see %s/logs/protocol-clients.log\n' "$state_dir" >&2
    exit 1
}

static_pid_before_route=$(remote_service_pid)
run_pulumi route-update route-only-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi route-update route-only-update.log up --stack acceptance --yes --non-interactive --parallel 1
static_pid_after_route=$(remote_service_pid)
[[ "$static_pid_after_route" == "$static_pid_before_route" ]] || {
    printf 'Dynamic-only route update unexpectedly restarted the static Traefik process.\n' >&2
    exit 1
}
run_guest_client route-update > "$state_dir/logs/route-update-client.log" 2>&1 || {
    printf 'Route-only client check failed; see %s/logs/route-update-client.log\n' "$state_dir" >&2
    exit 1
}

old_resolver_name="acceptance-$resolver_epoch"
[[ "$resolver_epoch" =~ ^[A-Za-z0-9_-]+$ ]] || {
    printf 'Resolver epoch may contain only letters, digits, underscore and hyphen.\n' >&2
    exit 2
}
old_resolver_storage=$(remote "jq -er --arg name '$old_resolver_name' '.certificatesResolvers[\$name].acme.storage | select(type == \"string\")' /etc/keroosha-iac/traefik/static.yml")
[[ "$old_resolver_storage" =~ ^/var/lib/keroosha-traefik/acme-[a-f0-9]{64}\.json$ ]] || {
    printf 'Active resolver storage path is not a helper-owned ACME storage file.\n' >&2
    exit 1
}
remote "test -s '$old_resolver_storage' && test -f '$old_resolver_storage' && test ! -L '$old_resolver_storage' && stat -c '%a:%u:%g' '$old_resolver_storage' && sha256sum '$old_resolver_storage' | cut -d' ' -f1" \
    > "$state_dir/old-resolver-storage-before-rotation.txt"
[[ -s "$state_dir/old-resolver-storage-before-rotation.txt" ]] || {
    printf 'The old DNS resolver did not leave readable ACME storage before rotation.\n' >&2
    exit 1
}
static_pid_before_rotation=$(remote_service_pid)
run_pulumi rotate resolver-rotation-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi rotate resolver-rotation-update.log up --stack acceptance --yes --non-interactive --parallel 1
remote "test -s '$old_resolver_storage' && test -f '$old_resolver_storage' && test ! -L '$old_resolver_storage' && stat -c '%a:%u:%g' '$old_resolver_storage' && sha256sum '$old_resolver_storage' | cut -d' ' -f1" \
    > "$state_dir/old-resolver-storage-after-rotation.txt"
cmp -s "$state_dir/old-resolver-storage-before-rotation.txt" "$state_dir/old-resolver-storage-after-rotation.txt" || {
    printf 'Resolver rotation changed or removed the prior DNS resolver ACME storage.\n' >&2
    exit 1
}
static_pid_after_rotation=$(remote_service_pid)
[[ "$static_pid_after_rotation" != "$static_pid_before_rotation" ]] || {
    printf 'Replacing the active DNS resolver did not restart the static Traefik process.\n' >&2
    exit 1
}
capture_pebble_root 15001 pebble-rotated-issued-root.pem
run_guest_client rotation > "$state_dir/logs/resolver-rotation-client.log" 2>&1 || {
    printf 'Independent CA resolver rotation check failed; see %s/logs/resolver-rotation-client.log\n' "$state_dir" >&2
    exit 1
}
export_checkpoint "$state_dir/rotated-checkpoint.json"
[[ "$(resource_id "$state_dir/rotated-checkpoint.json")" == "$legacy_id" ]] || {
    printf 'Resolver rotation replaced the existing logical resource.\n' >&2
    exit 1
}
run_transaction_review

boot_before=$(remote 'cat /proc/sys/kernel/random/boot_id')
printf '%s\n' "$boot_before" > "$state_dir/logs/structured-boot-id-before.txt"
chmod 600 "$state_dir/logs/structured-boot-id-before.txt"
remote "wc -c < '$GUEST_ROOT/logs/otelcol.log' > '$GUEST_ROOT/logs/otel-before-reboot.bytes'"
boot_after=$(reboot_guest "$boot_before")
[[ -n "$boot_after" ]] || { printf 'The structured configuration reboot phase did not return a boot ID.\n' >&2; exit 1; }
printf '%s\n' "$boot_after" > "$state_dir/logs/structured-boot-id-after.txt"
chmod 600 "$state_dir/logs/structured-boot-id-after.txt"
run_pulumi rotate post-reboot-refresh.log refresh --stack acceptance --yes --non-interactive
run_pulumi rotate post-reboot-preview.log preview --stack acceptance --expect-no-changes --non-interactive --color=never
run_pulumi rotate post-reboot-noop-up.log up --stack acceptance --yes --non-interactive --skip-preview --expect-no-changes --parallel 1
capture_pebble_root 15001 pebble-reboot-issued-root.pem
run_guest_client after-reboot > "$state_dir/logs/post-reboot-clients.log" 2>&1 || {
    printf 'Post-reboot real client check failed; see %s/logs/post-reboot-clients.log\n' "$state_dir" >&2
    exit 1
}
post_reboot_journal_since=$(remote 'systemctl show --property=ActiveEnterTimestamp --value keroosha-traefik.service')
post_reboot_journal_until=$(remote 'date --iso-8601=seconds')
[[ -n "$post_reboot_journal_since" && -n "$post_reboot_journal_until" ]] || {
    printf 'Could not capture the active Traefik unit journal time bounds.\n' >&2
    exit 1
}
remote "journalctl --boot --unit=keroosha-traefik.service --since '$post_reboot_journal_since' --until '$post_reboot_journal_until' --no-pager --output=short-iso --lines=1000" \
    > "$state_dir/logs/post-reboot-traefik-journal.log"
[[ -s "$state_dir/logs/post-reboot-traefik-journal.log" ]] || {
    printf 'Active-instance Traefik journal evidence is empty.\n' >&2
    exit 1
}
post_reboot_journal_lines=$(wc -l < "$state_dir/logs/post-reboot-traefik-journal.log" | tr -d '[:space:]')
[[ "$post_reboot_journal_lines" =~ ^[0-9]+$ ]] && ((post_reboot_journal_lines <= 1000)) || {
    printf 'Active-instance Traefik journal evidence exceeded its line bound.\n' >&2
    exit 1
}
jq -n \
    --arg since "$post_reboot_journal_since" \
    --arg until "$post_reboot_journal_until" \
    --argjson lineCount "$post_reboot_journal_lines" \
    '{
        unit: "keroosha-traefik.service",
        since: $since,
        until: $until,
        maxLines: 1000,
        lineCount: $lineCount
    }' > "$state_dir/post-reboot-journal-window.json"
chmod 600 "$state_dir/post-reboot-journal-window.json"
assert_guest_secret_isolation present

copy_to_guest "$script_dir/drift.sh" "$GUEST_ROOT/drift.sh" "$state_dir/logs/drift-script-copy.log"
remote "chmod 700 '$GUEST_ROOT/drift.sh'; bash '$GUEST_ROOT/drift.sh' '$GUEST_ROOT'" \
    > "$state_dir/logs/drift-injection.log" 2>&1
hash_before_refresh=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
run_pulumi rotate drift-read-refresh.log refresh --stack acceptance --yes --non-interactive
hash_after_refresh=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
[[ "$hash_after_refresh" == "$hash_before_refresh" ]] || {
    printf 'Pulumi Read/refresh repaired drift instead of leaving files untouched.\n' >&2
    exit 1
}
# A failed dial is 502; after the health checker removes the sole upstream it is 503.
for attempt in $(seq 1 12); do
    drift_status=$(remote 'curl --max-time 2 --silent --show-error --resolve shop.acceptance.test:18081:127.0.0.1 --output /dev/null --write-out "%{http_code}" http://shop.acceptance.test:18081/items/drift')
    if [[ "$drift_status" == 502 || "$drift_status" == 503 ]]; then break; fi
    sleep 0.25
done
[[ "$drift_status" == 502 || "$drift_status" == 503 ]] || { printf 'Injected HTTP drift did not remain active after Read/refresh.\n' >&2; exit 1; }
run_pulumi rotate drift-repair-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi rotate drift-repair-up.log up --stack acceptance --yes --non-interactive --parallel 1
hash_after_repair=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
[[ "$hash_after_repair" != "$hash_before_refresh" ]] || { printf 'Pulumi Update did not repair the owned dynamic configuration drift.\n' >&2; exit 1; }
run_guest_client after-reboot > "$state_dir/logs/post-drift-repair-clients.log" 2>&1 || {
    printf 'Protocol route was not restored after drift repair; see %s/logs/post-drift-repair-clients.log\n' "$state_dir" >&2
    exit 1
}

remote "bash '$GUEST_ROOT/drift.sh' inject '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-drift-injection.log" 2>&1
udp_drift_hash_before_refresh=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
run_pulumi rotate udp-drift-read-refresh.log refresh --stack acceptance --yes --non-interactive
udp_drift_hash_after_refresh=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
[[ "$udp_drift_hash_after_refresh" == "$udp_drift_hash_before_refresh" ]] || {
    printf 'Pulumi Read/refresh repaired UDP drift instead of leaving files untouched.\n' >&2
    exit 1
}
remote "bash '$GUEST_ROOT/drift.sh' assert-drift '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-drift-after-refresh.log" 2>&1
run_guest_client udp-drift > "$state_dir/logs/udp-drift-client.log" 2>&1 || {
    printf 'UDP drift data-plane assertions failed; see %s/logs/udp-drift-client.log\n' "$state_dir" >&2
    exit 1
}
run_pulumi rotate udp-drift-repair-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi rotate udp-drift-repair-up.log up --stack acceptance --yes --non-interactive --parallel 1
remote "bash '$GUEST_ROOT/drift.sh' assert-repaired '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-drift-after-repair.log" 2>&1
run_guest_client udp-repaired > "$state_dir/logs/udp-repaired-client.log" 2>&1 || {
    printf 'UDP route was not repaired; see %s/logs/udp-repaired-client.log\n' "$state_dir" >&2
    exit 1
}

udp_missing_route_static_before=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml' | awk '{print $1}')
udp_missing_route_dynamic_before=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
remote "bash '$GUEST_ROOT/review-transactions.sh' udp-drift-inject '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-missing-route-drift-inject.log" 2>&1
udp_missing_route_dynamic_injected=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
[[ "$udp_missing_route_dynamic_injected" != "$udp_missing_route_dynamic_before" ]] || {
    printf 'UDP missing-route drift fixture did not change the dynamic file.\n' >&2
    exit 1
}
run_pulumi rotate udp-missing-route-read-refresh.log refresh --stack acceptance --yes --non-interactive
udp_missing_route_dynamic_refreshed=$(remote 'sha256sum /etc/keroosha-iac/traefik/dynamic/current.yml' | awk '{print $1}')
[[ "$udp_missing_route_dynamic_refreshed" == "$udp_missing_route_dynamic_injected" ]] || {
    printf 'Pulumi Read/refresh repaired externally removed UDP route state.\n' >&2
    exit 1
}
remote "bash '$GUEST_ROOT/review-transactions.sh' udp-live-witness '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-live-after-read-witness.log" 2>&1
static_pid_before_udp_withdraw=$(remote_service_pid)
static_hash_before_udp_withdraw=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml' | awk '{print $1}')
[[ "$udp_missing_route_static_before" == "$static_hash_before_udp_withdraw" ]] || {
    printf 'External UDP route drift unexpectedly changed static Traefik bytes.\n' >&2
    exit 1
}
run_pulumi withdraw-udp udp-withdraw-preview.log preview --stack acceptance --diff --non-interactive --color=never
run_pulumi withdraw-udp udp-withdraw-up.log up --stack acceptance --yes --non-interactive --parallel 1
static_pid_after_udp_withdraw=$(remote_service_pid)
static_hash_after_udp_withdraw=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml' | awk '{print $1}')
[[ "$static_pid_after_udp_withdraw" != "$static_pid_before_udp_withdraw" ]] || {
    printf 'Withdrawing the last UDP handler from its accepted graph did not restart Traefik.\n' >&2
    exit 1
}
[[ "$static_hash_after_udp_withdraw" == "$static_hash_before_udp_withdraw" ]] || {
    printf 'UDP-only withdrawal changed static Traefik bytes and does not isolate the dynamic removal.\n' >&2
    exit 1
}
export_checkpoint "$state_dir/after-udp-withdraw-checkpoint.json"
assert_checkpoint "$state_dir/after-udp-withdraw-checkpoint.json" "UDP withdrawal" true
assert_read_checkpoint "$state_dir/after-udp-withdraw-checkpoint.json" true "UDP withdrawal"
remote "bash '$GUEST_ROOT/review-transactions.sh' udp-withdrawn-witness '$GUEST_ROOT'" \
    > "$state_dir/logs/udp-withdrawn-witness.log" 2>&1
for witness in \
    review-transactions-udp-before \
    review-transactions-udp-after \
    review-transactions-credential-staged \
    review-transactions-credential-recovered \
    review-transactions-static-staged \
    review-transactions-static-recovered \
    review-transactions-binary-stage-injected \
    review-transactions-binary-stage-clean \
    review-transactions-journal-v2; do
    copy_from_guest "$GUEST_ROOT/logs/$witness.json" "$state_dir/$witness.json" \
        "$state_dir/logs/$witness-copy.log"
done
jq -n \
    --arg staticPidBefore "$static_pid_before_udp_withdraw" \
    --arg staticPidAfter "$static_pid_after_udp_withdraw" \
    --arg staticHashBefore "$static_hash_before_udp_withdraw" \
    --arg staticHashAfter "$static_hash_after_udp_withdraw" \
    --arg dynamicHashBefore "$udp_missing_route_dynamic_before" \
    --arg dynamicHashAfterInjection "$udp_missing_route_dynamic_injected" \
    --arg dynamicHashAfterRead "$udp_missing_route_dynamic_refreshed" \
    '{
        missingRouteDriftReadLeftDiskUnchanged: ($dynamicHashAfterInjection == $dynamicHashAfterRead),
        staleLiveRouteWitnessPassed: true,
        pulumiWithdrawalRestartedTraefik: ($staticPidBefore != $staticPidAfter),
        staticBytesUnchanged: ($staticHashBefore == $staticHashAfter),
        withdrawnRouteWitnessPassed: true
    }' > "$state_dir/udp-withdrawal-metrics.json"
chmod 600 "$state_dir/udp-withdrawal-metrics.json"

export_checkpoint "$state_dir/before-udp-rollback-checkpoint.json"
udp_rollback_config_hash=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
udp_rollback_pid_before=$(remote_service_pid)
run_pulumi rollback-udp udp-rollback-preview.log preview --stack acceptance --diff --non-interactive --color=never
expect_pulumi_failure rollback-udp udp-rollback-up.log up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
grep -Fq 'Traefik activation did not satisfy the bounded readiness checks' "$state_dir/logs/udp-rollback-up.log" || {
    printf 'UDP rollback failure did not report the bounded activation rollback diagnostic.\n' >&2
    exit 1
}
udp_rollback_pid_after=$(remote_service_pid)
[[ "$udp_rollback_pid_after" != "$udp_rollback_pid_before" ]] || {
    printf 'UDP withdrawal rollback did not restart Traefik to restore the prior route set.\n' >&2
    exit 1
}
udp_rollback_config_hash_after=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
[[ "$udp_rollback_config_hash_after" == "$udp_rollback_config_hash" ]] || {
    printf 'Rejected UDP rollback candidate did not restore the withdrawn configuration files.\n' >&2
    exit 1
}
export_checkpoint "$state_dir/after-udp-rollback-checkpoint.json"
assert_checkpoint "$state_dir/after-udp-rollback-checkpoint.json" "UDP rollback" true
run_pulumi withdraw-udp udp-rollback-noop.log preview --stack acceptance --refresh=false --expect-no-changes --non-interactive
run_guest_client udp-drift > "$state_dir/logs/udp-rollback-client.log" 2>&1 || {
    printf 'UDP rollback did not retain the withdrawn route state; see %s/logs/udp-rollback-client.log\n' "$state_dir" >&2
    exit 1
}
remote "bash '$GUEST_ROOT/review-transactions.sh' unverified-drift-inject '$GUEST_ROOT'" \
    > "$state_dir/logs/unverified-drift-inject.log" 2>&1
expect_pulumi_failure rollback-udp unverified-rollback-up.log up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
grep -Fq 'prior configuration could not be verified' "$state_dir/logs/unverified-rollback-up.log" || {
    printf 'Unverified-state rollback did not preserve its targeted failure reason.\n' >&2
    exit 1
}
remote "bash '$GUEST_ROOT/review-transactions.sh' unverified-rollback-assert '$GUEST_ROOT'" \
    > "$state_dir/logs/unverified-rollback-assert.log" 2>&1
run_pulumi rotate unverified-repair-up.log up --stack acceptance --yes --non-interactive --parallel 1
remote "bash '$GUEST_ROOT/review-transactions.sh' unverified-repair-assert '$GUEST_ROOT'" \
    > "$state_dir/logs/unverified-repair-assert.log" 2>&1
export_checkpoint "$state_dir/after-udp-restore-checkpoint.json"
assert_checkpoint "$state_dir/after-udp-restore-checkpoint.json" "Recovered UDP route graph" true
assert_read_checkpoint "$state_dir/after-udp-restore-checkpoint.json" true "Recovered UDP route graph"
run_guest_client udp-repaired > "$state_dir/logs/udp-restored-client.log" 2>&1 || {
    printf 'Full UDP routes were not restored after transaction recovery; see %s/logs/udp-restored-client.log\n' "$state_dir" >&2
    exit 1
}
for witness in \
    review-transactions-unverified-drift \
    review-transactions-unverified-rollback \
    review-transactions-unverified-repair; do
    copy_from_guest "$GUEST_ROOT/logs/$witness.json" "$state_dir/$witness.json" \
        "$state_dir/logs/$witness-copy.log"
done
export_checkpoint "$state_dir/before-rollback-checkpoint.json"
static_rollback_config_hash_before=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
static_rollback_pid_before=$(remote_service_pid)
expect_pulumi_failure rollback rollback-up.log up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
grep -Fq 'Traefik activation did not satisfy the bounded readiness checks' "$state_dir/logs/rollback-up.log" || {
    printf 'Static rollback failure did not report the bounded activation rollback diagnostic.\n' >&2
    exit 1
}
static_rollback_config_hash_after=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
[[ "$static_rollback_config_hash_after" == "$static_rollback_config_hash_before" ]] || {
    printf 'Rejected static socket activation did not restore the prior configuration files.\n' >&2
    exit 1
}
static_rollback_pid_after=$(remote_service_pid)
[[ "$static_rollback_pid_after" != "$static_rollback_pid_before" ]] || {
    printf 'Rejected static socket activation did not restart Traefik to restore the prior process.\n' >&2
    exit 1
}
if ! remote_systemctl_is_active; then
    printf 'Could not positively query Traefik service activity after static rollback.\n' >&2
    exit 1
fi
[[ "$REMOTE_SYSTEMCTL_STATE" == active && "$REMOTE_SYSTEMCTL_EXIT" == 0 ]] || {
    printf 'Traefik service was not active after static rollback.\n' >&2
    exit 1
}
printf '%s\n' "$REMOTE_SYSTEMCTL_STATE" > "$state_dir/logs/rollback-service-active.log"
chmod 600 "$state_dir/logs/rollback-service-active.log"
export_checkpoint "$state_dir/after-rollback-checkpoint.json"
assert_checkpoint "$state_dir/after-rollback-checkpoint.json" "Static rollback" true
assert_secret_checkpoint "$state_dir/after-rollback-checkpoint.json"
jq -n \
    --arg pidBefore "$static_rollback_pid_before" \
    --arg pidAfter "$static_rollback_pid_after" \
    --arg hashBefore "$static_rollback_config_hash_before" \
    --arg hashAfter "$static_rollback_config_hash_after" \
    --arg diagnostic 'Traefik activation did not satisfy the bounded readiness checks' \
    --arg serviceState "$REMOTE_SYSTEMCTL_STATE" \
    --argjson systemctlExit "$REMOTE_SYSTEMCTL_EXIT" \
    '{
        pidBefore: $pidBefore,
        pidAfter: $pidAfter,
        configurationHashBefore: $hashBefore,
        configurationHashAfter: $hashAfter,
        activationDiagnostic: $diagnostic,
        serviceState: $serviceState,
        systemctlExit: $systemctlExit
    }' > "$state_dir/static-rollback-metrics.json"
chmod 600 "$state_dir/static-rollback-metrics.json"
run_pulumi rotate rollback-noop.log preview --stack acceptance --refresh=false --expect-no-changes --non-interactive
run_guest_client after-reboot > "$state_dir/logs/post-rollback-clients.log" 2>&1 || {
    printf 'Prior configuration was not restored after rejection; see %s/logs/post-rollback-clients.log\n' "$state_dir" >&2
    exit 1
}

export_checkpoint "$state_dir/before-foreign-owner-delete-checkpoint.json"
assert_checkpoint "$state_dir/before-foreign-owner-delete-checkpoint.json" "Foreign-owner Delete baseline" true
foreign_owner_pid_before=$(remote_service_pid)
foreign_owner_config_hash_before=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
remote "test -f /etc/keroosha-iac/traefik/.keroosha-owner && test ! -L /etc/keroosha-iac/traefik/.keroosha-owner && test ! -e '$foreign_owner_backup' && cp --preserve=mode,ownership,timestamps /etc/keroosha-iac/traefik/.keroosha-owner '$foreign_owner_backup'"
foreign_owner_marker_active=1
remote "printf '%s\\n' foreign-owner-fixture > /etc/keroosha-iac/traefik/.keroosha-owner && chmod 600 /etc/keroosha-iac/traefik/.keroosha-owner"
expect_pulumi_failure delete foreign-owner-delete.log up --stack acceptance --yes --non-interactive --skip-preview --parallel 1
grep -Fq 'configuration directory collides with an unowned Traefik path' "$state_dir/logs/foreign-owner-delete.log" || {
    printf 'Foreign-owner Delete failure did not report the ownership boundary.\n' >&2
    exit 1
}
foreign_owner_pid_after=$(remote_service_pid)
foreign_owner_config_hash_after=$(remote 'sha256sum /etc/keroosha-iac/traefik/static.yml /etc/keroosha-iac/traefik/dynamic/current.yml' | sha256sum | awk '{print $1}')
[[ "$foreign_owner_pid_after" == "$foreign_owner_pid_before" \
   && "$foreign_owner_config_hash_after" == "$foreign_owner_config_hash_before" ]] || {
    printf 'Foreign-owner Delete changed the running service or owned configuration.\n' >&2
    exit 1
}
if ! remote_systemctl_is_active \
   || [[ "$REMOTE_SYSTEMCTL_STATE" != active || "$REMOTE_SYSTEMCTL_EXIT" != 0 ]]; then
    printf 'Traefik did not remain positively active after foreign-owner Delete refusal.\n' >&2
    exit 1
fi
restore_foreign_owner_marker
export_checkpoint "$state_dir/after-foreign-owner-delete-checkpoint.json"
assert_checkpoint "$state_dir/after-foreign-owner-delete-checkpoint.json" "Foreign-owner Delete" true
assert_secret_checkpoint "$state_dir/after-foreign-owner-delete-checkpoint.json"
assert_guest_secret_isolation present
jq -n \
    --arg pidBefore "$foreign_owner_pid_before" \
    --arg pidAfter "$foreign_owner_pid_after" \
    --arg hashBefore "$foreign_owner_config_hash_before" \
    --arg hashAfter "$foreign_owner_config_hash_after" \
    --arg serviceState "$REMOTE_SYSTEMCTL_STATE" \
    --argjson systemctlExit "$REMOTE_SYSTEMCTL_EXIT" \
    '{
        deleteRejectedForForeignOwner: true,
        pidBefore: $pidBefore,
        pidAfter: $pidAfter,
        configurationHashBefore: $hashBefore,
        configurationHashAfter: $hashAfter,
        serviceState: $serviceState,
        systemctlExit: $systemctlExit
    }' > "$state_dir/foreign-owner-delete-metrics.json"
chmod 600 "$state_dir/foreign-owner-delete-metrics.json"
remote 'find /var/lib/keroosha-traefik -maxdepth 1 -type f -name "acme-*.json" -size +0c -print | sort' \
    > "$state_dir/acme-stores-before-delete.txt"
[[ -s "$state_dir/acme-stores-before-delete.txt" ]] || { printf 'No issued ACME storage files exist before Delete.\\n' >&2; exit 1; }
remote 'find /var/lib/keroosha-traefik -maxdepth 1 -type f -name "acme-*.json" -size +0c -print | sort | xargs -r sha256sum' \
    > "$state_dir/acme-store-hashes-before-delete.txt"
[[ -s "$state_dir/acme-store-hashes-before-delete.txt" ]] || { printf 'ACME storage hash manifest is empty before Delete.\\n' >&2; exit 1; }
acme_store_before_delete=$(sha256sum "$state_dir/acme-store-hashes-before-delete.txt" | awk '{ print $1 }')
run_pulumi delete delete-preview.log preview --stack acceptance --diff --non-interactive --color=never
traefik_pid_before_delete=$(remote_service_pid)
run_pulumi delete delete-up.log up --stack acceptance --yes --non-interactive --parallel 1
export_checkpoint "$state_dir/deleted-checkpoint.json"
deleted_count=$(jq "$traefik_query | length" "$state_dir/deleted-checkpoint.json")
[[ "$deleted_count" == 0 ]] || { printf 'Pulumi did not delete the Traefik resource.\n' >&2; exit 1; }
if ! remote_systemctl_is_active; then
    printf 'Could not positively query Traefik service activity after Delete; SSH or systemctl failed.\n' >&2
    exit 1
fi
[[ "$REMOTE_SYSTEMCTL_STATE" == inactive && "$REMOTE_SYSTEMCTL_EXIT" == 3 \
   || "$REMOTE_SYSTEMCTL_STATE" == unknown && "$REMOTE_SYSTEMCTL_EXIT" == 4 ]] || {
    printf 'Traefik service remained active after Delete.\n' >&2
    exit 1
}
printf '%s %s\n' "$REMOTE_SYSTEMCTL_STATE" "$REMOTE_SYSTEMCTL_EXIT" \
    > "$state_dir/logs/deleted-service-active.log"
chmod 600 "$state_dir/logs/deleted-service-active.log"
remote 'find /var/lib/keroosha-traefik -maxdepth 1 -type f -name "acme-*.json" -size +0c -print | sort' \
    > "$state_dir/acme-stores-after-delete.txt"
remote 'find /var/lib/keroosha-traefik -maxdepth 1 -type f -name "acme-*.json" -size +0c -print | sort | xargs -r sha256sum' \
    > "$state_dir/acme-store-hashes-after-delete.txt"
[[ -s "$state_dir/acme-store-hashes-after-delete.txt" ]] || { printf 'ACME storage disappeared during Delete.\n' >&2; exit 1; }
acme_store_after_delete=$(sha256sum "$state_dir/acme-store-hashes-after-delete.txt" | awk '{ print $1 }')
cmp -s "$state_dir/acme-stores-before-delete.txt" "$state_dir/acme-stores-after-delete.txt" || {
    printf 'ACME storage file names changed during Delete.\n' >&2
    exit 1
}
[[ "$acme_store_after_delete" == "$acme_store_before_delete" ]] || {
    printf 'ACME certificate storage changed during Delete.\n' >&2
    exit 1
}
# Do not uninstall the guest's bootstrap packages: they are shared with the test CA and
# SSH. The acceptance boundary is the Traefik resource; cleanup.sh discards this VM/backend.
remote "test ! -e '/proc/$traefik_pid_before_delete' && test ! -e /etc/systemd/system/keroosha-traefik.service && test ! -e /etc/keroosha-iac/traefik/dns-credentials.env" || {
    printf 'Delete left the Traefik process, service unit, or credential file behind.\n' >&2
    exit 1
}
assert_guest_secret_isolation absent
assert_local_secret_absent
jq -n \
    --arg mainPidBeforeDelete "$traefik_pid_before_delete" \
    --arg journalSince "$post_reboot_journal_since" \
    --arg journalUntil "$post_reboot_journal_until" \
    --argjson journalLines "$post_reboot_journal_lines" \
    --argjson guestMainPidCmdlineSnapshots "$guest_mainpid_cmdline_snapshot_count" \
    --argjson sshArgvAuditInvocations "$ssh_argv_audit_invocations" \
    --argjson sshArgvAuditEntries "$ssh_argv_audit_entries" \
    --argjson sshArgvAuditTokenChecks "$ssh_argv_audit_tokens" \
    --argjson sshArgvAuditComparisons "$ssh_argv_audit_comparisons" \
    '{
        pulumiConfigurationInputOutputCiphertextAsserted: true,
        literalTsigValuesAbsentFromPulumiCheckpoints: true,
        literalTsigValuesAbsentFromExposedHostArtifacts: true,
        guestBarrierReceiptValidated: true,
        guestBarrierAuthorizationValidated: true,
        exposedHostScanScope: ["Pulumi file backend", "exported checkpoint JSON", "Pulumi project files", "harness logs"],
        providerSshArgvComparedToEveryDnsFixtureToken: true,
        providerSshArgvContainsNoDnsFixtureTokens: true,
        sshArgvAudit: {
            invocations: $sshArgvAuditInvocations,
            outgoingArgvEntriesChecked: $sshArgvAuditEntries,
            fixtureTokenChecks: $sshArgvAuditTokenChecks,
            comparisons: $sshArgvAuditComparisons
        },
        guestTraefikMainPidCmdlineSnapshots: $guestMainPidCmdlineSnapshots,
        literalTsigValuesAbsentFromTraefikMainPidCmdline: true,
        literalTsigValuesAbsentFromTraefikConfigFilesUnitAndBoundedJournal: true,
        postRebootJournalWindow: {
            unit: "keroosha-traefik.service",
            since: $journalSince,
            until: $journalUntil,
            maxLines: 1000,
            lines: $journalLines
        },
        postDelete: {
            mainPidBeforeDelete: $mainPidBeforeDelete,
            priorMainPidAbsent: true,
            serviceUnitRemoved: true,
            credentialEnvironmentRemoved: true
        },
        rootOnlyRollbackSnapshotsMayContainReversibleCredentials: true,
        rootOnlyRollbackSnapshotsArePrivateAndNotShared: true
    }' > "$state_dir/secret-hygiene-metrics.json"
chmod 600 "$state_dir/secret-hygiene-metrics.json"
if [[ "$run_mode" == full ]]; then
    evidence_file=${TRAEFIK_ACCEPTANCE_EVIDENCE_FILE:-"$state_dir.evidence.json"}
    if ! bash "$script_dir/write-evidence.sh" "$state_dir" "$provider_dir" "$run_mode" "$evidence_file"; then
        printf 'Could not write sanitized machine-readable acceptance evidence.\n' >&2
        exit 1
    fi
    printf 'Sanitized machine-readable evidence: %s\n' "$evidence_file"
fi

printf 'Real VM acceptance passed.\n'
printf 'Legacy checkpoint: %s/legacy-checkpoint.json\n' "$state_dir"
printf 'Detailed logs and disposable credentials remain private under: %s\n' "$state_dir"
printf 'Guest: %s@%s:%s\n' "$SSH_USER" "$SSH_HOST" "$SSH_PORT"
printf 'Cleanup: tests/Traefik.Acceptance/cleanup.sh %q\n' "$state_dir"
