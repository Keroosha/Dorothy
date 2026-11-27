#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
    printf 'Usage: %s /tmp/dorothy-traefik-acceptance.XXXXXXXX\n' "$0" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(realpath -e -- "$script_dir/../..")
state_dir=$(realpath -e -- "$1")
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to build outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" && "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || {
    printf 'Private acceptance ownership marker is missing.\n' >&2
    exit 2
}
barrier_checker="$script_dir/guest-barrier-check.sh"
if ! bash "$barrier_checker" acceptance "$state_dir"; then
    printf 'Guest barrier acceptance failed; refusing legacy bootstrap.\n' >&2
    exit 1
fi

source "$state_dir/handle.env"
for command in git tar dotnet pulumi openssl jq base64; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done
[[ -f "$state_dir/upstream-ca.pem" && -f "$state_dir/client-ca.pem" && -s "$DNS_TSIG_SECRET_FILE" ]] || {
    printf 'The isolated guest protocol fixtures are not ready.\n' >&2
    exit 2
}

base_sha=2d486e33fc8cdae60c6a7571f8ba6f07b5b5ebf3
legacy_source="$state_dir/legacy-source"
mkdir -m 700 -p "$state_dir/logs" "$state_dir/home" "$state_dir/dotnet-home" "$state_dir/nuget-packages" "$state_dir/legacy-program" "$state_dir/pulumi-project"
chmod 700 "$state_dir/logs" "$state_dir/home" "$state_dir/dotnet-home" "$state_dir/nuget-packages" "$state_dir/legacy-program" "$state_dir/pulumi-project"
# Reached only after authorization of this VM's exact isolation receipt.
[[ "$GUEST_ROOT" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]]
/usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" \
    "bash '$GUEST_ROOT/guest-activate-fixtures.sh' '$GUEST_ROOT'" \
    > "$state_dir/logs/approved-fixture-activation.log" 2>&1
scp -F "$SSH_CONFIG" -P "$SSH_PORT" "$SSH_USER@$SSH_HOST:$GUEST_ROOT/logs/baseline-observations.log" "$state_dir/baseline-runtime.log"

if [[ -e "$legacy_source" ]]; then
    [[ -d "$legacy_source" && -f "$legacy_source/.legacy-base-sha" && "$(<"$legacy_source/.legacy-base-sha")" == "$base_sha" ]] || {
        printf 'An unmarked frozen-base archive already occupies the private path.\n' >&2
        exit 2
    }
else
    mkdir -m 700 "$legacy_source"
    if ! git -C "$repo_root" archive "$base_sha" | tar -xf - -C "$legacy_source"; then
        printf 'Could not extract the frozen public base commit.\n' >&2
        exit 1
    fi
    printf '%s\n' "$base_sha" > "$legacy_source/.legacy-base-sha"
    chmod 600 "$legacy_source/.legacy-base-sha"
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
export PATH="$state_dir/bin:$PATH"

helper_publish_log="$state_dir/logs/frozen-helper-publish.log"
if [[ ! -x "$legacy_source/src/Dorothy.DSL.Providers/Provider/helper/linux-x64/keroosha-iac-helper" ]]; then
    if ! bash "$legacy_source/scripts/publish-host-helper.sh" linux-x64 > "$helper_publish_log" 2>&1; then
        printf 'Frozen base NativeAOT helper publish failed; see %s\n' "$helper_publish_log" >&2
        exit 1
    fi
fi

legacy_provider="$state_dir/legacy-provider"
mkdir -m 700 -p "$legacy_provider"
if [[ ! -x "$legacy_provider/pulumi-resource-keroosha" ]]; then
    if ! dotnet publish "$legacy_source/src/Dorothy.DSL.Providers/Dorothy.DSL.Providers.fsproj" \
        --configuration Release --output "$legacy_provider" \
        > "$state_dir/logs/frozen-provider-publish.log" 2>&1; then
        printf 'Frozen base provider publish failed; see %s\n' "$state_dir/logs/frozen-provider-publish.log" >&2
        exit 1
    fi
fi

legacy_project="$state_dir/legacy-program-source"
mkdir -m 700 -p "$legacy_project"
cp "$script_dir/LegacyProgram.fs" "$legacy_project/Program.fs"
cat > "$legacy_project/LegacyProgram.fsproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>Traefik.Acceptance</AssemblyName>
    <RootNamespace>Dorothy.Traefik.Acceptance</RootNamespace>
    <WarningsAsErrors>FS0020;FS3221</WarningsAsErrors>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="$legacy_source/src/Dorothy.DSL/Dorothy.DSL.fsproj" />
  </ItemGroup>
  <ItemGroup>
    <Compile Include="Program.fs" />
  </ItemGroup>
</Project>
EOF
if ! dotnet publish "$legacy_project/LegacyProgram.fsproj" \
    --configuration Release --output "$state_dir/legacy-program" \
    > "$state_dir/logs/frozen-program-publish.log" 2>&1; then
    printf 'Frozen base legacy Pulumi program publish failed; see %s\n' "$state_dir/logs/frozen-program-publish.log" >&2
    exit 1
fi

cat > "$state_dir/pulumi-project/Pulumi.yaml" <<EOF
name: traefik-acceptance
runtime:
  name: dotnet
  options:
    binary: $state_dir/legacy-program/Traefik.Acceptance.dll
description: Private real-VM Traefik compatibility acceptance
EOF
chmod 600 "$state_dir/pulumi-project/Pulumi.yaml"

if ! pulumi plugin install resource keroosha 0.1.0 --file "$legacy_provider" --reinstall \
    > "$state_dir/logs/frozen-plugin-install.log" 2>&1; then
    printf 'Frozen base provider plugin install failed; see %s\n' "$state_dir/logs/frozen-plugin-install.log" >&2
    exit 1
fi
if ! pulumi login "file://$state_dir/backend" --non-interactive \
    > "$state_dir/logs/pulumi-login.log" 2>&1; then
    printf 'Private Pulumi file-backend login failed; see %s\n' "$state_dir/logs/pulumi-login.log" >&2
    exit 1
fi

run_pulumi() {
    local log_name=$1
    shift
    if ! (cd "$state_dir/pulumi-project" && pulumi "$@") > "$state_dir/logs/$log_name" 2>&1; then
        printf 'Pulumi %s failed; see %s/logs/%s\n' "$1" "$state_dir" "$log_name" >&2
        exit 1
    fi
}

if ! (cd "$state_dir/pulumi-project" && pulumi stack init acceptance --secrets-provider passphrase --non-interactive) \
    > "$state_dir/logs/pulumi-stack-init.log" 2>&1; then
    printf 'Private legacy Pulumi stack initialization failed; see %s/logs/pulumi-stack-init.log\n' "$state_dir" >&2
    exit 1
fi
run_pulumi pulumi-config-scenario.log config set scenario traefik --stack acceptance --non-interactive
run_pulumi pulumi-config-backend.log config set backend http://127.0.0.1:8080 --stack acceptance --non-interactive
run_pulumi pulumi-config-admin.log config set adminPort 19080 --stack acceptance --non-interactive

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$state_dir/legacy-example.key" -out "$state_dir/legacy-example.pem" \
    -subj '/CN=example.org' -days 2 \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=serverAuth' \
    -addext 'subjectAltName=DNS:example.org' \
    > "$state_dir/logs/legacy-certificate-generation.log" 2>&1
chmod 600 "$state_dir/legacy-example.key" "$state_dir/legacy-example.pem"
export TRAEFIK_ACCEPTANCE_LEGACY_CERT_FILE="$state_dir/legacy-example.pem"
export TRAEFIK_ACCEPTANCE_LEGACY_KEY_FILE="$state_dir/legacy-example.key"

if ! (cd "$state_dir/pulumi-project" && pulumi up --stack acceptance --yes --non-interactive --skip-preview --parallel 1) \
    > "$state_dir/logs/legacy-create.log" 2>&1; then
    printf 'Frozen-base legacy resource create failed; see %s/logs/legacy-create.log\n' "$state_dir" >&2
    exit 1
fi
if ! (cd "$state_dir/pulumi-project" && pulumi stack export --stack acceptance) \
    > "$state_dir/legacy-checkpoint.json" 2> "$state_dir/logs/legacy-export.log"; then
    printf 'Could not export the real legacy Pulumi checkpoint; see %s/logs/legacy-export.log\n' "$state_dir" >&2
    exit 1
fi
chmod 600 "$state_dir/legacy-checkpoint.json"

legacy_resources=$(jq '[.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))] | length' "$state_dir/legacy-checkpoint.json")
[[ "$legacy_resources" == 1 ]] || { printf 'The real legacy checkpoint does not contain exactly one sandbox Traefik resource.\n' >&2; exit 1; }
jq -e '[.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))][0].inputs | (has("configuration") | not)' \
    "$state_dir/legacy-checkpoint.json" > /dev/null || {
    printf 'The legacy checkpoint unexpectedly contains the structured configuration input.\n' >&2
    exit 1
}
jq -r '[.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))][0].id' \
    "$state_dir/legacy-checkpoint.json" > "$state_dir/legacy-resource-id.txt"
chmod 600 "$state_dir/legacy-resource-id.txt"

if ! (cd "$state_dir/pulumi-project" && pulumi preview --stack acceptance --expect-no-changes --non-interactive --color=never) \
    > "$state_dir/logs/frozen-base-legacy-noop-preview.log" 2>&1; then
    printf 'Frozen-base legacy checkpoint did not preview as a no-op; see %s/logs/frozen-base-legacy-noop-preview.log\n' "$state_dir" >&2
    exit 1
fi
printf 'Created real frozen-base legacy checkpoint for URN suffix sandbox.\n'
printf 'Project/stack: traefik-acceptance/acceptance\n'
printf 'Checkpoint: %s/legacy-checkpoint.json\n' "$state_dir"
printf 'Resource ID: %s\n' "$(<"$state_dir/legacy-resource-id.txt")"
printf 'Next command after candidate integration: tests/Traefik.Acceptance/run.sh %s <candidate-provider-dir>\n' "$state_dir"
