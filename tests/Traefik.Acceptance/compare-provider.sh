#!/usr/bin/env bash
# Compare two separately published providers with the SAME synthetic inputs and real daemon captures.
# Run once per artifact. The candidate must meet every assertion; the baseline reports its decisions.
set -euo pipefail
umask 077
[[ $# == 5 ]] || { echo 'usage: compare-provider.sh before|after PROVIDER_DIR MANAGED_HELPER_DLL CAPTURE_DIR RESULT.json' >&2; exit 2; }
mode=$1; case "$mode" in before|after) ;; *) exit 2;; esac
bundle=$(realpath -e "$2"); helper=$(realpath -e "$3"); captures=$(realpath -e "$4"); output=$5
[[ -f "$bundle/pulumi-resource-keroosha.dll" && -s "$captures/model/rawdata.json" && ! -e "$output" && ! -L "$output" ]] || exit 2
dir=$(dirname "$(realpath "$0")"); work=$(mktemp -d /tmp/dorothy-traefik-compare.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
export DOTNET_ROOT=$(dirname "$(readlink -f "$(command -v dotnet)")"); export DOTNET_ROOT_X64="$DOTNET_ROOT"
export HOME="$work/home" DOTNET_CLI_HOME="$work/dotnet" NUGET_PACKAGES="$work/packages" NUGET_HTTP_CACHE_PATH="$work/http" PULUMI_HOME="$work/pulumi"
export DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 PULUMI_SKIP_UPDATE_CHECK=1
mkdir -p "$HOME" "$PULUMI_HOME"
assertions=(); [[ "$mode" == before ]] || assertions=(--assert-current)
provider=(-I:"$bundle" -r:Pulumi.dll -r:pulumi-resource-keroosha.dll)
compare(){
    local result=$1; shift
    if ! dotnet fsi --nologo "$@" "${assertions[@]}" > "$result"; then
        jq -r '.[] | select(.expected != .observed) | "\(.case): expected \(.expected), observed \(.observed)"' "$result" >&2
        return 1
    fi
}
compare "$work/check.json" "${provider[@]}" "$dir/compare-admission.fsx"
compare "$work/runtime.json" -r:"$helper" "$dir/compare-runtime.fsx" "$captures"
# Use the package validator, not only a JSON parse. Keep the unrelated Users schema out of scope.
dotnet fsi --nologo "${provider[@]}" "$dir/emit-schema.fsx" | jq -e '{name,version,types:(.types|with_entries(select(.key|contains("SshConnection") or contains("Traefik")))),resources:(.resources|with_entries(select(.key=="keroosha:debian:Traefik")))}' > "$work/schema.json"
pulumi schema check "$work/schema.json"
for path in "$work/check.json" "$work/runtime.json"; do jq -e 'type=="array" and length>0 and all(.[]; (.case|type=="string") and (.expected|type=="boolean") and (.observed|type=="boolean"))' "$path" >/dev/null; done
sha(){ sha256sum "$1" | cut -d' ' -f1; }
jq -n --arg mode "$mode" --arg p "$(sha "$bundle/pulumi-resource-keroosha.dll")" --arg h "$(sha "$helper")" --arg s "$(sha "$work/schema.json")" \
  --slurpfile check "$work/check.json" --slurpfile runtime "$work/runtime.json" \
  '{mode:$mode,providerAssemblySha256:$p,helperAssemblySha256:$h,moduleSchemaSha256:$s,moduleSchemaChecked:true,admission:$check[0],runtime:$runtime[0]}' > "$output"
