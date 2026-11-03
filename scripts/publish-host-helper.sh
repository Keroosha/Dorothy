#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ( "$1" != "linux-x64" && "$1" != "linux-arm64" ) ]]; then
  printf 'Usage: bash scripts/publish-host-helper.sh linux-x64|linux-arm64\n' >&2
  exit 64
fi

rid="$1"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
project="$repo_root/src/Dorothy.HostHelper/Dorothy.HostHelper.fsproj"
output="$repo_root/src/Dorothy.DSL.Providers/Provider/helper/$rid"

# Run this on the matching Linux build host/toolchain; native AOT output is not part of normal builds.
# On Debian 13, the provider bootstraps missing libicu76 before helper dispatch; targets still need libc/OpenSSL and ICU. AOT removes the target .NET runtime, not OS libraries.
dotnet publish "$project" \
  --configuration Release \
  --runtime "$rid" \
  --self-contained true \
  --output "$output" \
  -p:PublishAot=true \
  -p:StripSymbols=true
