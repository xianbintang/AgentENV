#!/usr/bin/env bash
# Pure render/refusal checks: no sudo, downloads, devices, service or profile use.
set -euo pipefail
installer="$(cd "$(dirname "$0")/.." && pwd)/install.sh"
run() { env -i PATH="$PATH" "$@"; }
legacy="$(run bash "$installer" --print-install-service)"
[[ "$legacy" == *$'User=aenv\nGroup=aenv'* ]]
[[ "$legacy" == *'CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN'* ]]
profile=/srv/codex-guest-416/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/agentenv-profile.json
native="$(run AENV_DEPLOYMENT_MODE=native-root AENV_NATIVE_PROFILE="$profile" AENV_NATIVE_VMM=/usr/local/bin/firecracker bash "$installer" --print-install-service)"
[[ "$native" == *$'User=root\nGroup=root'* && "$native" == *'RuntimeDirectoryMode=0700'* && "$native" == *'SecureBits=noroot noroot-locked'* && "$native" == *'NoNewPrivileges=true'* && "$native" == *'Restart=no'* ]]
[[ "$native" == *'CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN'* && "$native" != *CAP_DAC_OVERRIDE* && "$native" != *CAP_SETUID* ]]
config="$(run AENV_DEPLOYMENT_MODE=native-root AENV_NATIVE_PROFILE="$profile" AENV_NATIVE_VMM=/usr/local/bin/firecracker bash "$installer" --print-native-root-config)"
[[ "$config" == *'deployment_mode = "native-root"'* && "$config" == *'work_dir = "/var/lib/aenv-native-root/work"'* && "$config" == *'p2p_enabled = false'* && "$config" == *'low_watermark = 0'* ]]
if run AENV_DEPLOYMENT_MODE=native-root AENV_NATIVE_VMM=/usr/local/bin/firecracker bash "$installer" --print-install-service >/dev/null 2>&1; then exit 1; fi
for home in /var/lib/aenv /run/aenv / /tmp/../native $'/tmp/native\nforged' ; do
 if run AENV_DEPLOYMENT_MODE=native-root AENV_HOME_PATH="$home" AENV_NATIVE_PROFILE="$profile" AENV_NATIVE_VMM=/usr/local/bin/firecracker bash "$installer" --print-install-service >/dev/null 2>&1; then exit 1; fi
done
if run AENV_DEPLOYMENT_MODE=native-root AENV_SERVICE_USER=aenv AENV_NATIVE_PROFILE="$profile" AENV_NATIVE_VMM=/usr/local/bin/firecracker bash "$installer" --print-install-service >/dev/null 2>&1; then exit 1; fi
if run AENV_DEPLOYMENT_MODE=unknown bash "$installer" --print-install-service >/dev/null 2>&1; then exit 1; fi
printf 'PASS: default/nonroot and explicit native-root service render; missing profile, unsafe paths and identity overrides refused (pure checks only)\n'
