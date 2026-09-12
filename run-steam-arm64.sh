#!/usr/bin/bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
steam_root="${script_dir}/Steam"
steam_arm_dir="${steam_root}/steamrtarm64"
steam_shim_dir="${steam_root}/lib/aarch64-linux-gnu"
steam_runtime_bin="${steam_root}/steam-runtime-steamrt-arm64/bin"
sysvsem_shim="${script_dir}/sysvipc-shim/libsysvsem-shim.so"
ui_watchdog="${script_dir}/steam-ui-watchdog.py"
cef_debug_sentinel="${steam_root}/.cef-enable-remote-debugging"

if [[ ! -x "${steam_arm_dir}/steam" ]]; then
    echo "ARM64 Steam executable is missing: ${steam_arm_dir}/steam" >&2
    exit 127
fi
if [[ ! -r "${sysvsem_shim}" ]]; then
    echo "System V semaphore shim is missing: ${sysvsem_shim}" >&2
    exit 127
fi
if ! mountpoint -q /dev/shm; then
    echo "/dev/shm is not mounted. Mount the 512 MiB tmpfs before starting Steam:" >&2
    echo "  sudo mount -t tmpfs -o size=512M,nosuid,nodev,mode=1777 tmpfs /dev/shm" >&2
    exit 126
fi

steam_args=("$@")
if [[ "${STEAM_ARM64_UI_WORKAROUND:-1}" != 0 ]]; then
    if [[ ! -x "${ui_watchdog}" ]]; then
        echo "SteamUI recovery watchdog is missing: ${ui_watchdog}" >&2
        exit 127
    fi
    if [[ -e "${cef_debug_sentinel}" && ! -f "${cef_debug_sentinel}" ]]; then
        echo "Refusing unexpected CEF debugger sentinel: ${cef_debug_sentinel}" >&2
        exit 126
    fi
    if [[ ! -e "${cef_debug_sentinel}" ]]; then
        umask 077
        printf '\n' > "${cef_debug_sentinel}"
    fi

    have_dev_flag=0
    for argument in "${steam_args[@]}"; do
        if [[ "${argument}" == -dev ]]; then
            have_dev_flag=1
            break
        fi
    done
    if (( ! have_dev_flag )); then
        steam_args+=( -dev )
    fi

    "${ui_watchdog}" --port 8080 --steam-pid "$$" &
fi

export LD_LIBRARY_PATH="${steam_arm_dir}:${steam_shim_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export LD_PRELOAD="${sysvsem_shim}${LD_PRELOAD:+:${LD_PRELOAD}}"
export PATH="${steam_runtime_bin}:${PATH}"

cd "${steam_arm_dir}"
exec "${steam_arm_dir}/steam" "${steam_args[@]}"
