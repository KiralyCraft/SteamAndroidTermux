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
direct_compat_source="${script_dir}/compatibilitytools/GE-Proton11-6-aarch64-direct"
direct_compat_root="${steam_root}/compatibilitytools.d"
direct_compat_target="${direct_compat_root}/GE-Proton11-6-aarch64-direct"

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

# CEF leaves its named shared-memory files behind when SteamUI restarts. A
# handful of those 25 MiB files can exhaust the deliberately small tmpfs and
# put steamwebhelper into a restart loop. Remove only this user's unopened
# Steam objects; fuser protects objects which are still owned by a live client.
if command -v fuser >/dev/null 2>&1; then
    shopt -s nullglob
    steam_shm_objects=(
        "/dev/shm/u$(id -u)-Shm_"*
        "/dev/shm/u$(id -u)-ValveIPCSharedObj-Steam"
    )
    shopt -u nullglob
    for steam_shm_object in "${steam_shm_objects[@]}"; do
        if [[ ! -d "${steam_shm_object}" ]] && ! fuser -s "${steam_shm_object}"; then
            rm -f -- "${steam_shm_object}"
        fi
    done
    unset steam_shm_object steam_shm_objects
fi

if [[ -x "${direct_compat_source}/proton" ]]; then
    mkdir -p -- "${direct_compat_root}"
    if [[ -L "${direct_compat_target}" ]]; then
        linked_target=$(readlink -- "${direct_compat_target}")
        if [[ "${linked_target}" != "${direct_compat_source}" ]]; then
            echo "Refusing unexpected compatibility-tool link: ${direct_compat_target}" >&2
            exit 126
        fi
    elif [[ -e "${direct_compat_target}" ]]; then
        echo "Refusing existing compatibility-tool path: ${direct_compat_target}" >&2
        exit 126
    else
        ln -s -- "${direct_compat_source}" "${direct_compat_target}"
    fi
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
