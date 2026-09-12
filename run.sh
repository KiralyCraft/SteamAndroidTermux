#!/usr/bin/bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
shm_path=/dev/shm
shm_size=${STEAM_ARM64_SHM_SIZE:-512M}
shim_dir="${script_dir}/sysvipc-shim"
shim_library="${shim_dir}/libsysvsem-shim.so"
steam_executable="${script_dir}/Steam/steamrtarm64/steam"
steam_launcher="${script_dir}/run-steam-arm64.sh"
proton_root=${GE_PROTON_ARM64_ROOT:-/opt/proton-ge/GE-Proton11-6-aarch64}

if [[ ! "${shm_size}" =~ ^[1-9][0-9]*[KMG]$ ]]; then
    echo "Invalid STEAM_ARM64_SHM_SIZE: ${shm_size}" >&2
    exit 2
fi
if [[ ! -x "${steam_executable}" ]]; then
    echo "ARM64 Steam executable is missing: ${steam_executable}" >&2
    exit 127
fi
if [[ ! -x "${steam_launcher}" ]]; then
    echo "Steam launcher is missing: ${steam_launcher}" >&2
    exit 127
fi

run_as_root() {
    if (( EUID == 0 )); then
        "$@"
    else
        sudo "$@"
    fi
}

if [[ -L "${shm_path}" || ( -e "${shm_path}" && ! -d "${shm_path}" ) ]]; then
    echo "Refusing unsafe shared-memory path: ${shm_path}" >&2
    exit 126
fi

if [[ ! -d "${shm_path}" ]]; then
    run_as_root mkdir -p -- "${shm_path}"
    run_as_root chmod 1777 "${shm_path}"
fi

if ! mountpoint -q "${shm_path}"; then
    if find "${shm_path}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
        echo "Refusing to mount over non-empty ${shm_path}" >&2
        exit 126
    fi
    echo "Mounting ${shm_size} tmpfs at ${shm_path}..."
    run_as_root mount -t tmpfs \
        -o "size=${shm_size},nosuid,nodev,mode=1777" \
        tmpfs "${shm_path}"
fi

shm_type=$(findmnt -n -o FSTYPE -T "${shm_path}")
if [[ "${shm_type}" != tmpfs ]]; then
    echo "Refusing non-tmpfs shared-memory mount at ${shm_path}: ${shm_type}" >&2
    exit 126
fi
if [[ $(stat -c %a "${shm_path}") != 1777 ]]; then
    run_as_root chmod 1777 "${shm_path}"
fi

if [[ ! -r "${shim_library}" \
      || "${shim_dir}/sysvsem_shim.c" -nt "${shim_library}" \
      || "${shim_dir}/sysvsem.map" -nt "${shim_library}" \
      || "${shim_dir}/Makefile" -nt "${shim_library}" ]]; then
    echo "Building the System V semaphore shim..."
    make -C "${shim_dir}" libsysvsem-shim.so
fi

if [[ ! -x "${proton_root}/proton" ]]; then
    echo "Warning: ARM64 GE-Proton is missing: ${proton_root}/proton" >&2
    echo "Steam can start, but the direct Windows-game launcher will not work." >&2
fi

export DISPLAY=${DISPLAY:-:0}
if command -v xdpyinfo >/dev/null 2>&1 \
   && ! xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
    echo "X display is unavailable: ${DISPLAY}" >&2
    exit 126
fi

if [[ "${STEAM_ARM64_PREPARE_ONLY:-0}" == 1 ]]; then
    echo "ARM64 Steam prerequisites are ready."
    exit 0
fi

steam_arguments=("$@")
if [[ "${STEAM_ARM64_CEF_GPU:-0}" != 1 ]]; then
    steam_arguments=(
        -cef-disable-gpu
        -cef-disable-gpu-compositing
        "${steam_arguments[@]}"
    )
fi

exec "${steam_launcher}" "${steam_arguments[@]}"
