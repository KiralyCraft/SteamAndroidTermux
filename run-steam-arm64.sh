#!/usr/bin/bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
steam_root="${script_dir}/Steam"
steam_arm_dir="${steam_root}/steamrtarm64"
steam_shim_dir="${steam_root}/lib/aarch64-linux-gnu"
steam_runtime_bin="${steam_root}/steam-runtime-steamrt-arm64/bin"
sysvsem_shim="${script_dir}/sysvipc-shim/libsysvsem-shim.so"

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

export LD_LIBRARY_PATH="${steam_arm_dir}:${steam_shim_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export LD_PRELOAD="${sysvsem_shim}${LD_PRELOAD:+:${LD_PRELOAD}}"
export PATH="${steam_runtime_bin}:${PATH}"

cd "${steam_arm_dir}"
exec "${steam_arm_dir}/steam" -steamdeck "$@"
