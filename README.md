# Native ARM64 Steam bootstrap tools

This directory contains the locally authored tooling used to run Valve's native
ARM64 Steam client on an Android-kernel Arch Linux chroot without installing
Steam or multilib packages through `pacman`.

The kernel does not implement System V IPC semaphores. The preload library in
`sysvipc-shim/` supplies the subset required by Steam, backed by files and
`flock(2)` under `/dev/shm`. See `sysvipc-shim/README.md` for its deliberately
narrow compatibility scope.

## Launch

Build and test the shim:

```sh
make -C sysvipc-shim clean all test
```

Ensure the chroot-local shared-memory mount exists:

```sh
sudo mkdir -p /dev/shm
sudo mount -t tmpfs -o size=512M,nosuid,nodev,mode=1777 tmpfs /dev/shm
```

Then start the installed client:

```sh
./run-steam-arm64.sh
```

The mount is intentionally not persistent. The launcher detects a missing
mount and prints the command needed to restore it.

## Included tools

- `extract-steam-seed.py` safely normalizes Valve's mixed path separators and
  preserves archive symlinks and executable modes.
- `verify-installed-steam.py` checks the installed manifest's directory,
  symlink, regular-file, and size records.
- `run-steam-arm64.sh` supplies the local runtime paths and semaphore preload.
- `sysvipc-shim/` contains the C source, test program, and build rules.

Steam itself, downloaded archives, logs, traces, and generated binaries are
excluded from Git.
