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

The launcher also starts `steam-ui-watchdog.py`. The current native ARM64
client can authenticate and connect successfully but remain in
`WaitingForLibraryReady`, which prevents SteamUI from receiving its final
logged-in transition. The watchdog waits five seconds for the native path,
then performs the missed UI initialization through Steam's localhost-only CEF
debugger. If the unavailable Friends Chat interface leaves its optional startup
promise pending, the watchdog releases that gate after its built-in timeout.

The workaround does not read or print credentials and exits after the UI is
ready. Disable it for an unmodified diagnostic launch with:

```sh
STEAM_ARM64_UI_WORKAROUND=0 ./run-steam-arm64.sh
```

The launcher intentionally starts Steam's desktop UI. Passing `-steamdeck`
forces the SteamOS Gaming Mode shell, which depends on platform components that
are not present in this chroot and can remain stuck on its startup spinner.

The mount is intentionally not persistent. The launcher detects a missing
mount and prints the command needed to restore it.

## Included tools

- `extract-steam-seed.py` safely normalizes Valve's mixed path separators and
  preserves archive symlinks and executable modes.
- `verify-installed-steam.py` checks the installed manifest's directory,
  symlink, regular-file, and size records.
- `run-steam-arm64.sh` supplies the local runtime paths and semaphore preload.
- `steam-ui-watchdog.py` recovers the ARM64 client's missed post-login UI
  handoff without external Python packages.
- `sysvipc-shim/` contains the C source, test program, and build rules.

Steam itself, downloaded archives, logs, traces, and generated binaries are
excluded from Git.
