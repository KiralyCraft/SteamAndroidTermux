# SteamAndroidTermux

SteamAndroidTermux is a small set of compatibility tools for running Valve's
native ARM64 Steam desktop client inside an AArch64 Linux chroot on an Android
kernel. It is intended for devices where Steam can run natively as ARM64, while
Windows games are translated by an ARM64 GE-Proton build with embedded FEX.

This is not a replacement Steam client, a Steam emulator, or a repack of
Valve's files. It does not bypass authentication, ownership checks, or Steam's
content system. The repository contains only the local launcher, UI recovery
helper, compatibility-tool descriptor, and a narrow System V semaphore shim.
Steam and GE-Proton must be supplied separately and are excluded from Git.

The project exists because the available ARM64 client assumes parts of the
Steam Frame/SteamOS platform that are absent in a generic Android-hosted
chroot. On the tested system, the client can authenticate and download content,
but its desktop UI stalls during the post-login handoff, receives an empty game
list, and cannot use the normal launch path for Windows games. The tools here
bridge those specific gaps without installing the x86 Steam package or Arch
multilib packages.

## Tested setup

The current code has been tested with this arrangement:

- an AArch64 Arch Linux userspace running as a chroot on an Android kernel;
- Termux:X11 as the X server;
- Mesa/Turnip graphics on an Adreno GPU;
- Valve's native `linuxarm64` desktop client installed under `./Steam`;
- `GE-Proton11-6-aarch64` installed under
  `/opt/proton-ge/GE-Proton11-6-aarch64`;
- the FEX support embedded in that Proton bundle, rather than host-side x86 or
  multilib packages; and
- a private 512 MiB tmpfs mounted at `/dev/shm` inside the chroot.

Other AArch64 distributions or X servers may work, but have not been verified.
This is experimental and tied to undocumented SteamUI internals, so a future
client update can require changes here.

## What the compatibility layer fixes

`run-steam-arm64.sh` sets the ARM64 runtime paths and preloads the semaphore
shim. It also registers the direct GE-Proton descriptor and starts
`steam-ui-watchdog.py`.

Together they provide the following behavior:

- System V semaphore calls used by Steam work on an Android kernel where
  `semget(2)` returns `ENOSYS`.
- A client stuck at Steam's `WaitingForLibraryReady` state completes the missed
  logged-in desktop-UI initialization.
- Entitled games are reconstructed from the local `appinfo.vdf` cache and
  verified with the logged-in Steam client before being shown in Library.
- Local artwork metadata is restored for the game list, grid, and app pages.
- Library routes survive the forced post-login SteamUI initialization.
- Stale, unopened Steam CEF shared-memory objects are removed before startup so
  they cannot fill the deliberately small `/dev/shm` mount.
- The normal Library Install action schedules `app_install` through Steam's own
  content service. Downloads, depots, verification, and app manifests remain
  Steam-managed.
- Properties -> Compatibility can display and persist
  `GE-Proton11-6-aarch64 (direct)` as the selected compatibility tool.
- Play launches a locally installed Windows executable through the ARM64 Proton
  bundle, while keeping Steam's Running/Stop state synchronized.
- Stop terminates only processes carrying that game's exact Proton data path,
  with a short SIGTERM grace period before SIGKILL.

## What is not included

You must provide:

1. A working AArch64 Linux chroot with an X display and usable graphics stack.
2. Valve's native ARM64 Steam client files.
3. An ARM64 GE-Proton bundle that includes the required x86 translation layer.

The expected repository layout after supplying Steam is:

```text
SteamAndroidTermux/
├── Steam/
│   ├── steamrtarm64/steam
│   ├── appcache/
│   └── steamapps/
├── compatibilitytools/
├── sysvipc-shim/
├── run.sh
├── run-steam-arm64.sh
└── steam-ui-watchdog.py
```

The default Proton layout is:

```text
/opt/proton-ge/GE-Proton11-6-aarch64/proton
```

Set `GE_PROTON_ARM64_ROOT` when starting Steam if the bundle lives elsewhere:

```sh
GE_PROTON_ARM64_ROOT=/path/to/GE-Proton11-6-aarch64 ./run.sh
```

`extract-steam-seed.py ARCHIVE DESTINATION` is available for an initial ZIP
payload. It rejects path traversal and unsafe absolute symlinks, normalizes the
mixed path separators found in the seed, and preserves executable modes. The
repository intentionally does not automate downloading undocumented client
payloads. Once a valid client tree exists, Steam's own updater manages it.

## Host requirements

The helper scripts use only the Python standard library. The host/chroot needs:

- Bash and Python 3.9 or newer;
- a C compiler and `make` to build the semaphore shim;
- `mount` and `mountpoint` from util-linux;
- `sudo` when the chroot user is not root;
- `fuser` from psmisc for guarded stale-shared-memory cleanup; and
- the normal runtime and graphics dependencies required by the supplied ARM64
  Steam and Proton builds.

No Arch `lib32-*` or multilib packages are installed by this repository. It
also makes no persistent package-manager, udev, or Android-system changes.

## Build and start

Clone the repository into a location with enough space for the Steam client,
Proton prefixes, and games:

```sh
git clone https://github.com/KiralyCraft/SteamAndroidTermux.git
cd SteamAndroidTermux
```

Optionally build and test the C shim up front:

```sh
make -C sysvipc-shim clean all test
```

The recommended entry point creates the chroot-local `/dev/shm` directory,
mounts a 512 MiB tmpfs there when needed, rebuilds an absent or outdated C
shim, checks the X display, applies the tested software-CEF flags, and starts
the lower-level launcher and UI watchdog:

```sh
./run.sh
```

It defaults to `DISPLAY=:0`; set `DISPLAY` first if the X server uses another
display. Mounting requires root, so `run.sh` invokes `sudo` only when it must
create or mount `/dev/shm`. An existing non-tmpfs mount or a non-empty unmounted
directory is rejected rather than hidden.

The equivalent manual mount and lower-level launch are:

```sh
export DISPLAY=:0
sudo mkdir -p /dev/shm
sudo mount -t tmpfs -o size=512M,nosuid,nodev,mode=1777 tmpfs /dev/shm
./run-steam-arm64.sh -cef-disable-gpu -cef-disable-gpu-compositing
```

Set `STEAM_ARM64_SHM_SIZE` to override the tmpfs size. Set
`STEAM_ARM64_CEF_GPU=1` only to experiment with Steam's CEF GPU path instead of
the tested `-cef-disable-gpu -cef-disable-gpu-compositing` defaults.
`STEAM_ARM64_PREPARE_ONLY=1 ./run.sh` performs the preparation and checks
without starting another Steam process.

The launcher refuses to start if `Steam/steamrtarm64/steam`, the semaphore
shim, or the `/dev/shm` mount is missing. It creates only one managed symlink in
`Steam/compatibilitytools.d`, and refuses to overwrite an unexpected file at
that location.

On first start, let the client finish its self-update and sign in normally.
The UI recovery may take a little longer than a normal desktop start because it
first gives Steam's native handoff a chance to complete. Do not pass
`-steamdeck`: this project targets the desktop UI, while Steam's Gaming Mode
expects additional SteamOS/Steam Frame platform services.

## Installing and launching a Windows game

After Library appears:

1. Select an uninstalled game and use its normal blue Install action. The
   fallback installs into Steam's default library; the folder-selection wizard
   is not used.
2. Open Properties -> Compatibility.
3. Enable **Force the use of a specific Steam Play compatibility tool**.
4. Select **GE-Proton11-6-aarch64 (direct)**.
5. Press Play. The entry should change to Running and then expose Stop.

For Windows-only titles, the Install fallback selects the direct tool
automatically as well. The explicit Properties steps are still useful as a
visual and persisted confirmation.

The direct descriptor delegates to the ARM64 Proton executable under `/opt`.
It deliberately omits the Steam Frame-only Steam Runtime dependency that the
generic client rejects as an invalid platform. Neither the Proton bundle nor
system packages are modified.

## Verified end-to-end example

On 2026-09-12, Else Heart.Break() (AppID 400110) was tested through the visible
desktop UI:

- the normal Install action downloaded and verified the depot;
- Steam committed a fully installed app manifest and 1.4 GB game directory;
- the Compatibility page retained the direct ARM64 GE-Proton selection across
  a full Steam restart;
- Play started the real 32-bit Windows game executable and produced a rendered
  game window through Proton/FEX;
- Steam displayed Running and the normal Stop confirmation dialog; and
- confirmed Stop removed the game and every process carrying its exact Proton
  prefix, after which Steam returned the entry to the normal Play state.

The same cold restart restored all 338 subscribed Library entries and their
available list, capsule, hero, and logo artwork. These numbers describe this
test account and client cache; they are evidence of the tested flow, not fixed
project limits.

## Current limitations

- The app-overview and Properties repairs depend on SteamUI module internals.
- GUI Install currently targets only the default Steam library.
- The direct Play bridge handles installed Windows games whose app metadata has
  a discoverable Windows executable. Complex launch-option pickers and custom
  command arguments are not yet reproduced.
- Overlay, cloud synchronization, achievements, controller configuration,
  SteamVR, and every game-specific Proton behavior are not claimed as working.
- The semaphore implementation is intentionally incomplete and appropriate
  only for a local, single-user Steam process tree. See
  `sysvipc-shim/README.md` for its exact scope.
- A game can still have its own rendering or compatibility bug after Steam has
  launched it successfully.

## Diagnostics and rollback

Useful logs are written below `Steam/logs/`, including
`arm64-game-launcher.log` for direct Proton startup. Proton also writes its
per-game log there when enabled by the launcher.

For a diagnostic run without the SteamUI patch, disable the workaround:

```sh
STEAM_ARM64_UI_WORKAROUND=0 ./run.sh
```

This also skips the direct GUI launch bridge, but still loads the semaphore
shim and ARM64 runtime paths.

To remove the runtime changes, stop Steam, remove the generated
`Steam/compatibilitytools.d/GE-Proton11-6-aarch64-direct` symlink, and unmount
the temporary shared-memory filesystem if nothing else in the chroot uses it:

```sh
sudo umount /dev/shm
```

Do not remove `/dev/shm` semaphore state while Steam is running.

## Repository contents

- `extract-steam-seed.py` safely extracts an initial client ZIP.
- `verify-installed-steam.py` validates file types and sizes against Steam's
  installed bootstrap manifest.
- `run.sh` is the recommended entry point; it prepares `/dev/shm`, builds the
  shim when needed, validates the X display, and applies the tested CEF flags.
- `run-steam-arm64.sh` prepares the runtime, guarded shared-memory cleanup, and
  UI watchdog.
- `steam-ui-watchdog.py` repairs post-login SteamUI, Library data, GUI install,
  compatibility selection, and direct Play/Stop integration without external
  Python packages.
- `compatibilitytools/GE-Proton11-6-aarch64-direct/` exposes the existing ARM64
  GE-Proton bundle to Steam without copying it.
- `sysvipc-shim/` contains the C semaphore shim, symbol map, tests, and detailed
  scope documentation.

Downloaded Valve files, game data, Proton prefixes, logs, traces, and compiled
artifacts are ignored by Git.
