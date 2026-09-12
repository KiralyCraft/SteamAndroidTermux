# Steam System V semaphore shim

This preload library supplies the System V semaphore calls used by the native
ARM64 Steam client on kernels where `semget(2)` returns `ENOSYS`. It stores
per-user semaphore state in `/dev/shm/steam-sysvsem-UID` and serializes updates
with `flock(2)`.

Build and test it with:

```sh
make clean all test
```

The Steam launcher in the parent directory loads the library automatically:

```sh
../run-steam-arm64.sh
```

`/dev/shm` must be a mounted tmpfs. In this chroot the mount is intentionally
nonpersistent and can be recreated with:

```sh
sudo mount -t tmpfs -o size=512M,nosuid,nodev,mode=1777 tmpfs /dev/shm
```

This is a narrow compatibility layer, not a complete kernel System V IPC
implementation. It ignores `SEM_UNDO`, reports `GETNCNT` and `GETZCNT` as zero,
uses polling for blocked operations, and does not enforce System V permission
checks. It should therefore be used only for this local, single-user Steam
installation. Stop Steam before manually removing its state directory.
