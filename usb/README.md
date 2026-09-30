# KernelGuard live USB

A bootable stick that scans the machine it is plugged into and writes the report back onto
the stick.

## What it does

1. Boots a small live Linux (distro kernel, busybox initramfs) from the stick.
2. Loads `kernelguard.ko` in that kernel and records the hardware/firmware posture it sees.
3. Mounts the machine's own drives **read-only** and lists every Linux kernel module
   (`/lib/modules`) and every Windows driver (`Windows/System32/drivers/*.sys`) with its SHA-256.
4. Matches them against the deny lists in `KGDATA/blocklist/` (see `blocklist/README.txt`).
5. Writes `reports/<timestamp>/report.txt` (plus the raw lists) to the `KGDATA` partition and powers off.

A match is a line starting with `FINDING` in `report.txt`. The stick never writes to the host's drives.

## Build and flash

```sh
usb/build-image.sh                      # -> usb/out/kernelguard-live.img (+ .sha256)
sudo usb/flash.sh /dev/sdX              # asks for confirmation, verifies after writing
```

The image is built without root. `build-image.sh` needs `busybox cpio sgdisk mtools dosfstools
grub-efi-amd64-bin` (and `grub-pc-bin` for legacy BIOS boot). Set `KG_KERNEL` if
`/boot/vmlinuz-*` is root-only; see the header of the script.

## Layout of the stick

| Partition | FS    | Content |
|-----------|-------|---------|
| 1         | none  | GRUB core image for BIOS boot |
| 2 `KGBOOT`| FAT32 | GRUB (UEFI + BIOS), kernel, initramfs |
| 3 `KGDATA`| FAT32 | `reports/`, `blocklist/`, `linux/` (the .deb), `windows/` (driver package) |

`KGDATA` is readable from Windows, macOS and Linux. `windows/` holds `KernelGuard.inf`,
`Deploy-KernelGuard.ps1` and, if you set `KG_WINDOWS_DIR`, the built driver files.

## Limits

- **Secure Boot.** The stick's GRUB and the module are not signed for Secure Boot. Either turn
  Secure Boot off in firmware, or sign the module (`KG_SIGN_KEY`/`KG_SIGN_CERT`) and enroll the
  certificate with `mokutil --import`. Without that the report says
  `module NOT loaded` and the host-drive audit still runs.
- **One kernel.** The image carries the kernel it was built against (`KG_KVER`).
- **What the module sees.** It monitors the *live* kernel's hardware and firmware state. It cannot
  inspect the installed OS's running kernel; that is what the drive audit is for.
- **Windows.** There is no WinPE scanner yet. Windows hosts are audited by the live Linux system,
  and the driver package on `KGDATA` is for installing KernelGuard on a running Windows machine.
  That package path has not been run on Windows.
