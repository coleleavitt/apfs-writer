# apfs-writer — Claude Instructions

## Mission
A pure-Rust APFS container builder — a faithful port of `mkapfs` (linux-apfs/apfsprogs). It
writes complete, `apfsck -cuw`-clean APFS containers from scratch on Linux (no macOS, no
diskutil, no HFS+ bridging) and can inject files. Built for one concrete job: produce an
iOS SSH-ramdisk `ramdisk.img4` on Linux that **iOS will actually boot**, matching what macOS
`newfs_apfs` emits closely enough that Apple's apfs kext mounts it without on-mount migration.

## Architecture First
- `src/builder.rs` — the container builder: NXSB (container super) + checkpoint, container
  omap, volume (`make_volume` = APSB), spaceman (`make_spaceman`), catalog/extref/omap b-trees.
  All on-disk offsets are ported field-by-field from apfsprogs/mkapfs (`reference/`), never
  from memory.
- `src/tree.rs` — multi-level b-tree node builder (catalog, extentref, omap).
- `src/reader.rs` — minimal APFS reader: pulls the first volume's root tree out of an existing
  container (used by `apfs-pack --image` to copy a stock ramdisk in).
- `src/ondisk.rs` — on-disk constants/structs.
- `src/bin/apfs-pack.rs` — the ramdisk tool: `--image <stock> --tar <ssh.tar.gz> --src <dir>`
  copies a stock APFS volume in, overlays tarballs/dirs, writes a new container. xattr reads
  tolerate `ENOTSUP`/`ENODATA` (Linux has no `com.apple.*` xattr namespace).
- `src/main.rs` — demo (one file) + the sealed-object self-check.

## Current State
- **iOS ramdisk boot: root cause found and fixed** — apfs-writer used to emit a *version-0*
  (non-versioned) space manager; iOS mounts the ramdisk r/w and ran a v0→v1 upgrade *write*
  that failed at boot → Recovery. `make_spaceman`/`make_volume` now emit a **version-1**
  spaceman byte-identical to macOS `newfs_apfs`. Full evidence + the exact v1 layout:
  **`notes/ios-ramdisk-boot.md`**. Device boot re-test is the only thing left to prove e2e.
- Large WIP in the working tree (reader/tree/bin split out of builder) — uncommitted.

## Working Rules
- **Port from the reference, not from memory.** Every struct/offset comes from apfsprogs/mkapfs
  (`reference/`) or verified against a real macOS-built image. When Apple-specific behavior is
  in play (mount validation, spaceman versioning), confirm it by RE of the iOS apfs kext, not
  assumption — see `notes/ios-ramdisk-boot.md` for the method (ipsw extract + IDA/idalib).
- Keep the output **`apfsck -cuw` clean** and mountable by apfs-fuse AND the linux-apfs-rw
  kernel module (strict r/w mounter — the closest proxy to iOS short of the device).
- Catalog records sorted by apfsck's keycmp; checksums are fletcher64; the self-check must stay
  green (`checksummed objects: N ok, 0 bad`).

## Validation
```sh
cargo build --release --bin apfs-pack
# structural parity vs a known-good macOS ramdisk (dump spaceman/superblock fields and diff)
# mount check (RO): apfs-fuse -o ro out.dmg mnt
# strict mount: build linux-apfs-rw (make APFS_CONFIG=-DCONFIG_APFS_RW_ALWAYS), insmod, loop-mount
# e2e: swap only ramdisk.img4 into a known-good macOS bootchain, boot the pwned device
```

## Project Claude Layout
- `CLAUDE.md` (this file): the guide. `MEMORY.md`: local state/handoff (git-ignored).
- `notes/ios-ramdisk-boot.md`: the RE-confirmed iOS boot root cause, v1 spaceman layout, fix.
- `reference/`: vendored apfsprogs/mkapfs source the builder is ported from.
