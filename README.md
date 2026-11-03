# apfs-writer

A pure-Rust APFS container builder. It writes complete, `apfsck`-clean APFS
containers from scratch — no macOS, no diskutil, no HFS+ bridging — and
supports injecting regular files into the volume's catalog.

Built as part of an iPhone A13 SSH-ramdisk project, but the builder itself is
generic: it writes valid containers at any size (tested from 4096 blocks to
17 TB apparent size via sparse images) and passes `apfsck -cuw` (crash, unknown,
weird) at every size tested.

A ramdisk built on Linux with `apfs-pack` boots iOS to a root SSH shell
(iPhone12,5, iOS 26.6.2 / 23G90), in the same bootchain as a macOS-built one.
See [iOS ramdisks](#ios-ramdisks) below.

## Usage

```console
$ cargo run --release [-- <image-path> <block-count>]
```

Defaults to `/tmp/test_container.apfs` with 4096 blocks. The default build
seals the container and injects one file (`hello.txt`) into the volume root;
use the library API (`ContainerBuilder`) for real injections.

Self-check prints `checksummed objects: N ok, 0 bad (of N sealed)` — the exact
set of objects the builder sealed, each verified over its full length.

## apfs-pack: build a ramdisk from a stock image

```console
$ apfs-pack --out ramdisk.dmg --size-mb 280 --image stock.dmg --tar ssh.tar.gz [--tar more.tar.gz] [--src dir]
```

Sources apply in order `--image`, `--src`, `--tar`; later ones override earlier paths.
`--image` reads the first volume of an unencrypted APFS container with the built-in reader
(`src/reader.rs`) and copies it as stored: compressed files keep their `com.apple.decmpfs`
xattr and resource fork (apfs-fuse cannot serve forks over 64 KiB, so copy from the image,
not from a mount). Owner, mode and mtime are kept; tar and `--src` entries are owned by
root:root unless `--keep-owner`. Symlinks, directories, regular and compressed files are
supported; other file types are skipped. Names must be ASCII.

The volume is normalization-insensitive and case-sensitive, like the iOS ramdisk volume.
Catalog, extent-reference and volume-omap trees are multi-level (`src/tree.rs`).
Check output with `apfsck -cw` (`-u` reports the real `fpmc` decmpfs signature as unknown).

## What it builds

- NXSB (container superblock) + checkpoint ring: CPMAP/NXSB descriptor+data pairs
- Container and volume object maps (fixed-kv B-tree roots)
- Spaceman: CIBs and CABs, per-chunk allocation bitmaps, internal pool,
  free queues, device free counts — all derived from the real layout, any size
- Volume superblock (case-sensitive, normalization-insensitive, as iOS volumes are),
  catalog tree with drec / inode / file-extent records, extref tree, snapmeta tree
- File injection: hashed drec keys, inode with name and DSTREAM xfields,
  DSTREAM_ID records, content blocks placed past the IP

## Findings that made it work

Documented here because they cost real time to get right (all validated
against apfsprogs source and mkapfs, never from memory):

- **fletcher64** covers `block[8..]` — excluding (not zeroing) the checksum
  field; fold `(s & 0xffffffff) + (s >> 32)` per 0x16a00-word chunk;
  stored = `~(s2+s1 mod M) | ~(low+s1 mod M) << 32`
- **Catalog records are sorted by apfsck's keycmp** — (obj id, type, number,
  name), where number is `hash & ~0x3FF` for drecs and the logical address for
  extents. Sorting raw LE key bytes is not equivalent.
- **Hashed drec keys** (normalization-insensitive volumes hash names even when
  case-sensitive): `crc32c(0xFFFFFFFF, LE-u32 per
  char)`, stored field = `((crc & 0x3FFFFF) << 10) | (namelen+1)` — the hash is
  already shifted; don't shift twice.
- **Inode xfields**: value length is `92 + 4 + 4 + round_up(namelen+1, 8)`;
  `xf_used_data` counts the padded data bytes only (apfsck semantics), each
  xfield's data starts at its own offset, and padding after the name must be
  zero.
- **Multi-block objects get one checksum over the whole object** — per-block
  checksums on the spaceman silently pass self-checks and fail fsck.
- **`nx_max_file_systems`** = `ceil(size / 512 MiB)` capped at 100 (mkapfs
  `get_max_volumes`) — hardcoding 1 breaks large containers.
- Spaceman field offsets after `sm_dev[]`, chunk_info/CIB/CAB sizes, free-queue
  node limits (including the `ret == 2 -> 3` fixup), and checkpoint block caps
  were all taken from mkapfs/apfsprogs via `offsetof` checks.

## iOS ramdisks

apfs-writer matches what macOS `newfs_apfs` writes in three places that go beyond being
`apfsck`-clean. Each was checked against the iOS apfs kext (2811.160.7, decompiled with IDA):

- **Version-1 space manager.** `sm_flags` VERSIONED bit set, `sm_version = 1`,
  `sm_struct_size = 0x9D8`, and the internal-pool arrays after a 2184-byte datazone. On a
  version-0 one, the kext's read-write transition (`nx_ro_to_rw`) rewrites it in place. This is
  the only one of the three the kext acts on.
- **A valid transaction history on the volume.** The creation xid (`formatted_by.last_xid`) is
  strictly less than the last-modified xid (`modified_by[0].last_xid`), which doesn't exceed the
  container's xid. The builder writes the container at xid 2 with the volume created at xid 1.
  Writing everything at xid 1 trips apfsck's "transaction is too recent"; the kext doesn't check it.
- **The volume fields the kext's own new-volume code sets**: `fext_tree_type`, `reserved_type`,
  `doc_id_tree_type` and `sec_root_tree_type`. Nothing in the mount path reads them.

Against a ramdisk built on macOS from the same stock image, the `apfs-pack` output has the same
file tree, all files byte-identical, and the same mode and symlink targets. Two things differ.
There's no `.fseventsd/`, the journal the Mac creates when it mounts the image. And files injected
from tarballs are owned by root, where the macOS build gives them `99:99` because it mounts the
image with ownership off. Apple's own stock files are root-owned in both.

The root ramdisk mounts read-only on iOS, and `mount -uw /` fails with EPERM. That's the kext's
rule for any APFS root filesystem (`apfs_mount_upgrade_checks`), not something about the image;
macOS-built ramdisks behave the same.

### Checking a ramdisk before it goes on a device

1. `apfsck -cw ramdisk.dmg` must print nothing. (`-u` reports the real `fpmc` decmpfs
   signature as unknown, which is expected.)
2. Mount it read-only with `apfs-fuse` and compare the file tree against a known-good ramdisk.
3. The strict kernel test: the [linux-apfs-rw](https://github.com/linux-apfs/linux-apfs-rw) module,
   `mount -t apfs -o loop,readwrite,cknodes`. Write a file, unmount, then run `apfsck -cw` again.
   This makes the kernel commit its own transactions on top of the image.
4. On the device, put only the new `ramdisk.img4` into a bootchain that's known to work, and boot.

Full notes, including the kext functions and offsets behind each point:
[`notes/ios-ramdisk-boot.md`](notes/ios-ramdisk-boot.md).

## Status

Done for its purpose. Known limits: no tier-2 (fusion) devices, CABs above
1000 are capped by the same limits as mkapfs, and the internal pool spilling
past chunk 0 is exercised but the >4M-block region is untested.

## Reference

The builder is ported from mkapfs and apfsck in
[linux-apfs/apfsprogs](https://github.com/linux-apfs/apfsprogs). The vendored copies of those
sources (`reference/`, `reference_*`) are kept locally and are not in this repository.
