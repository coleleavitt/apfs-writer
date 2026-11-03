# Why iOS wouldn't boot an apfs-writer ramdisk (root cause + fix)

**Date:** 2026-11-03 · **Status:** fixed in `src/builder.rs` (`make_volume`/`make_spaceman`),
device boot re-test pending.

## Symptom
An SSH ramdisk whose `ramdisk.img4` was built by apfs-writer (via `apfs-pack`) caused iOS
(A13, iPhone12,5, iOS 26.6.2 / 23G90) to fall back to **iBoot Recovery** right after `bootx`.
The *same* bootchain with a `ramdisk.img4` built by macOS `newfs_apfs`/`hdiutil` booted to a
root SSH shell. Everything else in the chain was identical.

## What was NOT the problem (ruled out, not guessed)
- apfs-writer's image is **apfsck -cuw clean** and mounts in **apfs-fuse** (RO).
- The **linux-apfs-rw kernel module** (strict, real RW mounter) mounts it too (RO; RW falls
  back the same way for the macOS image).
- Container (NXSB) + volume (APSB) superblock fields match macOS: features/incompat/ro-compat,
  fs_flags, role, tree types, omap. Earlier cosmetic deltas (formatted_by/modified_by version
  strings, `fext_tree_type`) were matched to macOS too, but were not the blocker.

## Root cause (confirmed by reverse-engineering apfs 2811.160.7)
iOS mounts the RestoreRamDisk **read-write** (`rd=md0`, the restore env writes to it). Apple's
apfs kext, on a **version-0 ("non-versioned") space manager**, runs
`spaceman_upgrade_sm_version_0_to_1` **during the mount** — a write migration. That write
during early-boot ramdisk mount does not complete, the mount fails, and the device drops to
Recovery. macOS `newfs_apfs` writes a **version-1** spaceman, so no upgrade runs → clean mount.

Evidence (iOS kernelcache `com.apple.filesystems.apfs`, extracted with `ipsw`, decompiled with
IDA/idalib):
- `sub_FFFFFFF009BE042C` (the upgrade): reads `sm_flags` at **offset 144**; when bit0
  (`APFS_SM_FLAG_VERSIONED`) is clear it inserts **0x888 (2184) bytes** at offset 336 and shifts
  the internal-pool offset fields (`sm_ip_bm_xid_offset`@324, `sm_ip_bitmap_offset`@328,
  `sm_ip_bm_free_next_offset`@332, `sm_dev[0].sm_addr_offset`@80, `sm_dev[1]`@128) by +2184.
- Log strings: `"failed to upgrade spaceman from version 0 to 1: %d"`,
  `"refusing to upgrade spaceman! new_smp_size %u old_smp_size %u block_size %u"`.
- `apfs_mount_upgrade_checks` (`sub_FFFFFFF009BFD810`) only *gates* write-upgrades (refuses on a
  snapshot mount / disallowed r→w); it does not perform the migration.
- All other on-mount `*_upgrade_*` / `*migrat*` paths are **encryption** (`apfs_migrate_aks_key_class`,
  media-key / pfk / prot-class). Our volume is `APFS_FS_UNENCRYPTED`, so none apply.

## The version-1 spaceman (byte-exact, verified against the macOS ramdisk)
| field | offset | v0 (old apfs-writer) | v1 (macOS newfs_apfs & apfs-writer now) |
|---|---|---|---|
| `sm_flags` | 144 | 0 | **1** (`APFS_SM_FLAG_VERSIONED`) |
| `sm_version` | 336 | (clobbered by data) | **1** |
| `sm_struct_size` | 340 | 0 | **2520** (0x9D8 — data start, after a 2184-byte datazone) |
| `sm_ip_bm_xid_offset` | 324 | 336 | **2520** |
| `sm_ip_bitmap_offset` | 328 | 344 | **2528** |
| `sm_ip_bm_free_next_offset` | 332 | 352 | **2536** |
| `sm_dev[0].sm_addr_offset` | 80 | 384 | **2568** |
| `sm_dev[1].sm_addr_offset` | 128 | 0 | **2576** |

i.e. the internal-pool arrays start at `0x150 + 0x888 = 0x9D8` (2520) instead of `0x150`, the
2184-byte datazone sits between the fixed header and the arrays, and the VERSIONED flag +
version + struct_size are set. apfs-pack's output now matches macOS on every one of these.

## Fix
`src/builder.rs`: `const BITMAP_XID_OFF = 0x150 + SM_DATAZONE_LEN (0x888)`; `make_spaceman`
sets `sm_flags@144=1`, `sm_version@336=1`, `sm_struct_size@340=0x9D8`, and `sm_dev[1]@128`.

## Remaining to prove e2e
Boot test on the device: known-good macOS bootchain with **only** the apfs-pack v1 ramdisk
swapped in. If it boots to SSH, apfs-writer is at parity for the ramdisk use case. (The xid
stays 1 — a single-transaction container — which every Linux validator and, per the RE, the
mount path accept; only the spaceman version gated the mount.)
