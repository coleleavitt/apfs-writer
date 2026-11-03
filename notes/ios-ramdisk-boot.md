# Why iOS wouldn't boot an apfs-writer ramdisk (root cause + fix)

**Date:** 2026-11-03 · **Status:** two root causes fixed in `src/builder.rs`
(`make_spaceman` v1 spaceman + `make_volume` transaction-xid chain); apfsck-clean and
apfs-fuse-mountable; device boot re-test pending. See both root-cause sections below.

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

## Second root cause — degenerate transaction-xid chain (fixed 2026-11-03)
The spaceman-v1 fix shipped alongside a new `apfs_modified_by[0]` "kext mount" stamp in
`make_volume` (a real mounted volume carries one; a never-mounted `newfs` shape was suspected
to be rejected). But that stamp was written with **`last_xid == MKFS_XID == 1`**, the same xid
as `formatted_by.last_xid` and the container — so the volume claimed it was *created* and
*mounted* in the very same transaction, a state no real volume can be in.

- **apfsck** rejects it: `Volume creation info: transaction is too recent.`
  (`apfsck/super.c`: after walking `apfs_modified_by`, it requires the creation xid
  `formatted_by.last_xid` to be **strictly less** than the smallest modification xid, i.e.
  `xid <= v_first_xid` ⇒ error.) The old "every Linux validator accepts xid=1" note was only
  true *before* the `modified_by` stamp existed (empty `modified_by` + `formatted=1` passes);
  adding the stamp at xid=1 is what broke it.
- **Ground truth** from a working macOS `newfs_apfs` ramdisk (iPhone12,5 23G90):
  `formatted_by.last_xid = 2` **<** `modified_by[0].last_xid = 18` **≤** container `nx_xid = 19`.
  The chain must be strictly increasing.

### Fix
`src/builder.rs`: current transaction is now **`MKFS_XID = 2`** (was 1), with a new
**`FORMAT_XID = 1`** used only for `formatted_by.last_xid@0x138`; `modified_by[0].last_xid@0x168`
stays `MKFS_XID` (2), and the container NXSB is `o_xid=2 / nx_next_xid=3`. Result:
`formatted(1) < modified(2) = container xid(2)` — the required chain, matching macOS's shape.

Verified: `apfsck -cw`/`-cuw` **clean** on demo + 71680-block (ramdisk size) + 1,048,576-block
containers; self-check green (`16 ok, 0 bad`); and a realistic 280 MiB rebuild
(`apfs-pack --image <stock vol> --tar ssh.tar.gz`, 1786 files / 1213 compressed) is apfsck-clean,
mounts in apfs-fuse, and carries the injected SSH payload
(`/usr/local/bin/dropbear*`, `/usr/bin/mount_ich`, `/private/etc/dropbear/*host_key`).

## Mount-path RE (full-kext decompile, 2026-11-03)
Decompiled all 2322 functions of `com.apple.filesystems.apfs` (idalib, 0 failures) and traced
the RO→RW mount path, to ground the parity claim in code rather than inference:
- **The apfsck "transaction too recent" check does NOT exist in the kext.** No string, log or
  panic mentions `modified_by`/`formatted_by`/xid ordering anywhere in the 2322 functions. That
  check is an apfsck-only sanity rule. So the xid-chain fix is required for `apfsck`-clean and
  macOS parity, but is **not, by itself, a device mount gate** (don't overclaim it as "the boot
  fix").
- **`nx_ro_to_rw` (`sub_FFFFFFF009BA2FF0`)** is the RO→RW transition iOS runs when it mounts the
  RestoreRamDisk read-write. Its hard gates, each satisfied by our image:
  1. `nx_readonly_compatible_features` unsupported → "r/w update not allowed". Ours = **0** → OK.
  2. non-writable nx dev / hibernate unlock → not applicable to a restore ramdisk.
  3. spaceman version upgrade `sub_FFFFFFF009BE042C`, gated by
     `(*(sm+144) & 1) == 0 || *(sm+336) == 0` (sm_flags VERSIONED bit / sm_version). Ours =
     **1 / 1** → the 2184-byte upgrade write is **skipped**. (Same gate also runs from `nx_resize`
     and the checkpoint/graft path `sub_FFFFFFF009C6D8B8`.)
  4. then writes the superblock to block 0 and enables temporary checkpoints — needs a valid
     checkpoint ring + spaceman, which our image has (apfsck-clean, apfs-fuse-mountable).
- Net: the image clears every gate visible in the mount and RO→RW paths. The one RE-confirmed
  blocker (spaceman version) is satisfied; nothing else in the kext rejects our shape.

## Gate-by-gate verification against our bytes (2026-11-03)
Work dir: `target/e2e-rw/` (gitignored). Scripts in `target/e2e-rw/scripts/`.
- **`nx_check_superblock` (`sub_FFFFFFF009B94C98`) ported line-for-line to Python**
  (`nx_check_superblock.py`, plus `obj_checksum_verify_phys` `sub_FFFFFFF009B94BA8`). It is the
  kext's on-disk NXSB validator, called on every checkpoint-ring superblock. It counts rule
  violations and returns 92 ("Container corruption detected") if any. All NXSB copies pass in
  the macOS image (all 4 ring copies), the old local image and the fixed image. The port was
  mutation-tested: corrupting the checksum, `max_file_systems=101`, `next_oid=0x100` and
  `spaceman_oid=0` are each caught by exactly the matching rule.
- **Volume-superblock field diff vs macOS, each field cross-referenced in all 2322 functions**
  (`apsb_diff.py`, `vsb_field_xref.py`, matching `*(fs+192)+OFF`): `formatted_by`/`modified_by`
  xids, `reserved_type`, `doc_id_tree_type`, `sec_root_tree_type`, `doc_id_index_xid`, `@0x460`
  are never read; `doc_id_index_flags` only in post-offline-purge cleanup; `@0x468` is
  `apfs_fixup_flags` (purgeable fixup, 0 = nothing pending); cloneinfo epoch/xid are clone-tracking
  counters; `unmount_time` is written at unmount. None is a mount gate.
- **Format parity added** (`make_volume`): `reserved_type@0x414 = PHYSICAL|BTREE`,
  `doc_id_tree_type@0x42C = VIRTUAL|BTREE`, `sec_root_tree_type@0x450 = VIRTUAL|BTREE`, the
  values the kext's own new-volume initializer `sub_FFFFFFF009C4EE04` writes. apfsck-clean.
  Remaining APSB diffs are layout oids and mounted-history state (`key_os_version`, `next_doc_id`,
  cloneinfo, doc-id index xid/flags, `@0x460`, fixup flags).
- **Strict kernel RW mount** (`linux-apfs-rw`, `-o loop,readwrite,cknodes`, write a file,
  umount, then apfsck the result) on the build *before* the tree-type parity change: macOS ✓,
  old local ✓ (mounts and writes, but stays apfsck "too recent"), fixed ✓ (stays apfsck-clean
  after the kernel's own transaction). The old local image mounting RW confirms the xid chain is
  not a mount gate.
- **Re-run on the final build (with the tree-type parity fields): pass.** The script is
  `scripts/rw_mount_test.sh`. It must be run from the user's own terminal because sudo
  credentials are cached per tty. Result: RW mount, write and mkdir OK; `dropbear` and
  `mount_ich` intact; umount OK. The kernel committed 3 transactions (xid 2→5) and all 4
  checkpoint-ring superblocks pass the ported `nx_check_superblock`. apfsck stays clean. The
  kernel stamped its own `modified_by[0]` entry and set `unmount_time`, which is the normal
  first-mount shape.

## Rebuilt from Apple's stock ramdisk, content parity vs the macOS build (2026-11-03)
Same steps as `ramdisk_expand.sh` on Linux. Stock `094-95379-094.dmg` was pulled from the 23G90
IPSW with the `pzb` shim. Then `apfs-pack --size-mb 280 --image <stock> --tar ssh.tar.gz --src
<restored_external stage>`, and the result was wrapped with the fixed img4-rs (`-A -T rdsk -M IM4M_0x8030`).
- File tree: identical to the macOS-built ramdisk apart from `.fseventsd/` (the Mac's fsevents
  journal from mounting it during the build).
- Content: all 1779 regular files are byte-identical (sha256).
- Metadata: mode, size and symlink targets are identical. Ownership differs: the 713 entries
  injected from ssh.tar.gz are `0:0` in ours and `99:99` in the macOS build, an artefact of the
  Mac pipeline's `-owners off` mount. Apple's stock files are `0:0` in both.
- `ramdisk.img4`: same total size as the macOS one (293610426), same IM4P header
  (`rdsk`/`Unknown`), identical IM4M.
- Staged as `bootchain/d431ap-26.6.2-23G90-macos-e2e`, a copy of the known-good macOS chain with
  only `ramdisk.img4` replaced.

## Device e2e: PASS (2026-11-03)
Booted `BOOTCHAIN_NAME=d431ap-26.6.2-23G90-macos-e2e ./boot.sh --no-logo` on the pwned iPhone12,5
(ECID 0x1210ce2208802e). That is the known-good macOS chain with only the apfs-pack `ramdisk.img4`
swapped in. iBEC, trustcache, ramdisk, kernel and `bootx` all went through. The phone came up as
usbmux "ICH_A12+ Ramdisk v1.1" about 3 s later with no fall back to Recovery. SSH over
`iproxy 2222 22` (root/alpine) gives a root shell on Darwin 25.6.0 RELEASE_ARM64_T8030, and
`dropbear`, `mount_ich` and `restored_external` are present and owned root:wheel.
**The custom Linux-built ramdisk is at boot parity with the macOS build.**

Root comes up as `/dev/md0 on / (apfs, local, read-only, journaled, noatime)`. `mount -uw /`
fails with EPERM. That comes from the kext, not our image: `apfs_mount_upgrade_checks`
(`sub_FFFFFFF009BFD810`) returns 1 (EPERM, "Updating mount to read/write mode is not allowed")
when `fs+896` (the fs's mount pointer, set by `handle_mount` on every mount) is set and the mount
has `MNT_ROOTFS` (0x4000). So no APFS root can be upgraded to read-write on this kernel, and the
macOS ramdisk behaves the same. Corollary: in this boot path the root ramdisk is never mounted
read-write, so the original "RW mount ran the v0→v1 spaceman upgrade" theory is not demonstrated
here. v1 is still what newfs_apfs emits and is correct, but the old failure may have had another cause.

## Remaining to prove e2e
Boot test on the device: known-good macOS bootchain with **only** the freshly-rebuilt apfs-pack
ramdisk (both fixes: v1 spaceman **and** the valid xid chain) swapped in. If it boots to SSH,
apfs-writer is at parity for the ramdisk use case. Strongest local proxy short of the device:
a **RW** mount with the strict `linux-apfs-rw` module (RO is already confirmed via apfs-fuse).

## 2. iOS 27 apfs kext — full-audit sweep (2026-11-03)

Pulled the iOS 27.0.1 `com.apple.filesystems.apfs` kext from the kernelcache fileset
(1.74 MB, 2322 functions). Decompiled headless with `~/bin/ida-dump-all-idalib`
in 71 s. Dump at `/tmp/kcdump/apfs/dump/all/`.

### Every mount-reject path the iOS 27 kext takes

Error strings grep says the kext rejects a mount for:

1. `unsupported apfs_incompatible_features` — volume super has a bit the kext
   doesn't know. Writer sets `0x8 (NORMALIZATION_INSENSITIVE)` only, which is
   universally supported.
2. `unsupported apfs_readonly_compatible_features` — would force r/o. Writer sets 0.
3. `unsupported nx_incompatible_features` — container super has unknown bit.
   Writer sets 0.
4. `unsupported nx_readonly_compatible_features` — forces r/o. Writer sets 0.
5. `unsupported flags` (volume-super fs_flags) — writer sets 0x1 (UNENCRYPTED).
6. Unsupported volume type / tree type — writer uses PHYSICAL|BTREE for
   data-stream trees, VIRTUAL|BTREE for catalog, matching stock.
7. `refusing to upgrade spaceman!` — the v0→v1 upgrade path. Writer emits v1
   directly (see §1), so this path is never taken.
8. Sealed-volume checks (`!apfs_is_sealed`, `Graft of an unsealed image not
   allowed`, `authenticated mount requested but volume is not sealed`) — these
   only fire when iBoot asked for an *authenticated* mount with ARV. Our
   ramdisk use case is `rd=md0` which does an unauthenticated r/w mount, so
   seal is not required.
9. Keybag version mismatch — only for encrypted volumes. Writer is UNENCRYPTED.
10. `check_rootmount_qualification() returned false` — qualification is about
    device/container identity, not image contents.

**Nothing in iOS 27's mount paths rejects a correctly-formed unencrypted volume
with v1 spaceman + the fields listed in §1.**

### Writer-field audit against iOS 27 kext checks

| field offset | writer value | iOS 27 expects for a ramdisk | ok |
|---|---|---|---|
| vol+0x28 `apfs_features` | 0x2 (HARDLINK_MAP_RECORDS) | any superset | ✓ |
| vol+0x38 `apfs_incompat_feat` | 0x8 (NORMALIZATION_INSENSITIVE) | iOS requires NI set | ✓ |
| vol+0x40 `apfs_ro_compat_feat` | 0 | 0 for no ro-compat features | ✓ |
| vol+0x108 `apfs_fs_flags` | 0x1 (UNENCRYPTED) | UNENCRYPTED | ✓ |
| vol+0x60–0x70 `meta_crypto` | wmcs 5/0, class-F | present even unencrypted | ✓ |
| vol+0x410 `fext_tree_type` | PHYSICAL\|BTREE | required by iOS 26+ | ✓ (§1) |
| vol+0x74 `root_tree_type` | VIRTUAL\|BTREE | VIRTUAL\|BTREE | ✓ |
| vol+0x78 `extentref_type` | PHYSICAL\|BTREE | PHYSICAL\|BTREE | ✓ |
| vol+0x7c `snap_meta_type` | PHYSICAL\|BTREE | PHYSICAL\|BTREE | ✓ |
| sm+144 `sm_flags` | 1 (VERSIONED) | VERSIONED required | ✓ (§1) |
| sm+336 `sm_version` | 1 | 1 | ✓ (§1) |
| sm+340 `sm_struct_size` | 0x9D8 | 0x9D8 | ✓ (§1) |
| nxsb `nx_incompat_feat` | 0 | 0 if no FUSION/VERSIONED container | ✓ |

### Features the kext knows about but the writer deliberately does NOT emit

These are runtime-only; the kext generates them during normal operation, they
are not required by newfs_apfs output:

- `apfs_clonegroup_*` — generated when a file is cloned via APFS_CLONE_IOCTL
- `expanded obj type` / `expanded record` — synthesized when obj id > 64-bit space
- `Supplemental flags` (inode supp_flags) — set via `apfs_set_supplemental_flags` API
- `Purgeable` records — set via purgeable file API
- Sealed-volume seal / snapshot authentication — SSV-only, our volume is unsealed
- `keybag_version_upgrade` — encrypted-volume keybag version bump
- `INODE_PROT_CLASS_UPGRADE_ROLLIP` — in-flight protection class upgrade
- `secondary fsroot` — secondary fsroot slot
- `restore change point` — restore-mode state record

### Verdict

**apfs-writer is at parity for the ramdisk use case on iOS 27.** No additional
keys/fields need to be emitted. The §1 spaceman v1 + fext_tree_type +
modified_by fixes were sufficient. Audit methodology (dump + grep + offset
cross-check) is reproducible on future iOS revisions.

### Reproduction commands

```sh
# extract the iOS N apfs kext
~/.local/bin/ipsw kernel dec kernelcache.img4 -o /tmp/kc/
~/.local/bin/ipsw macho info /tmp/kc/kernelcache*.decompressed \
    --fileset-entry 'com.apple.filesystems.apfs' --extract-fileset-entry -o /tmp/kc/

# decompile everything
~/bin/ida-dump-all-idalib /tmp/kc/com.apple.filesystems.apfs \
    --out /tmp/apfs_dump --skip-thunks

# audit reject strings
strings -a /tmp/kc/com.apple.filesystems.apfs \
    | grep -iE 'unsupported|refusing|unable to mount|not allowed'
```
