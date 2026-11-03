//! APFS container builder - faithful port of mkapfs (linux-apfs/apfsprogs).
//! Layout, oids, checkpoint semantics and spaceman follow mkapfs exactly;
//! block checksums follow Apple's newfs_apfs (kuna-verified, 233/233 blocks).

use crate::image::Image;
use crate::tree::{build_tree, node_count, Rec, TreeSpec};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::PathBuf;

pub const BLOCK_SIZE: usize = 4096;
pub const NX_MAGIC: u32 = u32::from_le_bytes(*b"NXSB");
pub const FS_MAGIC: u32 = u32::from_le_bytes(*b"APSB");

pub const OBJ_VIRTUAL: u32 = 0x0000_0000;
pub const OBJ_EPHEMERAL: u32 = 0x8000_0000;
pub const OBJ_PHYSICAL: u32 = 0x4000_0000;

pub const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x01;
pub const OBJECT_TYPE_BTREE: u32 = 0x02;
pub const OBJECT_TYPE_BTREE_NODE: u32 = 0x03;
pub const OBJECT_TYPE_SPACEMAN: u32 = 0x05;
pub const OBJECT_TYPE_SPACEMAN_CAB: u32 = 0x06;
pub const OBJECT_TYPE_SPACEMAN_CIB: u32 = 0x07;
pub const OBJECT_TYPE_SPACEMAN_FREE_QUEUE: u32 = 0x09;
pub const OBJECT_TYPE_OMAP: u32 = 0x0b;
pub const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0x0c;
pub const OBJECT_TYPE_FS: u32 = 0x0d;
pub const OBJECT_TYPE_FSTREE: u32 = 0x0e;
pub const OBJECT_TYPE_BLOCKREFTREE: u32 = 0x0f;
pub const OBJECT_TYPE_SNAPMETATREE: u32 = 0x10;
pub const OBJECT_TYPE_NX_REAPER: u32 = 0x11;

pub const BTNODE_ROOT: u16 = 0x0001;
pub const BTNODE_LEAF: u16 = 0x0002;
pub const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;
pub const BTOFF_INVALID: u16 = 0xFFFF;

// oids (mkapfs constants)
pub const NX_SUPERBLOCK_OID: u64 = 1;
pub const SPACEMAN_OID: u64 = 1024;
pub const REAPER_OID: u64 = 1025;
pub const FIRST_VOL_OID: u64 = 1026;
pub const FIRST_VOL_CAT_ROOT_OID: u64 = 1027;
pub const IP_FREE_QUEUE_OID: u64 = 1028;
pub const MAIN_FREE_QUEUE_OID: u64 = 1029;

pub const ROOT_DIR_INO: u64 = 2;
pub const PRIV_DIR_INO: u64 = 3;
pub const NEXT_OID_AFTER_MKFS: u64 = 1024 + 100;

// The container's current transaction. A real newfs_apfs volume is created in one transaction
// and then advanced (the kext stamps it on first mount), so a mounted volume always has
// formatted_by.last_xid < modified_by.last_xid <= container xid. We emitted everything at a
// single xid=1, which made creation xid == modification xid == container xid — a shape no
// mounted volume can have. apfsck rejects it ("Volume creation info: transaction is too
// recent.", super.c check: xid <= v_first_xid), and it is not the formatted-and-mounted shape
// iOS expects. Emit the current transaction as xid=2 with the volume recorded as created at
// FORMAT_XID (1), giving the required strictly-increasing chain. (Verified against a macOS
// newfs_apfs ramdisk: formatted_by.last_xid=2 < modified_by.last_xid=18 <= container xid=19.)
pub const MKFS_XID: u64 = 2;
/// The transaction the volume was originally formatted in (formatted_by.last_xid), strictly
/// less than MKFS_XID so the volume reads as "formatted earlier, mounted now".
pub const FORMAT_XID: u64 = 1;

/// Dentry hash of a name on a normalization-insensitive, case-sensitive volume. ASCII names only (NFD is the identity there).
pub fn dentry_hash_standalone(name: &str) -> u32 {
    let mut hash: u32 = 0xFFFFFFFF;
    let table = crc32c_table();
    for c in name.chars() {
        let utf32 = (c as u32).to_le_bytes();
        for &byte in &utf32 {
            hash = table[((hash ^ (byte as u32)) & 0xff) as usize] ^ (hash >> 8);
        }
    }
    (hash & 0x3FFFFF) << 10
}

/// CRC32C (Castagnoli) lookup table, computed at first use.
fn crc32c_table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0x82F63B78 ^ (c >> 1) } else { c >> 1 };
            }
            t[i as usize] = c;
        }
        t
    })
}
// A real iOS volume is formatted by newfs_apfs and then stamped by the kext on first mount.
// iOS's ramdisk mounter rejects the "formatted but never mounted" shape apfs-writer used to
// emit (generic formatter id, empty apfs_modified_by), even though it is apfsck-clean, so we
// present the formatted-and-mounted shape a stock RestoreRamDisk has.
pub const MKFS_ID: &str = "newfs_apfs (2142.41.2.100.2)";
pub const KEXT_ID: &str = "apfs_kext (2142.41.2.100.2)";
pub const APFS_MIN_USER_INO: u64 = 1004;
pub const APFS_MIN_DOC_ID: u32 = 16;

const M: u64 = 0xFFFF_FFFF;
const IP_BM_TX_MULTIPLIER: u32 = 16;
const IP_BM_INDEX_INVALID: u16 = 0xFFFF;
// Version-1 ("versioned") spaceman: the internal-pool arrays start at 0x9D8 (2520), after a
// 2184-byte (0x888) datazone, not at 0x150 (336). iOS's apfs mounts the RestoreRamDisk
// read-write and, on a version-0 spaceman, runs spaceman_upgrade_sm_version_0_to_1 — a write
// during the ramdisk mount that fails and drops the device to Recovery. newfs_apfs emits v1
// directly; apfs-writer now does too. (Confirmed by RE of apfs 2811.160.7 sub_FFFFFFF009BE042C.)
const SM_DATAZONE_LEN: usize = 0x888; // 2184
const BITMAP_XID_OFF: usize = 0x150 + SM_DATAZONE_LEN; // 0x9D8 = 2520

pub(crate) fn div_round_up(n: u64, d: u64) -> u64 {
    (n + d - 1) / d
}
pub(crate) fn round_up8(x: usize) -> usize {
    (x + 7) & !7
}
fn u16le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
fn u64le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}
pub(crate) fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&u16le(v));
}
pub(crate) fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&u32le(v));
}
pub(crate) fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&u64le(v));
}
pub(crate) fn obj_header(b: &mut [u8], oid: u64, xid: u64, otype: u32, subtype: u32) {
    put64(b, 8, oid);
    put64(b, 16, xid);
    put32(b, 24, otype);
    put32(b, 28, subtype);
}

// ---- Apple fletcher64 (kuna-verified) ----
fn fletcher_core(block: &[u8]) -> (u64, u64) {
    let data = &block[8..];
    let nwords = data.len() / 4;
    let (mut s1, mut s2) = (0u64, 0u64);
    let (mut i, mut remaining) = (0usize, nwords);
    while remaining > 0 {
        let chunk = remaining.min(0x16a00);
        for w in data[i * 4..(i + chunk) * 4].chunks_exact(4) {
            s1 = s1.wrapping_add(u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64);
            s2 = s2.wrapping_add(s1);
        }
        i += chunk;
        remaining -= chunk;
        s1 = (s1 & M) + (s1 >> 32);
        s2 = (s2 & M) + (s2 >> 32);
    }
    s1 = (s1 & M) + (s1 >> 32);
    s2 = (s2 & M) + (s2 >> 32);
    if s1 == M { s1 = 0; }
    if s2 == M { s2 = 0; }
    (s1, s2)
}
pub fn checksum(block: &[u8]) -> u64 {
    let (s1, s2) = fletcher_core(block);
    let v1 = (s2 + s1) % M;
    let low = v1 ^ M;
    let v1b = (low + s1) % M;
    let high = (!v1b) & M;
    low | (high << 32)
}
pub fn seal(block: &mut [u8]) {
    let c = checksum(block);
    block[..8].copy_from_slice(&c.to_le_bytes());
}
pub fn verify(block: &[u8]) -> bool {
    u64::from_le_bytes(block[..8].try_into().unwrap()) == checksum(block)
}

// ---- size-dependent parameters (mkapfs.h, lib/parameters.c) ----
fn cpoint_desc_blocks(blocks: u64) -> u32 {
    if blocks < 512 * 1024 / 4 {
        8
    } else if blocks < 1024 * 1024 / 4 {
        12
    } else if blocks < 50 * 1024 * 1024 / 4 {
        let off_512m = ((blocks - 1024 * 1024 / 4) / (512 * 1024 / 4)) as u32;
        20 + 60 * off_512m / 23
    } else {
        280
    }
}
fn cpoint_data_blocks(blocks: u64) -> u32 {
    let b = blocks as i64;
    let n = if b < 4545 {
        52
    } else if b < 13633 {
        124
    } else if b < 36353 {
        160 + 36 * ((b - 13633) / 4544)
    } else if b < 131777 {
        308 + 4 * ((b - 36353) / 4544)
    } else if b < 262144 {
        648 + 4 * ((b - 131777) / 4544)
    } else if b == 262144 {
        992
    } else if b < 1048576 {
        let off_512m = (b - 262144) / 131072;
        1248 + 488 * off_512m + 4 * ((b - (261280 + off_512m * 131776)) / 2272)
    } else if b < 4063232 {
        4112 + 256 * ((b - 1048576) / 131072)
    } else if b < 13107200 {
        10000 + 256 * ((b - 4063232) / 131072)
    } else {
        27672
    };
    n as u32
}
fn ip_fq_node_limit(chunks: u64) -> u16 {
    match (3 * (chunks + 751) / 1127 - 1) as u16 {
        2 => 3, // room for a new root node
        n => n,
    }
}
fn main_fq_node_limit(blocks: u64) -> u16 {
    let n = if blocks < 0x40000 {
        1 + (blocks - 1) / 4544
    } else if blocks < 0x100000 {
        116 + (blocks - 261281) / 2272
    } else {
        512
    };
    match n as u16 {
        2 => 3, // room for a new root node
        n => n,
    }
}

// ---- spaceman geometry (mkapfs spaceman.c) ----
fn blocks_per_chunk() -> u64 {
    (8 * BLOCK_SIZE) as u64
}
fn chunk_info_size() -> u64 {
    32 // sizeof(struct apfs_chunk_info)
}
fn cib_head_size() -> u64 {
    40 // sizeof(struct apfs_chunk_info_block)
}
fn chunks_per_cib() -> u64 {
    (BLOCK_SIZE as u64 - cib_head_size()) / chunk_info_size()
}
fn cibs_per_cab() -> u64 {
    (BLOCK_SIZE as u64 - 40) / 8 // sizeof(struct apfs_cib_addr_block)
}

#[derive(Clone, Copy)]
pub struct SmInfo {
    pub chunk_count: u64,
    pub cib_count: u32,
    pub cab_count: u32,
    pub ip_blocks: u64,
    pub ip_bm_size: u32,
    pub ip_bmap_blocks: u32,
    pub ip_base: u64,
    pub bm_addr_off: usize,
    pub bm_free_next_off: usize,
    pub cib_addr_base_off: usize,
    pub used_blocks_end: u64,
    pub used_chunks_end: u64,
    pub first_chunk_bmap: u64,
    pub first_cib: u64,
    pub first_cab: u64,
    pub spaceman_blocks: u64,
}

#[derive(Clone, Copy)]
pub struct Layout {
    pub block_count: u64,
    pub desc_blocks: u32,
    pub data_blocks: u32,
    pub desc_base: u64,
    pub data_base: u64,
    pub cpoint_end: u64,
    pub reaper_bno: u64,
    pub spaceman_bno: u64,
    pub ip_fq_bno: u64,
    pub main_fq_bno: u64,
    pub total_eph: u64,
    pub main_omap: u64,
    pub main_omap_root: u64,
    pub first_vol: u64,
    pub vol_omap: u64,
    pub vol_omap_root: u64,
    pub cat_root: u64,
    pub extref_root: u64,
    pub snap_root: u64,
    pub ip_bmap_base: u64,
    pub sm: SmInfo,
}

impl Layout {
    /// `file_blocks`: file data placed right after the internal pool.
    pub fn compute(block_count: u64, file_blocks: u64) -> Self {
        let (desc_blocks, data_blocks) = (cpoint_desc_blocks(block_count), cpoint_data_blocks(block_count));
        let desc_base = 1u64;
        let data_base = desc_base + desc_blocks as u64;
        let cpoint_end = data_base + data_blocks as u64;
        let main_omap = cpoint_end;
        let main_omap_root = cpoint_end + 1;
        let first_vol = cpoint_end + 2;
        let vol_omap = cpoint_end + 3;
        let vol_omap_root = cpoint_end + 4;
        let cat_root = cpoint_end + 5;
        let extref_root = cpoint_end + 6;
        let snap_root = cpoint_end + 7;
        let ip_bmap_base = cpoint_end + 8;

        let chunk_count = div_round_up(block_count, blocks_per_chunk());
        let cib_count = div_round_up(chunk_count, chunks_per_cib()) as u32;
        // cib address blocks only when the cib addresses don't fit in one (mkapfs calculate_dev_info)
        let cab_count = match div_round_up(cib_count as u64, cibs_per_cab()) as u32 {
            1 => 0,
            n => n,
        };

        let ip_blocks = (chunk_count + cib_count as u64 + cab_count as u64) * 3;
        let ip_bm_size = div_round_up(ip_blocks, blocks_per_chunk()) as u32;
        let ip_bmap_blocks = 16 * ip_bm_size;
        let ip_base = ip_bmap_base + ip_bmap_blocks as u64;
        let bm_addr_off = BITMAP_XID_OFF + 8 * ip_bm_size as usize;
        let bm_free_next_off = bm_addr_off + round_up8(2 * ip_bm_size as usize);
        let cib_addr_base_off = bm_free_next_off + ip_bmap_blocks as usize * 2;

        // the spaceman holds every cab address, or every cib address when there are no cabs
        let addr_count = if cab_count > 0 { cab_count } else { cib_count };
        let spaceman_blocks = div_round_up(cib_addr_base_off as u64 + addr_count as u64 * 8, BLOCK_SIZE as u64);
        let reaper_bno = data_base;
        let spaceman_bno = reaper_bno + 1;
        let ip_fq_bno = spaceman_bno + spaceman_blocks;
        let main_fq_bno = ip_fq_bno + 1;
        let used_blocks_end = ip_base + ip_blocks;
        let used_chunks_end = div_round_up(used_blocks_end + file_blocks, blocks_per_chunk());
        let first_chunk_bmap = ip_base;
        let first_cib = first_chunk_bmap + used_chunks_end;
        let first_cab = first_cib + cib_count as u64;
        let total_eph = main_fq_bno - reaper_bno + 1;

        Layout {
            block_count,
            desc_blocks,
            data_blocks,
            desc_base,
            data_base,
            cpoint_end,
            reaper_bno,
            spaceman_bno,
            ip_fq_bno,
            main_fq_bno,
            total_eph,
            main_omap,
            main_omap_root,
            first_vol,
            vol_omap,
            vol_omap_root,
            cat_root,
            extref_root,
            snap_root,
            ip_bmap_base,
            sm: SmInfo {
                chunk_count,
                cib_count,
                cab_count,
                ip_blocks,
                ip_bm_size,
                ip_bmap_blocks,
                ip_base,
                bm_addr_off,
                bm_free_next_off,
                cib_addr_base_off,
                used_blocks_end,
                used_chunks_end,
                first_chunk_bmap,
                first_cib,
                first_cab,
                spaceman_blocks,
            },
        }
    }
}

/// What an entry is. Entries are listed parents-first; the volume root is implicit.
#[derive(Clone)]
pub enum EntryKind {
    Dir,
    File(Source),
    Symlink(String),
    /// A transparently compressed file (decmpfs), stored as the original xattrs.
    Compressed(Compressed),
}

/// `FileEntry::size` is the uncompressed size.
#[derive(Clone)]
pub struct Compressed {
    /// Value of `com.apple.decmpfs`.
    pub decmpfs: Vec<u8>,
    /// Value of `com.apple.ResourceFork`; empty when the data is inline in `decmpfs`.
    pub rsrc: Vec<u8>,
}

#[derive(Clone)]
pub enum Source {
    Path(PathBuf),
    Mem(Vec<u8>),
}

#[derive(Clone)]
pub struct FileEntry {
    /// Path relative to the volume root, `/`-separated, no leading slash.
    pub path: String,
    pub kind: EntryKind,
    /// Permission bits only (`0o7777`); the file type comes from `kind`.
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub mtime_ns: u64,
    /// Content length of a `File`.
    pub size: u64,
}

impl FileEntry {
    pub fn file_mem(path: &str, data: Vec<u8>) -> Self {
        FileEntry { path: path.into(), mode: 0o644, uid: 0, gid: 0, mtime_ns: 0, size: data.len() as u64, kind: EntryKind::File(Source::Mem(data)) }
    }

    fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap()
    }

    fn parent(&self) -> &str {
        self.path.rsplit_once('/').map_or("", |p| p.0)
    }

    fn data_blocks(&self) -> u64 {
        match &self.kind {
            EntryKind::File(_) => div_round_up(self.size, BLOCK_SIZE as u64),
            EntryKind::Compressed(c) => div_round_up(c.rsrc.len() as u64, BLOCK_SIZE as u64),
            _ => 0,
        }
    }

    fn type_bits(&self) -> u16 {
        match self.kind {
            EntryKind::Dir => 0x4000,
            EntryKind::File(_) | EntryKind::Compressed(_) => 0x8000,
            EntryKind::Symlink(_) => 0xA000,
        }
    }
}

pub struct ContainerBuilder<'a> {
    pub image: &'a mut Image,
    pub l: Layout,
    pub entries: Vec<FileEntry>,
    pub label: String,
    pub nx_uuid: [u8; 16],
    pub vol_uuid: [u8; 16],
    pub timestamp: u64,
    pub sb_template: Vec<u8>,
    /// Every sealed object written: (first block, block count).
    pub sealed: Vec<(u64, u64)>,
    /// Physical block of each entry's content (0 when it has none).
    paddrs: Vec<u64>,
    /// Block ranges allocated past the internal pool: file content and extra tree nodes.
    allocs: Vec<(u64, u64)>,
    cursor: u64,
    next_oid: u64,
    extra_blocks: u64,
}

const FIRST_INO: u64 = NEXT_OID_AFTER_MKFS + 16;

#[derive(Clone, Copy)]
struct InodeExtra {
    bsd_flags: u32,
    internal_flags: u64,
    uncompressed_size: u64,
}

const NO_RSRC_FORK: u64 = 0x8000;
const HAS_RSRC_FORK: u64 = 0x4000;
const HAS_UNCOMPRESSED_SIZE: u64 = 0x40000;
const UF_COMPRESSED: u32 = 0x20;
const PLAIN: InodeExtra = InodeExtra { bsd_flags: 0, internal_flags: NO_RSRC_FORK, uncompressed_size: 0 };

/// Object ids of the resource-fork data streams: one per compressed file that has a fork,
/// numbered after the inodes.
fn stream_ids(entries: &[FileEntry]) -> Vec<u64> {
    let mut next = FIRST_INO + entries.len() as u64;
    entries
        .iter()
        .map(|e| match &e.kind {
            EntryKind::Compressed(c) if !c.rsrc.is_empty() => {
                next += 1;
                next - 1
            }
            _ => 0,
        })
        .collect()
}

fn cat_spec() -> TreeSpec {
    TreeSpec { fixed: None, bt_flags: 0x40, storage: OBJ_VIRTUAL, subtype: OBJECT_TYPE_FSTREE, root_oid: FIRST_VOL_CAT_ROOT_OID }
}

fn extref_spec(root: u64) -> TreeSpec {
    TreeSpec { fixed: None, bt_flags: 0x10 | 0x40, storage: OBJ_PHYSICAL, subtype: OBJECT_TYPE_BLOCKREFTREE, root_oid: root }
}

fn omap_spec(root: u64) -> TreeSpec {
    TreeSpec { fixed: Some((16, 16)), bt_flags: 0x10, storage: OBJ_PHYSICAL, subtype: OBJECT_TYPE_OMAP, root_oid: root }
}

fn omap_recs(maps: &[(u64, u64)]) -> Vec<Rec> {
    maps.iter()
        .map(|&(oid, paddr)| {
            let mut k = u64le(oid).to_vec();
            k.extend(u64le(MKFS_XID));
            let mut v = u32le(0).to_vec();
            v.extend(u32le(BLOCK_SIZE as u32));
            v.extend(u64le(paddr));
            (k, v)
        })
        .collect()
}

/// Catalog records for the whole volume, sorted in apfsck key order.
fn catalog_records(entries: &[FileEntry], paddrs: &[u64], ts: u64) -> Vec<Rec> {
    let drec_key = |parent: u64, name: &str| -> Vec<u8> {
        let mut k = u64le((9u64 << 60) | parent).to_vec();
        k.extend(u32le(dentry_hash_standalone(name) | (name.len() + 1) as u32));
        k.extend(name.bytes());
        k.push(0);
        k
    };
    let drec_val = |ino: u64, type_bits: u16| -> Vec<u8> {
        let mut v = u64le(ino).to_vec();
        v.extend(u64le(ts));
        v.extend(u16le(type_bits >> 12));
        v
    };
    let ino_key = |ino: u64| u64le((3u64 << 60) | ino).to_vec();
    #[allow(clippy::too_many_arguments)]
    let ino_val = |ino: u64, parent: u64, name: &str, mode: u16, nlink: u32, uid: u32, gid: u32, mtime: u64, dstream: Option<(u64, u64)>, x: InodeExtra| -> Vec<u8> {
        let mut v = u64le(parent).to_vec();
        v.extend(u64le(ino));
        for _ in 0..4 {
            v.extend(u64le(mtime));
        }
        v.extend(u64le(x.internal_flags));
        v.extend(u32le(nlink)); // nchildren for directories
        v.extend(u32le(0)); // default_protection_class
        v.extend(u32le(0)); // write gen
        v.extend(u32le(x.bsd_flags));
        v.extend(u32le(uid));
        v.extend(u32le(gid));
        v.extend(u16le(mode));
        v.extend(u16le(0)); // pad
        v.extend(u64le(x.uncompressed_size));
        let mut name_val = name.as_bytes().to_vec();
        name_val.push(0);
        let mut xfields = vec![(4u8, 0x02u8, name_val)]; // NAME, DO_NOT_COPY
        if let Some((size, alloced)) = dstream {
            let mut d = u64le(size).to_vec();
            d.extend(u64le(alloced));
            d.extend([0u8; 24]); // crypto id, bytes written, bytes read
            xfields.push((8, 0x20, d)); // DSTREAM, SYSTEM_FIELD
        }
        let used: usize = xfields.iter().map(|x| x.2.len().next_multiple_of(8)).sum();
        v.extend(u16le(xfields.len() as u16));
        v.extend(u16le(used as u16));
        for (ty, fl, val) in &xfields {
            v.push(*ty);
            v.push(*fl);
            v.extend(u16le(val.len() as u16));
        }
        for (_, _, val) in &xfields {
            v.extend(val);
            v.extend(vec![0u8; val.len().next_multiple_of(8) - val.len()]);
        }
        v
    };

    let mut ino_of: HashMap<&str, u64> = HashMap::new();
    ino_of.insert("", ROOT_DIR_INO);
    for (i, e) in entries.iter().enumerate() {
        ino_of.insert(&e.path, FIRST_INO + i as u64);
    }
    let mut nchildren: HashMap<u64, u32> = HashMap::new();
    nchildren.insert(PRIV_DIR_INO, 0);
    for e in entries {
        *nchildren.entry(ino_of[e.parent()]).or_default() += 1;
    }

    let mut recs: Vec<Rec> = vec![];
    recs.push((drec_key(1, "root"), drec_val(ROOT_DIR_INO, 0x4000)));
    recs.push((drec_key(1, "private-dir"), drec_val(PRIV_DIR_INO, 0x4000)));
    recs.push((ino_key(ROOT_DIR_INO), ino_val(ROOT_DIR_INO, 1, "root", 0o755 | 0x4000, nchildren.get(&ROOT_DIR_INO).copied().unwrap_or(0), 0, 0, ts, None, PLAIN)));
    recs.push((ino_key(PRIV_DIR_INO), ino_val(PRIV_DIR_INO, 1, "private-dir", 0o755 | 0x4000, 0, 0, 0, ts, None, PLAIN)));

    let sids = stream_ids(entries);
    for (i, e) in entries.iter().enumerate() {
        let ino = FIRST_INO + i as u64;
        let parent = ino_of[e.parent()];
        let mode = e.type_bits() | e.mode;
        let inode = |nlink: u32, dstream: Option<(u64, u64)>, x: InodeExtra| {
            (ino_key(ino), ino_val(ino, parent, e.name(), mode, nlink, e.uid, e.gid, e.mtime_ns, dstream, x))
        };
        let xattr = |name: &[u8], flags: u16, data: Vec<u8>| {
            let mut k = u64le((4u64 << 60) | ino).to_vec(); // XATTR
            k.extend(u16le(name.len() as u16 + 1));
            k.extend(name);
            k.push(0);
            let mut v = u16le(flags).to_vec();
            v.extend(u16le(data.len() as u16));
            v.extend(data);
            (k, v)
        };
        // content stream records: DSTREAM_ID (not for xattr streams) and one FILE_EXTENT, owned by `id`
        let stream = |recs: &mut Vec<Rec>, id: u64, alloced: u64, paddr: u64, dstream_id: bool| {
            if dstream_id {
                recs.push((u64le((6u64 << 60) | id).to_vec(), u32le(1).to_vec())); // refcnt 1
            }
            let mut k = u64le((8u64 << 60) | id).to_vec();
            k.extend(u64le(0)); // logical addr
            let mut v = u64le(alloced).to_vec();
            v.extend(u64le(paddr));
            v.extend(u64le(0)); // crypto_id
            recs.push((k, v));
        };
        recs.push((drec_key(parent, e.name()), drec_val(ino, e.type_bits())));
        match &e.kind {
            EntryKind::Dir => {
                let n = nchildren.get(&ino).copied().unwrap_or(0);
                recs.push(inode(n, None, PLAIN));
            }
            EntryKind::File(_) => {
                let alloced = e.size.next_multiple_of(BLOCK_SIZE as u64);
                recs.push(inode(1, (e.size > 0).then_some((e.size, alloced)), PLAIN));
                if e.size > 0 {
                    stream(&mut recs, ino, alloced, paddrs[i], true);
                }
            }
            EntryKind::Symlink(target) => {
                recs.push(inode(1, None, PLAIN));
                let mut data = target.as_bytes().to_vec();
                data.push(0);
                recs.push(xattr(b"com.apple.fs.symlink", 0x2 | 0x4, data)); // EMBEDDED | FILE_SYSTEM_OWNED
            }
            EntryKind::Compressed(c) => {
                let fork = if c.rsrc.is_empty() { NO_RSRC_FORK } else { HAS_RSRC_FORK };
                let x = InodeExtra { bsd_flags: UF_COMPRESSED, internal_flags: fork | HAS_UNCOMPRESSED_SIZE, uncompressed_size: e.size };
                recs.push(inode(1, None, x));
                recs.push(xattr(b"com.apple.decmpfs", 0x2, c.decmpfs.clone())); // EMBEDDED
                if !c.rsrc.is_empty() {
                    let alloced = (c.rsrc.len() as u64).next_multiple_of(BLOCK_SIZE as u64);
                    let mut d = u64le(sids[i]).to_vec(); // xattr_dstream: stream id + dstream
                    d.extend(u64le(c.rsrc.len() as u64));
                    d.extend(u64le(alloced));
                    d.extend([0u8; 24]);
                    recs.push(xattr(b"com.apple.ResourceFork", 0x1, d)); // DATA_STREAM
                    stream(&mut recs, sids[i], alloced, paddrs[i], false);
                }
            }
        }
    }
    recs.sort_by_key(|(k, _)| {
        let hdr = u64::from_le_bytes(k[0..8].try_into().unwrap());
        let (id, ty) = (hdr & 0x0FFF_FFFF_FFFF_FFFF, hdr >> 60);
        let (number, name) = match ty {
            9 => (u32::from_le_bytes(k[8..12].try_into().unwrap()) as u64 & !0x3FF, k[12..].to_vec()),
            8 => (u64::from_le_bytes(k[8..16].try_into().unwrap()), vec![]),
            4 => (0, k[10..].to_vec()),
            _ => (0, vec![]),
        };
        (id, ty, number, name)
    });
    recs
}

/// One extent-reference record per file with content, owned by its inode.
fn extref_records(entries: &[FileEntry], paddrs: &[u64]) -> Vec<Rec> {
    let sids = stream_ids(entries);
    let mut recs: Vec<Rec> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.data_blocks() > 0)
        .map(|(i, e)| {
            let k = u64le((2u64 << 60) | paddrs[i]).to_vec(); // APFS_TYPE_EXTENT
            let mut v = u64le((1u64 << 60) | e.data_blocks()).to_vec(); // KIND_NEW
            v.extend(u64le(if sids[i] != 0 { sids[i] } else { FIRST_INO + i as u64 }));
            v.extend(u32le(1));
            (k, v)
        })
        .collect();
    recs.sort_by_key(|r| u64::from_le_bytes(r.0[..8].try_into().unwrap()));
    recs
}

impl<'a> ContainerBuilder<'a> {
    /// Plan the layout for `entries` on a `block_count`-block image. `image` must hold at least
    /// `block_count` blocks; write it out with [`Image::write_to`] after [`build`](Self::build).
    pub fn new(
        image: &'a mut Image,
        block_count: u64,
        label: &str,
        nx_uuid: [u8; 16],
        vol_uuid: [u8; 16],
        timestamp: u64,
        entries: Vec<FileEntry>,
    ) -> Result<Self> {
        if image.len() < block_count * BLOCK_SIZE as u64 {
            bail!("image is {} bytes, smaller than {block_count} blocks", image.len());
        }
        let mut seen: HashMap<&str, bool> = HashMap::new();
        seen.insert("", true);
        for e in &entries {
            if !e.path.is_ascii() || e.path.starts_with('/') || e.name().len() > 254 {
                bail!("unsupported path {:?} (ASCII, relative, names under 255 bytes)", e.path);
            }
            match seen.get(e.parent()) {
                Some(true) => {}
                _ => bail!("{}: parent directory missing or not a directory", e.path),
            }
            if seen.insert(&e.path, matches!(e.kind, EntryKind::Dir)).is_some() {
                bail!("{}: duplicate path", e.path);
            }
        }

        // Node counts depend only on record sizes, so a dry run with zero addresses sizes the trees.
        let zeros = vec![0u64; entries.len()];
        let cat_nodes = node_count(&cat_spec(), &catalog_records(&entries, &zeros, timestamp));
        let ext_nodes = node_count(&extref_spec(0), &extref_records(&entries, &zeros));
        let omap_nodes = node_count(&omap_spec(0), &omap_recs(&vec![(0, 0); cat_nodes as usize]));
        let extra_blocks = (cat_nodes - 1) + (ext_nodes - 1) + (omap_nodes - 1);
        let data_blocks: u64 = entries.iter().map(|e| e.data_blocks()).sum();

        let l = Layout::compute(block_count, data_blocks + extra_blocks);
        let cursor = l.sm.used_blocks_end.max(l.snap_root + 1);
        if cursor + data_blocks + extra_blocks > block_count {
            bail!(
                "image too small: need {} blocks ({} MiB), have {}",
                cursor + data_blocks + extra_blocks,
                (cursor + data_blocks + extra_blocks) * BLOCK_SIZE as u64 >> 20,
                block_count
            );
        }
        Ok(ContainerBuilder {
            image,
            l,
            entries,
            label: label.into(),
            nx_uuid,
            vol_uuid,
            timestamp,
            sb_template: vec![],
            sealed: vec![],
            paddrs: vec![],
            allocs: vec![],
            cursor,
            next_oid: NEXT_OID_AFTER_MKFS,
            extra_blocks,
        })
    }

    /// Seal `obj` (one checksum over the whole object) and write it at `bno`.
    fn write_obj(&mut self, bno: u64, obj: &mut [u8]) {
        seal(obj);
        let off = bno as usize * BLOCK_SIZE;
        self.image.bytes_mut(off, obj.len()).copy_from_slice(obj);
        self.sealed.push((bno, (obj.len() / BLOCK_SIZE) as u64));
    }

    /// Empty b-tree root (mkapfs make_empty_btree_root).
    fn make_empty_btree_root(&mut self, bno: u64, oid: u64, subtype: u32, ephemeral: bool) {
        let mut b = vec![0u8; BLOCK_SIZE];
        let flags = BTNODE_ROOT | BTNODE_LEAF
            | if subtype == OBJECT_TYPE_SPACEMAN_FREE_QUEUE { BTNODE_FIXED_KV_SIZE } else { 0 };
        // mkapfs min_table_size: fixed-kv trees preallocate the whole table
        let toc_len: u16 = if subtype == OBJECT_TYPE_SPACEMAN_FREE_QUEUE { ((BLOCK_SIZE - 56) / (16 + 8 + 4) * 4) as u16 } else { 8 * 16 };
        put16(&mut b, 0x20, flags);
        put16(&mut b, 0x22, 0); // level
        put32(&mut b, 0x24, 0); // nkeys
        put16(&mut b, 0x28, 0); // table off
        put16(&mut b, 0x2a, toc_len);
        put16(&mut b, 0x2c, 0); // free off
        put16(&mut b, 0x2e, (BLOCK_SIZE - 0x38 - toc_len as usize - 40) as u16);
        put16(&mut b, 0x30, BTOFF_INVALID);
        put16(&mut b, 0x34, BTOFF_INVALID);
        // btree_info (mkapfs set_empty_btree_info)
        let off = BLOCK_SIZE - 40;
        if subtype == OBJECT_TYPE_SPACEMAN_FREE_QUEUE {
            put32(&mut b, off, 0x8 | 0x4); // EPHEMERAL | ALLOW_GHOSTS
            put32(&mut b, off + 8, 16); // key size
            put32(&mut b, off + 12, 8); // val size
            put32(&mut b, off + 16, 16); // longest key
            put32(&mut b, off + 20, 8); // longest val
        } else {
            put32(&mut b, off, 0x10 | 0x40); // PHYSICAL | KV_NONALIGNED
        }
        put32(&mut b, off + 4, BLOCK_SIZE as u32); // node size
        put64(&mut b, off + 24, 0); // key count
        put64(&mut b, off + 32, 1); // node count
        let otype = if ephemeral { OBJ_EPHEMERAL | OBJECT_TYPE_BTREE } else { OBJ_PHYSICAL | OBJECT_TYPE_BTREE };
        obj_header(&mut b, oid, MKFS_XID, otype, subtype);
        self.write_obj(bno, &mut b);
    }

    /// omap object (mkapfs make_omap_btree): object at `bno`, tree root at `bno + 1`,
    /// further tree nodes allocated past the internal pool.
    fn make_omap_btree(&mut self, bno: u64, maps: &[(u64, u64)]) {
        let recs = omap_recs(maps);
        let spec = omap_spec(bno + 1);
        let nodes = build_tree(&spec, &recs, &mut || self.alloc(1));
        for n in nodes {
            let mut data = n.data;
            self.write_obj(n.oid, &mut data);
        }
        let mut om = vec![0u8; BLOCK_SIZE];
        obj_header(&mut om, bno, MKFS_XID, OBJ_PHYSICAL | OBJECT_TYPE_OMAP, 0);
        put32(&mut om, 32, if bno == self.l.main_omap { 0x1 } else { 0 }); // om_flags: MANUALLY_MANAGED for container
        put32(&mut om, 36, 0); // om_snap_count
        put32(&mut om, 40, OBJ_PHYSICAL | OBJECT_TYPE_BTREE); // om_tree_type
        put32(&mut om, 44, OBJ_PHYSICAL | OBJECT_TYPE_BTREE); // om_snapshot_tree_type
        put64(&mut om, 48, bno + 1); // om_tree_oid
        self.write_obj(bno, &mut om);
    }

    /// Reserve `n` contiguous blocks past the internal pool.
    fn alloc(&mut self, n: u64) -> u64 {
        let start = self.cursor;
        self.cursor += n;
        self.allocs.push((start, n));
        start
    }

    /// Volume superblock (mkapfs make_volume).
    fn make_volume(&mut self) {
        let l = self.l;
        let mut b = vec![0u8; BLOCK_SIZE];
        put32(&mut b, 0x20, FS_MAGIC);
        put32(&mut b, 0x24, 0); // fs_index
        put64(&mut b, 0x28, 0x2); // features: HARDLINK_MAP_RECORDS
        put64(&mut b, 0x38, 0x8); // incompatible: NORMALIZATION_INSENSITIVE only (case-sensitive), as iOS volumes
        // meta_crypto @0x60: wmcs
        put16(&mut b, 0x60, 5); // major
        put16(&mut b, 0x62, 0); // minor
        put32(&mut b, 0x64, 0); // cpflags
        put32(&mut b, 0x68, 6); // persistent_class = PROTECTION_CLASS_F
        put16(&mut b, 0x70, 1); // key_revision
        b[0xF0..0x100].copy_from_slice(&self.vol_uuid); // vol_uuid (16)
        put64(&mut b, 0x108, 0x1); // fs_flags: UNENCRYPTED
        // formatted_by @0x110: id[32]+timestamp u64+last_xid u64
        let id = MKFS_ID.as_bytes();
        b[0x110..0x110 + id.len()].copy_from_slice(id);
        put64(&mut b, 0x130, self.timestamp);
        put64(&mut b, 0x138, FORMAT_XID); // formatted_by.last_xid: creation txn, < modified/current
        // apfs_modified_by[0] @0x140: the kext mount stamp a real (mounted) volume carries.
        let kext = KEXT_ID.as_bytes();
        b[0x140..0x140 + kext.len()].copy_from_slice(kext);
        put64(&mut b, 0x160, self.timestamp);
        put64(&mut b, 0x168, MKFS_XID);
        // apfs_fext_tree_type @0x410: newfs_apfs sets the type (OBJ_PHYSICAL|BTREE) even with no tree.
        put32(&mut b, 0x410, OBJ_PHYSICAL | OBJECT_TYPE_BTREE);
        // The kext's own new-volume initializer (apfs 2811.160.7 sub_FFFFFFF009C4EE04) also
        // stamps these tree types on every fresh volume, and a macOS newfs_apfs ramdisk carries
        // them. Nothing in the mount path reads them (verified across all 2322 decompiled
        // functions); this is pure format parity. apfsck accepts reserved_type only as
        // PHYSICAL|BTREE and doesn't check the other two.
        put32(&mut b, 0x414, OBJ_PHYSICAL | OBJECT_TYPE_BTREE); // reserved_type
        put32(&mut b, 0x42C, OBJ_VIRTUAL | OBJECT_TYPE_BTREE); // apfs_doc_id_tree_type
        put32(&mut b, 0x450, OBJ_VIRTUAL | OBJECT_TYPE_BTREE); // apfs_sec_root_tree_type
        // volname @0x2C0
        let name = self.label.as_bytes();
        b[0x2C0..0x2C0 + name.len()].copy_from_slice(name);
        put32(&mut b, 0x3C0, APFS_MIN_DOC_ID);
        // tree types
        put32(&mut b, 0x74, OBJ_VIRTUAL | OBJECT_TYPE_BTREE); // root_tree_type
        put32(&mut b, 0x78, OBJ_PHYSICAL | OBJECT_TYPE_BTREE); // extentref
        put32(&mut b, 0x7c, OBJ_PHYSICAL | OBJECT_TYPE_BTREE); // snapmeta
        put64(&mut b, 0x80, l.vol_omap);
        put64(&mut b, 0x88, FIRST_VOL_CAT_ROOT_OID); // virtual oid -> vol omap
        put64(&mut b, 0x90, l.extref_root); // physical tree
        put64(&mut b, 0x98, l.snap_root); // physical tree
        let count = |f: fn(&EntryKind) -> bool| self.entries.iter().filter(|e| f(&e.kind)).count() as u64;
        let data_blocks: u64 = self.entries.iter().map(|e| e.data_blocks()).sum();
        // 5 fixed tree objects (omap, omap root, catalog, extref, snapshot-meta) plus content and extra nodes
        put64(&mut b, 0x58, 5 + data_blocks + self.extra_blocks); // fs_alloc_count
        put64(&mut b, 0xB0, stream_ids(&self.entries).iter().max().map_or(0, |m| *m).max(FIRST_INO + self.entries.len() as u64 - 1) + 1); // next_obj_id (inode numbers)
        put64(&mut b, 0xB8, count(|k| matches!(k, EntryKind::File(_) | EntryKind::Compressed(_)))); // num_files
        put64(&mut b, 0xC0, count(|k| matches!(k, EntryKind::Dir))); // num_directories
        put64(&mut b, 0xC8, count(|k| matches!(k, EntryKind::Symlink(_)))); // num_symlinks
        obj_header(&mut b, FIRST_VOL_OID, MKFS_XID, OBJ_VIRTUAL | OBJECT_TYPE_FS, 0);
        self.write_obj(l.first_vol, &mut b);
    }

    /// Catalog tree: root at the fixed block, other nodes get virtual oids mapped in the volume omap.
    fn make_cat_tree(&mut self) -> Vec<(u64, u64)> {
        let recs = catalog_records(&self.entries, &self.paddrs, self.timestamp);
        let mut maps = vec![(FIRST_VOL_CAT_ROOT_OID, self.l.cat_root)];
        let nodes = build_tree(&cat_spec(), &recs, &mut || {
            let oid = self.next_oid;
            self.next_oid += 1;
            let bno = self.alloc(1);
            maps.push((oid, bno));
            oid
        });
        let bno_of: HashMap<u64, u64> = maps.iter().copied().collect();
        for n in nodes {
            let mut data = n.data;
            self.write_obj(bno_of[&n.oid], &mut data);
        }
        maps.sort();
        maps
    }

    fn make_extref_tree(&mut self) {
        let recs = extref_records(&self.entries, &self.paddrs);
        let nodes = build_tree(&extref_spec(self.l.extref_root), &recs, &mut || self.alloc(1));
        for n in nodes {
            let mut data = n.data;
            self.write_obj(n.oid, &mut data);
        }
    }


    /// Spaceman (mkapfs make_spaceman + devices + internal pool).
    fn make_spaceman(&mut self) {
        let l = self.l;
        let nblocks = l.sm.spaceman_blocks as usize;
        let mut sm = vec![0u8; nblocks * BLOCK_SIZE];

        put32(&mut sm, 32, BLOCK_SIZE as u32);
        put32(&mut sm, 36, blocks_per_chunk() as u32);
        put32(&mut sm, 40, chunks_per_cib() as u32);
        put32(&mut sm, 44, cibs_per_cab() as u32);

        let d0 = 48usize;
        put64(&mut sm, d0, l.block_count);
        put64(&mut sm, d0 + 8, l.sm.chunk_count);
        put32(&mut sm, d0 + 16, l.sm.cib_count);
        put32(&mut sm, d0 + 20, l.sm.cab_count);
        // allocation bitmap: one block per chunk, so bit b of the flat bitmap is block b
        let mut bmap = vec![0u8; l.sm.used_chunks_end as usize * BLOCK_SIZE];
        let mut used = vec![
            (0, 1),
            (l.desc_base, l.desc_blocks as u64),
            (l.data_base, l.data_blocks as u64),
            (l.main_omap, l.snap_root + 1 - l.main_omap), // container omap, volume and its trees
            (l.ip_bmap_base, l.sm.ip_bmap_blocks as u64),
            (l.sm.ip_base, l.sm.ip_blocks),
        ];
        used.extend(self.allocs.iter().copied());
        for (start, len) in used {
            for b in start..start + len {
                bmap[(b / 8) as usize] |= 1u8 << (b % 8);
            }
        }
        let chunk_used: Vec<u64> = bmap
            .chunks(BLOCK_SIZE)
            .map(|c| c.iter().map(|byte| byte.count_ones() as u64).sum())
            .collect();
        put64(&mut sm, d0 + 24, l.block_count - chunk_used.iter().sum::<u64>());
        put32(&mut sm, d0 + 32, l.sm.cib_addr_base_off as u32);

        put32(&mut sm, 148, IP_BM_TX_MULTIPLIER);
        put64(&mut sm, 152, l.sm.ip_blocks);
        put32(&mut sm, 160, l.sm.ip_bm_size);
        put32(&mut sm, 164, l.sm.ip_bmap_blocks);
        put64(&mut sm, 168, l.ip_bmap_base);
        put64(&mut sm, 176, l.sm.ip_base);

        let fq = |tree_oid: u64, node_limit: u16| -> Vec<u8> {
            let mut f = vec![0u8; 40];
            f[8..16].copy_from_slice(&u64le(tree_oid));
            f[24..26].copy_from_slice(&u16le(node_limit));
            f
        };
        sm[200..240].copy_from_slice(&fq(IP_FREE_QUEUE_OID, ip_fq_node_limit(l.sm.chunk_count)));
        sm[240..280].copy_from_slice(&fq(MAIN_FREE_QUEUE_OID, main_fq_node_limit(l.block_count)));

        put16(&mut sm, 320, l.sm.ip_bm_size as u16); // ip_bm_free_head
        put16(&mut sm, 322, l.sm.ip_bmap_blocks as u16 - 1); // ip_bm_free_tail
        put32(&mut sm, 324, BITMAP_XID_OFF as u32);
        put32(&mut sm, 328, l.sm.bm_addr_off as u32);
        put32(&mut sm, 332, l.sm.bm_free_next_off as u32);
        // v1 spaceman header: VERSIONED flag + version + struct_size (= data start, past the datazone).
        put32(&mut sm, 144, 1); // sm_flags = APFS_SM_FLAG_VERSIONED
        put32(&mut sm, 336, 1); // sm_version = 1
        put32(&mut sm, 340, BITMAP_XID_OFF as u32); // sm_struct_size = 0x9D8

        for i in 0..l.sm.ip_bm_size {
            put64(&mut sm, BITMAP_XID_OFF + i as usize * 8, MKFS_XID);
        }
        for i in 0..l.sm.ip_bm_size {
            put16(&mut sm, l.sm.bm_addr_off + i as usize * 2, i as u16);
        }
        for i in 0..l.sm.ip_bmap_blocks {
            let i = i as usize;
            let in_use = i < l.sm.ip_bm_size as usize;
            let v = if in_use || i + 1 == l.sm.ip_bmap_blocks as usize { IP_BM_INDEX_INVALID } else { (i + 1) as u16 };
            put16(&mut sm, l.sm.bm_free_next_off + i * 2, v);
        }
        let (first_addr, addr_count) = if l.sm.cab_count > 0 {
            (l.sm.first_cab, l.sm.cab_count)
        } else {
            (l.sm.first_cib, l.sm.cib_count)
        };
        for i in 0..addr_count {
            put64(&mut sm, l.sm.cib_addr_base_off + i as usize * 8, first_addr + i as u64);
        }
        // sm_dev[1].sm_addr_offset: newfs_apfs points it just past device 0's cib addresses.
        put32(&mut sm, 128, (l.sm.cib_addr_base_off + addr_count as usize * 8) as u32);

        // chunk info blocks
        for cib in 0..l.sm.cib_count {
            let cib_bno = l.sm.first_cib + cib as u64;
            let mut cb = vec![0u8; BLOCK_SIZE];
            put32(&mut cb, 32, cib);
            let mut count = 0u32;
            let mut start = cib as u64 * chunks_per_cib() * blocks_per_chunk();
            for ci in 0..chunks_per_cib() {
                if start >= l.block_count { break; }
                let entry = (cib_head_size() + ci * chunk_info_size()) as usize;
                let chunkno = start / blocks_per_chunk();
                put64(&mut cb, entry, MKFS_XID);
                put64(&mut cb, entry + 8, start);
                if chunkno < l.sm.used_chunks_end {
                    put64(&mut cb, entry + 24, l.sm.first_chunk_bmap + chunkno);
                }
                let bc = blocks_per_chunk().min(l.block_count - start);
                put32(&mut cb, entry + 16, bc as u32);
                let used_in_chunk = chunk_used.get(chunkno as usize).copied().unwrap_or(0);
                put32(&mut cb, entry + 20, (bc - used_in_chunk) as u32);
                start += bc;
                count += 1;
            }
            put32(&mut cb, 36, count);
            obj_header(&mut cb, cib_bno, MKFS_XID, OBJ_PHYSICAL | OBJECT_TYPE_SPACEMAN_CIB, 0);
            self.write_obj(cib_bno, &mut cb);
        }

        // cib address blocks, each listing the next cibs_per_cab() cibs
        for cab in 0..l.sm.cab_count {
            let cab_bno = l.sm.first_cab + cab as u64;
            let mut ab = vec![0u8; BLOCK_SIZE];
            let first = cab as u64 * cibs_per_cab();
            let last = (first + cibs_per_cab()).min(l.sm.cib_count as u64);
            put32(&mut ab, 32, cab);
            put32(&mut ab, 36, (last - first) as u32);
            for (i, cib) in (first..last).enumerate() {
                put64(&mut ab, 40 + i * 8, l.sm.first_cib + cib);
            }
            obj_header(&mut ab, cab_bno, MKFS_XID, OBJ_PHYSICAL | OBJECT_TYPE_SPACEMAN_CAB, 0);
            self.write_obj(cab_bno, &mut ab);
        }

        obj_header(&mut sm, SPACEMAN_OID, MKFS_XID, OBJ_EPHEMERAL | OBJECT_TYPE_SPACEMAN, 0);
        self.write_obj(l.spaceman_bno, &mut sm);

        let off = l.sm.first_chunk_bmap as usize * BLOCK_SIZE;
        self.image.bytes_mut(off, bmap.len()).copy_from_slice(&bmap);

        // internal pool bitmap (mkapfs make_ip_bitmap)
        let ip_off = l.ip_bmap_base as usize * BLOCK_SIZE;
        self.image.bytes_mut(ip_off, l.sm.ip_bm_size as usize * BLOCK_SIZE).fill(0);
        let ip_used = [
            (l.sm.first_chunk_bmap, l.sm.used_chunks_end),
            (l.sm.first_cib, l.sm.cib_count as u64),
            (l.sm.first_cab, l.sm.cab_count as u64),
        ];
        for (start, len) in ip_used {
            for b in start - l.sm.ip_base..start - l.sm.ip_base + len {
                self.image.bytes_mut(ip_off + (b / 8) as usize, 1)[0] |= 1u8 << (b % 8);
            }
        }

    }

    /// Empty reaper (mkapfs make_empty_reaper).
    fn make_reaper(&mut self) {
        let l = self.l;
        let mut b = vec![0u8; BLOCK_SIZE];
        obj_header(&mut b, REAPER_OID, MKFS_XID, OBJ_EPHEMERAL | OBJECT_TYPE_NX_REAPER, 0);
        put64(&mut b, 32, 1); // next_reap_id
        put32(&mut b, 64, 0x1); // nr_flags: BHM
        put32(&mut b, 108, (BLOCK_SIZE - 112) as u32); // state buffer size
        self.write_obj(l.reaper_bno, &mut b);
    }

    /// Checkpoint map + nxsb copy at desc_base/desc_base+1, then final nxsb at 0.
    fn make_checkpoint(&mut self) -> Result<()> {
        let l = self.l;
        let xid = MKFS_XID;

        // CPMAP @ desc_base
        let mut cm = vec![0u8; BLOCK_SIZE];
        put32(&mut cm, 32, 0x1); // MAP_LAST
        put32(&mut cm, 36, 4); // count: reaper, ip_fq, main_fq, spaceman
        let mut entry = |i: usize, otype: u32, subtype: u32, size: u32, oid: u64, paddr: u64| {
            let off = 40 + i * 40;
            put32(&mut cm, off, OBJ_EPHEMERAL | otype);
            put32(&mut cm, off + 4, subtype);
            put32(&mut cm, off + 8, size);
            put32(&mut cm, off + 12, 0);
            put64(&mut cm, off + 16, 0); // fs_oid
            put64(&mut cm, off + 24, oid);
            put64(&mut cm, off + 32, paddr);
        };
        entry(0, OBJECT_TYPE_NX_REAPER, 0, BLOCK_SIZE as u32, REAPER_OID, l.reaper_bno);
        entry(1, OBJECT_TYPE_SPACEMAN, 0, ((l.sm.spaceman_blocks as usize) * BLOCK_SIZE) as u32, SPACEMAN_OID, l.spaceman_bno);
        entry(2, OBJECT_TYPE_BTREE, OBJECT_TYPE_SPACEMAN_FREE_QUEUE, BLOCK_SIZE as u32, IP_FREE_QUEUE_OID, l.ip_fq_bno);
        entry(3, OBJECT_TYPE_BTREE, OBJECT_TYPE_SPACEMAN_FREE_QUEUE, BLOCK_SIZE as u32, MAIN_FREE_QUEUE_OID, l.main_fq_bno);
        obj_header(&mut cm, l.desc_base, xid, OBJ_PHYSICAL | OBJECT_TYPE_CHECKPOINT_MAP, 0);
        self.write_obj(l.desc_base, &mut cm);

        // the same superblock goes in the checkpoint (desc_base+1) and at block 0
        let mut sb = self.sb_template.clone();
        self.write_obj(l.desc_base + 1, &mut sb);
        self.write_obj(0, &mut sb);
        Ok(())
    }

    /// Allocate and write file content; records each entry's first block.
    fn place_files(&mut self) -> Result<()> {
        for i in 0..self.entries.len() {
            let n = self.entries[i].data_blocks();
            if n == 0 {
                self.paddrs.push(0);
                continue;
            }
            let paddr = self.alloc(n);
            let off = paddr as usize * BLOCK_SIZE;
            let e = &self.entries[i];
            let len = match &e.kind {
                EntryKind::Compressed(c) => c.rsrc.len(),
                _ => e.size as usize,
            };
            let dst = self.image.bytes_mut(off, len);
            match &e.kind {
                EntryKind::Compressed(c) => dst.copy_from_slice(&c.rsrc),
                EntryKind::File(Source::Mem(d)) => dst.copy_from_slice(d),
                EntryKind::File(Source::Path(p)) => {
                    use std::io::Read;
                    std::fs::File::open(p)?.read_exact(dst).map_err(|err| anyhow::anyhow!("{}: {err}", p.display()))?
                }
                _ => unreachable!(),
            }
            self.paddrs.push(paddr);
        }
        Ok(())
    }

    /// Build the whole container image.
    pub fn build(&mut self) -> Result<()> {
        let l = self.l; // Layout is Copy
        self.place_files()?;
        let mut sb = vec![0u8; BLOCK_SIZE];
        put32(&mut sb, 32, NX_MAGIC);
        put32(&mut sb, 36, BLOCK_SIZE as u32);
        put64(&mut sb, 40, l.block_count);
        put64(&mut sb, 64, 0x2); // INCOMPAT_VERSION2
        sb[72..88].copy_from_slice(&self.nx_uuid);
        put64(&mut sb, 88, NEXT_OID_AFTER_MKFS);
        put64(&mut sb, 96, MKFS_XID + 1);
        put32(&mut sb, 104, l.desc_blocks);
        put32(&mut sb, 108, l.data_blocks);
        put64(&mut sb, 112, l.desc_base);
        put64(&mut sb, 120, l.data_base);
        put32(&mut sb, 128, 2); // desc_next
        put32(&mut sb, 132, l.total_eph as u32); // data_next = mapped ephemeral count
        put32(&mut sb, 136, 0); // desc_index
        put32(&mut sb, 140, 2); // desc_len
        put32(&mut sb, 144, 0); // data_index
        put32(&mut sb, 148, l.total_eph as u32); // data_len
        put64(&mut sb, 152, SPACEMAN_OID);
        put64(&mut sb, 160, l.main_omap);
        put64(&mut sb, 168, REAPER_OID);
        put32(&mut sb, 180, div_round_up(l.block_count * BLOCK_SIZE as u64, 512 << 20).min(100) as u32); // max_file_systems
        put64(&mut sb, 184, FIRST_VOL_OID); // fs_oid[0]
        // nx_ephemeral_info[0] @0x520: (min_block_count << 32) | (MAX_FILE_SYSTEM_EPH_STRUCTS << 16) | VERSION_1
        let min_blk = if l.block_count * (BLOCK_SIZE as u64) < 128 << 20 {
            main_fq_node_limit(l.block_count) as u64
        } else {
            8 // APFS_NX_EPH_MIN_BLOCK_COUNT
        };
        put64(&mut sb, 0x520, (min_blk << 32) | (4 << 16) | 1);
        obj_header(&mut sb, NX_SUPERBLOCK_OID, MKFS_XID, OBJ_EPHEMERAL | OBJECT_TYPE_NX_SUPERBLOCK, 0);
        self.sb_template = sb;

        // ephemeral objects (data area)
        self.make_reaper();
        self.make_empty_btree_root(l.ip_fq_bno, IP_FREE_QUEUE_OID, OBJECT_TYPE_SPACEMAN_FREE_QUEUE, true);
        self.make_empty_btree_root(l.main_fq_bno, MAIN_FREE_QUEUE_OID, OBJECT_TYPE_SPACEMAN_FREE_QUEUE, true);

        // volume trees; the omaps come last because they map every tree node allocated above
        let vol_maps = self.make_cat_tree();
        self.make_extref_tree();
        self.make_empty_btree_root(l.snap_root, l.snap_root, OBJECT_TYPE_SNAPMETATREE, false);
        put64(&mut self.sb_template, 88, self.next_oid); // virtual node oids are container oids
        self.make_omap_btree(l.main_omap, &[(FIRST_VOL_OID, l.first_vol)]);
        self.make_omap_btree(l.vol_omap, &vol_maps);
        self.make_volume();
        self.make_spaceman();

        // checkpoint + block 0
        self.make_checkpoint()?;
        Ok(())
    }
}
