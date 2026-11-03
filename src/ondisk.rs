//! APFS on-disk structures - exact per Apple newfs_apfs (iOS 16.4.1, kuna-verified)
//! and the apfsprogs reference (linux-apfs/apfsprogs, saved in reference/).

pub const BLOCK_SIZE: usize = 4096;
pub const NX_MAGIC: u32 = u32::from_le_bytes(*b"NXSB");
pub const FS_MAGIC: u32 = u32::from_le_bytes(*b"APSB");

// object storage type flags (top bits of o_type)
pub const OBJ_VIRTUAL: u32 = 0x0000_0000;
pub const OBJ_EPHEMERAL: u32 = 0x8000_0000;
pub const OBJ_PHYSICAL: u32 = 0x4000_0000;

// container object types
pub const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x01;
pub const OBJECT_TYPE_BTREE: u32 = 0x02;
pub const OBJECT_TYPE_BTREE_NODE: u32 = 0x03;
pub const OBJECT_TYPE_SPACEMAN: u32 = 0x05;
pub const OBJECT_TYPE_SPACEMAN_CIB: u32 = 0x07;
pub const OBJECT_TYPE_SPACEMAN_BITMAP: u32 = 0x08;
pub const OBJECT_TYPE_SPACEMAN_FREE_QUEUE: u32 = 0x09;
pub const OBJECT_TYPE_OMAP: u32 = 0x0b;
pub const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0x0c;
pub const OBJECT_TYPE_FS: u32 = 0x0d;
pub const OBJECT_TYPE_FSTREE: u32 = 0x0e;
pub const OBJECT_TYPE_BLOCKREFTREE: u32 = 0x0f;
pub const OBJECT_TYPE_SNAPMETATREE: u32 = 0x10;
pub const OBJECT_TYPE_NX_REAPER: u32 = 0x11;
pub const OBJECT_TYPE_NX_REAP_LIST: u32 = 0x12;

// b-tree node flags
pub const BTNODE_ROOT: u16 = 0x0001;
pub const BTNODE_LEAF: u16 = 0x0002;
pub const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;

pub const BTOFF_INVALID: u16 = 0xFFFF;
pub const OID_INVALID: u64 = 0;

// oids (mkapfs constants)
pub const APFS_OID_NX_SUPERBLOCK: u64 = 1;
pub const SPACEMAN_OID: u64 = 1024; // APFS_OID_RESERVED_COUNT
pub const REAPER_OID: u64 = 1025;
pub const FIRST_VOL_OID: u64 = 1026;
pub const FIRST_VOL_CAT_ROOT_OID: u64 = 1027;
pub const IP_FREE_QUEUE_OID: u64 = 1028;
pub const MAIN_FREE_QUEUE_OID: u64 = 1029;

// volume inodes
pub const APFS_ROOT_DIR_INO_NUM: u64 = 2;
pub const APFS_PRIV_DIR_INO_NUM: u64 = 3;
pub const APFS_MIN_USER_INO_NUM: u64 = 1004;

const M: u64 = 0xFFFF_FFFF;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ObjPhys {
    pub cksum: u64,
    pub oid: u64,
    pub xid: u64,
    pub o_type: u32,
    pub o_flags: u32,
}

pub fn set_object_header(
    block: &mut [u8],
    oid: u64,
    xid: u64,
    o_type: u32,
    subtype: u32,
) {
    // obj_phys_t on disk, little-endian: cksum u64 (left zero for sealing), oid u64, xid u64,
    // o_type u32, o_subtype u32.
    block[0..8].copy_from_slice(&0u64.to_le_bytes());
    block[8..16].copy_from_slice(&oid.to_le_bytes());
    block[16..24].copy_from_slice(&xid.to_le_bytes());
    block[24..28].copy_from_slice(&o_type.to_le_bytes());
    block[28..32].copy_from_slice(&subtype.to_le_bytes());
}

/// Apple fletcher64 (validated against stock ramdisk; see PROJECT.md).
fn fletcher_core(block: &[u8]) -> (u64, u64) {
    let data = &block[8..];
    let nwords = data.len() / 4;
    let mut s1: u64 = 0;
    let mut s2: u64 = 0;
    let mut i = 0;
    let mut remaining = nwords;
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

/// Compute checksum and store it in the first 8 bytes of the block.
pub fn seal_block(block: &mut [u8]) {
    debug_assert_eq!(block.len(), BLOCK_SIZE);
    let c = checksum(block);
    block[..8].copy_from_slice(&c.to_le_bytes());
}

pub fn verify_block(block: &[u8]) -> bool {
    let stored = u64::from_le_bytes(block[..8].try_into().unwrap());
    checksum(block) == stored
}

// ---- b-tree node header helpers (apfs_btree_node_phys) ----
// 0x00 obj_phys | 0x20 flags u16 | 0x22 level u16 | 0x24 nkeys u32
// 0x28 table_space nloc | 0x2c free_space | 0x30 key_free | 0x34 val_free
// 0x38 table (kvloc/kvoff array), keys grow forward from table end,
// values grow backward from block end (minus btree_info for root nodes).

pub fn btree_put_header(
    block: &mut [u8],
    oid: u64,
    xid: u64,
    o_type: u32,
    subtype: u32,
    flags: u16,
    level: u16,
    nkeys: u32,
    toc_len: u16,
    free_off: u16,
    free_len: u16,
    info_len: usize,
) {
    set_object_header(block, oid, xid, o_type, subtype);
    block[0x20..0x22].copy_from_slice(&flags.to_le_bytes());
    block[0x22..0x24].copy_from_slice(&level.to_le_bytes());
    block[0x24..0x28].copy_from_slice(&nkeys.to_le_bytes());
    // table_space: off=0, len=toc_len
    block[0x28..0x2a].copy_from_slice(&0u16.to_le_bytes());
    block[0x2a..0x2c].copy_from_slice(&toc_len.to_le_bytes());
    // free space
    block[0x2c..0x2e].copy_from_slice(&free_off.to_le_bytes());
    block[0x2e..0x30].copy_from_slice(&free_len.to_le_bytes());
    // no fragmentation
    block[0x30..0x32].copy_from_slice(&BTOFF_INVALID.to_le_bytes());
    block[0x32..0x34].copy_from_slice(&0u16.to_le_bytes());
    block[0x34..0x36].copy_from_slice(&BTOFF_INVALID.to_le_bytes());
    block[0x36..0x38].copy_from_slice(&0u16.to_le_bytes());
    let _ = info_len;
}

/// Write the trailing btree_info for a root node (bt_fixed + longest k/v + counts).
/// bt_fixed: flags u32, toplevel u32, leaf u32, fixed u32; then lk u32, lv u32, kc u64, nc u64
pub fn btree_write_info(block: &mut [u8], subtype: u32, key_count: u64, node_count: u64, longest_key: u32, longest_val: u32) {
    let info_len = 40usize;
    let off = block.len() - info_len;
    block[off..off+4].copy_from_slice(&subtype.to_le_bytes());          // bt_flags
    block[off+4..off+8].copy_from_slice(&1u32.to_le_bytes());          // toplevel
    block[off+8..off+12].copy_from_slice(&1u32.to_le_bytes());         // leaf (typical)
    block[off+12..off+16].copy_from_slice(&0u32.to_le_bytes());        // fixed
    block[off+16..off+20].copy_from_slice(&longest_key.to_le_bytes());
    block[off+20..off+24].copy_from_slice(&longest_val.to_le_bytes());
    block[off+24..off+32].copy_from_slice(&key_count.to_le_bytes());
    block[off+32..off+40].copy_from_slice(&node_count.to_le_bytes());
}

// ---- omap structures ----
pub struct OmapPhys;
/// omap object block: om_flags, om_tree_type, om_snapshot_tree_type, om_tree_oid, om_snapshot_tree_oid (+ pad)
pub fn write_omap_phys(block: &mut [u8], oid: u64, xid: u64, tree_oid: u64, manually_managed: bool) {
    set_object_header(block, oid, xid, OBJ_PHYSICAL | OBJECT_TYPE_OMAP, OID_INVALID as u32);
    let flags: u32 = if manually_managed { 0x1 } else { 0 }; // APFS_OMAP_MANUALLY_MANAGED
    block[32..36].copy_from_slice(&flags.to_le_bytes());
    block[36..40].copy_from_slice(&(OBJ_PHYSICAL | OBJECT_TYPE_BTREE).to_le_bytes());
    block[40..44].copy_from_slice(&(OBJ_PHYSICAL | OBJECT_TYPE_BTREE).to_le_bytes());
    block[44..52].copy_from_slice(&tree_oid.to_le_bytes());
    block[52..60].copy_from_slice(&OID_INVALID.to_le_bytes());
}

/// omap entry (fixed kv): key = {ok_oid, ok_xid}, val = {ov_flags, ov_size, ov_paddr}
pub fn omap_kv(key_oid: u64, key_xid: u64, val_paddr: u64, val_size: u32) -> ([u8; 16], [u8; 16]) {
    let mut k = [0u8; 16];
    k[0..8].copy_from_slice(&key_oid.to_le_bytes());
    k[8..16].copy_from_slice(&key_xid.to_le_bytes());
    let mut v = [0u8; 16];
    v[0..4].copy_from_slice(&0u32.to_le_bytes());      // ov_flags
    v[4..8].copy_from_slice(&val_size.to_le_bytes());
    v[8..16].copy_from_slice(&val_paddr.to_le_bytes());
    (k, v)
}
