//! Generic multi-level B-tree writer for APFS (variable and fixed key/value sizes).

use crate::builder::*;

pub type Rec = (Vec<u8>, Vec<u8>);

pub struct TreeSpec {
    /// `(key_size, val_size)` for fixed-kv trees (omap), `None` for variable-kv (catalog, extref).
    pub fixed: Option<(usize, usize)>,
    pub bt_flags: u32,
    /// `OBJ_VIRTUAL` or `OBJ_PHYSICAL`: child pointers are virtual oids or block numbers.
    pub storage: u32,
    pub subtype: u32,
    pub root_oid: u64,
}

pub struct Node {
    pub oid: u64,
    pub data: Vec<u8>,
}

const NODE_HDR: usize = 0x38;
const INFO_SIZE: usize = 40;

/// Fixed-kv trees preallocate the whole table of contents (apfsck `node_min_table_size`).
fn toc_len(spec: &TreeSpec, n: usize, leaf: bool) -> usize {
    match spec.fixed {
        Some((k, v)) => {
            let val = if leaf { v } else { 8 };
            (BLOCK_SIZE - NODE_HDR) / (k + val + 4) * 4
        }
        None => 8 * n,
    }
}

fn fits(spec: &TreeSpec, n: usize, bytes: usize, root: bool, leaf: bool) -> bool {
    NODE_HDR + toc_len(spec, n, leaf) + bytes <= BLOCK_SIZE - if root { INFO_SIZE } else { 0 }
}

fn rec_bytes(r: &Rec) -> usize {
    r.0.len() + r.1.len()
}

/// Split `recs` into runs that each fit one non-root node.
fn pack(spec: &TreeSpec, recs: &[Rec], leaf: bool) -> Vec<std::ops::Range<usize>> {
    let mut out = vec![];
    let (mut start, mut bytes) = (0, 0);
    for (i, r) in recs.iter().enumerate() {
        if i > start && !fits(spec, i - start + 1, bytes + rec_bytes(r), false, leaf) {
            out.push(start..i);
            start = i;
            bytes = 0;
        }
        bytes += rec_bytes(r);
    }
    out.push(start..recs.len());
    out
}

fn make_node(spec: &TreeSpec, recs: &[Rec], level: u16, oid: u64, root: Option<(u64, u64, u32, u32)>) -> Vec<u8> {
    let mut b = vec![0u8; BLOCK_SIZE];
    let n = recs.len();
    let toc = toc_len(spec, n, level == 0);
    let is_root = root.is_some();
    let mut flags = if level == 0 { BTNODE_LEAF } else { 0 };
    if is_root {
        flags |= BTNODE_ROOT;
    }
    if spec.fixed.is_some() {
        flags |= BTNODE_FIXED_KV_SIZE;
    }
    put16(&mut b, 0x20, flags);
    put16(&mut b, 0x22, level);
    put32(&mut b, 0x24, n as u32);
    put16(&mut b, 0x28, 0);
    put16(&mut b, 0x2a, toc as u16);
    put16(&mut b, 0x30, BTOFF_INVALID);
    put16(&mut b, 0x34, BTOFF_INVALID);

    let key_area = NODE_HDR + toc;
    let val_end = BLOCK_SIZE - if is_root { INFO_SIZE } else { 0 };
    let (mut key_off, mut val_start) = (key_area, val_end);
    for (i, (k, v)) in recs.iter().enumerate() {
        val_start -= v.len();
        let t = NODE_HDR + i * if spec.fixed.is_some() { 4 } else { 8 };
        put16(&mut b, t, (key_off - key_area) as u16);
        if spec.fixed.is_some() {
            put16(&mut b, t + 2, (val_end - val_start) as u16);
        } else {
            put16(&mut b, t + 2, k.len() as u16);
            put16(&mut b, t + 4, (val_end - val_start) as u16);
            put16(&mut b, t + 6, v.len() as u16);
        }
        b[key_off..key_off + k.len()].copy_from_slice(k);
        b[val_start..val_start + v.len()].copy_from_slice(v);
        key_off += k.len();
    }
    put16(&mut b, 0x2c, (key_off - key_area) as u16);
    put16(&mut b, 0x2e, (val_start - key_off) as u16);

    let otype = if is_root { OBJECT_TYPE_BTREE } else { OBJECT_TYPE_BTREE_NODE };
    if let Some((key_count, node_count, longest_k, longest_v)) = root {
        let o = BLOCK_SIZE - INFO_SIZE;
        put32(&mut b, o, spec.bt_flags);
        put32(&mut b, o + 4, BLOCK_SIZE as u32);
        if let Some((ks, vs)) = spec.fixed {
            put32(&mut b, o + 8, ks as u32);
            put32(&mut b, o + 12, vs as u32);
        }
        put32(&mut b, o + 16, longest_k);
        put32(&mut b, o + 20, longest_v);
        put64(&mut b, o + 24, key_count);
        put64(&mut b, o + 32, node_count);
    }
    obj_header(&mut b, oid, MKFS_XID, spec.storage | otype, spec.subtype);
    b
}

/// Build the nodes of a tree over sorted `recs`. Non-root nodes get their oid from `new_oid`;
/// the root (last element) gets `spec.root_oid`. For physical trees an oid is a block number.
pub fn build_tree(spec: &TreeSpec, recs: &[Rec], new_oid: &mut dyn FnMut() -> u64) -> Vec<Node> {
    let longest_k = recs.iter().map(|r| r.0.len()).max().unwrap_or(0) as u32;
    let longest_v = recs.iter().map(|r| r.1.len()).max().unwrap_or(0) as u32;
    let key_count = recs.len() as u64;
    let mut nodes: Vec<Node> = vec![];
    let mut level_recs: Vec<Rec> = recs.to_vec();
    let mut level = 0u16;
    loop {
        let total: usize = level_recs.iter().map(rec_bytes).sum();
        if fits(spec, level_recs.len(), total, true, level == 0) {
            let info = (key_count, nodes.len() as u64 + 1, longest_k, longest_v);
            let data = make_node(spec, &level_recs, level, spec.root_oid, Some(info));
            nodes.push(Node { oid: spec.root_oid, data });
            return nodes;
        }
        let mut next = vec![];
        for run in pack(spec, &level_recs, level == 0) {
            let oid = new_oid();
            let chunk = &level_recs[run];
            next.push((chunk[0].0.clone(), oid.to_le_bytes().to_vec()));
            nodes.push(Node { oid, data: make_node(spec, chunk, level, oid, None) });
        }
        level_recs = next;
        level += 1;
    }
}

pub fn node_count(spec: &TreeSpec, recs: &[Rec]) -> u64 {
    build_tree(spec, recs, &mut || 0).len() as u64
}
