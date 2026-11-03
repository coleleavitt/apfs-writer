//! Minimal APFS reader: extracts the root directory tree of the first volume of an
//! unencrypted, snapshot-free container (e.g. an iOS restore ramdisk) as `FileEntry`s.
//! Compressed files are returned as stored (decmpfs xattr + resource fork), not decompressed.

use crate::builder::{Compressed, EntryKind, FileEntry, Source, BLOCK_SIZE, NX_MAGIC};
use anyhow::{bail, ensure, Context, Result};
use std::collections::HashMap;

fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

const BTNODE_ROOT: u16 = 1;
const BTNODE_LEAF: u16 = 2;
const BTNODE_FIXED_KV: u16 = 4;

struct Container<'a> {
    data: &'a [u8],
}

impl<'a> Container<'a> {
    fn block(&self, bno: u64) -> Result<&'a [u8]> {
        let off = bno as usize * BLOCK_SIZE;
        self.data.get(off..off + BLOCK_SIZE).with_context(|| format!("block {bno} is past the end of the image"))
    }

    /// Visit every leaf record of a tree in key order. `resolve` maps child oids to blocks
    /// (identity for physical trees); `fixed` gives `(key, value)` sizes of fixed-kv trees.
    fn walk(
        &self,
        bno: u64,
        fixed: Option<(usize, usize)>,
        resolve: &dyn Fn(u64) -> Result<u64>,
        visit: &mut dyn FnMut(&'a [u8], &'a [u8]) -> Result<()>,
    ) -> Result<()> {
        let b = self.block(bno)?;
        let flags = u16at(b, 0x20);
        let (leaf, root) = (flags & BTNODE_LEAF != 0, flags & BTNODE_ROOT != 0);
        let n = u32at(b, 0x24) as usize;
        let key_base = 0x38 + u16at(b, 0x28) as usize + u16at(b, 0x2a) as usize;
        let toc = 0x38 + u16at(b, 0x28) as usize;
        let val_end = BLOCK_SIZE - if root { 40 } else { 0 };
        for i in 0..n {
            let (k, klen, v, vlen) = if flags & BTNODE_FIXED_KV != 0 {
                let (ks, vs) = fixed.context("fixed-kv node without known sizes")?;
                let vs = if leaf { vs } else { 8 };
                let e = toc + i * 4;
                (u16at(b, e) as usize, ks, u16at(b, e + 2) as usize, vs)
            } else {
                let e = toc + i * 8;
                (u16at(b, e) as usize, u16at(b, e + 2) as usize, u16at(b, e + 4) as usize, u16at(b, e + 6) as usize)
            };
            let key = &b[key_base + k..key_base + k + klen];
            let val = &b[val_end - v..val_end - v + vlen];
            if leaf {
                visit(key, val)?;
            } else {
                self.walk(resolve(u64at(val, 0))?, fixed, resolve, visit)?;
            }
        }
        Ok(())
    }

    /// oid -> block for the newest mapping with xid <= `max_xid`.
    fn omap(&self, omap_bno: u64, max_xid: u64) -> Result<HashMap<u64, u64>> {
        let om = self.block(omap_bno)?;
        let mut best: HashMap<u64, (u64, u64)> = HashMap::new();
        self.walk(u64at(om, 48), Some((16, 16)), &|oid| Ok(oid), &mut |k, v| {
            let (oid, xid) = (u64at(k, 0), u64at(k, 8));
            if xid <= max_xid && best.get(&oid).is_none_or(|b| b.0 < xid) {
                best.insert(oid, (xid, u64at(v, 8)));
            }
            Ok(())
        })?;
        Ok(best.into_iter().map(|(oid, (_, paddr))| (oid, paddr)).collect())
    }
}

#[derive(Default)]
struct Inode {
    private_id: u64,
    mtime: u64,
    bsd_flags: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    uncompressed_size: u64,
    dstream_size: u64,
}

struct Xattr {
    embedded: Vec<u8>,
    /// (stream id, size) when the value is a data stream.
    stream: Option<(u64, u64)>,
}

struct Drec {
    parent: u64,
    name: String,
    ino: u64,
    dtype: u16,
}

fn parse_inode(v: &[u8]) -> Inode {
    let mut ino = Inode {
        private_id: u64at(v, 8),
        mtime: u64at(v, 24),
        bsd_flags: u32at(v, 68),
        uid: u32at(v, 72),
        gid: u32at(v, 76),
        mode: u16at(v, 80),
        uncompressed_size: u64at(v, 84),
        dstream_size: 0,
    };
    if v.len() > 96 {
        let (count, data) = (u16at(v, 92) as usize, 96 + 4 * u16at(v, 92) as usize);
        let mut off = data;
        for i in 0..count {
            let (ty, len) = (v[96 + i * 4], u16at(v, 96 + i * 4 + 2) as usize);
            if ty == 8 {
                ino.dstream_size = u64at(v, off);
            }
            off += len.next_multiple_of(8);
        }
    }
    ino
}

/// Read the root directory tree of the first volume in `data`.
pub fn read_root_tree(data: &[u8]) -> Result<Vec<FileEntry>> {
    let c = Container { data };
    let b0 = c.block(0)?;
    ensure!(u32at(b0, 32) == NX_MAGIC, "not an APFS container");
    ensure!(u32at(b0, 36) as usize == BLOCK_SIZE, "unsupported block size {}", u32at(b0, 36));
    // newest checkpoint superblock in the descriptor area
    let (desc_base, desc_blocks) = (u64at(b0, 112), u32at(b0, 104) & 0x7fff_ffff);
    let mut sb = b0;
    for i in 0..desc_blocks as u64 {
        let b = c.block(desc_base + i)?;
        if u32at(b, 32) == NX_MAGIC && u64at(b, 16) > u64at(sb, 16) {
            sb = b;
        }
    }
    let sb_xid = u64at(sb, 16);
    let cont_omap = c.omap(u64at(sb, 160), sb_xid)?;
    let vol_oid = u64at(sb, 184);
    let vol = c.block(*cont_omap.get(&vol_oid).context("volume missing from container omap")?)?;
    ensure!(u32at(vol, 32) == u32::from_le_bytes(*b"APSB"), "bad volume superblock");
    ensure!(u64at(vol, 0x108) & 0x1 != 0, "encrypted volumes are not supported");
    let hashed = u64at(vol, 0x38) & 0x9 != 0; // case or normalization insensitive
    let vol_omap = c.omap(u64at(vol, 0x80), u64at(vol, 16))?;
    let resolve = |oid: u64| vol_omap.get(&oid).copied().with_context(|| format!("oid {oid} missing from volume omap"));
    let cat_root = resolve(u64at(vol, 0x88))?;

    let mut inodes: HashMap<u64, Inode> = HashMap::new();
    let mut drecs: Vec<Drec> = vec![];
    let mut xattrs: HashMap<u64, HashMap<String, Xattr>> = HashMap::new();
    let mut extents: HashMap<u64, Vec<(u64, u64, u64)>> = HashMap::new(); // id -> (logical, len, paddr)
    c.walk(cat_root, None, &resolve, &mut |k, v| {
        let hdr = u64at(k, 0);
        let (id, ty) = (hdr & 0x0fff_ffff_ffff_ffff, hdr >> 60);
        match ty {
            3 => {
                inodes.insert(id, parse_inode(v));
            }
            4 => {
                let name_len = u16at(k, 8) as usize;
                let name = String::from_utf8_lossy(&k[10..10 + name_len - 1]).into_owned();
                let flags = u16at(v, 0);
                let data = &v[4..4 + u16at(v, 2) as usize];
                let stream = (flags & 0x1 != 0).then(|| (u64at(data, 0), u64at(data, 8)));
                let embedded = if stream.is_none() { data.to_vec() } else { vec![] };
                xattrs.entry(id).or_default().insert(name, Xattr { embedded, stream });
            }
            8 => {
                let (len, paddr) = (u64at(v, 0) & 0x00ff_ffff_ffff_ffff, u64at(v, 8));
                extents.entry(id).or_default().push((u64at(k, 8), len, paddr));
            }
            9 => {
                let (name_off, name_len) = if hashed { (12, (u32at(k, 8) & 0x3ff) as usize) } else { (10, u16at(k, 8) as usize) };
                let name = String::from_utf8_lossy(&k[name_off..name_off + name_len - 1]).into_owned();
                drecs.push(Drec { parent: id, name, ino: u64at(v, 0), dtype: u16at(v, 16) & 0xf });
            }
            _ => {}
        }
        Ok(())
    })?;

    let read_stream = |id: u64, size: u64| -> Result<Vec<u8>> {
        let mut out = vec![0u8; size as usize];
        for &(logical, len, paddr) in extents.get(&id).map(|v| v.as_slice()).unwrap_or_default() {
            if paddr == 0 || logical >= size {
                continue;
            }
            let n = len.min(size - logical) as usize;
            let src = c.data.get(paddr as usize * BLOCK_SIZE..paddr as usize * BLOCK_SIZE + n).context("extent past end of image")?;
            out[logical as usize..logical as usize + n].copy_from_slice(src);
        }
        Ok(out)
    };
    let xattr_value = |ino: u64, name: &str| -> Result<Option<Vec<u8>>> {
        match xattrs.get(&ino).and_then(|m| m.get(name)) {
            None => Ok(None),
            Some(Xattr { stream: Some((id, size)), .. }) => Ok(Some(read_stream(*id, *size)?)),
            Some(x) => Ok(Some(x.embedded.clone())),
        }
    };

    let mut children: HashMap<u64, Vec<&Drec>> = HashMap::new();
    for d in &drecs {
        children.entry(d.parent).or_default().push(d);
    }
    for list in children.values_mut() {
        list.sort_by(|a, b| a.name.cmp(&b.name));
    }

    let mut out = vec![];
    let mut stack: Vec<(u64, String)> = vec![(2, String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut subdirs = vec![];
        for d in children.get(&dir).map(|v| v.as_slice()).unwrap_or_default() {
            let path = if prefix.is_empty() { d.name.clone() } else { format!("{prefix}/{}", d.name) };
            let ino = inodes.get(&d.ino).with_context(|| format!("{path}: inode {} missing", d.ino))?;
            let mut e = FileEntry {
                path: path.clone(),
                kind: EntryKind::Dir,
                mode: ino.mode & 0o7777,
                uid: ino.uid,
                gid: ino.gid,
                mtime_ns: ino.mtime,
                size: 0,
            };
            match d.dtype {
                4 => subdirs.push((d.ino, path)),
                8 if ino.bsd_flags & 0x20 != 0 => {
                    let decmpfs = xattr_value(d.ino, "com.apple.decmpfs")?.with_context(|| format!("{path}: compressed without decmpfs"))?;
                    let rsrc = xattr_value(d.ino, "com.apple.ResourceFork")?.unwrap_or_default();
                    e.size = if ino.uncompressed_size != 0 { ino.uncompressed_size } else { u64at(&decmpfs, 8) };
                    e.kind = EntryKind::Compressed(Compressed { decmpfs, rsrc });
                }
                8 => {
                    e.size = ino.dstream_size;
                    e.kind = EntryKind::File(Source::Mem(read_stream(ino.private_id, ino.dstream_size)?));
                }
                10 => {
                    let t = xattr_value(d.ino, "com.apple.fs.symlink")?.with_context(|| format!("{path}: symlink without target"))?;
                    let t = t.strip_suffix(&[0]).unwrap_or(&t);
                    e.kind = EntryKind::Symlink(String::from_utf8(t.to_vec())?);
                }
                t => bail!("{path}: unsupported file type {t}"),
            }
            out.push(e);
        }
        // depth-first, children right after their parent
        for s in subdirs.into_iter().rev() {
            stack.push(s);
        }
    }
    Ok(out)
}
