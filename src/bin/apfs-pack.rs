//! apfs-pack: build an APFS image from directory trees and tarballs (later sources override earlier ones).

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use apfs_writer::builder::{verify, Compressed, ContainerBuilder, EntryKind, FileEntry, Source};
use apfs_writer::Image;
use std::os::unix::fs::FileExt;
use clap::Parser;
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Build an APFS container image from directories and tarballs")]
struct Args {
    /// Output image path.
    #[arg(short, long)]
    out: PathBuf,
    /// Image size in MiB.
    #[arg(short, long, default_value_t = 280)]
    size_mb: u64,
    /// Volume label.
    #[arg(short, long, default_value = "ramdisk")]
    label: String,
    /// Existing APFS container image whose first volume is copied in first (compression preserved).
    #[arg(long)]
    image: Option<PathBuf>,
    /// Directory to copy into the volume root; repeatable.
    #[arg(long = "src")]
    srcs: Vec<PathBuf>,
    /// Tarball (.tar or .tar.gz) to extract over the volume; repeatable. Applied after all `--src`.
    #[arg(long = "tar")]
    tars: Vec<PathBuf>,
    /// Keep uid/gid from `--src` directories instead of forcing root:root (`--image` always keeps its own).
    #[arg(long)]
    keep_owner: bool,
}

/// Full value of an extended attribute, or `None` when absent. Does not follow symlinks
/// (`lgetxattr`).
fn xattr(path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    match xattr::get(path, name) {
        // `xattr::get` already maps ENODATA (no such attribute) to `Ok(None)`.
        Ok(value) => Ok(value),
        // ENOTSUP/EOPNOTSUPP: the name has no Linux xattr namespace (`com.apple.*` is only valid
        // on macOS), so it cannot exist on a Linux source tree.
        Err(err) if err.raw_os_error() == Some(libc::ENOTSUP) => Ok(None),
        Err(err) => Err(err).with_context(|| format!("{}: reading xattr {name}", path.display())),
    }
}

/// decmpfs header: "fpmc", algorithm u32, uncompressed size u64.
fn compressed(path: &Path) -> Result<Option<(Compressed, u64)>> {
    let Some(decmpfs) = xattr(path, "com.apple.decmpfs")? else { return Ok(None) };
    if decmpfs.len() < 16 || &decmpfs[..4] != b"fpmc" {
        bail!("{}: malformed com.apple.decmpfs", path.display());
    }
    let size = u64::from_le_bytes(decmpfs[8..16].try_into().unwrap());
    let rsrc = xattr(path, "com.apple.ResourceFork")?.unwrap_or_default();
    Ok(Some((Compressed { decmpfs, rsrc }, size)))
}

struct Tree {
    entries: BTreeMap<String, FileEntry>,
    keep_owner: bool,
    skipped: usize,
}

impl Tree {
    fn insert(&mut self, e: FileEntry) -> Result<()> {
        let mut dir = String::new();
        if let Some((parent, _)) = e.path.rsplit_once('/') {
            for part in parent.split('/') {
                if !dir.is_empty() {
                    dir.push('/');
                }
                dir.push_str(part);
                match self.entries.get(&dir) {
                    Some(p) if matches!(p.kind, EntryKind::Dir) => {}
                    Some(_) => bail!("{}: parent {dir} is not a directory", e.path),
                    None => {
                        let d = FileEntry { path: dir.clone(), kind: EntryKind::Dir, mode: 0o755, uid: 0, gid: 0, mtime_ns: e.mtime_ns, size: 0 };
                        self.entries.insert(dir.clone(), d);
                    }
                }
            }
        }
        if let Some(old) = self.entries.get(&e.path) {
            // keep the existing directory's children when a directory overlays a directory
            if matches!(old.kind, EntryKind::Dir) && matches!(e.kind, EntryKind::Dir) {
                let old = self.entries.get_mut(&e.path).unwrap();
                old.mode = e.mode;
                return Ok(());
            }
            let prefix = format!("{}/", e.path);
            self.entries.retain(|k, _| !k.starts_with(&prefix));
        }
        self.entries.insert(e.path.clone(), e);
        Ok(())
    }

    fn add_dir(&mut self, root: &Path, rel: &str) -> Result<()> {
        let dir = if rel.is_empty() { root.to_path_buf() } else { root.join(rel) };
        for ent in std::fs::read_dir(&dir).with_context(|| dir.display().to_string())? {
            let ent = ent?;
            let name = ent.file_name().into_string().map_err(|n| anyhow::anyhow!("non-UTF-8 name {n:?}"))?;
            let path = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            let full = ent.path();
            let md = std::fs::symlink_metadata(&full)?;
            let ft = md.file_type();
            let mut content_size = md.len();
            let kind = if ft.is_dir() {
                EntryKind::Dir
            } else if ft.is_symlink() {
                EntryKind::Symlink(std::fs::read_link(&full)?.into_os_string().into_string().map_err(|_| anyhow::anyhow!("{path}: non-UTF-8 link target"))?)
            } else if ft.is_file() {
                match compressed(&full)? {
                    Some((c, size)) => {
                        content_size = size;
                        EntryKind::Compressed(c)
                    }
                    None => EntryKind::File(Source::Path(full)),
                }
            } else {
                eprintln!("skipping special file {path}");
                self.skipped += 1;
                continue;
            };
            let (uid, gid) = if self.keep_owner { (md.uid(), md.gid()) } else { (0, 0) };
            let is_dir = matches!(kind, EntryKind::Dir);
            let e = FileEntry {
                path: path.clone(),
                kind,
                mode: (md.mode() & 0o7777) as u16,
                uid,
                gid,
                mtime_ns: (md.mtime() as u64) * 1_000_000_000 + md.mtime_nsec() as u64,
                size: content_size,
            };
            self.insert(e)?;
            if is_dir {
                self.add_dir(root, &path)?;
            }
        }
        Ok(())
    }

    fn add_tar(&mut self, file: &Path) -> Result<()> {
        let mut f = std::fs::File::open(file).with_context(|| file.display().to_string())?;
        let mut magic = [0u8; 2];
        f.read_exact(&mut magic)?;
        let f = std::fs::File::open(file)?;
        let rd: Box<dyn Read> = if magic == [0x1f, 0x8b] { Box::new(flate2::read::GzDecoder::new(f)) } else { Box::new(f) };
        let mut ar = tar::Archive::new(rd);
        for ent in ar.entries()? {
            let mut ent = ent?;
            let raw = ent.path()?.to_string_lossy().into_owned();
            let path = raw.trim_start_matches("./").trim_end_matches('/').to_string();
            if path.is_empty() || path == "." {
                continue;
            }
            let hdr = ent.header();
            let mode = (hdr.mode()? & 0o7777) as u16;
            let mtime_ns = hdr.mtime()? * 1_000_000_000;
            let (uid, gid) = if self.keep_owner { (hdr.uid()? as u32, hdr.gid()? as u32) } else { (0, 0) };
            let ty = hdr.entry_type();
            let (kind, size) = if ty.is_dir() {
                (EntryKind::Dir, 0)
            } else if ty.is_file() {
                let mut data = vec![];
                ent.read_to_end(&mut data)?;
                let n = data.len() as u64;
                (EntryKind::File(Source::Mem(data)), n)
            } else if ty.is_symlink() {
                let t = ent.link_name()?.context("symlink without target")?.to_string_lossy().into_owned();
                (EntryKind::Symlink(t), 0)
            } else if ty.is_hard_link() {
                let t = ent.link_name()?.context("hardlink without target")?.to_string_lossy().trim_start_matches("./").to_string();
                match self.entries.get(&t) {
                    Some(FileEntry { kind: EntryKind::File(Source::Mem(d)), .. }) => (EntryKind::File(Source::Mem(d.clone())), d.len() as u64),
                    Some(FileEntry { kind: EntryKind::File(Source::Path(p)), size, .. }) => (EntryKind::File(Source::Path(p.clone())), *size),
                    _ => bail!("{path}: hardlink target {t} not found"),
                }
            } else {
                eprintln!("skipping tar entry {path} ({ty:?})");
                self.skipped += 1;
                continue;
            };
            self.insert(FileEntry { path, kind, mode, uid, gid, mtime_ns, size })?;
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut tree = Tree { entries: BTreeMap::new(), keep_owner: args.keep_owner, skipped: 0 };
    if let Some(img) = &args.image {
        let data = std::fs::read(img).with_context(|| img.display().to_string())?;
        for mut e in apfs_writer::reader::read_root_tree(&data)? {
            tree.insert(e)?;
        }
    }
    for s in &args.srcs {
        tree.add_dir(s, "")?;
    }
    for t in &args.tars {
        tree.add_tar(t)?;
    }
    let entries: Vec<FileEntry> = tree.entries.into_values().collect();
    let (nf, nd, nl) = entries.iter().fold((0, 0, 0), |(f, d, l), e| match e.kind {
        EntryKind::File(_) | EntryKind::Compressed(_) => (f + 1, d, l),
        EntryKind::Dir => (f, d + 1, l),
        EntryKind::Symlink(_) => (f, d, l + 1),
    });
    let bytes: u64 = entries.iter().map(|e| e.size).sum();
    let nc = entries.iter().filter(|e| matches!(e.kind, EntryKind::Compressed(_))).count();
    eprintln!("{nf} files ({nc} compressed, {} MiB uncompressed), {nd} dirs, {nl} symlinks, {} skipped", bytes >> 20, tree.skipped);

    let block_count = args.size_mb * 1024 * 1024 / 4096;
    let mut image = Image::new(block_count * 4096);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos() as u64;
    let sealed = {
        let mut cb = ContainerBuilder::new(
            &mut image,
            block_count,
            &args.label,
            *uuid::Uuid::new_v4().as_bytes(),
            *uuid::Uuid::new_v4().as_bytes(),
            now,
            entries,
        )?;
        cb.build()?;
        cb.sealed
    };
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&args.out)?;
    image.write_to(&file).with_context(|| format!("writing {}", args.out.display()))?;

    // Check the objects as written to disk, not the in-memory copy.
    let mut bad = 0;
    for &(b, n) in &sealed {
        let mut obj = vec![0u8; n as usize * 4096];
        file.read_exact_at(&mut obj, b * 4096)?;
        bad += !verify(&obj) as usize;
    }
    if bad > 0 {
        bail!("{bad} of {} sealed objects fail their checksum", sealed.len());
    }
    eprintln!("wrote {} ({} MiB)", args.out.display(), args.size_mb);
    Ok(())
}
