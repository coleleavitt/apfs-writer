//! Golden test: builder output for fixed inputs must stay byte-identical.
//!
//! The expected hash was recorded with the builder as of 94c0b5c, before the image moved from a
//! memory-mapped file to `Image` + positioned writes. A change here means the on-disk format
//! changed: if that is intended, verify the new output (apfsck, kernel RW mount, device) and
//! update the hash.

use apfs_writer::builder::{verify, Compressed, ContainerBuilder, EntryKind, FileEntry, Source};
use apfs_writer::Image;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

const NX_UUID: [u8; 16] = *b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x01";
const VOL_UUID: [u8; 16] = *b"\x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a\xab\xbc\xcd\xde\xef\xf0";
const TS: u64 = 1_788_000_000_123_456_789;
const GOLDEN_65536: &str = "fb1858d0111be92328acf4462791031d2646f67a4ba89c5e948edb23f4347c57";

fn e(path: &str, kind: EntryKind, mode: u16, uid: u32, size: u64, mtime: u64) -> FileEntry {
    FileEntry { path: path.into(), kind, mode, uid, gid: uid, mtime_ns: mtime, size }
}

/// Every entry kind: nested dirs, symlink, a file read from disk, inline and resource-fork
/// compressed files, and 3000 files so the catalog, extentref and omap trees are multi-level.
fn entries(disk_file: &Path) -> Vec<FileEntry> {
    let mut v = vec![
        e("a", EntryKind::Dir, 0o755, 0, 0, TS),
        e("a/b", EntryKind::Dir, 0o700, 501, 0, TS + 1),
        e("c", EntryKind::Dir, 0o755, 0, 0, TS + 2),
        e("a/link", EntryKind::Symlink("../c/target".into()), 0o777, 0, 11, TS + 3),
    ];
    let disk_len = std::fs::metadata(disk_file).unwrap().len();
    v.push(e("c/from_disk.bin", EntryKind::File(Source::Path(disk_file.into())), 0o644, 0, disk_len, TS + 4));
    let inline = b"fpmc\x01\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00hello".to_vec();
    v.push(e("c/inline.cmp", EntryKind::Compressed(Compressed { decmpfs: inline, rsrc: vec![] }), 0o644, 0, 64, TS + 5));
    let rsrc: Vec<u8> = (0..10_000u32).map(|i| (i * 7 % 253) as u8).collect();
    let fork = b"fpmc\x04\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00".to_vec();
    v.push(e("c/fork.cmp", EntryKind::Compressed(Compressed { decmpfs: fork, rsrc }), 0o755, 0, 65536, TS + 6));
    for d in 0..10 {
        v.push(e(&format!("d{d}"), EntryKind::Dir, 0o755, 0, 0, TS + 10 + d));
        for f in 0..300u64 {
            let len = ((f * 37 + d * 11) % 9000) as usize;
            let data: Vec<u8> = (0..len).map(|i| ((i as u64 * 31 + f + d) % 251) as u8).collect();
            let mut fe = FileEntry::file_mem(&format!("d{d}/file_{f:04}.dat"), data);
            fe.mode = if f % 3 == 0 { 0o755 } else { 0o644 };
            fe.uid = (f % 2) as u32 * 501;
            fe.mtime_ns = TS + f * 1000;
            v.push(fe);
        }
    }
    v
}

/// Builds the fixed container on `blocks` blocks and writes it to a file in the test tmpdir.
fn build(name: &str, blocks: u64) -> (PathBuf, Vec<(u64, u64)>) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("golden");
    std::fs::create_dir_all(&dir).unwrap();
    let disk = dir.join("disk_input.bin");
    std::fs::write(&disk, (0..13_000u32).map(|i| (i * 13 % 241) as u8).collect::<Vec<_>>()).unwrap();

    let mut image = Image::new(blocks * 4096);
    let sealed = {
        let mut cb = ContainerBuilder::new(&mut image, blocks, "golden", NX_UUID, VOL_UUID, TS, entries(&disk)).unwrap();
        cb.build().unwrap();
        cb.sealed.clone()
    };
    let out = dir.join(name);
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&out).unwrap();
    image.write_to(&file).unwrap();
    (out, sealed)
}

fn sha256_file(path: &Path) -> String {
    let mut f = std::fs::File::open(path).unwrap();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn builder_output_is_byte_identical_to_golden() {
    let (out, sealed) = build("g_65536.img", 65536);
    assert_eq!(std::fs::metadata(&out).unwrap().len(), 65536 * 4096);
    assert_eq!(sha256_file(&out), GOLDEN_65536);

    // Every sealed object reads back from the file with a valid checksum.
    let file = std::fs::File::open(&out).unwrap();
    for &(bno, n) in &sealed {
        let mut obj = vec![0u8; n as usize * 4096];
        file.read_exact_at(&mut obj, bno * 4096).unwrap();
        assert!(verify(&obj), "object at block {bno} fails its checksum");
    }
}

#[test]
fn large_images_stay_sparse() {
    let (out, _) = build("g_1048576.img", 1 << 20);
    let meta = std::fs::metadata(&out).unwrap();
    assert_eq!(meta.len(), 4 << 30, "apparent size is the full 4 GiB");
    let allocated = meta.blocks() * 512;
    assert!(allocated < 64 << 20, "only written blocks are allocated, got {allocated} bytes");
}
