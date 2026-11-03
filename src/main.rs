#![forbid(unsafe_code)]

use apfs_writer::builder::{verify, ContainerBuilder, FileEntry};
use apfs_writer::Image;
use std::os::unix::fs::FileExt;

/// Demo: a small container with one file. See `apfs-pack` for real images.
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (path, block_count) = match args.len() {
        3 => (args[1].clone(), args[2].parse::<u64>()?),
        _ => ("/tmp/test_container.apfs".into(), 4096),
    };
    let hello = b"Hello from the Rust APFS writer!\n".to_vec();

    let mut image = Image::new(block_count * 4096);
    let sealed = {
        let mut cb = ContainerBuilder::new(
            &mut image,
            block_count,
            "ramdisk",
            *b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00",
            *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
            1_700_000_000_000_000_000,
            vec![FileEntry::file_mem("hello.txt", hello)],
        )?;
        cb.build()?;
        cb.sealed
    };
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path)?;
    image.write_to(&file)?;

    // Check the objects as written to disk, not the in-memory copy.
    let mut ok = 0;
    for &(bno, n) in &sealed {
        let mut obj = vec![0u8; n as usize * 4096];
        file.read_exact_at(&mut obj, bno * 4096)?;
        ok += verify(&obj) as usize;
    }
    println!("wrote {path}; checksummed objects: {ok} ok, {} bad", sealed.len() - ok);
    Ok(())
}
