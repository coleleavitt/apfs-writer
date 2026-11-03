use apfs_writer::builder::{verify, ContainerBuilder, FileEntry};

/// Demo: a small container with one file. See `apfs-pack` for real images.
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (path, block_count) = match args.len() {
        3 => (args[1].clone(), args[2].parse::<u64>()?),
        _ => ("/tmp/test_container.apfs".into(), 4096),
    };
    let hello = b"Hello from the Rust APFS writer!\n".to_vec();

    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path)?;
    file.set_len(block_count * 4096)?;
    let mut image = unsafe { memmap2::MmapMut::map_mut(&file)? };
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
    image.flush()?;
    let ok = sealed.iter().filter(|&&(bno, n)| verify(&image[bno as usize * 4096..(bno + n) as usize * 4096])).count();
    println!("wrote {path}; checksummed objects: {ok} ok, {} bad", sealed.len() - ok);
    Ok(())
}
