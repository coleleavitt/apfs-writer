use apfs_writer::builder::{verify, ContainerBuilder, FileEntry, Layout};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (path, block_count) = match args.len() {
        3 => (args[1].clone(), args[2].parse::<u64>()?),
        _ => ("/tmp/test_container.apfs".into(), 4096),
    };

    let files = vec![FileEntry {
        name: "hello.txt".into(),
        data: b"Hello from the Rust APFS writer! Nonces, seeds and cryptex data will live here.\n".to_vec(),
    }];
    let file_blocks = files.iter().map(|f| f.data.len().div_ceil(4096) as u64).sum();
    let l = Layout::compute(block_count, file_blocks);
    println!(
        "layout: {} blocks; omap@{} vol@{} cat@{}; ephemeral {}..{}",
        l.block_count, l.main_omap, l.first_vol, l.cat_root, l.reaper_bno, l.main_fq_bno
    );

    // a sparse file mapped in place: only the blocks we write take space
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path)?;
    file.set_len(block_count * 4096)?;
    let mut image = unsafe { memmap2::MmapMut::map_mut(&file)? };
    let sealed = {
        let mut cb = ContainerBuilder {
            image: &mut image,
            l,
            label: "ramdisk".into(),
            nx_uuid: *b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00",
            vol_uuid: *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
            timestamp: 1_700_000_000_000_000_000,
            sb_template: vec![],
            files,
            file_paddns: vec![],
            sealed: vec![],
        };
        cb.build()?;
        cb.sealed
    };

    image.flush()?;
    println!("wrote {path}");

    let ok = sealed
        .iter()
        .filter(|&&(bno, n)| verify(&image[bno as usize * 4096..(bno + n) as usize * 4096]))
        .count();
    println!("checksummed objects: {ok} ok, {} bad (of {} sealed)", sealed.len() - ok, sealed.len());
    Ok(())
}
