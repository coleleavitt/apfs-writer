//! The container image while it is being built.
//!
//! The builder addresses the image by byte offset. The bytes are held in memory, but only up to
//! the highest offset written so far, so a multi-terabyte sparse container costs no more memory
//! than its metadata and file data. [`Image::write_to`] then writes the result with positioned
//! writes and leaves all-zero blocks as holes, so the output file stays sparse.
//!
//! This replaces mapping the output file into memory: a memory map is inherently `unsafe` in
//! Rust, because another process can shrink or change the file while it is mapped.

use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

/// Granularity for leaving holes in the output file.
const HOLE_BLOCK: usize = 4096;

/// An image of a fixed size whose unwritten bytes read as zero.
pub struct Image {
    len: u64,
    /// Bytes `0..buf.len()`; everything past it is still zero.
    buf: Vec<u8>,
}

impl Image {
    /// An all-zero image of `len` bytes. Nothing is allocated until bytes are written.
    pub fn new(len: u64) -> Self {
        Image { len, buf: Vec::new() }
    }

    /// Size of the image in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Writable view of the `n` bytes at `off`.
    ///
    /// # Panics
    ///
    /// If `off + n` is past the end of the image. That would be a bug in the caller's layout:
    /// [`ContainerBuilder::new`](crate::ContainerBuilder::new) rejects images too small for the
    /// planned layout before anything is written.
    pub fn bytes_mut(&mut self, off: usize, n: usize) -> &mut [u8] {
        let end = self.check(off, n);
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        &mut self.buf[off..end]
    }

    /// The `n` bytes at `off`. Bytes never written read as zero.
    ///
    /// # Panics
    ///
    /// If `off + n` is past the end of the image.
    pub fn bytes(&self, off: usize, n: usize) -> Cow<'_, [u8]> {
        let end = self.check(off, n);
        if end <= self.buf.len() {
            return Cow::Borrowed(&self.buf[off..end]);
        }
        let mut out = vec![0u8; n];
        if off < self.buf.len() {
            out[..self.buf.len() - off].copy_from_slice(&self.buf[off..]);
        }
        Cow::Owned(out)
    }

    /// Writes the image to `file`: truncates it, sizes it to [`len`](Self::len), and writes every
    /// block that isn't all zero. Zero blocks are left as holes.
    pub fn write_to(&self, file: &File) -> io::Result<()> {
        file.set_len(0)?;
        file.set_len(self.len)?;
        let blocks: Vec<&[u8]> = self.buf.chunks(HOLE_BLOCK).collect();
        let mut i = 0;
        while i < blocks.len() {
            if is_zero(blocks[i]) {
                i += 1;
                continue;
            }
            // One write per run of non-zero blocks.
            let start = i;
            while i < blocks.len() && !is_zero(blocks[i]) {
                i += 1;
            }
            let from = start * HOLE_BLOCK;
            let to = (from + (i - start) * HOLE_BLOCK).min(self.buf.len());
            file.write_all_at(&self.buf[from..to], from as u64)?;
        }
        Ok(())
    }

    fn check(&self, off: usize, n: usize) -> usize {
        let end = off.checked_add(n).expect("image range overflows usize");
        assert!(end as u64 <= self.len, "image range {off}..{end} is past its size {}", self.len);
        end
    }
}

fn is_zero(block: &[u8]) -> bool {
    block.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwritten_bytes_read_as_zero() {
        let mut img = Image::new(10 * 4096);
        img.bytes_mut(4096, 3).copy_from_slice(b"abc");
        assert_eq!(&*img.bytes(4095, 5), b"\0abc\0");
        assert_eq!(&*img.bytes(8 * 4096, 4096), &[0u8; 4096][..]);
        assert_eq!(img.buf.len(), 4096 + 3, "only grows to the highest byte written");
    }

    #[test]
    #[should_panic(expected = "past its size")]
    fn writing_past_the_end_panics() {
        Image::new(4096).bytes_mut(4000, 200);
    }
}
