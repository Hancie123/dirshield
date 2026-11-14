//! Chunked authenticated encryption for arbitrarily large files ("blobs").
//!
//! Blob layout (all integers little endian):
//!
//! ```text
//! offset size
//! 0      4    magic  "DSHB"
//! 4      1    version (1)
//! 5      1    kind   (0 = file content, 1 = manifest)
//! 6      2    reserved (0)
//! 8      4    chunk size in bytes (default 4 MiB)
//! 12     16   file id (random per blob)
//! 28     ...  chunks: ciphertext || 16-byte GCM tag; every chunk except the
//!             last holds exactly `chunk size` plaintext bytes. An empty file is
//!             a single empty final chunk (tag only).
//! ```
//!
//! Security properties (STREAM construction, Hoang-Reyhanitabar-Rogaway-Vizár):
//! * Per-blob key  = HKDF-SHA256(vault key, salt = file id, info = kind label).
//!   File ids are 128-bit random, so every blob has its own key.
//! * Nonce         = chunk index (u64 BE) || 0x000000 || last-flag. Unique per
//!   (key, chunk), never reused: a re-encrypted file always gets a new file id.
//! * AAD           = vault id || blob header || chunk index || last-flag.
//!   Binds each chunk to its vault, blob, position, and finality, so reordering,
//!   swapping between blobs/vaults, truncation and extension all fail to verify.
//! * Plaintext of a chunk is only released after its tag verifies.

use std::io::{self, Read, Write};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};

use crate::domain::error::{Error, Result};
use crate::security::crypto::{hkdf32, random_bytes};

pub const BLOB_MAGIC: &[u8; 4] = b"DSHB";
pub const BLOB_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 28;
pub const TAG_LEN: usize = 16;
pub const DEFAULT_CHUNK: u32 = 4 * 1024 * 1024;
const MAX_CHUNK: u32 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlobKind {
    File = 0,
    Manifest = 1,
}

impl BlobKind {
    fn label(self) -> &'static [u8] {
        match self {
            BlobKind::File => b"dirshield/v1/file-key",
            BlobKind::Manifest => b"dirshield/v1/manifest-key",
        }
    }
}

fn header_bytes(kind: BlobKind, chunk: u32, file_id: &[u8; 16]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(BLOB_MAGIC);
    h[4] = BLOB_VERSION;
    h[5] = kind as u8;
    h[8..12].copy_from_slice(&chunk.to_le_bytes());
    h[12..28].copy_from_slice(file_id);
    h
}

fn nonce_for(index: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&index.to_be_bytes());
    n[11] = last as u8;
    n
}

fn aad_for(vault_id: &[u8; 16], header: &[u8; HEADER_LEN], index: u64, last: bool) -> [u8; 16 + HEADER_LEN + 9] {
    let mut a = [0u8; 16 + HEADER_LEN + 9];
    a[..16].copy_from_slice(vault_id);
    a[16..16 + HEADER_LEN].copy_from_slice(header);
    a[16 + HEADER_LEN..16 + HEADER_LEN + 8].copy_from_slice(&index.to_le_bytes());
    a[16 + HEADER_LEN + 8] = last as u8;
    a
}

/// Exact ciphertext size of a blob holding `plain` bytes.
pub fn blob_size(plain: u64, chunk: u32) -> u64 {
    let chunks = if plain == 0 { 1 } else { plain.div_ceil(chunk as u64) };
    HEADER_LEN as u64 + plain + chunks * TAG_LEN as u64
}

pub fn chunk_count(plain: u64, chunk: u32) -> u64 {
    if plain == 0 {
        1
    } else {
        plain.div_ceil(chunk as u64)
    }
}

/// Streaming encryptor implementing `io::Write`. Memory use is one chunk.
pub struct BlobWriter<W: Write> {
    inner: W,
    cipher: Aes256Gcm,
    vault_id: [u8; 16],
    header: [u8; HEADER_LEN],
    chunk: usize,
    buf: Vec<u8>,
    index: u64,
    plain_total: u64,
}

impl<W: Write> BlobWriter<W> {
    pub fn new(mut inner: W, vault_key: &[u8; 32], vault_id: &[u8; 16], kind: BlobKind, chunk: u32) -> Result<(Self, [u8; 16])> {
        let file_id = random_bytes::<16>();
        let header = header_bytes(kind, chunk, &file_id);
        inner.write_all(&header)?;
        let key = hkdf32(vault_key, &file_id, kind.label());
        let cipher = Aes256Gcm::new((&*key).into());
        Ok((Self { inner, cipher, vault_id: *vault_id, header, chunk: chunk as usize, buf: Vec::with_capacity(chunk as usize + TAG_LEN), index: 0, plain_total: 0 }, file_id))
    }

    fn emit(&mut self, last: bool) -> io::Result<()> {
        let nonce = nonce_for(self.index, last);
        let aad = aad_for(&self.vault_id, &self.header, self.index, last);
        let tag = self.cipher.encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut self.buf).map_err(|_| io::Error::other("encryption failed"))?;
        self.inner.write_all(&self.buf)?;
        self.inner.write_all(&tag)?;
        self.index = self.index.checked_add(1).ok_or_else(|| io::Error::other("chunk counter overflow"))?;
        self.buf.clear();
        Ok(())
    }

    /// Emits the final chunk and returns (inner writer, plaintext bytes, chunk count).
    pub fn finish(mut self) -> io::Result<(W, u64, u64)> {
        self.emit(true)?;
        self.inner.flush()?;
        Ok((self.inner, self.plain_total, self.index))
    }
}

impl<W: Write> Write for BlobWriter<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let total = data.len();
        while !data.is_empty() {
            // Only emit a full chunk once we know more data follows it, so the
            // final chunk can always be flagged as final.
            if self.buf.len() == self.chunk {
                self.emit(false)?;
            }
            let take = (self.chunk - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        self.plain_total += total as u64;
        Ok(total)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(()) // chunks are only written whole; see finish()
    }
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub struct BlobInfo {
    pub file_id: [u8; 16],
    pub plain_bytes: u64,
    pub chunks: u64,
}

/// Decrypts and authenticates a blob, passing verified plaintext chunks to `sink`.
/// `on_chunk` is called between chunks and may abort (pause/cancel support).
pub fn decrypt_blob<R: Read>(
    mut r: R,
    vault_key: &[u8; 32],
    vault_id: &[u8; 16],
    expect_kind: BlobKind,
    expect_file_id: Option<&[u8; 16]>,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<BlobInfo> {
    let mut header = [0u8; HEADER_LEN];
    if read_full(&mut r, &mut header)? != HEADER_LEN || &header[0..4] != BLOB_MAGIC {
        return Err(Error::Integrity("encrypted object header is missing or damaged".into()));
    }
    if header[4] != BLOB_VERSION {
        return Err(Error::Format(format!("blob version {}", header[4])));
    }
    if header[5] != expect_kind as u8 || header[6] != 0 || header[7] != 0 {
        return Err(Error::Integrity("encrypted object has an unexpected type".into()));
    }
    let chunk = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if chunk == 0 || chunk > MAX_CHUNK {
        return Err(Error::Integrity("invalid chunk size".into()));
    }
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&header[12..28]);
    if let Some(e) = expect_file_id {
        if e != &file_id {
            return Err(Error::Integrity("encrypted object does not belong to this entry".into()));
        }
    }
    let key = hkdf32(vault_key, &file_id, expect_kind.label());
    let cipher = Aes256Gcm::new((&*key).into());

    let full = chunk as usize + TAG_LEN;
    let mut cur = vec![0u8; full];
    let mut next = vec![0u8; full];
    let mut cur_n = read_full(&mut r, &mut cur)?;
    let mut index: u64 = 0;
    let mut plain: u64 = 0;
    loop {
        let mut next_n = 0;
        let last = if cur_n < full {
            true
        } else {
            next_n = read_full(&mut r, &mut next)?;
            next_n == 0
        };
        if cur_n < TAG_LEN {
            return Err(Error::Integrity("encrypted data is truncated".into()));
        }
        let (body, tag) = cur[..cur_n].split_at_mut(cur_n - TAG_LEN);
        let nonce = nonce_for(index, last);
        let aad = aad_for(vault_id, &header, index, last);
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, body, Tag::from_slice(tag))
            .map_err(|_| Error::Integrity(format!("chunk {index} failed authentication (corrupted, modified, truncated or wrong key)")))?;
        plain += body.len() as u64;
        sink(body)?;
        index += 1;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_n = next_n;
    }
    Ok(BlobInfo { file_id, plain_bytes: plain, chunks: index })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::crypto::random_key;

    fn roundtrip(len: usize, chunk: u32) {
        let vk = random_key();
        let vid = random_bytes::<16>();
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let (mut w, fid) = BlobWriter::new(Vec::new(), &vk, &vid, BlobKind::File, chunk).unwrap();
        // write in odd-sized pieces to exercise buffering
        for piece in data.chunks(7) {
            w.write_all(piece).unwrap();
        }
        let (ct, n, chunks) = w.finish().unwrap();
        assert_eq!(n as usize, len);
        assert_eq!(chunks, chunk_count(len as u64, chunk));
        assert_eq!(ct.len() as u64, blob_size(len as u64, chunk));
        let mut out = Vec::new();
        let info = decrypt_blob(&ct[..], &vk, &vid, BlobKind::File, Some(&fid), |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(out, data);
        assert_eq!(info.plain_bytes as usize, len);
    }

    #[test]
    fn roundtrips_at_boundaries() {
        for len in [0, 1, 63, 64, 65, 128, 129, 1000] {
            roundtrip(len, 64);
        }
    }

    fn sample() -> (crate::security::crypto::Key32, [u8; 16], Vec<u8>) {
        let vk = random_key();
        let vid = random_bytes::<16>();
        let (mut w, _) = BlobWriter::new(Vec::new(), &vk, &vid, BlobKind::File, 64).unwrap();
        w.write_all(&[7u8; 200]).unwrap();
        (vk, vid, w.finish().unwrap().0)
    }

    fn fails(vk: &[u8; 32], vid: &[u8; 16], ct: &[u8]) -> bool {
        decrypt_blob(ct, vk, vid, BlobKind::File, None, |_| Ok(())).is_err()
    }

    #[test]
    fn detects_corruption_truncation_extension_reordering() {
        let (vk, vid, ct) = sample();
        // flipped ciphertext bit
        let mut c = ct.clone();
        c[HEADER_LEN + 5] ^= 1;
        assert!(fails(&vk, &vid, &c));
        // flipped tag bit
        let mut c = ct.clone();
        let l = c.len();
        c[l - 1] ^= 1;
        assert!(fails(&vk, &vid, &c));
        // truncated at a chunk boundary (drop the final chunk)
        let c = ct[..HEADER_LEN + 3 * (64 + 16)].to_vec();
        assert!(fails(&vk, &vid, &c));
        // extended
        let mut c = ct.clone();
        c.extend_from_slice(&[0u8; 80]);
        assert!(fails(&vk, &vid, &c));
        // swapped chunks 0 and 1
        let mut c = ct.clone();
        let a = HEADER_LEN;
        let b = HEADER_LEN + 80;
        let first: Vec<u8> = c[a..a + 80].to_vec();
        let second: Vec<u8> = c[b..b + 80].to_vec();
        c[a..a + 80].copy_from_slice(&second);
        c[b..b + 80].copy_from_slice(&first);
        assert!(fails(&vk, &vid, &c));
        // modified header (chunk size)
        let mut c = ct.clone();
        c[8] = 65;
        assert!(fails(&vk, &vid, &c));
        // wrong vault id / wrong key
        assert!(fails(&vk, &random_bytes::<16>(), &ct));
        assert!(fails(&random_key(), &vid, &ct));
        // intact still works
        assert!(!fails(&vk, &vid, &ct));
    }

    #[test]
    fn kind_is_enforced() {
        let (vk, vid, ct) = sample();
        assert!(decrypt_blob(&ct[..], &vk, &vid, BlobKind::Manifest, None, |_| Ok(())).is_err());
    }
}
