//! Restore (decrypt) a vault, or selected items of it, to a folder. Files
//! are written to a temp name, verified on disk, then moved into place;
//! existing files are never overwritten.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::header::{VaultHeader, MANIFEST_FILE};
use super::super::manifest::{self, read_manifest, safe_rel_path, Line};
use super::super::scan::is_link;
use super::super::stream::{blob_size, decrypt_blob, BlobKind};
use super::control::ItemProgress;
use super::journal::{insert_items, run_journal};
use super::*;
use crate::domain::error::{Error, Result};
use crate::platform::fsutil::{self, RESTORABLE_ATTRS};
use crate::storage::db::{now_ms, Db};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DecryptParams {
    pub dest: String,
    /// "fail" | "skip" | "rename" – existing files are never overwritten.
    pub conflict: String,
    pub prev_status: String,
    /// Selective restore ("extract"): manifest paths of the chosen files and
    /// folders. Empty means the whole vault.
    #[serde(default)]
    pub include: Vec<String>,
    /// Folder (manifest path, "" = vault root) that every `include` entry is
    /// directly inside. Selected items land in `dest` relative to it, so
    /// extracting "a/b/report.pdf" gives `<dest>/report.pdf`.
    #[serde(default)]
    pub base: String,
}

impl DecryptParams {
    pub fn is_partial(&self) -> bool {
        !self.include.is_empty()
    }

    /// For a selective restore: the destination-relative path of manifest
    /// path `p`, or None if `p` is not selected (nor inside a selected folder).
    fn select(&self, p: &str, include: &std::collections::HashSet<&str>) -> Option<String> {
        if include.is_empty() {
            return Some(p.to_string());
        }
        let mut cur = p;
        let hit = loop {
            if include.contains(cur) {
                break true;
            }
            match cur.rfind('/') {
                Some(i) => cur = &cur[..i],
                None => break false,
            }
        };
        if !hit {
            return None;
        }
        if self.base.is_empty() {
            Some(p.to_string())
        } else {
            p.strip_prefix(&self.base).and_then(|r| r.strip_prefix('/')).map(str::to_string)
        }
    }

    /// Every selected path must sit directly inside `base` and be safe.
    fn validate_selection(&self) -> Result<()> {
        if !self.base.is_empty() {
            safe_rel_path(&self.base)?;
        }
        for i in &self.include {
            safe_rel_path(i)?;
            let parent = i.rfind('/').map(|n| &i[..n]).unwrap_or("");
            if parent != self.base {
                return Err(Error::Invalid("selected items must all be in the same folder".into()));
            }
        }
        Ok(())
    }
}

pub fn prepare_decrypt(db: &Db, op_id: &str, vault_dir: &Path, vk: &[u8; 32], p: &DecryptParams, ctrl: &Control) -> Result<()> {
    ctrl.set_phase("Verifying vault");
    let header = VaultHeader::read(vault_dir)?;
    header.verify_mac(vk)?;
    if !header.sealed {
        return Err(Error::Integrity("this vault was never completed".into()));
    }
    let vid = header.vault_id_bytes()?;
    let dest = PathBuf::from(&p.dest);
    if let Ok(m) = fs::symlink_metadata(&dest) {
        if !m.is_dir() || is_link(&m) {
            return Err(Error::Conflict("the destination exists and is not a folder".into()));
        }
    }
    p.validate_selection()?;
    let include: std::collections::HashSet<&str> = p.include.iter().map(String::as_str).collect();
    let mut matched = 0usize;
    let mut batch = Vec::with_capacity(BATCH);
    let mut next = 0i64;
    let (mut missing, mut conflicts, mut files, mut bytes) = (0u64, 0u64, 0u64, 0u64);
    let mut conflict_sample = String::new();
    read_manifest(BufReader::new(File::open(vault_dir.join(MANIFEST_FILE))?), vk, &vid, |line| {
        if ctrl.stopped() {
            return Err(Error::Cancelled);
        }
        let line = match line {
            Line::Dir { p: rel, a, m } => match p.select(&rel, &include) {
                Some(out) => Line::Dir { p: out, a, m },
                None => return Ok(()),
            },
            Line::File { p: rel, s, a, m, b, h, c } => match p.select(&rel, &include) {
                Some(out) => Line::File { p: out, s, a, m, b, h, c },
                None => return Ok(()),
            },
            _ => return Ok(()),
        };
        if cfg!(windows) {
            if let Line::Dir { p: rel, .. } | Line::File { p: rel, .. } = &line {
                if let Some(why) = manifest::windows_name_problem(rel) {
                    return Err(Error::Invalid(format!("“{rel}” cannot be restored on Windows: {why}. It was probably locked on another system; nothing was restored.")));
                }
            }
        }
        matched += 1;
        let item = match line {
            Line::Dir { p: rel, a, m } => Item { item_id: next, rel, kind: "d".into(), size: 0, mtime: m, attrs: a, blob_id: None, sha256: None },
            Line::File { p: rel, s, a, m, b, h, .. } => {
                let ok = hex::decode(&b).map(|v| v.len() == 16).unwrap_or(false) && fs::metadata(blob_path(vault_dir, &b)).map(|md| md.len() == blob_size(s, header.chunk_size)).unwrap_or(false);
                if !ok {
                    missing += 1;
                }
                if p.conflict == "fail" && fs::symlink_metadata(dest.join(safe_rel_path(&rel)?)).is_ok() {
                    conflicts += 1;
                    if conflict_sample.is_empty() {
                        conflict_sample = rel.clone();
                    }
                }
                files += 1;
                bytes += s;
                Item { item_id: next, rel, kind: "f".into(), size: s, mtime: m, attrs: a, blob_id: Some(b), sha256: Some(h) }
            }
            _ => return Ok(()),
        };
        next += 1;
        batch.push(item);
        if batch.len() >= BATCH {
            insert_items(db, op_id, &batch)?;
            batch.clear();
        }
        Ok(())
    })?;
    insert_items(db, op_id, &batch)?;
    if p.is_partial() && matched == 0 {
        return Err(Error::NotFound("the selected items in this vault".into()));
    }
    if missing > 0 {
        return Err(Error::Integrity(format!("{missing} encrypted object(s) are missing or damaged; nothing was restored")));
    }
    if conflicts > 0 {
        return Err(Error::Conflict(format!(
            "{conflicts} file(s) already exist at the destination (for example \"{conflict_sample}\"). Choose another location or a conflict option; files are never overwritten."
        )));
    }
    let free = fsutil::free_space(&dest)?;
    if bytes > free {
        return Err(Error::InsufficientSpace { need: bytes, free });
    }
    db.lock().execute("UPDATE operations SET total_files=?2, total_bytes=?3 WHERE id=?1", params![op_id, files as i64, bytes as i64])?;
    Ok(())
}

pub struct DecryptJob<'a> {
    pub db: &'a Db,
    pub op_id: &'a str,
    pub vault_id: &'a str,
    pub vault_dir: &'a Path,
    pub vk: &'a [u8; 32],
    pub params: &'a DecryptParams,
    pub workers: usize,
    pub ctrl: &'a Control,
}

pub fn run_decrypt(job: &DecryptJob) -> Result<()> {
    let header = VaultHeader::read(job.vault_dir)?;
    header.verify_mac(job.vk)?;
    let vid = header.vault_id_bytes()?;
    let dest = PathBuf::from(&job.params.dest);
    fs::create_dir_all(&dest)?;
    load_counters(job.db, job.op_id, job.ctrl)?;
    job.ctrl.set_phase("Decrypting");
    run_journal(job.db, job.op_id, job.ctrl, job.workers, |item| decrypt_item(job, &vid, &dest, item))?;
    let failed = count_status(job.db, job.op_id, "error")?;
    if failed > 0 {
        return Err(Error::Invalid(format!("{failed} item(s) could not be restored. The vault is intact; retry after fixing the cause.")));
    }
    job.ctrl.set_phase("Restoring folder attributes");
    // Directory timestamps/attributes last (adding files changes a folder's mtime). Deepest first.
    let mut last = i64::MAX;
    loop {
        let rows: Vec<(i64, String, Option<i64>, u32)> = {
            let c = job.db.lock();
            let mut st =
                c.prepare_cached("SELECT item_id, item_path_reference, mtime, attrs FROM operation_journal WHERE operation_id=?1 AND kind='d' AND item_id<?2 ORDER BY item_id DESC LIMIT ?3")?;
            let r = st.query_map(params![job.op_id, last, PAGE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            r
        };
        if rows.is_empty() {
            break;
        }
        for (id, rel, mtime, attrs) in rows {
            last = id;
            let p = dest.join(safe_rel_path(&rel)?);
            let _ = fsutil::set_mtime(&p, mtime);
            if attrs & RESTORABLE_ATTRS & !fsutil::FILE_ATTRIBUTE_ARCHIVE != 0 {
                let _ = fsutil::set_attrs(&p, attrs & RESTORABLE_ATTRS);
            }
        }
    }
    let now = now_ms();
    let mut c = job.db.lock();
    let tx = c.transaction()?;
    // Extracting a few files leaves the vault's state as it was.
    let status = if job.params.is_partial() { job.params.prev_status.as_str() } else { "restored" };
    tx.execute("UPDATE vaults SET status=?3, updated_at=?2 WHERE id=?1", params![job.vault_id, now, status])?;
    tx.execute("UPDATE operations SET status='completed', processed_bytes=total_bytes, error=NULL, updated_at=?2 WHERE id=?1", params![job.op_id, now])?;
    tx.execute("DELETE FROM operation_journal WHERE operation_id=?1", [job.op_id])?;
    tx.commit()?;
    Ok(())
}

pub(super) fn unique_target(target: &Path) -> Result<PathBuf> {
    let stem = target.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = target.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    for n in 1..10_000 {
        let label = if n == 1 { " (restored)".to_string() } else { format!(" (restored {n})") };
        let c = target.with_file_name(format!("{stem}{label}{ext}"));
        if fs::symlink_metadata(&c).is_err() {
            return Ok(c);
        }
    }
    Err(Error::Conflict("could not find a free file name".into()))
}

pub(super) fn decrypt_item(job: &DecryptJob, vid: &[u8; 16], dest: &Path, item: &Item) -> Result<Outcome> {
    let rel = safe_rel_path(&item.rel)?;
    let target = dest.join(&rel);
    if item.kind == "d" {
        if let Ok(m) = fs::symlink_metadata(&target) {
            if !m.is_dir() || is_link(&m) {
                return Err(Error::Conflict("a file with this folder's name already exists".into()));
            }
        }
        fs::create_dir_all(&target)?;
        return Ok(Outcome::Done { blob_id: None, sha256: None, chunks: None, size: 0, mtime: item.mtime, attrs: item.attrs });
    }
    let parent = target.parent().ok_or_else(|| Error::Invalid("bad target".into()))?;
    fs::create_dir_all(parent)?;
    let final_target = match fs::symlink_metadata(&target) {
        Ok(_) => match job.params.conflict.as_str() {
            "skip" => return Ok(Outcome::Skipped("already exists at destination".into())),
            "rename" => unique_target(&target)?,
            _ => return Err(Error::Conflict("file already exists at destination".into())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => target.clone(),
        Err(e) => return Err(e.into()),
    };
    let blob_id = item.blob_id.as_deref().ok_or_else(|| Error::Integrity("missing object id".into()))?;
    let fid: [u8; 16] = hex::decode(blob_id).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| Error::Integrity("bad object id".into()))?;
    let expect_sha = item.sha256.as_deref().unwrap_or("");
    let tmp = parent.join(format!("~dirshield-{}-{}.tmp", &job.op_id[..8], item.item_id));
    let _ = fs::remove_file(&tmp); // leftover from an interrupted attempt (our own temp name)
    let ctrl = job.ctrl;
    let mut prog = ItemProgress::new(ctrl);
    let result = (|| -> Result<Outcome> {
        let mut out = BufWriter::with_capacity(READ_BUF, fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?);
        let mut h = Sha256::new();
        let blob = BufReader::with_capacity(READ_BUF, File::open(blob_path(job.vault_dir, blob_id))?);
        let info = decrypt_blob(blob, job.vk, vid, BlobKind::File, Some(&fid), |b| {
            ctrl.checkpoint()?;
            h.update(b);
            out.write_all(b)?;
            prog.add(b.len() as u64 / 2);
            Ok(())
        })?;
        let f = out.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        drop(f);
        if info.plain_bytes != item.size || hex::encode(h.finalize()) != expect_sha {
            return Err(Error::Integrity("decrypted data does not match the recorded checksum".into()));
        }
        // Verify what actually landed on disk.
        let mut vh = Sha256::new();
        let mut r = File::open(&tmp)?;
        let mut buf = vec![0u8; READ_BUF];
        loop {
            ctrl.checkpoint()?;
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            vh.update(&buf[..n]);
            prog.add(n as u64 / 2);
        }
        drop(r);
        if hex::encode(vh.finalize()) != expect_sha {
            return Err(Error::Integrity("restored file failed verification on disk".into()));
        }
        fsutil::set_mtime(&tmp, item.mtime)?;
        fsutil::rename_noreplace(&tmp, &final_target).map_err(|e| {
            if e.raw_os_error() == Some(183) || e.raw_os_error() == Some(80) {
                Error::Conflict("file appeared at destination during restore".into())
            } else {
                Error::Io(e)
            }
        })?;
        let a = item.attrs & RESTORABLE_ATTRS & !fsutil::FILE_ATTRIBUTE_ARCHIVE;
        if a != 0 {
            let _ = fsutil::set_attrs(&final_target, item.attrs & RESTORABLE_ATTRS);
        }
        prog.settle(item.size);
        Ok(Outcome::Done { blob_id: None, sha256: None, chunks: None, size: item.size, mtime: item.mtime, attrs: item.attrs })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        prog.rollback();
    }
    result
}
