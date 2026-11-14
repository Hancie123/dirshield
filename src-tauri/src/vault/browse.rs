//! Read-only view of a sealed vault: the decrypted manifest as a folder tree,
//! for browsing a vault and pulling single files out of it without a full
//! restore. Nothing here writes to the vault.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::engine::blob_path;
use super::header::{VaultHeader, MANIFEST_FILE};
use super::manifest::{read_manifest, Line};
use super::stream::{blob_size, decrypt_blob, BlobKind};
use crate::domain::error::{Error, Result};
use crate::platform::fsutil;

const ROOT: u32 = 0;

struct Node {
    name: String,
    parent: u32,
    dir: bool,
    /// Files: size. Folders: total size of everything inside.
    size: u64,
    /// Folders: number of files inside (recursively).
    files: u64,
    mtime: Option<i64>,
    blob: Option<String>,
    sha: Option<String>,
}

pub struct VaultIndex {
    nodes: Vec<Node>,
    children: HashMap<u32, Vec<u32>>,
    vault_id: [u8; 16],
    chunk: u32,
    pub root_name: String,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    /// Manifest path ("a/b/c.txt"), the handle the UI passes back.
    pub path: String,
    pub dir: bool,
    pub size: u64,
    pub files: u64,
    /// Milliseconds since the Unix epoch.
    pub modified: Option<i64>,
}

pub struct FileRef {
    pub name: String,
    pub size: u64,
    blob: String,
    sha: String,
}

impl VaultIndex {
    /// Decrypts and indexes the manifest of a sealed vault.
    pub fn load(vault_dir: &Path, vk: &[u8; 32]) -> Result<Self> {
        let header = VaultHeader::read(vault_dir)?;
        header.verify_mac(vk)?;
        if !header.sealed {
            return Err(Error::Integrity("this vault was never completed".into()));
        }
        let vault_id = header.vault_id_bytes()?;
        let mut ix = VaultIndex {
            nodes: vec![Node { name: String::new(), parent: ROOT, dir: true, size: 0, files: 0, mtime: None, blob: None, sha: None }],
            children: HashMap::new(),
            vault_id,
            chunk: header.chunk_size,
            root_name: String::new(),
            files: 0,
            bytes: 0,
        };
        // Path -> node while building only.
        let mut by_path: HashMap<String, u32> = HashMap::new();
        read_manifest(BufReader::new(File::open(vault_dir.join(MANIFEST_FILE))?), vk, &vault_id, |l| {
            match l {
                Line::Head { root_name, .. } => ix.root_name = root_name,
                Line::Dir { p, m, .. } => {
                    let id = ix.ensure_dir(&mut by_path, &p);
                    ix.nodes[id as usize].mtime = m;
                }
                Line::File { p, s, m, b, h, .. } => {
                    let (parent, name) = match p.rfind('/') {
                        Some(i) => (ix.ensure_dir(&mut by_path, &p[..i]), p[i + 1..].to_string()),
                        None => (ROOT, p.clone()),
                    };
                    let id = ix.push(Node { name, parent, dir: false, size: s, files: 1, mtime: m, blob: Some(b), sha: Some(h) });
                    by_path.insert(p, id);
                    ix.files += 1;
                    ix.bytes += s;
                }
                Line::End { .. } => {}
            }
            Ok(())
        })?;
        drop(by_path);
        // Parents always come before their children, so one reverse pass
        // rolls sizes and counts up the tree.
        for i in (1..ix.nodes.len()).rev() {
            let (parent, size, files) = (ix.nodes[i].parent, ix.nodes[i].size, ix.nodes[i].files);
            let p = &mut ix.nodes[parent as usize];
            p.size += size;
            p.files += files;
        }
        let nodes = &ix.nodes;
        for list in ix.children.values_mut() {
            list.sort_by(|&a, &b| {
                let (a, b) = (&nodes[a as usize], &nodes[b as usize]);
                b.dir.cmp(&a.dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())).then_with(|| a.name.cmp(&b.name))
            });
        }
        Ok(ix)
    }

    fn push(&mut self, n: Node) -> u32 {
        let id = self.nodes.len() as u32;
        self.children.entry(n.parent).or_default().push(id);
        self.nodes.push(n);
        id
    }

    /// Node for folder `p`, creating it (and missing parents) if needed.
    fn ensure_dir(&mut self, by_path: &mut HashMap<String, u32>, p: &str) -> u32 {
        if let Some(&id) = by_path.get(p) {
            return id;
        }
        let (parent, name) = match p.rfind('/') {
            Some(i) => (self.ensure_dir(by_path, &p[..i]), &p[i + 1..]),
            None => (ROOT, p),
        };
        let id = self.push(Node { name: name.to_string(), parent, dir: true, size: 0, files: 0, mtime: None, blob: None, sha: None });
        by_path.insert(p.to_string(), id);
        id
    }

    fn resolve(&self, path: &str) -> Option<u32> {
        if path.is_empty() {
            return Some(ROOT);
        }
        let mut cur = ROOT;
        for part in path.split('/') {
            cur = *self.children.get(&cur)?.iter().find(|&&c| self.nodes[c as usize].name == part)?;
        }
        Some(cur)
    }

    /// Contents of folder `dir` ("" = the vault's top level): folders first, then by name.
    pub fn list(&self, dir: &str) -> Result<Vec<Entry>> {
        let id = self.resolve(dir).filter(|&i| self.nodes[i as usize].dir).ok_or_else(|| Error::NotFound("folder in this vault".into()))?;
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        Ok(self
            .children
            .get(&id)
            .map(|c| {
                c.iter()
                    .map(|&i| {
                        let n = &self.nodes[i as usize];
                        Entry { name: n.name.clone(), path: format!("{prefix}{}", n.name), dir: n.dir, size: n.size, files: n.files, modified: n.mtime.map(|ns| ns / 1_000_000) }
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Checks that every path exists in the vault; returns (files, bytes) selected.
    pub fn measure(&self, paths: &[String]) -> Result<(u64, u64)> {
        let (mut files, mut bytes) = (0, 0);
        for p in paths {
            let id = self.resolve(p).ok_or_else(|| Error::NotFound(format!("\"{p}\" in this vault")))?;
            files += self.nodes[id as usize].files;
            bytes += self.nodes[id as usize].size;
        }
        Ok((files, bytes))
    }

    pub fn file(&self, path: &str) -> Result<FileRef> {
        let n = self.resolve(path).map(|i| &self.nodes[i as usize]).filter(|n| !n.dir).ok_or_else(|| Error::NotFound(format!("file \"{path}\" in this vault")))?;
        Ok(FileRef { name: n.name.clone(), size: n.size, blob: n.blob.clone().unwrap_or_default(), sha: n.sha.clone().unwrap_or_default() })
    }

    /// Decrypts one file to `out` (which must not exist): authenticated chunk
    /// by chunk, checked against its recorded SHA-256, written to a temp name
    /// first and only renamed into place once verified.
    pub fn decrypt_file(&self, vault_dir: &Path, vk: &[u8; 32], f: &FileRef, out: &Path) -> Result<()> {
        let fid: [u8; 16] = hex::decode(&f.blob).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| Error::Integrity("bad object id".into()))?;
        let src = blob_path(vault_dir, &f.blob);
        if fs::metadata(&src).map(|m| m.len()).ok() != Some(blob_size(f.size, self.chunk)) {
            return Err(Error::Integrity(format!("the encrypted object for \"{}\" is missing or damaged", f.name)));
        }
        let parent = out.parent().ok_or_else(|| Error::Invalid("bad target".into()))?;
        let tmp = parent.join(format!("~dirshield-{}.tmp", &f.blob[..8]));
        let _ = fs::remove_file(&tmp);
        let result = (|| -> Result<()> {
            let mut w = BufWriter::new(fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?);
            let mut h = Sha256::new();
            let info = decrypt_blob(BufReader::new(File::open(&src)?), vk, &self.vault_id, BlobKind::File, Some(&fid), |b| {
                h.update(b);
                w.write_all(b)?;
                Ok(())
            })?;
            let file = w.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            drop(file);
            if info.plain_bytes != f.size || hex::encode(h.finalize()) != f.sha {
                return Err(Error::Integrity("decrypted data does not match the recorded checksum".into()));
            }
            fsutil::rename_noreplace(&tmp, out)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

/// Extensions that run code, mount content or carry active content (macros,
/// script in web pages) when "opened". Those files can be extracted, but
/// DirShield won't launch them straight out of a vault.
pub fn is_executable(name: &str) -> bool {
    // Grouped by kind, several per line: rustfmt would put each on its own line.
    #[rustfmt::skip]
    const EXT: &[&str] = &[
        // Programs, installers and scripts
        "exe", "com", "bat", "cmd", "scr", "pif", "msi", "msp", "msix", "msixbundle", "appx", "appxbundle", "appinstaller", "ps1", "psm1", "psd1", "ps1xml", "psc1", "vb", "vbs", "vbe", "js", "jse",
        "wsf", "wsh", "wsc", "sct", "hta", "cpl", "msc", "jar", "dll", "sys", "drv", "ocx", "inf", "reg", "xll", "application", "appref-ms", "xbap", "vsto", "gadget", "diagcab",
        // Shortcuts and shell files that point at or run something else
        "lnk", "url", "scf", "library-ms", "settingcontent-ms", "search-ms", "searchconnector-ms",
        // Disk images: opening one mounts it and shows whatever is inside
        "iso", "img", "vhd", "vhdx",
        // Office files with macros, add-ins, OneNote
        "docm", "dotm", "xlsm", "xltm", "xlam", "xla", "pptm", "potm", "ppsm", "ppam", "sldm", "one", "onepkg",
        // Web pages and active documents (script runs in the viewer)
        "htm", "html", "xht", "xhtml", "mht", "mhtml", "svg", "svgz", "chm",
    ];
    let lower = name.trim_end_matches(['.', ' ']).to_lowercase();
    lower.rsplit_once('.').map(|(_, e)| EXT.contains(&e)).unwrap_or(false)
}

/// Marks a file as downloaded from the internet (Mark of the Web: a
/// `Zone.Identifier` stream with ZoneId=3). Office then opens it in Protected
/// View, SmartScreen and attachment checks apply, and Windows warns before
/// running anything inside it. Best effort: needs NTFS.
pub fn mark_from_internet(file: &Path) -> Result<()> {
    let mut ads = file.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).open(PathBuf::from(ads))?;
    f.write_all(
        b"[ZoneTransfer]
ZoneId=3
",
    )?;
    Ok(())
}

/// Overwrites every file below `dir` with zeros, then deletes the tree.
/// Best effort: files still open in another program are left for a later
/// attempt. Returns true if `dir` is gone.
///
/// This is NOT secure erasure. On SSDs (wear levelling, TRIM), on
/// copy-on-write or journaling file systems and with Volume Shadow Copies or
/// file history, the old data can remain on the device. It only stops the
/// copy from being opened normally. See `WIPE_CAVEAT` for the user-facing text.
pub fn wipe_tree(dir: &Path) -> bool {
    if !dir.exists() {
        return true;
    }
    for e in walkdir::WalkDir::new(dir).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.path();
        let _ = fsutil::clear_readonly(p);
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(p) {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            let zeros = vec![0u8; 1024 * 1024];
            let mut left = len;
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
            let _ = f.sync_all();
        }
        let _ = fs::remove_file(p);
    }
    let _ = fs::remove_dir_all(dir);
    !dir.exists()
}

/// Shown wherever opened copies are mentioned to the user.
pub const WIPE_CAVEAT: &str = "Opening a file puts a decrypted copy on disk. DirShield overwrites and deletes it when you close the vault, but on SSDs the old data can remain on the drive. To keep a file from ever touching the disk unencrypted, don't open it from the vault.";

/// Wipes every leftover folder under DirShield's temp directory.
pub fn wipe_all(temp_root: &Path) {
    if let Ok(rd) = fs::read_dir(temp_root) {
        for e in rd.flatten() {
            wipe_tree(&e.path());
        }
    }
}

/// A fresh, private folder for one opened file.
pub fn new_temp_dir(temp_root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(temp_root)?;
    let d = temp_root.join(crate::security::crypto::random_id());
    fs::create_dir(&d)?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_detection() {
        for n in [
            "setup.EXE",
            "a.b.ps1",
            "x.lnk",
            "run.cmd",
            "console.msc",
            "app.appref-ms",
            "disk.iso",
            "d.vhdx",
            "budget.xlsm",
            "page.HTML",
            "pic.svg",
            "a.mht",
            "add.xll",
            "s.sct",
            "nb.one",
            "trick.exe.",
            "trick.exe ",
        ] {
            assert!(is_executable(n), "{n}");
        }
        for n in ["report.pdf", "photo.jpg", "notes", "archive.tar.gz", "exe"] {
            assert!(!is_executable(n), "{n}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn mark_from_internet_writes_zone_identifier() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("report.docx");
        fs::write(&f, b"data").unwrap();
        mark_from_internet(&f).unwrap();
        let mut ads = f.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        let zone = fs::read_to_string(PathBuf::from(ads)).unwrap();
        assert!(zone.contains("ZoneId=3"), "{zone}");
        assert_eq!(fs::read(&f).unwrap(), b"data");
    }

    #[test]
    fn wipe_removes_tree() {
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("t");
        fs::create_dir_all(t.join("x")).unwrap();
        fs::write(t.join("x").join("f.txt"), b"secret").unwrap();
        assert!(wipe_tree(&t));
        assert!(!t.exists());
    }
}
