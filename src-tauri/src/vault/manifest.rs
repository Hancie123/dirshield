//! Encrypted manifest: the only place original names, directory structure,
//! sizes, timestamps and attributes are recorded. It is a stream of JSON lines
//! encrypted as a `BlobKind::Manifest` blob, so it is written and read with
//! bounded memory even for millions of entries.

use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::stream::{decrypt_blob, BlobKind};
use crate::domain::error::{Error, Result};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "t")]
pub enum Line {
    #[serde(rename = "h")]
    Head { v: u32, root_name: String, original_path: String, created_utc: i64 },
    #[serde(rename = "d")]
    Dir { p: String, a: u32, m: Option<i64> },
    #[serde(rename = "f")]
    File { p: String, s: u64, a: u32, m: Option<i64>, b: String, h: String, c: u64 },
    #[serde(rename = "e")]
    End { dirs: u64, files: u64, bytes: u64 },
}

pub fn write_line<W: Write>(w: &mut W, line: &Line) -> Result<()> {
    serde_json::to_writer(&mut *w, line)?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Streams manifest lines to `f`, enforcing structure: a Head first, an End
/// last whose counts match, and safe relative paths throughout.
pub fn read_manifest<R: std::io::Read>(r: R, vk: &[u8; 32], vault_id: &[u8; 16], mut f: impl FnMut(Line) -> Result<()>) -> Result<()> {
    let mut pending: Vec<u8> = Vec::new();
    let mut seen_head = false;
    let mut end: Option<(u64, u64, u64)> = None;
    let (mut dirs, mut files, mut bytes) = (0u64, 0u64, 0u64);
    let mut handle = |raw: &[u8], f: &mut dyn FnMut(Line) -> Result<()>| -> Result<()> {
        if raw.is_empty() {
            return Ok(());
        }
        if end.is_some() {
            return Err(Error::Integrity("manifest has data after its end marker".into()));
        }
        let line: Line = serde_json::from_slice(raw).map_err(|_| Error::Integrity("manifest entry is malformed".into()))?;
        match &line {
            Line::Head { .. } => {
                if seen_head {
                    return Err(Error::Integrity("duplicate manifest head".into()));
                }
                seen_head = true;
            }
            _ if !seen_head => return Err(Error::Integrity("manifest head missing".into())),
            Line::Dir { p, .. } => {
                safe_rel_path(p)?;
                dirs += 1;
            }
            Line::File { p, s, .. } => {
                safe_rel_path(p)?;
                files += 1;
                bytes = bytes.checked_add(*s).ok_or_else(|| Error::Integrity("manifest sizes overflow".into()))?;
            }
            Line::End { dirs: d, files: fl, bytes: b } => end = Some((*d, *fl, *b)),
        }
        f(line)
    };
    decrypt_blob(r, vk, vault_id, BlobKind::Manifest, None, |chunk| {
        pending.extend_from_slice(chunk);
        while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            let rest = pending.split_off(pos + 1);
            let line = std::mem::replace(&mut pending, rest);
            handle(&line[..line.len() - 1], &mut f)?;
        }
        if pending.len() > 1024 * 1024 {
            return Err(Error::Integrity("manifest line too long".into()));
        }
        Ok(())
    })?;
    let tail = std::mem::take(&mut pending);
    handle(&tail, &mut f)?;
    match end {
        Some((d, fl, b)) if d == dirs && fl == files && b == bytes => Ok(()),
        Some(_) => Err(Error::Integrity("manifest entry counts do not match".into())),
        None => Err(Error::Integrity("manifest is incomplete".into())),
    }
}

/// Validates a manifest-relative path ("a/b/c.txt"): no absolute paths, drive
/// prefixes, `..`, empty components, NTFS alternate data streams, or reserved
/// characters. Defence in depth – the manifest is authenticated anyway.
pub fn safe_rel_path(p: &str) -> Result<PathBuf> {
    if p.is_empty() || p.len() > 32_000 {
        return Err(Error::Integrity("invalid path in manifest".into()));
    }
    let mut out = PathBuf::new();
    for part in p.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(['\\', ':', '*', '?', '"', '<', '>', '|', '\0']) {
            return Err(Error::Integrity(format!("unsafe path in manifest: {p}")));
        }
        out.push(part);
    }
    if out.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(Error::Integrity(format!("unsafe path in manifest: {p}")));
    }
    Ok(out)
}

/// Why Windows cannot create a manifest path as-is, or `None` if it can.
/// `safe_rel_path` deliberately allows these names (a vault made elsewhere may
/// contain them and should stay browsable); restoring on Windows must not.
/// Covers reserved device names (CON, NUL, aux.txt, COM1…) and components
/// ending in a dot or space, which Windows silently strips.
pub fn windows_name_problem(p: &str) -> Option<String> {
    const RESERVED: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    for part in p.split('/') {
        if part.ends_with('.') || part.ends_with(' ') {
            return Some(format!("“{part}” ends with a dot or space"));
        }
        let stem = part.split('.').next().unwrap_or(part).trim_end_matches(' ').to_ascii_uppercase();
        let numbered = |prefix: &str| {
            stem.strip_prefix(prefix).is_some_and(|n| {
                let mut c = n.chars();
                matches!((c.next(), c.next()), (Some('1'..='9' | '¹' | '²' | '³'), None))
            })
        };
        if RESERVED.contains(&stem.as_str()) || numbered("COM") || numbered("LPT") {
            return Some(format!("“{part}” is a reserved name on Windows"));
        }
    }
    None
}

/// Relative path of `full` below `root`, with `/` separators.
pub fn rel_string(root: &Path, full: &Path) -> Result<String> {
    let rel = full.strip_prefix(root).map_err(|_| Error::Invalid("path outside of folder".into()))?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| match c {
            Component::Normal(s) => s.to_str().map(|s| s.to_string()).ok_or_else(|| Error::Invalid(format!("file name is not valid Unicode: {}", full.display()))),
            _ => Err(Error::Invalid("unexpected path component".into())),
        })
        .collect::<Result<_>>()?;
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_paths() {
        for p in ["", "..", "a/../b", "C:/x", "a//b", "/a", "a\\b", "file.txt:stream", "./a"] {
            assert!(safe_rel_path(p).is_err(), "{p}");
        }
        assert!(safe_rel_path("Ünïcode/名前/file (1).txt").is_ok());
    }

    #[test]
    fn flags_windows_unfriendly_names() {
        for p in ["CON", "nul", "a/aux.txt", "Com1", "lpt9.log", "x/CONOUT$", "nul .txt", "dir./f", "f ", "a/b."] {
            assert!(windows_name_problem(p).is_some(), "{p}");
        }
        for p in ["console", "a/null.txt", "COM", "COM10", "LPT0", "auxiliary/x", "a.b/c", ".hidden", "Ünïcode/名前/file (1).txt"] {
            assert!(windows_name_problem(p).is_none(), "{p}");
        }
    }
}
