// SPDX-License-Identifier: AGPL-3.0-or-later
//! Turn a path into an import: a `.fit` file, a folder of them, or a zip of them (the twin of the
//! FIT half of `ingest/sources.py`; a Connect-export layout is recognised and refused until
//! slice 2 adds export ingest).
//!
//! Two passes over the FIT bytes: first collect every UTC offset the files state, so local dates
//! resolve consistently regardless of file order; then decode and write.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::clock::ClockOffsets;
use crate::fit;
use crate::redact::mask_label;
use crate::writer::{ImportStats, Writer, WriterError};

pub const TRANSPORT_DROP: &str = "drop";
/// The transports `--transport` accepts.
pub const TRANSPORTS: [&str; 5] = ["connect_export", "usb", "gadgetbridge", "ciq", "drop"];

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("no such file or folder: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("{0}")]
    Writer(#[from] WriterError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("this looks like a Connect account export; export ingest arrives in slice 2 of the Rust port")]
    ExportUnsupported,
}

/// The folder an extracted Connect account export keeps its data in.
pub const EXPORT_ROOT: &str = "DI_CONNECT";

/// `connect_export.looks_like_export`: true for an extracted export root, its `DI_CONNECT`
/// folder, or the outer zip (any entry whose first component is `DI_CONNECT` or that sits inside
/// a `DI_CONNECT/` folder).
pub fn looks_like_export(path: &Path) -> bool {
    if path.is_dir() {
        let named = path.file_name().is_some_and(|n| n == EXPORT_ROOT);
        return named || path.join(EXPORT_ROOT).is_dir();
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if path.is_file() && suffix_lower(&name) == ".zip" {
        let Ok(file) = fs::File::open(path) else {
            return false;
        };
        let Ok(mut archive) = zip::ZipArchive::new(file) else {
            return false;
        };
        let inside = format!("/{EXPORT_ROOT}/");
        return (0..archive.len()).any(|i| {
            archive.by_index_raw(i).is_ok_and(|entry| {
                let entry_name = entry.name();
                entry_name.split('/').next() == Some(EXPORT_ROOT) || entry_name.contains(&inside)
            })
        });
    }
    false
}

/// Python's `PurePath.suffix`: the text from the last dot, unless the dot is the first or last character.
fn suffix_lower(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => name[i..].to_lowercase(),
        _ => String::new(),
    }
}

/// Sort key reproducing Python's `sorted(Path)` order: component by component, not by the joined string.
fn components_key(relative: &Path) -> Vec<Vec<u8>> {
    relative.components().map(|c| c.as_os_str().as_encoded_bytes().to_vec()).collect()
}

/// Every regular file under `root` (symlinked files included, symlinked directories not entered,
/// as `Path.rglob("*")` does), as paths relative to `root`.
fn walk_files(root: &Path, relative: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let rel = relative.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            walk_files(root, &rel, out)?;
        } else if fs::metadata(root.join(&rel)).map(|m| m.is_file()).unwrap_or(false) {
            out.push(rel);
        }
    }
    Ok(())
}

fn le16(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn le32(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// The start of the end-of-central-directory record (the last one in the file).
fn end_record(raw: &[u8]) -> Option<usize> {
    let floor = raw.len().saturating_sub(22 + 65_535);
    (floor..=raw.len().checked_sub(22)?)
        .rev()
        .find(|&i| raw[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])
}

/// Entry count the central directory states (`None` for zip64 sentinels or no directory).
fn directory_entry_count(raw: &[u8]) -> Option<usize> {
    let count = le16(raw, end_record(raw)? + 10)?;
    (count != 0xFFFF).then_some(count)
}

/// `(name, bytes)` for every central-directory entry, same-named ones included, stable-sorted by
/// name. Stored and deflated entries only (what the zip crate is built with here); no zip64.
fn duplicate_aware_entries(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, SourceError> {
    let bad = || SourceError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "unreadable zip directory"));
    let end = end_record(raw).ok_or_else(bad)?;
    let count = le16(raw, end + 10).ok_or_else(bad)?;
    let mut at = le32(raw, end + 16).ok_or_else(bad)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if raw.get(at..at + 4) != Some(&[0x50, 0x4b, 0x01, 0x02]) {
            return Err(bad());
        }
        let flags = le16(raw, at + 8).ok_or_else(bad)?;
        let method = le16(raw, at + 10).ok_or_else(bad)?;
        let packed = le32(raw, at + 20).ok_or_else(bad)?;
        let name_len = le16(raw, at + 28).ok_or_else(bad)?;
        let extra_len = le16(raw, at + 30).ok_or_else(bad)?;
        let comment_len = le16(raw, at + 32).ok_or_else(bad)?;
        let local = le32(raw, at + 42).ok_or_else(bad)?;
        let name = String::from_utf8_lossy(raw.get(at + 46..at + 46 + name_len).ok_or_else(bad)?).into_owned();
        at += 46 + name_len + extra_len + comment_len;
        if flags & 1 != 0 || raw.get(local..local + 4) != Some(&[0x50, 0x4b, 0x03, 0x04]) {
            return Err(bad());
        }
        let data_at = local + 30 + le16(raw, local + 26).ok_or_else(bad)? + le16(raw, local + 28).ok_or_else(bad)?;
        let packed_bytes = raw.get(data_at..data_at + packed).ok_or_else(bad)?;
        let mut bytes = Vec::new();
        match method {
            0 => bytes.extend_from_slice(packed_bytes),
            8 => {
                flate2::read::DeflateDecoder::new(packed_bytes).read_to_end(&mut bytes)?;
            }
            _ => return Err(bad()),
        }
        entries.push((name, bytes));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

/// `(label, bytes)` for every `.fit` under `path` (file, folder or zip), in the Python order.
/// Labels are masked relative names: never a table value, only the run's failure report.
pub fn iter_fit_files(path: &Path) -> Result<Vec<(String, Vec<u8>)>, SourceError> {
    let is_file = path.is_file();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if is_file && suffix_lower(&name) == ".zip" {
        let mut archive = zip::ZipArchive::new(fs::File::open(path)?)?;
        // The zip crate keys entries by name, so of two same-named entries it keeps one; the
        // oracle imports both. When the directory states more entries than the crate kept, read
        // the directory directly.
        let raw = fs::read(path)?;
        if directory_entry_count(&raw).is_some_and(|stated| stated > archive.len()) {
            let mut out = Vec::new();
            for (entry_name, bytes) in duplicate_aware_entries(&raw)? {
                if entry_name.ends_with('/') || !entry_name.to_lowercase().ends_with(".fit") {
                    continue;
                }
                out.push((mask_label(&entry_name), bytes));
            }
            return Ok(out);
        }
        // `sorted(infolist(), key=filename)` is stable, so equal names would keep archive order.
        let mut entries: Vec<(String, usize)> = Vec::with_capacity(archive.len());
        for index in 0..archive.len() {
            entries.push((archive.by_index_raw(index)?.name().to_string(), index));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out = Vec::new();
        for (entry_name, index) in entries {
            if entry_name.ends_with('/') || !entry_name.to_lowercase().ends_with(".fit") {
                continue;
            }
            let mut entry = archive.by_index(index)?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            out.push((mask_label(&entry_name), bytes));
        }
        return Ok(out);
    }
    if is_file {
        return Ok(vec![(mask_label(&name), fs::read(path)?)]);
    }
    let mut files = Vec::new();
    walk_files(path, Path::new(""), &mut files)?;
    files.retain(|rel| rel.file_name().is_some_and(|n| suffix_lower(&n.to_string_lossy()) == ".fit"));
    files.sort_by_key(|rel| components_key(rel));
    let mut out = Vec::with_capacity(files.len());
    for rel in files {
        out.push((mask_label(&rel.to_string_lossy()), fs::read(path.join(&rel))?));
    }
    Ok(out)
}

fn import_batch(files: &[(String, Vec<u8>)], writer: &mut Writer<'_>) -> Result<(), WriterError> {
    for (_label, data) in files {
        writer.offsets.extend(fit::scan_clock_offsets(data));
    }
    for (label, data) in files {
        writer.write_fit(data, label, None)?;
    }
    writer.derive_daily_steps()?;
    writer.derive_daily_from_samples()?;
    Ok(())
}

/// Import whatever `path` is into `conn` (a writable connection holding the write lock) and report.
/// `transport` defaults to `drop`.
pub fn import_path(conn: &Connection, path: &Path, transport: Option<&str>) -> Result<ImportStats, SourceError> {
    if !path.exists() {
        return Err(SourceError::NotFound(path.display().to_string()));
    }
    if looks_like_export(path) {
        return Err(SourceError::ExportUnsupported);
    }
    let transport = transport.unwrap_or(TRANSPORT_DROP);
    let mut writer = Writer::new(conn, ClockOffsets::load(conn)?, transport);
    writer.begin_run()?;
    let outcome = iter_fit_files(path)
        .and_then(|files| import_batch(&files, &mut writer).map_err(SourceError::from));
    if let Err(error) = outcome {
        writer.finish_run(Some(&error.to_string()))?;
        return Err(error);
    }
    writer.stats.dates_assumed_utc = writer.offsets.assumed_utc();
    writer.finish_run(None)?;
    Ok(writer.stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zip_with(path: &Path, entries: &[(&str, &[u8])]) {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(fs::File::create(path).expect("create zip"));
        let options = zip::write::SimpleFileOptions::default();
        for (name, bytes) in entries {
            writer.start_file(*name, options).expect("start entry");
            writer.write_all(bytes).expect("write entry");
        }
        writer.finish().expect("finish zip");
    }

    #[test]
    fn export_layouts_are_recognised_like_the_oracle() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The extracted root holds a DI_CONNECT folder.
        let root = dir.path().join("export");
        fs::create_dir_all(root.join("DI_CONNECT/DI-Connect-Wellness")).expect("mkdir");
        assert!(looks_like_export(&root));
        // The DI_CONNECT folder itself.
        assert!(looks_like_export(&root.join("DI_CONNECT")));
        // A plain folder of FIT files is not one.
        let plain = dir.path().join("plain");
        fs::create_dir_all(&plain).expect("mkdir");
        assert!(!looks_like_export(&plain));
        // Outer zips: first component or an inner DI_CONNECT folder.
        let first = dir.path().join("first.zip");
        zip_with(&first, &[("DI_CONNECT/a.json", b"[]")]);
        assert!(looks_like_export(&first));
        let nested = dir.path().join("nested.ZIP");
        zip_with(&nested, &[("wrapper/DI_CONNECT/a.json", b"[]")]);
        assert!(looks_like_export(&nested));
        let other = dir.path().join("other.zip");
        zip_with(&other, &[("DI_CONNECTED/a.json", b"[]"), ("x.fit", b"")]);
        assert!(!looks_like_export(&other));
        // Not a zip at all, or not there.
        let bad = dir.path().join("bad.zip");
        fs::write(&bad, b"nope").expect("write");
        assert!(!looks_like_export(&bad));
        assert!(!looks_like_export(&dir.path().join("missing")));
    }

    #[test]
    fn zip_entries_with_the_same_name_are_all_returned_in_archive_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dup.zip");
        // The zip writer refuses duplicate names, so write distinct ones of equal length and
        // rename the second in both its local header and the central directory.
        zip_with(
            &path,
            &[("b.fit", b"second-name"), ("a.fit", b"first"), ("c.fit", b"again"), ("skip.txt", b"x")],
        );
        let mut raw = fs::read(&path).expect("read zip");
        let needle = b"c.fit";
        let mut at = 0;
        while let Some(found) = raw[at..].windows(needle.len()).position(|w| w == needle) {
            raw[at + found] = b'a';
            at += found + needle.len();
        }
        fs::write(&path, raw).expect("write zip");
        let files = iter_fit_files(&path).expect("read zip");
        let bytes: Vec<&[u8]> = files.iter().map(|f| f.1.as_slice()).collect();
        assert_eq!(bytes, [b"first".as_slice(), b"again", b"second-name"]);
    }

    #[test]
    fn importing_an_export_layout_is_refused_for_now() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("DI_CONNECT")).expect("mkdir");
        let conn = Connection::open_in_memory().expect("memory db");
        let error = import_path(&conn, dir.path(), None).expect_err("export input is refused");
        assert!(matches!(error, SourceError::ExportUnsupported));
        assert!(!error.to_string().contains('\n'));
    }

    #[test]
    fn suffix_follows_python() {
        assert_eq!(suffix_lower("a.FIT"), ".fit");
        assert_eq!(suffix_lower(".fit"), "");
        assert_eq!(suffix_lower("a."), "");
        assert_eq!(suffix_lower("a.b.zip"), ".zip");
    }

    #[test]
    fn folder_order_is_component_wise_like_python_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        for rel in ["a-b/x.fit", "a/x.fit", "a.fit", "a/b.fit", "skip.txt", "a/Y.FIT"] {
            let path = dir.path().join(rel);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(&path, rel.as_bytes()).expect("write");
        }
        let labels: Vec<String> = iter_fit_files(dir.path()).expect("walk").into_iter().map(|f| f.0).collect();
        // Python: sorted(Path) compares part by part: "a" < "a-b" < "a.fit", and "Y" < "b" inside a/
        assert_eq!(labels, ["a/Y.FIT", "a/b.fit", "a/x.fit", "a-b/x.fit", "a.fit"]);
    }
}
