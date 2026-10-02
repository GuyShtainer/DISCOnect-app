// SPDX-License-Identifier: AGPL-3.0-or-later
//! Turn a path into an import: a `.fit` file, a folder of them, or a zip of them (the twin of the
//! FIT half of `ingest/sources.py`; the Connect-export layout is not handled here).
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

/// `(label, bytes)` for every `.fit` under `path` (file, folder or zip), in the Python order.
/// Labels are masked relative names: never a table value, only the run's failure report.
pub fn iter_fit_files(path: &Path) -> Result<Vec<(String, Vec<u8>)>, SourceError> {
    let is_file = path.is_file();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if is_file && suffix_lower(&name) == ".zip" {
        let mut archive = zip::ZipArchive::new(fs::File::open(path)?)?;
        let mut names: Vec<String> = archive.file_names().map(str::to_string).collect();
        names.sort();
        names.dedup();
        let mut out = Vec::new();
        for entry_name in names {
            if entry_name.ends_with('/') || !entry_name.to_lowercase().ends_with(".fit") {
                continue;
            }
            let mut entry = archive.by_name(&entry_name)?;
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
        writer.write_fit(data, label)?;
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
