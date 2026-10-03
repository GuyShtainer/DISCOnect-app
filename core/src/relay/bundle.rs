// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bundle format and cryptography: the twin of `hearthbeat/relay/bundle.py` (`docs/relay-protocol.md`).
//!
//! ```text
//! object  = version(1) || salt(32) || nonce(12) || ChaCha20-Poly1305(k, nonce, padded, AAD)
//! k       = HKDF-SHA256(master, salt, info = "hearthbeat/relay/v1/bundle")
//! AAD     = "hearthbeat/relay/v1/" || account || "/" || object name
//! padded  = u64be(len(z)) || z || zeros, to the Padme size with a 64 KiB floor
//! z       = zlib(JSON lines: header, then {"t":"r",..} records and {"t":"x",..} ranges)
//! account = hex(HKDF-SHA256(master, no salt, info = "hearthbeat/relay-account"))
//! ```
//!
//! A rejection carries the reason name the oracle records: its own constants (`truncated`,
//! `authentication_failed`, ...) or the Python exception class name of the defect (see
//! [`reasons`]). Both cores must accept each other's objects.

use std::io::Write;

use base64::Engine;
use base64::alphabet::STANDARD as STANDARD_ALPHABET;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use flate2::write::ZlibEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canon::{self, Value};

pub const FORMAT_VERSION: i64 = 1;
const INFO_BUNDLE: &[u8] = b"hearthbeat/relay/v1/bundle";
const INFO_ACCOUNT: &[u8] = b"hearthbeat/relay-account";
const AAD_PREFIX: &[u8] = b"hearthbeat/relay/v1/";
pub const PAD_FLOOR: usize = 64 * 1024;
pub const MAX_PLAINTEXT: usize = 64 * 1024 * 1024;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The smallest object a reader looks at: version, salt, nonce and one tag.
pub const ENVELOPE_LEN: usize = 1 + SALT_LEN + NONCE_LEN + TAG_LEN;

/// Every rejection reason a bundle can carry. The first group are the oracle's own constants; the
/// second are the Python exception class names `unpack` stores through `type(exc).__name__`
/// (a zlib failure and a failed `struct.unpack` are both the class `error`).
pub mod reasons {
    pub const TRUNCATED: &str = "truncated";
    pub const UNKNOWN_FORMAT: &str = "unknown_format";
    pub const AUTHENTICATION_FAILED: &str = "authentication_failed";
    pub const BAD_LENGTH: &str = "bad_length";
    pub const TOO_LARGE: &str = "too_large";
    pub const MISSING_HEADER: &str = "missing_header";
    pub const BAD_HEADER: &str = "bad_header";
    pub const BAD_RECORD: &str = "bad_record";
    pub const BAD_RANGE: &str = "bad_range";
    pub const BAD_BUNDLE: &str = "bad_bundle";
    /// `zlib.error` and `struct.error` (both classes are named `error`).
    pub const PY_ERROR: &str = "error";
    pub const PY_JSON_DECODE_ERROR: &str = "JSONDecodeError";
    pub const PY_UNICODE_DECODE_ERROR: &str = "UnicodeDecodeError";
    /// Read failures of the relay adapter (`OSError` subclasses and the folder's own errors).
    pub const PY_FILE_NOT_FOUND: &str = "FileNotFoundError";
    pub const PY_PERMISSION: &str = "PermissionError";
    pub const PY_IS_A_DIRECTORY: &str = "IsADirectoryError";
    pub const PY_NOT_A_DIRECTORY: &str = "NotADirectoryError";
    pub const PY_FILE_EXISTS: &str = "FileExistsError";
    pub const PY_INTERRUPTED: &str = "InterruptedError";
    pub const PY_TIMEOUT: &str = "TimeoutError";
    pub const PY_BLOCKING_IO: &str = "BlockingIOError";
    pub const PY_BROKEN_PIPE: &str = "BrokenPipeError";
    pub const PY_OS_ERROR: &str = "OSError";
    pub const PY_VALUE_ERROR: &str = "ValueError";
}

/// The columns of a `raw_records` row that travel (`id` never does), in the oracle's order.
pub const RECORD_COLUMNS: [&str; 12] = [
    "stream",
    "source_key",
    "source_scope",
    "transport",
    "device_id",
    "start_utc",
    "end_utc",
    "payload_kind",
    "payload",
    "payload_hash",
    "payload_bytes",
    "imported_at",
];

/// The object could not be authenticated, decoded or validated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct BundleRejected {
    pub reason: String,
}

fn reject(reason: &str) -> BundleRejected {
    BundleRejected {
        reason: reason.to_string(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// The oracle's `ValueError("bundle name must live under the master's account")`.
    #[error("bundle name must live under the master's account")]
    NameOutsideAccount,
    #[error("the operating system has no random bytes: {0}")]
    Random(String),
    #[error("encryption failed")]
    Seal,
    #[error("compression failed: {0}")]
    Compress(String),
}

/// One `raw_records` row as it travels. `payload` is the stored zlib bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRow {
    pub stream: String,
    pub source_key: String,
    pub source_scope: String,
    pub transport: String,
    pub device_id: Option<String>,
    pub start_utc: Option<String>,
    pub end_utc: Option<String>,
    pub payload_kind: String,
    pub payload: Vec<u8>,
    pub payload_hash: String,
    pub payload_bytes: i64,
    pub imported_at: String,
}

/// One `export_ranges` claim as it travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeRow {
    pub stream: String,
    pub from_day: String,
    pub to_day: String,
}

/// The header fields a reader needs (`core`, `records`, `ranges` are informational).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub device_id: String,
    pub device_seq: i64,
    pub prev: Option<String>,
    pub created_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub header: Header,
    pub records: Vec<RawRow>,
    pub ranges: Vec<RangeRow>,
}

fn hkdf_expand(master: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below the HKDF-SHA256 limit; expand cannot fail.
    if Hkdf::<Sha256>::new(salt, master)
        .expand(info, &mut *out)
        .is_err()
    {
        out.fill(0);
    }
    out
}

/// `hex(HKDF-SHA256(master, no salt, "hearthbeat/relay-account"))`: 64 hex characters.
pub fn account_for(master: &[u8]) -> String {
    hex::encode(*hkdf_expand(master, None, INFO_ACCOUNT))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], BundleError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| BundleError::Random(e.to_string()))?;
    Ok(out)
}

/// `account || "/" || 32 random hex`.
pub fn new_name(account: &str) -> Result<String, BundleError> {
    Ok(format!("{account}/{}", hex::encode(random_bytes::<16>()?)))
}

/// Padme (PURBs, Nikitin et al. 2019): round `length` up so only O(log log n) bits of it leak,
/// with a 64 KiB floor.
pub fn padme(length: usize) -> usize {
    let length = length.max(PAD_FLOOR) as u64;
    let exponent = u64::from(63 - length.leading_zeros());
    let s = u64::from(64 - exponent.leading_zeros());
    let low_bits = exponent - s;
    let mask = (1u64 << low_bits) - 1;
    ((length + mask) & !mask) as usize
}

fn aad(account: &str, name: &str) -> Vec<u8> {
    let mut out = AAD_PREFIX.to_vec();
    out.extend_from_slice(account.as_bytes());
    out.push(b'/');
    out.extend_from_slice(name.as_bytes());
    out
}

fn cipher(master: &[u8], salt: &[u8]) -> ChaCha20Poly1305 {
    let key = hkdf_expand(master, Some(salt), INFO_BUNDLE);
    ChaCha20Poly1305::new((&*key).into())
}

/// Standard base64 with padding, strict about padding like `b64decode(validate=True)`, lenient
/// about the unused trailing bits of the last character (as Python is).
fn b64() -> GeneralPurpose {
    GeneralPurpose::new(
        &STANDARD_ALPHABET,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
            .with_decode_allow_trailing_bits(true),
    )
}

fn text(s: &str) -> Value {
    Value::Str(s.to_string())
}

fn opt_text(s: &Option<String>) -> Value {
    s.as_ref().map_or(Value::Null, |v| text(v))
}

fn record_line(row: &RawRow) -> Vec<u8> {
    canon::dumps(&Value::Object(vec![
        ("t".to_string(), text("r")),
        ("stream".to_string(), text(&row.stream)),
        ("source_key".to_string(), text(&row.source_key)),
        ("source_scope".to_string(), text(&row.source_scope)),
        ("transport".to_string(), text(&row.transport)),
        ("device_id".to_string(), opt_text(&row.device_id)),
        ("start_utc".to_string(), opt_text(&row.start_utc)),
        ("end_utc".to_string(), opt_text(&row.end_utc)),
        ("payload_kind".to_string(), text(&row.payload_kind)),
        (
            "payload".to_string(),
            Value::Str(b64().encode(&row.payload)),
        ),
        ("payload_hash".to_string(), text(&row.payload_hash)),
        ("payload_bytes".to_string(), Value::Int(row.payload_bytes)),
        ("imported_at".to_string(), text(&row.imported_at)),
    ]))
}

fn range_line(range: &RangeRow) -> Vec<u8> {
    canon::dumps(&Value::Object(vec![
        ("t".to_string(), text("x")),
        ("stream".to_string(), text(&range.stream)),
        ("from_day".to_string(), text(&range.from_day)),
        ("to_day".to_string(), text(&range.to_day)),
    ]))
}

/// Encrypt `records` and `ranges` under `master` as the object called `name`. `core` names the
/// writing build in the header.
pub fn pack(
    master: &[u8],
    name: &str,
    core: &str,
    header: &Header,
    records: &[RawRow],
    ranges: &[RangeRow],
) -> Result<Vec<u8>, BundleError> {
    let head = Value::Object(vec![
        ("t".to_string(), text("h")),
        ("format".to_string(), Value::Int(FORMAT_VERSION)),
        ("core".to_string(), text(core)),
        ("device_id".to_string(), text(&header.device_id)),
        ("device_seq".to_string(), Value::Int(header.device_seq)),
        ("prev".to_string(), opt_text(&header.prev)),
        ("created_utc".to_string(), text(&header.created_utc)),
        (
            "records".to_string(),
            Value::Int(i64::try_from(records.len()).unwrap_or(i64::MAX)),
        ),
        (
            "ranges".to_string(),
            Value::Int(i64::try_from(ranges.len()).unwrap_or(i64::MAX)),
        ),
    ]);
    let mut lines = vec![canon::dumps(&head)];
    lines.extend(records.iter().map(record_line));
    lines.extend(ranges.iter().map(range_line));
    seal_lines(master, name, &lines)
}

/// The sealing step on already-serialised lines (tests craft malformed bundles through it).
pub fn seal_lines(master: &[u8], name: &str, lines: &[Vec<u8>]) -> Result<Vec<u8>, BundleError> {
    let account = account_for(master);
    if !name.starts_with(&format!("{account}/")) {
        return Err(BundleError::NameOutsideAccount);
    }
    let joined = lines.join(&b'\n');
    let compress = |e: std::io::Error| BundleError::Compress(e.to_string());
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(9));
    encoder.write_all(&joined).map_err(compress)?;
    let z = encoder.finish().map_err(compress)?;
    let mut padded = Vec::with_capacity(8 + z.len());
    padded.extend_from_slice(&(z.len() as u64).to_be_bytes());
    padded.extend_from_slice(&z);
    padded.resize(padme(padded.len()), 0);
    let salt = random_bytes::<SALT_LEN>()?;
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| BundleError::Seal)?;
    let sealed = cipher(master, &salt)
        .encrypt(
            &nonce,
            Payload {
                msg: &padded,
                aad: &aad(&account, name),
            },
        )
        .map_err(|_| BundleError::Seal)?;
    let mut object = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + sealed.len());
    object.push(FORMAT_VERSION as u8);
    object.extend_from_slice(&salt);
    object.extend_from_slice(&nonce_bytes);
    object.extend_from_slice(&sealed);
    Ok(object)
}

/// `zlib.decompressobj().decompress(data, cap)` plus the `unconsumed_tail` check: a truncated
/// stream is not an error (the partial text is what the caller parses), a stream that hits the
/// cap with input left over is `too_large`, any zlib defect is the class `error`.
fn inflate_capped(input: &[u8], cap: usize) -> Result<Vec<u8>, BundleRejected> {
    let mut inflater = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 256 * 1024];
    loop {
        if out.len() >= cap {
            if (inflater.total_in() as usize) < input.len() {
                return Err(reject(reasons::TOO_LARGE));
            }
            return Ok(out);
        }
        let consumed = inflater.total_in() as usize;
        let produced_before = inflater.total_out();
        let room = chunk.len().min(cap - out.len());
        let status = inflater
            .decompress(
                &input[consumed..],
                &mut chunk[..room],
                FlushDecompress::None,
            )
            .map_err(|_| reject(reasons::PY_ERROR))?;
        let produced = (inflater.total_out() - produced_before) as usize;
        out.extend_from_slice(&chunk[..produced]);
        let progressed = produced > 0 || inflater.total_in() as usize > consumed;
        if matches!(status, Status::StreamEnd) || !progressed {
            return Ok(out);
        }
    }
}

/// Authenticate and decode an object. Any defect is a [`BundleRejected`] with the oracle's reason.
pub fn unpack(master: &[u8], name: &str, blob: &[u8]) -> Result<Bundle, BundleRejected> {
    let account = account_for(master);
    if blob.len() < ENVELOPE_LEN {
        return Err(reject(reasons::TRUNCATED));
    }
    if i64::from(blob[0]) != FORMAT_VERSION {
        return Err(reject(reasons::UNKNOWN_FORMAT));
    }
    let salt = &blob[1..1 + SALT_LEN];
    let nonce = Nonce::try_from(&blob[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN])
        .map_err(|_| reject(reasons::TRUNCATED))?;
    let padded = cipher(master, salt)
        .decrypt(
            &nonce,
            Payload {
                msg: &blob[1 + SALT_LEN + NONCE_LEN..],
                aad: &aad(&account, name),
            },
        )
        .map_err(|_| reject(reasons::AUTHENTICATION_FAILED))?;
    let Some(prefix) = padded.get(..8) else {
        return Err(reject(reasons::PY_ERROR)); // struct.error
    };
    let length = u64::from_be_bytes(prefix.try_into().map_err(|_| reject(reasons::PY_ERROR))?);
    if length > MAX_PLAINTEXT as u64 || 8 + length > padded.len() as u64 {
        return Err(reject(reasons::BAD_LENGTH));
    }
    let inflated = inflate_capped(&padded[8..8 + length as usize], MAX_PLAINTEXT)?;
    let body =
        std::str::from_utf8(&inflated).map_err(|_| reject(reasons::PY_UNICODE_DECODE_ERROR))?;
    let mut items = Vec::new();
    for line in body.split('\n').filter(|l| !l.is_empty()) {
        items.push(
            canon::parse(line.as_bytes()).map_err(|_| reject(reasons::PY_JSON_DECODE_ERROR))?,
        );
    }
    validate(&items)
}

fn member<'a>(object: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    object.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// `isinstance(x, int)`: Python counts a bool as an int.
fn py_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Int(n)) => Some(*n),
        Some(Value::Bool(b)) => Some(i64::from(*b)),
        _ => None,
    }
}

/// `header.get("format") != 1` is false for `1`, `1.0` and `True` in Python.
fn py_equals_format(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Int(n)) => *n == FORMAT_VERSION,
        Some(Value::Float(x)) => *x == FORMAT_VERSION as f64,
        Some(Value::Bool(b)) => i64::from(*b) == FORMAT_VERSION,
        _ => false,
    }
}

fn string(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::Str(s)) => Some(s),
        _ => None,
    }
}

/// A column that must be a string, or null/absent where the oracle never looks at it.
fn nullable_string(
    object: &[(String, Value)],
    key: &str,
) -> Result<Option<String>, BundleRejected> {
    match member(object, key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s.clone())),
        // the oracle would carry any JSON value through; this port refuses what is not text
        Some(_) => Err(reject(reasons::BAD_RECORD)),
    }
}

fn validate(items: &[Value]) -> Result<Bundle, BundleRejected> {
    let Some(Value::Object(first)) = items.first() else {
        return Err(reject(reasons::MISSING_HEADER));
    };
    if string(member(first, "t")) != Some("h") {
        return Err(reject(reasons::MISSING_HEADER));
    }
    if !py_equals_format(member(first, "format")) {
        return Err(reject(reasons::UNKNOWN_FORMAT));
    }
    let device_id = string(member(first, "device_id"));
    let device_seq = py_int(member(first, "device_seq"));
    let prev = match member(first, "prev") {
        None | Some(Value::Null) => Some(None),
        Some(Value::Str(s)) => Some(Some(s.clone())),
        Some(_) => None,
    };
    let created_utc = string(member(first, "created_utc"));
    let (Some(device_id), Some(device_seq), Some(prev), Some(created_utc)) =
        (device_id, device_seq, prev, created_utc)
    else {
        return Err(reject(reasons::BAD_HEADER));
    };
    let header = Header {
        device_id: device_id.to_string(),
        device_seq,
        prev,
        created_utc: created_utc.to_string(),
    };
    let mut records = Vec::new();
    let mut ranges = Vec::new();
    for item in &items[1..] {
        let Value::Object(object) = item else {
            return Err(reject(reasons::BAD_BUNDLE));
        };
        match string(member(object, "t")) {
            Some("r") => records.push(decode_record(object)?),
            Some("x") => {
                let mut fields = Vec::with_capacity(3);
                for key in ["stream", "from_day", "to_day"] {
                    // a missing key is the oracle's KeyError -> the generic reason
                    let value = member(object, key).ok_or_else(|| reject(reasons::BAD_BUNDLE))?;
                    fields.push(value);
                }
                let (Value::Str(stream), Value::Str(from_day), Value::Str(to_day)) =
                    (fields[0], fields[1], fields[2])
                else {
                    return Err(reject(reasons::BAD_RANGE));
                };
                ranges.push(RangeRow {
                    stream: stream.clone(),
                    from_day: from_day.clone(),
                    to_day: to_day.clone(),
                });
            }
            _ => return Err(reject(reasons::BAD_BUNDLE)),
        }
    }
    Ok(Bundle {
        header,
        records,
        ranges,
    })
}

/// `decode_record` followed by the column type checks of `_validate`.
fn decode_record(object: &[(String, Value)]) -> Result<RawRow, BundleRejected> {
    // `item["payload"]` and `b64decode(..., validate=True)`: any failure is the generic reason
    let Some(Value::Str(encoded)) = member(object, "payload") else {
        return Err(reject(reasons::BAD_BUNDLE));
    };
    let payload = b64()
        .decode(encoded.as_bytes())
        .map_err(|_| reject(reasons::BAD_BUNDLE))?;
    let text_columns = [
        "stream",
        "source_key",
        "source_scope",
        "transport",
        "payload_kind",
        "payload_hash",
        "imported_at",
    ];
    let mut texts: Vec<String> = Vec::with_capacity(text_columns.len());
    for key in text_columns {
        match member(object, key) {
            Some(Value::Str(s)) => texts.push(s.clone()),
            _ => return Err(reject(reasons::BAD_RECORD)),
        }
    }
    let Some(payload_bytes) = py_int(member(object, "payload_bytes")) else {
        return Err(reject(reasons::BAD_RECORD));
    };
    let mut texts = texts.into_iter();
    let mut next = || texts.next().unwrap_or_default();
    let (stream, source_key, source_scope, transport) = (next(), next(), next(), next());
    let (payload_kind, payload_hash, imported_at) = (next(), next(), next());
    Ok(RawRow {
        stream,
        source_key,
        source_scope,
        transport,
        device_id: nullable_string(object, "device_id")?,
        start_utc: nullable_string(object, "start_utc")?,
        end_utc: nullable_string(object, "end_utc")?,
        payload_kind,
        payload,
        payload_hash,
        payload_bytes,
        imported_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn other() -> Vec<u8> {
        (1u8..33).collect()
    }

    fn row() -> RawRow {
        RawRow {
            stream: "fit:monitoring_b".into(),
            source_key: "a".repeat(64),
            source_scope: "device".into(),
            transport: "usb".into(),
            device_id: Some("7".into()),
            start_utc: None,
            end_utc: None,
            payload_kind: "fit".into(),
            payload: vec![0x78, 0x9c, 1, 2, 3],
            payload_hash: "a".repeat(64),
            payload_bytes: 1,
            imported_at: "2025-07-01T00:00:00Z".into(),
        }
    }

    fn header() -> Header {
        Header {
            device_id: "d".into(),
            device_seq: 1,
            prev: None,
            created_utc: "2025-07-01T00:00:00Z".into(),
        }
    }

    fn lines(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn padme_rounds_up_with_a_floor() {
        assert_eq!(padme(10), PAD_FLOOR);
        assert_eq!(padme(PAD_FLOOR), PAD_FLOOR);
        assert!(padme(PAD_FLOOR + 1) > PAD_FLOOR + 1);
        let big = padme(1_000_003);
        assert!(
            big >= 1_000_003 && ((big - 1_000_003) as f64) / 1_000_003.0 < 0.07,
            "overhead stays small"
        );
        // the Python oracle's values, computed with `relay.bundle.padme`
        for (input, expected) in [
            (100_000, 100_352),
            (1 << 20, 1 << 20),
            ((1 << 20) + 1, 1_081_344),
            (70_000, 71_680),
            (123_456, 124_928),
            (999_999, 1_015_808),
            (5_000_000, 5_111_808),
            (70_000_000, 71_303_168),
            (1_000_003, 1_015_808),
        ] {
            assert_eq!(padme(input), expected, "padme({input})");
        }
        // every output is a fixed point (a padded size is already a size)
        for n in [70_000, 123_456, 999_999, 5_000_000, 70_000_000] {
            assert_eq!(padme(padme(n)), padme(n));
        }
    }

    #[test]
    fn round_trip_and_every_defect_is_rejected_with_the_right_reason() {
        let name = new_name(&account_for(&master())).expect("name");
        let ranges = [RangeRow {
            stream: "json:uds".into(),
            from_day: "2025-06-01".into(),
            to_day: "2025-06-30".into(),
        }];
        let blob = pack(&master(), &name, "test", &header(), &[row()], &ranges).expect("pack");
        assert_eq!(
            blob.len(),
            ENVELOPE_LEN + PAD_FLOOR,
            "a tiny bundle pads to the 64 KiB floor plus the envelope"
        );
        let out = unpack(&master(), &name, &blob).expect("unpack");
        assert_eq!(out.header, header());
        assert_eq!(out.records, vec![row()]);
        assert_eq!(out.ranges, ranges.to_vec());
        let reason =
            |result: Result<Bundle, BundleRejected>| result.expect_err("must be rejected").reason;
        assert_eq!(
            reason(unpack(&other(), &name, &blob)),
            "authentication_failed",
            "a different master"
        );
        let renamed = new_name(&account_for(&master())).expect("name");
        assert_eq!(
            reason(unpack(&master(), &renamed, &blob)),
            "authentication_failed",
            "name bound in the AAD"
        );
        let mut flipped = blob.clone();
        flipped[200] ^= 1;
        assert_eq!(
            reason(unpack(&master(), &name, &flipped)),
            "authentication_failed"
        );
        let reason_cut = reason(unpack(&master(), &name, &blob[..blob.len() - 40]));
        assert!(reason_cut == "truncated" || reason_cut == "authentication_failed");
        assert_eq!(reason(unpack(&master(), &name, &blob[..10])), "truncated");
        let mut format = blob.clone();
        format[0] = 2;
        assert_eq!(reason(unpack(&master(), &name, &format)), "unknown_format");
        let outside = pack(&other(), &name, "test", &header(), &[], &[])
            .expect_err("name under another account");
        assert!(matches!(outside, BundleError::NameOutsideAccount));
    }

    #[test]
    fn two_packs_of_the_same_bundle_differ_and_both_open() {
        let name = new_name(&account_for(&master())).expect("name");
        let a = pack(&master(), &name, "t", &header(), &[row()], &[]).expect("pack");
        let b = pack(&master(), &name, "t", &header(), &[row()], &[]).expect("pack");
        assert_ne!(a, b, "a fresh salt and nonce per object");
        assert_eq!(
            unpack(&master(), &name, &a).expect("a"),
            unpack(&master(), &name, &b).expect("b")
        );
    }

    #[test]
    fn padded_length_classes_follow_padme() {
        let name = new_name(&account_for(&master())).expect("name");
        // incompressible payloads of growing size: the sealed length is always a Padme size
        for count in [1usize, 40, 300] {
            let mut rows = Vec::new();
            for i in 0..count {
                let mut r = row();
                r.source_key = format!("{i:064x}");
                // deterministic noise that zlib cannot shrink much
                r.payload = (0..900u32)
                    .map(|j| (j.wrapping_mul(2_654_435_761).rotate_left(i as u32 % 31) >> 13) as u8)
                    .collect();
                rows.push(r);
            }
            let blob = pack(&master(), &name, "t", &header(), &rows, &[]).expect("pack");
            let padded_len = blob.len() - ENVELOPE_LEN;
            assert_eq!(padme(padded_len), padded_len, "{count} records");
            assert!(padded_len >= PAD_FLOOR);
            assert_eq!(
                unpack(&master(), &name, &blob)
                    .expect("unpack")
                    .records
                    .len(),
                count
            );
        }
    }

    #[test]
    fn malformed_bundles_carry_the_oracles_reason_names() {
        let account = account_for(&master());
        let name = new_name(&account).expect("name");
        let head =
            r#"{"t":"h","format":1,"device_id":"zz","device_seq":1,"prev":null,"created_utc":"x"}"#;
        let seal = |items: &[&str]| seal_lines(&master(), &name, &lines(items)).expect("seal");
        let reason = |blob: Vec<u8>| {
            unpack(&master(), &name, &blob)
                .expect_err("rejected")
                .reason
        };
        // test_a_poison_bundle...: a range without to_day (KeyError) and a bare list item
        assert_eq!(
            reason(seal(&[head, r#"{"t":"x","stream":"s","from_day":"a"}"#])),
            "bad_bundle"
        );
        assert_eq!(reason(seal(&[head, "[1,2]"])), "bad_bundle");
        assert_eq!(
            reason(seal(&[r#"{"t":"h","format":1,"device_seq":"1"}"#])),
            "bad_header"
        );
        assert_eq!(
            reason(seal(&[
                head,
                r#"{"t":"x","stream":"s","from_day":1,"to_day":"b"}"#
            ])),
            "bad_range"
        );
        assert_eq!(reason(seal(&[head, r#"{"t":"q"}"#])), "bad_bundle");
        assert_eq!(reason(seal(&[])), "missing_header");
        assert_eq!(reason(seal(&[r#"{"t":"r"}"#])), "missing_header");
        assert_eq!(
            reason(seal(&[
                r#"{"t":"h","format":2,"device_id":"a","device_seq":1,"created_utc":"x"}"#
            ])),
            "unknown_format"
        );
        // a record with a bad column, a bad payload, a missing payload
        let good = String::from_utf8(record_line(&row())).expect("utf8");
        assert!(unpack(&master(), &name, &seal(&[head, &good])).is_ok());
        let bad_column = good.replace("\"payload_bytes\":1", "\"payload_bytes\":\"1\"");
        assert_eq!(reason(seal(&[head, &bad_column])), "bad_record");
        let b64_of_payload = b64().encode(&row().payload);
        let bad_payload = good.replace(&b64_of_payload, "%%%%");
        assert_eq!(reason(seal(&[head, &bad_payload])), "bad_bundle");
        let no_payload = good.replace("\"payload\":", "\"payloa_\":");
        assert_eq!(reason(seal(&[head, &no_payload])), "bad_bundle");
        // JSON and text defects are the Python class names
        assert_eq!(reason(seal(&[head, "{not json"])), "JSONDecodeError");
        let raw = seal_lines(&master(), &name, &[b"\xff\xfe".to_vec()]).expect("seal");
        assert_eq!(reason(raw), "UnicodeDecodeError");
        // a header may carry 1.0 or true as the format and a bool as the sequence, as Python accepts
        let lenient =
            r#"{"t":"h","format":1.0,"device_id":"a","device_seq":true,"created_utc":"x"}"#;
        let bundle = unpack(&master(), &name, &seal(&[lenient])).expect("python-compatible header");
        assert_eq!(bundle.header.device_seq, 1);
        // blank lines are skipped
        assert!(unpack(&master(), &name, &seal(&["", head, "", &good])).is_ok());
    }

    /// Hand-seal a padded body (length prefix, zlib bytes) to reach the post-decrypt checks.
    fn seal_padded(padded: &[u8], name: &str) -> Vec<u8> {
        let account = account_for(&master());
        let salt = [7u8; SALT_LEN];
        let nonce_bytes = [9u8; NONCE_LEN];
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce");
        let sealed = cipher(&master(), &salt)
            .encrypt(
                &nonce,
                Payload {
                    msg: padded,
                    aad: &aad(&account, name),
                },
            )
            .expect("seal");
        let mut object = vec![1u8];
        object.extend_from_slice(&salt);
        object.extend_from_slice(&nonce_bytes);
        object.extend_from_slice(&sealed);
        object
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(9));
        encoder.write_all(data).expect("write");
        encoder.finish().expect("finish")
    }

    #[test]
    fn post_decrypt_defects_follow_the_oracle() {
        let name = new_name(&account_for(&master())).expect("name");
        let reason = |padded: Vec<u8>| {
            unpack(&master(), &name, &seal_padded(&padded, &name))
                .expect_err("rejected")
                .reason
        };
        // fewer than 8 bytes: struct.error -> "error"
        assert_eq!(reason(vec![1, 2, 3]), "error");
        // a length beyond the body
        let mut over = (100u64).to_be_bytes().to_vec();
        over.extend_from_slice(&[0; 10]);
        assert_eq!(reason(over), "bad_length");
        // a length beyond the plaintext cap
        let mut huge = ((MAX_PLAINTEXT as u64) + 1).to_be_bytes().to_vec();
        huge.extend_from_slice(&[0; 10]);
        assert_eq!(reason(huge), "bad_length");
        // not a zlib stream: zlib.error -> "error"
        let mut junk = (4u64).to_be_bytes().to_vec();
        junk.extend_from_slice(b"junk");
        assert_eq!(reason(junk), "error");
        // a truncated zlib stream is not an error by itself: the partial text is parsed
        let head =
            r#"{"t":"h","format":1,"device_id":"a","device_seq":1,"prev":null,"created_utc":"x"}"#;
        let z = zlib(head.as_bytes());
        let mut cut = ((z.len() - 4) as u64).to_be_bytes().to_vec();
        cut.extend_from_slice(&z[..z.len() - 4]);
        let outcome = unpack(&master(), &name, &seal_padded(&cut, &name));
        assert!(outcome.is_ok() || outcome.expect_err("rejected").reason != "error");
        // a zlib bomb stops at the cap
        let bomb = zlib(&vec![b'a'; MAX_PLAINTEXT + 1024]);
        let mut padded = (bomb.len() as u64).to_be_bytes().to_vec();
        padded.extend_from_slice(&bomb);
        assert_eq!(reason(padded), "too_large");
    }

    #[test]
    fn account_ids_are_stable_and_distinct() {
        assert_eq!(account_for(&master()).len(), 64);
        assert_eq!(account_for(&master()), account_for(&master()));
        assert_ne!(account_for(&master()), account_for(&other()));
    }

    #[test]
    fn base64_matches_python_strictness() {
        let engine = b64();
        assert_eq!(engine.decode("AAEC").expect("ok"), vec![0, 1, 2]);
        assert!(engine.decode("AAE").is_err(), "missing padding");
        assert!(engine.decode("AA=A").is_err());
        assert!(engine.decode("A A=").is_err(), "whitespace");
        // unused trailing bits are tolerated, as binascii does
        assert_eq!(engine.decode("AB==").expect("lenient"), vec![0]);
    }
}

#[cfg(test)]
mod wire_constants {
    //! The committed relay object, built once by the Python relay code from synthetic records under
    //! the committed test key; the Python twin is `tests/test_wire_constants.py`.
    use super::*;
    use crate::keys::{self, PassphraseSource};
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    const ACCOUNT_HEX: &str = "053e1211c6660255d9168e529d6a11ff000433dab305659da7e9aa8dfa92021e";
    const BUNDLE_SHA256: &str = "fbf8bf9ae03e91062bea3a00b12c9beda24829c5cc96f7eb72da07fe518ea0d6";
    const PAYLOAD_SHA256: &str = "4958ec2a21a490f2213f2f1d7b9cf93863d1e7eb257aa265f5716c943a3a0c87";
    const NAME: &str = "053e1211c6660255d9168e529d6a11ff000433dab305659da7e9aa8dfa92021e/00112233445566778899aabbccddeeff";

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    #[test]
    fn labels_are_frozen_verbatim() {
        assert_eq!(INFO_BUNDLE, b"hearthbeat/relay/v1/bundle");
        assert_eq!(INFO_ACCOUNT, b"hearthbeat/relay-account");
        assert_eq!(AAD_PREFIX, b"hearthbeat/relay/v1/");
    }

    #[test]
    fn known_answer_bundle_decrypts_and_parses() {
        let master = keys::unlock(
            &fixtures().join("test.keys.json"),
            PassphraseSource::Explicit("core-test-passphrase-2026"),
        )
        .expect("unlock the fixture key");
        assert_eq!(account_for(master.as_ref()), ACCOUNT_HEX);
        let blob = std::fs::read(fixtures().join("relay/known-answer.bundle")).expect("fixture bundle");
        assert_eq!(hex::encode(Sha256::digest(&blob)), BUNDLE_SHA256);
        let opened = unpack(master.as_ref(), NAME, &blob).expect("unpack");
        assert_eq!((opened.records.len(), opened.ranges.len()), (3, 1));
        assert_eq!(opened.header.device_id, "synthetic-device-a");
        assert_eq!(opened.header.device_seq, 1);
        let mut digest = Sha256::new();
        for record in &opened.records {
            digest.update(&record.payload);
        }
        assert_eq!(hex::encode(digest.finalize()), PAYLOAD_SHA256);
    }
}
