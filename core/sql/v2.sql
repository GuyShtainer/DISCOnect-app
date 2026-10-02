
-- v2 (Bet 4, coverage ledger). Additive only; v1 tables are untouched.

-- The window a Connect-export JSON file *claims* to cover, parsed from its
-- name. A day inside a claimed window with no record for it is one the
-- source genuinely had nothing for. Local calendar dates, inclusive.
CREATE TABLE IF NOT EXISTS export_ranges (
    id        INTEGER PRIMARY KEY,
    run_id    INTEGER NOT NULL REFERENCES import_runs(id),   -- the run that first recorded it
    stream    TEXT NOT NULL,
    from_day  TEXT NOT NULL,
    to_day    TEXT NOT NULL,
    UNIQUE(stream, from_day, to_day)
);

-- One row per record that failed to decode or load, with whatever span was
-- knowable (the FIT header's file type and the timestamps seen before the
-- failure; a JSON file's name-derived window). Never a label, path or
-- device id. raw_record_id is set when the bytes are retained (reparse).
CREATE TABLE IF NOT EXISTS import_failures (
    id            INTEGER PRIMARY KEY,
    run_id        INTEGER NOT NULL REFERENCES import_runs(id),
    stream        TEXT,
    start_utc     TEXT,
    end_utc       TEXT,
    raw_record_id INTEGER REFERENCES raw_records(id),
    payload_hash  TEXT,                    -- sha256 of the failing bytes; the same bytes fail once
    kind          TEXT NOT NULL,
    recorded_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_import_failures_payload
    ON import_failures(payload_hash) WHERE payload_hash IS NOT NULL;
