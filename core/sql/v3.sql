
CREATE TABLE IF NOT EXISTS relay_bundles (
    name        TEXT PRIMARY KEY,           -- '<account>/<32 hex>' as stored on the relay
    direction   TEXT NOT NULL,              -- pushed | pulled
    status      TEXT NOT NULL,              -- applied | rejected
    device_id   TEXT,                       -- the writing device's random id (from the header)
    device_seq  INTEGER,                    -- that device's bundle counter
    prev        TEXT,                       -- that device's previous bundle name
    created_utc TEXT,
    noted_at    TEXT NOT NULL,
    bytes       INTEGER NOT NULL DEFAULT 0,
    records     INTEGER NOT NULL DEFAULT 0,
    reason      TEXT                        -- why it was rejected (class name only)
);
CREATE TABLE IF NOT EXISTS relay_seen (
    raw_record_id INTEGER PRIMARY KEY REFERENCES raw_records(id),
    bundle        TEXT NOT NULL,
    direction     TEXT NOT NULL             -- pushed | pulled: both mean 'never push again'
);
CREATE TABLE IF NOT EXISTS relay_seen_ranges (
    export_range_id INTEGER PRIMARY KEY REFERENCES export_ranges(id),
    bundle          TEXT NOT NULL,
    direction       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS relay_device (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    device_id   TEXT NOT NULL,
    next_seq    INTEGER NOT NULL,
    last_bundle TEXT
);
CREATE TABLE IF NOT EXISTS sync_conflicts (
    id          INTEGER PRIMARY KEY,
    stream      TEXT NOT NULL,
    source_key  TEXT NOT NULL,
    winner_hash TEXT NOT NULL,
    loser_hash  TEXT NOT NULL,
    rule        TEXT NOT NULL,              -- observed_utc | payload_hash
    bundle      TEXT,
    decided_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS raw_superseded (
    id            INTEGER PRIMARY KEY,
    stream        TEXT NOT NULL,
    source_key    TEXT NOT NULL,
    payload_kind  TEXT NOT NULL,
    payload       BLOB NOT NULL,            -- zlib bytes of the record that lost
    payload_hash  TEXT NOT NULL,
    transport     TEXT NOT NULL,
    imported_at   TEXT NOT NULL,
    superseded_at TEXT NOT NULL,
    bundle        TEXT
);
