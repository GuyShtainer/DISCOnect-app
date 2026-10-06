
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- The permanent re-parse basis. One row per source file (FIT) or record (JSON).
CREATE TABLE IF NOT EXISTS raw_records (
    id             INTEGER PRIMARY KEY,
    stream         TEXT NOT NULL,          -- 'fit:monitoring_b', 'fit:49', 'json:uds', ...
    source_key     TEXT NOT NULL,          -- sha256 of FIT bytes / natural key of a JSON record
    source_scope   TEXT NOT NULL,          -- device | vendor_cloud
    transport      TEXT NOT NULL,          -- connect_export | usb | gadgetbridge | ciq | drop
    device_id      TEXT,
    start_utc      TEXT,
    end_utc        TEXT,
    payload_kind   TEXT NOT NULL,          -- fit | json
    payload        BLOB NOT NULL,          -- zlib-compressed original bytes
    payload_hash   TEXT NOT NULL,          -- sha256 of the uncompressed bytes
    payload_bytes  INTEGER NOT NULL,
    decode_summary TEXT,                   -- JSON: message counts, dropped sentinels, warnings
    imported_at    TEXT NOT NULL,
    UNIQUE(stream, source_key)
);
CREATE INDEX IF NOT EXISTS idx_raw_records_stream ON raw_records(stream, start_utc);

CREATE TABLE IF NOT EXISTS metric_samples (
    id            INTEGER PRIMARY KEY,
    metric        TEXT NOT NULL,
    ts_utc        TEXT NOT NULL,
    value         REAL NOT NULL,
    source_scope  TEXT NOT NULL,
    device_id     TEXT,
    raw_record_id INTEGER REFERENCES raw_records(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_metric_samples
    ON metric_samples(metric, ts_utc, source_scope, COALESCE(device_id, ''));
CREATE INDEX IF NOT EXISTS idx_metric_samples_raw ON metric_samples(raw_record_id);

CREATE TABLE IF NOT EXISTS daily_metrics (
    id            INTEGER PRIMARY KEY,
    date          TEXT NOT NULL,           -- local calendar date YYYY-MM-DD
    metric        TEXT NOT NULL,
    value         REAL NOT NULL,
    observed_utc  TEXT,                    -- when the watch/cloud produced the value
    source_scope  TEXT NOT NULL,
    device_id     TEXT,
    raw_record_id INTEGER REFERENCES raw_records(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_daily_metrics
    ON daily_metrics(date, metric, source_scope, COALESCE(device_id, ''));
CREATE INDEX IF NOT EXISTS idx_daily_metrics_raw ON daily_metrics(raw_record_id);

CREATE TABLE IF NOT EXISTS daily_labels (
    id            INTEGER PRIMARY KEY,
    date          TEXT NOT NULL,
    metric        TEXT NOT NULL,
    label         TEXT NOT NULL,
    observed_utc  TEXT,
    source_scope  TEXT NOT NULL,
    device_id     TEXT,
    raw_record_id INTEGER REFERENCES raw_records(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_daily_labels
    ON daily_labels(date, metric, source_scope, COALESCE(device_id, ''));

CREATE TABLE IF NOT EXISTS sleep_sessions (
    id                     INTEGER PRIMARY KEY,
    sleep_id               TEXT NOT NULL UNIQUE,   -- '<date>|<source_scope>|<device_id or ''>'
    date                   TEXT NOT NULL,          -- local date the sleep ended
    start_utc              TEXT,
    end_utc                TEXT,
    deep_s                 INTEGER,
    light_s                INTEGER,
    rem_s                  INTEGER,
    awake_s                INTEGER,
    unmeasurable_s         INTEGER,
    overall_score          INTEGER,
    quality_score          INTEGER,
    duration_score         INTEGER,
    recovery_score         INTEGER,
    deep_score             INTEGER,
    rem_score              INTEGER,
    light_score            INTEGER,
    awake_time_score       INTEGER,
    awakenings_count_score INTEGER,
    combined_awake_score   INTEGER,
    restlessness_score     INTEGER,
    interruptions_score    INTEGER,
    awakenings_count       INTEGER,
    avg_stress             REAL,
    avg_spo2               REAL,
    lowest_spo2            INTEGER,
    avg_hr                 REAL,
    avg_respiration        REAL,
    lowest_respiration     REAL,
    highest_respiration    REAL,
    retro                  INTEGER NOT NULL DEFAULT 0,
    source_scope           TEXT NOT NULL,
    device_id              TEXT,
    raw_record_id          INTEGER REFERENCES raw_records(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_sleep_sessions
    ON sleep_sessions(date, source_scope, COALESCE(device_id, ''));

CREATE TABLE IF NOT EXISTS sleep_stages (
    id        INTEGER PRIMARY KEY,
    sleep_id  TEXT NOT NULL REFERENCES sleep_sessions(sleep_id) ON DELETE CASCADE,
    stage     TEXT NOT NULL,               -- deep | light | rem | awake
    start_utc TEXT NOT NULL,
    end_utc   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sleep_stages_sleep ON sleep_stages(sleep_id, start_utc);

-- Cumulative all-day counters as the watch writes them (per activity type,
-- reset at local midnight). Daily steps are derived from these.
CREATE TABLE IF NOT EXISTS monitoring_intervals (
    id                   INTEGER PRIMARY KEY,
    ts_utc               TEXT NOT NULL,
    activity_type        TEXT NOT NULL,
    steps                INTEGER,
    cycles               REAL,
    active_time_s        REAL,
    active_calories_kcal INTEGER,
    distance_m           REAL,
    intensity            INTEGER,
    source_scope         TEXT NOT NULL,
    device_id            TEXT,
    raw_record_id        INTEGER REFERENCES raw_records(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_monitoring_intervals
    ON monitoring_intervals(ts_utc, activity_type, source_scope, COALESCE(device_id, ''));
CREATE INDEX IF NOT EXISTS idx_monitoring_intervals_raw ON monitoring_intervals(raw_record_id);

CREATE TABLE IF NOT EXISTS activities (
    id              INTEGER PRIMARY KEY,
    activity_id     TEXT NOT NULL UNIQUE,  -- '<start_utc>|<source_scope>|<device_id or ''>'
    start_utc       TEXT NOT NULL,
    end_utc         TEXT,
    sport           TEXT,
    sub_sport       TEXT,
    total_timer_s   REAL,
    total_elapsed_s REAL,
    distance_m      REAL,
    calories_kcal   INTEGER,
    avg_hr          INTEGER,
    max_hr          INTEGER,
    avg_speed_mps   REAL,
    total_ascent_m  REAL,
    total_descent_m REAL,
    source_scope    TEXT NOT NULL,
    device_id       TEXT,
    raw_record_id   INTEGER REFERENCES raw_records(id)
);

-- The watch's own UTC offset at known moments; resolves local calendar dates.
CREATE TABLE IF NOT EXISTS clock_offsets (
    id            INTEGER PRIMARY KEY,
    ts_utc        TEXT NOT NULL,
    offset_s      INTEGER NOT NULL,
    device_id     TEXT,
    raw_record_id INTEGER REFERENCES raw_records(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_clock_offsets
    ON clock_offsets(ts_utc, COALESCE(device_id, ''));

-- Parse and write are different failures with different fixes; keep both.
CREATE TABLE IF NOT EXISTS stream_provenance (
    stream                   TEXT PRIMARY KEY,
    last_parse_ok_at         TEXT,
    last_parse_error_at      TEXT,
    last_parse_error_kind    TEXT,
    last_parse_error_message TEXT,
    last_write_ok_at         TEXT,
    last_write_error_at      TEXT,
    last_write_error_kind    TEXT,
    last_write_error_message TEXT,
    files_ok                 INTEGER NOT NULL DEFAULT 0,
    files_failed             INTEGER NOT NULL DEFAULT 0,
    records_written          INTEGER NOT NULL DEFAULT 0,
    updated_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS import_runs (
    id              INTEGER PRIMARY KEY,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    transport       TEXT NOT NULL,
    status          TEXT NOT NULL,         -- running | ok | partial | failed
    files_seen      INTEGER NOT NULL DEFAULT 0,
    files_imported  INTEGER NOT NULL DEFAULT 0,
    files_duplicate INTEGER NOT NULL DEFAULT 0,
    files_failed    INTEGER NOT NULL DEFAULT 0,
    records_written INTEGER NOT NULL DEFAULT 0,
    error           TEXT
);
