// The only place product identity strings live on the UI side (ADR 0001 mitigations: a cheap
// rename, no manufacturer marks). The Python core carries the same two in disconect/identity.py.
export const PRODUCT = "DISCOnect";
export const NOTICE = "Not affiliated with or endorsed by any watch manufacturer.";

// Names mirrored from identity.py (tests/test_identity_drift.py fails on drift).
export const DATA_DIR = ".disconect";
export const DB_FILENAME = "disconect.db";
export const ENV_PREFIX = "DISCONECT_";
export const CLI_KEYCHAIN_SERVICE = "disconect-cli";
export const LEGACY_CLI_KEYCHAIN_SERVICES = ["hearthbeat"] as const;
export const MCP_SERVER_NAME = "disconect";
export const COMMAND = "disconect";
export const LEGACY_HOMES = [".hearthbeat"] as const;
export const LEGACY_DB_FILENAME = "hearthbeat.db";
export const LEGACY_ENV_PREFIX = "HEARTHBEAT_";
export const BACKUP_PREFIX = "disconect";
export const LEGACY_BACKUP_PREFIXES = ["hearthbeat"] as const;

/** Source words as the design system spells them; the core's scope ids are the keys. */
export const SCOPE_WORD: Record<string, string> = {
  device: "device",
  vendor_cloud: "vendor cloud",
  local: "local",
};

/** Human labels for the metrics the screens show; everything else falls back to the id. */
export const METRIC_LABEL: Record<string, string> = {
  // ours
  energy_reserve: "Energy reserve",
  energy_reserve_high: "Energy reserve, high",
  energy_reserve_low: "Energy reserve, low",
  energy_reserve_charged: "Energy reserve, gained",
  energy_reserve_drained: "Energy reserve, spent",
  // the vendor cloud's figures (its own metric names are trademarks and never rendered)
  body_battery_high: "Energy, vendor high",
  body_battery_low: "Energy, vendor low",
  body_battery_charged: "Energy, vendor gained",
  body_battery_drained: "Energy, vendor spent",
  training_readiness: "Readiness, vendor",
  training_readiness_level: "Readiness level, vendor",
  training_readiness_context: "Readiness context, vendor",
  readiness_factor_hrv: "Readiness factor, vendor: HRV",
  readiness_factor_load_ratio: "Readiness factor, vendor: load ratio",
  readiness_factor_recovery_time: "Readiness factor, vendor: recovery time",
  readiness_factor_sleep: "Readiness factor, vendor: sleep",
  readiness_factor_sleep_history: "Readiness factor, vendor: sleep history",
  readiness_factor_stress_history: "Readiness factor, vendor: stress history",
  training_load_acute: "Training load, acute",
  training_load_chronic: "Training load, chronic",
  training_load_ratio: "Training load, ratio",
  training_load_status: "Training load status",
  recovery_time: "Recovery time, vendor",
  endurance_score: "Endurance score",
  fitness_age: "Fitness age",
  hydration_ml: "Hydration",
  sweat_loss_ml: "Sweat loss",
  weight_kg: "Weight",
  active_minutes: "Active minutes",
  highly_active_minutes: "Highly active minutes",
  hrv_weekly_average: "HRV, weekly average",
  hrv_status: "HRV status",
  heart_rate: "Heart rate",
  stress: "Stress",
  respiration_rate: "Respiration rate",
  spo2: "SpO₂",
  hrv_rmssd: "HRV (RMSSD)",
  steps: "Steps",
  resting_heart_rate: "Resting HR",
  sleep_score: "Sleep score",
  sleep_duration: "Sleep duration",
  stress_avg: "Stress avg",
  hrv_last_night_average: "HRV, last night",
  spo2_avg: "SpO₂ avg",
  respiration_avg_waking: "Respiration, awake",
  vo2max: "VO₂max",
  distance: "Distance",
  calories_total: "Calories",
};

export function metricLabel(id: string): string {
  return METRIC_LABEL[id] ?? id.replaceAll("_", " ");
}

export function scopeWord(id: string): string {
  return SCOPE_WORD[id] ?? id;
}
