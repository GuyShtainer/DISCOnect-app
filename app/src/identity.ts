// The only place product identity strings live on the UI side (ADR 0001 mitigations: a cheap
// rename, no manufacturer marks). The Python core carries the same two in hearthbeat/identity.py.
export const PRODUCT = "DISCOnect";
export const NOTICE = "Not affiliated with or endorsed by any watch manufacturer.";

/** Source words as the design system spells them; the core's scope ids are the keys. */
export const SCOPE_WORD: Record<string, string> = {
  device: "device",
  vendor_cloud: "vendor cloud",
  local: "local",
};

/** Human labels for the metrics the screens show; everything else falls back to the id. */
export const METRIC_LABEL: Record<string, string> = {
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
