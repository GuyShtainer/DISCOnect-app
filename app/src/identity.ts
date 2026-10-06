// The only place product identity strings live on the UI side (ADR 0001 mitigations: a cheap
// rename, no manufacturer marks). The Python core carries the same two in disconect/identity.py.
export const PRODUCT = "DISCOnect";
export const NOTICE = "Not affiliated with or endorsed by any watch manufacturer.";
// The one sentence every coaching session shows (CLAIMS-POLICY.md); drift-pinned against identity.py.
export const DISCLAIMER = "This describes patterns in your own data. It is not medical advice, a diagnosis or a treatment plan.";
// The Off card's claim (Bet 15c pitch section 4): a hand-off makes health text leave by clipboard and
// browser while the coach is off, so the previous, narrower claim no longer held.
export const OFF_NETWORK = "This app opens no network connection while coaching is off.";
// Shown beside the hand-off's provider picker (Bet 15c, legal review condition 5): no claim about any provider's
// own behaviour, only what this app is and is not.
export const AI_NOTICE =
  "Not integrated with, endorsed by or responsible for any AI provider; a hand-off opens that provider's own site under your own account, governed by their terms, not ours.";

// The hand-off's five chats (Bet 15c): plain names, no logos, no provider colours. `name` and `host` mirror
// src-tauri/src/coach/handoff.rs's `name`/`host` literals exactly (test_lint_app.py pins the drift); the host
// is shown before the click but never used to build anything.
export const PROVIDERS: { id: "chat_gpt" | "claude" | "gemini" | "le_chat" | "deep_seek"; name: string; host: string }[] = [
  { id: "chat_gpt", name: "ChatGPT", host: "chatgpt.com" },
  { id: "claude", name: "Claude", host: "claude.ai" },
  { id: "gemini", name: "Gemini", host: "gemini.google.com" },
  { id: "le_chat", name: "Le Chat", host: "chat.mistral.ai" },
  { id: "deep_seek", name: "DeepSeek", host: "chat.deepseek.com" },
];

// ---- support channels (Bet 17, donations only; the sponsor-message tier is cut). Mirrors
// src-tauri/src/coach/support.rs's SupportSite arms exactly (test_lint_app.py pins the drift, the way it
// pins PROVIDERS against handoff.rs). Ships empty: the channels are Guy's decision, not this bet's.
export const SUPPORT_INTRO = "This app is free software. If it is useful to you, the maintainer takes support through these channels. Nothing is required, nothing in the app changes whether you give or not, nothing is recorded here, and this app has no way to learn whether you gave.";
export const SUPPORT_NETWORK = "This screen opens no network connection; the buttons open your browser, under your own session with that service, governed by their terms, not ours.";
export const SUPPORT_EMPTY = "No support channel is configured in this build.";
// Off macOS the opener command does not exist (lib.rs); the nav row is hidden and this is what a direct
// visit sees — not SUPPORT_EMPTY, which would be false on a build that does configure channels.
export const SUPPORT_UNAVAILABLE = "This build cannot open a support channel in your browser.";
// What the screen lists comes from the Rust table (`support_sites`); this mirror exists for the drift pin
// only, so editing it alone changes nothing on screen — the lint says so when the two disagree.
export const SUPPORT_SITES: { id: string; name: string; host: string }[] = [];

// Names mirrored from identity.py (tests/test_identity_drift.py fails on drift).
export const DATA_DIR = ".disconect";
export const DB_FILENAME = "disconect.db";
export const ENV_PREFIX = "DISCONECT_";
export const CLI_KEYCHAIN_SERVICE = "disconect-cli";
export const LEGACY_CLI_KEYCHAIN_SERVICES = ["hearthbeat"] as const;
// The in-app coach's provider-key keychain item (Bet 15); a third service, never shared with either core's.
export const COACH_KEYCHAIN_SERVICE = "disconect-coach";
export const MCP_SERVER_NAME = "disconect";
export const COMMAND = "disconect";
export const LEGACY_HOMES = [".hearthbeat"] as const;
export const LEGACY_DB_FILENAME = "hearthbeat.db";
export const LEGACY_ENV_PREFIX = "HEARTHBEAT_";
export const BACKUP_PREFIX = "disconect";
// The key screen and its keychain switch, as app.ts shows them (the Rust MCP's messages quote both).
export const KEY_SCREEN = "Your key";
export const KEYCHAIN_SWITCH = "Keep the key in this device's keychain";
export const LEGACY_BACKUP_PREFIXES = ["hearthbeat"] as const;

/** Source words as the design system spells them; the core's scope ids are the keys. */
export const SCOPE_WORD: Record<string, string> = {
  device: "device",
  vendor_cloud: "vendor cloud",
  local: "local",
  live: "live link",
};

/** Human labels for the metrics the screens show; everything else falls back to the id. */
export const METRIC_LABEL: Record<string, string> = {
  // ours
  energy_reserve: "Energy reserve",
  energy_reserve_high: "Energy reserve, high",
  energy_reserve_low: "Energy reserve, low",
  energy_reserve_charged: "Energy reserve, gained",
  energy_reserve_drained: "Energy reserve, spent",
  // the vendor cloud's figures (its own metric names are trademarks and never rendered; its score names
  // are said in the plain words of SCORE_NAMES below — the claims lint allows no exemption)
  body_battery_high: "Energy, vendor high",
  body_battery_low: "Energy, vendor low",
  body_battery_charged: "Energy, vendor gained",
  body_battery_drained: "Energy, vendor spent",
  training_readiness: "Daily preparedness, vendor",
  training_readiness_level: "Daily preparedness level, vendor",
  training_readiness_context: "Daily preparedness context, vendor",
  readiness_factor_hrv: "Daily preparedness factor, vendor: HRV",
  readiness_factor_load_ratio: "Daily preparedness factor, vendor: load ratio",
  readiness_factor_recovery_time: "Daily preparedness factor, vendor: rest time",
  readiness_factor_sleep: "Daily preparedness factor, vendor: sleep",
  readiness_factor_sleep_history: "Daily preparedness factor, vendor: sleep history",
  readiness_factor_stress_history: "Daily preparedness factor, vendor: stress history",
  training_load_acute: "Training load, acute",
  training_load_chronic: "Training load, chronic",
  training_load_ratio: "Training load, ratio",
  training_load_status: "Training load status",
  recovery_time: "Rest time, vendor",
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

// ---- what the coach's words are scrubbed with before they are drawn (Bet 15) -----------------------------
// Mirrors identity.rs::neutral_text (the maker's name becomes a placeholder), then replaces the score names
// CLAIMS-POLICY.md marks with plain words. The names are spelled in two fragments so that no authored string
// and no built bundle carries one; tests/test_claims_policy.py joins the fragments back and checks that the
// keys are exactly the policy's `score-marks` and `score-names` lists.
const mark = (head: string, tail: string): string => head + tail;

/** Multi-word marks, matched in any letter case (the policy's `score-marks`). */
export const SCORE_MARKS: [string, string][] = [
  [mark("Body Bat", "tery"), "energy level"],
  [mark("Recov", "ery score"), "rest estimate"],
  [mark("Training Read", "iness"), "daily preparedness"],
];
/** Single names, matched as whole words in exactly this case (the policy's `score-names`). */
export const SCORE_NAMES: [string, string][] = [
  [mark("Read", "iness"), "daily preparedness"],
  [mark("Recov", "ery"), "rest"],
  [mark("T", "SS"), "training stress total"],
  [mark("C", "TL"), "long-term training load"],
  [mark("A", "TL"), "short-term training load"],
  [mark("T", "SB"), "training balance"],
];

// identity.rs: the name with an optional " connect"; Python's ignore-case also folds U+0130 and U+0131 to i.
const MAKER = new RegExp(["gar", "m", "[i\u0130\u0131]", "n", "(?: connect)?"].join(""), "gi");
const VENDOR_PLACEHOLDER = "{vendor}";

function startsSentence(text: string, at: number): boolean {
  return /(^|[.!?]\s+|\n)$/.test(text.slice(0, at));
}

function plain(text: string, key: string, words: string, flags: string): string {
  const pattern = new RegExp(`\\b${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, flags);
  return text.replace(pattern, (_hit: string, at: number) => {
    return startsSentence(text, at) ? words.charAt(0).toUpperCase() + words.slice(1) : words;
  });
}

/** The coach's text as it may be drawn: the maker's name scrubbed, score names in plain words. */
export function neutralText(text: string): string {
  let out = text.replace(MAKER, VENDOR_PLACEHOLDER);
  for (const [key, words] of SCORE_MARKS) out = plain(out, key, words, "gi");
  for (const [key, words] of SCORE_NAMES) out = plain(out, key, words, "g");
  return out;
}
