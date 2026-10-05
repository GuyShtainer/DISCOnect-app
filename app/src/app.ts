// DISCOnect shell (Bet 7 slice 3): a hash router, four screens, one source of truth (the core).
// Rules: every value carries its source word; a missing day is drawn as absence; the UI never
// computes health facts itself; colours come from tokens only (see app.css / charts.ts).
import * as core from "./core";
import { DISCLAIMER, NOTICE, PRODUCT, metricLabel, neutralText, scopeWord } from "./identity";
import { disposeCharts, drawTrend, type Series } from "./charts";

type KeyStatus = { key_file: boolean; encrypted: boolean; unlocked: boolean; keychain: "cached" | "absent" | "stale" };
type AppInfo = { product: string; core: string; db: string; encrypted: boolean };
type Day = { day: string; value: number | null; status: string };
type Metric = { metric: string; scope: string; unit: string | null; days: Day[] };
type TodayRow = { metric: string; scope: string; value: number | null; unit: string | null; day: string | null; status: string };
type Today = { day: string; metrics: TodayRow[] };
type Fact = {
  metric: string; unit: string; source_scope: string; value: number | null; confidence: string; reason_code: string;
  comparison: { delta: number | null; direction: string } | null;
};
type Facts = { as_of: string | null; window: { days: number }; baseline: { days: number }; facts: Fact[] };
type LedgerRow = {
  metric: string; source_scope: string; sparse: boolean; present: number; failed: number; source_empty: number;
  not_covered: number; gaps: { from?: string; to?: string; status?: string; days?: number }[]; gaps_truncated: boolean;
};
type Health = { coverage: { window: { from: string; to: string; days: number }; ledger: LedgerRow[] }; never_imported: boolean };

const SCOPES = ["device", "vendor_cloud", "local"];
const TREND_METRICS = ["energy_reserve_high", "energy_reserve_low", "resting_heart_rate", "steps", "sleep_score", "stress_avg", "hrv_last_night_average", "sleep_duration"];
const SCREENS: { id: string; title: string }[] = [
  { id: "today", title: "Today" },
  { id: "watch", title: "Watch" },
  { id: "trend", title: "Trends" },
  { id: "health", title: "Data health" },
  { id: "coach", title: "Coach" },
  { id: "coach-settings", title: "Coach settings" },
  { id: "key", title: "Your key" },
];

const nav = document.getElementById("nav") as HTMLElement;
const main = document.getElementById("main") as HTMLElement;
let keyStatus: KeyStatus | null = null;
let banner: string | null = null;
let coachSettings: core.CoachSettings | null = null;
/** The endpoint host while a coach request is out (set before the call, cleared in finally). */
let coachSending: string | null = null;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls = "", text = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text) node.textContent = text;
  return node;
}

function scopeTag(scope: string): HTMLElement {
  return el("span", `caption scope-${scope}`, scopeWord(scope));
}

function fmt(value: number | null, unit: string | null): string {
  if (value === null || value === undefined) return "no data";
  const n = Math.abs(value) >= 100 ? Math.round(value).toLocaleString("en").replace(/,/g, "\u202f") : (Math.round(value * 10) / 10).toString();
  return unit && unit !== "score" && unit !== "steps" ? `${n} ${unit}` : n;
}

function missingWord(status: string): string {
  return status === "source_empty" ? "source had nothing" : status === "failed" ? "a file failed to decode" : status === "not_covered" ? "no import covered this day" : "";
}

function current(): string {
  return location.hash.replace(/^#\/?/, "") || "today";
}

/** The Coach entry's indicator: grey dot "off", hollow dot "ready", red dot and the host while a request is out. */
function coachFlag(): HTMLElement {
  const flag = el("span", "flag");
  const dot = el("span", "dot");
  const word = el("span", "caption");
  if (coachSending) {
    dot.classList.add("sending");
    word.textContent = coachSending;
    word.classList.add("error");
    flag.title = `Sending to ${coachSending}`;
  } else if (coachSettings && coachSettings.mode !== "off") {
    dot.classList.add("ready");
    word.textContent = "ready";
    word.classList.add("muted");
  } else {
    dot.classList.add("off");
    word.textContent = "off";
    word.classList.add("muted");
  }
  flag.append(dot, word);
  return flag;
}

function renderNav(): void {
  nav.replaceChildren();
  nav.append(el("div", "brand", PRODUCT));
  for (const s of SCREENS) {
    const a = el("a", "", s.title) as HTMLAnchorElement;
    a.href = `#/${s.id}`;
    if (current() === s.id) a.setAttribute("aria-current", "page");
    if (s.id === "coach") a.append(coachFlag());
    nav.append(a);
  }
  nav.append(el("div", "spacer"));
  const status = el("div", "status caption muted");
  status.textContent = keyStatus
    ? keyStatus.encrypted
      ? keyStatus.unlocked ? `Encrypted · unlocked${keyStatus.keychain === "cached" ? " · key in keychain" : ""}` : "Encrypted · locked"
      : "Not encrypted"
    : "";
  nav.append(status);
  nav.append(el("footer", "notice", NOTICE));
}

async function refreshKey(): Promise<KeyStatus | null> {
  try {
    keyStatus = await core.call<KeyStatus>("key.status");
  } catch (e) {
    keyStatus = null;
    banner = core.isCoreError(e) ? `The core is not available: ${e.message}` : String(e);
  }
  return keyStatus;
}

function locked(): boolean {
  return !!keyStatus && keyStatus.encrypted && !keyStatus.unlocked;
}

async function refreshCoach(): Promise<void> {
  try {
    coachSettings = await core.coachSettingsGet();
  } catch {
    coachSettings = null;
  }
}

let generation = 0;
type Later = (fn: () => void) => void;

/** Render the current screen. Single-flight: a newer route() wins and an older one draws nothing. */
async function route(): Promise<void> {
  const mine = ++generation;
  await refreshKey();
  await refreshCoach();
  if (mine !== generation) return;
  renderNav();
  const id = current();
  // the coach settings need no data from the store (the probe works on a locked one), so they stay reachable
  // the watch screen reads the link, not the store
  if (locked() && id !== "key" && id !== "coach-settings" && id !== "watch") {
    location.hash = "#/key"; // hashchange re-enters route()
    return;
  }
  const out = document.createDocumentFragment();
  const queue: (() => void)[] = [];
  const later: Later = (fn) => queue.push(fn);
  if (banner) {
    out.append(el("div", "banner body", banner));
    banner = null; // shown once
  }
  try {
    if (id === "today") await screenToday(out);
    else if (id === "watch") await screenWatch(out, later);
    else if (id === "trend") await screenTrend(out, later);
    else if (id === "health") await screenHealth(out);
    else if (id === "coach") screenCoach(out, later);
    else if (id === "coach-settings") await screenCoachSettings(out);
    else await screenKey(out);
  } catch (e) {
    if (core.isCoreError(e) && e.code === "locked") {
      location.hash = "#/key";
      return;
    }
    out.append(el("div", "banner body error", core.isCoreError(e) ? `${e.code}: ${e.message}` : String(e)));
  }
  if (mine !== generation) return;
  out.append(el("footer", "notice", NOTICE));
  disposeCharts();
  main.replaceChildren(out);
  for (const fn of queue) fn();
}

function header(out: ParentNode, title: string, sub: string): void {
  const row = el("div", "row");
  row.append(el("h1", "display", title));
  row.append(el("span", "caption muted", sub));
  out.append(row);
}

// ---- Today -----------------------------------------------------------------------------
async function screenToday(out: ParentNode): Promise<void> {
  const [today, facts] = await Promise.all([core.call<Today>("data.today"), core.call<Facts>("data.facts", { days: 7, baseline_days: 28 })]);
  header(out, "Today", today.day);
  const cards = el("div", "cards");
  for (const row of today.metrics) {
    const card = el("div", "card");
    card.append(el("span", "caption muted", metricLabel(row.metric)));
    const v = el("span", "value", fmt(row.value, row.unit));
    if (row.value === null) v.classList.add("muted");
    card.append(v);
    const line = el("span", "caption");
    line.append(scopeTag(row.scope));
    const note = row.value === null ? missingWord(row.status) : row.day && row.day !== today.day ? `latest · ${row.day}` : "";
    if (note) line.append(el("span", "muted", ` · ${note}`));
    card.append(line);
    cards.append(card);
  }
  out.append(cards);
  const card = el("div", "card");
  card.append(el("h2", "heading", `Last ${facts.window.days} days vs your ${facts.baseline.days}-day baseline`));
  const grid = el("div", "grid3 body");
  for (const f of facts.facts) {
    const name = el("span");
    name.append(document.createTextNode(`${metricLabel(f.metric)} `));
    name.append(scopeTag(f.source_scope));
    grid.append(name);
    const delta = f.comparison && f.comparison.delta !== null
      ? `${f.comparison.delta > 0 ? "+" : f.comparison.delta < 0 ? "−" : ""}${fmt(Math.abs(f.comparison.delta), f.unit)}`
      : "no comparison";
    grid.append(el("span", "mono", delta));
    grid.append(el("span", "muted", f.comparison ? `${f.confidence} confidence` : f.reason_code.replaceAll("_", " ")));
  }
  if (!facts.facts.length) grid.append(el("span", "muted", facts.as_of ? "no metric has data in this window" : "nothing imported yet"));
  card.append(grid);
  card.append(el("span", "caption muted", "Comparisons are against your own history only. They describe; they do not diagnose."));
  out.append(card);
}

// ---- Watch (the live link, Bet 9 follow-up) -----------------------------------------------
// The lab's Python reads the watch over Bluetooth as a child of the app; every reading arrives as an event and
// is also collected in the lab's raw folder on this Mac. The screen only draws the latest value per metric.
const LIVE_ORDER = ["heart_rate", "steps", "stress", "respiration_rate", "spo2", "energy_reserve"];
const liveLatest = new Map<string, { value: number; t: number }>();
let liveStatus = "idle";
let liveStop: string | null = null;
let liveRunning = false;
const liveNodes: { values: Map<string, HTMLElement>; since: Map<string, HTMLElement>; status: HTMLElement | null; button: HTMLButtonElement | null } = {
  values: new Map(), since: new Map(), status: null, button: null,
};

function liveStatusWord(): string {
  if (liveStatus === "stopped") return liveStop ? `stopped (${liveStop.replaceAll(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()})` : "stopped";
  return liveStatus;
}

function ago(t: number): string {
  const s = Math.max(0, Math.round(Date.now() / 1000 - t));
  return s < 60 ? `${s} s ago` : `${Math.round(s / 60)} min ago`;
}

function drawLive(): void {
  if (liveNodes.status) liveNodes.status.textContent = liveStatusWord();
  if (liveNodes.button) {
    liveNodes.button.textContent = liveRunning ? "Disconnect" : "Connect to watch";
    liveNodes.button.disabled = liveStatus === "scanning" || liveStatus === "connecting";
  }
  for (const [metric, node] of liveNodes.values) {
    const latest = liveLatest.get(metric);
    node.textContent = latest ? String(latest.value) : "—";
    node.classList.toggle("muted", !latest);
    const since = liveNodes.since.get(metric);
    if (since) since.textContent = latest ? ago(latest.t) : "no reading yet";
  }
}

function onLive(line: core.LiveLine): void {
  if (typeof line.status === "string") {
    liveStatus = line.status;
    liveStop = typeof line.stop === "string" ? line.stop : null;
    if (line.status === "stopped") liveRunning = false;
  }
  if (typeof line.metric === "string" && typeof line.value === "number" && typeof line.t === "number") {
    liveLatest.set(line.metric, { value: line.value, t: line.t });
  }
  drawLive();
}

async function toggleLive(): Promise<void> {
  try {
    if (liveRunning) {
      await core.liveStop();
      liveRunning = false;
      liveStatus = "stopped";
      liveStop = null;
    } else {
      liveLatest.clear();
      liveStop = null;
      liveStatus = "starting";
      drawLive();
      await core.liveStart();
      liveRunning = true;
    }
  } catch (e) {
    liveRunning = false;
    liveStatus = "stopped";
    liveStop = core.isCoreError(e) ? e.code : "error";
  }
  drawLive();
}

async function screenWatch(out: ParentNode, later: Later): Promise<void> {
  const state = await core.liveState().catch(() => ({ running: false, available: false }));
  liveRunning = state.running;
  header(out, "Watch", "live readings over Bluetooth, read-only");
  const card = el("div", "card");
  const row = el("div", "actions");
  const button = el("button", "", "Connect to watch");
  button.onclick = () => void toggleLive();
  if (!state.available) {
    button.disabled = true;
    card.append(el("p", "caption muted", "The live link runs in development builds only: this build has no lab to run."));
  }
  const cable = el("button", "secondary", "Cable sync");
  cable.disabled = true;
  cable.title = "Not wired yet";
  row.append(button, cable);
  card.append(row);
  const status = el("p", "caption");
  card.append(status);
  card.append(el("p", "caption muted", "Turn the phone's Bluetooth off first: the watch talks to one device at a time, and it stays silent while the phone holds the link. The first connection shows a code on the watch; confirm it. Cable sync will copy the watch's files over USB for days without Bluetooth; it is not wired yet."));
  out.append(card);
  const cards = el("div", "cards");
  liveNodes.values.clear();
  liveNodes.since.clear();
  for (const metric of LIVE_ORDER) {
    const tile = el("div", "card");
    tile.append(el("span", "caption muted", metricLabel(metric)));
    const value = el("span", "value", "—");
    const since = el("span", "caption muted", "no reading yet");
    tile.append(value, since);
    liveNodes.values.set(metric, value);
    liveNodes.since.set(metric, since);
    cards.append(tile);
  }
  out.append(cards);
  out.append(el("p", "caption muted", "Every reading is collected in the lab's raw folder on this Mac, never in the store yet. The watch is only read; nothing is written to it."));
  liveNodes.status = status;
  liveNodes.button = button;
  later(drawLive);
}

void core.onLiveLine(onLive);
void core.onLiveEnded(() => {
  liveRunning = false;
  if (liveStatus !== "stopped") liveStatus = "stopped";
  drawLive();
});
setInterval(() => {
  if (liveNodes.status && document.contains(liveNodes.status)) drawLive();
}, 1000);

// ---- Trend ------------------------------------------------------------------------------
let trendMetric = TREND_METRICS[0];
let trendDays = 90;

async function screenTrend(out: ParentNode, later: Later): Promise<void> {
  const controls = el("div", "row");
  const select = el("select") as HTMLSelectElement;
  for (const m of TREND_METRICS) {
    const o = el("option", "", metricLabel(m)) as HTMLOptionElement;
    o.value = m;
    o.selected = m === trendMetric;
    select.append(o);
  }
  select.onchange = () => { trendMetric = select.value; void route(); };
  const range = el("select") as HTMLSelectElement;
  for (const d of [30, 90, 365]) {
    const o = el("option", "", `${d} days`) as HTMLOptionElement;
    o.value = String(d);
    o.selected = d === trendDays;
    range.append(o);
  }
  range.onchange = () => { trendDays = Number(range.value); void route(); };
  header(out, metricLabel(trendMetric), "");
  controls.append(select, range);
  out.append(controls);

  // The window ends on the latest day any metric has data, so an archive still draws.
  const today = await core.call<Today>("data.today");
  const lastDay = today.metrics.reduce<string>((acc, m) => (m.value !== null && m.day && m.day > acc ? m.day : acc), "") || today.day;
  const results = await Promise.all(SCOPES.map((scope) => core.call<Metric>("data.metric", { metric: trendMetric, scope, days: trendDays, last_day: lastDay })));
  const series: Series[] = results
    .filter((m) => m.days.some((d) => d.value !== null))
    .map((m) => ({ scope: m.scope, unit: m.unit, days: m.days }));
  const legend = el("div", "legend caption");
  for (const s of series) {
    const item = el("span", `scope-${s.scope}`);
    const sw = el("span", `swatch ${s.scope}`);
    item.append(sw, document.createTextNode(scopeWord(s.scope)));
    legend.append(item);
  }
  out.append(legend);
  const card = el("div", "card");
  const chart = el("div", "chart");
  card.append(chart);
  out.append(card);
  if (!series.length) {
    card.append(el("span", "muted body", "No source has values for this metric in the window."));
    return;
  }
  const gapDays = series[0].days.filter((d) => d.status === "not_covered").length;
  const ends = lastDay !== today.day ? ` Window ends ${lastDay}, the latest day with data.` : "";
  card.append(el("span", "caption muted", (gapDays
    ? `Hatched bands: ${gapDays} days no import covered the ${scopeWord(series[0].scope)} source. Nothing is drawn there; a line never bridges a gap.`
    : `Every day in the window was covered by an import of the ${scopeWord(series[0].scope)} source.`) + ends));
  later(() => drawTrend(chart, series, metricLabel(trendMetric)));
}

// ---- Data health ------------------------------------------------------------------------
let healthDays = 90;

async function screenHealth(out: ParentNode): Promise<void> {
  const health = await core.call<Health>("data.health", { window_days: healthDays });
  const cov = health.coverage;
  header(out, "Data health", `Why a day is missing · ${cov.window.from} → ${cov.window.to} · one row per metric and source`);
  const range = el("select") as HTMLSelectElement;
  for (const [d, label] of [[90, "last 90 days"], [365, "last year"], [1825, "last 5 years"]] as const) {
    const o = el("option", "", label) as HTMLOptionElement;
    o.value = String(d);
    o.selected = d === healthDays;
    range.append(o);
  }
  range.onchange = () => { healthDays = Number(range.value); void route(); };
  out.append(range);
  const legend = el("div", "legend caption");
  for (const [status, word] of [["present", "present"], ["failed", "failed (striped, taller)"], ["source_empty", "source empty"], ["not_covered", "not covered"]]) {
    const item = el("span");
    item.append(el("span", `chip ${status}`), document.createTextNode(word));
    legend.append(item);
  }
  out.append(legend);
  if (health.never_imported) {
    out.append(el("div", "banner body", "Nothing imported yet. Import with the command line for now: disconect import <export zip | watch folder>."));
    return;
  }
  const card = el("div", "card ledger");
  const rows = [...cov.ledger].sort((a, b) => (b.present - a.present) || a.metric.localeCompare(b.metric));
  for (const r of rows) {
    const block = el("div");
    const top = el("div", "row body");
    const name = el("span");
    name.append(document.createTextNode(`${metricLabel(r.metric)} `), scopeTag(r.source_scope));
    if (r.sparse) name.append(el("span", "caption muted", " sparse"));
    top.append(name);
    const words: string[] = [];
    for (const [k, w] of [["present", "present"], ["failed", "failed"], ["source_empty", "empty"], ["not_covered", "not covered"]] as const) {
      const n = r[k as keyof LedgerRow] as number;
      if (n) words.push(`${n} ${w}`);
    }
    top.append(el("span", "value-small", words.join(" · ")));
    block.append(top);
    const bar = el("div", "bar");
    for (const k of ["present", "failed", "source_empty", "not_covered"] as const) {
      const n = r[k] as number;
      if (!n) continue;
      const seg = el("span", `seg ${k}`);
      seg.style.flexGrow = String(n);
      seg.style.minWidth = "3px"; // one failed day out of 1825 must still be visible
      bar.append(seg);
    }
    block.append(bar);
    if (r.gaps.length) {
      const g = r.gaps.map((x) => (x.from && x.to ? (x.from === x.to ? x.from : `${x.from} → ${x.to}`) : JSON.stringify(x))).join(", ");
      block.append(el("span", "caption muted", `gaps: ${g}${r.gaps_truncated ? " (newest shown)" : ""}`));
    }
    card.append(block);
  }
  card.append(el("span", "caption muted", `Counts are days out of ${cov.window.days}, in status order, not time order. "present" can still be a partial day. A sparse metric is recorded only on some days, so its empty days are normal.`));
  out.append(card);
}

// ---- Your key ---------------------------------------------------------------------------
async function screenKey(out: ParentNode): Promise<void> {
  const info = await core.call<AppInfo>("app.info");
  header(out, "Your key", info.encrypted ? "Your database and its backups are encrypted with a key only you hold." : "This database is not encrypted yet.");
  const card = el("div", "card");
  if (!keyStatus) {
    card.append(el("span", "body", "The core is not running, so nothing can be unlocked."));
    out.append(card);
    return;
  }
  if (!keyStatus.encrypted) {
    card.append(el("h2", "heading", "Turn encryption on"));
    card.append(el("p", "body", "Run this once in a terminal, where the recovery words can be shown to you and to no one else:"));
    card.append(el("pre", "mono body", "disconect key init"));
    card.append(el("p", "caption muted", "The app never shows the 24 words. They are the key; a screenshot or a transcript would be a copy."));
    out.append(card);
    return;
  }
  if (!keyStatus.unlocked) {
    card.append(el("h2", "heading", "Unlock"));
    const form = el("form");
    form.style.display = "flex"; form.style.gap = "var(--space-2)"; form.style.flexWrap = "wrap";
    const input = el("input") as HTMLInputElement;
    input.type = "password"; input.autocomplete = "current-password"; input.placeholder = "Passphrase"; input.setAttribute("aria-label", "Passphrase");
    input.style.flexGrow = "1";
    const button = el("button", "", "Unlock") as HTMLButtonElement;
    const err = el("span", "caption error");
    form.append(input, button);
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      button.disabled = true; err.textContent = "";
      try {
        await core.unlock(input.value);
        input.value = "";
        location.hash = "#/today";
        await route();
      } catch (e) {
        err.textContent = core.isCoreError(e) && e.code === "wrong_passphrase" ? "That passphrase does not open this database." : core.isCoreError(e) ? `${e.code}: ${e.message}` : String(e);
      } finally {
        button.disabled = false;
      }
    };
    card.append(form, err);
    card.append(el("p", "caption muted", "Lost the passphrase? Use your 24 words in a terminal: disconect key recover."));
    out.append(card);
    setTimeout(() => input.focus(), 0);
    return;
  }
  card.append(el("h2", "heading", "Unlock on this device"));
  const label = el("label", "switch body") as HTMLLabelElement;
  label.append(el("span", "", "Keep the key in this device's keychain"));
  const word = (state: KeyStatus["keychain"]) => (state === "cached" ? "on" : state === "stale" ? "stale" : "off");
  const right = el("span", "caption muted", word(keyStatus.keychain));
  const box = el("input") as HTMLInputElement;
  box.type = "checkbox"; box.checked = keyStatus.keychain === "cached"; box.setAttribute("role", "switch");
  const note = el("span", "caption error");
  box.onchange = async () => {
    note.textContent = "";
    try {
      const r = await core.call<{ keychain: KeyStatus["keychain"] }>("key.cache", { enable: box.checked });
      right.textContent = word(r.keychain);
      box.checked = r.keychain === "cached";
      await refreshKey(); renderNav();
    } catch (e) {
      box.checked = !box.checked;
      note.textContent = core.isCoreError(e) ? `${e.code}: ${e.message}` : String(e);
    }
  };
  const wrap = el("span"); wrap.style.display = "inline-flex"; wrap.style.alignItems = "center"; wrap.style.gap = "var(--space-2)";
  wrap.append(right, box);
  label.append(wrap);
  card.append(label, note);
  if (keyStatus.keychain === "stale") card.append(el("p", "caption", "A key saved by another program or an earlier build of this app is in the keychain, and this build cannot read it without asking. Turn the switch on to replace it with one this build can read; macOS may ask you once to allow that."));
  card.append(el("p", "caption muted", "Off by default: you are asked for your passphrase each time the app starts. On, it is convenient, but programs you approve can then read the key. The app and the terminal each keep their own copy, and an update of the app forgets its copy: cache again afterwards."));
  out.append(card);
  const about = el("div", "card body");
  about.append(el("h2", "heading", "About"));
  about.append(el("span", "muted", `core ${info.core}`));
  about.append(el("span", "muted", `database ${info.db}`));
  const mcp = await core.mcpCommand().catch(() => "");
  if (mcp) {
    about.append(el("span", "", "Claude Desktop can use this app's core as its MCP server with this command:"));
    about.append(el("pre", "mono caption", mcp));
    // The MCP is a separate program with its own keychain item: it needs its own one-time cache.
    const cache = mcp.replace(/ mcp$/, " cli key cache");
    if (cache !== mcp) {
      about.append(el("span", "", "To let it open your encrypted database without a passphrase, run this once in a terminal (it asks for your passphrase):"));
      about.append(el("pre", "mono caption", cache));
      about.append(el("span", "caption muted", "If it reports an existing entry (error -25244), a different copy of the core made it: delete the “disconect-cli” item (not the “disconect” item, which is the app’s own) in Keychain Access, then run it again."));
    }
  }
  about.append(el("span", "caption muted", "If macOS refuses to open a copy of this app: System Settings → Privacy & Security → Open Anyway. A locally built app opens directly."));
  out.append(about);
}

// ---- Coach (Bet 15) ---------------------------------------------------------------------
// Everything the model says is drawn with textContent only: no markup, no links, no images. The conversation
// lives in this module (not in storage); the shell keeps the model's side of it until "New conversation".
type Turn =
  | { role: "user"; text: string }
  | { role: "coach"; text: string; trace: core.CoachTrace[]; host: string }
  | { role: "error"; text: string; trace: core.CoachTrace[]; host: string };
let conversation: Turn[] = [];
let coachDraft = "";
let coachIntroSeen = false; // this session only: a module variable, never storage

function hostOf(base: string): string {
  try {
    return new URL(base).host || "the endpoint";
  } catch {
    return "the endpoint";
  }
}

function tierSentence(s: core.CoachSettings): string {
  const host = hostOf(s.base_url);
  return s.mode === "local"
    ? `Day-level summaries of your data go to ${host}, an address you chose on this computer or your network. They stay on your network.`
    : `Day-level summaries of your data go over the internet to ${host}, a service you chose, and nowhere else.`;
}

function outcomeWord(o: core.CoachOutcome): string {
  switch (o.kind) {
    case "ok": return "sent";
    case "rejected": return `withheld (${o.detail})`;
    case "too_large": return "too large, nothing sent";
    default: return `failed (${o.detail})`;
  }
}

function drawer(trace: core.CoachTrace[], host: string, failed = false): HTMLElement {
  const results = trace.filter((t) => t.outcome.kind === "ok").length;
  const bytes = trace.reduce((n, t) => n + t.bytes_sent, 0);
  const box = el("details", "drawer");
  const sent = `Sent to ${host}${failed ? " before the error" : ""}: ${results} tool ${results === 1 ? "result" : "results"}, ${bytes} bytes`;
  box.append(el("summary", "caption", `What the model can see · ${sent}`));
  box.append(el("p", "caption muted", "Each answer below is exactly what the model received from one tool. The app's own instructions and the words you typed are sent with it."));
  for (const t of trace) {
    const entry = el("details");
    entry.append(el("summary", "caption mono", `${t.tool} ${JSON.stringify(t.arguments_sent)} · ${t.bytes_sent} bytes · ${outcomeWord(t.outcome)}`));
    entry.append(el("pre", "mono caption", JSON.stringify(t.projected, null, 2)));
    box.append(entry);
  }
  if (!trace.length) box.append(el("p", "caption muted", "No tool was called for this answer."));
  return box;
}

function bubble(turn: Turn): HTMLElement {
  const wrap = el("div", `turn ${turn.role === "user" ? "user" : "coach"}`);
  // neutralText runs here, at the one place model text is drawn
  wrap.append(el("p", `bubble ${turn.role}`, turn.role === "coach" ? neutralText(turn.text) : turn.text));
  if (turn.role === "coach") wrap.append(drawer(turn.trace, turn.host));
  // a failed question still shows what had already left before the error
  if (turn.role === "error" && turn.trace.length) wrap.append(drawer(turn.trace, turn.host, true));
  return wrap;
}

async function sendQuestion(): Promise<void> {
  const text = coachDraft.trim();
  if (!text || coachSending || !coachSettings) return;
  const host = hostOf(coachSettings.base_url);
  conversation.push({ role: "user", text });
  coachDraft = "";
  coachSending = host;
  renderNav();
  void route();
  try {
    const reply = await core.coachAsk(text);
    conversation.push({ role: "coach", text: reply.text, trace: reply.trace, host });
  } catch (e) {
    conversation.push({ role: "error", text: core.coachErrorText(e), trace: core.coachErrorTrace(e), host });
  } finally {
    coachSending = null;
    renderNav();
  }
  if (current() === "coach") void route();
}

function screenCoach(out: ParentNode, later: Later): void {
  header(out, "Coach", "Questions about your own days");
  out.append(el("p", "caption muted", DISCLAIMER)); // every visit, not dismissible
  const s = coachSettings;
  if (!s || s.mode === "off") {
    const card = el("div", "card");
    card.append(el("h2", "heading", "Coaching is off"));
    card.append(el("p", "body", "Nothing leaves this computer while it is off. Turning it on means this: day-level summaries of your data, and the words you type, go to the endpoint you choose. Nothing else is sent, and this app stores no conversation."));
    const link = el("a", "", "Open Coach settings") as HTMLAnchorElement;
    link.href = "#/coach-settings";
    card.append(link);
    out.append(card);
    return;
  }
  const host = hostOf(s.base_url);
  if (!coachIntroSeen) {
    const card = el("div", "card");
    card.append(el("h2", "heading", "Before you ask"));
    card.append(el("p", "body", tierSentence(s)));
    card.append(el("p", "body", `Your typed words also leave: everything you write in the box below is sent to ${host} too.`));
    card.append(el("p", "body", DISCLAIMER));
    const got = el("button", "", "Got it") as HTMLButtonElement;
    got.onclick = () => { coachIntroSeen = true; void route(); };
    card.append(got);
    out.append(card);
  }
  const thread = el("div", "thread");
  thread.setAttribute("aria-live", "polite");
  for (const turn of conversation) thread.append(bubble(turn));
  if (coachSending) {
    const waiting = el("div", "turn coach");
    waiting.append(el("p", "bubble coach waiting", `Waiting for ${coachSending}\u2026`));
    thread.append(waiting);
  }
  if (!conversation.length && !coachSending) thread.append(el("p", "muted body", "No questions yet. Ask about a metric, a week, or a night."));
  out.append(thread);

  const form = el("form", "card") as HTMLFormElement;
  const box = el("textarea") as HTMLTextAreaElement;
  box.placeholder = "Ask about your own days, for example: how did my sleep change this week?";
  box.setAttribute("aria-label", "Your question");
  box.value = coachDraft;
  box.disabled = !!coachSending;
  box.oninput = () => { coachDraft = box.value; };
  box.onkeydown = (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) {
      ev.preventDefault();
      form.requestSubmit();
    }
  };
  const actions = el("div", "actions");
  const ask = el("button", "", "Ask") as HTMLButtonElement;
  ask.type = "submit";
  ask.disabled = !!coachSending;
  const fresh = el("button", "secondary", "New conversation") as HTMLButtonElement;
  fresh.type = "button";
  fresh.disabled = !!coachSending;
  fresh.onclick = async () => {
    fresh.disabled = true;
    try {
      await core.coachReset();
      conversation = [];
    } catch (e) {
      // busy: a question is still running on the shell side, so the turns stay and the reason is shown
      conversation.push({ role: "error", text: core.coachErrorText(e), trace: [], host: "" });
    }
    void route();
  };
  actions.append(ask, fresh, el("span", "caption muted", "Enter sends, Shift+Enter starts a new line."));
  form.append(box, actions);
  form.onsubmit = (ev) => { ev.preventDefault(); void sendQuestion(); };
  out.append(form);
  later(() => {
    if (!coachSending) box.focus();
    thread.lastElementChild?.scrollIntoView({ block: "nearest" });
  });
}

// ---- Coach settings ---------------------------------------------------------------------
const KEY_WORDS: Record<core.CoachKeyState, string> = {
  absent: "No key is stored.",
  cached: "The key is in this device's keychain.",
  stale: "A key is in the keychain that this build cannot read without asking. Enter it again.",
  session_only: "The key is held for this session only; quitting the app forgets it.",
};

function badge(text: string, kind: "good" | "warn" | "bad"): HTMLElement {
  return el("span", `badge ${kind}`, text);
}

/** Only a short lowercase code is ever shown from a probe report. */
function codeWord(code: string | null): string {
  return code !== null && /^[a-z_]{1,40}$/.test(code) ? code : "unknown";
}

function probeBadges(r: core.ProbeReport): HTMLElement {
  const row = el("div", "badges");
  row.append(r.reachable ? badge("reachable", "good") : badge(`unreachable (${codeWord(r.error)})`, "bad"));
  if (r.error === "unauthorised") row.append(badge("unauthorised", "bad"));
  else if (r.reachable && r.error === "status") row.append(badge(`error status ${r.status ?? "unknown"}`, "bad"));
  else if (r.reachable && r.error) row.append(badge(`unreadable answer (${codeWord(r.error)})`, "warn"));
  const tools = { yes: "good", no: "bad", unknown: "warn" } as const;
  const context = { ok: "good", too_small: "bad", unknown: "warn" } as const;
  row.append(badge(`tools: ${r.tools}`, tools[r.tools]));
  const read = r.measured_prompt_tokens === null ? "" : ` (${r.measured_prompt_tokens} tokens read)`;
  row.append(badge(`context: ${r.context.replace("_", " ")}${read}`, context[r.context]));
  return row;
}

async function screenCoachSettings(out: ParentNode): Promise<void> {
  const s = await core.coachSettingsGet();
  let keyState = await core.coachKeyState();
  header(out, "Coach settings", "Which model answers, and where your questions go");

  const card = el("div", "card");
  card.append(el("h2", "heading", "Endpoint"));
  const group = el("div");
  group.setAttribute("role", "radiogroup");
  group.setAttribute("aria-label", "Coach mode");
  const radios: [core.CoachMode, string][] = [["off", "Off"], ["local", "Local endpoint"], ["cloud", "Cloud endpoint"]];
  let mode: core.CoachMode = s.mode;
  const url = el("input") as HTMLInputElement;
  const placeholder = (m: core.CoachMode): string => (m === "cloud" ? "https://…/v1" : "http://127.0.0.1:11434/v1");
  for (const [value, label] of radios) {
    const row = el("label", "choice body") as HTMLLabelElement;
    const radio = el("input") as HTMLInputElement;
    radio.type = "radio"; radio.name = "coach-mode"; radio.value = value; radio.checked = value === mode;
    radio.onchange = () => { mode = value; url.placeholder = placeholder(mode); };
    row.append(radio, el("span", "", label));
    group.append(row);
  }
  card.append(group);
  card.append(el("p", "caption muted", "Local: an address on this computer or your network, over plain http. Cloud: https only, with your own key. Off sends nothing."));
  url.type = "text"; url.value = s.base_url; url.placeholder = placeholder(mode); url.autocomplete = "off";
  url.setAttribute("aria-label", "Endpoint address");
  const model = el("input") as HTMLInputElement;
  model.type = "text"; model.value = s.model; model.placeholder = "model name"; model.autocomplete = "off";
  model.setAttribute("aria-label", "Model name");
  const addressField = el("label", "field body");
  addressField.append(el("span", "", "Address"), url);
  const modelField = el("label", "field body");
  modelField.append(el("span", "", "Model"), model);
  card.append(addressField, modelField);
  const points = el("label", "switch body") as HTMLLabelElement;
  points.append(el("span", "", "Include day-by-day points in facts"));
  const pointsBox = el("input") as HTMLInputElement;
  pointsBox.type = "checkbox"; pointsBox.checked = s.include_points; pointsBox.setAttribute("role", "switch");
  points.append(pointsBox);
  card.append(points);
  card.append(el("p", "caption muted", "Off: a fact carries its window and baseline figures only. On: a fact also carries its day-by-day points. Daily series are sent as days either way."));
  const save = el("button", "", "Save") as HTMLButtonElement;
  const saved = el("span", "caption");
  save.onclick = async () => {
    save.disabled = true; saved.textContent = ""; saved.className = "caption";
    try {
      coachSettings = await core.coachSettingsSet({ mode, base_url: url.value.trim(), model: model.value.trim(), key_in_keychain: s.key_in_keychain, include_points: pointsBox.checked });
      saved.textContent = "Saved."; saved.classList.add("muted");
      renderNav();
    } catch (e) {
      saved.textContent = core.coachErrorText(e); saved.classList.add("error");
    } finally {
      save.disabled = false;
    }
  };
  const saveRow = el("div", "actions");
  saveRow.append(save, saved);
  card.append(saveRow);
  out.append(card);

  const keyCard = el("div", "card");
  keyCard.append(el("h2", "heading", "Provider key"));
  const state = el("p", "body", KEY_WORDS[keyState]);
  const keyForm = el("form", "field") as HTMLFormElement;
  const keyInput = el("input") as HTMLInputElement;
  keyInput.type = "password"; keyInput.autocomplete = "off"; keyInput.placeholder = "Provider key"; keyInput.setAttribute("aria-label", "Provider key");
  const remember = el("label", "switch body") as HTMLLabelElement;
  remember.append(el("span", "", "Remember in this device's keychain"));
  const rememberBox = el("input") as HTMLInputElement;
  rememberBox.type = "checkbox"; rememberBox.checked = s.key_in_keychain; rememberBox.setAttribute("role", "switch");
  remember.append(rememberBox);
  const keyActions = el("div", "actions");
  const saveKey = el("button", "", "Save key") as HTMLButtonElement;
  saveKey.type = "submit";
  const forget = el("button", "secondary", "Forget key") as HTMLButtonElement;
  forget.type = "button";
  const keyNote = el("span", "caption");
  const showKey = (next: core.CoachKeyState) => { keyState = next; state.textContent = KEY_WORDS[keyState]; };
  keyForm.onsubmit = async (ev) => {
    ev.preventDefault();
    saveKey.disabled = true; keyNote.textContent = ""; keyNote.className = "caption";
    // the key is handed over and the field emptied in the same breath: it is never held in a variable here
    const pending = core.coachKeySet(keyInput.value, rememberBox.checked);
    keyInput.value = "";
    try {
      showKey(await pending);
    } catch (e) {
      keyNote.textContent = core.coachErrorText(e); keyNote.classList.add("error");
    } finally {
      saveKey.disabled = false;
    }
  };
  forget.onclick = async () => {
    keyNote.textContent = ""; keyNote.className = "caption";
    try {
      showKey(await core.coachKeyForget());
      rememberBox.checked = false;
    } catch (e) {
      keyNote.textContent = core.coachErrorText(e); keyNote.classList.add("error");
    }
  };
  keyActions.append(saveKey, forget, keyNote);
  keyForm.append(keyInput, remember, keyActions);
  keyCard.append(state, keyForm);
  keyCard.append(el("p", "caption muted", "A local endpoint usually needs no key. A cloud endpoint does."));
  out.append(keyCard);

  const testCard = el("div", "card");
  testCard.append(el("h2", "heading", "Test the endpoint"));
  testCard.append(el("p", "caption muted", "Sends two short made-up requests to the saved address, with none of your data: one asks for a tool call, one measures how much of a long prompt the model reads. Save first."));
  const results = el("div");
  const test = el("button", "secondary", "Test endpoint") as HTMLButtonElement;
  test.onclick = async () => {
    test.disabled = true; results.replaceChildren();
    try {
      const report = await core.coachProbe();
      results.append(probeBadges(report));
      if (report.context === "too_small") results.append(el("p", "caption", "The model read only part of a long prompt. Raise its context window (for Ollama, num_ctx) or choose another model."));
      if (report.tools === "no") results.append(el("p", "caption", "The model did not call a tool. The coach needs a model that supports tool calls."));
    } catch (e) {
      results.append(el("span", "caption error", core.coachErrorText(e)));
    } finally {
      test.disabled = false;
    }
  };
  testCard.append(test, results);
  out.append(testCard);

  out.append(el("p", "caption muted", "These settings are saved in a small file named coach.json in this app's configuration folder, on this computer. The provider key is never written to it."));
}

// ---- Boot -------------------------------------------------------------------------------
window.addEventListener("hashchange", () => void route());
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => void route());
void core.onCoreEvent("restarted", () => {
  banner = "The core restarted after an error; the last request was lost.";
  void (async () => {
    await refreshKey();
    if (locked()) await core.unlockFromKeychain();
    await route();
  })();
});
void core.onCoreEvent("exited", () => { banner = "The core stopped and could not be restarted. Quit and reopen the app."; void route(); });
void (async () => {
  await refreshKey();
  if (locked() && (await core.unlockFromKeychain())) await refreshKey();
  const args = await core.launchArgs().catch(() => [] as string[]);
  const i = args.indexOf("--screen");
  const wanted = i >= 0 && SCREENS.some((s) => s.id === args[i + 1]) ? args[i + 1] : null;
  const h = args.indexOf("--health-days");
  if (h >= 0 && [90, 365, 1825].includes(Number(args[h + 1]))) healthDays = Number(args[h + 1]);
  if (wanted && current() !== wanted) {
    location.hash = `#/${wanted}`; // hashchange runs route()
  } else {
    await route();
  }
})();
