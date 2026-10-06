// DISCOnect shell (Bet 7 slice 3): a hash router, four screens, one source of truth (the core).
// Rules: every value carries its source word; a missing day is drawn as absence; the UI never
// computes health facts itself; colours come from tokens only (see app.css / charts.ts).
import * as core from "./core";
import { AI_NOTICE, DISCLAIMER, NOTICE, OFF_NETWORK, PRODUCT, PROVIDERS, SUPPORT_EMPTY, SUPPORT_INTRO, SUPPORT_NETWORK, SUPPORT_UNAVAILABLE, metricLabel, neutralText, scopeWord } from "./identity";
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
type LiveBlock = { records: number; samples: number; first_day: string | null; last_day: string | null };
type ImportRun = {
  id: number; started_at: string | null; finished_at: string | null; transport: string; status: string;
  files_seen: number; files_imported: number; files_duplicate: number; files_failed: number; records_written: number; error: string | null;
};
type Health = {
  live?: LiveBlock; never_imported: boolean; recent_imports?: ImportRun[];
  coverage: { window: { from: string; to: string; days: number }; ledger: LedgerRow[]; unattributed_failures?: number; undatable_files?: number };
};
const TRANSPORT_WORD: Record<string, string> = { connect_export: "export", usb: "USB", ble: "Bluetooth", drop: "dropped files" };

const LIVE_FOLDED: { metric: string; unit: string | null }[] = [
  { metric: "heart_rate", unit: "bpm" }, { metric: "stress", unit: null }, { metric: "respiration_rate", unit: "breaths/min" },
  { metric: "spo2", unit: "%" }, { metric: "energy_reserve", unit: null },
];
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
  { id: "support", title: "Support" },
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

// Bet 17: the Support row is drawn only where the opener command exists (macOS; lib.rs's cfg). The probe
// at boot flips this off when `support_sites` is absent, so the row is absent there, never present-and-broken.
let supportShown = true;

/** The Watch entry's indicator while the link runs: a diamond and the word "live". */
function liveFlag(): HTMLElement {
  const flag = el("span", "flag");
  const mark = el("span", "livemark");
  mark.append(el("span", "swatch live"), document.createTextNode(liveStub ? "stub" : "live"));
  flag.append(mark);
  return flag;
}

function renderNav(): void {
  nav.replaceChildren();
  nav.append(el("div", "brand", PRODUCT));
  for (const s of SCREENS) {
    if (s.id === "support" && !supportShown) continue;
    const a = el("a", "", s.title) as HTMLAnchorElement;
    a.href = `#/${s.id}`;
    if (current() === s.id) a.setAttribute("aria-current", "page");
    if (s.id === "coach") a.append(coachFlag());
    if (s.id === "watch" && liveRunning) a.append(liveFlag());
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
  if (locked() && id !== "key" && id !== "coach-settings" && id !== "watch" && id !== "support") {
    location.hash = "#/key"; // hashchange re-enters route()
    return;
  }
  const out = document.createDocumentFragment();
  const queue: (() => void)[] = [];
  const later: Later = (fn) => queue.push(fn);
  if (banner) {
    out.append(bannerEl("The core", banner));
    banner = null; // shown once
  }
  try {
    if (id === "today") await screenToday(out);
    else if (id === "watch") await screenWatch(out, later);
    else if (id === "trend") await screenTrend(out, later);
    else if (id === "health") await screenHealth(out);
    else if (id === "coach") screenCoach(out, later);
    else if (id === "coach-settings") await screenCoachSettings(out);
    else if (id === "support") await screenSupport(out);
    else await screenKey(out);
  } catch (e) {
    if (core.isCoreError(e) && e.code === "locked") {
      location.hash = "#/key";
      return;
    }
    out.append(core.isCoreError(e) ? bannerEl(e.code, e.message, true) : bannerEl("Error", String(e), true));
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
/** The live-link card: the day's means of the folded minute samples, apart from every other scope. Nothing when no link was ever stored. */
async function liveCard(out: ParentNode, todayDay: string): Promise<void> {
  const health = await core.call<Health>("data.health", { window_days: 7 }).catch(() => null);
  const live = health?.live;
  if (!live || !live.records || !live.last_day) return;
  const lastDay = live.last_day;
  const results = await Promise.all(LIVE_FOLDED.map((m) => core.call<Metric>("data.metric", { metric: m.metric, scope: "live", days: 1, last_day: lastDay }).catch(() => null)));
  const card = el("section", "card");
  card.setAttribute("aria-label", "Live link");
  const row = el("div", "row");
  row.append(el("h2", "heading", "Live link"));
  const tag = el("span", "caption scope-live");
  tag.append(el("span", "swatch live"), document.createTextNode(scopeWord("live")));
  row.append(tag);
  card.append(row);
  card.append(el("span", "caption muted", `${live.records} session records · ${live.samples} minute samples · ${lastDay === todayDay ? "today" : `latest ${lastDay}`}`));
  const grid = el("div", "grid3 body live-grid");
  results.forEach((m, i) => {
    const d = m?.days.find((x) => x.day === lastDay) ?? m?.days[m.days.length - 1];
    if (!m || !d || d.value === null) return;
    const spec = LIVE_FOLDED[i];
    grid.append(el("span", "", metricLabel(spec.metric)));
    const v = el("span", "value-small scope-live", fmt(d.value, null));
    if (spec.unit) v.append(el("span", "unit", ` ${spec.unit}`));
    grid.append(v);
    grid.append(el("span", "muted caption", "daily mean of the link's minutes"));
  });
  card.append(grid);
  card.append(el("span", "caption muted", "Means of the minutes the watch sent while the link ran. Kept apart from the device's own figures and never combined with them. Data health lists every session."));
  out.append(card);
}

async function screenToday(out: ParentNode): Promise<void> {
  const [today, facts] = await Promise.all([core.call<Today>("data.today"), core.call<Facts>("data.facts", { days: 7, baseline_days: 28 })]);
  header(out, "Today", today.day);
  await liveCard(out, today.day);
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
let liveSeq = 0; // the current link's number: a stored event of another link is ignored
let liveStored: string | null = null; // what the sweep of the readings folder said after the last link ended
let liveReadings = 0; // reading lines since this link started
let liveClock: number | null = null; // ms epoch of the first "connected" status or first reading of this link
let liveStopAt: number | null = null; // when this link was first drawn as stopped: the clock freezes there
let liveNavShown = false;
let liveStub = false; // a stub stands in for the lab (evidence runs): every reading is invented
const liveNodes: { values: Map<string, HTMLElement>; since: Map<string, HTMLElement>; status: HTMLElement | null; steps: HTMLElement[]; button: HTMLButtonElement | null } = {
  values: new Map(), since: new Map(), status: null, steps: [], button: null,
};

function liveStatusWord(): string {
  if (liveStatus === "stopped") {
    const base = liveStop ? `stopped (${liveStop.replaceAll(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()})` : "stopped";
    return liveStored ? `${base} · ${liveStored}` : base;
  }
  return liveStatus;
}

function ago(t: number): string {
  const s = Math.max(0, Math.round(Date.now() / 1000 - t));
  return s < 60 ? `${s} s ago` : `${Math.round(s / 60)} min ago`;
}

const LIVE_UNITS: Record<string, string> = { heart_rate: "bpm", steps: "steps", respiration_rate: "breaths/min", spo2: "%" };

/** Which of the four steps is done / current, from the existing state. */
function liveStep(): { done: number; now: number } {
  if (liveStatus === "stopped") return { done: 3, now: 4 };
  if (liveReadings > 0) return { done: 2, now: 3 };
  if (liveStatus === "connected") return { done: 1, now: 2 };
  if (liveStatus === "starting" || liveStatus === "scanning" || liveStatus === "connecting") return { done: 0, now: 1 };
  return { done: 0, now: 0 };
}

function liveStepText(n: number): string {
  if (n === 1) return "connecting";
  if (n === 2) return "connected";
  if (n === 3) {
    if (liveStatus === "stopped") liveStopAt ??= Date.now(); else liveStopAt = null;
    const secs = liveClock === null ? 0 : Math.max(0, Math.floor(((liveStopAt ?? Date.now()) - liveClock) / 1000));
    if (liveReadings === 0 && liveStatus !== "stopped") return "reading";
    return `reading · ${liveReadings} readings · for ${Math.floor(secs / 60)} min ${secs % 60} s`;
  }
  return liveStatus === "stopped" ? liveStatusWord() : "stopped";
}

function drawLive(): void {
  const step = liveStep();
  liveNodes.steps.forEach((li, i) => {
    li.classList.toggle("done", i < step.done);
    li.classList.toggle("now", i + 1 === step.now);
    if (i + 1 === step.now) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
    const label = li.lastElementChild;
    if (label) label.textContent = liveStepText(i + 1);
  });
  if (liveNavShown !== liveRunning) { liveNavShown = liveRunning; renderNav(); }
  if (liveNodes.button) {
    liveNodes.button.textContent = liveRunning ? "Disconnect" : "Connect to watch";
    liveNodes.button.disabled = liveStatus === "starting" || liveStatus === "scanning" || liveStatus === "connecting";
  }
  for (const [metric, node] of liveNodes.values) {
    const latest = liveLatest.get(metric);
    node.textContent = latest ? String(latest.value) : "—";
    node.classList.toggle("muted", !latest);
    const unit = LIVE_UNITS[metric];
    if (latest && unit) node.append(el("span", "unit", ` ${unit}`));
    const since = liveNodes.since.get(metric);
    if (since) since.textContent = latest ? ago(latest.t) : "no reading yet";
  }
}

function onLive(line: core.LiveLine): void {
  if (typeof line.status === "string") {
    liveStatus = line.status;
    liveStop = typeof line.stop === "string" ? line.stop : null;
    liveRunning = line.status !== "stopped"; // any other status line comes from a running link
    if (line.status === "connected" && liveClock === null) liveClock = Date.now();
  }
  if (typeof line.metric === "string" && typeof line.value === "number" && typeof line.t === "number") {
    liveLatest.set(line.metric, { value: line.value, t: line.t });
    liveReadings += 1;
    if (liveClock === null) liveClock = Date.now();
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
      liveReadings = 0;
      liveClock = null;
      liveStop = null;
      liveStored = null;
      liveStatus = "starting";
      drawLive();
      liveSeq = (await core.liveStart()).seq ?? liveSeq;
      liveRunning = true;
    }
  } catch (e) {
    const code = core.isCoreError(e) ? e.code : "error";
    liveRunning = code === "live_busy"; // a refused second start: the first link still runs
    if (!liveRunning) {
      liveStatus = "stopped";
      liveStop = code;
    }
  }
  drawLive();
}

async function screenWatch(out: ParentNode, later: Later): Promise<void> {
  const state = await core.liveState().catch((): core.LiveStatus => ({ running: false, available: false }));
  liveRunning = state.running;
  liveStub = state.stub === true;
  liveSeq = state.seq ?? liveSeq;
  header(out, "Watch", liveStub ? "STUB LAB: every reading below is invented, not your watch's" : "live readings over Bluetooth, read-only · development builds only");
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
  const steps = el("ol", "steps");
  liveNodes.steps = [1, 2, 3, 4].map((n) => {
    const li = el("li");
    li.append(el("span", "n", String(n)), el("span", "", liveStepText(n)));
    steps.append(li);
    return li;
  });
  card.append(steps);
  out.append(card);
  if (liveStub) {
    const stub = el("section", "banner error");
    stub.append(el("span", "lead", "Stub lab"), el("span", "", "This run replaces the Bluetooth lab with a script. The numbers on this screen are made up for a screenshot; nothing is read from any watch."));
    out.append(stub);
  }
  const caution = el("section", "banner");
  caution.append(el("span", "lead", "Before you connect"), el("span", "", "Turn the phone's Bluetooth off first: the watch talks to one device at a time, and it stays silent while the phone holds the link. The first connection shows a code on the watch; confirm it. Cable sync will copy the watch's files over USB for days without Bluetooth; it is not wired yet."));
  out.append(caution);
  const cards = el("div", "cards");
  liveNodes.values.clear();
  liveNodes.since.clear();
  for (const metric of LIVE_ORDER) {
    const tile = el("div", "card vcard");
    const top = el("span", "caption top");
    top.append(el("span", "muted", metricLabel(metric)), el("span", "scope-live", scopeWord("live")));
    tile.append(top);
    const value = el("span", "value", "—");
    const since = el("span", "caption muted", "no reading yet");
    tile.append(value, since);
    liveNodes.values.set(metric, value);
    liveNodes.since.set(metric, since);
    cards.append(tile);
  }
  out.append(cards);
  out.append(el("p", "caption muted", "Every reading is collected in the lab's raw folder on this Mac, and stored when the link ends. The watch is only read; nothing is written to it."));
  liveNodes.status = steps;
  liveNodes.button = button;
  later(drawLive);
}

void core.onLiveLine(onLive);
void core.onLiveStored((text, seq) => {
  if (seq !== liveSeq) return;
  liveStored = text;
  drawLive();
});
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

function bannerEl(lead: string, text: string, error = false): HTMLElement {
  const b = el("section", error ? "banner body error" : "banner body");
  b.append(el("span", "lead", lead), el("span", "", text));
  return b;
}

function healthLiveCard(out: ParentNode, live: LiveBlock | undefined): void {
  if (!live || !live.records) return;
  const card = el("section", "card body");
  card.setAttribute("aria-label", "Live link");
  const row = el("div", "row");
  row.append(el("h2", "heading", "Live link"));
  const tag = el("span", "caption scope-live");
  tag.append(el("span", "swatch live"), document.createTextNode(scopeWord("live")));
  row.append(tag);
  card.append(row);
  const days = live.first_day && live.last_day ? (live.first_day === live.last_day ? live.first_day : `${live.first_day} → ${live.last_day}`) : "no day";
  card.append(el("span", "value-small", `${live.records} session records · ${live.samples} minute samples · ${days}`));
  card.append(el("span", "caption muted", "Session days count as present or not covered only; the link's minutes are kept apart from the device's own figures and never compared with them."));
  out.append(card);
}

function healthFailedCard(out: ParentNode, health: Health): void {
  const rows = health.coverage.ledger.filter((r) => r.failed > 0);
  const failedDays = rows.reduce((n, r) => n + r.failed, 0);
  const runs = (health.recent_imports ?? []).filter((r) => r.files_failed > 0 || r.status === "failed");
  const unplaced = health.coverage.unattributed_failures ?? 0;
  const undatable = health.coverage.undatable_files ?? 0;
  if (!failedDays && !runs.length && !unplaced && !undatable) return;
  const card = el("section", "card body");
  card.setAttribute("aria-label", "Failed to decode");
  card.append(el("h2", "heading", "Failed to decode"));
  if (failedDays) card.append(el("span", "value-small", `${failedDays} failed day${failedDays === 1 ? "" : "s"} across ${rows.length} metric row${rows.length === 1 ? "" : "s"} in this window`));
  for (const run of runs) {
    const when = run.started_at ? run.started_at.slice(0, 16).replace("T", " ") : "unknown time";
    const line = el("span", "caption");
    line.append(document.createTextNode(`${when} · ${TRANSPORT_WORD[run.transport] ?? run.transport} · ${run.files_failed} of ${run.files_seen} file${run.files_seen === 1 ? "" : "s"} failed`));
    if (run.error) line.append(el("span", "muted", ` · ${run.error}`));
    card.append(line);
  }
  if (unplaced || undatable) {
    const parts: string[] = [];
    if (unplaced) parts.push(`${unplaced} failure${unplaced === 1 ? "" : "s"} not placeable on a day`);
    if (undatable) parts.push(`${undatable} retained file${undatable === 1 ? "" : "s"} without a date span`);
    card.append(el("span", "caption muted", parts.join(" · ")));
  }
  card.append(el("span", "caption muted", "The core keeps counts and masked error text, never file names. A failed day is striped and taller in the bars below."));
  out.append(card);
}

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
    out.append(bannerEl("Nothing imported yet", "Import with the command line for now: disconect import <export zip | watch folder>."));
    return;
  }
  healthLiveCard(out, health.live);
  healthFailedCard(out, health);
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
    const span = (x: LedgerRow["gaps"][number]) => (x.from && x.to ? (x.from === x.to ? x.from : `${x.from} → ${x.to}`) : JSON.stringify(x));
    const failedGaps = r.gaps.filter((x) => x.status === "failed");
    const otherGaps = r.gaps.filter((x) => x.status !== "failed");
    if (otherGaps.length) block.append(el("div", "caption muted", `gaps: ${otherGaps.map(span).join(", ")}${r.gaps_truncated ? " (newest shown)" : ""}`));
    if (failedGaps.length) block.append(el("div", "caption status-failed", `failed: ${failedGaps.map(span).join(", ")}`));
    if (r.source_scope === "live") block.append(el("div", "caption muted", "session days only"));
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
    about.append(el("span", "", "Your AI tools can use this app's core as their MCP server with this command:"));
    about.append(el("pre", "mono caption", mcp));
    // The MCP is a separate program with its own keychain item: it needs its own one-time cache.
    const cache = mcp.replace(/ mcp$/, " cli key cache");
    if (cache !== mcp) {
      about.append(el("span", "", "To let it open your encrypted database without a passphrase, run this once in a terminal (it asks for your passphrase):"));
      about.append(el("pre", "mono caption", cache));
      about.append(el("span", "caption muted", "If it reports an existing entry (error -25244), a different copy of the core made it: delete the “disconect-cli” item (not the “disconect” item, which is the app’s own) in Keychain Access, then run it again."));
    }
  }
  about.append(el("span", "caption muted", "If the system refuses to open a copy of this app: System Settings → Privacy & Security → Open Anyway. A locally built app opens directly."));
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

// ---- the hand-off card (Bet 15c): module state only, never storage, never logged. ----------------------
let handoffWindow: 7 | 28 | 90 = 28;
let handoffBuilding = false;
let handoff: core.HandoffText | null = null;
let handoffSeq = 0; // a sequence guard: a response from an earlier build is dropped
let handoffProvider: core.ProviderId | null = null;
let handoffCopying = false;
let handoffCopiedOnce = false;
let handoffStatus = "";
let handoffStatusError = false;

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
    card.append(el("p", "body", `${OFF_NETWORK} Turning it on means this: day-level summaries of your data, and the words you type, go to the endpoint you choose. Nothing else is sent, and this app stores no conversation.`));
    const link = el("a", "", "Open Coach settings") as HTMLAnchorElement;
    link.href = "#/coach-settings";
    card.append(link);
    out.append(card);
    out.append(handoffCard());
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
  out.append(handoffCard());
  later(() => {
    if (!coachSending) box.focus();
    thread.lastElementChild?.scrollIntoView({ block: "nearest" });
  });
}

// ---- The hand-off to the user's own chat (Bet 15c): a different path from Ask. The app copies a day-level
// summary to the clipboard and opens a fixed provider site; it holds no login, no key, no session for any
// of the five, and never reads the answer back. Available whether coaching is on or off. ------------------

async function prepareHandoff(): Promise<void> {
  const seq = ++handoffSeq;
  handoffBuilding = true;
  handoff = null;
  handoffStatus = "";
  void route();
  try {
    const result = await core.handoffBuild(handoffWindow, false);
    if (seq !== handoffSeq) return; // a slower earlier build lost the race: drop it
    handoff = result;
    handoffBuilding = false;
  } catch (e) {
    if (seq !== handoffSeq) return;
    handoffBuilding = false;
    handoffStatus = core.handoffErrorText(e);
    handoffStatusError = true;
  }
  void route();
}

function handoffCard(): HTMLElement {
  const card = el("div", "card");
  card.append(el("h2", "heading", "Use the chat I use"));
  card.append(el("p", "body", "A different path from Ask: this app copies a day-level summary of your data to the clipboard, for you to paste into the chat you already use, signed in under your own account. The app holds no login and no key for it, and never reads the answer back."));
  card.append(el("p", "caption muted", "What the text holds: values by day (steps, resting heart rate, sleep length, stress, energy reserve, a recent window against your own earlier days, the latest night's stages, recent workouts). What it does not hold: times of day, raw samples, file names, device or account identifiers."));

  const windowGroup = el("div");
  windowGroup.setAttribute("role", "radiogroup");
  windowGroup.setAttribute("aria-label", "Window");
  for (const days of [7, 28, 90] as const) {
    const row = el("label", "choice body") as HTMLLabelElement;
    const radio = el("input") as HTMLInputElement;
    radio.type = "radio"; radio.name = "handoff-window"; radio.value = String(days); radio.checked = days === handoffWindow;
    radio.onchange = () => { handoffWindow = days; handoff = null; handoffStatus = ""; void route(); };
    row.append(radio, el("span", "", `${days} days`));
    windowGroup.append(row);
  }
  card.append(windowGroup);
  card.append(el("p", "caption muted", "Sleep detail is always the latest night."));

  const prepare = el("button", "", handoffBuilding ? "Preparing…" : "Prepare the text") as HTMLButtonElement;
  prepare.disabled = handoffBuilding;
  prepare.onclick = () => void prepareHandoff();
  card.append(prepare);

  if (handoff) {
    const preview = el("pre", "mono caption preview");
    preview.textContent = handoff.text;
    card.append(preview);
    card.append(el("p", "caption muted", `${handoff.bytes} bytes`));
    const s = handoff.shortened;
    if (s.thinned + s.truncated + s.dropped_facts > 0) {
      card.append(el("p", "caption muted", `Shortened to fit: ${s.thinned} series thinned, ${s.truncated} lists truncated, ${s.dropped_facts} facts dropped.`));
    }
  }

  const providerRow = el("div", "actions");
  for (const p of PROVIDERS) {
    const btn = el("button", "secondary", p.name) as HTMLButtonElement;
    btn.setAttribute("aria-pressed", String(p.id === handoffProvider));
    btn.onclick = () => { handoffProvider = p.id; void route(); };
    providerRow.append(btn);
  }
  card.append(providerRow);

  const chosen = PROVIDERS.find((p) => p.id === handoffProvider) ?? null;
  if (chosen) {
    card.append(el("p", "caption muted", `Opens ${chosen.host} in your browser.`));
    card.append(el("p", "body", "The clipboard is yours, not the app's: any app on this Mac can read it, clipboard managers keep a history of it, and Universal Clipboard pushes it to your other Apple devices over iCloud if that is on."));
    card.append(el("p", "body", "What the provider keeps, and whether it trains on what you paste, is set in your own account with that provider, not here. A long paste may be turned into an attachment by the provider."));
    card.append(el("p", "body", AI_NOTICE));

    const copyOpen = el("button", "", `Copy and open ${chosen.name}`) as HTMLButtonElement;
    copyOpen.disabled = !handoff || handoffCopying;
    copyOpen.onclick = () => {
      if (!handoff || handoffCopying) return;
      const text = handoff.text;
      const bytes = handoff.bytes;
      const provider = chosen.id;
      const host = chosen.host;
      handoffCopying = true;
      copyOpen.disabled = true;
      navigator.clipboard.writeText(text).then(
        () => {
          handoffCopiedOnce = true; // the text is in the clipboard from here on, whatever the open does
          return core.handoffOpen(provider).then(
            () => {
              handoffStatus = `Copied ${bytes} bytes; ${host} opened. Paste with ⌘V.`;
              handoffStatusError = false;
              handoffCopying = false;
              void route();
            },
            () => {
              handoffStatus = `Copied ${bytes} bytes; the browser could not be opened. Paste with ⌘V, or replace the clipboard below.`;
              handoffStatusError = true;
              handoffCopying = false;
              void route();
            },
          );
        },
        () => {
          handoffStatus = "The clipboard refused the write; nothing was opened.";
          handoffStatusError = true;
          handoffCopying = false;
          void route();
        },
      );
    };
    card.append(copyOpen);
  }

  if (handoffCopiedOnce) {
    const replace = el("button", "secondary", "Replace the clipboard") as HTMLButtonElement;
    replace.onclick = () => {
      navigator.clipboard.writeText(" ").then(
        () => {
          handoffStatus = "The clipboard now holds a space.";
          handoffStatusError = false;
          void route();
        },
        () => {
          handoffStatus = "The clipboard refused the write; it still holds the copied text.";
          handoffStatusError = true;
          void route();
        },
      );
    };
    card.append(replace);
  }

  if (handoffStatus) card.append(el("p", `caption ${handoffStatusError ? "error" : "muted"}`, handoffStatus));
  return card;
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
  card.append(el("p", "caption muted", "Local: an address on this computer or your network, over plain http. Cloud: https only, with your own key. Off opens no network connection."));
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

// ---- Support (Bet 17, donations only) --------------------------------------------------
// This screen opens no network connection of its own: the buttons open the system browser. Off macOS the
// command does not exist (lib.rs's cfg): the nav row is hidden and a direct visit draws SUPPORT_UNAVAILABLE.
async function screenSupport(out: ParentNode): Promise<void> {
  header(out, "Support", "If this app is useful to you");
  const intro = el("div", "card");
  intro.append(el("p", "body", SUPPORT_INTRO));
  intro.append(el("p", "caption muted", SUPPORT_NETWORK));
  out.append(intro);

  const sites = await core.supportSites().catch(() => null);
  if (sites === null) {
    out.append(el("div", "card body", SUPPORT_UNAVAILABLE));
    return;
  }
  if (!sites.length) {
    out.append(el("div", "card body", SUPPORT_EMPTY));
    return;
  }
  for (const s of sites) {
    const card = el("div", "card");
    card.append(el("h2", "heading", s.name));
    card.append(el("span", "caption muted", s.host));
    const button = el("button", "secondary", `Open ${s.host}`) as HTMLButtonElement;
    button.setAttribute("aria-label", `Open ${s.host} in your browser`);
    const status = el("p", "caption");
    button.onclick = async () => {
      try {
        await core.supportOpen(s.id);
        status.textContent = "";
        status.className = "caption";
      } catch {
        status.textContent = "The browser could not be opened.";
        status.className = "caption error";
      }
    };
    card.append(button, status);
    out.append(card);
  }
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
  await core.supportSites().then(() => undefined, () => { supportShown = false; });
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
