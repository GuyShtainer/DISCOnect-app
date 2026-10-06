// DISCOnect shell (Bet 7 slice 3): a hash router, four screens, one source of truth (the core).
// Rules: every value carries its source word; a missing day is drawn as absence; the UI never
// computes health facts itself; colours come from tokens only (see app.css / charts.ts).
import * as core from "./core";
import qrcode from "qrcode-generator";
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
type LiveSession = { start_utc: string; end_utc: string; start_local: string; end_local: string; minutes: number };
type LiveDay = { day: string; sessions: LiveSession[]; metrics: { metric: string; unit: string | null; minutes: number; median: number | null }[] };
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
const TREND_METRICS = ["energy_reserve_high", "energy_reserve_low", "resting_heart_rate", "heart_rate", "steps", "sleep_score", "stress_avg", "stress", "hrv_last_night_average", "sleep_duration"];
// Sample-cadence metrics: data.metric returns each day's mean of its stored minutes (every scope, live included).
const DAILY_MEAN = new Set(["heart_rate", "stress"]);
function trendLabel(metric: string): string {
  return DAILY_MEAN.has(metric) ? `${metricLabel(metric)}, daily mean` : metricLabel(metric);
}
const SCREENS: { id: string; title: string }[] = [
  { id: "today", title: "Today" },
  { id: "watch", title: "Watch" },
  { id: "sync", title: "Sync" },
  { id: "import", title: "Import" },
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
    if (current().split("/")[0] === s.id) a.setAttribute("aria-current", "page");
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
  const [id, sub] = current().split("/");
  if (id !== "import") {
    importUi.error = null; // an import failure is shown on Import; leaving the screen ends it
    importUi.notice = null;
  }
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
    else if (id === "sync") await screenSync(out, later, sub === "pair");
    else if (id === "import") await screenImport(out);
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
    if (core.isCoreError(e) && e.code === "not_found" && e.message.includes("database yet")) {
      // no store on disk yet: the first drop on Import creates it
      const banner = bannerEl("Nothing imported yet", "There is no data on this Mac yet. Drop an export zip or a copied watch folder on Import.");
      banner.append(importLink());
      out.append(banner);
    } else {
      out.append(core.isCoreError(e) ? bannerEl(e.code, e.message, true) : bannerEl("Error", String(e), true));
    }
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
/** The live-link card: today's sessions and, per folded metric, the median of the link's minutes, apart from
 *  every other scope. Only on a day with a session (design decision 3): nothing when no link was ever stored
 *  and nothing on a day without one — Data health counts every session. */
async function liveCard(out: ParentNode, todayDay: string, health: Health | null): Promise<void> {
  const live = health?.live;
  if (!live || !live.records || !live.last_day) return;
  const day = await core.call<LiveDay>("data.live", { day: todayDay }).catch(() => null);
  if (!day || !day.sessions.length) return;
  const card = el("section", "card");
  card.setAttribute("aria-label", "Live link");
  const row = el("div", "row");
  row.append(el("h2", "heading", "Live link"));
  const tag = el("span", "caption scope-live");
  tag.append(el("span", "swatch live"), document.createTextNode(scopeWord("live")));
  row.append(tag);
  card.append(row);
  const n = day.sessions.length;
  const spans = day.sessions.map((x) => `${clock(x.start_local)}–${clock(x.end_local, x.start_local)}`).join(", ");
  const minutes = day.sessions.reduce((acc, x) => acc + x.minutes, 0);
  card.append(el("span", "caption muted", `${n} ${n === 1 ? "session" : "sessions"} today · ${spans} · ${minutes} min`));
  const grid = el("div", "grid3 body live-grid");
  for (const m of day.metrics) {
    if (!m.minutes || m.median === null) continue;
    grid.append(el("span", "", metricLabel(m.metric)));
    const v = el("span", "value-small scope-live", fmt(m.median, null));
    if (m.unit && m.unit !== "score") v.append(el("span", "unit", ` ${m.unit}`));
    grid.append(v);
    grid.append(el("span", "muted caption", `median over ${m.minutes} min`));
  }
  card.append(grid);
  card.append(el("span", "caption muted", "Medians of the minutes the watch sent while the link ran. Kept apart from the device's own figures and never combined with them. Data health counts every session."));
  out.append(card);
}

/** "HH:MM" of a local `YYYY-MM-DDTHH:MM`; with the date when it is not `sameDayAs`'s. */
function clock(local: string, sameDayAs?: string): string {
  const time = local.slice(11, 16);
  return sameDayAs && local.slice(0, 10) !== sameDayAs.slice(0, 10) ? `${local.slice(0, 10)} ${time}` : time;
}

async function screenToday(out: ParentNode): Promise<void> {
  const [today, facts, health] = await Promise.all([
    core.call<Today>("data.today"),
    core.call<Facts>("data.facts", { days: 7, baseline_days: 28 }),
    core.call<Health>("data.health", { window_days: 7 }).catch(() => null),
  ]);
  header(out, "Today", today.day);
  if (health?.never_imported) {
    // design pass 2026-10-06, states: a banner, not the empty value list (review N15)
    const nothing = bannerEl("Nothing imported yet", "Drop an export zip or a copied watch folder on the Import screen. Every screen fills from the first import.");
    nothing.append(importLink());
    out.append(nothing);
    return;
  }
  await liveCard(out, today.day, health);
  // Design pass 2026-10-06 (decision 2): the device and local figures first, a value from an earlier day
  // muted with its date; the vendor cloud's figures in a closed drawer; pairs never stored as a list.
  const fresh = today.metrics.filter((r) => r.value !== null && r.scope !== "vendor_cloud");
  const cloud = today.metrics.filter((r) => r.value !== null && r.scope === "vendor_cloud");
  const never = today.metrics.filter((r) => r.value === null);
  const cards = el("div", "cards");
  for (const row of fresh) cards.append(todayCard(row, today.day));
  if (fresh.length) out.append(cards);
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
  if (never.length) {
    const box = el("section", "card");
    box.append(el("h2", "heading", "No value stored"));
    const list = el("div", "notlist");
    const SHOWN = 6;
    never.forEach((row, i) => {
      const item = el("span");
      if (i >= SHOWN) item.hidden = true;
      const name = el("span");
      name.append(document.createTextNode(`${metricLabel(row.metric)} `), scopeTag(row.scope));
      item.append(name, el("span", "caption muted", missingWord(row.status) || "never stored"));
      list.append(item);
    });
    box.append(list);
    if (never.length > SHOWN) {
      const more = el("button", "secondary", `Show all ${never.length}`) as HTMLButtonElement;
      more.onclick = () => { for (const item of list.children) (item as HTMLElement).hidden = false; more.remove(); };
      box.append(more);
    }
    out.append(box);
  }
  if (cloud.length) {
    const drawer = el("details", "drawer");
    const latest = cloud.reduce<string | null>((m, r) => (r.day && (!m || r.day > m) ? r.day : m), null);
    drawer.append(el("summary", "", `${scopeWord("vendor_cloud")} · ${cloud.length} figure${cloud.length === 1 ? "" : "s"}${latest ? ` · latest ${latest}` : ""}`));
    const grid = el("div", "cards");
    for (const row of cloud) grid.append(todayCard(row, today.day));
    drawer.append(grid);
    out.append(drawer);
  }
}

/** One Today value card: label and scope on top, the value (muted when it is from an earlier day), then the day. */
function todayCard(row: TodayRow, todayDay: string): HTMLElement {
  const card = el("div", "card vcard");
  const top = el("span", "caption muted top");
  top.append(document.createTextNode(metricLabel(row.metric)), scopeTag(row.scope));
  card.append(top);
  const stale = !!row.day && row.day !== todayDay;
  const v = el("span", stale ? "value muted" : "value", fmtValue(row.value, row.unit));
  card.append(v);
  card.append(el("span", "caption muted", stale ? `latest · ${row.day}` : "today"));
  return card;
}

/** `fmt`, with minutes of an hour or more read as hours and minutes ("7 h 00 min"). */
function fmtValue(value: number | null, unit: string | null): string {
  if (value !== null && unit === "min" && Math.abs(value) >= 60) {
    const total = Math.round(Math.abs(value));
    return `${value < 0 ? "−" : ""}${Math.floor(total / 60)} h ${String(total % 60).padStart(2, "0")} min`;
  }
  return fmt(value, unit);
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
let liveReached = 0; // furthest step done while this link ran (review N3: a failed connect never shows "connected" as done)
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
  if (liveStatus === "stopped") return liveReached >= 2 ? { done: 3, now: 4 } : { done: liveReached, now: 0 };
  const step = liveReadings > 0 ? { done: 2, now: 3 }
    : liveStatus === "connected" ? { done: 1, now: 2 }
    : liveStatus === "starting" || liveStatus === "scanning" || liveStatus === "connecting" ? { done: 0, now: 1 }
    : { done: 0, now: 0 };
  liveReached = Math.max(liveReached, step.done);
  return step;
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
      liveReached = 0;
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

// ---- Sync and pairing (Bet 7b-2) ---------------------------------------------------------
// Every method that opens a network connection (sync.run, relay.serve, pair.*) is called from a click inside
// screenSync, and only there (test_lint_app.py slices this function). State lives at module level so a re-render
// (route()) draws the same walk; the event listeners are registered per render and the old ones dropped.
type SyncStatus = {
  bundles: Record<string, number>; records_unsent: number; records_seen: number; conflicts: number; superseded: number;
  gaps: unknown[]; last_pushed_at: string | null; last_pulled_at: string | null;
  serving: null | { url: string; keep: boolean; offer: null | "open" | "bound" | "released" | "delivered" };
};
type RelayAddresses = { addresses: { ip: string; label: string }[]; port: number };
type OfferReply = { offer: string; url: string; expires_at: number };
type PairPhase = "idle" | "pushing" | "open" | "bound" | "released" | "done";
type Step = "idle" | "now" | "done";

const syncRun = { running: false, push: "idle" as Step, pull: "idle" as Step, pushNote: "", pullNote: "", result: "" };
let syncError: core.CoreError | null = null; // shown once
let relayStoppedNote = false; // shown once
let chosenIp: string | null = null;
let pairPhase: PairPhase = "idle";
let pairOffer: OfferReply | null = null;
let pairEnding: { text: string; error: boolean } | null = null;
let pairNoDevice = false;
let pairPushing = false;
let pairDigitsTried = false;
let debugListen: { ip: string; port: number } | null = null; // --debug-listen ip:port (evidence runs): preselects that address and uses its port
let debugPairDigits = false; // --debug-pair-digits (evidence runs, debug builds)
let pairTimer: ReturnType<typeof setTimeout> | null = null;
let syncListenersArmed = false;

/** Redraw only while the Sync screen (or its pairing view) is on; any other screen picks the state up on return. */
function syncRedraw(): void {
  if (current().split("/")[0] === "sync") void route();
}
function syncFail(e: unknown): void {
  syncError = core.isCoreError(e) ? e : { code: "error", message: String(e) };
  syncRedraw();
}
// The core's pair / relay / progress events mutate module state here; the listeners are armed once at boot (review
// 7b-2 S3: per-render listeners lost the events that landed between a drop and the asynchronous re-registration).
function onPairEvent(payload: unknown): void {
  const p = payload as { state?: string; reason?: string };
  if (p.state === "bound") {
    if (pairPhase === "open" || pairPhase === "idle") pairPhase = "bound";
    pairNoDevice = false;
    if (debugPairDigits && !pairDigitsTried) {
      pairDigitsTried = true;
      void core.debugPairDigitsFromFile().then(() => { if (pairPhase === "bound") pairPhase = "released"; syncRedraw(); }, syncFail);
    }
    syncRedraw();
  } else if (p.state === "delivered") {
    endOfferState(null);
    pairPhase = "done";
    syncRedraw();
  } else if (p.state === "aborted") {
    const text = p.reason === "codes_differ" ? "The codes differ. The offer is closed; start a new one."
      : p.reason === "another_device" ? "Another device answered. Start over."
      : "Offer cancelled.";
    endOfferState({ text, error: p.reason !== "cancelled" });
    syncRedraw();
  } else if (p.state === "expired") {
    endOfferState({ text: "The offer expired after 15 minutes.", error: false });
    syncRedraw();
  }
}
function onRelayEvent(payload: unknown): void {
  const p = payload as { state?: string; reason?: string };
  if (p.state !== "stopped") return;
  // "offer_ended": the server followed the offer's lifetime rule (expiry or the linger after an end) — the pair
  // event already told the story, so only the "Serving at" line goes (review N4); "address_gone": the watcher
  if (p.reason === "address_gone") {
    if (pairOffer || pairPhase !== "idle") endOfferState({ text: "This Mac's address changed; the relay stopped. Start over on the new address.", error: true });
    else relayStoppedNote = true;
  }
  syncRedraw();
}
function onSyncProgress(payload: unknown): void {
  const p = payload as { op?: string; phase?: string; state?: string; bundles?: number; records?: number; applied?: number; rejected?: number; done?: number; total?: number | null; note?: string };
  if (p.op === "import") {
    onImportProgress(p);
  } else if (p.op === "sync") {
    const key = p.phase === "pull" ? "pull" : "push";
    syncRun[key] = p.state === "done" ? "done" : "now";
    if (p.state === "done") {
      syncRun[key === "push" ? "pushNote" : "pullNote"] = key === "push" ? `${p.bundles ?? 0} bundles, ${p.records ?? 0} records` : `${p.applied ?? 0} applied, ${p.rejected ?? 0} refused`;
    }
    syncRedraw();
  } else if (p.op === "pair") {
    syncRedraw();
  }
}
function armSyncListeners(): void {
  if (syncListenersArmed) return;
  syncListenersArmed = true;
  void core.onCoreEvent("progress", onSyncProgress);
  void core.onCoreEvent("pair", onPairEvent);
  void core.onCoreEvent("relay", onRelayEvent);
  void core.onCoreEvent("import", onImportEvent);
  void core.onDragHover(onDragHover);
}

/** The offer is over (any ending): the QR, the text and the typed digits go with it. No redraw here. */
function endOfferState(ending: { text: string; error: boolean } | null): void {
  pairOffer = null;
  pairPhase = "idle";
  pairNoDevice = false;
  pairPushing = false;
  pairDigitsTried = false;
  if (pairTimer) clearTimeout(pairTimer);
  pairTimer = null;
  if (ending) pairEnding = ending;
}

/** `[ip]:port` for an IPv6 literal, else `ip:port`. */
function listenOf(ip: string, port: number): string {
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

function drawQr(text: string): HTMLElement {
  const box = el("div", "qr");
  try {
    const qr = qrcode(0, "M");
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    const size = 216;
    const dpr = Math.max(1, Math.round(window.devicePixelRatio || 1));
    const canvas = el("canvas");
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", "Pairing code to scan with the other device");
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--qr-ink").trim() || "CanvasText";
      const px = size * dpr;
      for (let r = 0; r < n; r++) {
        for (let c = 0; c < n; c++) {
          if (!qr.isDark(r, c)) continue;
          const x0 = Math.round((c * px) / n);
          const y0 = Math.round((r * px) / n);
          ctx.fillRect(x0, y0, Math.round(((c + 1) * px) / n) - x0, Math.round(((r + 1) * px) / n) - y0);
        }
      }
    }
    box.append(canvas);
  } catch {
    box.append(el("span", "caption muted", "The code is too long to draw; use the text."));
  }
  return box;
}

async function screenSync(out: ParentNode, later: Later, pairing: boolean): Promise<void> {
  const mine = generation; // a render that lost to a newer route() must not touch the offer state below
  let status: SyncStatus | null = null;
  let statusErr: core.CoreError | null = null;
  try {
    status = await core.call<SyncStatus>("sync.status");
  } catch (e) {
    if (core.isCoreError(e) && e.code === "locked") throw e;
    statusErr = core.isCoreError(e) ? e : { code: "error", message: String(e) };
  }
  let addrs: RelayAddresses | null = null;
  let addrErr: core.CoreError | null = null;
  if (status) {
    try {
      addrs = await core.call<RelayAddresses>("relay.addresses");
    } catch (e) {
      addrErr = core.isCoreError(e) ? e : { code: "error", message: String(e) };
    }
  }
  if (mine !== generation) return; // stale: its sync.status may predate the offer that a newer render already holds
  const serving = status?.serving ?? null;
  // reconcile with the core: an offer this screen holds but the core no longer has is over
  if (status && pairOffer && !serving?.offer) endOfferState({ text: "The offer ended.", error: false });
  if (serving?.offer === "bound" && pairPhase === "open") pairPhase = "bound";
  if (serving?.offer === "released" && (pairPhase === "open" || pairPhase === "bound")) pairPhase = "released";
  // a delivered offer the screen missed; never while a new offer is being pushed (the core keeps the delivered one
  // until the push replaces it — review 7b-2 S1)
  if (serving?.offer === "delivered" && (pairPhase === "open" || pairPhase === "bound" || pairPhase === "released" || (pairPhase === "idle" && !pairPushing))) {
    endOfferState(null);
    pairPhase = "done";
  }
  if (!pairing) {
    pairEnding = null;
    if (pairPhase === "done") pairPhase = "idle";
  }
  const hostOfUrl = serving ? serving.url.replace(/^https?:\/\//, "").replace(/:\d+$/, "").replace(/^\[|\]$/g, "") : null;
  if (hostOfUrl) chosenIp = hostOfUrl;
  else if (debugListen && chosenIp === null && addrs?.addresses.some((a) => a.ip === debugListen?.ip)) chosenIp = debugListen.ip;
  if (addrs && !addrs.addresses.some((a) => a.ip === chosenIp)) chosenIp = addrs.addresses[0]?.ip ?? null;
  const redraw = syncRedraw; // re-routes only while the Sync screen is on (review S3)

  const addressSelect = (): HTMLSelectElement => {
    const select = el("select") as HTMLSelectElement;
    select.setAttribute("aria-label", "Network address to serve on");
    for (const a of addrs?.addresses ?? []) {
      const o = el("option", "", `${a.ip} · ${a.label}`) as HTMLOptionElement;
      o.value = a.ip;
      o.selected = a.ip === chosenIp;
      select.append(o);
    }
    select.disabled = !addrs || !addrs.addresses.length;
    select.onchange = () => { chosenIp = select.value; };
    return select;
  };
  const listen = (): string | null => (addrs && chosenIp ? listenOf(chosenIp, debugListen && debugListen.ip === chosenIp ? debugListen.port : addrs.port) : null);
  const fail = syncFail;

  // ---- Sync now ----
  const runSync = async (): Promise<void> => {
    syncRun.running = true;
    syncRun.push = "idle"; syncRun.pull = "idle"; syncRun.pushNote = ""; syncRun.pullNote = ""; syncRun.result = "";
    redraw();
    try {
      const r = await core.call<{ push: { bundles: number; records: number }; pull: { applied: number; records_new: number; status: string } }>("sync.run");
      syncRun.result = `Sent ${r.push.bundles} bundles (${r.push.records} records); received ${r.pull.applied} bundles, ${r.pull.records_new} new records${r.pull.status === "partial" ? " (partial)" : ""}.`;
    } catch (e) {
      syncError = core.isCoreError(e) ? e : { code: "error", message: String(e) };
    }
    syncRun.running = false;
    redraw();
  };

  // ---- serving ----
  const setServing = async (on: boolean): Promise<void> => {
    try {
      if (on) {
        const l = listen();
        if (!l) throw { code: "bad_params", message: "no network address to serve on" };
        await core.call("relay.serve", { on: true, listen: l });
      } else {
        await core.call("relay.serve", { on: false });
      }
      redraw();
    } catch (e) { fail(e); }
  };

  // ---- pairing ----
  const startOffer = async (): Promise<void> => {
    const l = listen();
    if (!l) return;
    pairEnding = null;
    pairNoDevice = false;
    pairDigitsTried = false;
    pairPhase = "pushing";
    pairPushing = true;
    redraw();
    try {
      const reply = await core.call<OfferReply>("pair.offer", { listen: l });
      pairPushing = false;
      pairOffer = reply;
      pairPhase = "open"; // `bound` cannot arrive before the reply
      if (pairTimer) clearTimeout(pairTimer);
      pairTimer = setTimeout(() => { if (pairPhase === "open") { pairNoDevice = true; redraw(); } }, 60000);
      redraw();
    } catch (e) {
      endOfferState(null);
      fail(e);
    }
  };
  const confirmDigits = async (digits: string): Promise<void> => {
    try {
      await core.call("pair.confirm", { digits });
      if (pairPhase === "bound") pairPhase = "released";
      redraw();
    } catch (e) {
      if (!pairEnding) { syncError = core.isCoreError(e) ? e : { code: "error", message: String(e) }; }
      redraw();
    }
  };
  const cancelOffer = async (): Promise<void> => {
    try {
      await core.call("pair.cancel");
    } catch (e) {
      if (!(core.isCoreError(e) && e.code === "not_found")) { fail(e); return; }
    }
    endOfferState({ text: "Offer cancelled.", error: false });
    redraw();
  };
  later(() => {
    if (pairing && debugPairDigits && serving?.offer === "bound" && !pairDigitsTried) onPairEvent({ state: "bound" });
  });

  // ---- drawing ----
  const stepsList = (items: { text: string; state: Step }[]): HTMLElement => {
    const ol = el("ol", "steps");
    items.forEach((it, i) => {
      const li = el("li", it.state === "idle" ? "" : it.state);
      if (it.state === "now") li.setAttribute("aria-current", "step");
      li.append(el("span", "n", String(i + 1)), el("span", "", it.text));
      ol.append(li);
    });
    return ol;
  };
  const errorBanners = (): void => {
    if (syncError) {
      out.append(bannerEl(syncError.code, syncError.message, true));
      syncError = null;
    }
    if (relayStoppedNote) {
      out.append(bannerEl("Relay stopped", "This Mac's address changed; the relay stopped. Start over on the new address.", true));
      relayStoppedNote = false;
    }
  };

  if (pairing) {
    header(out, "Pair a device", "The other device gets your key; nothing about it is stored here");
    errorBanners();
    const back = el("a", "", "Back to Sync") as HTMLAnchorElement;
    back.href = "#/sync";
    out.append(back);
    if (pairEnding) out.append(bannerEl(pairEnding.text, "", pairEnding.error));
    if (pairNoDevice) out.append(bannerEl("Nothing yet", "No device has reached this Mac yet. If the system asked about incoming connections, allow them; both devices must be on the same network."));
    if (addrErr) out.append(bannerEl(addrErr.code, addrErr.message, true));
    const grid = el("div", "card pair");
    const left = el("div", "field");
    const offerOpen = pairPhase === "open" || pairPhase === "bound" || pairPhase === "released";
    if (pairOffer && offerOpen) {
      left.append(drawQr(pairOffer.offer));
      const row = el("div", "offer-text");
      row.append(el("code", "", pairOffer.offer));
      const text = pairOffer.offer;
      const copy = el("button", "secondary", "Copy") as HTMLButtonElement;
      const said = el("span", "caption muted", "Copies to the clipboard, which other devices and clipboard managers may keep.");
      copy.onclick = () => {
        navigator.clipboard.writeText(text).then(() => { copy.textContent = "Copied"; }, () => { said.textContent = "The clipboard refused the write."; });
      };
      row.append(copy);
      left.append(row, said);
    } else if (serving?.offer && serving.offer !== "delivered" && !pairOffer) {
      left.append(el("p", "body muted", "An offer is open, but its text is not on this screen any more. Cancel it and start a new one."));
    } else if (pairPhase === "pushing") {
      left.append(el("p", "body", "Sending your data to the relay first…"));
    } else {
      if (pairPhase === "done") left.append(el("p", "body", "Done — the other device holds your key. Start a new offer to pair another device."));
      left.append(addressSelect());
      const start = el("button", "", "Start an offer") as HTMLButtonElement;
      start.disabled = !listen() || syncRun.running;
      start.onclick = () => void startOffer();
      left.append(start);
      left.append(el("p", "caption muted", "Other devices on this network can reach the relay while the offer is open. Use it only on a network you trust. The system may ask whether to allow incoming connections for this app: allow them, or no device can reach it."));
    }
    const right = el("div", "field");
    const reached = pairPhase === "bound" || pairPhase === "released" || pairPhase === "done" || serving?.offer === "bound";
    const typed = pairPhase === "released" || pairPhase === "done";
    right.append(stepsList([
      { text: "Offer shown — scan it or paste the text on the other device", state: offerOpen || pairPhase === "done" ? "done" : pairPhase === "pushing" ? "now" : "idle" },
      { text: "A device answered", state: reached ? "done" : offerOpen ? "now" : "idle" },
      { text: "Type the code the other device shows", state: typed ? "done" : pairPhase === "bound" || serving?.offer === "bound" ? "now" : "idle" },
      { text: "Done — the device holds your key", state: pairPhase === "done" ? "done" : pairPhase === "released" ? "now" : "idle" },
    ]));
    const input = el("input", "code-input") as HTMLInputElement;
    input.type = "text";
    input.inputMode = "numeric";
    input.maxLength = 6;
    input.pattern = "[0-9]{6}";
    input.autocomplete = "off";
    input.setAttribute("aria-label", "The six digits the other device shows");
    const canType = (pairPhase === "bound" || (serving?.offer === "bound" && pairPhase !== "released" && pairPhase !== "done")) && !!(pairOffer || serving?.offer);
    input.disabled = !canType;
    const pair = el("button", "", "Pair") as HTMLButtonElement;
    pair.disabled = !canType;
    pair.onclick = () => {
      const digits = input.value.trim();
      input.value = "";
      void confirmDigits(digits);
    };
    input.oninput = () => { input.value = input.value.replace(/\D/g, "").slice(0, 6); };
    const cancel = el("button", "secondary", "Cancel offer") as HTMLButtonElement;
    cancel.disabled = !(offerOpen || (serving?.offer && serving.offer !== "delivered"));
    cancel.onclick = () => void cancelOffer();
    const actions = el("div", "actions");
    actions.append(input, pair, cancel);
    right.append(actions);
    if (pairPhase === "done") {
      right.append(el("p", "caption muted", "The relay keeps serving until the offer expires (15 minutes) so the new device can make its first pull; turn the switch on the Sync screen on to keep serving."));
      if (serving && !serving.keep) {
        const stop = el("button", "secondary", "Stop serving now") as HTMLButtonElement;
        stop.onclick = () => { stop.disabled = true; void setServing(false); };
        right.append(stop);
      }
    }
    grid.append(left, right);
    out.append(grid);
    return;
  }

  header(out, "Sync", "Move your data between this Mac and your other devices through a relay you run");
  errorBanners();
  const card = el("section", "card");
  card.append(el("h2", "heading", "Relay"));
  const kv = el("dl", "kv");
  // sync.status answers on a store with no relay; only relay.addresses says not_found (review S1)
  const noRelay = addrErr?.code === "not_found";
  kv.append(el("dt", "", "Kind"), el("dd", "", noRelay ? "none set" : addrErr?.code === "bad_params" ? "another device's relay" : "folder relay"));
  card.append(kv);
  if (noRelay) card.append(el("p", "caption muted", "Set with the command line: disconect sync push --relay <folder> --remember"));
  if (statusErr) out.append(bannerEl(statusErr.code, statusErr.message, true));
  if (status && addrs) {
    const sw = el("label", "switch");
    sw.append(el("span", "", "Keep serving while the app runs"));
    const box = el("input") as HTMLInputElement;
    box.type = "checkbox";
    box.checked = serving?.keep === true;
    box.onchange = () => { box.disabled = true; void setServing(box.checked); };
    sw.append(box);
    card.append(sw, addressSelect());
    card.append(el("p", "caption muted", "Off, the relay serves only while an offer is open. The switch resets when the app quits."));
  } else if (status && addrErr && !noRelay) {
    card.append(el("p", "caption muted", `${addrErr.code}: ${addrErr.message}`));
  }
  // a running listener is always shown and always stoppable, whatever relay.addresses answered (review 7b-2 S4, S5)
  if (serving) {
    card.append(el("p", "body", `Serving at ${serving.url}`));
    if (!serving.keep) {
      const stop = el("button", "secondary", "Stop serving now") as HTMLButtonElement;
      stop.onclick = () => { stop.disabled = true; void setServing(false); };
      card.append(stop);
    }
  }
  if (status && addrs) card.append(el("p", "caption muted", "Other devices on this network can reach the relay while it serves. Use it only on a network you trust. The system may ask whether to allow incoming connections for this app: allow them, or no device can reach it."));
  out.append(card);
  if (!status) return;

  const stat = el("section", "card");
  stat.append(el("h2", "heading", "Status"));
  const when = (t: string | null): string => (t ? new Date(t).toLocaleString() : "never");
  const rows: [string, string][] = [
    ["Bundles pushed", String(status.bundles.pushed_applied ?? 0)],
    ["Bundles pulled", String(status.bundles.pulled_applied ?? 0)],
    ["Bundles refused", String(status.bundles.pulled_rejected ?? 0)],
    ["Records on the relay", String(status.records_seen)],
    ["Records not sent yet", String(status.records_unsent)],
    ["Conflicts", String(status.conflicts)],
    ["Versions kept aside", String(status.superseded)],
    ["Chain gaps", String(status.gaps.length)],
    ["Last sent", when(status.last_pushed_at)],
    ["Last received", when(status.last_pulled_at)],
  ];
  const kv2 = el("dl", "kv");
  for (const [k, v] of rows) kv2.append(el("dt", "", k), el("dd", "value-small", v));
  stat.append(kv2);
  const actions = el("div", "actions");
  const now = el("button", "", "Sync now") as HTMLButtonElement;
  now.disabled = syncRun.running || pairPushing;
  now.onclick = () => void runSync();
  const pairBtn = el("a", "button", "Pair a device") as HTMLAnchorElement;
  pairBtn.href = "#/sync/pair";
  actions.append(now, pairBtn);
  stat.append(actions);
  if (syncRun.running || syncRun.push !== "idle") {
    stat.append(stepsList([
      { text: `Push${syncRun.pushNote ? ` · ${syncRun.pushNote}` : ""}`, state: syncRun.push },
      { text: `Pull${syncRun.pullNote ? ` · ${syncRun.pullNote}` : ""}`, state: syncRun.pull },
    ]));
  }
  if (syncRun.result) stat.append(el("p", "body", syncRun.result));
  out.append(stat);

  // design decision 7: no device list, the honest card
  const devices = el("section", "card");
  devices.append(el("h2", "heading", "Devices that hold your key"));
  devices.append(el("p", "body", "Every paired device holds the same key, so this Mac cannot tell them apart and keeps no list."));
  devices.append(el("p", "caption muted", "To shut one device out: rotate the key with the command line (disconect key rotate-recovery), then pair the devices you keep again."));
  out.append(devices);
}

// ---- Trend ------------------------------------------------------------------------------
let trendMetric = TREND_METRICS[0];
let trendDays = 90;

async function screenTrend(out: ParentNode, later: Later): Promise<void> {
  const controls = el("div", "row");
  const select = el("select") as HTMLSelectElement;
  for (const m of TREND_METRICS) {
    const o = el("option", "", trendLabel(m)) as HTMLOptionElement;
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
  header(out, trendLabel(trendMetric), "");
  controls.append(select, range);
  out.append(controls);

  // The window ends on the latest day any metric has data, so an archive still draws.
  const today = await core.call<Today>("data.today");
  const lastDay = today.metrics.reduce<string>((acc, m) => (m.value !== null && m.day && m.day > acc ? m.day : acc), "") || today.day;
  // the live scope only exists for the metrics the link folds (decision 8: diamonds, never a line)
  const scopes = LIVE_FOLDED.some((m) => m.metric === trendMetric) ? [...SCOPES, "live"] : SCOPES;
  const results = await Promise.all(scopes.map((scope) => core.call<Metric>("data.metric", { metric: trendMetric, scope, days: trendDays, last_day: lastDay })));
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
  // the hatched bands follow the first non-live series: a live session claims no day, so its gaps mean nothing
  const lead = series.find((s) => s.scope !== "live") ?? series[0];
  const gapDays = lead.scope === "live" ? 0 : lead.days.filter((d) => d.status === "not_covered").length;
  const ends = lastDay !== today.day ? ` Window ends ${lastDay}, the latest day with data.` : "";
  const liveNote = series.some((s) => s.scope === "live") ? ` Diamonds: days with a live-link session, the mean of the minutes the link recorded; a session claims no day, so it draws no band.` : "";
  card.append(el("span", "caption muted", (lead.scope === "live"
    ? "Only live-link sessions have values for this metric in the window."
    : gapDays
      ? `Hatched bands: ${gapDays} days no import covered the ${scopeWord(lead.scope)} source. Nothing is drawn there; a line never bridges a gap.`
      : `Every day in the window was covered by an import of the ${scopeWord(lead.scope)} source.`) + liveNote + ends));
  later(() => drawTrend(chart, series, trendLabel(trendMetric)));
}

// ---- Import (Bet 7b-3) ------------------------------------------------------------------
// The drop is handled in Rust (import_drop.rs): the window's OS drop event becomes the core's import call there and
// `core://import` events (started / done / failed) come back here. This screen never starts an import and never
// holds a path; it reads import.last and draws the events and the core's `progress` events (op "import").
type ImportUi = {
  running: boolean; kind: "export" | "usb" | null; done: number; total: number | null; note: string; seen: boolean;
  error: { code: string; message: string } | null;
  /** A second drop answered `busy` while this app's own import runs: said once under the cards, then gone. */
  notice: string | null;
  /** Drops that sent `started` while an import of this app already ran: each will be answered `busy`. */
  extra: number;
};
const importUi: ImportUi = { running: false, kind: null, done: 0, total: null, note: "", seen: false, error: null, notice: null, extra: 0 };
let dropOverDebug = false;
let importBusyTimer: ReturnType<typeof setTimeout> | null = null;
const IMPORT_BUSY = "An import or a sync is already running. Drop it again when that ends.";
const IMPORT_SECOND = "Another import is already running; drop it again when that ends.";
const IMPORT_GONE = "The item is gone; drop it again.";
const IMPORT_KEPT = "What you drop stays where it is, unencrypted. Delete it when you no longer need it.";

/** Redraw only while the Import screen is on. */
function importRedraw(): void {
  if (current().split("/")[0] === "import") void route();
}

function importLink(): HTMLElement {
  const a = el("a", "caption", "Open Import");
  a.setAttribute("href", "#/import");
  return a;
}

/** The running card's bar and line, repainted in place from the module state (a tick never redraws the screen). */
function importPaint(): void {
  const text = document.getElementById("import-progress-text");
  const bar = document.getElementById("import-progress-bar");
  const fill = document.getElementById("import-progress-fill");
  if (text) text.textContent = importProgressLine();
  if (bar) bar.hidden = importUi.total === null;
  if (fill) fill.style.width = importUi.total ? `${Math.min(100, Math.round((importUi.done / importUi.total) * 100))}%` : "0%";
}

function importProgressLine(): string {
  if (!importUi.seen) return "Starting";
  // only an export's JSON phase reports no total (a folder counts its files from the first event)
  if (importUi.total === null) return `Reading the export's records · ${importUi.done} read`;
  return `${importUi.done} of ${importUi.total} files`;
}

function importIdleLater(): void {
  // a `busy` answer with nothing of ours running means something else holds the slot (a sync, a pair push); if no
  // progress arrives for a while, stop waiting
  if (importBusyTimer) clearTimeout(importBusyTimer);
  importBusyTimer = setTimeout(() => {
    importBusyTimer = null;
    if (importUi.running && importUi.kind === null) {
      importUi.running = false;
      importRedraw();
    }
  }, 5000);
}

function onImportEvent(payload: unknown): void {
  const p = payload as { state?: string; kind?: string; code?: string; message?: string };
  const ours = importUi.running && importUi.kind !== null; // an import of this app is running now
  if (p.state === "started") {
    if (ours) {
      importUi.extra += 1; // a second drop: the core will answer `busy`; the live state stays as it is
    } else {
      importUi.running = true;
      importUi.kind = p.kind === "usb" ? "usb" : "export";
      importUi.done = 0;
      importUi.total = null;
      importUi.note = "";
      importUi.seen = false;
      importUi.error = null;
      importUi.notice = null;
    }
  } else if (p.state === "done") {
    importUi.running = false;
    importUi.kind = null;
    importUi.error = null;
    importUi.extra = 0;
  } else if (p.state === "failed") {
    if (p.code === "bad_drop" || p.code === "core_unavailable") {
      importUi.error = { code: p.code, message: p.message ?? "" }; // never touches a run in progress
    } else if (p.code === "busy" && importUi.extra > 0) {
      importUi.extra -= 1;
      importUi.notice = IMPORT_SECOND;
    } else if (p.code === "busy") {
      importUi.running = true; // nothing of ours runs: a sync or a pair push holds the slot
      importUi.kind = null;
      importUi.error = null;
      importIdleLater();
    } else {
      importUi.running = false;
      importUi.kind = null;
      importUi.extra = 0;
      importUi.error = { code: p.code ?? "error", message: p.message ?? "" };
    }
  } else return;
  // a drop on any screen shows its outcome on Import (the route draws the running or failed state there)
  if (current().split("/")[0] !== "import") location.hash = "#/import";
  else importRedraw();
}

function onImportProgress(p: { done?: number; total?: number | null; note?: string }): void {
  if (!importUi.running) return;
  importUi.seen = true;
  importUi.done = p.done ?? 0;
  importUi.total = typeof p.total === "number" ? p.total : null;
  importUi.note = p.note ?? "";
  if (importUi.kind === null) importIdleLater();
  importPaint();
}

function onDragHover(over: boolean): void {
  for (const card of document.querySelectorAll(".drop")) card.classList.toggle("over", over && !importUi.running);
}

function dropCard(kind: "export" | "usb", title: string, hint: string): HTMLElement {
  const card = el("section", "drop");
  card.setAttribute("aria-label", title);
  card.append(el("h2", "heading", title));
  const running = importUi.running && importUi.kind === kind;
  const muted = importUi.running && !running;
  if (muted) card.classList.add("muted");
  if (dropOverDebug && !importUi.running) card.classList.add("over");
  if (running) {
    const bar = el("div", "progress");
    bar.id = "import-progress-bar";
    bar.hidden = importUi.total === null;
    bar.setAttribute("role", "progressbar");
    const fill = el("span");
    fill.id = "import-progress-fill";
    bar.append(fill);
    card.append(el("p", "body", "Importing"));
    card.append(bar);
    const line = el("span", "caption", importProgressLine());
    line.id = "import-progress-text";
    card.append(line);
    fill.style.width = importUi.total ? `${Math.min(100, Math.round((importUi.done / importUi.total) * 100))}%` : "0%";
  } else {
    card.append(el("p", "body", hint));
  }
  return card;
}

/** Plain words for a failed import: never a code name, never the core's own message. */
function importErrorText(e: { code: string; message: string }): string {
  if (e.code === "bad_drop") return e.message;
  if (e.code === "not_found") return IMPORT_GONE;
  if (e.code === "busy") return IMPORT_BUSY;
  if (e.code === "locked") return "Unlock the store first.";
  if (e.code === "core_unavailable") return "The core is not running.";
  return "The import failed. The command line says more: disconect import <path>.";
}

function importOutcomeBanner(run: ImportRun | undefined): HTMLElement {
  if (importUi.error) return bannerEl("Not imported", importErrorText(importUi.error), true);
  if (importUi.running && importUi.kind !== null) {
    return bannerEl("Importing", `${importUi.kind === "usb" ? "The copied watch folder" : "The account export"} is being read · the counts arrive when it ends`);
  }
  if (importUi.running) return bannerEl("Busy", IMPORT_BUSY); // nothing of ours runs, yet the slot is held
  if (!run) return bannerEl("Nothing imported yet", "Drop an export zip or a copied watch folder below. Every screen fills from the first import.");
  if (run.status === "running") {
    // the newest run never ended and nothing runs now: the app or the core stopped under it
    const when = run.started_at ? new Date(run.started_at).toLocaleString() : "unknown time";
    return bannerEl("Interrupted", `${when} · this import stopped before it ended · drop it again, files already held are skipped`, true);
  }
  const failedRun = run.status === "failed";
  const withFailures = !failedRun && run.files_failed > 0;
  const lead = failedRun ? "Failed" : withFailures ? "Done with failures" : "Done";
  const when = run.started_at ? new Date(run.started_at).toLocaleString() : "unknown time";
  const text = failedRun
    ? `${when} · the import failed${run.error ? ` · ${run.error}` : ""}`
    : run.files_seen === 0
    ? `${when} · nothing to import was found in it`
    : `${when} · ${run.files_imported} of ${run.files_seen} file${run.files_seen === 1 ? "" : "s"} imported · ${run.files_duplicate} already held · ${run.files_failed} failed`;
  const b = bannerEl(lead, text, failedRun);
  if (failedRun || withFailures) {
    const link = el("a", "caption", "See what failed on Data health");
    link.setAttribute("href", "#/health");
    b.append(link);
  }
  return b;
}

async function screenImport(out: ParentNode): Promise<void> {
  // a store that does not exist yet is exactly where the first drop goes: the core creates it on that run
  const last = await core.call<{ runs: ImportRun[] }>("import.last").catch((e: unknown) => {
    if (core.isCoreError(e) && e.code === "not_found") return { runs: [] as ImportRun[] };
    throw e;
  });
  const runs = last.runs ?? [];
  header(out, "Import", "Drop it on this window");
  if (keyStatus && !keyStatus.encrypted) {
    out.append(bannerEl("Not encrypted", "This store is not encrypted yet. Run disconect key init from the command line before pairing a phone."));
  }
  out.append(importOutcomeBanner(runs[0]));
  const drops = el("div", "drops");
  drops.append(dropCard("export", "Account export", "Drop your account export zip here"));
  drops.append(dropCard("usb", "Copied watch folder", "Drop the folder you copied from the watch"));
  const cable = el("section", "card muted");
  cable.setAttribute("aria-label", "Cable sync");
  cable.setAttribute("aria-disabled", "true");
  cable.append(el("h2", "heading", "Cable sync"));
  cable.append(el("p", "body", "Needs the watch over USB with the vendor's sync fully quit — command line only for now"));
  out.append(drops);
  if (importUi.notice) out.append(el("span", "caption", importUi.notice));
  importUi.notice = null; // said once
  out.append(el("span", "caption muted", IMPORT_KEPT), cable);
  const recent = el("section", "card");
  recent.setAttribute("aria-label", "Recent imports");
  recent.append(el("h2", "heading", "Recent imports"));
  if (!runs.length) {
    recent.append(el("span", "caption muted", "No imports yet."));
  } else {
    const grid = el("div", "runs body");
    for (const [i, run] of runs.entries()) {
      grid.append(el("span", "", run.started_at ? new Date(run.started_at).toLocaleString() : "unknown time"));
      grid.append(el("span", "", TRANSPORT_WORD[run.transport] ?? run.transport));
      grid.append(el("span", "value-small", `${run.files_seen} file${run.files_seen === 1 ? "" : "s"}`));
      const failedRun = run.status === "failed";
      const withFailures = !failedRun && run.files_failed > 0;
      if (failedRun || withFailures) {
        const a = el("a", "caption", failedRun ? "failed" : "done with failures");
        a.setAttribute("href", "#/health");
        grid.append(a);
      } else {
        const word = run.status !== "running" ? "done" : i === 0 && importUi.running ? "running" : "interrupted";
        grid.append(el("span", "caption", word));
      }
    }
    recent.append(grid);
  }
  out.append(recent);
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
  card.append(el("span", "value-small", `${live.records} session record${live.records === 1 ? "" : "s"} · ${live.samples} minute sample${live.samples === 1 ? "" : "s"} · ${days}`));
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
    const when = run.started_at ? new Date(run.started_at).toLocaleString() : "unknown time";
    const line = el("span", "caption");
    const what = run.files_seen ? `${run.files_failed} of ${run.files_seen} file${run.files_seen === 1 ? "" : "s"} failed` : "the import failed";
    line.append(document.createTextNode(`${when} · ${TRANSPORT_WORD[run.transport] ?? run.transport} · ${what}`));
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
    const nothing = bannerEl("Nothing imported yet", "Drop an export zip or a copied watch folder on the Import screen.");
    nothing.append(importLink());
    out.append(nothing);
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
  if (keyStatus.keychain === "stale") card.append(el("p", "caption", "A key saved by another program or an earlier build of this app is in the keychain, and this build cannot read it without asking. Turn the switch on to replace it with one this build can read; the system may ask you once to allow that."));
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
  if (pairOffer || pairPhase !== "idle") endOfferState({ text: "The core stopped; the offer is gone.", error: true });
  banner = "The core restarted after an error; the last request was lost.";
  void (async () => {
    await refreshKey();
    if (locked()) await core.unlockFromKeychain();
    await route();
  })();
});
armSyncListeners();
void core.onCoreEvent("exited", () => { if (pairOffer || pairPhase !== "idle") endOfferState({ text: "The core restarted; the offer is gone.", error: true }); banner = "The core stopped and could not be restarted. Quit and reopen the app."; void route(); });
void (async () => {
  await refreshKey();
  if (locked() && (await core.unlockFromKeychain())) await refreshKey();
  await core.supportSites().then(() => undefined, () => { supportShown = false; });
  const args = await core.launchArgs().catch(() => [] as string[]);
  const i = args.indexOf("--screen");
  const wanted = i >= 0 && SCREENS.some((s) => s.id === args[i + 1]) ? args[i + 1] : null;
  const h = args.indexOf("--health-days");
  if (h >= 0 && [90, 365, 1825].includes(Number(args[h + 1]))) healthDays = Number(args[h + 1]);
  const t = args.indexOf("--trend"); // evidence runs: open Trends on one metric
  if (t >= 0 && TREND_METRICS.includes(args[t + 1])) trendMetric = args[t + 1];
  const dl = args.indexOf("--debug-listen");
  const m = dl >= 0 ? /^(.+):(\d{1,5})$/.exec(args[dl + 1] ?? "") : null;
  if (m) debugListen = { ip: m[1].replace(/^\[|\]$/g, ""), port: Number(m[2]) };
  dropOverDebug = args.includes("--debug-drop-over"); // debug builds only: Rust adds it from DISCONECT_DEBUG_DROP_OVER
  debugPairDigits = args.includes("--debug-pair-digits"); // debug builds only: the Rust command is compiled out of release
  const target = args.includes("--sync-pair") ? "sync/pair" : wanted;
  if (target && current() !== target) {
    location.hash = `#/${target}`; // hashchange runs route()
  } else {
    await route();
  }
})();
