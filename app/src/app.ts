// DISCOnect shell (Bet 7 slice 3): a hash router, four screens, one source of truth (the core).
// Rules: every value carries its source word; a missing day is drawn as absence; the UI never
// computes health facts itself; colours come from tokens only (see app.css / charts.ts).
import * as core from "./core";
import { NOTICE, PRODUCT, metricLabel, scopeWord } from "./identity";
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
  { id: "trend", title: "Trends" },
  { id: "health", title: "Data health" },
  { id: "key", title: "Your key" },
];

const nav = document.getElementById("nav") as HTMLElement;
const main = document.getElementById("main") as HTMLElement;
let keyStatus: KeyStatus | null = null;
let banner: string | null = null;

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

function renderNav(): void {
  nav.replaceChildren();
  nav.append(el("div", "brand", PRODUCT));
  for (const s of SCREENS) {
    const a = el("a", "", s.title) as HTMLAnchorElement;
    a.href = `#/${s.id}`;
    if (current() === s.id) a.setAttribute("aria-current", "page");
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

let generation = 0;
type Later = (fn: () => void) => void;

/** Render the current screen. Single-flight: a newer route() wins and an older one draws nothing. */
async function route(): Promise<void> {
  const mine = ++generation;
  await refreshKey();
  if (mine !== generation) return;
  renderNav();
  const id = current();
  if (locked() && id !== "key") {
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
    else if (id === "trend") await screenTrend(out, later);
    else if (id === "health") await screenHealth(out);
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
    out.append(el("div", "banner body", "Nothing imported yet. Import with the command line for now: hearthbeat import <export zip | watch folder>."));
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
    card.append(el("pre", "mono body", "hearthbeat key init"));
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
    card.append(el("p", "caption muted", "Lost the passphrase? Recovery with the 24 words is done in a terminal: hearthbeat key recover."));
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
  if (keyStatus.keychain === "stale") card.append(el("p", "caption", "A key saved by an earlier build of this app is in the keychain and this build cannot read it. Turn the switch on again to replace it."));
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
  }
  about.append(el("span", "caption muted", "If macOS refuses to open a copy of this app: System Settings → Privacy & Security → Open Anyway. A locally built app opens directly."));
  out.append(about);
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
