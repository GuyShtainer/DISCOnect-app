// DISCOnect shell (Bet 7 slice 3): a hash router, four screens, one source of truth (the core).
// Rules: every value carries its source word; a missing day is drawn as absence; the UI never
// computes health facts itself; colours come from tokens only (see app.css / charts.ts).
import * as core from "./core";
import * as phone from "./phone";
import qrcode from "qrcode-generator";
import { AI_NOTICE, DISCLAIMER, NOTICE, OFF_NETWORK, PRODUCT, PROVIDERS, SUPPORT_EMPTY, SUPPORT_INTRO, SUPPORT_NETWORK, SUPPORT_UNAVAILABLE, metricLabel, neutralText, scopeWord, metricHue } from "./identity";
import { disposeCharts, drawTrend, hatchedDays, showTipOn, type Series } from "./charts";

// Build-time constant (vite.config.ts `define`): true only in the iOS build. Every `PHONE` branch below is the phone's.
declare const __PHONE__: boolean;
const PHONE = __PHONE__;
if (PHONE) document.body.classList.add("phone");

type KeyStatus = { key_file: boolean; encrypted: boolean; unlocked: boolean; keychain: "cached" | "absent" | "stale" };
type AppInfo = { product: string; notice: string; core: string; db: string; encrypted: boolean; schema: number; contract: number };
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

// The metric list is read once per session from data.contract (contract order; sample cadence = daily mean);
// each entry's scopes (the live link last, where a session stream folds the metric) are what Trends and Sleep draw.
type ContractMetric = { metric: string; unit: string | null; cadence: "daily" | "sample"; scopes: string[] };
let contractList: ContractMetric[] | null = null;
/** The product words on screen: the TS constants until `app.info` answers, then the core's. */
const productWords = { product: PRODUCT, notice: NOTICE };
/** The contract read both Trends and Sleep use: the list, or the failure that stopped it. A failed read is asked again;
 *  an empty answer is kept for the session (the core's answer is fixed per build and reads no store). */
async function contractMetrics(): Promise<ContractMetric[] | { failure: { code?: string } | null }> {
  if (contractList === null) {
    let failure: { code?: string } | null = null;
    const c = await core.call<{ metrics: ContractMetric[] }>("data.contract").catch((e: { code?: string }) => { failure = e; return null; });
    if (!c) return { failure };
    contractList = c.metrics.filter((m) => m.scopes.length > 0);
  }
  return contractList;
}
function contractFailureWords(failure: { code?: string } | null): string {
  return failure?.code === "core_unavailable" ? "The core is not running." : "The core did not answer with its metric list.";
}
let trendArg: string | null = null; // --trend <id>, resolved after the first contract read
function trendLabel(metric: string): string {
  const m = contractList?.find((c) => c.metric === metric);
  return m?.cadence === "sample" ? `${metricLabel(metric)}, daily mean` : metricLabel(metric);
}
const GROUPS = ["Your data", "Getting data in", "Coach", "This app"] as const;
// One ordered list, grouped: the sidebar, the drawer, the route code and the lint all read it.
const SCREENS: { id: string; title: string; group: (typeof GROUPS)[number] }[] = [
  { id: "today", title: "Today", group: "Your data" },
  { id: "sleep", title: "Sleep", group: "Your data" },
  { id: "trend", title: "Trends", group: "Your data" },
  { id: "health", title: "Data health", group: "Your data" },
  { id: "import", title: "Import", group: "Getting data in" },
  { id: "sync", title: "Sync", group: "Getting data in" },
  { id: "watch", title: "Watch", group: "Getting data in" },
  { id: "coach", title: "Coach", group: "Coach" },
  { id: "coach-settings", title: "Coach settings", group: "Coach" },
  { id: "key", title: "Your key", group: "This app" },
  { id: "support", title: "Support", group: "This app" },
];

// The phone (12-F, shape C): the drawer is Today, Sleep, Trends, Data health, Sync, Settings, Support. Import, Watch, Coach
// and Coach settings live on the Mac; Your key is folded into Settings (its id still answers the lock redirect).
const PHONE_HIDDEN = new Set(["import", "watch", "coach", "coach-settings", "key"]);
const PHONE_SETTINGS = { id: "settings", title: "Settings", group: "This app" } as const;
const PHONE_MORE = "Import, the watch link and the coach live on your Mac. This phone reads the copy it pulls.";
function visibleScreens(): { id: string; title: string; group: (typeof GROUPS)[number] }[] {
  if (!PHONE) return SCREENS;
  return SCREENS.filter((s) => !PHONE_HIDDEN.has(s.id)).flatMap((s) => (s.id === "support" ? [PHONE_SETTINGS, s] : [s]));
}

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
/** A phone that has never been paired: no store and no key file. Its only screen is Pair Start. */
function unpaired(): boolean {
  return PHONE && !!keyStatus && !keyStatus.key_file && !keyStatus.encrypted;
}

/** The Watch entry's indicator while the link runs: a diamond and the word "live". */
function liveFlag(): HTMLElement {
  const flag = el("span", "flag");
  const mark = el("span", "livemark");
  mark.append(el("span", "swatch live"), document.createTextNode(liveStub ? "stub" : "live"));
  flag.append(mark);
  return flag;
}

const topbar = document.getElementById("topbar") as HTMLElement;
const menuButton = document.getElementById("menu") as HTMLButtonElement;
const scrim = document.getElementById("scrim") as HTMLElement;
const narrow = window.matchMedia("(max-width: 720px)");
(topbar.querySelector(".name") as HTMLElement).textContent = productWords.product;

/** The drawer (under 720 px): the sidebar shown over a scrim, the page behind it inert. */
function drawerOpen(): boolean {
  return nav.hasAttribute("data-open");
}
function setDrawer(open: boolean, returnFocus = true): void {
  if (open === drawerOpen() || (open && !narrow.matches)) return;
  if (open) nav.setAttribute("data-open", ""); else nav.removeAttribute("data-open");
  scrim.hidden = !open;
  main.inert = open;
  topbar.inert = open;
  menuButton.setAttribute("aria-expanded", String(open));
  if (open) focusDrawer();
  else if (returnFocus) menuButton.focus();
}
function focusDrawer(): void {
  const target = nav.querySelector<HTMLElement>('a[aria-current="page"]') ?? nav.querySelector<HTMLElement>("a");
  target?.focus();
}
menuButton.addEventListener("click", () => setDrawer(!drawerOpen()));
scrim.addEventListener("click", () => setDrawer(false));
nav.addEventListener("click", (e) => { if ((e.target as HTMLElement).closest("a")) setDrawer(false); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && drawerOpen()) { e.preventDefault(); setDrawer(false); } });
narrow.addEventListener("change", () => {
  if (!narrow.matches) setDrawer(false, false);
  else if (nav.contains(document.activeElement)) menuButton.focus();
});

/** Paint the core's product words into what is already drawn (the title, the top bar, the sidebar brand and notice). */
function paintIdentity(): void {
  document.title = productWords.product;
  (topbar.querySelector(".name") as HTMLElement).textContent = productWords.product;
  const brand = nav.querySelector(".brand");
  if (brand) brand.textContent = productWords.product;
  const notice = nav.querySelector("footer.notice");
  if (notice) notice.textContent = productWords.notice;
  const inMain = main.querySelector("footer.notice");
  if (inMain) inMain.textContent = productWords.notice;
}

function renderNav(): void {
  nav.replaceChildren();
  nav.append(el("div", "brand", productWords.product));
  for (const g of GROUPS) {
    const here = visibleScreens().filter((s) => s.group === g);
    if (!here.length) continue; // the phone has no Coach group
    const box = el("div", "navgroup");
    box.setAttribute("role", "group");
    const cap = el("div", "group caption muted", g);
    cap.id = `group-${g.toLowerCase().replace(/[^a-z]+/g, "-")}`;
    box.setAttribute("aria-labelledby", cap.id);
    box.append(cap);
    for (const s of here) {
      if (s.id === "support" && !supportShown && !PHONE) continue; // the phone's Support screen says what it cannot do
      const a = el("a", "", s.title) as HTMLAnchorElement;
      a.href = `#/${s.id}`;
      if (current().split("/")[0] === s.id) a.setAttribute("aria-current", "page");
      if (s.id === "coach") a.append(coachFlag());
      if (s.id === "watch" && liveRunning) a.append(liveFlag());
      box.append(a);
    }
    nav.append(box);
  }
  nav.append(el("div", "spacer"));
  const status = el("div", "status caption muted");
  status.textContent = unpaired() ? "" : PHONE && keyStatus?.key_file && !keyStatus.encrypted ? "Nothing pulled yet" : keyStatus
    ? keyStatus.encrypted
      ? keyStatus.unlocked ? `Encrypted · unlocked${keyStatus.keychain === "cached" ? " · key in keychain" : ""}` : "Encrypted · locked"
      : "Not encrypted"
    : "";
  nav.append(status);
  if (PHONE) nav.append(el("p", "caption muted more", neutralText(PHONE_MORE))); // the board's More caption, as the drawer's footer
  nav.append(el("footer", "notice", productWords.notice));
  (topbar.querySelector(".keyword") as HTMLElement).textContent = unpaired() ? "" : PHONE && keyStatus?.key_file && !keyStatus.encrypted ? "Nothing pulled" : keyStatus
    ? keyStatus.encrypted ? (keyStatus.unlocked ? "Unlocked" : "Locked") : "Not encrypted"
    : "";
  if (drawerOpen() && !nav.contains(document.activeElement)) focusDrawer(); // a redraw must not strand the focus
}

async function refreshKey(): Promise<KeyStatus | null> {
  try {
    keyStatus = await core.call<KeyStatus>("key.status");
  } catch (e) {
    keyStatus = null;
    banner = "The core is not available. Quit and reopen the app.";
  }
  return keyStatus;
}

function locked(): boolean {
  return !!keyStatus && keyStatus.encrypted && !keyStatus.unlocked;
}

async function refreshCoach(): Promise<void> {
  if (PHONE) return; // the phone build registers no coach command
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
  menuButton.hidden = PHONE && (unpaired() || locked() || pairingActive()); // Pair Start, the pairing steps and Unlock are drawn with no drawer
  const [id, sub] = current().split("/");
  if (id !== "import") {
    importUi.error = null; // an import failure is shown on Import; leaving the screen ends it
    importUi.notice = null;
  }
  // the coach settings need no data from the store (the probe works on a locked one), so they stay reachable
  // the watch screen reads the link, not the store
  if (locked() && !pairingActive() && id !== "key" && id !== "coach-settings" && id !== "watch" && id !== "support") {
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
    // an id the phone's drawer lacks (Your key's lock redirect, Import, Watch, Coach, a typo): Unlock when locked, else home
    const phoneStray = PHONE && !visibleScreens().some((s) => s.id === id);
    if (PHONE && (pairingActive() || unpaired())) screenPairStart(out);
    else if (phoneStray) {
      if (locked()) screenPhoneUnlock(out);
      else { location.hash = "#/today"; return; }
    } else if (id === "today") await screenToday(out);
    else if (id === "sleep") await screenSleep(out, later, sub);
    else if (id === "watch") await screenWatch(out, later);
    else if (id === "sync") await screenSync(out, later, sub === "pair");
    else if (id === "import") await screenImport(out);
    else if (id === "trend") await screenTrend(out, later);
    else if (id === "health") await screenHealth(out);
    else if (id === "coach") screenCoach(out, later);
    else if (id === "coach-settings") await screenCoachSettings(out);
    else if (id === "support") await screenSupport(out);
    else if (PHONE && id === "settings") await screenPhoneSettings(out);
    else await screenKey(out);
  } catch (e) {
    if (core.isCoreError(e) && e.code === "locked") {
      location.hash = "#/key";
      return;
    }
    if (PHONE && core.isCoreError(e) && e.code === "not_found" && e.message.includes("database yet")) {
      out.append(phoneEmptyBanner()); // paired (a key file), but no store has been made: the same state as an empty one
    } else if (PHONE) {
      out.append(pbanner("This screen could not be read", PHONE_READ_FAIL, true)); // never a raw code or the core's own text
    } else if (core.isCoreError(e) && e.code === "not_found" && e.message.includes("database yet")) {
      // no store on disk yet: the first drop on Import creates it
      const banner = bannerEl("Nothing imported yet", "There is no data on this Mac yet. Drop an export zip or a copied watch folder on Import.");
      banner.append(importLink());
      out.append(banner);
    } else {
      const w = coreWords(e);
      out.append(bannerEl(w.lead, w.text, true));
    }
  }
  if (mine !== generation) return;
  out.append(el("footer", "notice", productWords.notice));
  disposeCharts();
  main.replaceChildren(out);
  for (const fn of queue) fn();
  if (scrollDebug > 0) requestAnimationFrame(() => { window.scrollTo(0, scrollDebug); main.scrollTop = scrollDebug; (document.scrollingElement ?? document.body).scrollTop = scrollDebug; });
}

function header(out: ParentNode, title: string, sub: string): void {
  const row = el("div", "row head"); // `.head`: on the phone the subtitle always sits below the title
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
  if (PHONE && health?.never_imported) {
    out.append(phoneEmptyBanner());
    return;
  }
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

/** The metric's hue class (decision 13): sets --hue on a card or a dot; "" when the metric has no group. */
function hueClass(metric: string): string {
  const g = metricHue(metric);
  return g ? ` hue-${g}` : "";
}
/** A dot in the metric's hue, before its name. */
function hueDot(metric: string): HTMLElement {
  const d = el("span", `huedot${hueClass(metric)}`);
  d.setAttribute("aria-hidden", "true");
  return d;
}

/** One Today value card: label and scope on top, the value (muted when it is from an earlier day), then the day. */
function todayCard(row: TodayRow, todayDay: string): HTMLElement {
  const card = el("div", `card vcard${hueClass(row.metric)}`);
  const top = el("span", "caption muted top");
  top.append(document.createTextNode(metricLabel(row.metric)), scopeTag(row.scope));
  card.append(top);
  const stale = !!row.day && row.day !== todayDay;
  const v = el("span", stale ? "value muted" : "value", fmtValue(row.value, row.unit));
  card.append(v);
  if (PHONE) { // room for a short "±" caption under the value (nothing fills it yet), so the cards do not jump when it lands
    const spread = el("span", "caption muted spread");
    spread.setAttribute("aria-hidden", "true");
    card.append(spread);
  }
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
      liveStop = "could not start"; // a refusal's machine word never shows
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
    const tile = el("div", `card vcard${hueClass(metric)}`);
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
  relay_url?: string | null; // the LAN relay's http://host:port from relay.json; null or absent: none to show
  relay_kind?: "folder" | "lan" | "mixed" | null; // 19a: what the relay list holds; the timer runs only with a folder in it
  chains?: { device_id: string; bundles: number; records: number; last_seq: number; self: boolean }[]; // 19b: counts per device chain; absent until the core says it
  relays?: SiteRow[] | null; // 19d: the sites of this session's last sync.run; null or absent before the first
};
/** One relay of the list, as `sync.run` reported it (19d): counts and a reason word, never a path or an address. */
type SiteRow = { id: string; kind: string; label?: string; pushed: number; healed: number; behind: number; pulled: number; rejected: number; error: string | null };
// The site words both cores emit (RelayError::site_word and open_sites), in plain words; anything else reads as a plain failure.
const SITE_WORDS: Record<string, string> = {
  unavailable: "Not reachable", same_relay: "Same as another relay", bad_url: "Bad address", unsupported_transport: "Needs the desktop core",
  unreachable: "Not reachable", refused: "Refused", unverified: "Not verified", too_large: "Too large", bad_name: "Bad name",
  missing: "Folder missing", no_permission: "No permission", io_error: "Read or write failed",
  not_auto: "Clicks only", // 19a: a network relay is never polled on a schedule; it is a rule, not a failure
};
const SITE_KINDS: Record<string, string> = { folder: "Folder", lan: "Network" };
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
let debugTipDay: string | null = null; // --debug-tip YYYY-MM-DD (evidence runs): the Trends tip shown on that day
let debugPairDigits = false; // --debug-pair-digits (evidence runs, debug builds)
let pairTimer: ReturnType<typeof setTimeout> | null = null;
let syncListenersArmed = false;

// ---- 19a: the desktop syncs from its folder relays on its own ------------------------------------
// autoSyncRun() is the one sync.run outside screenSync (test_lint_app.py slices this section out by its two
// heading comments): it always passes auto: true, and the core runs the folder sites only — a network relay is
// reported not_auto and never polled on a schedule (pitch 19a; the OFF_NETWORK promise stays enforced by the core).
// The phone never runs it (it syncs by its own rule when opened).
const AUTO_SYNC_STORE = "disconect.autoSync"; // the user's switch, per device; absent = on
const autoSync = {
  on: true, every: 5 * 60 * 1000, first: 30_000,
  timer: null as ReturnType<typeof setTimeout> | null,
  at: null as Date | null, // the last run that reached the core (ok or failed), for the walk line and the focus rule
  line: "", // the walk line under the switch: "Synced on its own at HH:MM · N new" or the failure, once
};
function autoSyncLoad(): void {
  try { autoSync.on = localStorage.getItem(AUTO_SYNC_STORE) !== "off"; } catch { autoSync.on = true; }
}
function autoSyncSet(on: boolean): void {
  autoSync.on = on;
  try { if (on) localStorage.removeItem(AUTO_SYNC_STORE); else localStorage.setItem(AUTO_SYNC_STORE, "off"); } catch { /* storage is optional */ }
  if (!on) autoSync.line = "";
}
async function autoSyncRun(): Promise<void> {
  if (PHONE || !autoSync.on || locked() || syncRun.running || pairPushing) return;
  const clock = (d: Date): string => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  try {
    const r = await core.call<{ pull: { applied: number; records_new: number; status: string }; sites?: SiteRow[]; status?: string }>("sync.run", { auto: true });
    autoSync.at = new Date();
    const failed = (r.sites ?? []).filter((x) => x.error && x.error !== "not_auto").length;
    autoSync.line = `Synced on its own at ${clock(autoSync.at)} · ${r.pull.records_new} new${r.status === "partial" || r.pull.status === "partial" ? " (partial)" : ""}${failed > 0 ? ` · ${failed} of ${r.sites?.length ?? 0} relays could not be used; see Relays below` : ""}`;
  } catch (e) {
    if (core.isCoreError(e) && (e.code === "busy" || e.code === "locked" || e.code === "not_found" || e.code === "not_folder")) return; // nothing to do this tick; the next one looks again
    autoSync.at = new Date();
    autoSync.line = `Could not sync on its own at ${clock(autoSync.at)}. ${coreLine(e)}`;
  }
  syncRedraw();
}
function autoSyncSchedule(delay: number): void {
  if (PHONE) return;
  if (autoSync.timer) clearTimeout(autoSync.timer);
  autoSync.timer = setTimeout(() => { void autoSyncRun().finally(() => autoSyncSchedule(autoSync.every)); }, delay);
}
if (!PHONE) window.addEventListener("focus", () => { // back to the app: look once, but not twice within a minute
  if (autoSync.at && Date.now() - autoSync.at.getTime() < 60_000) return;
  void autoSyncRun();
});
// ---- 19a end --------------------------------------------------------------------------------------

/** Redraw only while the Sync screen (or its pairing view) is on; any other screen picks the state up on return. */
function syncRedraw(): void {
  if (current().split("/")[0] === "sync") void route();
}
// The relay's two answers a person can act on, in plain words (the core's own text names the causes at length).
const SYNC_WORDS: Record<string, string> = {
  relay_auth_failed: "The relay refused this device: its clock and this device's clock disagree. Check the date and time on both.",
  relay_unverified: "This device could not verify the relay's answer: it may not be the relay this device paired with, the relay may have been set up again with a new key (pair again from it), the network may have altered the answer, or the connection broke.",
};
const SYNC_LEADS: Record<string, string> = { relay_auth_failed: "Refused", relay_unverified: "Not verified" };

function syncFail(e: unknown): void {
  syncError = core.isCoreError(e) ? e : { code: "error", message: String(e) };
  syncRedraw();
}
// The core's pair / relay / progress events mutate module state here; the listeners are armed once at boot (review
// 7b-2 S3: per-render listeners lost the events that landed between a drop and the asynchronous re-registration).
function onPairEvent(payload: unknown): void {
  if (PHONE) { phonePairEvent(payload); return; } // the phone's `pair` events are the joiner's (code, released)
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
    if (PHONE) phonePairProgress(p);
    else syncRedraw();
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
    const qr = qrcode(0, "L"); // error-correction L: the offer fits version 13 (69 modules), so each module is drawn larger
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    const dpr = Math.max(1, Math.round(window.devicePixelRatio || 1));
    // 312 CSS px at most, every module a whole number of device pixels (crisp edges: a camera reads them better)
    const mod = Math.max(1, Math.floor((312 * dpr) / n));
    const size = (mod * n) / dpr;
    const canvas = el("canvas");
    canvas.width = mod * n;
    canvas.height = mod * n;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", "Pairing code to scan with the other device");
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--qr-ink").trim() || "CanvasText";
      for (let r = 0; r < n; r++) {
        for (let c = 0; c < n; c++) {
          if (qr.isDark(r, c)) ctx.fillRect(c * mod, r * mod, mod, mod);
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
  if (PHONE) {
    // the phone's Sync: a pull from the Mac's relay, no serving and no pairing offer (relay.addresses is not on its list)
    const pull = async (): Promise<void> => {
      phonePull.running = true; phonePull.failure = null; phonePull.result = "";
      syncRedraw();
      try {
        const r = await core.call<{ push?: { bundles: number }; pull: { applied: number; records_new: number; status: string } }>("sync.run");
        phonePull.sent = r.push?.bundles ?? 0;
        phonePull.result = `Pulled ${r.pull.applied} ${r.pull.applied === 1 ? "bundle" : "bundles"}, ${r.pull.records_new} new records${r.pull.status === "partial" ? " (not all of it yet)" : ""}.`;
      } catch (e) {
        phonePull.failure = phoneSyncFailure(e);
      }
      phonePull.running = false;
      syncRedraw();
    };
    let produced: phone.Produced | null = null;
    try { produced = await phone.liveProduced(); } catch { produced = null; }
    phoneSync(out, status, statusErr, pull, produced);
    return;
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
      const r = await core.call<{ push: { bundles: number; records: number }; pull: { applied: number; records_new: number; status: string }; sites?: SiteRow[]; status?: string }>("sync.run");
      const failed = (r.sites ?? []).filter((s) => s.error && s.error !== "not_auto").length;
      const partial = r.status === "partial" || r.pull.status === "partial";
      syncRun.result = `Sent ${r.push.bundles} bundles (${r.push.records} records); received ${r.pull.applied} bundles, ${r.pull.records_new} new records${partial ? " (partial)" : ""}.${failed > 0 ? ` ${failed} of ${r.sites?.length ?? 0} relays could not be used; see Relays below.` : ""}`;
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
      out.append(bannerEl(coreWords(syncError).lead, coreWords(syncError).text, true));
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
    if (addrErr) {
      const w = addrErr.code === "not_found" ? NO_RELAY : coreWords(addrErr); // no relay folder: say the step, not the code
      out.append(bannerEl(w.lead, w.text, true));
    }
    const grid = el("div", "card pair");
    const left = el("div", "field");
    const offerOpen = pairPhase === "open" || pairPhase === "bound" || pairPhase === "released";
    if (pairOffer && offerOpen) {
      left.append(drawQr(pairOffer.offer));
      const row = el("div", "offer-text");
      row.append(el("code", "", pairOffer.offer));
      left.append(row);
      if (import.meta.env.DEV) { // 12-F M1: Copy exists in debug builds only (a second desktop joiner; Universal Clipboard would carry the offer)
        const text = pairOffer.offer;
        const copy = el("button", "secondary", "Copy") as HTMLButtonElement;
        const said = el("span", "caption muted", "Copies to the clipboard, which other devices and clipboard managers may keep.");
        copy.onclick = () => {
          navigator.clipboard.writeText(text).then(() => { copy.textContent = "Copied"; }, () => { said.textContent = "The clipboard refused the write."; });
        };
        row.append(copy);
        left.append(said);
      }
    } else if (serving?.offer && serving.offer !== "delivered" && !pairOffer) {
      left.append(el("p", "body muted", "An offer is open, but its text is not on this screen any more. Cancel it and start a new one."));
    } else if (pairPhase === "pushing") {
      left.append(el("p", "body", "Sending your data to the relay first…"));
    } else {
      if (pairPhase === "done") left.append(el("p", "body", "Paired — the other device holds your key. Start a new offer to pair another device."));
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
      { text: "Paired — the device holds your key", state: pairPhase === "done" ? "done" : pairPhase === "released" ? "now" : "idle" },
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
  // bad_params from relay.addresses: a relay list with no serving folder (this Mac is a joiner until one is marked --serve)
  const noServe = addrErr?.code === "bad_params";
  kv.append(el("dt", "", "Kind"), el("dd", "", noRelay ? "none set" : noServe ? "relays set, none serves" : "folder relay"));
  card.append(kv);
  if (noRelay) card.append(el("p", "caption muted", "Set with the command line: disconect sync relay add <folder> --serve"));
  if (noServe) card.append(el("p", "caption muted", "To serve your other devices from this Mac, mark one folder: disconect sync relay add <folder> --serve"));
  if (statusErr) out.append(bannerEl(coreWords(statusErr).lead, coreWords(statusErr).text, true));
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
    card.append(el("p", "caption muted", coreLine(addrErr)));
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
  if (status.relay_kind === "folder" || status.relay_kind === "mixed") { // 19a: the switch exists only with a folder in the list
    const sw = el("label", "switch");
    sw.append(el("span", "", "Sync from the folders on its own"));
    const box = el("input") as HTMLInputElement;
    box.type = "checkbox";
    box.checked = autoSync.on;
    box.onchange = () => { autoSyncSet(box.checked); if (box.checked) autoSyncSchedule(1000); redraw(); };
    sw.append(box);
    stat.append(sw);
    const rule = status.relay_kind === "mixed" ? " A network relay is never polled on its own: Sync now reaches it." : "";
    stat.append(el("p", "caption muted", autoSync.on ? (autoSync.line || `Every 5 minutes while the app is open, and when you come back to it.${rule}`) : "Off. Sync now still works."));
  }
  if (syncRun.running || syncRun.push !== "idle") {
    stat.append(stepsList([
      { text: `Push${syncRun.pushNote ? ` · ${syncRun.pushNote}` : ""}`, state: syncRun.push },
      { text: `Pull${syncRun.pullNote ? ` · ${syncRun.pullNote}` : ""}`, state: syncRun.pull },
    ]));
  }
  if (syncRun.result) stat.append(el("p", "body", syncRun.result));
  out.append(stat);

  // 19d: every relay of the list and what the last sync of this session did on it; read-only (the list is edited with
  // the command line until a folder picker is decided — pitch 19d, shape 6)
  const sites = el("section", "card");
  sites.append(el("h2", "heading", "Relays"));
  if (!status.relays || status.relays.length === 0) {
    sites.append(el("p", "caption muted", "Each relay in the list shows here with what the last sync did on it. Run a sync to see them."));
  } else {
    const kv3 = el("dl", "kv");
    for (const s of status.relays) {
      const parts = [`sent ${s.pushed}`, `healed ${s.healed}`, `received ${s.pulled}`];
      if (s.behind > 0) parts.push(`${s.behind} still to send`);
      if (s.rejected > 0) parts.push(`refused ${s.rejected}`);
      const word = s.error ? (SITE_WORDS[s.error] ?? "Failed") : null;
      const warn = word && s.error !== "not_auto"; // "Clicks only" is the rule for a network relay, not a failure
      kv3.append(el("dt", "", `${s.label || (SITE_KINDS[s.kind] ?? "Relay")} · ${s.id}`), el("dd", warn ? "value-small warn" : "value-small", word ? `${word} · ${parts.join(" · ")}` : parts.join(" · ")));
    }
    sites.append(kv3);
    sites.append(el("p", "caption muted", "Add or remove a relay with the command line: disconect sync relay add <folder or address>, disconect sync relay remove <id>."));
  }
  out.append(sites);

  // design decision 7: no device list, the honest card
  const devices = el("section", "card");
  devices.append(el("h2", "heading", "Devices that hold your key"));
  devices.append(el("p", "body", "Every paired device holds the same key, so this Mac cannot tell them apart and keeps no list."));
  devices.append(el("p", "caption muted", "To shut one device out: rotate the key with the command line (disconect key rotate-recovery), then pair the devices you keep again."));
  out.append(devices);
}

// ---- Trend ------------------------------------------------------------------------------
let trendMetric = "";
let trendDays = 90;

async function screenTrend(out: ParentNode, later: Later): Promise<void> {
  const read = await contractMetrics();
  if (!Array.isArray(read) || !read.length) {
    header(out, "Trends", "");
    out.append(el("p", "caption muted", Array.isArray(read) ? "The core answered with no metrics." : contractFailureWords(read.failure)));
    return; // --trend stays unconsumed until a read succeeds
  }
  const list = read;
  if (trendArg !== null) {
    if (list.some((m) => m.metric === trendArg)) trendMetric = trendArg;
    trendArg = null;
  }
  if (!list.some((m) => m.metric === trendMetric)) trendMetric = list[0]?.metric ?? "";
  const controls = el("div", "row");
  const select = el("select") as HTMLSelectElement;
  for (const { metric: m } of list) {
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
  const picker = el("span", "picker"); // the dot and the metric picker are one unit, so the row's space-between never parts them
  picker.append(hueDot(trendMetric), select);
  controls.append(picker, range);
  out.append(controls);

  // The window ends on the latest day any metric has data, so an archive still draws.
  const today = await core.call<Today>("data.today");
  const lastDay = today.metrics.reduce<string>((acc, m) => (m.value !== null && m.day && m.day > acc ? m.day : acc), "") || today.day;
  // the scopes the contract declares for this metric, the live link last (decision 8: diamonds, never a line)
  const scopes = list.find((m) => m.metric === trendMetric)?.scopes ?? [];
  const results = await Promise.all(scopes.map((scope) => core.call<Metric>("data.metric", { metric: trendMetric, scope, days: trendDays, last_day: lastDay })));
  const series: Series[] = results
    // a declared source joins the legend, the gap band and the caption even when it holds no value in the window;
    // the live link stays out when the window holds no session (a session claims no day)
    .filter((m) => m.scope !== "live" || m.days.some((d) => d.value !== null))
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
  if (!series.some((x) => x.days.some((d) => d.value !== null))) {
    card.append(el("span", "muted body", "No source has values for this metric in the window."));
    return;
  }
  // the band is drawn from the same set the caption counts: hatchedDays is the one definition
  const drawn = series.filter((x) => x.scope !== "live");
  const hatched = hatchedDays(series);
  const plural = (n: number) => `${n} day${n === 1 ? "" : "s"}`;
  const lacks = drawn
    .map((x) => ({ x, n: x.days.filter((d) => d.value === null && !hatched.has(d.day)).length, none: !x.days.some((d) => d.value !== null) }))
    .filter((e) => e.none || e.n > 0)
    .map((e) => e.none ? `The ${scopeWord(e.x.scope)} line has no value in this window.`
      : `The ${scopeWord(e.x.scope)} line lacks ${hatched.size ? `${e.n} more day${e.n === 1 ? "" : "s"}` : plural(e.n)}.`)
    .join(" ");
  const ends = lastDay !== today.day ? ` Window ends ${lastDay}, the latest day with data.` : "";
  const liveNote = series.some((s) => s.scope === "live") ? ` Diamonds: days with a live-link session, the mean of the minutes the link recorded; a session claims no day, so it draws no band.` : "";
  const bandWords = hatched.size
    ? `Hatched bands: ${plural(hatched.size)} no import covered any source. No line is drawn there; a line never bridges a gap.`
    : "Every day in the window was covered by an import of at least one source.";
  const valued = drawn.filter((x) => x.days.some((d) => d.value !== null));
  // no drawn line has a value: the live link alone holds this window, so the band sentence does not apply
  const lead = !valued.length
    ? `Only live-link sessions have values for this metric in the window.${lacks ? ` ${lacks}` : ""}`
    : bandWords + (lacks ? ` ${lacks}` : "");
  card.append(el("span", "caption muted", lead + liveNote + ends));
  later(() => {
    drawTrend(chart, series, trendLabel(trendMetric));
    if (debugTipDay) { const day = debugTipDay; debugTipDay = null; setTimeout(() => showTipOn(day), 800); }
  });
}

// ---- Sleep (Bet 7b-4) -------------------------------------------------------------------
type SleepStage = { stage: string; start_utc: string; end_utc: string; minutes: number; start_local?: string; end_local?: string };
type SleepSession = {
  source_scope: string; start_utc?: string; end_utc?: string; overall_score?: number; retro: boolean;
  stage_minutes: Record<string, number>; stages?: SleepStage[]; utc_offset_s?: number;
  avg_hr?: number; avg_spo2?: number; avg_respiration?: number; awakenings_count?: number;
};
type Night = { date: string | null; sessions: SleepSession[]; reason?: string };
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
/** The sources the Sleep screen sets side by side: the `sleep_duration` entry's non-live scopes in the contract. */
let sleepScopes: string[] = [];
const STAGE_ROWS = ["awake", "rem", "light", "deep"];
const STAGE_WORD: Record<string, string> = { awake: "Awake", rem: "REM", light: "Light", deep: "Deep", unmeasurable: "Not measured" };
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const SVG_NS = "http://www.w3.org/2000/svg";

/** The core's lowercase reasons start a sentence on screen. */
function sentence(t: string | undefined | null): string | null {
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : null;
}

function sleepMinutes(m: number): string {
  const n = Math.round(m);
  return n >= 60 ? `${Math.floor(n / 60)} h ${String(n % 60).padStart(2, "0")} min` : `${n} min`;
}

/** One daily figure of a night: the sleep length (`sleep_duration`, in MINUTES) or the sleep score. */
type DailyFigure = { metric: "sleep_duration" | "sleep_score"; value: number };
/** A day's daily sleep figure per source: the scope's own metric (device: sleep length in minutes; vendor cloud: sleep
 *  score) when it has one, else the other metric stored for that scope. */
type DailySleep = { device?: DailyFigure; vendor_cloud?: DailyFigure };
const OWN_METRIC: Record<string, DailyFigure["metric"]> = { device: "sleep_duration", vendor_cloud: "sleep_score" };

/** The days of a month (`YYYY-MM`) on which any source has a night (sleep duration from the device, sleep score from the
 *  vendor cloud), each with the daily figure that marks it. */
async function sleepMarks(month: string): Promise<Map<string, DailySleep>> {
  const [y, m] = month.split("-").map(Number);
  const days = new Date(Date.UTC(y, m, 0)).getUTCDate();
  const last = `${month}-${String(days).padStart(2, "0")}`;
  const pairs = sleepScopes.flatMap((scope) => (["sleep_duration", "sleep_score"] as const).map((metric) => ({ metric, scope })));
  const reads = await Promise.all(pairs.map(({ metric, scope }) =>
    core.call<Metric>("data.metric", { metric, scope, days, last_day: last }).catch(() => null)));
  const marked = new Map<string, DailySleep>();
  reads.forEach((r, i) => {
    const { metric, scope } = pairs[i];
    for (const d of r?.days ?? []) {
      if (d.value === null) continue;
      const have = marked.get(d.day) ?? {};
      const now = have[scope as keyof DailySleep];
      // the scope's own metric wins; the other one only fills an empty place
      if (!now || (metric === OWN_METRIC[scope] && now.metric !== metric)) have[scope as keyof DailySleep] = { metric, value: d.value };
      marked.set(d.day, have);
    }
  });
  return marked;
}

/** The month calendar: Monday first, a dot on the nights that have data, the chosen night accented; a night without
 *  data is drawn and not selectable. Moving a month re-reads the marks only. */
function sleepCalendar(chosen: string | null, firstMonth: string, firstMarks: Map<string, DailySleep>): HTMLElement {
  const box = el("section", "card");
  box.setAttribute("aria-label", "Nights");
  let month = firstMonth;
  let marks = firstMarks;
  let ticket = 0;
  const draw = (): void => {
    const [y, m] = month.split("-").map(Number);
    const head = el("div", "row");
    const prev = el("button", "secondary", "‹") as HTMLButtonElement;
    prev.setAttribute("aria-label", "Previous month");
    const next = el("button", "secondary", "›") as HTMLButtonElement;
    next.setAttribute("aria-label", "Next month");
    const step = (by: number): void => {
      const [py, pm] = month.split("-").map(Number); // the pending month, not the drawn one: two quick clicks move two months
      const d = new Date(Date.UTC(py, pm - 1 + by, 1));
      month = d.toISOString().slice(0, 7);
      const mine = ++ticket;
      void sleepMarks(month).then((got) => { if (mine === ticket) { marks = got; draw(); } });
    };
    prev.onclick = () => step(-1);
    next.onclick = () => step(1);
    head.append(prev, el("h2", "heading", `${MONTHS[m - 1]} ${y}`), next);
    const grid = el("div", "calendar");
    for (const w of WEEKDAYS) grid.append(el("span", "caption muted", w));
    const lead = (new Date(Date.UTC(y, m - 1, 1)).getUTCDay() + 6) % 7;
    for (let i = 0; i < lead; i++) grid.append(el("span"));
    const days = new Date(Date.UTC(y, m, 0)).getUTCDate();
    for (let d = 1; d <= days; d++) {
      const day = `${month}-${String(d).padStart(2, "0")}`;
      const has = marks.has(day);
      const cell = has ? el("button", "cell has", String(d)) : el("span", "cell off", String(d));
      if (has) {
        const target = day;
        cell.setAttribute("aria-label", `Night of ${day}`);
        (cell as HTMLButtonElement).onclick = () => { location.hash = `#/sleep/${target}`; };
        cell.append(el("span", "pip"));
      }
      if (day === chosen) cell.setAttribute("aria-current", "date");
      grid.append(cell);
    }
    box.replaceChildren(head, grid, el("span", "caption muted", "A dot marks a night with data; the others cannot be opened."));
  };
  draw();
  return box;
}

function svgEl(tag: string, attrs: Record<string, string>): SVGElement {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

/** A local `HH:MM` of an instant on the watch's clock (offset in seconds; 0 for UTC). */
function hhmm(ms: number, offsetS: number): string {
  return new Date(ms + offsetS * 1000).toISOString().slice(11, 16);
}

/** The hypnogram: stage bands placed by their UTC instants plus the session's offset, so a stage that crosses local
 *  midnight stays one contiguous bar; ticks are labelled with local HH:MM. Without a stored offset the axis is UTC
 *  and says so. Unmeasurable is a full-height hatched band. */
function hypnogram(session: SleepSession): HTMLElement {
  const stages = (session.stages ?? []).map((s) => ({ ...s, a: Date.parse(s.start_utc), b: Date.parse(s.end_utc) })).filter((s) => s.b > s.a);
  const box = el("div", "hypno");
  if (!stages.length) return box;
  const t0 = Math.min(...stages.map((s) => s.a));
  const t1 = Math.max(...stages.map((s) => s.b));
  const known = typeof session.utc_offset_s === "number";
  const off = known ? (session.utc_offset_s as number) : 0;
  const W = 960, X0 = 64, X1 = 944, ROW = 32, TOP = 8, H = TOP + ROW * 4 + 28;
  const x = (t: number): number => X0 + ((t - t0) / (t1 - t0)) * (X1 - X0);
  // the hover text of a segment: the core's own local stage times; UTC (and said so) while no offset is stored
  const segTitle = (s: SleepStage & { a: number; b: number }): SVGElement => {
    const t = svgEl("title", {});
    t.textContent = known
      ? `${STAGE_WORD[s.stage] ?? s.stage} ${s.start_local ?? hhmm(s.a, off)}\u2013${s.end_local ?? hhmm(s.b, off)}`
      : `${STAGE_WORD[s.stage] ?? s.stage} ${hhmm(s.a, 0)}\u2013${hhmm(s.b, 0)} UTC`;
    return t;
  };
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Sleep stages through the night" });
  const defs = svgEl("defs", {});
  const pat = svgEl("pattern", { id: `hypno-unmeasurable-${session.source_scope}`, patternUnits: "userSpaceOnUse", width: "6", height: "6", patternTransform: "rotate(45)" });
  pat.append(svgEl("line", { x1: "0", y1: "0", x2: "0", y2: "6", class: "hatch" }));
  defs.append(pat);
  svg.append(defs);
  STAGE_ROWS.forEach((name, i) => {
    const y = TOP + i * ROW;
    svg.append(svgEl("line", { x1: String(X0), x2: String(X1), y1: String(y + ROW), y2: String(y + ROW), class: "grid" }));
    const label = svgEl("text", { x: String(X0 - 8), y: String(y + ROW / 2 + 4), "text-anchor": "end", class: "tick" });
    label.textContent = STAGE_WORD[name];
    svg.append(label);
  });
  for (const s of stages) {
    const x0 = x(s.a), w = Math.max(1, x(s.b) - x0);
    if (s.stage === "unmeasurable") {
      const hatched = svgEl("rect", { x: String(x0), y: String(TOP), width: String(w), height: String(ROW * 4), fill: `url(#hypno-unmeasurable-${session.source_scope})`, class: "unmeasurable" });
      hatched.append(segTitle(s));
      svg.append(hatched);
      continue;
    }
    const row = STAGE_ROWS.indexOf(s.stage);
    if (row < 0) continue; // a stage word this screen does not know is not drawn
    const bar = svgEl("rect", { x: String(x0), y: String(TOP + row * ROW + 4), width: String(w), height: String(ROW - 8), class: `stage-${s.stage}` });
    bar.append(segTitle(s));
    svg.append(bar);
  }
  const hour = 3600000;
  const span = (t1 - t0) / hour;
  const stride = Math.max(1, Math.ceil(span / 8)) * hour;
  const ticks: number[] = [];
  for (let t = Math.ceil((t0 + off * 1000) / stride) * stride - off * 1000; t <= t1; t += stride) ticks.push(t);
  if (!ticks.length) ticks.push(t0, t1); // no whole hour inside a short night: label its two ends
  ticks.forEach((t, i) => {
    const edge = i === ticks.length - 1 && X1 - x(t) < 24; // the last label never runs past the viewBox
    const tx = svgEl("text", { x: String(x(t)), y: String(TOP + ROW * 4 + 18), "text-anchor": edge ? "end" : "middle", class: "tick" });
    tx.textContent = hhmm(t, off);
    svg.append(tx);
  });
  box.append(svg);
  return box;
}

async function screenSleep(out: ParentNode, later: Later, sub: string | undefined): Promise<void> {
  const health = await core.call<Health>("data.health", { window_days: 7 }).catch(() => null);
  header(out, "Sleep", ""); // the subtitle is the night the core answers with, set below
  if (PHONE && health?.never_imported) {
    out.append(phoneEmptyBanner());
    return;
  }
  if (health?.never_imported) {
    const nothing = bannerEl("Nothing imported yet", "Drop an export zip or a copied watch folder on the Import screen. Every screen fills from the first import.");
    nothing.append(importLink());
    out.append(nothing);
    return;
  }
  const read = await contractMetrics();
  if (!Array.isArray(read)) {
    out.append(el("p", "caption muted", contractFailureWords(read.failure)));
    return;
  }
  if (!read.some((m) => m.metric === "sleep_duration")) {
    out.append(el("p", "caption muted", "The core answered with no metrics."));
    return;
  }
  sleepScopes = read.find((m) => m.metric === "sleep_duration")?.scopes.filter((sc) => sc !== "live") ?? [];
  const notANight = (): void => {
    out.append(bannerEl("Not a night", "A night is written as a date, like 2025-06-15. Pick one in the calendar."));
  };
  if (sub !== undefined && !DAY_RE.test(sub)) {
    notANight();
    sub = undefined;
  }
  let night: Night;
  try {
    night = await core.call<Night>("data.sleep", sub ? { date: sub } : {});
  } catch (e) {
    // a date that is shaped right but not on the calendar (2025-02-30): the core says bad_params; show the latest night
    if (!(sub && core.isCoreError(e) && e.code === "bad_params")) throw e;
    notANight();
    night = await core.call<Night>("data.sleep", {});
  }
  const date = night.date;
  const month = (date ?? new Date().toISOString().slice(0, 10)).slice(0, 7);
  const marks = await sleepMarks(month);
  if (date && night.sessions.length && !marks.has(date)) marks.set(date, {});
  out.append(sleepCalendar(date, month, marks));
  if (!date) {
    out.append(el("span", "caption muted", sentence(night.reason) ?? "No sleep is stored yet."));
    return;
  }
  const head = out.querySelector(".row .caption");
  if (head) head.textContent = date;

  const two = el("div", "two");
  for (const scope of sleepScopes) {
    const s = night.sessions.find((x) => x.source_scope === scope);
    if (!s) {
      const box = el("div", "absent");
      const daily = date ? marks.get(date)?.[scope as keyof DailySleep] : undefined;
      box.append(el("span", "body", `No record of this night from ${scopeWord(scope)}`));
      if (daily) {
        // the day is marked by a daily figure alone (a summary without a session): say what is stored
        const own = daily.metric === OWN_METRIC[scope];
        box.append(el("span", "caption muted", daily.metric === "sleep_duration"
          ? `${own ? "Sleep length for the day" : "Only a sleep length is stored for the day"}: ${sleepMinutes(daily.value)}.`
          : `${own ? "Sleep score for the day" : "Only a sleep score is stored for the day"}: ${Math.round(daily.value)}.`));
      }
      two.append(box);
      continue;
    }
    const card = el("section", "card");
    card.setAttribute("aria-label", scopeWord(scope));
    const top = el("div", "row");
    top.append(scopeTag(scope));
    if (s.retro) top.append(el("span", "badge", "added later"));
    card.append(top, el("span", "caption muted", "Sleep score"));
    card.append(el("span", "value", typeof s.overall_score === "number" ? String(s.overall_score) : "not recorded"));
    const kv = el("dl", "kv body");
    const row = (k: string, v: string): void => { kv.append(el("dt", "", k), el("dd", "", v)); };
    const span = s.start_utc && s.end_utc ? (Date.parse(s.end_utc) - Date.parse(s.start_utc)) / 60000 : null;
    row("In bed", span !== null && span > 0 ? sleepMinutes(span) : "not recorded");
    const slept = ["deep", "light", "rem"].filter((k) => typeof s.stage_minutes[k] === "number");
    row("Asleep", slept.length ? sleepMinutes(slept.reduce((acc, k) => acc + s.stage_minutes[k], 0)) : "not recorded");
    card.append(kv);
    two.append(card);
  }
  out.append(two);
  if (!night.sessions.length) out.append(el("span", "caption muted", sentence(night.reason) ?? "No record of that night."));
  if (!night.sessions.length) return;
  out.append(el("span", "caption muted", "In bed is the span from start to end. Asleep is the deep, light and REM minutes added up."));

  const drawn = night.sessions.filter((x) => x.stages?.length);
  for (const s of drawn) {
    const card = el("section", "card");
    const top = el("div", "row");
    top.append(el("h2", "heading", "Stages"), scopeTag(s.source_scope));
    card.append(top, hypnogram(s));
    const legend = el("div", "legend caption");
    for (const k of [...STAGE_ROWS, "unmeasurable"]) {
      const item = el("span");
      item.append(el("span", `chip stage-${k}`), document.createTextNode(STAGE_WORD[k]));
      legend.append(item);
    }
    card.append(legend);
    card.append(el("span", "caption muted", typeof s.utc_offset_s === "number"
      ? "Hours are the watch's own clock."
      : "watch clock unknown · UTC"));
    out.append(card);
  }

  const table = el("section", "card");
  table.append(el("h2", "heading", "Stage minutes and overnight"));
  const grid = el("div", "grid3 body");
  grid.append(el("span"), ...sleepScopes.map((sc) => el("span", `caption scope-${sc}`, scopeWord(sc))));
  const line = (label: string, get: (s: SleepSession) => string | null): void => {
    grid.append(el("span", "", label));
    for (const sc of sleepScopes) {
      const s = night.sessions.find((x) => x.source_scope === sc);
      const v = s ? get(s) : null;
      grid.append(el("span", v === null ? "muted" : "value-small", v ?? "not recorded"));
    }
  };
  for (const k of [...STAGE_ROWS, "unmeasurable"]) {
    if (!night.sessions.some((s) => typeof s.stage_minutes[k] === "number")) continue;
    line(STAGE_WORD[k], (s) => (typeof s.stage_minutes[k] === "number" ? sleepMinutes(s.stage_minutes[k]) : null));
  }
  const num = (v: number | undefined, unit: string): string | null => (typeof v === "number" ? fmt(v, unit) : null);
  line("Average heart rate", (s) => num(s.avg_hr, "bpm"));
  line("Average oxygen", (s) => num(s.avg_spo2, "%"));
  if (night.sessions.some((s) => typeof s.avg_respiration === "number")) line("Average breathing", (s) => num(s.avg_respiration, "breaths/min"));
  if (night.sessions.some((s) => typeof s.awakenings_count === "number")) line("Awakenings", (s) => (typeof s.awakenings_count === "number" ? String(s.awakenings_count) : null));
  table.append(grid);
  out.append(table);

  const hrv = await core.call<Metric>("data.metric", { metric: "hrv_rmssd", scope: "device", days: 30, last_day: date }).catch(() => null);
  const last = await core.call<Metric>("data.metric", { metric: "hrv_last_night_average", scope: "device", days: 1, last_day: date }).catch(() => null);
  const card = el("section", "card");
  card.append(el("h2", "heading", metricLabel("hrv_last_night_average")));
  const tonight = last?.days.find((d) => d.day === date)?.value ?? null;
  card.append(el("span", "value", tonight === null ? "not recorded" : fmt(tonight, "ms")));
  out.append(card);
  if (hrv && hrv.days.some((d) => d.value !== null)) {
    const chart = el("div", "chart short");
    card.append(chart, el("span", "caption muted", `The line is ${metricLabel("hrv_rmssd")}, the 30 days ending ${date}, the ${scopeWord("device")} source; it never bridges a gap.`));
    later(() => drawTrend(chart, [{ scope: hrv.scope, unit: hrv.unit, days: hrv.days }], metricLabel("hrv_rmssd")));
  } else {
    card.append(el("span", "caption muted", "No HRV readings in these 30 days."));
  }
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
  /** The Cancel button was pressed and the core said "cancelling": the file being read finishes, then the run ends. */
  cancelling: boolean;
};
const importUi: ImportUi = { running: false, kind: null, done: 0, total: null, note: "", seen: false, error: null, notice: null, extra: 0, cancelling: false };
let debugImportCancel = false; // --debug-import-cancel (evidence runs, debug builds): the running card's Cancel is clicked a moment after the import starts
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
  if (importUi.cancelling) return importUi.done > 0 ? `Stopping after this file · ${importUi.done} read` : "Stopping · nothing read yet";
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
      importUi.cancelling = false;
      if (debugImportCancel) setTimeout(() => (document.getElementById("import-cancel") as HTMLButtonElement | null)?.click(), 700);
    }
  } else if (p.state === "done" || (p.state === "failed" && p.code === "cancelled")) {
    // `cancelled`: the Cancel button's own ending; the run row below says what was kept
    importUi.running = false;
    importUi.kind = null;
    importUi.error = null;
    importUi.extra = 0;
    importUi.cancelling = false;
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
    const cancel = el("button", "secondary", "Cancel");
    cancel.id = "import-cancel";
    cancel.disabled = importUi.cancelling;
    cancel.onclick = () => void importCancel();
    card.append(cancel);
    fill.style.width = importUi.total ? `${Math.min(100, Math.round((importUi.done / importUi.total) * 100))}%` : "0%";
  } else {
    card.append(el("p", "body", hint));
  }
  return card;
}

/** The running card's Cancel: the core stops after the file it is reading (`import.cancel`); a `not_found` means it
 * already ended, which the import event is about to say. */
async function importCancel(): Promise<void> {
  try {
    await core.call("import.cancel");
  } catch (e) {
    if (!(core.isCoreError(e) && e.code === "not_found")) {
      // a notice, not the outcome: the import keeps running (review N6)
      importUi.notice = core.isCoreError(e) ? e.message : String(e);
      importRedraw();
    }
    return;
  }
  if (!importUi.running) return; // the end event overtook the reply (review N6): nothing to mark
  importUi.cancelling = true;
  const button = document.getElementById("import-cancel") as HTMLButtonElement | null;
  if (button) button.disabled = true;
  importPaint();
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
  if (run.status === "running" || run.status === "interrupted") {
    // the newest run never ended and nothing of ours runs now: `interrupted` = a later write open noticed the dead
    // writer; `running` = not noticed yet, or a command-line import running beside the app (7b-10)
    const when = run.started_at ? new Date(run.started_at).toLocaleString() : "unknown time";
    return bannerEl("Interrupted", `${when} · this import stopped before it ended · drop it again, files already held are skipped`, true);
  }
  if (run.status === "cancelled") {
    const when = run.started_at ? new Date(run.started_at).toLocaleString() : "unknown time";
    const read = run.files_seen === 0 ? "stopped before the first file" : `stopped after ${run.files_seen} file${run.files_seen === 1 ? "" : "s"}`;
    const failed = run.files_failed > 0 ? ` · ${run.files_failed} failed` : "";
    return bannerEl("Cancelled", `${when} · ${read}${failed} · what was read is kept · drop it again to finish, files already held are skipped`);
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
      const cancelledRun = run.status === "cancelled"; // before `withFailures`: a cancelled run with failed files says so (review N5)
      const withFailures = !failedRun && !cancelledRun && run.files_failed > 0;
      if (cancelledRun && run.files_failed > 0) {
        const a = el("a", "caption", "cancelled, with failures");
        a.setAttribute("href", "#/health");
        grid.append(a);
      } else if (failedRun || withFailures) {
        const a = el("a", "caption", failedRun ? "failed" : "done with failures");
        a.setAttribute("href", "#/health");
        grid.append(a);
      } else {
        const word = run.status === "interrupted" ? "interrupted"
          : run.status === "cancelled" ? "cancelled"
          : run.status === "running" ? (i === 0 && importUi.running ? "running" : "interrupted")
          : "done";
        grid.append(el("span", "caption", word));
      }
    }
    recent.append(grid);
  }
  out.append(recent);
}

// ---- Data health ------------------------------------------------------------------------
let healthDays = 90;
let scrollDebug = 0; // evidence runs: `--scroll <px>` scrolls every drawn screen so a shot shows its lower part

function bannerEl(lead: string, text: string, error = false): HTMLElement {
  const b = el("section", error ? "banner body error" : "banner body");
  b.append(el("span", "lead", lead), el("span", "", text));
  return b;
}

/** A core refusal in words: a lead and a sentence. The machine word (`busy`, `not_found`) and the core's own
 *  sentence never reach the page; the lint pins it. */
const CORE_WORDS: Record<string, { lead: string; text: string }> = {
  busy: { lead: "Another task is running", text: "An import, a sync, a pull or a pairing is using this store, or a key change is not finished. Try again when it ends." },
  locked: { lead: "The store is locked", text: "Unlock it with your passphrase, then try again." },
  not_found: { lead: "Nothing there yet", text: "What this screen asked for does not exist yet." },
  bad_params: { lead: "That could not be used", text: "The request was not in a shape the core accepts. Close and reopen the app." },
  core_unavailable: { lead: "The core is not running", text: "Quit and reopen the app." },
  pair_failed: { lead: "Pairing did not finish", text: "Cancel on the other device and start a new offer." },
  relay_unreachable: { lead: "The relay is not reachable", text: "Check that the relay is available from this device, then try again." },
  relay_auth_failed: { lead: SYNC_LEADS.relay_auth_failed, text: SYNC_WORDS.relay_auth_failed },
  relay_unverified: { lead: SYNC_LEADS.relay_unverified, text: SYNC_WORDS.relay_unverified },
  wrong_passphrase: { lead: "Wrong passphrase", text: "That passphrase does not open this database." },
};
const CORE_WORDS_OTHER = { lead: "That did not work", text: "Try again. If it keeps failing, close and reopen the app." };
function coreWords(e: unknown): { lead: string; text: string } {
  return (core.isCoreError(e) ? CORE_WORDS[e.code] : undefined) ?? CORE_WORDS_OTHER;
}
/** One line for a caption or an inline note. */
function coreLine(e: unknown): string {
  const w = coreWords(e);
  return `${w.lead}. ${w.text}`;
}
const NO_RELAY = { lead: "No relay set up yet", text: "Pairing hands the key over through a relay, and this store has none. The Relay section on Sync shows the command that sets one; run it once, then come back." };

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

/** Whole days from a to b (both YYYY-MM-DD), by UTC midnights so a clock change never skews the count. */
function dayDiff(a: string, b: string): number {
  return Math.round((Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / 86400000);
}

/** A ledger row's bar in time order: [status, days] segments from the window's first day to its last, the gap runs
 * as the core names them and `present` between them. Null when the core kept only the newest gaps (the older ones
 * are unknown) or the days do not add up to the window; the bar then runs in status order. */
function timeOrderSegments(r: LedgerRow, window: { from: string; to: string; days: number }): [string, number][] | null {
  if (r.gaps_truncated) return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(window.from) || !/^\d{4}-\d{2}-\d{2}$/.test(window.to)) return null;
  const segs: [string, number][] = [];
  let cursor = window.from;
  for (const g of r.gaps) {
    if (!g.from || !g.to || !g.status || g.from < cursor) return null;
    if (g.from > cursor) segs.push(["present", dayDiff(cursor, g.from)]);
    segs.push([g.status, dayDiff(g.from, g.to) + 1]);
    cursor = new Date(Date.parse(`${g.to}T00:00:00Z`) + 86400000).toISOString().slice(0, 10);
  }
  if (cursor <= window.to) segs.push(["present", dayDiff(cursor, window.to) + 1]);
  return segs.reduce((n, [, d]) => n + d, 0) === window.days ? segs : null;
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
  if (PHONE && health.never_imported) {
    out.append(phoneEmptyBanner());
    return;
  }
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
  const ordered: boolean[] = []; // per row: true when its bar runs in time order
  for (const r of rows) {
    const block = el("div");
    const top = el("div", "row body");
    const name = el("span");
    name.append(hueDot(r.metric), document.createTextNode(`${metricLabel(r.metric)} `), scopeTag(r.source_scope));
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
    const segs = timeOrderSegments(r, cov.window);
    ordered.push(segs !== null);
    for (const [k, n] of segs ?? (["present", "failed", "source_empty", "not_covered"] as const).map((k) => [k, r[k] as number] as const)) {
      if (!n) continue;
      const seg = el("span", `seg ${k}`);
      seg.style.flexGrow = String(n);
      seg.style.minWidth = "3px"; // one failed day out of 1825 must still be visible
      bar.append(seg);
    }
    block.append(bar);
    if (segs === null && !r.gaps_truncated) block.append(el("div", "caption muted", "status order"));
    const lastGap = r.gaps[r.gaps.length - 1];
    if (r.source_scope === "vendor_cloud" && lastGap && lastGap.status === "not_covered" && lastGap.to === cov.window.to && lastGap.from) {
      // the import ends where the trailing not-covered run begins
      block.append(el("div", "caption muted", lastGap.from === cov.window.from ? "no export day in this window" : `the export ends ${new Date(Date.parse(`${lastGap.from}T00:00:00Z`) - 86400000).toISOString().slice(0, 10)}`));
    }
    const span = (x: LedgerRow["gaps"][number]) => (x.from && x.to ? (x.from === x.to ? x.from : `${x.from} → ${x.to}`) : JSON.stringify(x));
    const failedGaps = r.gaps.filter((x) => x.status === "failed");
    const otherGaps = r.gaps.filter((x) => x.status !== "failed");
    if (otherGaps.length) block.append(el("div", "caption muted", `gaps: ${otherGaps.map(span).join(", ")}${r.gaps_truncated ? " (newest gaps shown)" : ""}`));
    if (r.gaps_truncated && !otherGaps.length) block.append(el("div", "caption muted", "newest gaps shown"));
    if (failedGaps.length) block.append(el("div", "caption status-failed", `failed: ${failedGaps.map(span).join(", ")}`));
    if (r.source_scope === "live") block.append(el("div", "caption muted", "session days only"));
    card.append(block);
  }
  const order = ordered.every((o) => o) ? "Bars run in time order."
    : ordered.some((o) => o) ? "Bars run in time order except the rows marked 'newest gaps shown' or 'status order', which run in status order."
      : "Bars run in status order, not time order.";
  card.append(el("span", "caption muted", `Counts are days out of ${cov.window.days}. ${order} "present" can still be a partial day. A sparse metric is recorded only on some days, so its empty days are normal.`));
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
        err.textContent = core.isCoreError(e) && e.code === "wrong_passphrase" ? "That passphrase does not open this database." : coreLine(e);
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
      note.textContent = coreLine(e);
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
  about.append(el("span", "muted wrap", `database ${info.db}`)); // a long path wraps (it ran past the edge at 390)
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

// ---- The phone's own screens (12-F shape C; built into every bundle, reached only when `PHONE`) ------------------
// Copy is drawn through neutralText like the coach's text (no maker's name, plain score words). No screen here shows a
// raw core code or the core's own message: a failure is one fixed sentence that says what to do.
const PHONE_READ_FAIL = "Close and reopen the app. If this stays, your copy on the Mac is untouched.";
const PHONE_SYNC_NOTE = "This phone talks only to your Mac, and only while both are on the same network. Nothing goes to any other server, and nothing is sent in the background.";

function pbanner(lead: string, text: string, error = false): HTMLElement {
  return bannerEl(neutralText(lead), neutralText(text), error);
}
function ptext<K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text: string): HTMLElementTagNameMap[K] {
  return el(tag, cls, neutralText(text));
}
function pcard(label: string): HTMLElement {
  const card = el("section", "card");
  card.setAttribute("aria-label", label);
  return card;
}
function psteps(items: { text: string; state: Step }[]): HTMLElement {
  const ol = el("ol", "steps");
  items.forEach((it, i) => {
    const li = el("li", it.state === "idle" ? "" : it.state);
    if (it.state === "now") li.setAttribute("aria-current", "step");
    li.append(el("span", "n", String(i + 1)), ptext("span", "", it.text));
    ol.append(li);
  });
  return ol;
}

/** Paired, but no pull has filled the store (PhoneEmpty). */
function phoneEmptyBanner(): HTMLElement {
  const b = pbanner("Nothing pulled yet", "This phone is paired, but its first pull did not finish. Pull from your Mac on the same network.");
  const actions = el("div", "actions");
  const go = el("a", "button", "Go to Sync") as HTMLAnchorElement;
  go.href = "#/sync";
  actions.append(go);
  b.append(actions);
  return b;
}

// ---- The phone's pairing screens (12-F row 4): Start, Scan, Code, Confirm, Landing, Done and the errors -----------------
// The core does the joining (`pair.join`, `pair.land`); this is its face. Rules from ADR 0011 (v2): the code is shown only
// while the Code screen is up and on no error; after a failure past the POST the screen says to cancel on the Mac and
// start a new offer; nothing here rescans or re-keys by itself; the scanner stops at its first decode. The offer text and
// the six digits live in this module's memory for as long as their screen needs them: never stored, never in a URL,
// never passed to console.*.
const OFFER_PREFIX = "disconect-pair:v2.";
type PairErrorKind = "expired" | "clock" | "paired" | "closed" | "ended" | "saved" | "other";
type PairView =
  | { v: "start" }
  | { v: "paste" } // debug builds only
  | { v: "scan"; note: string }
  | { v: "joining"; host: string | null; exp: number | null; reached: boolean }
  | { v: "code"; code: string; host: string | null; exp: number | null }
  | { v: "confirm"; host: string | null }
  | { v: "stopping" }
  | { v: "landing"; done: string[] }
  | { v: "done"; applied: number; fresh: number; rejected: number; partial: boolean; protectedKey: boolean | null }
  | { v: "error"; kind: PairErrorKind; lead: string; text: string; exp: number | null };
let pp: PairView = { v: "start" };
let scanRun = 0; // a scan whose number is not the current one has been cancelled; its late answer is dropped
let joinHost: string | null = null; // the host and expiry of the offer being joined, for the later screens (display only)
let joinExp: number | null = null;
let joinCodeShown = false; // an end after the code was shown reads as "closed by your Mac"; before it, as "already ended"
let answerBusy = false;
let declinedByUi = false; // the UI itself sent pair.land false (a No tap): only then is "Not paired" the user's own choice
let debugPairYes = false; // --debug-pair-yes / --debug-pair-no / --debug-pair-cancel (evidence runs, debug builds)
let debugPairNo = false;
let debugPairCancel = false;
let debugPairOpen = false;
let debugPairReload: "code" | "confirm" | "landing" | null = null;
/** Evidence run (12-F row 4, attack M3), debug builds only: reload the webview once, a moment after the named screen shows. */
function debugReloadOnce(at: "code" | "confirm" | "landing"): void {
  if (import.meta.env.DEV) {
    if (debugPairReload !== at) return;
    try {
      if (sessionStorage.getItem("debug-reloaded")) return;
      sessionStorage.setItem("debug-reloaded", "1");
    } catch { return; }
    setTimeout(() => location.reload(), at === "landing" ? 0 : 2000);
  }
}

/** Move to another pairing screen. The screen stays awake exactly while the code is up, so every way out of the Code
 *  screen (confirm, cancel, error, reload at start-up) goes through here and switches it off. */
function setPair(next: PairView): void {
  const wasCode = pp.v === "code";
  pp = next;
  if (wasCode !== (next.v === "code")) void phone.keepAwake(next.v === "code").catch(() => undefined);
  document.documentElement.classList.toggle("scanning", next.v === "scan");
  void route();
}

/** `host` and `exp` of an offer text, for display only (the core parses and checks it for real). */
function readOffer(text: string): { host: string; exp: number } | null {
  if (!text.startsWith(OFFER_PREFIX)) return null;
  try {
    const b64 = text.slice(OFFER_PREFIX.length).replace(/-/g, "+").replace(/_/g, "/");
    const body = JSON.parse(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4))) as { url?: unknown; exp?: unknown };
    if (typeof body.url !== "string" || typeof body.exp !== "number") return null;
    return { host: new URL(body.url).hostname.replace(/^\[|\]$/g, ""), exp: body.exp };
  } catch {
    return null;
  }
}
function clockTime(unix: number): string {
  const d = new Date(unix * 1000);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** The pairing screens' routing: Start for a phone that was never paired, and any later step while one is under way. */
function pairingActive(): boolean {
  return PHONE && pp.v !== "start";
}

function pairError(kind: PairErrorKind, lead: string, text: string, exp: number | null = null): void {
  joinHost = null;
  setPair({ v: "error", kind, lead, text, exp });
}

/** A failed `pair.join` / `pair.land` as one frame: the core's fixed message, and the action that fits. */
function pairFailure(e: unknown): void {
  const exp = joinExp;
  if (!core.isCoreError(e)) {
    pairError("other", "Pairing did not finish", "Pairing stopped. Cancel on your Mac and start a new offer.");
    return;
  }
  const m = e.message;
  if (e.code === "pair_failed") {
    if (m.startsWith("This offer expired")) {
      pairError("expired", "Time ran out", m, exp);
    } else if (m.startsWith("This offer is too far ahead")) {
      pairError("clock", "This phone's clock is off", m, exp);
    } else if (m.startsWith("This phone is already paired")) {
      pairError("paired", "This phone is already paired", "It already holds a copy of your data. To pair it again, forget this phone in Settings first; that deletes its copy, and your Mac keeps everything.");
    } else if (m.startsWith("Your Mac closed this offer")) {
      if (joinCodeShown) pairError("closed", "Pairing stopped", m);
      else pairError("ended", "This offer has already ended", m);
    } else if (m.startsWith("The key was saved")) {
      pairError("saved", "Paired, but the first pull did not finish", m);
    } else if (m.startsWith("Cancelled.")) {
      pairError("other", "Pairing stopped", m);
    } else if (m.startsWith("Not paired.")) {
      // always after the release (the Mac's Cancel is disabled by then): never ask for a Cancel there; the phone's own words
      pairError("other", declinedByUi ? "You chose not to pair" : "Pairing stopped", "Nothing was saved on this phone. Your Mac may say Paired; it keeps no record of this phone. Start a new offer on your Mac to pair.");
    } else {
      pairError("other", "Pairing did not finish", m);
    }
    return;
  }
  // a refusal that is not a pair_failed (bad_params, busy, unsupported...): the core's fixed sentence, never an address
  if (e.code === "busy") pairError("other", "Pairing did not start", "Another pairing, sync or pull is running on this phone. Wait for it to finish, then start again.");
  else if (e.code === "locked") pairError("other", "Pairing did not start", "This phone is locked. Unlock it, then start again.");
  else if (["bad_params", "not_found", "unsupported_transport"].includes(e.code)) pairError("other", "Pairing did not start", "This phone could not start pairing with that offer. Scan the code on your Mac again.");
  else pairError("other", "Pairing did not finish", "Pairing stopped. Cancel on your Mac and start a new offer.");
}

/** Start the join with an offer text (from the scan, or Paste in a debug build). The text goes to the core and no further. */
async function phoneJoin(text: string): Promise<void> {
  const shown = readOffer(text.trim());
  joinHost = shown?.host ?? null;
  joinExp = shown?.exp ?? null;
  joinCodeShown = false;
  declinedByUi = false;
  setPair({ v: "joining", host: joinHost, exp: joinExp, reached: false });
  try {
    const r = await core.call<{ pull: { applied: number; records_new: number; rejected: number; status: string }; key_file_protected: boolean | null }>("pair.join", { offer: text });
    joinHost = null;
    // the Mac just paired joins the relay list as "Your Mac" on its own: the shell reads relay.json (no page call)
    setPair({ v: "done", applied: r.pull.applied, fresh: r.pull.records_new, rejected: r.pull.rejected, partial: r.pull.status === "partial", protectedKey: r.key_file_protected });
  } catch (e) {
    pairFailure(e);
  }
}

/** The core's `pair` events and the progress of the landing, for the phone. */
function phonePairEvent(payload: unknown): void {
  const p = payload as { phase?: string; code?: string };
  if (p.phase === "code" && typeof p.code === "string" && (pp.v === "joining" || pp.v === "code")) {
    joinCodeShown = true;
    setPair({ v: "code", code: p.code, host: joinHost, exp: joinExp });
    debugReloadOnce("code");
  } else if (p.phase === "released" && (pp.v === "code" || pp.v === "joining")) {
    setPair({ v: "confirm", host: joinHost });
    debugReloadOnce("confirm");
  }
}
function phonePairProgress(p: { phase?: string; state?: string }): void {
  if (p.state !== "done" || typeof p.phase !== "string") return;
  // the first progress line can arrive a moment before pair.land's own answer: it moves Confirm to Landing too
  if (pp.v === "confirm") { setPair({ v: "landing", done: [p.phase] }); debugReloadOnce("landing"); }
  else if (pp.v === "landing" && !pp.done.includes(p.phase)) setPair({ v: "landing", done: [...pp.done, p.phase] });
}

async function phoneAnswer(yes: boolean): Promise<void> {
  if (answerBusy) return;
  answerBusy = true;
  if (!yes) declinedByUi = true;
  main.querySelectorAll<HTMLButtonElement>("button").forEach((b) => { b.disabled = true; }); // one answer only, while the call runs
  try {
    await core.call("pair.land", { confirm: yes });
    if (yes && pp.v === "confirm") { setPair({ v: "landing", done: [] }); debugReloadOnce("landing"); }
    // a no: the join answers "Not paired. …" and that frame is drawn from its rejection (pairFailure, in the phone's words)
  } catch (e) {
    pairFailure(e);
  } finally {
    answerBusy = false;
  }
}

async function phoneCancel(): Promise<void> {
  if (pp.v === "scan") {
    scanRun++;
    await phone.cancelScan().catch(() => undefined);
    setPair({ v: "start" });
    return;
  }
  setPair({ v: "stopping" }); // the code leaves the screen now, not when the join rejects
  try {
    await core.call("pair.cancel");
    // the join answers "Cancelled. Cancel on your Mac too." and that frame is drawn from its rejection
  } catch (e) {
    if (core.isCoreError(e) && e.code === "busy") { void phoneAnswer(false); return; } // already released: answer the check with no
    pairError("other", "Pairing stopped", "Cancelled. Cancel on your Mac too.");
  }
}

/** The camera: ask once, then scan. A QR that is not an offer scans again; the first offer ends the scanner. */
async function phoneScan(): Promise<void> {
  const mine = ++scanRun;
  setPair({ v: "scan", note: "" });
  const stopped = (): boolean => mine !== scanRun || pp.v !== "scan";
  try {
    if ((await phone.cameraPermission()) !== "granted") {
      if (!stopped()) pairError("other", "The camera is off", "DISCOnect cannot use the camera. Turn it on under Settings, Privacy and Security, Camera, then start again.");
      return;
    }
    while (!stopped()) {
      const text = await phone.scanQr();
      if (stopped()) return;
      if (text.trim().startsWith(OFFER_PREFIX) && readOffer(text.trim())) {
        await phoneJoin(text.trim());
        return;
      }
      setPair({ v: "scan", note: "That code is not a pairing offer from DISCOnect. Point the camera at the code in your Mac's Sync screen." });
    }
  } catch {
    if (!stopped()) pairError("other", "The camera could not start", "This phone could not open the camera. Start again, or check that DISCOnect may use it.");
  }
}

/** Start-up: a page that reloaded while a join was open cannot show its code again, so it ends that join first, and says
 *  only what the core answered: stopped before the release, thrown away after it, or (a landing under way after Yes)
 *  nothing until the landing has ended and the store says which way it went. */
async function phoneEndStrayJoin(): Promise<void> {
  if (!PHONE) return;
  void phone.keepAwake(false).catch(() => undefined);
  void phone.cancelScan().catch(() => undefined); // a reload during a scan must not leave the camera running (no scan: an error, ignored)
  try {
    await core.call("pair.cancel"); // before the Mac released: aborted
    pairError("other", "Pairing stopped", "This screen reloaded, so pairing stopped. Nothing was saved and your Mac sent nothing. Choose Cancel on your Mac.");
    return;
  } catch (e) {
    if (!(core.isCoreError(e) && e.code === "busy")) return; // no join (not_found), or the store is locked: nothing to end
  }
  try {
    await core.call("pair.land", { confirm: false }); // after the release, before an answer: say no
    pairError("other", "Pairing stopped", "This screen reloaded after your Mac sent the key, so this phone threw it away. Nothing was saved. Your Mac may say Done; it keeps no record of this phone. Start a new offer to pair.");
    return;
  } catch (e) {
    if (!(core.isCoreError(e) && e.code === "busy")) return; // the join ended meanwhile
  }
  // both busy: a landing is under way (a Yes was sent before the reload). Claim nothing until it ends.
  setPair({ v: "landing", done: [] });
  // pair.cancel answers busy only while the landing runs; ok, not_found, locked or anything else means it has ended
  // (the core bounds the landing, so there is no cap, and the frame claims nothing until the store says which way it went)
  for (;;) {
    await new Promise((r) => setTimeout(r, 750));
    try { await core.call("pair.cancel"); break; } catch (e) { if (!(core.isCoreError(e) && e.code === "busy")) break; }
  }
  await refreshKey();
  if (unpaired()) pairError("other", "Pairing stopped", "Pairing did not finish. Start a new offer on your Mac.");
  else setPair({ v: "start" }); // paired: the app's own routing shows Unlock or Today
}

function stackOf(...nodes: HTMLElement[]): HTMLElement {
  const s = el("div", "stack");
  s.append(...nodes);
  return s;
}
function pbutton(text: string, cls: string, go: () => void): HTMLButtonElement {
  const b = el("button", cls, neutralText(text)) as HTMLButtonElement;
  b.onclick = go;
  return b;
}

const PAIR_STEPS = ["Offer scanned", "Mac checked", "Type the code into your Mac", "Key received, first pull"];
function pairSteps(now: number): HTMLElement {
  const ol = psteps(PAIR_STEPS.map((text, i) => ({ text, state: i < now ? "done" : i === now ? "now" : "idle" }) as { text: string; state: Step }));
  ol.setAttribute("aria-label", "Steps");
  return ol;
}

/** Pair Start (a phone with no store and no key file), and every later pairing screen. */
function screenPairStart(out: ParentNode): void {
  switch (pp.v) {
    case "scan": return drawPairScan(out, pp.note);
    case "joining": return drawPairJoining(out, pp);
    case "code": return drawPairCode(out, pp);
    case "confirm": return drawPairConfirm(out, pp);
    case "stopping": return drawPairStopping(out);
    case "landing": return drawPairLanding(out, pp.done);
    case "done": return drawPairDone(out, pp);
    case "error": return drawPairError(out, pp);
    case "paste": if (drawPairPaste) drawPairPaste(out); return;
    default: break;
  }
  header(out, "Pair with your Mac", "This phone keeps a copy of your data and pulls what is new from your Mac.");
  const how = pcard("How pairing works");
  how.append(psteps([
    { text: "On your Mac, open Sync and choose Pair a device.", state: "now" },
    { text: "Scan the code your Mac shows.", state: "idle" },
    { text: "Type the six digits this phone shows into your Mac.", state: "idle" },
  ]));
  out.append(how);
  const buttons = [pbutton("Scan the code", "wide", () => void phoneScan())];
  if (import.meta.env.DEV) buttons.push(pbutton("Paste the offer text", "secondary wide", () => setPair({ v: "paste" })));
  out.append(stackOf(...buttons));
  out.append(ptext("p", "caption muted", "Pairing gives this phone your key. DISCOnect then asks for two permissions: the camera, to scan the code, and the local network, to reach your Mac. It reaches nothing else."));
}

function drawPairScan(out: ParentNode, note: string): void {
  const top = el("div", "scan-top");
  header(top, "Scan the code", "Point the camera at the code in your Mac's Sync screen.");
  out.append(top);
  const camera = el("div", "camera");
  camera.setAttribute("role", "img");
  camera.setAttribute("aria-label", "Camera view");
  camera.append(el("div", "finder"));
  out.append(camera);
  const bottom = el("div", "scan-bottom");
  if (note) bottom.append(ptext("p", "body", note));
  bottom.append(pbutton("Cancel", "secondary wide", () => void phoneCancel()));
  out.append(bottom);
}

function drawPairStopping(out: ParentNode): void {
  header(out, "Stopping…", "");
  const b = pbanner("Stopping pairing", "Nothing is saved on this phone.");
  b.setAttribute("role", "status");
  out.append(b);
}

function drawPairJoining(out: ParentNode, s: { host: string | null; exp: number | null }): void {
  header(out, "Pairing with your Mac", "Keep this screen open.");
  const b = pbanner("Reaching your Mac…", s.exp ? `The offer is open until ${clockTime(s.exp)} by this phone's clock.` : "Your Mac's offer is open for 15 minutes.");
  b.setAttribute("role", "status");
  out.append(b);
  out.append(ptext("p", "caption muted", "The first time, iOS asks whether DISCOnect may find devices on your local network. Choose Allow."));
  const slow = ptext("p", "caption muted", "Still trying. If it doesn't connect, allow DISCOnect under Settings, Privacy and Security, Local Network.");
  slow.hidden = true;
  out.append(slow);
  setTimeout(() => { if (slow.isConnected && pp.v === "joining") slow.hidden = false; }, 15000);
  out.append(stackOf(pbutton("Cancel", "secondary wide", () => void phoneCancel())));
}

function drawPairCode(out: ParentNode, s: { code: string; exp: number | null }): void {
  header(out, "Type this code into your Mac", "This phone checked that it is talking to the Mac that made the offer.");
  const card = pcard("Pairing code");
  card.append(ptext("p", "caption muted center", "Code on this phone"));
  const big = el("span", "bigcode", `${s.code.slice(0, 3)} ${s.code.slice(3)}`);
  big.setAttribute("role", "img");
  big.setAttribute("aria-label", `Code ${s.code.split("").join(" ")}`);
  card.append(big);
  card.append(ptext("p", "caption muted center", "Your Mac sends your key only when these digits match. If they are typed wrong, the offer closes and nothing is sent."));
  out.append(card);
  const wait = pbanner("Waiting for your Mac…", s.exp ? `The offer is open until ${clockTime(s.exp)} by this phone's clock.` : "The offer is open for 15 minutes.");
  wait.setAttribute("role", "status");
  wait.setAttribute("aria-live", "polite");
  out.append(wait);
  out.append(pairSteps(2));
  out.append(stackOf(pbutton("Cancel", "secondary wide", () => void phoneCancel())));
  if (import.meta.env.DEV && debugPairCancel) setTimeout(() => Array.from(document.querySelectorAll("button")).find((b) => b.textContent === "Cancel")?.click(), 6000);
}

function drawPairConfirm(out: ParentNode, s: { host: string | null }): void {
  header(out, "Check your Mac", "Answer after you typed the digits into your Mac.");
  const card = pcard("Confirm");
  card.append(ptext("p", "body", `Did your Mac say Paired? This phone will trust the Mac at ${s.host ?? "the address in the offer"}.`));
  card.append(ptext("p", "caption muted", "Answer Yes only if your Mac showed Paired just now. If it did not, answer No: nothing is saved."));
  out.append(card);
  const yes = pbutton("Yes", "wide", () => void phoneAnswer(true));
  yes.setAttribute("aria-label", "Yes, my Mac said Paired");
  const no = pbutton("No", "secondary wide", () => void phoneAnswer(false));
  no.setAttribute("aria-label", "No, it did not");
  out.append(stackOf(yes, no));
  const heading = (out as HTMLElement).querySelector("h1");
  if (heading) { heading.tabIndex = -1; setTimeout(() => heading.focus(), 50); } // VoiceOver lands on the question
  if (import.meta.env.DEV && (debugPairYes || debugPairNo)) {
    setTimeout(() => Array.from(document.querySelectorAll("button")).find((b) => b.textContent === (debugPairYes ? "Yes" : "No"))?.click(), 2500);
  }
}

function drawPairLanding(out: ParentNode, done: string[]): void {
  header(out, "Saving your key", "Keep this screen open.");
  const names: [string, string][] = [["relay_file", "Your Mac's address saved"], ["key_file", "Key saved on this phone"], ["store", "Copy of your data created"], ["pull", "First pull finished"]];
  const first = names.findIndex(([phase]) => !done.includes(phase));
  const ol = psteps(names.map(([phase, text], i) => ({ text, state: done.includes(phase) ? "done" : i === first ? "now" : "idle" }) as { text: string; state: Step }));
  ol.setAttribute("aria-label", "Steps");
  const card = pcard("Saving");
  card.append(ol);
  out.append(card);
}

function drawPairDone(out: ParentNode, s: { applied: number; fresh: number; rejected: number; partial: boolean; protectedKey: boolean | null }): void {
  header(out, "Pairing done", "This phone now holds your key and a copy of your data.");
  const steps = pairSteps(4);
  out.append(steps);
  const card = pcard("First pull");
  card.append(el("h2", "heading", "First pull"));
  const kv = el("dl", "kv");
  for (const [label, n] of [["Bundles pulled", s.applied], ["New records", s.fresh], ["Refused", s.rejected]] as [string, number][]) {
    const dd = el("dd", "value-small", String(n));
    kv.append(el("dt", "", label), dd);
  }
  card.append(kv);
  if (s.partial) card.append(ptext("p", "caption muted", "Not all of it has come yet. Open Sync and choose Pull now to get the rest."));
  out.append(card);
  if (s.protectedKey === false) out.append(ptext("p", "caption muted", "This phone could not lock the key file to its passcode protection."));
  out.append(ptext("p", "caption muted", "Next time DISCOnect opens, it asks for your passphrase: the one your Mac uses. You can keep the key in this phone's keychain from Settings."));
  out.append(stackOf(pbutton("Open Today", "wide", () => { setPair({ v: "start" }); location.hash = "#/today"; })));
  if (import.meta.env.DEV && debugPairOpen) setTimeout(() => Array.from(document.querySelectorAll("button")).find((b) => b.textContent === "Open Today")?.click(), 5000);
}

function drawPairError(out: ParentNode, s: { kind: PairErrorKind; lead: string; text: string; exp: number | null }): void {
  header(out, "Pair with your Mac", "");
  // a landing that failed after the relay setting was written leaves a phone with no key file that is "already paired"
  const partial = s.kind === "paired" && unpaired();
  const b = partial
    ? pbanner("This phone holds part of an earlier pairing", "Forget it to start again; your Mac keeps everything.", true)
    : pbanner(s.lead, s.text, true);
  b.setAttribute("role", "alert");
  out.append(b);
  if (s.kind === "expired" && s.exp) out.append(ptext("p", "caption muted", `Offers last 15 minutes. This one ended at ${clockTime(s.exp)} by this phone's clock. Start a new one on your Mac.`));
  if (s.kind === "closed") out.append(ptext("p", "caption muted", "Nothing was sent to this phone. The digits typed on the Mac may not have matched, the offer may have been cancelled there, or another device answered."));
  if (s.kind === "ended") out.append(ptext("p", "caption muted", "Each offer pairs one device, once. Start a new offer on your Mac."));
  const actions: HTMLElement[] = [];
  if (partial) {
    actions.push(forgetButton());
  } else if (s.kind === "paired") {
    actions.push(pbutton("Go to Settings", "secondary wide", () => { setPair({ v: "start" }); location.hash = "#/settings"; }));
  } else if (s.kind === "saved") {
    actions.push(pbutton("Open Sync", "wide", () => { setPair({ v: "start" }); location.hash = "#/sync"; }));
  } else if (s.kind === "expired" || s.kind === "clock" || s.kind === "closed" || s.kind === "ended") {
    actions.push(pbutton("Scan a new code", "wide", () => void phoneScan()));
  } else {
    actions.push(pbutton("Start again", "wide", () => setPair({ v: "start" })));
  }
  out.append(stackOf(...actions));
}

/** Paste the offer text: a debug build's stand-in for the camera (and the simulator's only way in). A release build
 *  has no such function: `import.meta.env.DEV` is false there and the whole expression is dropped. */
const drawPairPaste: ((out: ParentNode) => void) | null = import.meta.env.DEV
  ? (out) => {
      header(out, "Paste the offer text", "Debug builds only: the simulator has no camera.");
      const card = pcard("Offer text");
      const area = el("textarea", "") as HTMLTextAreaElement;
      area.rows = 5;
      area.setAttribute("aria-label", "Offer text");
      area.setAttribute("autocomplete", "off");
      area.setAttribute("spellcheck", "false");
      card.append(area);
      out.append(card);
      const join = pbutton("Join", "wide", () => { const t = area.value; area.value = ""; void phoneJoin(t); });
      out.append(stackOf(join, pbutton("Cancel", "secondary wide", () => setPair({ v: "start" }))));
    }
  : null;

// Forget this phone: the confirmation sheet and its result. The core's `pair.forget` deletes the copy, the key file, the
// keychain entry and the relay setting, in an order that a crash cannot leave half done. The count of records not yet
// sent comes from `sync.status` (`records_unsent`) and is read before the confirmation.
let forgetSheet: HTMLElement | null = null;
let forgetOpener: HTMLElement | null = null;
function closeForgetSheet(): void {
  if (!forgetSheet) return;
  forgetSheet.remove();
  forgetSheet = null;
  document.querySelectorAll(".sheet-shade").forEach((n) => n.remove());
  main.inert = false;
  topbar.inert = false;
  forgetOpener?.focus();
}
const FORGET_REVOKE = "Forgetting does not shut this phone out of your account. Only a key rotation on your Mac does that.";

/** The sentence that says how many records this phone holds that your Mac may not have, and why that number is what it is. */
async function forgetUnsentLine(): Promise<string> {
  if (locked()) return "This phone is locked, so it cannot count what has not been sent. Unlock it first if you want the count; forgetting works either way.";
  try {
    const status = await core.call<{ records_unsent: number }>("sync.status");
    const n = status.records_unsent;
    if (n > 0) return `${n} ${n === 1 ? "record" : "records"} on this phone ${n === 1 ? "has" : "have"} not been sent to your Mac. ${n === 1 ? "It is" : "They are"} lost if you forget this phone.`;
    return "0 records on this phone are waiting to be sent. This phone only copies what it pulled from your Mac, so your Mac already has all of it.";
  } catch (e) {
    if (core.isCoreError(e) && e.code === "not_found") return "0 records on this phone are waiting to be sent: nothing has been pulled onto it yet.";
    return "This phone could not count what has not been sent. Your Mac keeps everything it already has.";
  }
}

function forgetResultSheet(sheet: HTMLElement, answer: { keychain: string }): void {
  sheet.replaceChildren();
  const title = ptext("h2", "heading", "This phone is forgotten");
  title.id = "forget-title";
  sheet.append(title);
  sheet.append(ptext("p", "body", "This phone's copy of your data, its key file and its relay setting are deleted. Your Mac keeps everything. Pair again to use this phone again."));
  if (answer.keychain === "removed") sheet.append(ptext("p", "body", "Its keychain entry was removed too."));
  else if (answer.keychain === "none") sheet.append(ptext("p", "body", "It had no keychain entry."));
  else sheet.append(el("p", "caption error", neutralText("The keychain entry could not be removed. This phone tries again the next time the app starts.")));
  sheet.append(ptext("p", "caption muted", FORGET_REVOKE));
  const actions = el("div", "actions");
  const done = el("button", "", "Done") as HTMLButtonElement;
  done.onclick = () => { forgetOpener = null; closeForgetSheet(); pp = { v: "start" }; location.hash = "#/today"; void route(); };
  actions.append(done);
  sheet.append(actions);
  // the shade and Escape end the result the same way Done does: back to the app, which is now Pair Start
  const shade = document.querySelector<HTMLElement>(".sheet-shade");
  if (shade) shade.onclick = done.onclick;
  sheet.onkeydown = (e) => { if (e.key === "Escape") { e.preventDefault(); done.click(); } };
  done.focus();
}

function openForgetSheet(opener: HTMLElement): void {
  closeForgetSheet();
  forgetOpener = opener;
  const shade = el("div", "sheet-shade");
  const sheet = el("section", "card sheet");
  sheet.setAttribute("role", "dialog");
  sheet.setAttribute("aria-modal", "true");
  sheet.setAttribute("aria-labelledby", "forget-title");
  const title = ptext("h2", "heading", "Forget this phone?");
  title.id = "forget-title";
  sheet.append(title);
  sheet.append(ptext("p", "body", "This deletes this phone's copy of your data, its key file, its keychain entry and its relay setting. Your Mac keeps everything. Pair again to use this phone again."));
  const unsent = ptext("p", "body", "Counting what has not been sent…");
  unsent.setAttribute("aria-live", "polite");
  sheet.append(unsent);
  sheet.append(ptext("p", "caption muted", FORGET_REVOKE));
  const problem = el("p", "caption error");
  problem.setAttribute("role", "alert");
  sheet.append(problem);
  const actions = el("div", "actions");
  const cancel = el("button", "secondary", "Cancel") as HTMLButtonElement;
  const forget = el("button", "danger", "Forget this phone") as HTMLButtonElement;
  forget.disabled = true; // until the count is in: the confirmation always shows it first
  cancel.onclick = closeForgetSheet;
  shade.onclick = () => { if (!cancel.disabled) closeForgetSheet(); };
  sheet.onkeydown = (e) => { if (e.key === "Escape" && !cancel.disabled) { e.preventDefault(); closeForgetSheet(); } };
  forget.onclick = async () => {
    forget.disabled = true; cancel.disabled = true; problem.textContent = "";
    try {
      const answer = await core.call<{ forgotten: boolean; keychain: string }>("pair.forget");
      forgetResultSheet(sheet, answer);
    } catch (e) {
      const busy = core.isCoreError(e) && e.code === "busy";
      problem.textContent = neutralText(busy
        ? "A pull is running. Wait for it to finish, then try again."
        : "This phone could not finish forgetting. Close and reopen the app: it finishes the job when it starts.");
      forget.disabled = false; cancel.disabled = false;
    }
  };
  actions.append(cancel, forget);
  sheet.append(actions);
  document.body.append(shade, sheet);
  forgetSheet = sheet;
  main.inert = true;
  topbar.inert = true;
  cancel.focus();
  void forgetUnsentLine().then((line) => {
    if (forgetSheet !== sheet) return;
    unsent.textContent = neutralText(line);
    forget.disabled = false;
  });
}
/** The sheet is two siblings of the page in the body; leaving a screen takes both away. */
window.addEventListener("hashchange", closeForgetSheet);

/** The "Forget this phone…" entry (Unlock and Settings): a danger button that opens the sheet. */
function forgetButton(): HTMLButtonElement {
  const b = el("button", "danger wide", "Forget this phone…") as HTMLButtonElement;
  b.onclick = () => openForgetSheet(b);
  return b;
}

function screenPhoneUnlock(out: ParentNode): void {
  header(out, "Unlock", "Your data on this phone is encrypted. Enter your passphrase to open it.");
  const card = pcard("Unlock");
  const form = el("form", "field");
  const label = el("label", "caption muted", "Passphrase") as HTMLLabelElement;
  label.htmlFor = "pp";
  const input = el("input", "wide") as HTMLInputElement;
  input.id = "pp";
  input.type = "password"; input.autocomplete = "current-password";
  const err = el("span", "caption error");
  err.id = "pp-err";
  err.setAttribute("role", "alert");
  const go = el("button", "wide", "Unlock") as HTMLButtonElement;
  go.type = "submit";
  form.append(label, input, err, go);
  const keep = el("label", "switch") as HTMLLabelElement;
  keep.append(el("span", "", "Keep the key in this phone's keychain"));
  const box = el("input") as HTMLInputElement;
  box.type = "checkbox"; box.setAttribute("role", "switch"); box.setAttribute("aria-describedby", "kc-cap");
  keep.append(box);
  const cap = ptext("span", "caption muted", "Off by default. When on, DISCOnect opens without the passphrase whenever this phone itself is unlocked. The key stays on this phone; it is never moved to another phone, not even by a backup.");
  cap.id = "kc-cap";
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    go.disabled = true; err.textContent = ""; input.classList.remove("invalid"); input.removeAttribute("aria-invalid");
    try {
      await core.unlock(input.value);
      input.value = "";
      if (box.checked) await core.call("key.cache", { enable: true }).catch(() => undefined); // the switch is on Settings too
      location.hash = "#/today";
      await route();
    } catch (e) {
      const wrong = core.isCoreError(e) && e.code === "wrong_passphrase";
      err.textContent = neutralText(wrong ? "That passphrase does not open this database." : "This phone could not open its data. Try again.");
      if (wrong) { input.classList.add("invalid"); input.setAttribute("aria-invalid", "true"); input.setAttribute("aria-describedby", "pp-err"); }
    } finally {
      go.disabled = false;
    }
  };
  card.append(form, keep, cap);
  out.append(card);
  out.append(ptext("p", "caption muted", "The passphrase is the one your Mac used when this phone was paired."));
  // recovery happens on the Mac: the phone never shows the recovery words or the command that uses them
  out.append(ptext("p", "caption muted", "Lost it? Recover it on your Mac, not here. Then forget this phone and pair it again."));
  const actions = el("div", "actions");
  actions.append(forgetButton());
  out.append(actions);
  setTimeout(() => input.focus(), 0);
}

// Appearance: the palettes tokens.css has. "Match the system" is the default (pastel, following the system's side).
const PHONE_THEMES: { id: string; word: string; theme: string | null }[] = [
  { id: "system", word: "Match the system", theme: null },
  { id: "light", word: "Light", theme: "light" },
  { id: "dark", word: "Dark", theme: "dark" },
  { id: "classic-light", word: "Classic light", theme: "classic-light" },
  { id: "classic-dark", word: "Classic dark", theme: "classic-dark" },
];
const THEME_STORE = "disconect.theme"; // a per-viewer convenience in the webview's own storage; the page works without it
function applyTheme(theme: string | null): void {
  if (theme) document.documentElement.dataset.theme = theme; else delete document.documentElement.dataset.theme;
}
function savedTheme(): string | null {
  try {
    const t = localStorage.getItem(THEME_STORE);
    return PHONE_THEMES.some((p) => p.theme === t) ? t : null;
  } catch { return null; }
}
function saveTheme(theme: string | null): void {
  try { if (theme) localStorage.setItem(THEME_STORE, theme); else localStorage.removeItem(THEME_STORE); } catch { /* storage is optional */ }
}

// ---- The phone's relay list (19d, I5 row 4): the Relays card on Settings. The shell owns the list (`phone.ts`); the page
// draws what it is told in words and never names a path. Each row says what the last sync did there, from the core's
// per-site answer the shell keeps. The core's own words (`unavailable`, `same_relay`, `behind`) are mapped here, never drawn.
const RELAY_REFUSALS: Record<string, string> = {
  own_folder: "That is the folder this app keeps its own data in. Pick another one.",
  already_listed: "That relay is already in the list.",
  bad_address: "That is not an address like http://192.168.1.20:24816. Give the Mac's IP address and its port.",
  address_name: "Use the Mac's IP address, like http://192.168.1.20:24816, not a name.",
  not_local: "That address is not on a private or local network. Use the Mac's address on your home network.",
  busy: "Another relay change is running. Try again in a moment.",
  not_found: "That relay is no longer in the list.",
  unavailable: "The Files picker could not open. Try again.",
};
function relayRefusal(e: unknown): string {
  return neutralText((core.isCoreError(e) ? RELAY_REFUSALS[e.code] : undefined) ?? "That did not work. Try again.");
}
function relayClock(secs: number): string {
  const d = new Date(secs * 1000);
  const time = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  return d.toDateString() === new Date().toDateString() ? time : `${d.toLocaleDateString("en-GB", { day: "numeric", month: "short" })} ${time}`;
}
// What the core says went wrong at one relay (its site words), in this phone's sentences. Nothing else is ever drawn:
// a word not listed reads as a plain failure. `unavailable` and `same_relay` are compared in relayState, not mapped here.
const PHONE_SITE_WORDS: Record<string, string> = {
  unreachable: "Not answering",
  refused: "Refused: check the date and time on both devices",
  unverified: "Not verified: it may not be the relay this phone paired with",
  too_large: "A file was too large to store there",
  bad_name: "A file had a name this relay does not take",
  missing: "Folder not found",
  no_permission: "No permission to use it",
  io_error: "Reading or writing failed",
  bad_url: "That address does not work",
  unsupported_transport: "This kind of relay is not supported on this phone",
};
/** The state line of one relay, from what the shell keeps of the core's last answer for it. */
function relayState(r: phone.RelayEntry): string {
  if (!r.available || r.site?.error === "unavailable") return "Unavailable";
  if (r.site?.error === "same_relay") return "Same as another relay";
  const times: string[] = [];
  if (r.last_push_at) times.push(`Last push ${relayClock(r.last_push_at)}`);
  if (r.last_pull_at) times.push(`${times.length ? "last" : "Last"} pull ${relayClock(r.last_pull_at)}`);
  if (r.site?.error) return [PHONE_SITE_WORDS[r.site.error] ?? "Failed at the last sync", ...times].join(" · ");
  const notes: string[] = [];
  const healed = r.site?.healed ?? 0;
  if (healed > 0) notes.push(healed === 1 ? "Restored 1 file it had lost" : `Restored ${healed} files it had lost`);
  const behind = r.site?.behind ?? 0;
  if (behind > 0) notes.push(`Behind by ${behind}`);
  const parts = [...notes, ...times];
  if (parts.length) return parts.join(" · ");
  return r.site ? "Synced, nothing new" : "Never synced";
}
/** A site that failed is drawn as a warning (a mark; the words carry the meaning). */
function relayFailed(r: phone.RelayEntry): boolean {
  return !r.available || !!r.site?.error;
}

async function relaysCard(out: ParentNode): Promise<void> {
  const card = pcard("Relays");
  card.append(el("h2", "heading", "Relays"));
  card.append(ptext("p", "caption muted", "Where this phone keeps copies of what it sends and fetches. Every sync uses every relay here that can be reached. Pick a folder in the Files app, on this phone or in a cloud service that shows there, or add your Mac."));
  const note = el("p", "caption error");
  note.setAttribute("role", "alert");
  const redraw = (): void => { void route(); };
  const attempt = async (job: () => Promise<unknown>): Promise<void> => {
    note.textContent = "";
    try { await job(); redraw(); } catch (e) { note.textContent = relayRefusal(e); }
  };
  let list: { relays: phone.RelayEntry[]; mac_url: string | null; unreadable?: boolean } | null = null;
  try { list = await phone.relaysList(); } catch { list = null; }
  if (!list) {
    card.append(ptext("p", "caption muted", "The relay list could not be read."));
    out.append(card);
    return;
  }
  if (list.unreadable) card.append(ptext("p", "caption error", "The saved relay list could not be read; a copy was kept."));
  if (!list.relays.length) card.append(ptext("p", "body", "No relays yet. Add a folder or your Mac to start."));
  const rows = el("ul", "relays");
  for (const r of list.relays) {
    const row = el("li", "relay");
    const head = el("div", "relay-head");
    head.append(el("span", "relay-name", neutralText(r.label)), el("span", "caption muted", r.kind === "folder" ? "Folder" : "On your network"));
    row.append(head);
    row.append(el("p", "caption muted wrap", neutralText(r.kind === "folder" ? (r.display ?? "Not found") : (r.url ?? ""))));
    const state = relayState(r);
    const stateLine = el("p", relayFailed(r) ? "caption error" : "caption", neutralText(state));
    row.append(stateLine);
    const actions = el("div", "actions");
    const rename = pbutton("Rename", "secondary", () => {
      const field = el("input") as HTMLInputElement;
      field.type = "text"; field.value = r.label; field.maxLength = 60; field.setAttribute("aria-label", `Name for ${r.label}`);
      const save = pbutton("Save", "", () => void attempt(() => phone.relaysRename(r.id, field.value)));
      const cancel = pbutton("Cancel", "secondary", () => { actions.replaceChildren(rename, remove); });
      actions.replaceChildren(field, save, cancel);
      field.focus();
    });
    const remove = pbutton("Remove", "danger", () => {
      const ask = el("span", "caption", neutralText(`Remove ${r.label}? What is already stored in it stays there.`));
      const yes = pbutton("Remove", "danger", () => void attempt(() => phone.relaysRemove(r.id)));
      const keep = pbutton("Keep", "secondary", () => actions.replaceChildren(rename, remove));
      actions.replaceChildren(ask, yes, keep);
      keep.focus();
    });
    actions.append(rename, remove);
    row.append(actions);
    rows.append(row);
  }
  card.append(rows);
  const adds = el("div", "actions");
  const addFolder = pbutton("Add a folder…", "secondary", () => void attempt(async () => { await phone.relaysAddFolder(); }));
  const addMac = pbutton("Add your Mac", "secondary", () => {
    const url = el("input") as HTMLInputElement;
    url.type = "text"; url.value = list?.mac_url ?? ""; url.placeholder = "http://192.168.1.20:24816"; url.setAttribute("aria-label", "Your Mac's address");
    url.autocapitalize = "off"; url.autocomplete = "off"; url.spellcheck = false;
    const name = el("input") as HTMLInputElement;
    name.type = "text"; name.value = "Your Mac"; name.maxLength = 60; name.setAttribute("aria-label", "Name");
    const save = pbutton("Add", "", () => void attempt(() => phone.relaysAddLan(url.value, name.value)));
    const cancel = pbutton("Cancel", "secondary", () => redraw());
    const form = el("div", "field");
    form.append(url, name, stackOf(save, cancel));
    adds.replaceWith(form);
    url.focus();
  });
  adds.append(addFolder, addMac);
  card.append(adds, note);
  out.append(card);
}

async function screenPhoneSettings(out: ParentNode): Promise<void> {
  const info = await core.call<AppInfo>("app.info");
  header(out, "Settings", "");

  const look = pcard("Appearance");
  look.append(el("h2", "heading", "Appearance"));
  const group = el("div", "field");
  group.setAttribute("role", "radiogroup");
  group.setAttribute("aria-label", "Theme");
  const pinned = document.documentElement.dataset.theme ?? null;
  const now = PHONE_THEMES.find((p) => p.theme === pinned)?.id ?? "system";
  for (const p of PHONE_THEMES) {
    const choice = el("label", "choice") as HTMLLabelElement;
    const radio = el("input") as HTMLInputElement;
    radio.type = "radio"; radio.name = "theme"; radio.checked = p.id === now;
    radio.onchange = () => { applyTheme(p.theme); saveTheme(p.theme); };
    choice.append(radio, el("span", "", p.word));
    group.append(choice);
  }
  look.append(group);
  out.append(look);

  const key = pcard("Your key");
  key.append(el("h2", "heading", "Your key"));
  const kv = el("dl", "kv");
  const store = !keyStatus ? "not read" : !keyStatus.encrypted ? "no store yet" : `encrypted · ${keyStatus.unlocked ? "unlocked" : "locked"}`;
  const kept = keyStatus?.keychain === "cached" ? "kept" : keyStatus?.keychain === "stale" ? "needs renewing" : "not kept";
  kv.append(el("dt", "", "Store"), el("dd", "", store), el("dt", "", "Keychain"), el("dd", "", kept));
  key.append(kv);
  const keep = el("label", "switch") as HTMLLabelElement;
  keep.append(el("span", "", "Keep the key in this phone's keychain"));
  const box = el("input") as HTMLInputElement;
  box.type = "checkbox"; box.setAttribute("role", "switch"); box.setAttribute("aria-describedby", "kc2");
  box.checked = keyStatus?.keychain === "cached";
  box.disabled = !keyStatus?.encrypted || !keyStatus.unlocked;
  const note = el("span", "caption error");
  note.setAttribute("role", "alert");
  box.onchange = async () => {
    note.textContent = "";
    try {
      const r = await core.call<{ keychain: KeyStatus["keychain"] }>("key.cache", { enable: box.checked });
      box.checked = r.keychain === "cached";
      await refreshKey(); renderNav();
      void route();
    } catch {
      box.checked = !box.checked;
      note.textContent = neutralText("The keychain did not accept that. Try again.");
    }
  };
  keep.append(box);
  key.append(keep, note);
  if (keyStatus?.keychain === "stale") key.append(ptext("p", "caption", "A key saved by an earlier build of this app is in the keychain. Turn the switch on to replace it with one this build can read."));
  const cap = ptext("span", "caption muted", "Off by default. When on, DISCOnect opens without the passphrase whenever this phone itself is unlocked. The key is never moved to another phone, not even by a backup.");
  cap.id = "kc2";
  key.append(cap);
  out.append(key);

  await relaysCard(out);

  const mine = pcard("This phone");
  mine.append(el("h2", "heading", "This phone"));
  mine.append(ptext("p", "body", "Forgetting deletes this phone's copy of your data, its key file and its keychain entry. Your Mac keeps everything. Pair again to use this phone again."));
  mine.append(forgetButton());
  out.append(mine);

  const about = pcard("About");
  about.append(el("h2", "heading", "About"));
  const kv2 = el("dl", "kv");
  const core2 = el("dd", "mono caption wrap", info.core.replace("/", " ")); // the core already says "(in-process)"
  kv2.append(el("dt", "", "Product"), el("dd", "", productWords.product), el("dt", "", "Core"), core2);
  about.append(kv2);
  out.append(about);
}

// ---- The phone's Sync ----
const phonePull = { running: false, failure: null as { lead: string; text: string } | null, result: "", sent: null as number | null };

/** The three things a pull can say that a person can act on, in plain words; anything else is one fixed sentence. */
function phoneSyncFailure(e: unknown): { lead: string; text: string } {
  const c = core.isCoreError(e) ? e : null;
  if (c?.code === "relay_auth_failed") {
    return { lead: "Your Mac refused this phone", text: "The date and time on this phone and on your Mac do not agree. Check both, then pull again." };
  }
  if (c?.code === "relay_unverified") {
    return {
      lead: "This may not be your Mac",
      text: "The answer could not be verified: it may come from another Mac, your Mac may have been set up again with a new key, or the network may have altered it. This phone never pairs again by itself. If your Mac was set up again, forget this phone in Settings and pair it again from your Mac.",
    };
  }
  if (c?.code === "not_found" && /unreachable/i.test(c.message)) {
    return { lead: "Your Mac is not reachable", text: "Open DISCOnect on your Mac with \"Serve the relay on this network\" on, join the same network with this phone, then pull again." };
  }
  return { lead: "The pull did not finish", text: "Pull again. If it keeps failing, close and reopen the app." };
}

/** "From this phone" (19b): what this phone recorded itself and what it has sent. Counts and times only. */
function phoneProduced(status: SyncStatus | null, p: phone.Produced | null): HTMLElement {
  const card = pcard("From this phone");
  card.append(el("h2", "heading", neutralText("From this phone")));
  const sessions = p?.sessions ?? 0;
  if (sessions === 0) {
    card.append(ptext("p", "caption muted", "Nothing recorded on this phone yet."));
  }
  const fmt = (secs: number, withDay: boolean): string =>
    new Date(secs * 1000).toLocaleString("en-GB", withDay ? { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
  const span = p?.last_from != null && p.last_to != null ? `${fmt(p.last_from, true)} to ${fmt(p.last_to, false)}` : "none yet";
  const unsent = status?.records_unsent ?? 0;
  const mine = (status?.chains ?? []).find((c) => c.self);
  const sent = phonePull.sent !== null
    ? `${phonePull.sent} ${phonePull.sent === 1 ? "bundle" : "bundles"}`
    : mine ? `${mine.bundles} ${mine.bundles === 1 ? "bundle" : "bundles"} so far` : "not yet this time";
  const rows: [string, string][] = [
    ["Sessions imported", String(sessions)],
    ["Readings held", String(p?.readings ?? 0)],
    ["Last session", span],
    ["Waiting to send", String(unsent)],
    ["Sent", sent],
  ];
  if (mine) rows.push(["Records sent so far", String(mine.records)]);
  const kv = el("dl", "kv");
  for (const [k, v] of rows) kv.append(el("dt", "", k), el("dd", "value-small", neutralText(v)));
  card.append(kv);
  return card;
}

/** Drawn from screenSync (the lint pins every user-started call there); `pull` is its one network call. */
function phoneSync(out: ParentNode, status: SyncStatus | null, statusErr: core.CoreError | null, pull: () => Promise<void>, produced: phone.Produced | null): void {
  header(out, "Sync", "This phone pulls what is new from your Mac, on your network.");
  // no store yet (a key file landed, the first pull has not): the pull below makes it, so only the rows are missing
  if (!status && statusErr?.code !== "not_found") {
    out.append(pbanner("Sync could not be read", PHONE_READ_FAIL, true));
    return;
  }
  const f = phonePull.failure;
  if (f) out.append(pbanner(f.lead, f.text, true));
  const unreachable = f?.lead === "Your Mac is not reachable";
  const mac = pcard("Your Mac");
  const when = status?.last_pulled_at
    ? new Date(status.last_pulled_at).toLocaleString("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })
    : "never";
  const kv = el("dl", "kv");
  // the board's "Your Mac · address" row: the core's `relay_url`; with none, no row
  if (status?.relay_url) kv.append(el("dt", "", "Your Mac"), el("dd", "mono caption wrap", status.relay_url));
  kv.append(el("dt", "", "Last pull"), el("dd", "", when));
  mac.append(kv);
  const go = el("button", "wide", f ? "Pull again" : "Pull now") as HTMLButtonElement;
  go.disabled = phonePull.running;
  go.onclick = () => void pull();
  mac.append(go);
  if (phonePull.running) {
    const live = el("p", "caption muted", "Pulling from your Mac…");
    live.setAttribute("role", "status");
    mac.append(live);
  }
  if (phonePull.result) mac.append(el("p", "body", phonePull.result));
  out.append(mac);
  out.append(phoneProduced(status, produced));
  if (status && !unreachable) {
    const stat = pcard("Status");
    stat.append(el("h2", "heading", "Status"));
    const rows: [string, string][] = [
      ["Bundles pulled", String(status.bundles.pulled_applied ?? 0)],
      ["Bundles refused", String(status.bundles.pulled_rejected ?? 0)],
      ["Records from your Mac", String(status.records_seen)],
      ["Conflicts", String(status.conflicts)],
      ["Chain gaps", status.gaps.length ? String(status.gaps.length) : "none"],
    ];
    const kv2 = el("dl", "kv");
    for (const [k, v] of rows) kv2.append(el("dt", "", k), el("dd", "value-small", v));
    stat.append(kv2);
    out.append(stat);
  } else if (unreachable) {
    out.append(ptext("p", "caption muted", "Everything on this phone is as of the last pull. Nothing is lost while the Mac is away."));
  }
  out.append(ptext("p", "caption muted", PHONE_SYNC_NOTE));
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
window.addEventListener("hashchange", () => {
  if (drawerOpen()) setDrawer(false);
  void route();
});
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => void route());
// 12-F row 5c: the shell dropped the master after five minutes away (`key.lock`, in Rust); draw Unlock, never the old screen
void core.onCoreEvent("locked", () => {
  if (PHONE) main.replaceChildren(); // the old screen's DOM is gone the moment the lock arrives, so a failsafe never reveals data
  void route();
  if (!PHONE) return;
  // the shell holds its cover across the lock: take it off only once the page really shows Unlock (the route may be
  // answered by a newer route, so look at the page, frame by frame; the shell's own failsafe covers a page that never gets there)
  const until = Date.now() + 1400;
  const look = (): void => {
    const unlocked = document.querySelector("main h1, .main h1")?.textContent?.trim() === "Unlock";
    if (unlocked || Date.now() > until) requestAnimationFrame(() => void phone.coverRelease().catch(() => undefined));
    else requestAnimationFrame(look);
  };
  requestAnimationFrame(look);
});
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
  // the product words come from the core (it answers on a locked store); no core, the constants stay
  const info = await core.call<AppInfo>("app.info").catch(() => null);
  if (info && typeof info.product === "string" && info.product.trim() && typeof info.notice === "string" && info.notice.trim()) {
    productWords.product = info.product;
    productWords.notice = info.notice;
    paintIdentity();
  }
  if (locked() && (await core.unlockFromKeychain())) await refreshKey();
  await core.supportSites().then(() => undefined, () => { supportShown = false; });
  const args = await core.launchArgs().catch(() => [] as string[]);
  // evidence runs, debug builds only (Rust drops --debug-* argv in release): unlock from the passphrase file
  if (import.meta.env.DEV && args.includes("--debug-unlock") && locked()) {
    await core.debugUnlockFromFile().then(() => undefined, () => undefined);
    await refreshKey();
  }
  const i = args.indexOf("--screen");
  const arg = args[i + 1] ?? "";
  const night = /^sleep\/\d{4}-\d{2}-\d{2}$/.test(arg); // evidence runs: open one night
  const wanted = i >= 0 && (night || visibleScreens().some((s) => s.id === arg)) ? arg : null;
  const h = args.indexOf("--health-days");
  if (h >= 0 && [90, 365, 1825].includes(Number(args[h + 1]))) healthDays = Number(args[h + 1]);
  const th = args.indexOf("--theme"); // evidence runs and trials: force a palette (pastel follows the system scheme)
  if (th >= 0 && ["pastel", "light", "dark", "pastel-light", "pastel-dark", "classic", "classic-light", "classic-dark"].includes(args[th + 1])) document.documentElement.dataset.theme = args[th + 1];
  else if (PHONE) applyTheme(savedTheme()); // the phone's Appearance choice, when the launch did not force a palette
  const sc = args.indexOf("--scroll"); // evidence runs: scroll the drawn screen
  if (sc >= 0 && /^\d{1,5}$/.test(args[sc + 1] ?? "")) scrollDebug = Number(args[sc + 1]);
  const t = args.indexOf("--trend"); // evidence runs: open Trends on one metric
  if (t >= 0 && args[t + 1]) trendArg = args[t + 1];
  if (import.meta.env.DEV) { // every --debug-* flag is read in dev builds only (the Rust side drops them from release argv too)
    const dl = args.indexOf("--debug-listen");
    const m = dl >= 0 ? /^(.+):(\d{1,5})$/.exec(args[dl + 1] ?? "") : null;
    if (m) debugListen = { ip: m[1].replace(/^\[|\]$/g, ""), port: Number(m[2]) };
    dropOverDebug = args.includes("--debug-drop-over"); // Rust adds it from DISCONECT_DEBUG_DROP_OVER
    debugPairDigits = args.includes("--debug-pair-digits"); // the Rust command is compiled out of release
    const tp = args.indexOf("--debug-tip"); // the Trends tip shown on one day
    if (tp >= 0 && /^\d{4}-\d{2}-\d{2}$/.test(args[tp + 1] ?? "")) debugTipDay = args[tp + 1];
    debugPairYes = args.includes("--debug-pair-yes"); // the Confirm screen answers itself with a real click (12-F row 4 evidence runs)
    debugPairNo = args.includes("--debug-pair-no");
    debugPairOpen = args.includes("--debug-pair-open-today"); // the Done screen's own "Open Today" is clicked once it shows
    if (args.includes("--debug-pair-reload-on-code")) debugPairReload = "code"; // reload the webview once, 2 s after the Code screen shows
    if (args.includes("--debug-pair-reload-on-confirm")) debugPairReload = "confirm";
    if (args.includes("--debug-pair-reload-on-landing")) debugPairReload = "landing"; // right after the Yes is sent (the first pull may be done by then)
    debugPairCancel = args.includes("--debug-pair-cancel"); // the Code screen's own Cancel is clicked a few seconds after it shows
    debugImportCancel = args.includes("--debug-import-cancel"); // the running import card's Cancel is clicked a moment after the import starts
    const as = args.indexOf("--debug-auto-sync-seconds"); // 19a evidence runs: the timer's first run and period in seconds (Rust drops the flag and its operand from release argv)
    if (as >= 0 && /^\d{1,4}$/.test(args[as + 1] ?? "")) { autoSync.first = Number(args[as + 1]) * 1000; autoSync.every = autoSync.first; }
  }
  await phoneEndStrayJoin(); // a reload mid-join ends that join before any screen is drawn (phone only; a no-op elsewhere)
  const target = args.includes("--sync-pair") ? "sync/pair" : wanted;
  if (target && current() !== target) {
    location.hash = `#/${target}`; // hashchange runs route()
  } else {
    await route();
  }
  autoSyncLoad();
  autoSyncSchedule(autoSync.first); // 19a: the desktop's own timer; a no-op on the phone
  if (import.meta.env.DEV) {
    if (PHONE) {
      // evidence runs (the phone's pairing screens): a state drawn with synthetic values, never a real offer or code
      const soon = Math.floor(Date.now() / 1000) + 12 * 60;
      joinExp = soon;
      const frames: [string, PairView][] = [
        ["--debug-pair-scan", { v: "scan", note: "" }],
        ["--debug-pair-code", { v: "code", code: "482917", host: "192.168.1.20", exp: soon }],
        ["--debug-pair-confirm", { v: "confirm", host: "192.168.1.20" }],
        ["--debug-pair-done", { v: "done", applied: 4, fresh: 4812, rejected: 0, partial: false, protectedKey: true }],
        ["--debug-pair-expired", { v: "error", kind: "expired", lead: "Time ran out", text: "This offer expired by this phone's clock. Check the date and time.", exp: soon - 20 * 60 }],
        ["--debug-pair-paired", { v: "error", kind: "paired", lead: "This phone is already paired", text: "It already holds a copy of your data. To pair it again, forget this phone in Settings first; that deletes its copy, and your Mac keeps everything.", exp: null }],
        ["--debug-pair-closed", { v: "error", kind: "closed", lead: "Pairing stopped", text: "Your Mac closed this offer. Cancel on your Mac and start a new offer.", exp: null }],
        ["--debug-pair-ended", { v: "error", kind: "ended", lead: "This offer has already ended", text: "Your Mac closed this offer. Cancel on your Mac and start a new offer.", exp: null }],
        ["--debug-pair-stopping", { v: "stopping" }],
        ["--debug-pair-landing", { v: "landing", done: ["relay"] }],
        ["--debug-pair-joining", { v: "joining", host: "192.168.1.20", exp: soon, reached: false }],
        ["--debug-pair-clock", { v: "error", kind: "clock", lead: "This phone's clock is off", text: "This offer is too far ahead of this phone's clock. Check the date and time on this phone.", exp: soon + 3 * 3600 }],
        ["--debug-pair-notpaired", { v: "error", kind: "other", lead: "Pairing stopped", text: "Nothing was saved on this phone. Your Mac may say Paired; it keeps no record of this phone. Start a new offer on your Mac to pair.", exp: null }],
        ["--debug-pair-failed", { v: "error", kind: "other", lead: "Pairing did not finish", text: "Your Mac refused this request. Cancel on your Mac and start a new offer.", exp: null }],
      ];
      for (const [flag, view] of frames) if (args.includes(flag)) setPair(view);
      // evidence run: the Start screen's own "Scan the code" button, clicked (the real scan route: permission first, then the camera)
      if (args.includes("--debug-pair-start-scan")) setTimeout(() => Array.from(document.querySelectorAll("button")).find((b) => b.textContent === "Scan the code")?.click(), 1500);
      // the simulator's camera: the offer text the host side wrote to a file, joined as if it had been scanned
      let reloaded = false;
      try { reloaded = sessionStorage.getItem("debug-reloaded") === "1"; } catch { /* no storage */ }
      if (args.includes("--debug-pair-offer-file") && pp.v === "start" && unpaired() && !reloaded) {
        void phone.debugOfferFromFile().then((text) => phoneJoin(text), () => undefined);
      }
    }
  }
  if (import.meta.env.DEV) {
    // evidence runs: the drawer drawn open
    if (args.includes("--debug-drawer-open")) setTimeout(() => setDrawer(true), 800);
    // evidence runs (the phone): the Forget sheet drawn open, by a real click on the screen's own button
    if (args.includes("--debug-forget-open") || args.includes("--debug-forget-confirm")) {
      setTimeout(() => Array.from(document.querySelectorAll("button")).find((b) => b.textContent === "Forget this phone…")?.click(), 1500);
    }
    // evidence runs (the phone): then a real click on the sheet's own confirm button, once the count is in
    if (args.includes("--debug-forget-confirm")) {
      setTimeout(() => Array.from(document.querySelectorAll<HTMLButtonElement>("button.danger")).find((b) => b.textContent === "Forget this phone")?.click(), 4500);
      // and a real click on the result's own Done button, which returns the app to Pair Start
      setTimeout(() => Array.from(document.querySelectorAll("button")).find((b) => b.textContent === "Done")?.click(), 9000);
    }
    // evidence runs (the phone): one synthetic live session written into the container and imported natively; the
    // Sync screen is drawn again once the shell has answered
    if (PHONE && args.includes("--debug-live-seed")) {
      setTimeout(() => void phone.liveDebugSeed().then(syncRedraw, syncRedraw), 800);
    }
    // evidence runs: a real click on the Sync screen's own "Sync now" button (the network call
    // still comes from a click, never from the page's own code path)
    if (args.includes("--debug-sync-run")) {
      setTimeout(() => {
        const button = Array.from(document.querySelectorAll("button")).find((b) => b.textContent === "Sync now" || b.textContent === "Pull now");
        button?.click();
      }, 800);
    }
    // evidence runs: a real click on the Sync screen's own "Pair a device" button (the offer and the
    // relay start from a click, as for a person; `--debug-listen` picks the address)
    if (args.includes("--debug-pair-start")) {
      const press = (label: string): void => { Array.from(document.querySelectorAll<HTMLElement>("a.button, button")).find((b) => b.textContent === label)?.click(); };
      setTimeout(() => press("Pair a device"), 1500);
      setTimeout(() => press("Start an offer"), 4000);
    }
  }
})();
