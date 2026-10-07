// ECharts drawing with the design tokens read at paint time (so a theme change re-reads them).
// A missing day is null and connectNulls is off: a line never bridges a gap. Days no source's import
// covered get a hatched band from the status-not-covered token.
import * as echarts from "echarts";
import { scopeWord } from "./identity";
import { fmtValue } from "./format";

export type Series = { scope: string; unit: string | null; days: { day: string; value: number | null; status: string; completeness?: number | null }[] };

/** A day whose mean rests on less than this share of the day (7b-12 `completeness`, 0-100) draws a hollow,
 * faded dot; the value is never withheld. */
export const LOW_COMPLETENESS = 50;

const SCOPE_TOKEN: Record<string, string> = { device: "--device", vendor_cloud: "--vendor-cloud", local: "--local", live: "--live" };

export function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Contiguous runs of hatched days as [first, last] pairs, for markArea; `gap` is the intersection day list. */
export function gapRuns(days: { day: string }[], gap: Set<string>): [string, string][] {
  const runs: [string, string][] = [];
  let start: string | null = null;
  for (let i = 0; i < days.length; i++) {
    const hit = gap.has(days[i].day);
    if (hit && start === null) start = days[i].day;
    if (!hit && start !== null) {
      runs.push([start, days[i - 1].day]);
      start = null;
    }
  }
  if (start !== null) runs.push([start, days[days.length - 1].day]);
  return runs;
}

/** Days hatched: every non-live series has status not_covered on them (a live session claims no day, so with
 * no non-live series the set is empty). drawTrend and the caption both read this. */
export function hatchedDays(series: Series[]): Set<string> {
  const drawn = series.filter((t) => t.scope !== "live");
  if (!drawn.length) return new Set();
  return new Set(drawn[0].days.filter((_d, i) => drawn.every((t) => t.days[i]?.status === "not_covered")).map((d) => d.day));
}

/** Days a run spans, by index in the window's day list. */
export function runDays(days: { day: string }[], a: string, b: string): number {
  return days.findIndex((d) => d.day === b) - days.findIndex((d) => d.day === a) + 1;
}

const GRID = { left: 56, right: 24, top: 24, bottom: 48 };
let active: { chart: echarts.ECharts; observer: ResizeObserver; readout: HTMLElement; days: string[]; latest: number; setReadout: (i: number) => void } | null = null;
/** The day index the tip last stood on (the arrow keys step from it); -1 before any. */
let tipIndex = -1;

/** Dispose the live chart (route() calls this before it replaces the screen, so nothing leaks). */
export function disposeCharts(): void {
  if (!active) return;
  active.observer.disconnect();
  active.readout.remove();
  active.chart.dispose();
  active = null;
  tipIndex = -1;
}

/** Show the tip on one day (the evidence door `--debug-tip`); a day outside the window does nothing. */
export function showTipOn(day: string): void {
  if (!active) return;
  const i = active.days.indexOf(day);
  if (i >= 0) stepTip(i);
}

function stepTip(i: number): void {
  if (!active) return;
  tipIndex = i;
  active.setReadout(i); // the keyboard writes the readout itself, at every width
  // by pixel, not by series point: a day on which the first line has no value has no point to anchor a tip to
  const x = active.chart.convertToPixel({ xAxisIndex: 0 }, active.days[i]);
  if (typeof x === "number") active.chart.dispatchAction({ type: "showTip", x, y: GRID.top + 40 });
}

/** One series' words for one day: "<scope word> <value> <unit>" or "<scope word> no data", then ", <n> % of the day"
 * when the core measured how much of the day the value rests on; a live series with no session that day says
 * nothing (a session claims no day). */
function seriesWords(series: Series[], i: number): string[] {
  const out: string[] = [];
  for (const s of series) {
    const d = s.days[i];
    const v = d?.value ?? null;
    if (v === null && s.scope === "live") continue;
    const share = typeof d?.completeness === "number" && v !== null ? `, ${d.completeness} % of the day` : "";
    out.push(`${scopeWord(s.scope)} ${fmtValue(v, s.unit ?? null)}${share}`);
  }
  return out;
}

/** The dot a non-live day draws: hollow and faded when its mean rests on less than LOW_COMPLETENESS of the day,
 * a full dot when it is isolated (both neighbours missing, so a line would not show it), else none. Hollow is a
 * ring in the scope's colour around the card's own colour: ECharts's "emptyCircle" always fills white, which on
 * the dark themes is a pale disc, not a hollow one. */
function dayPoint(days: Series["days"], i: number, scope: string): number | null | { value: number; symbol: string; symbolSize: number; itemStyle?: { color: string; borderColor: string; borderWidth: number; opacity: number } } {
  const d = days[i];
  if (d.value === null) return null;
  if (typeof d.completeness === "number" && d.completeness < LOW_COMPLETENESS) {
    return { value: d.value, symbol: "circle", symbolSize: 6, itemStyle: { color: token("--surface-raised"), borderColor: token(SCOPE_TOKEN[scope] ?? "--ink"), borderWidth: 2, opacity: 0.45 } };
  }
  if (days[i - 1]?.value == null && days[i + 1]?.value == null) return { value: d.value, symbol: "circle", symbolSize: 5 };
  return d.value;
}

/** A diagonal-hatch canvas in the given colour: ECharts applies decals to series only, so a
 * markArea gets its hatch as a pattern image instead. */
function hatchImage(color: string): HTMLCanvasElement {
  const canvas = document.createElement("canvas");
  canvas.width = 8;
  canvas.height = 8;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, 8);
    ctx.lineTo(8, 0);
    ctx.stroke();
  }
  return canvas;
}

/** A band is labelled only when it is at least this many pixels wide (the words need room). */
const LABEL_MIN_PX = 72;

export function drawTrend(host: HTMLElement, series: Series[], title: string): void {
  disposeCharts();
  host.tabIndex = 0;
  host.setAttribute("role", "group");
  host.setAttribute("aria-roledescription", "chart");
  const days = series[0].days.map((d) => d.day);
  host.setAttribute("aria-label", `${title} trend, ${days.length} days`);
  const readout = document.createElement("div");
  readout.className = "readout";
  readout.setAttribute("aria-live", "polite");
  readout.setAttribute("aria-atomic", "true");
  // one line per non-live series plus the day (a live line is omitted when absent, so it reserves none)
  readout.style.minHeight = `${(series.filter((s) => s.scope !== "live").length + 1) * 1.3}em`;
  host.after(readout);
  const chart = echarts.init(host, undefined, { renderer: "canvas" });
  const setReadout = (i: number) => {
    readout.textContent = [days[i], ...seriesWords(series, i)].join(" · ");
  };
  // before any touch the readout shows the latest day any series has a value on
  let latest = days.length - 1;
  while (latest > 0 && series.every((s) => s.days[latest]?.value == null)) latest--;
  setReadout(latest);
  chart.on("updateAxisPointer", (e: unknown) => {
    const v = (e as { axesInfo?: { value?: unknown }[] }).axesInfo?.[0]?.value;
    const i = typeof v === "number" ? v : typeof v === "string" ? days.indexOf(v) : -1;
    if (i >= 0 && i < days.length) {
      tipIndex = i;
      if (chart.getWidth() <= 720) setReadout(i); // the mouse feeds the readout only where the tip is off
    }
  });
  host.onkeydown = (ev: KeyboardEvent) => {
    const last = days.length - 1;
    const from = tipIndex < 0 ? latest : tipIndex; // the first press moves one step from the latest day
    const to = ev.key === "ArrowLeft" ? from - 1 : ev.key === "ArrowRight" ? Math.min(from + 1, last) : ev.key === "Home" ? 0 : ev.key === "End" ? last : null;
    if (to === null) return;
    ev.preventDefault();
    stepTip(Math.max(0, Math.min(last, to)));
  };
  host.onblur = () => chart.dispatchAction({ type: "hideTip" });
  const hatch = token("--status-not-covered");
  const gap = hatchedDays(series);
  const runs = gapRuns(series.find((t) => t.scope !== "live")?.days ?? [], gap);
  // the band-label gate is in pixels (a band narrower than LABEL_MIN_PX cannot hold the words), so a new width
  // re-decides it, as does the tooltip's on/off at 720 px; nothing else in the option depends on the width, so a
  // resize that leaves every decision as it was only resizes the canvas (BL-6: the observer's first callback and
  // every drag tick used to rebuild it all)
  const labelShows = (width: number): boolean[] => {
    const plotWidth = width - GRID.left - GRID.right;
    const d = series.find((t) => t.scope !== "live")?.days ?? [];
    return runs.map(([a, b]) => (plotWidth * runDays(d, a, b)) / d.length >= LABEL_MIN_PX);
  };
  let drawn = "";
  const draw = (width: number): void => {
    const shows = labelShows(width);
    const tip = width > 720; // under 720 px the readout row does the tooltip's job
    const key = `${tip ? "t" : "r"}${shows.map((x) => (x ? "1" : "0")).join("")}`;
    if (key === drawn) return;
    drawn = key;
    chart.setOption(build(shows, tip));
  };
  const observer = new ResizeObserver(() => {
    chart.resize();
    draw(chart.getWidth());
  });
  active = { chart, observer, readout, days, latest, setReadout };
  function build(shows: boolean[], tip: boolean) {
    const hatchPattern = hatchImage(hatch); // one canvas per draw
    return {
    backgroundColor: "transparent",
    animation: false,
    textStyle: { color: token("--ink"), fontFamily: token("--font-sans") },
    tooltip: {
      trigger: "axis",
      confine: true,
      showContent: tip, // under 720 px the readout row does that job; the cursor line still shows
      backgroundColor: token("--surface-raised"),
      borderColor: token("--hairline"),
      textStyle: { color: token("--ink") },
      axisPointer: { type: "line", lineStyle: { type: "dashed", color: token("--axis") } },
      // beside the cursor: right of it when it fits, else left, else the side with more room; never over the hovered day
      position: (point: number[], _params: unknown, _dom: unknown, _rect: unknown, size: { contentSize: number[]; viewSize: number[] }) => {
        const [w, h] = size.contentSize;
        const [vw, vh] = size.viewSize;
        const r = point[0] + 14;
        const l = point[0] - 14 - w;
        const x = r + w <= vw ? r : l >= 0 ? l : point[0] > vw / 2 ? 0 : vw - w;
        return [x, Math.max(0, Math.min(point[1] - h / 2, vh - h))];
      },
      formatter: (params: unknown) => {
        const first = (Array.isArray(params) ? params[0] : params) as { dataIndex?: number } | undefined;
        const i = first?.dataIndex ?? -1;
        if (i < 0 || i >= days.length) return document.createElement("div");
        const box = document.createElement("div");
        for (const line of [days[i], ...seriesWords(series, i)]) {
          const row = document.createElement("div");
          row.textContent = line;
          box.append(row);
        }
        return box;
      },
    },
    grid: GRID,
    xAxis: {
      type: "category",
      boundaryGap: true, // each day owns a full slot, so a band can span its edges
      data: days,
      axisLabel: { color: token("--ink-muted") },
      axisLine: { lineStyle: { color: token("--axis") } },
      axisTick: { lineStyle: { color: token("--axis") } },
    },
    yAxis: {
      type: "value",
      name: series[0].unit ?? title,
      nameTextStyle: { color: token("--ink-muted") },
      axisLabel: { color: token("--ink-muted") },
      splitLine: { lineStyle: { color: token("--hairline") } },
      scale: true,
      boundaryGap: ["6%", "6%"], // a value on the extent is a whole dot, not half a dot on the axis line
    },
    // the band draws once, on the first non-live series: a live session claims no day
    series: series.map((s, i) => ({
      name: scopeWord(s.scope),
      // live is a diamond per session day and never a line: a session is not a day of monitoring
      type: s.scope === "live" ? "scatter" : "line",
      symbol: s.scope === "live" ? "diamond" : "none",
      symbolSize: s.scope === "live" ? 9 : 4,
      // non-live lines draw no dots, except an isolated value (both neighbours missing), which would vanish,
      // and a low-completeness day, which draws hollow and faded (dayPoint)
      showSymbol: s.scope !== "live",
      // ECharts's default ("auto") samples a few days' symbol sizes against the day width and, when one is too
      // big for it, hides every symbol that is not on an axis-label tick: a lone marked day then vanishes
      // (seen on the 90-day window). The marked days are the point, so every one draws.
      showAllSymbol: true,
      connectNulls: false,
      // vendor cloud is dashed: when it agrees with device the two lines overlap exactly and both must stay visible
      lineStyle: { width: 1.5, type: s.scope === "vendor_cloud" ? "dashed" : "solid" },
      itemStyle: { color: token(SCOPE_TOKEN[s.scope] ?? "--ink") },
      data: s.scope === "live" ? s.days.map((d) => d.value) : s.days.map((_d, i) => dayPoint(s.days, i, s.scope)),
      markArea: i === series.findIndex((t) => t.scope !== "live")
        ? {
            silent: true,
            itemStyle: { color: { image: hatchPattern, repeat: "repeat" }, opacity: 0.6 },
            label: { show: true, position: "insideBottom", color: token("--ink-muted"), formatter: "not covered" },
            // a band narrower than LABEL_MIN_PX cannot hold the words: adjacent labels collided and the
            // right-edge one clipped; the caption's count still names every band
            data: runs.map(([a, b], r) => [
              // category ordinals: a day owns the slot from index-0.5 to index+0.5, so a 1-day run has width
              { xAxis: s.days.findIndex((d) => d.day === a) - 0.5, label: { show: shows[r] ?? false } },
              { xAxis: s.days.findIndex((d) => d.day === b) + 0.5 },
            ]),
          }
        : undefined,
    })),
    };
  }
  draw(host.clientWidth);
  observer.observe(host);
}
