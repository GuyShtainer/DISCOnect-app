// ECharts drawing with the design tokens read at paint time (so a theme change re-reads them).
// A missing day is null and connectNulls is off: a line never bridges a gap. Days no source's import
// covered get a hatched band from the status-not-covered token.
import * as echarts from "echarts";
import { scopeWord } from "./identity";

export type Series = { scope: string; unit: string | null; days: { day: string; value: number | null; status: string }[] };

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
let active: { chart: echarts.ECharts; observer: ResizeObserver; readout: HTMLElement; days: string[] } | null = null;
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
  // by pixel, not by series point: a day on which the first line has no value has no point to anchor a tip to
  const x = active.chart.convertToPixel({ xAxisIndex: 0 }, active.days[i]);
  if (typeof x === "number") active.chart.dispatchAction({ type: "showTip", x, y: GRID.top + 40 });
}

/** Group digits with a thin space like the rest of the app; one decimal under 100. */
function numWord(v: number): string {
  return Math.abs(v) >= 100 ? Math.round(v).toLocaleString("en").replace(/,/g, "\u202f") : String(Math.round(v * 10) / 10);
}

/** One series' words for one day: "<scope word> <value> <unit>" or "<scope word> no data"; a live series with no
 * session that day says nothing (a session claims no day). */
function seriesWords(series: Series[], i: number): string[] {
  const out: string[] = [];
  for (const s of series) {
    const v = s.days[i]?.value ?? null;
    if (v === null && s.scope === "live") continue;
    out.push(`${scopeWord(s.scope)} ${v === null ? "no data" : `${numWord(v)}${s.unit ? ` ${s.unit}` : ""}`}`);
  }
  return out;
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
  host.setAttribute("role", "img");
  const days = series[0].days.map((d) => d.day);
  host.setAttribute("aria-label", `${title} trend, ${days.length} days`);
  const readout = document.createElement("div");
  readout.className = "readout";
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
      setReadout(i);
    }
  });
  host.onkeydown = (ev: KeyboardEvent) => {
    const last = days.length - 1;
    const from = tipIndex < 0 ? last + 1 : tipIndex;
    const to = ev.key === "ArrowLeft" ? from - 1 : ev.key === "ArrowRight" ? Math.min(from + 1, last) : ev.key === "Home" ? 0 : ev.key === "End" ? last : null;
    if (to === null) return;
    ev.preventDefault();
    stepTip(Math.max(0, Math.min(last, to)));
  };
  const observer = new ResizeObserver(() => {
    chart.resize();
    chart.setOption(build(chart.getWidth())); // the band-label gate is in pixels, so a new width re-decides it
  });
  active = { chart, observer, readout, days };
  const hatch = token("--status-not-covered");
  const gap = hatchedDays(series);
  function build(width: number) {
    const plotWidth = width - GRID.left - GRID.right;
    return {
    backgroundColor: "transparent",
    animation: false,
    textStyle: { color: token("--ink"), fontFamily: token("--font-sans") },
    tooltip: {
      trigger: "axis",
      confine: true,
      backgroundColor: token("--surface-raised"),
      borderColor: token("--hairline"),
      textStyle: { color: token("--ink") },
      axisPointer: { type: "line", lineStyle: { type: "dashed", color: token("--axis") } },
      // beside the cursor, on the side with room: left of it in the right half, right of it otherwise, so the tip never covers the hovered day
      position: (point: number[], _params: unknown, _dom: unknown, _rect: unknown, size: { contentSize: number[]; viewSize: number[] }) => {
        const [w, h] = size.contentSize;
        const [vw, vh] = size.viewSize;
        const x = point[0] > vw / 2 ? point[0] - w - 14 : point[0] + 14;
        return [Math.max(0, Math.min(x, vw - w)), Math.max(0, Math.min(point[1] - h / 2, vh - h))];
      },
      formatter: (params: unknown) => {
        const first = (Array.isArray(params) ? params[0] : params) as { dataIndex?: number } | undefined;
        const i = first?.dataIndex ?? -1;
        if (i < 0 || i >= days.length) return "";
        return [days[i], ...seriesWords(series, i)].join("<br/>");
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
      // non-live lines draw no dots, except an isolated value (both neighbours missing), which would vanish
      showSymbol: s.scope !== "live",
      connectNulls: false,
      // vendor cloud is dashed: when it agrees with device the two lines overlap exactly and both must stay visible
      lineStyle: { width: 1.5, type: s.scope === "vendor_cloud" ? "dashed" : "solid" },
      itemStyle: { color: token(SCOPE_TOKEN[s.scope] ?? "--ink") },
      data: s.scope === "live"
        ? s.days.map((d) => d.value)
        : s.days.map((d, i) => (d.value !== null && s.days[i - 1]?.value == null && s.days[i + 1]?.value == null
          ? { value: d.value, symbol: "circle", symbolSize: 5 }
          : d.value)),
      markArea: i === series.findIndex((t) => t.scope !== "live")
        ? {
            silent: true,
            itemStyle: { color: { image: hatchImage(hatch), repeat: "repeat" }, opacity: 0.6 },
            label: { show: true, position: "insideBottom", color: token("--ink-muted"), formatter: "not covered" },
            // a band narrower than LABEL_MIN_PX cannot hold the words: adjacent labels collided and the
            // right-edge one clipped; the caption's count still names every band
            data: gapRuns(s.days, gap).map(([a, b]) => [
              // category ordinals: a day owns the slot from index-0.5 to index+0.5, so a 1-day run has width
              { xAxis: s.days.findIndex((d) => d.day === a) - 0.5, label: { show: (plotWidth * runDays(s.days, a, b)) / s.days.length >= LABEL_MIN_PX } },
              { xAxis: s.days.findIndex((d) => d.day === b) + 0.5 },
            ]),
          }
        : undefined,
    })),
    };
  }
  chart.setOption(build(host.clientWidth));
  observer.observe(host);
}
