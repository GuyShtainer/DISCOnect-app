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

let active: { chart: echarts.ECharts; observer: ResizeObserver } | null = null;

/** Dispose the live chart (route() calls this before it replaces the screen, so nothing leaks). */
export function disposeCharts(): void {
  if (!active) return;
  active.observer.disconnect();
  active.chart.dispose();
  active = null;
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

export function drawTrend(host: HTMLElement, series: Series[], title: string): void {
  disposeCharts();
  const chart = echarts.init(host, undefined, { renderer: "canvas" });
  const observer = new ResizeObserver(() => chart.resize());
  observer.observe(host);
  active = { chart, observer };
  const days = series[0].days.map((d) => d.day);
  const hatch = token("--status-not-covered");
  const gap = hatchedDays(series);
  const unit = series[0].unit ?? "";
  chart.setOption({
    backgroundColor: "transparent",
    animation: false,
    textStyle: { color: token("--ink"), fontFamily: token("--font-sans") },
    tooltip: {
      trigger: "axis",
      backgroundColor: token("--surface-raised"),
      borderColor: token("--hairline"),
      textStyle: { color: token("--ink") },
      valueFormatter: (v: unknown) => (v === null || v === undefined ? "no data" : `${v}${unit ? ` ${unit}` : ""}`),
    },
    grid: { left: 56, right: 24, top: 24, bottom: 48 },
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
            // a band narrower than a tenth of the window cannot hold the words: adjacent labels
            // collided and the right-edge one clipped; the caption's count still names every band
            data: gapRuns(s.days, gap).map(([a, b]) => [
              // category ordinals: a day owns the slot from index-0.5 to index+0.5, so a 1-day run has width
              { xAxis: s.days.findIndex((d) => d.day === a) - 0.5, label: { show: runDays(s.days, a, b) >= Math.ceil(s.days.length / 10) } },
              { xAxis: s.days.findIndex((d) => d.day === b) + 0.5 },
            ]),
          }
        : undefined,
    })),
  });
}
