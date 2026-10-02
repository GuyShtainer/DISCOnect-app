// ECharts drawing with the design tokens read at paint time (so a theme change re-reads them).
// A missing day is null and connectNulls is off: a line never bridges a gap. Days no import
// covered get a hatched band from the status-not-covered token.
import * as echarts from "echarts";
import { scopeWord } from "./identity";

export type Series = { scope: string; unit: string | null; days: { day: string; value: number | null; status: string }[] };

const SCOPE_TOKEN: Record<string, string> = { device: "--device", vendor_cloud: "--vendor-cloud", local: "--local" };

export function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Contiguous runs of not_covered days as [first, last] pairs, for markArea. */
export function notCoveredRuns(days: { day: string; status: string }[]): [string, string][] {
  const runs: [string, string][] = [];
  let start: string | null = null;
  for (let i = 0; i < days.length; i++) {
    const gap = days[i].status === "not_covered";
    if (gap && start === null) start = days[i].day;
    if (!gap && start !== null) {
      runs.push([start, days[i - 1].day]);
      start = null;
    }
  }
  if (start !== null) runs.push([start, days[days.length - 1].day]);
  return runs;
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
    },
    series: series.map((s, i) => ({
      name: scopeWord(s.scope),
      type: "line",
      showSymbol: false,
      connectNulls: false,
      // vendor cloud is dashed: when it agrees with device the two lines overlap exactly and both must stay visible
      lineStyle: { width: 1.5, type: s.scope === "vendor_cloud" ? "dashed" : "solid" },
      itemStyle: { color: token(SCOPE_TOKEN[s.scope] ?? "--ink") },
      data: s.days.map((d) => d.value),
      markArea: i === 0
        ? {
            silent: true,
            itemStyle: { color: { image: hatchImage(hatch), repeat: "repeat" }, opacity: 0.6 },
            label: { show: true, position: "insideBottom", color: token("--ink-muted"), formatter: "not covered" },
            data: notCoveredRuns(s.days).map(([a, b]) => [{ xAxis: a }, { xAxis: b }]),
          }
        : undefined,
    })),
  });
}
