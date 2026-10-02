// ECharts drawing with the design tokens read at paint time (so a theme change re-reads them).
// A missing day is null and connectNulls is off: a line never bridges a gap. Days no import
// covered get a hatched band from the status-not-covered token.
import * as echarts from "echarts";

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

const charts = new WeakMap<HTMLElement, echarts.ECharts>();

export function drawTrend(host: HTMLElement, series: Series[], title: string): void {
  charts.get(host)?.dispose();
  const chart = echarts.init(host, undefined, { renderer: "canvas" });
  charts.set(host, chart);
  const days = series[0].days.map((d) => d.day);
  const hatch = token("--status-not-covered");
  chart.setOption({
    backgroundColor: "transparent",
    animation: false,
    textStyle: { color: token("--ink"), fontFamily: token("--font-sans") },
    tooltip: {
      trigger: "axis",
      backgroundColor: token("--surface-raised"),
      borderColor: token("--hairline"),
      textStyle: { color: token("--ink") },
      valueFormatter: (v: unknown) => (v === null || v === undefined ? "no data" : String(v)),
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
      name: s.scope,
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
            itemStyle: { color: hatch, opacity: 0.18, decal: { symbol: "line", rotation: Math.PI / 4, color: hatch, dashArrayX: [1, 0], dashArrayY: [2, 4] } },
            label: { show: true, position: "insideBottom", color: token("--ink-muted"), formatter: "not covered" },
            data: notCoveredRuns(s.days).map(([a, b]) => [{ xAxis: a }, { xAxis: b }]),
          }
        : undefined,
    })),
  });
  const onResize = () => chart.resize();
  window.addEventListener("resize", onResize, { once: true });
}
