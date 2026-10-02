// Bet-3 hello-world page: one ECharts bar chart of real daily steps served by the Rust side.
import { invoke } from "@tauri-apps/api/core";
import * as echarts from "echarts";

type DailySteps = { date: string; steps: number; source: string };

async function render(): Promise<void> {
  const host = document.getElementById("chart") as HTMLDivElement;
  const note = document.getElementById("note") as HTMLParagraphElement;
  try {
    const rows = await invoke<DailySteps[]>("daily_steps");
    // Design tokens (Bet 6): every colour the chart draws comes from tokens.css, never a literal.
    const token = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const scope = rows[0]?.source ?? "device";
    const scopeToken = scope.startsWith("steps[local]") || scope === "local" ? "--local"
      : scope.includes("vendor") ? "--vendor-cloud" : "--device";
    const legend = document.getElementById("legend") as HTMLParagraphElement;
    legend.textContent = `${rows.length} days · source ${scope}`;
    legend.style.color = token(scopeToken);
    const chart = echarts.init(host, undefined, { renderer: "canvas" });
    chart.setOption({
      backgroundColor: "transparent",
      animation: false, // deterministic frames so a window capture is always the final state
      textStyle: { color: token("--ink"), fontFamily: token("--font-sans") },
      tooltip: { trigger: "axis" },
      grid: { left: 56, right: 24, top: 24, bottom: 64 },
      xAxis: { type: "category", data: rows.map((r) => r.date),
               axisLabel: { rotate: 45, color: token("--axis") }, axisLine: { lineStyle: { color: token("--axis") } } },
      yAxis: { type: "value", name: "steps", nameTextStyle: { color: token("--ink-muted") },
               axisLabel: { color: token("--axis") }, splitLine: { lineStyle: { color: token("--hairline") } } },
      series: [{ type: "bar", data: rows.map((r) => r.steps), itemStyle: { color: token(scopeToken) } }],
    });
    window.addEventListener("resize", () => chart.resize());
    note.textContent = "Tauri 2 · Rust command → WKWebView · ECharts 6 · data from the Python oracle's CSV export";
  } catch (err) {
    note.textContent = `Could not load data: ${String(err)}`;
  }
}

window.addEventListener("DOMContentLoaded", () => void render());
