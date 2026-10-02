// Bet-3 hello-world page: one ECharts bar chart of real daily steps served by the Rust side.
import { invoke } from "@tauri-apps/api/core";
import * as echarts from "echarts";

type DailySteps = { date: string; steps: number; source: string };

async function render(): Promise<void> {
  const host = document.getElementById("chart") as HTMLDivElement;
  const note = document.getElementById("note") as HTMLParagraphElement;
  try {
    const rows = await invoke<DailySteps[]>("daily_steps");
    const chart = echarts.init(host);
    chart.setOption({
      title: { text: "Daily steps", subtext: `${rows.length} days · source ${rows[0]?.source ?? "?"}` },
      tooltip: { trigger: "axis" },
      grid: { left: 56, right: 24, bottom: 64 },
      xAxis: { type: "category", data: rows.map((r) => r.date), axisLabel: { rotate: 45 } },
      yAxis: { type: "value", name: "steps" },
      series: [{ type: "bar", data: rows.map((r) => r.steps) }],
    });
    window.addEventListener("resize", () => chart.resize());
    note.textContent = "Tauri 2 · Rust command → WKWebView · ECharts 6 · data from the Python oracle's CSV export";
  } catch (err) {
    note.textContent = `Could not load data: ${String(err)}`;
  }
}

window.addEventListener("DOMContentLoaded", () => void render());
