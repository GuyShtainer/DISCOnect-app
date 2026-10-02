// Bet-3 hello-world page: one ECharts bar chart of real daily steps served by the Rust side.
import { invoke } from "@tauri-apps/api/core";
import * as echarts from "echarts";

type DailySteps = { date: string; steps: number; source: string };
type Day = { date: string; steps: number | null };

/** Every calendar day from the first to the last row; days the data skips become null (a gap, drawn as absence). */
export function fillCalendar(rows: DailySteps[]): Day[] {
  if (rows.length === 0) return [];
  const byDate = new Map(rows.map((r) => [r.date, r.steps]));
  const out: Day[] = [];
  const last = new Date(rows[rows.length - 1].date + "T00:00:00Z").getTime();
  for (let t = new Date(rows[0].date + "T00:00:00Z").getTime(); t <= last; t += 86_400_000) {
    const date = new Date(t).toISOString().slice(0, 10);
    out.push({ date, steps: byDate.has(date) ? (byDate.get(date) as number) : null });
  }
  return out;
}

/** The source word the design system uses, from the CSV column name (e.g. "steps[local]"). */
function scopeWord(source: string): string {
  if (source.includes("vendor")) return "vendor cloud";
  if (source.includes("local")) return "local";
  return "device";
}

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
    const days = fillCalendar(rows);
    const gaps = days.filter((d) => d.steps === null).length;
    const legend = document.getElementById("legend") as HTMLParagraphElement;
    legend.textContent = `${rows.length} days with data${gaps ? ` · ${gaps} not covered` : ""} · source ${scopeWord(scope)}`;
    legend.style.color = token(scopeToken);
    const chart = echarts.init(host, undefined, { renderer: "canvas" });
    chart.setOption({
      backgroundColor: "transparent",
      animation: false, // deterministic frames so a window capture is always the final state
      textStyle: { color: token("--ink"), fontFamily: token("--font-sans") },
      tooltip: { trigger: "axis", backgroundColor: token("--surface-raised"), borderColor: token("--hairline"),
                 textStyle: { color: token("--ink") } },
      grid: { left: 56, right: 24, top: 24, bottom: 64 },
      xAxis: { type: "category", data: days.map((d) => d.date),
               axisLabel: { rotate: 45, color: token("--ink-muted") }, axisLine: { lineStyle: { color: token("--axis") } } },
      yAxis: { type: "value", name: "steps", nameTextStyle: { color: token("--ink-muted") },
               axisLabel: { color: token("--ink-muted") }, splitLine: { lineStyle: { color: token("--hairline") } } },
      // A day the CSV does not have is a gap: null draws nothing (never 0, never a bar borrowed from a neighbour).
      series: [{ type: "bar", data: days.map((d) => d.steps), itemStyle: { color: token(scopeToken) } }],
    });
    window.addEventListener("resize", () => chart.resize());
    note.textContent = "Tauri 2 · Rust command → WKWebView · ECharts 6 · data from the Python oracle's CSV export";
  } catch (err) {
    note.textContent = `Could not load data: ${String(err)}`;
  }
}

window.addEventListener("DOMContentLoaded", () => void render());
