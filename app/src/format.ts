// The one number formatter (BL-6, 7b-7 review N9): Today, Sleep, Data health and the Trends readout all say a value
// the same way. `fmt` rounds (one decimal under 100, thin-space thousands at 100 and above) and drops the unit word
// for a score or steps; `fmtValue` also reads minutes at an hour and above as "7 h 12 min".
export function fmt(value: number | null, unit: string | null): string {
  if (value === null || value === undefined) return "no data";
  const n = Math.abs(value) >= 100 ? Math.round(value).toLocaleString("en").replace(/,/g, "\u202f") : (Math.round(value * 10) / 10).toString();
  return unit && unit !== "score" && unit !== "steps" ? `${n} ${unit}` : n;
}

export function fmtValue(value: number | null, unit: string | null): string {
  if (value !== null && unit === "min" && Math.abs(value) >= 60) {
    const total = Math.round(Math.abs(value));
    return `${value < 0 ? "−" : ""}${Math.floor(total / 60)} h ${String(total % 60).padStart(2, "0")} min`;
  }
  return fmt(value, unit);
}
