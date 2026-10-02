//! Bet-3 hello-world: prove Tauri 2 + Rust + ECharts on macOS with REAL data.
//!
//! The only command reads the daily CSV that the Python oracle exports
//! (`hearthbeat export --format wide`) and returns (date, steps) pairs. No decoding, no
//! storage — the Rust core port is Bet 5. The CSV lives in the git-ignored `data/` folder;
//! override with `DISCONECT_DAILY_CSV=/path/to/daily.csv`.

use std::path::PathBuf;

#[derive(serde::Serialize)]
pub struct DailySteps {
    pub date: String,
    pub steps: u32,
    pub source: String,
}

fn csv_path() -> PathBuf {
    std::env::var_os("DISCONECT_DAILY_CSV")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/daily.csv"))
}

/// Pick the steps column: device scope first, then local, then any `steps[...]`.
fn steps_column(header: &[&str]) -> Option<(usize, String)> {
    let preferred = ["steps[device]", "steps[local]"];
    for want in preferred {
        if let Some(i) = header.iter().position(|h| *h == want) {
            return Some((i, want.to_string()));
        }
    }
    header
        .iter()
        .position(|h| h.starts_with("steps["))
        .map(|i| (i, header[i].to_string()))
}

pub fn parse_daily_steps(text: &str) -> Result<Vec<DailySteps>, String> {
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().ok_or("empty CSV")?.split(',').collect();
    let date_col = header.iter().position(|h| *h == "date").ok_or("no date column")?;
    let (steps_col, source) = steps_column(&header).ok_or("no steps column")?;
    let mut rows = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        let Some(raw) = fields.get(steps_col) else { continue };
        if raw.is_empty() {
            continue;
        }
        let steps = raw
            .parse::<f64>()
            .map_err(|e| format!("bad steps value {raw:?}: {e}"))? as u32;
        rows.push(DailySteps { date: fields[date_col].to_string(), steps, source: source.clone() });
    }
    Ok(rows)
}

#[tauri::command]
fn daily_steps() -> Result<Vec<DailySteps>, String> {
    let path = csv_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse_daily_steps(&text)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![daily_steps])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::parse_daily_steps;

    #[test]
    fn prefers_device_scope_and_skips_blanks() {
        let csv = "date,steps[vendor_cloud],steps[device]\n2025-06-11,100,120\n2025-06-12,,\n2025-06-13,90,";
        let rows = parse_daily_steps(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].date.as_str(), rows[0].steps), ("2025-06-11", 120));
        assert_eq!(rows[0].source, "steps[device]");
    }

    #[test]
    fn falls_back_to_any_steps_column() {
        let csv = "date,steps[vendor_cloud]\n2025-06-11,7\n";
        let rows = parse_daily_steps(csv).unwrap();
        assert_eq!(rows[0].source, "steps[vendor_cloud]");
    }

    #[test]
    fn missing_steps_column_is_an_error() {
        assert!(parse_daily_steps("date,foo\n2025-06-11,1\n").is_err());
    }
}
