// SPDX-License-Identifier: AGPL-3.0-or-later
//! The six tools of the MCP server, their parameters and what each one reads (Bet 11e, slice 2): the twins of
//! `disconect/mcp_server.py`. A tool is a name, its parameters (coerced by [`crate::mcp_args`]) and a
//! function over the store; a failure is an [`Outcome`] the protocol layer words from `mcp.json`.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::sync::LazyLock;

use serde_json::Value;

use crate::contract::Contract;
use crate::identity;
use crate::keys::KeyError;
use crate::mcp::Server;
use crate::mcp_args::{Arg, Kind, Param};
use crate::read::ReadError;
use crate::read::health;
use crate::read::insight::{self, FactsQuery};
use crate::read::mcp_paths;
use crate::store::StoreError;
use crate::time::now_instant;
use crate::wirejson::{self, Json, PyStr};

const SPEC_JSON: &str = include_str!("../mcp.json");

pub(crate) static SPEC: LazyLock<Value> =
    LazyLock::new(|| serde_json::from_str(SPEC_JSON).unwrap_or(Value::Null));

/// `mcp.json` at a path of keys: the text there, or "" (a test proves every path the code uses exists).
pub(crate) fn spec_text(path: &[&str]) -> &'static str {
    path.iter()
        .try_fold(&*SPEC, |node, key| node.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub(crate) fn spec_json(path: &[&str]) -> String {
    let node = path.iter().try_fold(&*SPEC, |node, key| node.get(key));
    let mut out = String::new();
    wirejson::write_value(&mut out, node.unwrap_or(&Value::Null));
    out
}

// ---- tools ----

pub(crate) type Run = fn(&Server, &[Arg]) -> Outcome;

pub(crate) struct Tool {
    pub(crate) name: &'static str,
    pub(crate) params: &'static [Param],
    pub(crate) run: Run,
}

pub(crate) enum Outcome {
    Done(Json),
    /// A `ToolError`: `Error executing tool <name>: <message>`.
    Failed(String),
    /// An exception without text (an `OverflowError`): `Error executing tool <name>`.
    Crashed,
}

pub(crate) const TOOLS: [Tool; 6] = [
    Tool {
        name: "get_data_health",
        params: &[Param {
            name: "window_days",
            kind: Kind::Int(30),
        }],
        run: data_health,
    },
    Tool {
        name: "get_metric_series",
        params: &[
            Param {
                name: "metrics",
                kind: Kind::Strs,
            },
            Param {
                name: "days",
                kind: Kind::Int(90),
            },
            Param {
                name: "source_scope",
                kind: Kind::OptStr,
            },
            Param {
                name: "end_date",
                kind: Kind::OptStr,
            },
        ],
        run: metric_series,
    },
    Tool {
        name: "get_sleep_detail",
        params: &[Param {
            name: "date",
            kind: Kind::OptStr,
        }],
        run: sleep_detail,
    },
    Tool {
        name: "list_activities",
        params: &[Param {
            name: "limit",
            kind: Kind::Int(20),
        }],
        run: list_activities,
    },
    Tool {
        name: "get_period_facts",
        params: &[
            Param {
                name: "window_days",
                kind: Kind::Int(7),
            },
            Param {
                name: "baseline_days",
                kind: Kind::Int(28),
            },
            Param {
                name: "end_date",
                kind: Kind::OptStr,
            },
            Param {
                name: "metrics",
                kind: Kind::OptStrs,
            },
            Param {
                name: "source_scope",
                kind: Kind::OptStr,
            },
            Param {
                name: "include_points",
                kind: Kind::Bool(false),
            },
        ],
        run: period_facts,
    },
    Tool {
        name: "get_contract",
        params: &[],
        run: contract_dict,
    },
];

fn int_at(args: &[Arg], at: usize) -> i64 {
    match args.get(at) {
        Some(Arg::Int(value)) => value.clamped_i64(),
        _ => 0,
    }
}

fn str_at(args: &[Arg], at: usize) -> Option<&PyStr> {
    match args.get(at) {
        Some(Arg::Str(value)) => value.as_ref(),
        _ => None,
    }
}

fn list_at(args: &[Arg], at: usize) -> Option<Vec<PyStr>> {
    match args.get(at) {
        Some(Arg::List(value)) => value.clone(),
        _ => None,
    }
}

fn data_health(server: &Server, args: &[Arg]) -> Outcome {
    let window_days = int_at(args, 0);
    read(server, |conn| {
        health::data_health_ordered(conn, Contract::get()?, window_days, now_instant())
    })
}

fn metric_series(server: &Server, args: &[Arg]) -> Outcome {
    let metrics = list_at(args, 0).unwrap_or_default();
    if metrics.is_empty() {
        return Outcome::Failed(template("no_metrics", ""));
    }
    read(server, |conn| {
        mcp_paths::metric_series(
            conn,
            &metrics,
            int_at(args, 1),
            str_at(args, 2),
            str_at(args, 3),
        )
    })
}

fn sleep_detail(server: &Server, args: &[Arg]) -> Outcome {
    read(server, |conn| {
        mcp_paths::sleep_detail(conn, str_at(args, 0))
    })
}

fn list_activities(server: &Server, args: &[Arg]) -> Outcome {
    read(server, |conn| {
        mcp_paths::list_activities(conn, int_at(args, 0))
    })
}

fn period_facts(server: &Server, args: &[Arg]) -> Outcome {
    let query = FactsQuery {
        window_days: int_at(args, 0),
        baseline_days: int_at(args, 1),
        end_date: str_at(args, 2).cloned(),
        metrics: list_at(args, 3),
        source_scope: str_at(args, 4).cloned(),
        include_points: matches!(args.get(5), Some(Arg::Bool(true))),
    };
    read(server, |conn| insight::period_facts_ordered(conn, &query))
}

/// `contract.as_dict()`: the conventions flattened, then scopes, streams, sparse metrics, metrics, labels.
fn contract_dict(_server: &Server, _args: &[Arg]) -> Outcome {
    let Ok(contract) = Contract::get() else {
        return Outcome::Crashed;
    };
    let strings =
        |items: &[String]| Json::Array(items.iter().map(|item| Json::text(item)).collect());
    let metrics = |items: &[crate::contract::MetricContract]| {
        Json::Array(
            items
                .iter()
                .map(|item| {
                    let mut entry = Json::dict();
                    for (key, value) in [
                        ("metric", &item.metric),
                        ("unit", &item.unit),
                        ("cadence", &item.cadence),
                        ("description", &item.description),
                    ] {
                        entry.set(key, Json::text(value));
                    }
                    entry
                })
                .collect(),
        )
    };
    let mut sparse = contract.sparse_metrics.clone();
    sparse.sort();
    let mut out = Json::dict();
    out.set("contract_version", Json::text(&contract.contract_version));
    let c = &contract.conventions;
    for (key, value) in [
        ("time", &c.time),
        ("missing_values", &c.missing_values),
        ("sources", &c.sources),
        ("privacy", &c.privacy),
        ("coverage", &c.coverage),
        ("completeness", &c.completeness),
    ] {
        out.set(key, Json::text(value));
    }
    out.set("source_scopes", strings(&contract.source_scopes));
    out.set("per_minute_metrics", strings(&contract.per_minute_metrics));
    let streams = contract.streams_for.iter().map(|entry| {
        let mut item = Json::dict();
        item.set("metric", Json::text(&entry.metric));
        item.set("source_scope", Json::text(&entry.source_scope));
        item.set("streams", strings(&entry.streams));
        item
    });
    out.set("streams_for", Json::Array(streams.collect()));
    out.set("session_streams", strings(&contract.session_streams));
    let sessions = contract.session_streams_for.iter().map(|entry| {
        let mut item = Json::dict();
        item.set("metric", Json::text(&entry.metric));
        item.set("source_scope", Json::text(&entry.source_scope));
        item.set("streams", strings(&entry.streams));
        item
    });
    out.set("session_streams_for", Json::Array(sessions.collect()));
    out.set("sparse_metrics", strings(&sparse));
    out.set("metrics", metrics(&contract.metrics));
    out.set("labels", metrics(&contract.labels));
    identity::neutral_json(&mut out);
    Outcome::Done(out)
}

/// An error text of `mcp.json`: its template with `{exc}` filled in.
fn template(key: &str, exc: &str) -> String {
    spec_text(&["errors", "templates", key]).replace("{exc}", exc)
}

fn read_outcome(error: ReadError) -> Outcome {
    match error {
        ReadError::Value(message) => Outcome::Failed(template("value_error", &message)),
        ReadError::Db(inner) => Outcome::Failed(template("database_error", &inner.to_string())),
        ReadError::Overflow | ReadError::Unexpected(_) | ReadError::Contract(_) => Outcome::Crashed,
    }
}

/// `_db()`'s mapping of a store that will not open.
fn open_failure(error: &StoreError) -> String {
    match error {
        StoreError::NotConfigured(_) => template(
            "not_configured",
            spec_text(&["errors", "storage", "not_configured"]),
        ),
        StoreError::SchemaTooNew { .. } => template("schema_too_new", &error.to_string()),
        StoreError::Encrypted(_)
        | StoreError::NotEncrypted(_)
        | StoreError::Key(KeyError::Locked | KeyError::WrongPassphrase) => changed_store_text(),
        other => template("open_failed", &other.to_string()),
    }
}

/// A store that stopped opening after the server started (it was encrypted, or its key changed, while Claude
/// Desktop kept the server running): the one way to reach the `locked` case, since a store that is locked at
/// start exits 9 before any call. Rust-owned, not `mcp.json`'s Python template (kb/23 class 19): that one sends
/// a person to `disconect key cache` and to a restart of `disconect-mcp`, neither of which exists in the app.
pub(crate) fn changed_store_text() -> String {
    format!(
        "The store is encrypted and this server has no working key for it: it changed after Claude Desktop \
         started the server. {}",
        crate::mcp_start::fix_instruction("on")
    )
}

/// The message of a serve `invalid_params` failure for rejected arguments: the parameters at fault, sorted
/// (`serve.py` words it from pydantic's error locations the same way). No reason and no value.
pub(crate) fn rejection_names(rejected: &[(&str, &str)]) -> String {
    let mut names: Vec<&str> = rejected.iter().map(|(param, _)| *param).collect();
    names.sort_unstable();
    names.dedup();
    format!("arguments rejected: {}", names.join(", "))
}

pub(crate) fn rejection(tool: &Tool, rejected: &[(&str, &str)]) -> String {
    let plural = if rejected.len() == 1 { "" } else { "s" };
    let mut text = format!(
        "{} validation error{plural} for {}Arguments",
        rejected.len(),
        tool.name
    );
    for (param, reason) in rejected {
        text.push_str(&format!("\n{param}\n  {reason}"));
    }
    spec_text(&["errors", "tool_error"])
        .replace("{name}", tool.name)
        .replace("{message}", &text)
}

/// A read-only connection for one call, then `f`; every failure becomes an [`Outcome`] the protocol layer words.
pub(crate) fn read(
    server: &Server,
    f: impl FnOnce(&rusqlite::Connection) -> Result<Json, ReadError>,
) -> Outcome {
    match crate::store::open_read_only_with(&server.db, server.master.as_ref()) {
        Err(error) => Outcome::Failed(open_failure(&error)),
        Ok(opened) => match f(opened.conn()) {
            Ok(mut json) => {
                identity::neutral_json(&mut json);
                Outcome::Done(json)
            }
            Err(error) => read_outcome(error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_args::coerce;
    use serde_json::json;

    fn spec() -> &'static Value {
        assert!(!SPEC.is_null(), "mcp.json must parse");
        &SPEC
    }

    fn encoded(arg: &Arg) -> Value {
        match arg {
            Arg::Int(value) => json!({"int": value.text()}),
            Arg::Bool(flag) => json!({"bool": flag}),
            Arg::Str(None) | Arg::List(None) => json!({"null": true}),
            Arg::Str(Some(text)) => json!({"str": text.units_lossy()}),
            Arg::List(Some(items)) => {
                json!({"list": items.iter().map(|i| json!({"str": i.units_lossy()})).collect::<Vec<_>>()})
            }
        }
    }

    fn tool(name: &str) -> &'static Tool {
        TOOLS
            .iter()
            .find(|t| t.name == name)
            .expect("a tool of that name")
    }

    /// `arguments` for one table case: the text of a JSON value under `param`, or nothing for `<absent>`.
    fn arguments(param: Option<&str>, input: &str) -> Json {
        match (param, input) {
            (_, "<absent>") => Json::dict(),
            (Some(name), text) => {
                let mut object = Json::dict();
                object.set(
                    name,
                    wirejson::parse(text).expect("the case's input is JSON"),
                );
                object
            }
            (None, text) => wirejson::parse(text).expect("the case's input is JSON"),
        }
    }

    #[test]
    fn every_case_of_the_measured_coercion_table_replays() {
        let mut replayed = 0;
        for (group, entry) in spec()["coercions"].as_object().expect("coercions") {
            let param = entry["param"].as_str();
            for case in entry["cases"].as_array().expect("cases") {
                let name = case["tool"]
                    .as_str()
                    .or(entry["tool"].as_str())
                    .expect("tool");
                let input = case["input"].as_str().expect("input");
                let given = arguments(param.filter(|_| group != "arguments"), input);
                let verdict = coerce(tool(name).params, &given);
                let label = format!("{group}: {name} {input}");
                match case["outcome"].as_str() {
                    Some("accepted") => {
                        let got = verdict.unwrap_or_else(|why| panic!("{label} rejected: {why:?}"));
                        let want = case["coerced"].as_object().expect("coerced");
                        if group == "arguments" {
                            assert_eq!(got.len(), want.len(), "{label}");
                        }
                        for (key, value) in want {
                            let at = tool(name)
                                .params
                                .iter()
                                .position(|p| p.name == key)
                                .expect("a parameter");
                            assert_eq!(&encoded(&got[at]), value, "{label} {key}");
                        }
                    }
                    Some("rejected") => assert!(verdict.is_err(), "{label} must be rejected"),
                    Some("protocol_error") => {
                        // not an `arguments` object: the protocol layer answers -32602 before any tool runs
                        assert!(
                            !matches!(given, Json::Object(_)) || input == "<absent>",
                            "{label}"
                        );
                    }
                    other => panic!("{label}: outcome {other:?}"),
                }
                replayed += 1;
            }
        }
        assert_eq!(replayed, 145);
    }

    #[test]
    fn the_tool_table_is_what_mcp_json_serves() {
        let served = spec()["tools"].as_array().expect("tools");
        let names: Vec<&str> = served.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(names, TOOLS.iter().map(|t| t.name).collect::<Vec<_>>());
        for (listed, tool) in served.iter().zip(TOOLS.iter()) {
            let schema = &listed["inputSchema"];
            let properties = schema["properties"].as_object().expect("properties");
            let wanted: Vec<&str> = properties.keys().map(String::as_str).collect();
            let mut have: Vec<&str> = tool.params.iter().map(|p| p.name).collect();
            let mut sorted = wanted.clone();
            sorted.sort_unstable();
            have.sort_unstable();
            assert_eq!(have, sorted, "{} parameters", tool.name);
            let required: Vec<&str> = schema["required"]
                .as_array()
                .map_or_else(Vec::new, |r| r.iter().filter_map(Value::as_str).collect());
            for param in tool.params {
                let property = &properties[param.name];
                assert_eq!(
                    required.contains(&param.name),
                    matches!(param.kind, Kind::Strs),
                    "{}",
                    param.name
                );
                match param.kind {
                    Kind::Int(default) => assert_eq!(
                        (property["type"].as_str(), property["default"].as_i64()),
                        (Some("integer"), Some(default))
                    ),
                    Kind::Bool(default) => assert_eq!(
                        (property["type"].as_str(), property["default"].as_bool()),
                        (Some("boolean"), Some(default))
                    ),
                    Kind::Strs => assert_eq!(
                        (
                            property["type"].as_str(),
                            property["items"]["type"].as_str()
                        ),
                        (Some("array"), Some("string"))
                    ),
                    Kind::OptStr => {
                        assert_eq!(property["anyOf"][0]["type"].as_str(), Some("string"))
                    }
                    Kind::OptStrs => {
                        assert_eq!(property["anyOf"][0]["type"].as_str(), Some("array"))
                    }
                }
            }
        }
    }

    #[test]
    fn every_text_the_server_takes_from_mcp_json_is_there() {
        for path in [
            vec!["serverInfo", "name"],
            vec!["serverInfo", "version"],
            vec!["instructions"],
            vec!["protocol", "default"],
            vec!["errors", "tool_error"],
            vec!["errors", "crash"],
            vec!["errors", "unknown_tool"],
            vec!["errors", "storage", "not_configured"],
        ] {
            assert!(!spec_text(&path).is_empty(), "{path:?}");
        }
        for key in [
            "not_configured",
            "schema_too_new",
            "locked",
            "open_failed",
            "value_error",
            "database_error",
            "no_metrics",
        ] {
            assert!(
                !spec_text(&["errors", "templates", key]).is_empty(),
                "{key}"
            );
        }
        assert_eq!(
            spec_text(&["serverInfo", "version"]),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            spec_text(&["serverInfo", "name"]),
            identity::MCP_SERVER_NAME
        );
        assert_eq!(
            spec()["protocol"]["accepted"].as_array().map(Vec::len),
            Some(4)
        );
    }

    #[test]
    fn a_rejection_names_the_parameter_and_never_the_value() {
        let rejected = rejection(
            tool("list_activities"),
            &[("limit", "Input should be a valid integer")],
        );
        assert_eq!(
            rejected,
            "Error executing tool list_activities: 1 validation error for list_activitiesArguments\nlimit\n  Input should be a valid integer"
        );
    }
}
