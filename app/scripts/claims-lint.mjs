// SPDX-License-Identifier: AGPL-3.0-or-later
// CLAIMS-POLICY.md as a lint: authored copy never claims medicine or borrows a score name.
//
// The policy file is the source of truth: its fenced `terms <category> [case]` blocks are the banned lists (one term
// per line, a trailing `*` is any word ending) and its `allow` block is the exact-sentence allowlist for negations.
// The same matcher as the Python core's tests/test_claims_policy.py, over this shell's authored strings, the Rust
// core's identity module and the coach modules. The policy is the repository root's in a standalone checkout and
// the Python core's beside this app in the monorepo. Exit 1 on any hit.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "..");
const core = join(here, "../../core");
const policyPath = [join(app, "../CLAIMS-POLICY.md"), join(app, "../disconect/CLAIMS-POLICY.md")].find(existsSync);
if (!policyPath) {
  console.error("claims-lint: no CLAIMS-POLICY.md beside the app");
  process.exit(2);
}
const policy = readFileSync(policyPath, "utf8");

function parsePolicy(text) {
  const categories = {};
  const allow = [];
  for (const m of text.matchAll(/^```([^\n]+)\n([\s\S]*?)^```/gm)) {
    const words = m[1].split(/\s+/).filter(Boolean);
    const lines = m[2].split("\n").map((l) => l.trim()).filter(Boolean);
    if (words[0] === "allow") allow.push(...lines);
    else if (words[0] === "terms") categories[words[1]] = compile(lines, words.slice(2).includes("case"));
  }
  return { categories, allow };
}

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function compile(terms, caseSensitive) {
  const parts = terms.map((term) =>
    term.split(/\s+/).map((w) => escape(w.replace(/\*+$/, "")) + (w.endsWith("*") ? "\\w*" : "")).join("\\s+"));
  return new RegExp("\\b(?:" + parts.join("|") + ")\\b", caseSensitive ? "g" : "gi");
}

function violations(text, { categories, allow }) {
  for (const sentence of allow) text = text.split(sentence).join(" ");
  const hits = [];
  for (const [name, pattern] of Object.entries(categories)) {
    for (const m of text.matchAll(pattern)) hits.push([name, m[0]]);
  }
  return hits;
}

const TOKENS = {
  ".ts": /"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\]|\\.)*)`|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
  ".rs": /r(#*)"([\s\S]*?)"\1|"((?:[^"\\]|\\.)*)"|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
};

function authoredStrings(path) {
  const text = readFileSync(path, "utf8");
  if (path.endsWith(".md")) return [text];
  if (path.endsWith(".html")) {
    return [...text.matchAll(/>([^<>]+)</g)].map((m) => m[1])
      .concat([...text.matchAll(/(?:title|alt|placeholder|aria-label)="([^"]*)"/g)].map((m) => m[1]));
  }
  const suffix = path.slice(path.lastIndexOf("."));
  const strings = [];
  for (const m of text.matchAll(TOKENS[suffix])) {
    const body = suffix === ".rs" ? m[2] ?? m[3] : m[1] ?? m[2];
    if (body) strings.push(body);
  }
  return strings;
}

const files = (dir, suffix) => readdirSync(dir).filter((f) => f.endsWith(suffix)).sort().map((f) => join(dir, f));
const scope = [
  ...files(join(app, "src"), ".ts"),
  join(app, "index.html"),
  join(app, "README.md"),
  join(core, "src/identity.rs"),
  ...files(join(app, "src-tauri/src/coach"), ".rs"),
];
const rootReadme = join(app, "../README.md");
if (policyPath === join(app, "../CLAIMS-POLICY.md")) scope.unshift(rootReadme); // the standalone repository's README

const parsed = parsePolicy(policy);
const failures = [];
if (Object.keys(parsed.categories).sort().join() !== "medical-nouns,medical-verbs,score-marks,score-names") {
  failures.push("the policy does not parse into the four term lists");
}
const disclaimer = (path, re) => readFileSync(path, "utf8").match(re)?.[1];
const tsDisclaimer = disclaimer(join(app, "src/identity.ts"), /export const DISCLAIMER = "([^"]+)"/);
const rsDisclaimer = disclaimer(join(core, "src/identity.rs"), /pub const DISCLAIMER: &str = "([^"]+)"/);
if (!tsDisclaimer || tsDisclaimer !== rsDisclaimer || !parsed.allow.includes(tsDisclaimer)) {
  failures.push("DISCLAIMER differs between identity.ts, identity.rs and the policy's allow block");
}
for (const path of scope) {
  if (!existsSync(path)) {
    failures.push(`${relative(app, path)} is in the lint scope but missing`);
    continue;
  }
  for (const s of authoredStrings(path)) {
    for (const [name, hit] of violations(s, parsed)) failures.push(`${relative(app, path)}: ${name} "${hit}" in "${s.trim().slice(0, 80)}"`);
  }
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`claims-lint: ${scope.length} files clean against ${relative(app, policyPath)}`);
