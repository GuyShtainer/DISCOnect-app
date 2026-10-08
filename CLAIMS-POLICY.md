# CLAIMS-POLICY — what DISCOnect's own words may claim

Linted always: `app/scripts/claims-lint.mjs` (`npm run lint` in `app/`) parses the fenced blocks below, so this file IS the lint's
source of truth.

**Positioning.** DISCOnect is training and wellness coaching software. It describes patterns in
the user's own history (their own days, their own baseline). It never diagnoses, treats or gives
medical advice, never compares a person with a population norm, and never names a condition.

**Disclaimer.** One sentence, shown in every coaching session, identical in `identity.ts` and
`identity.rs` here and in the Python core's `identity.py` as `DISCLAIMER` (drift test); it is the first `allow` line below.

## Rules for authored copy
1. No medical verbs or nouns (lists below), case-insensitive, whole words; a trailing `*` stands for
   any word ending (`diagnos*` = diagnose, diagnosed, diagnosis).
2. No score names or marks: the watch makers' and training-software vendors' product names
   (Readiness, Recovery as a score name, Body Battery, TSS, CTL, ATL, TSB). The lowercase common
   word "recovery" in prose is fine; the capitalised score-name forms are not.
3. A string naming a vendor's own figure says ", vendor" after plain words (`Daily preparedness,
   vendor`, `Rest time, vendor`); it is not exempt from the score lists (the exemption was dropped 2026-10-06).
4. A negation may name a banned word only as an exact sentence in the `allow` block (the lint removes
   those sentences, then matches). Prefer rewording; allow only "do not diagnose" style lines.

Scope (authored strings only): this repository's `README.md`; the shell's `src/*.ts`, `index.html` and
`README.md`; the Rust core's identity module (`core/src/identity.rs`) and every coach module (`app/src-tauri/src/coach/*.rs`,
the system prompt included).
**Not in scope**, on purpose: the contract (`contract.json`), `mcp.json` and the Rust read paths carry
contract labels ("Body battery", "Training readiness"), a known debt (renaming breaks the parity
fixtures); test files and docs discuss these words.

```terms medical-verbs
diagnos*
treat*
cure*
prescri*
prevent* disease*
prevent* illness*
screen* for
detect* a condition
detect* disease*
heal
healing
```
```terms medical-nouns
disease*
disorder*
condition*
symptom*
patient*
clinic*
medical*
medicine*
illness*
therap*
arrhythmia*
atrial fibrillation
apnea
hypertension
depression
anxiety
diabetes
diabetic
```
```terms score-marks
Body Battery
Recovery score
Training Readiness
```
```terms score-names case
Readiness
Recovery
TSS
CTL
ATL
TSB
```
```allow
This describes patterns in your own data. It is not medical advice, a diagnosis or a treatment plan.
They describe; they do not diagnose.
```
