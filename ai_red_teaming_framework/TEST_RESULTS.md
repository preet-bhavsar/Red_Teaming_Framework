# RedLens — Test Results & Metric Reconciliation

## Test setup

- Input: `data/raw_results.csv` — the real, unmodified 288 model responses
  from your last full 288/288 run (72 prompts × 4 mutations), re-analyzed
  with the fixed pipeline.
- `python3 test_owasp.py` and `python3 test_owasp_metrics.py` — **PASS**
  (unchanged, run against the fixed `owasp_mapper.py`).
- `python3 test_metrics.py` — **PASS (50/50 checks)**, new unit test
  suite for `src/metrics.py` covering the exact reported bug scenario,
  zero-denominator edge cases, Security Score clamping, category/result
  aliasing, and the severity matrix. See "Automated unit tests" section
  below for the full breakdown.
- Full reconciliation script:

```python
from src.analyzer import analyze_results
from src import metrics, trend_tracker
from src.report_generator import generate_pdf_report
import pandas as pd
from pathlib import Path

# Backend: re-run classification (no live Ollama needed — raw responses
# already exist)
analyze_results(Path("data/raw_results.csv"), Path("results_regenerated.csv"))
df = pd.read_csv("results_regenerated.csv")

# Backend stats (single source of truth)
stats = metrics.compute_stats(df)

# History
trend_tracker.record_run(df, model_version="mistral:latest",
                          run_label="verify-run",
                          history_path=Path("run_history.csv"),
                          runtime_seconds=2471.82)
hist = pd.read_csv("run_history.csv").iloc[-1]

# Dashboard uses the same stats dict (compute_core_stats delegates to
# metrics.compute_stats)

# PDF — both with dashboard-precomputed score and via its own fallback
generate_pdf_report(df, extra={"score": stats["security_score"]})
generate_pdf_report(df)  # fallback path, no `score` in extra
```

## 288/288 completion check

| Check | Result |
|---|---|
| Rows produced | 288 / 288 |
| Missing evaluations | 0 |
| Duplicate `attack_id`+`mutation_type` pairs | 0 |
| Classification counts vs. your original `data/results.csv` | Identical (143/10/95/40/0) |

## Metric reconciliation — one run, all components

| Metric | Backend (`metrics.compute_stats`) | CSV (`results.csv`, recount) | Dashboard (`compute_core_stats`) | History (`run_history.csv`) | PDF |
|---|---|---|---|---|---|
| Total evaluations | 288 | 288 | 288 | 288 | 288 |
| Harmful total | 248 | 248 | 248 | 248 | 248 (card sum) |
| Benign total | 40 | 40 | 40 | 40 | — |
| Bypassed | 143 | 143 | 143 | 143 | 143 ("Successful" card) |
| Partial | 10 | 10 | 10 | 10 | 10 ("Partial" card) |
| Blocked | 95 | 95 | 95 | 95 | 95 ("Blocked" card) |
| Benign Pass (passed) | 40 | 40 | 40 | 40 | — |
| Over-Refusal | 0 | 0 | 0 | 0 | — |
| ASR | 57.66% | 57.66% | 57.66% | 57.66% | 57.7% ("Success Rate" card) |
| Block Rate | 38.31% | 38.31% | 38.31% | 38.31% | (shown in narrative) |
| Partial Rate | 4.03% | 4.03% | 4.03% | 4.03% | (shown in narrative) |
| Benign Pass Rate | 100.0% | 100.0% | 100.0% | 100.0% | — |
| Over-Refusal Rate | 0.0% | 0.0% | 0.0% | 0.0% | — |
| **Security Score** | **56.01** | **56.01** | **56.01** | **56.01** | **56.0 / 100** |
| Critical | 21 | 21 | 21 | — | 21 |
| High | 112 | 112 | 112 | — | 112 |
| Medium | 10 | 10 | 10 | — | 10 |
| Safe / Info (LOW+INFO) | 145 | 145 | 145 | — | 145 |
| OWASP: LLM01 (Prompt Injection) | 100 rows, ASR 61.0% | same | same | same (history JSON) | same |
| OWASP: LLM02 (Sensitive Info Disclosure) | 44 rows, ASR 81.82% | same | same | same | same |
| OWASP: LLM09 (Misinformation) | 12 rows, ASR 83.33% | same | same | same | same |
| OWASP: Unmapped | 132 rows | same | same | same | same |
| OWASP categories tested | 3 / 10 | — | 3 / 10 | — | 3 / 10 |
| Runtime | 2471.82s (passed through) | — | — | 2471.82s | 2471.82s |

**Every value agrees across all five views.** Before the fix, Security
Score alone diverged: Dashboard/PDF = 38.3 vs. History = 56.01 for this
exact run — now all four show 56.01 (PDF displays it rounded to 1 decimal:
56.0).

## Before / after — the headline bug, reproduced exactly

Using your reported numbers (143 Bypassed / 10 Partial / 95 Blocked / 40
Benign):

| | Before | After |
|---|---|---|
| PDF "Successful" | 153 (143+10, partial folded in) | 143 |
| PDF "Partial" | *(not shown)* | 10 |
| PDF Security Score | 38.3 | 56.0 |
| History Security Score | 56.01 | 56.01 |
| Match? | ❌ | ✅ |

## Category / OWASP fragmentation fix (Problem 10)

Before: `category_asr` in `run_history.csv` contained both `"weapon":
37.5` and `"weapons": 0.0` as separate keys (1 dataset row for "weapons"
skewing its own bucket to 0%). After: a single `"weapon": 31.82` entry
covering all 44 evaluated rows for that real-world category, consistently
used by the dashboard's per-category risk buckets, the PDF's category
chart, and history's `category_asr`.

## Severity fix (Problem 11)

Before, for the same 288 rows, the PDF and dashboard could disagree on
individual rows' severity (e.g. `cybercrime` CRITICAL in PDF vs. HIGH on
dashboard). After, both use `metrics.get_severity()`:
`CRITICAL=21, HIGH=112, MEDIUM=10, LOW=10, INFO=135` — identical in both
places (confirmed by extracting the PDF's rendered "Findings Summary"
panel: `21 / 112 / 10 / 145` where 145 = LOW+INFO).

## Automated unit tests (`test_metrics.py`)

```
$ python3 test_metrics.py
Running metrics.py unit tests
----------------------------------------
test_reported_bug_scenario ...
test_empty_dataframe ...
test_no_harmful_rows ...
test_no_benign_rows ...
test_missing_columns ...
test_score_clamping ...
test_partial_alias ...
test_category_alias_weapon_weapons ...
test_per_category_asr_excludes_partial ...
test_severity_matrix ...
test_real_data_if_present ...
----------------------------------------
PASSED: 50   FAILED: 0

ALL TESTS PASSED
```

Coverage:

| Test | What it guards against |
|---|---|
| `test_reported_bug_scenario` | Reproduces your exact 143/10/95/40 numbers; asserts bypassed=143 (not 153), security_score=56.01 (not 38.3) |
| `test_empty_dataframe` / `test_no_harmful_rows` / `test_no_benign_rows` | Division-by-zero / NaN on edge-case inputs |
| `test_missing_columns` | Crash-safety when a df lacks `result`/`prompt_type`/`category` |
| `test_score_clamping` | Security Score never goes below 0 or above 100 |
| `test_partial_alias` | `"partial"` and `"partial_compliance"` classify identically |
| `test_category_alias_weapon_weapons` | The dataset's `weapon`/`weapons` spelling split stays merged |
| `test_per_category_asr_excludes_partial` | Per-category ASR uses bypassed-only, not bypassed+partial (the exact bug that was in `trend_tracker._per_category_asr`) |
| `test_severity_matrix` | Full severity table, including the old `cybercrime` HIGH-vs-CRITICAL PDF/dashboard mismatch |
| `test_real_data_if_present` | Sanity check against your actual `data/results.csv` |

## Known, documented limitation

- No live Ollama connection in this environment, so `src/attack_runner.py`
  itself (the HTTP calls to the model) could not be exercised end-to-end
  here. It was not modified. Everything downstream of a raw model
  response — classification, OWASP mapping, severity, rates, Security
  Score, history, dashboard, PDF — was fully tested against your real
  288-row raw output.
- 7 categories (`benign`, `weapon`, `fraud`, `social_engineering`,
  `drugs`, `violence`, `crime` — 132 rows total) remain OWASP-unmapped.
  This is correct: none of the OWASP LLM Top 10 categories genuinely
  covers these as a *technical LLM vulnerability class* — mapping them
  would be fabricated. See Problem 10 in `FINAL_VERIFICATION.md`.
