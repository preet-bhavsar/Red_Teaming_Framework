from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

from .utils import RUN_HISTORY_PATH, ensure_dir, is_empty_csv_file
from . import metrics as _metrics

log = logging.getLogger(__name__)


# ============================================================
# HISTORY COLUMNS
# ============================================================

HISTORY_COLUMNS = [
    "run_id",
    "timestamp",
    "model_version",
    "run_label",
    "total",
    "harmful",
    "benign",
    "blocked",
    "partial",
    "bypassed",
    "asr",
    "block_rate",
    "partial_rate",
    "benign_pass_rate",
    "over_refusal_rate",
    "security_score",
    "runtime_seconds",
    "category_asr",
    "mutation_asr",
    "mutation_metrics",
    "owasp_metrics",
]


# ============================================================
# BASIC HELPERS
# ============================================================

def _safe_bool_series(s: pd.Series) -> pd.Series:
    """Convert common boolean representations into True/False."""

    if s.dtype == bool:
        return s.fillna(False)

    if pd.api.types.is_numeric_dtype(s):
        return (
            s.fillna(0)
            .astype(int)
            .astype(bool)
        )

    return (
        s.astype(str)
        .str.strip()
        .str.lower()
        .isin({
            "1",
            "true",
            "t",
            "yes",
            "y",
        })
    )


def _get_harmful_mask(df: pd.DataFrame) -> pd.Series:
    """Return rows classified as harmful. Delegates to metrics.py (single
    source of truth) — kept as a thin wrapper so the rest of this file
    doesn't need to change."""
    return _metrics.harmful_mask(df)


def _get_benign_mask(df: pd.DataFrame) -> pd.Series:
    """Return rows classified as benign. Delegates to metrics.py."""
    return _metrics.benign_mask(df)


def _is_partial_result(
    series: pd.Series,
) -> pd.Series:
    """
    Detect partial-compliance results.

    Supports multiple naming conventions. Delegates to metrics.py.
    """
    return _metrics.is_partial(series)


# ============================================================
# CATEGORY ASR
# ============================================================

def _per_category_asr(
    df: pd.DataFrame,
) -> dict:
    """
    Calculate ASR separately for each harmful category.

    Benign prompts are excluded.

    FIX (Problem 14): this used to compute "success" from the
    `attack_success` boolean column, which is True for BOTH "bypassed"
    and "partial_compliance" rows. That made this function disagree with
    every other ASR figure in the same run_history.csv row (overall ASR,
    mutation ASR, OWASP ASR), all of which correctly count only
    "bypassed" as an attack success. Now delegates to metrics.py so the
    definition is identical everywhere.
    """

    required = {
        "category",
        "result",
    }

    if not required.issubset(
        df.columns
    ):
        return {}

    return _metrics.per_category_asr(df)


# ============================================================
# MUTATION METRICS
# ============================================================

def _mutation_metrics(
    df: pd.DataFrame,
) -> dict:
    """
    Calculate security metrics for
    every mutation technique.
    """

    if "mutation_type" not in df.columns:
        return {}

    if "result" not in df.columns:
        return {}

    output = {}

    for mutation, group in df.groupby(
        df["mutation_type"].astype(str)
    ):
        mutation = str(mutation)

        harmful = group[
            _get_harmful_mask(group)
        ]

        benign = group[
            _get_benign_mask(group)
        ]

        harmful_total = len(harmful)
        benign_total = len(benign)

        result_values = (
            group["result"]
            .astype(str)
            .str.strip()
            .str.lower()
        )

        blocked = int(
            result_values
            .loc[harmful.index]
            .eq("blocked")
            .sum()
        )

        partial = int(
            _is_partial_result(
                group["result"]
            )
            .loc[harmful.index]
            .sum()
        )

        bypassed = int(
            result_values
            .loc[harmful.index]
            .eq("bypassed")
            .sum()
        )

        passed = int(
            result_values
            .loc[benign.index]
            .eq("passed")
            .sum()
        )

        over_refused = int(
            result_values
            .loc[benign.index]
            .eq("over_refused")
            .sum()
        )

        asr = (
            bypassed
            / harmful_total
            * 100
            if harmful_total
            else 0.0
        )

        block_rate = (
            blocked
            / harmful_total
            * 100
            if harmful_total
            else 0.0
        )

        partial_rate = (
            partial
            / harmful_total
            * 100
            if harmful_total
            else 0.0
        )

        benign_pass_rate = (
            passed
            / benign_total
            * 100
            if benign_total
            else 0.0
        )

        over_refusal_rate = (
            over_refused
            / benign_total
            * 100
            if benign_total
            else 0.0
        )

        output[mutation] = {
            "total": len(group),
            "harmful": harmful_total,
            "benign": benign_total,
            "blocked": blocked,
            "partial": partial,
            "bypassed": bypassed,
            "passed": passed,
            "over_refused": over_refused,
            "asr": round(asr, 2),
            "block_rate": round(
                block_rate,
                2,
            ),
            "partial_rate": round(
                partial_rate,
                2,
            ),
            "benign_pass_rate": round(
                benign_pass_rate,
                2,
            ),
            "over_refusal_rate": round(
                over_refusal_rate,
                2,
            ),
        }

    return output


# ============================================================
# OWASP LLM METRICS
# ============================================================

def _owasp_metrics(
    df: pd.DataFrame,
) -> dict:
    """
    Calculate OWASP LLM Top 10 metrics.

    Expected columns in results.csv:

        owasp_id
        owasp_category
        prompt_type
        result

    ASR is calculated as:

        bypassed harmful prompts
        ------------------------
        total harmful prompts

    Example:

        {
            "LLM01": {
                "owasp_category": "Prompt Injection",
                "total": 100,
                "harmful": 90,
                "blocked": 60,
                "partial": 0,
                "bypassed": 30,
                "asr": 33.33,
                "block_rate": 66.67
            }
        }
    """

    required = {
        "owasp_id",
        "result",
    }

    if not required.issubset(
        df.columns
    ):
        log.warning(
            "OWASP columns not found in results. "
            "OWASP metrics will be empty."
        )
        return {}

    result_values = (
        df["result"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    output = {}

    # Group by OWASP ID
    for owasp_id, group in df.groupby(
        df["owasp_id"].astype(str)
    ):

        owasp_id = str(owasp_id).strip()

        if (
            not owasp_id
            or owasp_id.lower()
            in {
                "nan",
                "none",
                "unknown",
            }
        ):
            continue

        harmful = group[
            _get_harmful_mask(group)
        ]

        benign = group[
            _get_benign_mask(group)
        ]

        harmful_total = len(harmful)
        benign_total = len(benign)

        if "owasp_category" in group.columns:

            categories = (
                group["owasp_category"]
                .dropna()
                .astype(str)
                .str.strip()
                .unique()
                .tolist()
            )

            if categories:
                owasp_category = categories[0]
            else:
                owasp_category = "Unknown"

        else:
            owasp_category = "Unknown"

        harmful_results = result_values.loc[
            harmful.index
        ]

        blocked = int(
            harmful_results
            .eq("blocked")
            .sum()
        )

        partial = int(
            _is_partial_result(
                group["result"]
            )
            .loc[harmful.index]
            .sum()
        )

        bypassed = int(
            harmful_results
            .eq("bypassed")
            .sum()
        )

        passed = int(
            result_values
            .loc[benign.index]
            .eq("passed")
            .sum()
        )

        over_refused = int(
            result_values
            .loc[benign.index]
            .eq("over_refused")
            .sum()
        )

        asr = (
            bypassed
            / harmful_total
            * 100
            if harmful_total
            else 0.0
        )

        block_rate = (
            blocked
            / harmful_total
            * 100
            if harmful_total
            else 0.0
        )

        partial_rate = (
            partial
            / harmful_total
            * 100
            if harmful_total
            else 0.0
        )

        benign_pass_rate = (
            passed
            / benign_total
            * 100
            if benign_total
            else 0.0
        )

        over_refusal_rate = (
            over_refused
            / benign_total
            * 100
            if benign_total
            else 0.0
        )

        output[owasp_id] = {
            "owasp_category": owasp_category,
            "total": len(group),
            "harmful": harmful_total,
            "benign": benign_total,
            "blocked": blocked,
            "partial": partial,
            "bypassed": bypassed,
            "passed": passed,
            "over_refused": over_refused,
            "asr": round(asr, 2),
            "block_rate": round(
                block_rate,
                2,
            ),
            "partial_rate": round(
                partial_rate,
                2,
            ),
            "benign_pass_rate": round(
                benign_pass_rate,
                2,
            ),
            "over_refusal_rate": round(
                over_refusal_rate,
                2,
            ),
        }

    return output


# ============================================================
# SECURITY SCORE
# ============================================================

def _calculate_security_score(
    block_rate: float,
    benign_pass_rate: float,
    partial_rate: float,
    over_refusal_rate: float,
) -> float:
    """
    Calculate standardized RedLens Security Score.

    Delegates to metrics.calculate_security_score() — the single
    authoritative implementation, also used by the dashboard and PDF
    report, so all three can never compute a different score for the
    same run again. See metrics.py for the formula and rationale.
    """
    return _metrics.calculate_security_score(
        block_rate=block_rate,
        benign_pass_rate=benign_pass_rate,
        partial_rate=partial_rate,
        over_refusal_rate=over_refusal_rate,
    )


# ============================================================
# RECORD RUN
# ============================================================

def record_run(
    results_df: pd.DataFrame,
    model_version: str = "unknown",
    run_label: str = "run",
    history_path: Optional[Path] = None,
    runtime_seconds: Optional[float] = None,
) -> Path:
    """
    Append one complete RedLens experiment
    to run_history.csv.

    Includes:

        - overall metrics
        - category ASR
        - mutation ASR
        - mutation metrics
        - OWASP LLM Top 10 metrics
        - standardized security score
    """

    if history_path is None:
        history_path = RUN_HISTORY_PATH

    total = len(results_df)

    harmful_mask = _get_harmful_mask(
        results_df
    )

    benign_mask = _get_benign_mask(
        results_df
    )

    harmful = results_df[
        harmful_mask
    ]

    benign = results_df[
        benign_mask
    ]

    harmful_count = len(harmful)
    benign_count = len(benign)

    if "result" in results_df.columns:

        result_series = (
            results_df["result"]
            .astype(str)
            .str.strip()
            .str.lower()
        )

    else:

        result_series = pd.Series(
            "",
            index=results_df.index,
        )

    blocked = int(
        result_series
        .eq("blocked")
        .sum()
    )

    partial = (
        int(
            _is_partial_result(
                results_df["result"]
            ).sum()
        )
        if "result" in results_df.columns
        else 0
    )

    bypassed = int(
        result_series
        .eq("bypassed")
        .sum()
    )

    passed = int(
        result_series
        .eq("passed")
        .sum()
    )

    over_refused = int(
        result_series
        .eq("over_refused")
        .sum()
    )

    # --------------------------------------------------------
    # Overall metrics
    # --------------------------------------------------------

    asr = (
        bypassed
        / harmful_count
        * 100
        if harmful_count
        else 0.0
    )

    block_rate = (
        blocked
        / harmful_count
        * 100
        if harmful_count
        else 0.0
    )

    partial_rate = (
        partial
        / harmful_count
        * 100
        if harmful_count
        else 0.0
    )

    benign_pass_rate = (
        passed
        / benign_count
        * 100
        if benign_count
        else 0.0
    )

    over_refusal_rate = (
        over_refused
        / benign_count
        * 100
        if benign_count
        else 0.0
    )

    # --------------------------------------------------------
    # Security score
    # --------------------------------------------------------

    security_score = _calculate_security_score(
        block_rate=block_rate,
        benign_pass_rate=benign_pass_rate,
        partial_rate=partial_rate,
        over_refusal_rate=over_refusal_rate,
    )

    # --------------------------------------------------------
    # Category metrics
    # --------------------------------------------------------

    category_asr = _per_category_asr(
        results_df
    )

    # --------------------------------------------------------
    # Mutation metrics
    # --------------------------------------------------------

    mutation_metrics = _mutation_metrics(
        results_df
    )

    mutation_asr = {
        mutation: metrics["asr"]
        for mutation, metrics
        in mutation_metrics.items()
    }

    # --------------------------------------------------------
    # OWASP metrics
    # --------------------------------------------------------

    owasp_metrics = _owasp_metrics(
        results_df
    )

    # --------------------------------------------------------
    # Run information
    # --------------------------------------------------------

    now = datetime.now(
        timezone.utc
    )

    run_id = now.strftime(
        "run_%Y%m%dT%H%M%S"
    )

    row = {
        "run_id": run_id,
        "timestamp": now.isoformat(),
        "model_version": model_version,
        "run_label": run_label,

        "total": total,
        "harmful": harmful_count,
        "benign": benign_count,

        "blocked": blocked,
        "partial": partial,
        "bypassed": bypassed,

        "asr": round(
            asr,
            2,
        ),

        "block_rate": round(
            block_rate,
            2,
        ),

        "partial_rate": round(
            partial_rate,
            2,
        ),

        "benign_pass_rate": round(
            benign_pass_rate,
            2,
        ),

        "over_refusal_rate": round(
            over_refusal_rate,
            2,
        ),

        "security_score": security_score,
        "runtime_seconds": round(float(runtime_seconds), 2) if runtime_seconds is not None else None,

        "category_asr": json.dumps(
            category_asr
        ),

        "mutation_asr": json.dumps(
            mutation_asr
        ),

        "mutation_metrics": json.dumps(
            mutation_metrics
        ),

        "owasp_metrics": json.dumps(
            owasp_metrics
        ),
    }

    # --------------------------------------------------------
    # Save history
    # --------------------------------------------------------

    ensure_dir(
        history_path.parent
    )

    if history_path.exists() and not is_empty_csv_file(history_path):

        history_df = pd.read_csv(
            history_path
        )

        # Add any new columns to old history.
        for column in HISTORY_COLUMNS:

            if column not in history_df.columns:

                history_df[column] = None

        # Remove unexpected columns from
        # the historical file and maintain
        # the standard order.
        history_df = history_df[
            [
                column
                for column in HISTORY_COLUMNS
            ]
        ]

        history_df = pd.concat(
            [
                history_df,
                pd.DataFrame([row]),
            ],
            ignore_index=True,
        )

    else:

        history_df = pd.DataFrame(
            [row],
            columns=HISTORY_COLUMNS,
        )

    history_df.to_csv(
        history_path,
        index=False,
    )

    # --------------------------------------------------------
    # Console summary
    # --------------------------------------------------------

    log.info(
        "----------------------------------------"
    )

    log.info(
        "RedLens Trend Analysis"
    )

    log.info(
        "----------------------------------------"
    )

    log.info(
        "Run=%s | Model=%s | Label=%s",
        run_id,
        model_version,
        run_label,
    )

    log.info(
        "Total=%d | Harmful=%d | Benign=%d",
        total,
        harmful_count,
        benign_count,
    )

    log.info(
        "Blocked=%d | Partial=%d | Bypassed=%d",
        blocked,
        partial,
        bypassed,
    )

    log.info(
        "ASR=%.2f%% | Block Rate=%.2f%%",
        asr,
        block_rate,
    )

    log.info(
        "Benign Pass=%.2f%% | Over-Refusal=%.2f%%",
        benign_pass_rate,
        over_refusal_rate,
    )

    log.info(
        "Security Score=%.2f/100",
        security_score,
    )

    log.info(
        "Score Components | "
        "Block=%.2f%% | "
        "Benign Pass=%.2f%% | "
        "Partial=%.2f%% | "
        "Over-Refusal=%.2f%%",
        block_rate,
        benign_pass_rate,
        partial_rate,
        over_refusal_rate,
    )

    # --------------------------------------------------------
    # OWASP console summary
    # --------------------------------------------------------

    if owasp_metrics:

        log.info(
            "----------------------------------------"
        )

        log.info(
            "OWASP LLM Top 10 Analysis"
        )

        log.info(
            "----------------------------------------"
        )

        for owasp_id, metrics in (
            owasp_metrics.items()
        ):

            log.info(
                "%s | %s | "
                "Tests=%d | "
                "ASR=%.2f%% | "
                "Block Rate=%.2f%%",
                owasp_id,
                metrics["owasp_category"],
                metrics["total"],
                metrics["asr"],
                metrics["block_rate"],
            )

    else:

        log.warning(
            "No OWASP metrics recorded. "
            "Check that results.csv contains "
            "'owasp_id' and 'owasp_category'."
        )

    # --------------------------------------------------------
    # Mutation summary
    # --------------------------------------------------------

    if mutation_metrics:

        log.info(
            "----------------------------------------"
        )

        log.info(
            "Mutation Technique Analysis"
        )

        log.info(
            "----------------------------------------"
        )

        for mutation, metrics in (
            mutation_metrics.items()
        ):

            log.info(
                "%s | Tests=%d | "
                "ASR=%.2f%% | "
                "Block Rate=%.2f%% | "
                "Partial=%.2f%%",
                mutation,
                metrics["total"],
                metrics["asr"],
                metrics["block_rate"],
                metrics["partial_rate"],
            )

        most_effective = max(
            mutation_metrics.items(),
            key=lambda item:
            item[1]["asr"],
        )

        least_effective = min(
            mutation_metrics.items(),
            key=lambda item:
            item[1]["asr"],
        )

        log.info(
            "Most effective mutation: %s "
            "(ASR=%.2f%%)",
            most_effective[0],
            most_effective[1]["asr"],
        )

        log.info(
            "Least effective mutation: %s "
            "(ASR=%.2f%%)",
            least_effective[0],
            least_effective[1]["asr"],
        )

    log.info(
        "----------------------------------------"
    )

    log.info(
        "History saved to %s",
        history_path,
    )

    return history_path


# ============================================================
# JSON PARSER
# ============================================================

def _parse_json(
    value,
):
    """Safely parse a JSON string."""

    if not isinstance(
        value,
        str,
    ):
        return {}

    value = value.strip()

    if not value:
        return {}

    try:
        return json.loads(value)

    except (
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return {}


# ============================================================
# LOAD HISTORY
# ============================================================

def load_run_history(
    history_path: Optional[Path] = None,
) -> pd.DataFrame:
    """
    Load run_history.csv and parse
    all JSON metric columns.
    """

    if history_path is None:
        history_path = RUN_HISTORY_PATH

    if is_empty_csv_file(history_path):

        # No runs yet (missing file) or a stale 0-byte file left
        # over from an interrupted write — both mean "no history",
        # not a parse error.
        return pd.DataFrame(
            columns=HISTORY_COLUMNS
        )

    df = pd.read_csv(
        history_path
    )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    if "timestamp" in df.columns:

        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce",
        )

    # --------------------------------------------------------
    # Category metrics
    # --------------------------------------------------------

    if "category_asr" in df.columns:

        df[
            "category_asr_dict"
        ] = (
            df["category_asr"]
            .apply(_parse_json)
        )

    # --------------------------------------------------------
    # Mutation ASR
    # --------------------------------------------------------

    if "mutation_asr" in df.columns:

        df[
            "mutation_asr_dict"
        ] = (
            df["mutation_asr"]
            .apply(_parse_json)
        )

    # --------------------------------------------------------
    # Mutation metrics
    # --------------------------------------------------------

    if "mutation_metrics" in df.columns:

        df[
            "mutation_metrics_dict"
        ] = (
            df["mutation_metrics"]
            .apply(_parse_json)
        )

    # --------------------------------------------------------
    # OWASP metrics
    # --------------------------------------------------------

    if "owasp_metrics" in df.columns:

        df[
            "owasp_metrics_dict"
        ] = (
            df["owasp_metrics"]
            .apply(_parse_json)
        )

    # --------------------------------------------------------
    # Sort history
    # --------------------------------------------------------

    if "timestamp" in df.columns:

        df = df.sort_values(
            "timestamp"
        )

    return df.reset_index(
        drop=True
    )


# ============================================================
# MUTATION TREND FRAME
# ============================================================

def mutation_trend_frame(
    history_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Convert mutation metrics into a
    dashboard-friendly long-format DataFrame.
    """

    columns = [
        "run_id",
        "timestamp",
        "model_version",
        "run_label",
        "mutation_type",
        "total",
        "harmful",
        "benign",
        "blocked",
        "partial",
        "bypassed",
        "asr",
        "block_rate",
        "partial_rate",
        "benign_pass_rate",
        "over_refusal_rate",
    ]

    if history_df.empty:

        return pd.DataFrame(
            columns=columns
        )

    if (
        "mutation_metrics_dict"
        not in history_df.columns
    ):

        return pd.DataFrame(
            columns=columns
        )

    records = []

    for _, row in (
        history_df.iterrows()
    ):

        metrics_map = (
            row.get(
                "mutation_metrics_dict"
            )
            or {}
        )

        for mutation, metrics in (
            metrics_map.items()
        ):

            records.append(
                {
                    "run_id": row[
                        "run_id"
                    ],

                    "timestamp": row[
                        "timestamp"
                    ],

                    "model_version": row[
                        "model_version"
                    ],

                    "run_label": row[
                        "run_label"
                    ],

                    "mutation_type": mutation,

                    **metrics,
                }
            )

    return pd.DataFrame.from_records(
        records,
        columns=columns,
    )


# ============================================================
# CATEGORY TREND FRAME
# ============================================================

def category_trend_frame(
    history_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Convert category ASR dictionaries into
    dashboard-friendly long-format DataFrame.
    """

    columns = [
        "run_id",
        "timestamp",
        "model_version",
        "run_label",
        "category",
        "asr",
    ]

    if history_df.empty:

        return pd.DataFrame(
            columns=columns
        )

    if (
        "category_asr_dict"
        not in history_df.columns
    ):

        return pd.DataFrame(
            columns=columns
        )

    records = []

    for _, row in (
        history_df.iterrows()
    ):

        category_map = (
            row.get(
                "category_asr_dict"
            )
            or {}
        )

        for category, asr in (
            category_map.items()
        ):

            records.append(
                {
                    "run_id": row[
                        "run_id"
                    ],

                    "timestamp": row[
                        "timestamp"
                    ],

                    "model_version": row[
                        "model_version"
                    ],

                    "run_label": row[
                        "run_label"
                    ],

                    "category": category,

                    "asr": asr,
                }
            )

    return pd.DataFrame.from_records(
        records,
        columns=columns,
    )


# ============================================================
# OWASP TREND FRAME
# ============================================================

def owasp_trend_frame(
    history_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Convert OWASP metrics into a
    dashboard-friendly long-format DataFrame.

    Output columns:

        run_id
        timestamp
        model_version
        run_label
        owasp_id
        owasp_category
        total
        harmful
        benign
        blocked
        partial
        bypassed
        passed
        over_refused
        asr
        block_rate
        partial_rate
        benign_pass_rate
        over_refusal_rate
    """

    columns = [
        "run_id",
        "timestamp",
        "model_version",
        "run_label",
        "owasp_id",
        "owasp_category",
        "total",
        "harmful",
        "benign",
        "blocked",
        "partial",
        "bypassed",
        "passed",
        "over_refused",
        "asr",
        "block_rate",
        "partial_rate",
        "benign_pass_rate",
        "over_refusal_rate",
    ]

    if history_df.empty:

        return pd.DataFrame(
            columns=columns
        )

    if (
        "owasp_metrics_dict"
        not in history_df.columns
    ):

        return pd.DataFrame(
            columns=columns
        )

    records = []

    for _, row in (
        history_df.iterrows()
    ):

        metrics_map = (
            row.get(
                "owasp_metrics_dict"
            )
            or {}
        )

        for owasp_id, metrics in (
            metrics_map.items()
        ):

            records.append(
                {
                    "run_id": row[
                        "run_id"
                    ],

                    "timestamp": row[
                        "timestamp"
                    ],

                    "model_version": row[
                        "model_version"
                    ],

                    "run_label": row[
                        "run_label"
                    ],

                    "owasp_id": owasp_id,

                    **metrics,
                }
            )

    return pd.DataFrame.from_records(
        records,
        columns=columns,
    )