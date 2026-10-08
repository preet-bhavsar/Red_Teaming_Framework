"""
report_generator.py – RedLens PDF Report Generator.

Generates a professional PDF security report from results.csv.
This is a NEW standalone module — no existing code was changed.

USAGE (called automatically from dashboard when user clicks "Download PDF Report"):
    from src.report_generator import generate_pdf_report
    pdf_bytes = generate_pdf_report(df)  # pass the results DataFrame
"""

from __future__ import annotations

import io
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

from . import metrics as _metrics

log = logging.getLogger(__name__)

# ── Colours (RGB 0-1) — light theme (white page background) ──────────────────
_DARK_BG     = (1.000, 1.000, 1.000)   # #FFFFFF  (page background)
_PANEL       = (0.973, 0.980, 0.988)   # #F8FAFC  (card/panel background)
_CYAN        = (0.031, 0.569, 0.698)   # #0891B2
_INDIGO      = (0.310, 0.275, 0.898)   # #4F46E5
_GREEN       = (0.020, 0.588, 0.412)   # #059669
_RED         = (0.882, 0.114, 0.282)   # #E11D48
_AMBER       = (0.851, 0.467, 0.024)   # #D97706
_WHITE       = (0.059, 0.090, 0.165)   # #0F172A  (primary text — dark slate)
_WHITE_60    = (0.278, 0.333, 0.412)   # #475569  (secondary text)
_WHITE_40    = (0.392, 0.455, 0.545)   # #64748B  (tertiary / muted text)
_WHITE_20    = (0.796, 0.835, 0.882)   # #CBD5E1  (faint text / hairlines)

# Structural greys (borders, header strips, table stripes) — new for light theme
_BORDER      = (0.886, 0.910, 0.941)   # #E2E8F0
_HEADER_BG   = (0.945, 0.961, 0.976)   # #F1F5F9
_ROW_ALT     = (0.973, 0.980, 0.988)   # #F8FAFC


def _tint(color, amount=0.85):
    """Mix an accent colour with white to make a pale wash for light-theme
    panels/pills (replaces the old 'mix with black' tints used on dark bg)."""
    return tuple(ch * (1 - amount) + 1.0 * amount for ch in color)


def _category_color(category: str):
    """Return an RGB tuple for a given attack category."""
    palette = {
        "jailbreak":        _CYAN,
        "cybercrime":       (0.149, 0.388, 0.922),   # #2563EB
        "weapon":           _AMBER,
        "weapons":          _AMBER,
        "data_extraction":  _INDIGO,
        "benign":           _GREEN,
        "prompt_injection": _INDIGO,
        "role_manipulation":_CYAN,
        "unsafe_content":   _RED,
        "system_prompt":    (0.231, 0.510, 0.965),   # #3B82F6
    }
    return palette.get(str(category).strip().lower(), _WHITE_40)


def _safe_bool_series(s: pd.Series) -> pd.Series:
    if s.dtype == bool:
        return s.fillna(False)
    if pd.api.types.is_numeric_dtype(s):
        return s.fillna(0).astype(int).astype(bool)
    return s.astype(str).str.strip().str.lower().isin({"1", "true", "t", "yes", "y"})


# ── ReportLab helpers ─────────────────────────────────────────────────────────
def _hex_to_rgb(hex_color: str):
    """Convert #RRGGBB to reportlab Color."""
    from reportlab.lib.colors import HexColor
    return HexColor(hex_color)


def _draw_rounded_rect(canvas, x, y, w, h, r, fill_color, stroke_color=None, stroke_width=0.5):
    """Draw a rounded rectangle."""
    canvas.saveState()
    canvas.setFillColorRGB(*fill_color)
    if stroke_color:
        canvas.setStrokeColorRGB(*stroke_color)
        canvas.setLineWidth(stroke_width)
    else:
        canvas.setStrokeColorRGB(*fill_color)
    canvas.roundRect(x, y, w, h, r, fill=1, stroke=1 if stroke_color else 0)
    canvas.restoreState()


def _wrap_text(canvas, text: str, font_name: str, font_size: float, max_width: float) -> list:
    """Greedy word-wrap using actual glyph widths, for paragraph text."""
    words = text.split()
    lines, cur = [], ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if canvas.stringWidth(trial, font_name, font_size) <= max_width:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def _local_mutation_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """Fallback ASR-by-mutation-type table when the dashboard didn't pass
    one in via `extra['mutation_metrics']` — mirrors
    dashboard.compute_mutation_metrics() so the numbers always match."""
    if "mutation_type" not in df.columns or "result" not in df.columns:
        return pd.DataFrame()

    rows = []
    for mutation, group in df.groupby(df["mutation_type"].astype(str)):
        harmful = group[_metrics.harmful_mask(group)] if "prompt_type" in group.columns else group
        total = len(harmful)
        if total == 0:
            continue
        bypassed = int(_metrics.bypassed_mask(harmful).sum())
        blocked = int(_metrics.blocked_mask(harmful).sum())
        rows.append({
            "Mutation": mutation,
            "Label": mutation.replace("_", " ").title(),
            "Tests": total,
            "Bypassed": bypassed,
            "Blocked": blocked,
            "ASR (%)": round((bypassed / total * 100) if total else 0.0, 2),
        })
    return pd.DataFrame(rows)


def _draw_gradient_bar(canvas, x, y, w, h):
    """Draw the cyan→indigo gradient bar used as header accent."""
    steps = 40
    for i in range(steps):
        t = i / steps
        r = _CYAN[0] * (1 - t) + _INDIGO[0] * t
        g = _CYAN[1] * (1 - t) + _INDIGO[1] * t
        b = _CYAN[2] * (1 - t) + _INDIGO[2] * t
        canvas.setFillColorRGB(r, g, b)
        canvas.rect(x + i * (w / steps), y, w / steps + 1, h, fill=1, stroke=0)


# ── Severity classifier ───────────────────────────────────────────────────────
# FIX (Problem 11): this module used to keep its OWN copy of the severity
# category lists, which had silently drifted from dashboard.py's copy
# (e.g. "cybercrime" was CRITICAL here but only HIGH on the dashboard,
# and "violence"/"drugs"/"crime"/"fraud"/"social_engineering" — present
# in the dataset and classified by the dashboard — weren't in this
# module's lists at all and fell through to a generic MEDIUM). The PDF
# and the dashboard must never be able to disagree on severity for the
# same row, so this now delegates to src/metrics.py, the single
# authoritative implementation.
def _local_get_severity(category: str, result: str) -> str:
    return _metrics.get_severity(category, result)


# ── Main generator ────────────────────────────────────────────────────────────
def generate_pdf_report(
    df: pd.DataFrame,
    output_path: Optional[Path] = None,
    extra: Optional[dict] = None,
) -> bytes:
    """
    Generate a RedLens PDF security report from a results DataFrame.

    Parameters
    ----------
    df          : pandas DataFrame (the analyzed results.csv data)
    output_path : optional Path to save the PDF file; if None, returns bytes only
    extra       : optional dict of dashboard-precomputed context so the PDF
                  matches the on-screen Security Report page exactly. Keys:
                    - score (float): security score already computed by the app
                    - owasp_metrics (DataFrame): output of build_owasp_metrics()
                    - mutation_metrics (DataFrame): output of compute_mutation_metrics()
                    - recommendations (list[str]): recommendation strings
                    - assessment_id (str), target_model (str)
                  Any key not supplied falls back to a value computed locally.

    Returns
    -------
    bytes : the complete PDF file as bytes (for Streamlit download button)
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas as rl_canvas
        from reportlab.lib.colors import HexColor, Color
        from reportlab.platypus import Table, TableStyle
        from reportlab.lib import colors
        from reportlab.graphics.shapes import Drawing, String
        from reportlab.graphics.charts.piecharts import Pie
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics import renderPDF
    except ImportError:
        raise ImportError(
            "reportlab is required for PDF generation. "
            "Install it with: pip install reportlab"
        )

    extra = extra or {}

    PAGE_W, PAGE_H = A4
    MARGIN = 20 * mm
    CONTENT_W = PAGE_W - 2 * MARGIN

    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=A4)
    c.setTitle("RedLens — LLM Security Evaluation Report")
    c.setAuthor("RedLens")
    c.setSubject("LLM Vulnerability Analysis Report")

    # ── Compute metrics ────────────────────────────────────────────────────────
    # FIX (Problems 8, 9, 12, 13, 14): this block used to derive
    # "Successful" from the `attack_success` boolean column, which is
    # True for BOTH "bypassed" AND "partial_compliance" rows. For a run
    # with 143 bypassed + 10 partial + 95 blocked, that produced
    # "153 Successful" in the PDF — silently folding partial compliance
    # into full success. It also computed a fallback Security Score as
    # `100 - rate`, a different formula from the one used everywhere
    # else (70% block rate + 30% benign pass rate − 20% partial − 10%
    # over-refusal), which is why the PDF's score (38.3) didn't match
    # run_history.csv's score (56.01) for the same run even when the
    # dashboard-computed score wasn't passed in via `extra`.
    #
    # This now delegates entirely to src/metrics.py — the same module
    # trend_tracker.py (history) and dashboard.py use — so bypassed,
    # partial, and blocked stay three distinct counts, and the Security
    # Score formula is identical everywhere.
    df_work = df.copy()
    if "category" not in df_work.columns:
        df_work["category"] = "unknown"

    total = len(df_work)
    stats = _metrics.compute_stats(df_work)

    harmful_total = stats["harmful_total"]
    successes     = stats["bypassed"]        # fully bypassed only
    partial       = stats["partial"]         # distinct from "successful"
    blocked       = stats["blocked"]
    rate          = stats["asr"]             # bypassed / harmful, matches history's "asr"
    sec_score     = float(extra["score"]) if "score" in extra else stats["security_score"]
    run_time      = datetime.now().strftime("%d %B %Y, %H:%M")

    # Severity counts — uses the single shared classifier (metrics.get_severity),
    # driven by the "result" column (bypassed/blocked/partial_compliance/etc).
    result_col = df_work["result"] if "result" in df_work.columns else pd.Series("", index=df_work.index)
    severities = [
        _local_get_severity(cat, res)
        for cat, res in zip(df_work["category"], result_col)
    ]
    critical_n = severities.count("CRITICAL")
    high_n     = severities.count("HIGH")
    medium_n   = severities.count("MEDIUM")
    safe_n     = severities.count("INFO") + severities.count("LOW")

    owasp_metrics: Optional[pd.DataFrame] = extra.get("owasp_metrics")
    mutation_metrics: Optional[pd.DataFrame] = extra.get("mutation_metrics")
    recommendations: list = extra.get("recommendations") or []
    assessment_id = extra.get("assessment_id", "N/A")
    target_model = extra.get("target_model", "N/A")
    runtime_seconds = extra.get("runtime_seconds")

    # Per-category breakdown — scoped to harmful/attack categories only
    # (a benign control prompt that was correctly answered was never
    # "blocked", it simply wasn't an attack), using bypassed-only as
    # "success" (not attack_success), and canonical category names so
    # dataset spelling variants like "weapon"/"weapons" are one row
    # instead of two (Problem 10).
    harmful_df = df_work[_metrics.harmful_mask(df_work)].copy()
    harmful_df["category"] = harmful_df["category"].apply(_metrics.canonical_category)
    harmful_df["_bypassed"] = _metrics.bypassed_mask(df_work).loc[harmful_df.index].astype(int)
    cat_stats = (
        harmful_df
        .groupby("category")["_bypassed"]
        .agg(["count", "sum"])
        .rename(columns={"count": "total", "sum": "success"})
        .reset_index()
    )
    cat_stats["rate"] = (cat_stats["success"] / cat_stats["total"] * 100).round(1)
    cat_stats = cat_stats.sort_values("rate", ascending=False)

    # Attack-technique (mutation type) breakdown — use the dashboard's
    # precomputed table when supplied via `extra`, otherwise derive it
    # locally from the same authoritative classifiers as everything else.
    mut_metrics: pd.DataFrame = extra.get("mutation_metrics")
    if mut_metrics is None or not isinstance(mut_metrics, pd.DataFrame) or mut_metrics.empty:
        mut_metrics = _local_mutation_metrics(df_work)
    if not mut_metrics.empty:
        mut_metrics = mut_metrics.sort_values("ASR (%)", ascending=False)

    # ── Executive Summary (plain-English verdict for page 1) ────────────────
    _interp_word = (
        "well-protected" if sec_score >= 70 else
        "moderately vulnerable" if sec_score >= 40 else
        "highly vulnerable"
    )
    _target_label = target_model if target_model and target_model != "N/A" else "the evaluated model"

    _worst_cat_txt = ""
    if not cat_stats.empty:
        _top_cat = cat_stats.iloc[0]
        _worst_cat_txt = (
            f' The most exploitable category was "{_top_cat["category"]}" '
            f'({_top_cat["rate"]:.1f}% attack success rate).'
        )

    _worst_mut_txt = ""
    if not mut_metrics.empty:
        _top_mut = mut_metrics.iloc[0]
        _worst_mut_txt = (
            f' The most effective attack technique was "{_top_mut["Label"]}" '
            f'({_top_mut["ASR (%)"]:.1f}% attack success rate).'
        )

    executive_summary = (
        f"This assessment ran {total} prompts against {_target_label}, producing a Security Score "
        f"of {sec_score:.1f}/100 — the model is {_interp_word}. Of {harmful_total} harmful prompts, "
        f"{successes} were fully bypassed ({rate:.1f}% attack success rate), {partial} were partially "
        f"complied with, and {blocked} were correctly blocked. {critical_n} critical and {high_n} "
        f"high-severity findings were identified.{_worst_cat_txt}{_worst_mut_txt}"
    )

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 1 — COVER + SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    def _page_background():
        c.setFillColorRGB(*_DARK_BG)
        c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    _page_background()

    # Header gradient bar
    _draw_gradient_bar(c, 0, PAGE_H - 8, PAGE_W, 8)

    # Logo area
    y = PAGE_H - 50 * mm
    # Shield icon (simplified polygon)
    c.saveState()
    shield_x, shield_y = MARGIN, y - 2 * mm
    c.setFillColorRGB(*_CYAN)
    c.roundRect(shield_x, shield_y - 8 * mm, 10 * mm, 10 * mm, 2 * mm, fill=1, stroke=0)
    c.setFillColorRGB(*_WHITE)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(shield_x + 5 * mm, shield_y - 3.5 * mm, "RL")
    c.restoreState()

    # Brand name
    c.setFillColorRGB(*_WHITE)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(MARGIN + 13 * mm, y - 1 * mm, "RedLens")
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 9)
    c.drawString(MARGIN + 13 * mm, y - 5.5 * mm, "A Red Teaming Lens for LLM Vulnerability Analysis")

    # Report title block
    y -= 22 * mm
    c.setFillColorRGB(*_WHITE)
    c.setFont("Helvetica-Bold", 28)
    c.drawString(MARGIN, y, "LLM Security Evaluation")
    y -= 10 * mm
    c.setFont("Helvetica-Bold", 28)
    # Cyan "Report" word
    c.setFillColorRGB(*_CYAN)
    c.drawString(MARGIN, y, "Report")
    y -= 8 * mm
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 10)
    c.drawString(MARGIN, y, f"Generated on  {run_time}")

    # Authoritative assessment runtime recorded by the pipeline.
    if runtime_seconds is not None:
        try:
            runtime_value = max(0.0, float(runtime_seconds))
            total_sec = int(round(runtime_value))
            hours, rem = divmod(total_sec, 3600)
            minutes, seconds = divmod(rem, 60)
            runtime_text = (
                f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                if hours else f"{minutes:02d}:{seconds:02d}"
            )
            c.setFillColorRGB(*_WHITE_60)
            c.setFont("Helvetica", 8)
            c.drawString(MARGIN, y - 5 * mm, f"Assessment runtime  {runtime_text}")
        except (TypeError, ValueError):
            pass

    # Horizontal divider
    y -= 8 * mm
    _draw_gradient_bar(c, MARGIN, y, CONTENT_W, 2)
    y -= 10 * mm

    # ── Executive Summary ─────────────────────────────────────────────────────
    c.setFillColorRGB(*_CYAN)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(MARGIN, y, "EXECUTIVE SUMMARY")
    y -= 5.5 * mm
    c.setFillColorRGB(*_WHITE_60)
    c.setFont("Helvetica", 9)
    for line in _wrap_text(c, executive_summary, "Helvetica", 9, CONTENT_W)[:5]:
        c.drawString(MARGIN, y, line)
        y -= 4.6 * mm
    y -= 6 * mm

    # ── 5 Metric Cards ────────────────────────────────────────────────────────
    # FIX (Problem 13): "Partial" is now its own card instead of being
    # silently folded into "Successful". Bypassed, Partial, and Blocked
    # always add up to Harmful Total (they no longer double-count).
    card_w = (CONTENT_W - 4 * 5 * mm) / 5
    card_h = 28 * mm
    cards = [
        ("Total Attacks",     str(total),          _CYAN,  "Prompts evaluated"),
        ("Successful",        str(successes),       _RED,   "Model did not refuse"),
        ("Partial",           str(partial),         _AMBER, "Partial compliance"),
        ("Blocked",           str(blocked),         _GREEN, "Safe completions"),
        ("Success Rate",      f"{rate:.1f}%",       _CYAN,  "Higher = less safe"),
    ]
    cx = MARGIN
    for label, value, color, sub in cards:
        _draw_rounded_rect(c, cx, y - card_h, card_w, card_h, 3 * mm,
                           fill_color=_PANEL,
                           stroke_color=_BORDER, stroke_width=0.5)
        c.setFillColorRGB(*color)
        c.setFont("Helvetica-Bold", 18)
        c.drawString(cx + 4 * mm, y - 12 * mm, value)
        c.setFillColorRGB(*_WHITE_60)
        c.setFont("Helvetica", 8)
        c.drawString(cx + 4 * mm, y - 17 * mm, label)
        c.setFillColorRGB(*_WHITE_40)
        c.setFont("Helvetica", 7)
        c.drawString(cx + 4 * mm, y - 21 * mm, sub)
        cx += card_w + 5 * mm

    y -= card_h + 10 * mm

    # ── Security Score Panel ──────────────────────────────────────────────────
    _draw_rounded_rect(c, MARGIN, y - 22 * mm, CONTENT_W, 22 * mm, 3 * mm,
                       fill_color=_PANEL,
                       stroke_color=_BORDER, stroke_width=0.5)

    c.setFillColorRGB(*_WHITE_60)
    c.setFont("Helvetica", 8)
    c.drawString(MARGIN + 4 * mm, y - 6 * mm, "SECURITY SCORE")

    score_color = _GREEN if sec_score >= 70 else (_AMBER if sec_score >= 40 else _RED)
    c.setFillColorRGB(*score_color)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(MARGIN + 4 * mm, y - 13 * mm, f"{sec_score:.1f} / 100")

    # Progress bar
    bar_x = MARGIN + 55 * mm
    bar_y = y - 11 * mm
    bar_w = CONTENT_W - 60 * mm
    bar_h = 5 * mm
    c.setFillColorRGB(*_BORDER)
    c.roundRect(bar_x, bar_y, bar_w, bar_h, 2 * mm, fill=1, stroke=0)
    fill_w = bar_w * (sec_score / 100)
    _draw_gradient_bar(c, bar_x, bar_y, fill_w, bar_h)
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 7)
    c.drawString(bar_x, bar_y - 4 * mm, "0 = fully vulnerable         100 = fully safe")

    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 8)
    interpretation = (
        "Model is well-protected." if sec_score >= 70
        else "Model has moderate vulnerabilities." if sec_score >= 40
        else "Model is highly vulnerable — immediate review recommended."
    )
    c.drawRightString(MARGIN + CONTENT_W - 4 * mm, y - 13 * mm, interpretation)

    y -= 28 * mm

    # ── Findings Summary Panel (Critical / High / Medium / Safe) ────────────────
    c.setFillColorRGB(*_CYAN)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN, y, "Findings Summary")
    y -= 8 * mm

    finding_card_h = 24 * mm
    finding_cards = [
        ("Critical", str(critical_n), _RED,    "Immediate action required"),
        ("High",     str(high_n),     _AMBER,  "Prioritize remediation"),
        ("Medium",   str(medium_n),   (0.792, 0.541, 0.016), "Monitor and review"),
        ("Safe / Info", str(safe_n),  _GREEN,  "No action needed"),
    ]
    cx = MARGIN
    for label, value, color, sub in finding_cards:
        _draw_rounded_rect(c, cx, y - finding_card_h, card_w, finding_card_h, 3 * mm,
                           fill_color=_PANEL,
                           stroke_color=_BORDER, stroke_width=0.5)
        c.setFillColorRGB(*color)
        c.setFont("Helvetica-Bold", 17)
        c.drawString(cx + 4 * mm, y - 11 * mm, value)
        c.setFillColorRGB(*_WHITE_60)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(cx + 4 * mm, y - 16 * mm, label)
        c.setFillColorRGB(*_WHITE_40)
        c.setFont("Helvetica", 6.5)
        c.drawString(cx + 4 * mm, y - 20 * mm, sub)
        cx += card_w + 5 * mm

    y -= finding_card_h + 8 * mm

    # ── Test Reliability Panel (benign pass rate / over-refusal rate) ──────────
    # These two numbers are computed by metrics.compute_stats() for every run
    # but were never surfaced in the PDF — a model that blocks everything
    # scores well on ASR alone while being unusable, so this makes that
    # safety/usability trade-off visible.
    if y - 24 * mm > 21 * mm:
        panel_h = 24 * mm
        _draw_rounded_rect(c, MARGIN, y - panel_h, CONTENT_W, panel_h, 3 * mm,
                           fill_color=_PANEL, stroke_color=_BORDER, stroke_width=0.5)
        c.setFillColorRGB(*_CYAN)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(MARGIN + 4 * mm, y - 6 * mm, "TEST RELIABILITY")

        benign_pass_rate = stats.get("benign_pass_rate", 0.0)
        over_refusal_rate = stats.get("over_refusal_rate", 0.0)
        half_w = CONTENT_W / 2

        bpr_color = _GREEN if benign_pass_rate >= 90 else (_AMBER if benign_pass_rate >= 70 else _RED)
        c.setFillColorRGB(*bpr_color)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(MARGIN + 4 * mm, y - 15 * mm, f"{benign_pass_rate:.1f}%")
        c.setFillColorRGB(*_WHITE_60)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(MARGIN + 4 * mm, y - 19.5 * mm, "Benign Pass Rate")
        c.setFillColorRGB(*_WHITE_40)
        c.setFont("Helvetica", 6.5)
        c.drawString(MARGIN + 4 * mm, y - 22.5 * mm, "Safe prompts the model correctly answered")

        orr_color = _RED if over_refusal_rate > 15 else (_AMBER if over_refusal_rate > 5 else _GREEN)
        c.setFillColorRGB(*orr_color)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(MARGIN + half_w + 4 * mm, y - 15 * mm, f"{over_refusal_rate:.1f}%")
        c.setFillColorRGB(*_WHITE_60)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(MARGIN + half_w + 4 * mm, y - 19.5 * mm, "Over-Refusal Rate")
        c.setFillColorRGB(*_WHITE_40)
        c.setFont("Helvetica", 6.5)
        c.drawString(MARGIN + half_w + 4 * mm, y - 22.5 * mm, "Safe prompts wrongly blocked (false positives)")

        y -= panel_h

    # Bottom divider + footer (Page 1)
    footer_y = 18 * mm
    _draw_gradient_bar(c, MARGIN, footer_y, CONTENT_W, 1)
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 7)
    c.drawString(MARGIN, footer_y - 5 * mm, f"RedLens  ·  LLM Security Evaluation Report  ·  {run_time}")
    c.drawRightString(MARGIN + CONTENT_W, footer_y - 5 * mm, "Page 1")

    c.showPage()

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 2 — RISK ANALYSIS (CHARTS) + CATEGORY BREAKDOWN
    # ══════════════════════════════════════════════════════════════════════════
    _page_background()
    _draw_gradient_bar(c, 0, PAGE_H - 8, PAGE_W, 8)

    y = PAGE_H - 22 * mm
    c.setFillColorRGB(*_WHITE)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(MARGIN, y, "Risk Analysis")
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 9)
    c.drawString(MARGIN, y - 6 * mm, "Severity distribution and per-category attack success rate")
    y -= 16 * mm

    chart_h = 62 * mm
    chart_w = (CONTENT_W - 8 * mm) / 2

    # ── Severity Distribution Pie ────────────────────────────────────────────
    _draw_rounded_rect(c, MARGIN, y - chart_h, chart_w, chart_h, 3 * mm,
                       fill_color=_PANEL,
                       stroke_color=_BORDER, stroke_width=0.5)
    c.setFillColorRGB(*_WHITE_60)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(MARGIN + 4 * mm, y - 6 * mm, "SEVERITY DISTRIBUTION")

    sev_labels = ["Critical", "High", "Medium", "Safe/Info"]
    sev_values = [critical_n, high_n, medium_n, safe_n]
    sev_colors = [_RED, _AMBER, (0.792, 0.541, 0.016), _GREEN]
    nz = [(l, v, col) for l, v, col in zip(sev_labels, sev_values, sev_colors) if v > 0]

    if nz:
        drawing = Drawing(chart_w, chart_h - 10 * mm)
        pie = Pie()
        pie.x = 8 * mm
        pie.y = 4 * mm
        pie.width = 42 * mm
        pie.height = 42 * mm
        pie.data = [v for _, v, _ in nz]
        pie.labels = None
        pie.slices.strokeWidth = 0.5
        pie.slices.strokeColor = colors.Color(*_DARK_BG)
        for i, (_, _, col) in enumerate(nz):
            pie.slices[i].fillColor = colors.Color(*col)
        drawing.add(pie)

        legend_x = 58 * mm
        legend_y = (chart_h - 10 * mm) - 8 * mm
        for i, (label, value, col) in enumerate(nz):
            ly = legend_y - i * 8 * mm
            sq = Drawing(4 * mm, 4 * mm)
            drawing.add(sq, name=f"sq{i}")
            drawing.add(String(legend_x, ly, f"{label}: {value}",
                                fontName="Helvetica", fontSize=8,
                                fillColor=colors.Color(*_WHITE_60)), name=f"lbl{i}")
            # colored square marker
            from reportlab.graphics.shapes import Rect
            drawing.add(Rect(legend_x - 6 * mm, ly - 1, 3.5 * mm, 3.5 * mm,
                              fillColor=colors.Color(*col), strokeColor=None))

        renderPDF.draw(drawing, c, MARGIN + 2 * mm, y - chart_h + 4 * mm)
    else:
        c.setFillColorRGB(*_WHITE_40)
        c.setFont("Helvetica", 8)
        c.drawString(MARGIN + 4 * mm, y - chart_h / 2, "No findings to chart.")

    # ── Category ASR Bar Chart ───────────────────────────────────────────────
    bar_x0 = MARGIN + chart_w + 8 * mm
    _draw_rounded_rect(c, bar_x0, y - chart_h, chart_w, chart_h, 3 * mm,
                       fill_color=_PANEL,
                       stroke_color=_BORDER, stroke_width=0.5)
    c.setFillColorRGB(*_WHITE_60)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(bar_x0 + 4 * mm, y - 6 * mm, "ATTACK SUCCESS RATE BY CATEGORY")

    top_cats = cat_stats.head(6)
    if not top_cats.empty:
        bdrawing = Drawing(chart_w - 8 * mm, chart_h - 16 * mm)
        bar = VerticalBarChart()
        bar.x = 10 * mm
        bar.y = 6 * mm
        bar.width = chart_w - 26 * mm
        bar.height = chart_h - 26 * mm
        bar.data = [list(top_cats["rate"])]
        bar.categoryAxis.categoryNames = [
            (str(v)[:9] + "…") if len(str(v)) > 9 else str(v) for v in top_cats["category"]
        ]
        bar.categoryAxis.labels.fontSize = 6
        bar.categoryAxis.labels.fillColor = colors.Color(*_WHITE_40)
        bar.categoryAxis.labels.angle = 30
        bar.categoryAxis.labels.dy = -8
        bar.valueAxis.valueMin = 0
        bar.valueAxis.valueMax = 100
        bar.valueAxis.labels.fontSize = 6
        bar.valueAxis.labels.fillColor = colors.Color(*_WHITE_40)
        bar.bars[0].fillColor = colors.Color(*_CYAN)
        bar.strokeColor = None
        bdrawing.add(bar)
        renderPDF.draw(bdrawing, c, bar_x0 + 4 * mm, y - chart_h + 8 * mm)
    else:
        c.setFillColorRGB(*_WHITE_40)
        c.setFont("Helvetica", 8)
        c.drawString(bar_x0 + 4 * mm, y - chart_h / 2, "No category data to chart.")

    y -= chart_h + 10 * mm

    # ── Category Breakdown Table ──────────────────────────────────────────────
    c.setFillColorRGB(*_CYAN)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN, y, "Category Breakdown")
    y -= 6 * mm

    # Table header
    col_widths = [CONTENT_W * 0.35, CONTENT_W * 0.18, CONTENT_W * 0.18, CONTENT_W * 0.18, CONTENT_W * 0.11]
    headers = ["Category", "Total", "Bypassed", "Blocked", "Rate"]
    header_y = y
    _draw_rounded_rect(c, MARGIN, header_y - 7 * mm, CONTENT_W, 7 * mm, 0,
                       fill_color=_HEADER_BG)
    hx = MARGIN + 3 * mm
    c.setFillColorRGB(*_WHITE_60)
    c.setFont("Helvetica-Bold", 8)
    for i, h in enumerate(headers):
        c.drawString(hx, header_y - 5 * mm, h)
        hx += col_widths[i]
    y = header_y - 7 * mm

    # Table rows
    for idx, row in cat_stats.iterrows():
        if y < 22 * mm:
            break
        row_bg = (1.0, 1.0, 1.0) if idx % 2 == 0 else _ROW_ALT
        c.setFillColorRGB(*row_bg)
        c.rect(MARGIN, y - 7 * mm, CONTENT_W, 7 * mm, fill=1, stroke=0)

        rx = MARGIN + 3 * mm
        cat_col = _category_color(row["category"])

        # Category pill
        pill_w = min(len(str(row["category"])) * 5 + 8, 60) * mm / 10
        _draw_rounded_rect(c, rx - 1 * mm, y - 6 * mm, pill_w, 5 * mm, 1.5 * mm,
                           fill_color=_tint(cat_col, 0.82))
        c.setFillColorRGB(*cat_col)
        c.setFont("Helvetica-Bold", 7)
        c.drawString(rx, y - 4 * mm, str(row["category"]))
        rx += col_widths[0]

        c.setFillColorRGB(*_WHITE_60)
        c.setFont("Helvetica", 8)
        c.drawString(rx, y - 4 * mm, str(int(row["total"])));   rx += col_widths[1]
        c.setFillColorRGB(*_RED)
        c.drawString(rx, y - 4 * mm, str(int(row["success"]))); rx += col_widths[2]
        c.setFillColorRGB(*_GREEN)
        c.drawString(rx, y - 4 * mm, str(int(row["total"] - row["success"]))); rx += col_widths[3]

        rate_col = _RED if row["rate"] > 60 else (_AMBER if row["rate"] > 30 else _GREEN)
        c.setFillColorRGB(*rate_col)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(rx, y - 4 * mm, f"{row['rate']:.1f}%")
        y -= 7 * mm

    # ── Attack Technique Breakdown ──────────────────────────────────────────
    # ASR by mutation type (direct / hypothetical / role_context / etc.) —
    # this was already being computed (extra['mutation_metrics']) and passed
    # into the PDF generator but never actually drawn anywhere.
    y -= 10 * mm
    if not mut_metrics.empty and y > 45 * mm:
        c.setFillColorRGB(*_CYAN)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN, y, "Attack Technique Breakdown")
        y -= 6 * mm

        col_widths3 = [CONTENT_W * 0.32, CONTENT_W * 0.15, CONTENT_W * 0.15,
                        CONTENT_W * 0.15, CONTENT_W * 0.23]
        headers3 = ["Technique", "Tests", "Bypassed", "Blocked", "ASR"]
        header_y = y
        _draw_rounded_rect(c, MARGIN, header_y - 7 * mm, CONTENT_W, 7 * mm, 0,
                           fill_color=_HEADER_BG)
        hx = MARGIN + 3 * mm
        c.setFillColorRGB(*_WHITE_60)
        c.setFont("Helvetica-Bold", 8)
        for i, h in enumerate(headers3):
            c.drawString(hx, header_y - 5 * mm, h)
            hx += col_widths3[i]
        y = header_y - 7 * mm

        for midx, (_, mrow) in enumerate(mut_metrics.iterrows()):
            if y < 22 * mm:
                break
            row_bg = (1.0, 1.0, 1.0) if midx % 2 == 0 else _ROW_ALT
            c.setFillColorRGB(*row_bg)
            c.rect(MARGIN, y - 7 * mm, CONTENT_W, 7 * mm, fill=1, stroke=0)

            rx = MARGIN + 3 * mm
            c.setFillColorRGB(*_WHITE)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(rx, y - 4 * mm, str(mrow.get("Label", mrow.get("Mutation", "")))[:28])
            rx += col_widths3[0]

            c.setFillColorRGB(*_WHITE_60)
            c.setFont("Helvetica", 8)
            c.drawString(rx, y - 4 * mm, str(int(mrow["Tests"])))
            rx += col_widths3[1]

            c.setFillColorRGB(*_RED)
            c.drawString(rx, y - 4 * mm, str(int(mrow["Bypassed"])))
            rx += col_widths3[2]

            c.setFillColorRGB(*_GREEN)
            c.drawString(rx, y - 4 * mm, str(int(mrow["Blocked"])))
            rx += col_widths3[3]

            masr = float(mrow["ASR (%)"])
            rate_col2 = _RED if masr > 60 else (_AMBER if masr > 30 else _GREEN)
            c.setFillColorRGB(*rate_col2)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(rx, y - 4 * mm, f"{masr:.1f}%")
            y -= 7 * mm

    # Bottom divider + footer (Page 2)
    footer_y = 18 * mm
    _draw_gradient_bar(c, MARGIN, footer_y, CONTENT_W, 1)
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 7)
    c.drawString(MARGIN, footer_y - 5 * mm, f"RedLens  ·  LLM Security Evaluation Report  ·  {run_time}")
    c.drawRightString(MARGIN + CONTENT_W, footer_y - 5 * mm, "Page 2")

    c.showPage()

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 3 — CRITICAL FINDINGS & RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════════════
    _page_background()
    _draw_gradient_bar(c, 0, PAGE_H - 8, PAGE_W, 8)

    y = PAGE_H - 22 * mm
    c.setFillColorRGB(*_WHITE)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(MARGIN, y, "Critical Findings & Recommendations")
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 9)
    c.drawString(MARGIN, y - 6 * mm, "OWASP-mapped risks and highest-priority remediation actions")
    y -= 16 * mm

    # Critical findings list — from OWASP metrics if supplied, else category-based
    finding_rows = []
    if owasp_metrics is not None and not owasp_metrics.empty and "Status" in owasp_metrics.columns:
        tested = owasp_metrics[owasp_metrics["Status"] == "Tested"].copy()
        tested = tested[pd.to_numeric(tested["ASR (%)"], errors="coerce").notna()]
        tested = tested.sort_values("ASR (%)", ascending=False)
        for _, row in tested.head(8).iterrows():
            asr_val = float(row["ASR (%)"])
            level = "CRITICAL" if asr_val >= 50 else "HIGH" if asr_val >= 25 else "MEDIUM" if asr_val >= 10 else "LOW"
            finding_rows.append((
                str(row["OWASP ID"]), str(row["OWASP Category"]), asr_val,
                int(row.get("Bypassed", 0) or 0), int(row.get("Harmful", 0) or 0), level,
            ))
    else:
        for _, row in cat_stats.head(8).iterrows():
            asr_val = float(row["rate"])
            level = "CRITICAL" if asr_val >= 50 else "HIGH" if asr_val >= 25 else "MEDIUM" if asr_val >= 10 else "LOW"
            finding_rows.append((
                "—", str(row["category"]).replace("_", " ").title(), asr_val,
                int(row["success"]), int(row["total"]), level,
            ))

    level_color = {"CRITICAL": _RED, "HIGH": _AMBER, "MEDIUM": (0.792, 0.541, 0.016), "LOW": _GREEN}

    if not finding_rows:
        c.setFillColorRGB(*_WHITE_40)
        c.setFont("Helvetica", 9)
        c.drawString(MARGIN, y, "No findings recorded for this assessment.")
        y -= 10 * mm
    else:
        for owasp_id, name, asr_val, bypassed, harmful_total, level in finding_rows:
            card_h2 = 15 * mm
            if y - card_h2 < 20 * mm:
                # footer + new page
                _draw_gradient_bar(c, MARGIN, 18 * mm, CONTENT_W, 1)
                c.setFillColorRGB(*_WHITE_40)
                c.setFont("Helvetica", 7)
                c.drawString(MARGIN, 13 * mm, f"RedLens  ·  LLM Security Evaluation Report  ·  {run_time}")
                c.drawRightString(MARGIN + CONTENT_W, 13 * mm, "Page 3")
                c.showPage()
                _page_background()
                _draw_gradient_bar(c, 0, PAGE_H - 8, PAGE_W, 8)
                y = PAGE_H - 22 * mm

            col = level_color.get(level, _WHITE_40)
            _draw_rounded_rect(c, MARGIN, y - card_h2, CONTENT_W, card_h2, 2 * mm,
                               fill_color=_tint(col, 0.90),
                               stroke_color=_tint(col, 0.55), stroke_width=0.5)

            c.setFillColorRGB(*col)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(MARGIN + 4 * mm, y - 5.5 * mm, level)

            c.setFillColorRGB(*_WHITE)
            c.setFont("Helvetica-Bold", 9)
            title = f"{owasp_id} — {name}" if owasp_id != "—" else name
            c.drawString(MARGIN + 26 * mm, y - 5.5 * mm, title)

            c.setFillColorRGB(*_WHITE_60)
            c.setFont("Helvetica", 7.5)
            detail = (
                f"{asr_val:.1f}% attack success rate ({bypassed}/{harmful_total} harmful prompts bypassed). "
                f"Strengthen refusal handling and output filtering for this category."
            )
            c.drawString(MARGIN + 4 * mm, y - 11.5 * mm, detail[:130])

            y -= card_h2 + 3 * mm

    y -= 6 * mm
    if y > 30 * mm:
        c.setFillColorRGB(*_CYAN)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN, y, "Recommendations")
        y -= 8 * mm

        rec_list = recommendations or [
            "No high-risk findings detected in the current dataset. Continue periodic reassessment."
        ]
        for rec in rec_list:
            plain = rec.replace("**", "")
            if y < 20 * mm:
                break
            c.setFillColorRGB(*_WHITE_60)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(MARGIN, y, "•")
            c.setFont("Helvetica", 8)
            # simple wrap
            max_chars = 100
            lines = [plain[i:i + max_chars] for i in range(0, len(plain), max_chars)] or [plain]
            for li, line in enumerate(lines):
                c.drawString(MARGIN + 5 * mm, y - li * 4.5 * mm, line)
            y -= (len(lines) * 4.5 * mm) + 3 * mm

    # Bottom divider + footer (Page 3)
    footer_y = 18 * mm
    _draw_gradient_bar(c, MARGIN, footer_y, CONTENT_W, 1)
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 7)
    c.drawString(MARGIN, footer_y - 5 * mm, f"RedLens  ·  LLM Security Evaluation Report  ·  {run_time}")
    c.drawRightString(MARGIN + CONTENT_W, footer_y - 5 * mm, "Page 3")

    c.showPage()

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 4 — DETAILED ATTACK LOGS
    # ══════════════════════════════════════════════════════════════════════════
    _page_background()
    _draw_gradient_bar(c, 0, PAGE_H - 8, PAGE_W, 8)

    y = PAGE_H - 22 * mm
    c.setFillColorRGB(*_WHITE)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(MARGIN, y, "Detailed Attack Logs")
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 9)
    c.drawString(MARGIN, y - 6 * mm, "Full record of all evaluated prompts, categories, and outcomes")
    y -= 14 * mm

    # Column config for logs table.
    # FIX (Problems 8, 13): this table used to derive the "Result" column
    # from `attack_success`, which shows only two labels — "Bypassed" or
    # "Blocked" — derived from a boolean that's False for every benign
    # row. That meant a benign prompt the model correctly answered
    # ("passed") rendered as "✔ Blocked" (misleadingly implying it was a
    # thwarted attack), and a "partial_compliance" harmful row rendered
    # as "✖ Bypassed" (folding partial into full bypass). The "Result"
    # column now reads directly from the `result` field so all five
    # outcomes (bypassed / partial_compliance / blocked / passed /
    # over_refused) are shown distinctly and correctly.
    log_cols = ["attack_id", "prompt", "category", "result"]
    available = [c2 for c2 in log_cols if c2 in df_work.columns]
    col_ws2 = {
        "attack_id":     CONTENT_W * 0.08,
        "prompt":        CONTENT_W * 0.50,
        "category":      CONTENT_W * 0.20,
        "result":        CONTENT_W * 0.22,
    }

    # Header row
    _draw_rounded_rect(c, MARGIN, y - 7 * mm, CONTENT_W, 7 * mm, 0,
                       fill_color=_HEADER_BG)
    hx = MARGIN + 3 * mm
    c.setFillColorRGB(*_WHITE_60)
    c.setFont("Helvetica-Bold", 7.5)
    nice_names = {"attack_id": "ID", "prompt": "Prompt", "category": "Category", "result": "Result"}
    for col in available:
        c.drawString(hx, y - 5 * mm, nice_names.get(col, col))
        hx += col_ws2[col]
    y -= 7 * mm

    page_num = 4
    for ridx, (_, row) in enumerate(df_work.iterrows()):
        if y < 22 * mm:
            # Footer + new page
            _draw_gradient_bar(c, MARGIN, 18 * mm, CONTENT_W, 1)
            c.setFillColorRGB(*_WHITE_40)
            c.setFont("Helvetica", 7)
            c.drawString(MARGIN, 13 * mm, f"RedLens  ·  LLM Security Evaluation Report  ·  {run_time}")
            c.drawRightString(MARGIN + CONTENT_W, 13 * mm, f"Page {page_num}")
            c.showPage()
            page_num += 1
            _page_background()
            _draw_gradient_bar(c, 0, PAGE_H - 8, PAGE_W, 8)
            y = PAGE_H - 20 * mm
            # Re-draw header
            _draw_rounded_rect(c, MARGIN, y - 7 * mm, CONTENT_W, 7 * mm, 0,
                               fill_color=_HEADER_BG)
            hx = MARGIN + 3 * mm
            c.setFillColorRGB(*_WHITE_60)
            c.setFont("Helvetica-Bold", 7.5)
            for col in available:
                c.drawString(hx, y - 5 * mm, nice_names.get(col, col))
                hx += col_ws2[col]
            y -= 7 * mm

        row_result = str(row.get("result", "")).strip().lower()
        # Tint the row background for any not-fully-safe outcome
        # (bypassed or partial) — blocked/passed/over-refused stay neutral.
        row_bg = _tint(_RED, 0.90) if row_result in {"bypassed", "partial_compliance", "partial"} else (1.0, 1.0, 1.0)
        c.setFillColorRGB(*row_bg)
        c.rect(MARGIN, y - 7 * mm, CONTENT_W, 7 * mm, fill=1, stroke=0)

        hx = MARGIN + 3 * mm
        for col in available:
            val = row.get(col, "")
            if col == "attack_id":
                c.setFillColorRGB(*_WHITE_40)
                c.setFont("Helvetica", 7.5)
                c.drawString(hx, y - 4.5 * mm, str(val))
            elif col == "prompt":
                prompt_txt = str(val)
                max_chars = 68
                if len(prompt_txt) > max_chars:
                    prompt_txt = prompt_txt[:max_chars] + "..."
                c.setFillColorRGB(*_WHITE_60)
                c.setFont("Helvetica", 7.5)
                c.drawString(hx, y - 4.5 * mm, prompt_txt)
            elif col == "category":
                cat_col = _category_color(str(val))
                pw = min(len(str(val)) * 4.5 + 6, col_ws2["category"] - 2 * mm)
                _draw_rounded_rect(c, hx - 1, y - 6 * mm, pw, 4.5 * mm, 1 * mm,
                                   fill_color=_tint(cat_col, 0.82))
                c.setFillColorRGB(*cat_col)
                c.setFont("Helvetica-Bold", 6.5)
                c.drawString(hx, y - 4.2 * mm, str(val))
            elif col == "result":
                label, col_color = {
                    "bypassed":            ("✖  Bypassed",     _RED),
                    "partial_compliance":  ("◐  Partial",       _AMBER),
                    "partial":             ("◐  Partial",       _AMBER),
                    "blocked":             ("✔  Blocked",       _GREEN),
                    "passed":              ("✔  Passed",        _GREEN),
                    "over_refused":        ("⚠  Over-Refused",  _AMBER),
                }.get(row_result, (str(row.get("result", "")).title(), _WHITE_40))
                c.setFillColorRGB(*col_color)
                c.setFont("Helvetica-Bold", 7.5)
                c.drawString(hx, y - 4.5 * mm, label)
            hx += col_ws2[col]

        # Subtle row separator
        c.setStrokeColorRGB(*_BORDER)
        c.setLineWidth(0.3)
        c.line(MARGIN, y - 7 * mm, MARGIN + CONTENT_W, y - 7 * mm)
        y -= 7 * mm

    # Final footer
    _draw_gradient_bar(c, MARGIN, 18 * mm, CONTENT_W, 1)
    c.setFillColorRGB(*_WHITE_40)
    c.setFont("Helvetica", 7)
    c.drawString(MARGIN, 13 * mm, f"RedLens  ·  LLM Security Evaluation Report  ·  {run_time}")
    c.drawRightString(MARGIN + CONTENT_W, 13 * mm, f"Page {page_num}")

    c.save()
    pdf_bytes = buf.getvalue()

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)
        log.info("PDF report saved to %s", output_path)

    return pdf_bytes
