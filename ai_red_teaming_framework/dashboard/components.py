"""
components.py — Reusable UI building blocks for the RedLens
LLM Security Platform dashboard.

Nothing in this module touches attack generation, evaluation,
OWASP mapping, mutation, trend, or report-generation logic — it is
purely presentational (CSS + small Streamlit rendering helpers) so
every page in dashboard.py can share one consistent look.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

import streamlit as st

try:
    import plotly.graph_objects as go
except Exception:  # pragma: no cover
    go = None


# ============================================================
# DESIGN TOKENS
# ============================================================

COLORS = {
    "bg_0": "#05070d",
    "bg_1": "#080b13",
    "panel": "rgba(15, 20, 32, 0.72)",
    "panel_solid": "#0d1220",
    "border": "rgba(148, 163, 184, 0.14)",
    "border_strong": "rgba(148, 163, 184, 0.28)",
    "text_hi": "#f1f5f9",
    "text_mid": "rgba(226, 232, 240, 0.68)",
    "text_low": "rgba(148, 163, 184, 0.55)",
    # brand accents
    "accent": "#22d3ee",     # cyan / primary
    "accent2": "#a78bfa",    # purple / secondary
    # risk scale
    "critical": "#f43f5e",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#34d399",
    "safe": "#22c55e",
    "info": "#818cf8",
    "muted": "#94a3b8",
}

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "NOT TESTED"]

RISK_COLOR = {
    "CRITICAL": COLORS["critical"],
    "HIGH": COLORS["high"],
    "MEDIUM": COLORS["medium"],
    "LOW": COLORS["low"],
    "SAFE": COLORS["safe"],
    "NOT TESTED": COLORS["muted"],
}

RESULT_COLOR = {
    "BYPASSED": COLORS["critical"],
    "PARTIAL_COMPLIANCE": COLORS["high"],
    "PARTIAL": COLORS["high"],
    "BLOCKED": COLORS["safe"],
    "PASSED": COLORS["safe"],
    "OVER_REFUSED": COLORS["medium"],
}


def asr_to_risk(asr: Optional[float]) -> str:
    """Map an Attack Success Rate percentage to a risk level."""
    if asr is None:
        return "NOT TESTED"
    if asr >= 75:
        return "CRITICAL"
    if asr >= 50:
        return "HIGH"
    if asr >= 25:
        return "MEDIUM"
    if asr > 0:
        return "LOW"
    return "SAFE"


# ============================================================
# THEME / CSS
# ============================================================

def inject_theme() -> None:

    st.markdown(
        f"""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {{
    --bg-0: {COLORS['bg_0']};
    --bg-1: {COLORS['bg_1']};
    --panel: {COLORS['panel']};
    --panel-solid: {COLORS['panel_solid']};
    --border: {COLORS['border']};
    --border-strong: {COLORS['border_strong']};
    --text-hi: {COLORS['text_hi']};
    --text-mid: {COLORS['text_mid']};
    --text-low: {COLORS['text_low']};
    --accent: {COLORS['accent']};
    --accent2: {COLORS['accent2']};
    --critical: {COLORS['critical']};
    --high: {COLORS['high']};
    --medium: {COLORS['medium']};
    --low: {COLORS['low']};
    --safe: {COLORS['safe']};
    --info: {COLORS['info']};
    --radius: 14px;
    --shadow: 0 8px 22px rgba(0,0,0,.35);
}}

html, body, [class*="css"] {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}}

.stApp {{
    background:
        radial-gradient(1100px 650px at 12% -8%, #0e2233 0%, transparent 55%),
        radial-gradient(850px 550px at 100% 0%, #171f36 0%, transparent 45%),
        linear-gradient(180deg, var(--bg-1) 0%, var(--bg-0) 100%);
}}

.block-container {{
    padding-top: 1rem;
    padding-bottom: 3.5rem;
    max-width: 1440px;
}}

/* ---------------- NATIVE STREAMLIT HEADER ----------------
   Streamlit's built-in top toolbar (hamburger menu / Deploy
   button / rerun spinner) keeps its own opaque background
   regardless of app theming. Left alone, that renders as a
   solid black strip sitting on top of our dark gradient
   background, which reads as a UI bug rather than a themed
   header. Make it transparent and let our .stApp background
   show through, and keep it slim so it doesn't eat vertical
   space above the command header. */

header[data-testid="stHeader"] {{
    background: transparent !important;
    background-color: transparent !important;
    height: 2.75rem;
}}

header[data-testid="stHeader"]::before {{
    content: none !important;
}}

div[data-testid="stDecoration"] {{
    display: none !important;
}}

div[data-testid="stToolbar"] {{
    background: transparent !important;
    right: 1rem;
}}

div[data-testid="stStatusWidget"] {{
    background: transparent !important;
}}

/* ---------------- SIDEBAR ---------------- */

section[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, #060911 0%, #04060b 100%);
    border-right: 1px solid var(--border);
    min-width: 275px !important;
}}

section[data-testid="stSidebar"] .block-container {{
    padding-top: 1.2rem;
    padding-left: 1.1rem;
    padding-right: 1.1rem;
}}

section[data-testid="stSidebar"] hr {{
    border-color: var(--border);
    margin: .9rem 0;
}}

section[data-testid="stSidebar"] div[role="radiogroup"] {{
    gap: 2px;
}}

section[data-testid="stSidebar"] div[role="radiogroup"] label {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 7px 10px !important;
    transition: background .15s ease, border-color .15s ease;
    font-size: .88rem !important;
}}

section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {{
    background: rgba(148, 163, 184, 0.07);
}}

section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {{
    background: rgba(34, 211, 238, 0.10);
    border-color: rgba(34, 211, 238, 0.35);
}}

section[data-testid="stSidebar"] div[role="radiogroup"] label p {{
    color: var(--text-mid) !important;
    font-weight: 500;
}}

section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p {{
    color: var(--text-hi) !important;
    font-weight: 600;
}}

/* ---------------- BRAND LOCKUP ---------------- */

.rl-brand {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 2px;
}}

.rl-logo {{
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: linear-gradient(135deg, var(--accent) 0%, var(--accent2) 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.05rem;
    flex-shrink: 0;
    box-shadow: 0 0 0 1px rgba(255,255,255,.08) inset;
}}

.rl-wordmark {{
    font-size: 1.25rem;
    font-weight: 800;
    color: var(--text-hi);
    letter-spacing: .5px;
    line-height: 1.1;
}}

.rl-tagline {{
    font-size: .64rem;
    font-weight: 700;
    color: var(--text-low);
    letter-spacing: 1.4px;
    text-transform: uppercase;
    margin-top: 1px;
}}

.rl-status-pill {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: .68rem;
    font-weight: 600;
    color: var(--safe);
    background: rgba(34, 197, 94, 0.10);
    border: 1px solid rgba(34, 197, 94, 0.28);
    padding: 4px 10px;
    border-radius: 999px;
    margin-top: 10px;
}}

.rl-status-dot {{
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--safe);
    box-shadow: 0 0 6px var(--safe);
}}

.rl-status-pill.offline {{
    color: var(--critical);
    background: rgba(244, 63, 94, 0.10);
    border-color: rgba(244, 63, 94, 0.28);
}}
.rl-status-pill.offline .rl-status-dot {{
    background: var(--critical);
    box-shadow: 0 0 6px var(--critical);
}}

.rl-nav-group {{
    font-size: .64rem;
    font-weight: 700;
    letter-spacing: 1.4px;
    text-transform: uppercase;
    color: var(--text-low);
    margin: 16px 0 4px 4px;
}}

.rl-sidebar-footer {{
    font-size: .72rem;
    color: var(--text-mid);
    line-height: 1.85;
}}
.rl-sidebar-footer b {{
    color: var(--text-hi);
    font-weight: 600;
}}
.rl-sidebar-footer .lbl {{
    color: var(--text-low);
    text-transform: uppercase;
    font-size: .62rem;
    letter-spacing: .6px;
    display: block;
    margin-top: 8px;
}}

/* ---------------- COMMAND CENTER HEADER ---------------- */

.rl-header-wrap {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 16px;
    padding-bottom: 4px;
}}

.rl-eyebrow {{
    font-size: .68rem;
    font-weight: 700;
    letter-spacing: 1.6px;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 4px;
}}

.rl-h1 {{
    font-size: 1.85rem;
    font-weight: 800;
    color: var(--text-hi);
    letter-spacing: -.02em;
    line-height: 1.15;
}}

.rl-h1-sub {{
    color: var(--text-mid);
    font-size: .92rem;
    margin-top: 5px;
    max-width: 640px;
}}

.rl-meta-row {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 12px;
}}

.rl-meta-chip {{
    display: flex;
    flex-direction: column;
    gap: 1px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 7px 12px;
    min-width: 118px;
}}

.rl-meta-chip .k {{
    font-size: .6rem;
    text-transform: uppercase;
    letter-spacing: .6px;
    color: var(--text-low);
    font-weight: 600;
}}

.rl-meta-chip .v {{
    font-size: .8rem;
    color: var(--text-hi);
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
}}

/* ---------------- SECTION HEADING ---------------- */

.sec-heading {{
    font-size: .74rem;
    font-weight: 700;
    letter-spacing: 1.4px;
    text-transform: uppercase;
    color: var(--text-low);
    margin: 1.8rem 0 .8rem;
    display: flex;
    align-items: center;
    gap: 12px;
}}

.sec-heading::after {{
    content: "";
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, var(--border) 0%, transparent 100%);
}}

/* ---------------- PANELS ---------------- */

.rt-panel {{
    background: var(--panel);
    backdrop-filter: blur(10px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px;
    margin-bottom: 14px;
    box-shadow: var(--shadow);
}}

.rt-panel-title {{
    font-size: .78rem;
    font-weight: 700;
    color: var(--text-mid);
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: .6px;
}}

/* ---------------- KPI CARDS ---------------- */

.kpi-card {{
    background: var(--panel);
    backdrop-filter: blur(10px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px;
    min-height: 128px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: transform .15s ease, border-color .15s ease;
}}

.kpi-card:hover {{
    transform: translateY(-2px);
    border-color: var(--border-strong);
}}

.kpi-card::before {{
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--bar-color, var(--accent));
    opacity: .9;
}}

.kpi-icon {{
    width: 34px;
    height: 34px;
    border-radius: 9px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 10px;
    font-size: .95rem;
}}

.kpi-lbl {{
    font-size: .68rem;
    color: var(--text-low);
    text-transform: uppercase;
    letter-spacing: .8px;
    font-weight: 600;
}}

.kpi-val {{
    font-size: 1.75rem;
    font-weight: 800;
    margin-top: 4px;
    letter-spacing: -.01em;
    font-variant-numeric: tabular-nums;
}}

.kpi-sub {{
    font-size: .68rem;
    color: var(--text-low);
    margin-top: 4px;
}}

.kpi-trend {{
    font-size: .68rem;
    font-weight: 700;
    margin-top: 2px;
}}

/* ---------------- BADGES ---------------- */

.rl-badge {{
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: .66rem;
    font-weight: 700;
    letter-spacing: .5px;
    text-transform: uppercase;
    padding: 3px 9px;
    border-radius: 999px;
    white-space: nowrap;
}}

/* ---------------- PROGRESS BAR ---------------- */

.rl-progress-track {{
    width: 100%;
    height: 7px;
    border-radius: 999px;
    background: rgba(148, 163, 184, 0.14);
    overflow: hidden;
    margin-top: 8px;
}}

.rl-progress-fill {{
    height: 100%;
    border-radius: 999px;
}}

/* ---------------- FINDING / OWASP CARDS ---------------- */

.finding-card {{
    background: var(--panel);
    backdrop-filter: blur(10px);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent-color, var(--accent));
    border-radius: 12px;
    padding: 16px;
    min-height: 172px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    box-shadow: var(--shadow);
    transition: transform .15s ease, border-color .15s ease;
}}

.finding-card:hover {{
    transform: translateY(-2px);
}}

.finding-id {{
    font-size: .68rem;
    font-weight: 800;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: .4px;
}}

.finding-name {{
    font-size: .82rem;
    color: var(--text-hi);
    font-weight: 600;
    line-height: 1.3;
    min-height: 2.1em;
}}

.finding-stat-row {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-top: 4px;
}}

.finding-asr {{
    font-size: 1.35rem;
    font-weight: 800;
    font-variant-numeric: tabular-nums;
}}

.finding-meta {{
    font-size: .66rem;
    color: var(--text-low);
}}

/* ---------------- NATIVE WIDGETS ---------------- */

div[data-testid="stMetric"] {{
    background: var(--panel);
    backdrop-filter: blur(10px);
    border: 1px solid var(--border);
    padding: 14px 16px;
    border-radius: 12px;
    box-shadow: var(--shadow);
}}

div[data-testid="stMetricLabel"] {{
    color: var(--text-low) !important;
    font-size: .74rem !important;
    text-transform: uppercase;
    letter-spacing: .6px;
}}

div[data-testid="stDataFrame"] {{
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
}}

pre, div[data-testid="stCodeBlock"] {{
    border-radius: 12px !important;
    border: 1px solid var(--border) !important;
    background: var(--panel-solid) !important;
}}

.stButton > button {{
    border-radius: 9px !important;
    border: 1px solid var(--border-strong) !important;
    background: rgba(148, 163, 184, 0.06) !important;
    color: var(--text-hi) !important;
    font-weight: 600 !important;
    transition: border-color .15s ease, background .15s ease;
}}

.stButton > button:hover {{
    border-color: var(--accent) !important;
    background: rgba(34, 211, 238, 0.08) !important;
    color: var(--accent) !important;
}}

.stButton > button[kind="primary"] {{
    background: linear-gradient(135deg, var(--accent) 0%, #0ea5e9 100%) !important;
    border-color: transparent !important;
    color: #04121a !important;
    font-weight: 700 !important;
}}

.stButton > button[kind="primary"]:hover {{
    filter: brightness(1.08);
    color: #04121a !important;
}}

section[data-testid="stSidebar"] .stButton > button {{
    text-align: left !important;
    justify-content: flex-start !important;
    padding: 8px 12px !important;
    font-size: .86rem !important;
    background: transparent !important;
    border-color: transparent !important;
    color: var(--text-mid) !important;
}}

section[data-testid="stSidebar"] .stButton > button:hover {{
    background: rgba(148, 163, 184, 0.07) !important;
    color: var(--text-hi) !important;
    border-color: transparent !important;
}}

section[data-testid="stSidebar"] .stButton > button[kind="primary"] {{
    background: rgba(34, 211, 238, 0.10) !important;
    border: 1px solid rgba(34, 211, 238, 0.35) !important;
    color: var(--text-hi) !important;
    font-weight: 600 !important;
}}

div[data-baseweb="select"] > div,
.stTextInput input,
.stNumberInput input {{
    border-radius: 9px !important;
    border-color: var(--border) !important;
    background: rgba(148, 163, 184, 0.04) !important;
}}

div[data-testid="stExpander"] {{
    border: 1px solid var(--border);
    border-radius: 12px;
    background: var(--panel);
    overflow: hidden;
}}

div[data-testid="stCheckbox"] label p {{
    font-size: .86rem;
    color: var(--text-mid);
}}

::-webkit-scrollbar {{ width: 9px; height: 9px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{
    background: rgba(148,163,184,.25);
    border-radius: 8px;
}}
::-webkit-scrollbar-thumb:hover {{ background: rgba(148,163,184,.4); }}

</style>
""",
        unsafe_allow_html=True,
    )


# ============================================================
# SIDEBAR
# ============================================================

def render_sidebar_brand(system_online: bool = True) -> None:

    status_cls = "" if system_online else "offline"
    status_txt = "SYSTEM ONLINE" if system_online else "SYSTEM OFFLINE"

    st.markdown(
        f"""
<div class="rl-brand">
  <div class="rl-logo">🛡️</div>
  <div>
    <div class="rl-wordmark">REDLENS</div>
    <div class="rl-tagline">LLM Security Platform</div>
  </div>
</div>
<div class="rl-status-pill {status_cls}">
  <span class="rl-status-dot"></span>{status_txt}
</div>
""",
        unsafe_allow_html=True,
    )


def render_nav_group(label: str) -> None:
    st.markdown(
        f"<div class='rl-nav-group'>{label}</div>",
        unsafe_allow_html=True,
    )


def render_sidebar_footer(
    target_model: str,
    engine: str,
    connection_ok: bool,
    last_assessment: str,
) -> None:

    conn_txt = "Connected" if connection_ok else "Not Connected"
    conn_color = COLORS["safe"] if connection_ok else COLORS["critical"]

    st.markdown(
        f"""
<div class="rl-sidebar-footer">
  <span class="lbl">Target Model</span>
  <b>{target_model}</b>
  <span class="lbl">Engine</span>
  <b>{engine}</b>
  <span class="lbl">Connection</span>
  <b style="color:{conn_color}">{conn_txt}</b>
  <span class="lbl">Last Assessment</span>
  <b>{last_assessment}</b>
</div>
""",
        unsafe_allow_html=True,
    )


# ============================================================
# HEADER
# ============================================================

def render_command_header(
    eyebrow: str,
    title: str,
    subtitle: str,
    meta: list[tuple[str, str]],
) -> None:
    """meta: list of (label, value) chips shown under the title."""

    chips_html = "".join(
        f"""<div class="rl-meta-chip"><span class="k">{k}</span><span class="v">{v}</span></div>"""
        for k, v in meta
    )

    st.markdown(
        f"""
<div class="rl-eyebrow">{eyebrow}</div>
<div class="rl-h1">{title}</div>
<div class="rl-h1-sub">{subtitle}</div>
<div class="rl-meta-row">{chips_html}</div>
""",
        unsafe_allow_html=True,
    )


# ============================================================
# BADGES
# ============================================================

def risk_badge_html(level: str) -> str:
    level = (level or "NOT TESTED").upper()
    color = RISK_COLOR.get(level, COLORS["muted"])
    return (
        f"<span class='rl-badge' style='color:{color};"
        f"background:{color}1c;border:1px solid {color}40;'>{level}</span>"
    )


def result_badge_html(result: str) -> str:
    key = (result or "").strip().upper()
    color = RESULT_COLOR.get(key, COLORS["muted"])
    label = key.replace("_", " ") or "UNKNOWN"
    return (
        f"<span class='rl-badge' style='color:{color};"
        f"background:{color}1c;border:1px solid {color}40;'>{label}</span>"
    )


# ============================================================
# KPI ROW
# ============================================================

def kpi_row(cards: list[dict[str, Any]]) -> None:
    """
    Each card dict: label, value, subtitle, icon, color (hex),
    optional trend (str, already formatted e.g. '+3.2%').
    """

    cols = st.columns(len(cards), gap="small")

    for col, card in zip(cols, cards):

        color = card.get("color", COLORS["accent"])
        trend = card.get("trend")

        trend_html = (
            f"<div class='kpi-trend' style='color:{color}'>{trend}</div>"
            if trend
            else ""
        )

        with col:
            st.markdown(
                f"""
<div class="kpi-card" style="--bar-color:{color};">
  <div class="kpi-icon" style="background:{color}18;">{card.get('icon','')}</div>
  <div class="kpi-lbl">{card['label']}</div>
  <div class="kpi-val" style="color:{color};">{card['value']}</div>
  <div class="kpi-sub">{card.get('subtitle','')}</div>
  {trend_html}
</div>
""",
                unsafe_allow_html=True,
            )


# ============================================================
# PROGRESS BAR (custom, for findings / assessment progress)
# ============================================================

def progress_bar_html(value: float, color: str, max_value: float = 100.0) -> str:
    pct = max(0.0, min(100.0, (value / max_value) * 100 if max_value else 0))
    return (
        f"<div class='rl-progress-track'>"
        f"<div class='rl-progress-fill' style='width:{pct:.1f}%;background:{color};'></div>"
        f"</div>"
    )


# ============================================================
# SECURITY GAUGE
# ============================================================

def security_gauge(score: float, height: int = 260):
    if go is None:
        return None

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": " / 100", "font": {"size": 30}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "rgba(255,255,255,.3)"},
                "steps": [
                    {"range": [0, 40], "color": "rgba(244,63,94,.20)"},
                    {"range": [40, 70], "color": "rgba(234,179,8,.16)"},
                    {"range": [70, 100], "color": "rgba(34,197,94,.16)"},
                ],
                "bar": {"color": COLORS["accent"]},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
            },
        )
    )

    fig.update_layout(
        height=height,
        margin=dict(l=20, r=20, t=30, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "rgba(255,255,255,.85)"},
    )

    return fig


# ============================================================
# OWASP / FINDING CARD
# ============================================================

def finding_card(
    owasp_id: str,
    name: str,
    risk_level: str,
    asr: Optional[float],
    tests: int,
    bypassed: int,
) -> str:

    color = RISK_COLOR.get(risk_level, COLORS["muted"])
    asr_text = f"{asr:.1f}%" if asr is not None else "N/A"
    bar = progress_bar_html(asr or 0, color)

    return f"""
<div class="finding-card" style="--accent-color:{color};">
  <div class="finding-id">{owasp_id}</div>
  <div class="finding-name">{name}</div>
  {risk_badge_html(risk_level)}
  <div class="finding-stat-row">
    <div class="finding-asr" style="color:{color};">{asr_text}</div>
    <div class="finding-meta">{bypassed}/{tests} bypassed</div>
  </div>
  {bar}
</div>
"""


def section_header(text: str) -> None:
    st.markdown(
        f"<div class='sec-heading'>{text}</div>",
        unsafe_allow_html=True,
    )


def panel_start(title: str) -> None:
    st.markdown(
        f"<div class='rt-panel'><div class='rt-panel-title'>{title}</div>",
        unsafe_allow_html=True,
    )


def panel_end() -> None:
    st.markdown("</div>", unsafe_allow_html=True)
