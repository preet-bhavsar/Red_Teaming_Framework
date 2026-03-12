from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

# Optional: Plotly charts look great in demos, but we fall back gracefully if not installed.
try:  # pragma: no cover
    import plotly.express as px  # type: ignore
    import plotly.graph_objects as go  # type: ignore
except Exception:  # noqa: BLE001
    px = None  # type: ignore[assignment]
    go = None  # type: ignore[assignment]


# ---------- Theme + styling ----------
def _inject_css() -> None:
    st.markdown(
        """
<style>
  /* Hide Streamlit chrome (top-right Deploy / menu) for a clean presentation look */
  header[data-testid="stHeader"] { display: none; }
  div[data-testid="stToolbar"] { display: none; }
  #MainMenu { visibility: hidden; }
  footer { visibility: hidden; }

  /* Global */
  .stApp { background: radial-gradient(1200px 800px at 20% 0%, #0b2a3a 0%, #070a12 45%, #05060b 100%); }
  section[data-testid="stSidebar"] { background: linear-gradient(180deg, #070a12 0%, #05060b 100%); border-right: 1px solid rgba(255,255,255,0.06); }
  .block-container { padding-top: 1.2rem; padding-bottom: 2.5rem; }

  /* Headers */
  .rt-title { font-size: 1.65rem; font-weight: 800; letter-spacing: 0.3px; }
  .rt-subtitle { color: rgba(255,255,255,0.72); margin-top: 0.2rem; }
  .rt-section { margin-top: 1.2rem; }

  /* Cards */
  .rt-card {
    background: rgba(10, 14, 22, 0.72);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 14px;
    padding: 14px 14px 12px 14px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.35);
  }
  .rt-card:hover { border-color: rgba(34, 211, 238, 0.28); }
  .rt-card-label { color: rgba(255,255,255,0.70); font-size: 0.82rem; }
  .rt-card-value { font-size: 1.55rem; font-weight: 800; margin-top: 4px; }
  .rt-card-delta { color: rgba(255,255,255,0.60); font-size: 0.78rem; margin-top: 2px; }

  /* Pills / tags */
  .rt-pill {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 700;
    border: 1px solid rgba(255,255,255,0.12);
    background: rgba(255,255,255,0.05);
    color: rgba(255,255,255,0.86);
  }

  /* Containers */
  .rt-panel {
    background: rgba(10, 14, 22, 0.62);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 14px;
    padding: 16px;
  }
  .rt-kv { color: rgba(255,255,255,0.80); font-size: 0.90rem; }
  .rt-muted { color: rgba(255,255,255,0.65); }
  .rt-good { color: #34d399; font-weight: 800; }
  .rt-bad { color: #fb7185; font-weight: 800; }
  .rt-accent { color: #22d3ee; font-weight: 800; }

  /* Streamlit widgets polish */
  div[data-testid="stMetric"] { background: rgba(10, 14, 22, 0.62); border: 1px solid rgba(255,255,255,0.08); padding: 12px; border-radius: 14px; }
  div[data-testid="stMetric"]:hover { border-color: rgba(34, 211, 238, 0.28); }
  div[data-testid="stDataFrame"] { border-radius: 14px; overflow: hidden; border: 1px solid rgba(255,255,255,0.08); }

  /* Code blocks */
  pre { border-radius: 14px !important; border: 1px solid rgba(255,255,255,0.08) !important; background: rgba(7,10,18,0.85) !important; }
</style>
""",
        unsafe_allow_html=True,
    )


def _pill(text: str, color: str) -> str:
    return f"<span class='rt-pill' style='border-color:{color}55;background:{color}18;color:{color};'>{text}</span>"


def _category_color(category: str) -> str:
    palette = {
        "jailbreak": "#22d3ee",  # cyan
        "cybercrime": "#60a5fa",  # blue
        "weapon": "#f59e0b",  # amber
        "weapons": "#f59e0b",
        "data_extraction": "#a78bfa",  # purple
        "benign": "#34d399",  # green
        "unknown": "#94a3b8",  # slate
    }
    return palette.get(str(category).strip().lower(), "#94a3b8")


# ---------- Data loading (cached) ----------
@st.cache_data(show_spinner=False)
def load_results_cached(results_path: str) -> pd.DataFrame:
    p = Path(results_path)
    if not p.exists():
        return pd.DataFrame()
    df = pd.read_csv(p)
    return df


def _safe_bool_series(s: pd.Series) -> pd.Series:
    # attack_success may be bool, int (0/1), or strings. Normalize without touching backend pipeline.
    if s.dtype == bool:
        return s.fillna(False)
    if pd.api.types.is_numeric_dtype(s):
        return s.fillna(0).astype(int).astype(bool)
    return s.astype(str).str.strip().str.lower().isin({"1", "true", "t", "yes", "y"})


# ---------- UI components ----------
def _metric_cards(df: pd.DataFrame) -> None:
    total = int(len(df))
    success_col_present = "attack_success" in df.columns
    successes = int(_safe_bool_series(df["attack_success"]).sum()) if success_col_present and total else 0
    blocked = total - successes
    success_rate = (successes / total * 100.0) if total else 0.0

    c1, c2, c3, c4 = st.columns(4, gap="medium")
    with c1:
        st.markdown(
            f"<div class='rt-card'><div class='rt-card-label'>Total Attacks</div>"
            f"<div class='rt-card-value rt-accent'>{total}</div>"
            f"<div class='rt-card-delta rt-muted'>Rows in results.csv</div></div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"<div class='rt-card'><div class='rt-card-label'>Successful Attacks</div>"
            f"<div class='rt-card-value' style='color:#fb7185'>{successes}</div>"
            f"<div class='rt-card-delta rt-muted'>Model did not refuse</div></div>",
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"<div class='rt-card'><div class='rt-card-label'>Blocked Attacks</div>"
            f"<div class='rt-card-value' style='color:#34d399'>{blocked}</div>"
            f"<div class='rt-card-delta rt-muted'>Refusal / safe completion</div></div>",
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"<div class='rt-card'><div class='rt-card-label'>Success Rate</div>"
            f"<div class='rt-card-value rt-accent'>{success_rate:.1f}%</div>"
            f"<div class='rt-card-delta rt-muted'>Higher is worse (more unsafe)</div></div>",
            unsafe_allow_html=True,
        )


def _charts(df: pd.DataFrame) -> None:
    st.markdown("<div class='rt-section'></div>", unsafe_allow_html=True)
    st.subheader("Security Analytics")

    if df.empty:
        st.info("No data to plot.")
        return

    df_plot = df.copy()
    if "category" not in df_plot.columns:
        df_plot["category"] = "unknown"
    if "attack_success" not in df_plot.columns:
        df_plot["attack_success"] = False

    df_plot["attack_success"] = _safe_bool_series(df_plot["attack_success"])
    df_plot["category"] = df_plot["category"].fillna("unknown").astype(str)

    left, mid, right = st.columns([1.2, 1.2, 1.0], gap="medium")

    # A) Category distribution
    cat_counts = (
        df_plot["category"]
        .astype(str)
        .str.strip()
        .replace("", "unknown")
        .value_counts()
        .rename_axis("category")
        .reset_index(name="count")
    )

    # B) Success rate by category
    grp = df_plot.groupby("category", dropna=False)["attack_success"]
    cat_success = (
        grp.mean()
        .mul(100.0)
        .rename("success_rate_pct")
        .reset_index()
        .sort_values("success_rate_pct", ascending=False)
    )

    # C) Overall "security score" gauge (inverted success rate)
    total = int(len(df_plot))
    successes = int(df_plot["attack_success"].sum())
    success_rate = (successes / total * 100.0) if total else 0.0
    security_score = max(0.0, 100.0 - success_rate)  # higher is better

    with left:
        st.markdown("<div class='rt-panel'>", unsafe_allow_html=True)
        st.markdown("**Attack Category Distribution**", unsafe_allow_html=True)
        if px is not None:
            fig = px.bar(
                cat_counts,
                x="category",
                y="count",
                color="category",
                color_discrete_map={c: _category_color(c) for c in cat_counts["category"].tolist()},
            )
            fig.update_layout(
                height=340,
                margin=dict(l=10, r=10, t=40, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="rgba(255,255,255,0.85)"),
                showlegend=False,
                xaxis=dict(title="", tickangle=-15, gridcolor="rgba(255,255,255,0.08)"),
                yaxis=dict(title="Attacks", gridcolor="rgba(255,255,255,0.08)"),
            )
            st.plotly_chart(fig, width="stretch")
        else:
            st.bar_chart(cat_counts.set_index("category")["count"])
            st.caption("Tip: install `plotly` for nicer charts.")
        st.markdown("</div>", unsafe_allow_html=True)

    with mid:
        st.markdown("<div class='rt-panel'>", unsafe_allow_html=True)
        st.markdown("**Attack Success Rate by Category**", unsafe_allow_html=True)
        if px is not None:
            fig = px.bar(
                cat_success,
                x="category",
                y="success_rate_pct",
                color="category",
                color_discrete_map={c: _category_color(c) for c in cat_success["category"].tolist()},
            )
            fig.update_layout(
                height=340,
                margin=dict(l=10, r=10, t=40, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="rgba(255,255,255,0.85)"),
                showlegend=False,
                xaxis=dict(title="", tickangle=-15, gridcolor="rgba(255,255,255,0.08)"),
                yaxis=dict(title="Success % (unsafe)", gridcolor="rgba(255,255,255,0.08)", range=[0, 100]),
            )
            st.plotly_chart(fig, width="stretch")
        else:
            st.bar_chart(cat_success.set_index("category")["success_rate_pct"])
            st.caption("Tip: install `plotly` for nicer charts.")
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='rt-panel'>", unsafe_allow_html=True)
        st.markdown("**Overall Security Score**", unsafe_allow_html=True)
        st.caption("Higher is better. Calculated as $100 - \\mathrm{success\\_rate}$.")
        if go is not None:
            fig = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=float(security_score),
                    number={"suffix": " / 100", "font": {"color": "rgba(255,255,255,0.9)", "size": 28}},
                    gauge={
                        "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "rgba(255,255,255,0.35)"},
                        "bar": {"color": "#22d3ee"},
                        "bgcolor": "rgba(0,0,0,0)",
                        "borderwidth": 0,
                        "steps": [
                            {"range": [0, 50], "color": "rgba(251,113,133,0.22)"},
                            {"range": [50, 80], "color": "rgba(245,158,11,0.18)"},
                            {"range": [80, 100], "color": "rgba(52,211,153,0.16)"},
                        ],
                    },
                )
            )
            fig.update_layout(
                height=340,
                margin=dict(l=10, r=10, t=35, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="rgba(255,255,255,0.85)"),
            )
            st.plotly_chart(fig, width="stretch")
        else:
            # Gauge-like fallback (no extra dependencies): score + progress bar.
            st.markdown(f"<div class='rt-card-value rt-accent'>{security_score:.1f} / 100</div>", unsafe_allow_html=True)
            st.progress(int(round(security_score)))
            st.caption("Tip: install `plotly` for a true gauge widget.")
        st.markdown("</div>", unsafe_allow_html=True)


def _styled_logs_table(df: pd.DataFrame) -> None:
    st.markdown("<div class='rt-section'></div>", unsafe_allow_html=True)
    st.subheader("Attack Logs")

    if df.empty:
        st.info("No rows to display.")
        return

    cols = [c for c in ["attack_id", "prompt", "category", "attack_success"] if c in df.columns]
    view = df[cols].copy()

    if "attack_success" in view.columns:
        view["attack_success"] = _safe_bool_series(view["attack_success"])

    # Styler: color category + highlight successful attacks (unsafe) to draw attention.
    def _style_row(row: pd.Series) -> list[str]:
        styles: list[str] = [""] * len(row)
        if "attack_success" in row.index and bool(row["attack_success"]):
            # Attack succeeded (unsafe) -> subtle red tint across row
            styles = ["background-color: rgba(251, 113, 133, 0.10);"] * len(row)
        return styles

    def _style_category(val: Any) -> str:
        c = str(val) if pd.notna(val) else "unknown"
        color = _category_color(c)
        return f"background-color: {color}20; color: {color}; font-weight: 800;"

    styler = view.style.apply(_style_row, axis=1)
    if "category" in view.columns:
        styler = styler.map(_style_category, subset=["category"])

    # Make prompt column wrap nicely
    styler = styler.set_properties(
        subset=["prompt"] if "prompt" in view.columns else None,
        **{"white-space": "pre-wrap", "max-width": "820px"},
    )

    st.dataframe(styler, width="stretch", hide_index=True)


def _detail_viewer(df: pd.DataFrame) -> None:
    st.markdown("<div class='rt-section'></div>", unsafe_allow_html=True)
    st.subheader("Detailed Response Viewer")

    if df.empty:
        st.info("No rows to inspect.")
        return

    if "attack_id" in df.columns:
        ids = df["attack_id"].astype(str).tolist()
        selected_id = st.selectbox("Select attack_id", ids, key="detail_attack_id")
        row = df[df["attack_id"].astype(str) == selected_id].iloc[0]
    else:
        idx = st.number_input("Row index", min_value=0, max_value=max(0, len(df) - 1), value=0, step=1)
        row = df.iloc[int(idx)]

    prompt = str(row.get("prompt", ""))
    response = str(row.get("response", ""))
    category = str(row.get("category", "unknown"))
    success = bool(_safe_bool_series(pd.Series([row.get("attack_success", False)])).iloc[0])

    cat_color = _category_color(category)
    cat_pill = _pill(category, cat_color)

    st.markdown("<div class='rt-panel'>", unsafe_allow_html=True)
    st.markdown(f"**Category:** {cat_pill}", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    c1, c2 = st.columns([1.0, 1.0], gap="medium")
    with c1:
        st.markdown("<div class='rt-panel'>", unsafe_allow_html=True)
        st.markdown("**Prompt Tested**", unsafe_allow_html=True)
        st.code(prompt or "(empty)")
        st.markdown("</div>", unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='rt-panel'>", unsafe_allow_html=True)
        st.markdown("**Model Response**", unsafe_allow_html=True)
        st.code(response or "(empty)")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='rt-panel'>", unsafe_allow_html=True)
    st.markdown("**Attack Result**", unsafe_allow_html=True)
    if success:
        st.markdown("<div class='rt-bad'>✖ Attack Succeeded (unsafe)</div>", unsafe_allow_html=True)
        st.caption("The heuristic flagged this output as a successful policy bypass / harmful compliance.")
    else:
        st.markdown("<div class='rt-good'>✔ Attack Blocked (safe)</div>", unsafe_allow_html=True)
        st.caption("The heuristic flagged this output as a refusal or safe completion.")
    st.markdown("</div>", unsafe_allow_html=True)


# ---------- Page ----------
def main() -> None:
    logging.basicConfig(level=logging.INFO)

    base_dir = Path(__file__).resolve().parent.parent
    data_dir = base_dir / "data"
    results_path = str(data_dir / "results.csv")

    st.set_page_config(page_title="AI Red Team Dashboard", layout="wide")
    _inject_css()

    # Sidebar (navigation + controls)
    with st.sidebar:
        st.markdown("<div class='rt-title'>AI Red Team Framework</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='rt-subtitle'>Modern dashboard for automated LLM security testing via adversarial prompts.</div>",
            unsafe_allow_html=True,
        )
        st.markdown("---")

        page = st.radio("Navigation", ["Overview", "Attack Logs", "Response Viewer"], index=0)
        st.markdown("---")

        # Load data (cached) + reload button
        if st.button("Reload Results", width="stretch"):
            load_results_cached.clear()
            st.success("Reloaded. If the pipeline just finished, your new results should appear now.")

        st.markdown("**Category Filter**")

    # Load results with spinner (UX)
    with st.spinner("Loading results from data/results.csv ..."):
        df = load_results_cached(results_path)

    if df.empty:
        st.markdown("<div class='rt-title'>AI Red Teaming Dashboard</div>", unsafe_allow_html=True)
        st.markdown(
            "<div class='rt-subtitle'>No results found yet. Run the pipeline to generate <code>data/results.csv</code>.</div>",
            unsafe_allow_html=True,
        )
        st.markdown("<div class='rt-section'></div>", unsafe_allow_html=True)
        st.error(f"Missing or empty file: `{results_path}`")
        st.info("Run from `ai_red_teaming_framework/`: `python -m src.attack_runner`")
        return

    # Normalize expected columns (UI-only; does not change pipeline outputs on disk)
    df_ui = df.copy()
    if "category" not in df_ui.columns:
        df_ui["category"] = "unknown"
    if "attack_success" not in df_ui.columns:
        df_ui["attack_success"] = False

    categories = ["(all)"] + sorted(df_ui["category"].dropna().astype(str).unique().tolist())
    selected_category = st.sidebar.selectbox("Category", categories, index=0)

    filtered = df_ui
    if selected_category != "(all)":
        filtered = filtered[filtered["category"].astype(str) == selected_category]

    # Sidebar dataset stats
    with st.sidebar:
        st.markdown("---")
        st.markdown("**Dataset Stats**")
        total_rows = int(len(df_ui))
        filt_rows = int(len(filtered))
        unique_cats = int(df_ui["category"].nunique(dropna=True))
        st.write(f"- **Total rows**: {total_rows}")
        st.write(f"- **Filtered rows**: {filt_rows}")
        st.write(f"- **Categories**: {unique_cats}")
        if "attack_success" in df_ui.columns and len(df_ui):
            sr = float(_safe_bool_series(df_ui["attack_success"]).mean()) * 100.0
            st.write(f"- **Overall success rate**: {sr:.1f}%")

    # Header
    st.markdown("<div class='rt-title'>AI Red Teaming Dashboard</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='rt-subtitle'>Threat simulation results from the latest run (Ollama model responses + heuristic analysis).</div>",
        unsafe_allow_html=True,
    )

    # Metrics cards always on top (requirement)
    _metric_cards(filtered)

    if page == "Overview":
        _charts(filtered)
        _styled_logs_table(filtered)
        _detail_viewer(filtered)
    elif page == "Attack Logs":
        _styled_logs_table(filtered)
    else:
        _detail_viewer(filtered)


if __name__ == "__main__":
    main()


