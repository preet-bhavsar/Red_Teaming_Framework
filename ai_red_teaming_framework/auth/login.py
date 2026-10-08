"""
login.py  -  Production-grade login for the AI Red Teaming Framework.

BUILT-IN DEMO CREDENTIALS (change before deploying):
    admin    / admin123
    analyst  / redteam

New accounts can also be created from the Sign Up tab on this page —
see user_store.py for how those are stored (salted + hashed, on disk).

ACTIVATE in dashboard/dashboard.py  main(), right after st.set_page_config():
    from auth.login import require_login, logout_button
    require_login()

NOTE ON THIS FILE
------------------
Only the presentation layer (CSS + the render functions) and the
addition of Sign Up live here. `require_login()` and `logout_button()`
still use the exact same session_state contract as before
(`authenticated`, `current_user`), so the rest of the dashboard (auth
gate, redirects, sidebar logout) is untouched.
"""

from __future__ import annotations

import time

import streamlit as st

from auth import user_store

_USERS: dict[str, str] = {
    "admin":   "admin123",
    "analyst": "redteam",
}


def _check_credentials(username: str, password: str) -> bool:
    """True if `username`/`password` match a built-in demo account or a
    registered (signed-up) account. Username matching is case-insensitive;
    passwords are matched exactly."""
    username = username.strip().lower()
    if _USERS.get(username) == password:
        return True
    return user_store.verify_user(username, password)


# ── design tokens (kept in sync with dashboard/components.py COLORS) ───────
_BG_0      = "#05070d"
_BG_1      = "#080b13"
_PANEL     = "rgba(15, 20, 32, 0.72)"
_BORDER    = "rgba(148, 163, 184, 0.14)"
_TEXT_HI   = "#f1f5f9"
_TEXT_MID  = "rgba(226, 232, 240, 0.68)"
_TEXT_LOW  = "rgba(148, 163, 184, 0.55)"
_ACCENT    = "#22d3ee"
_ACCENT2   = "#a78bfa"
_CRITICAL  = "#f43f5e"
_SAFE      = "#22c55e"


_CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

header[data-testid="stHeader"],div[data-testid="stToolbar"],
#MainMenu,footer{{display:none!important;visibility:hidden!important;}}

html, body, [class*="css"] {{ font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif; }}

[data-testid="stAppViewContainer"]{{background:{_BG_0}!important;}}
section[data-testid="stSidebar"]{{display:none!important;}}
.block-container{{padding:0!important;max-width:100%!important;}}
*,*::before,*::after{{box-sizing:border-box;}}

/* ── two-column wrapper via Streamlit columns ── */
[data-testid="stHorizontalBlock"]{{gap:0!important;}}

/* left column — brand / context panel */
[data-testid="stHorizontalBlock"] > div:first-child {{
    background:{_BG_1};
    padding:3.5rem 4rem!important;
    border-right:1px solid rgba(255,255,255,.055);
    min-height:100vh;
    position:relative;
    overflow:hidden;
    background-image:
        linear-gradient(rgba(34,211,238,.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(34,211,238,.045) 1px, transparent 1px);
    background-size:34px 34px;
}}
[data-testid="stHorizontalBlock"] > div:first-child::before{{
    content:'';position:absolute;top:-140px;left:-100px;
    width:440px;height:440px;border-radius:50%;
    background:radial-gradient(circle,rgba(34,211,238,.12) 0%,transparent 65%);
    pointer-events:none;
}}
[data-testid="stHorizontalBlock"] > div:first-child::after{{
    content:'';position:absolute;bottom:-100px;right:-60px;
    width:300px;height:300px;border-radius:50%;
    background:radial-gradient(circle,rgba(167,139,250,.10) 0%,transparent 65%);
    pointer-events:none;
}}

/* right column — auth card */
[data-testid="stHorizontalBlock"] > div:last-child {{
    background:{_BG_0};
    padding:3.5rem 3rem!important;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
}}

/* ── left panel elements ── */
.lp-brand{{display:flex;align-items:center;gap:10px;margin-bottom:0;position:relative;z-index:1;}}
.lp-logo{{width:36px;height:36px;border-radius:10px;
         background:linear-gradient(135deg,{_ACCENT},{_ACCENT2});
         display:flex;align-items:center;justify-content:center;flex-shrink:0;
         box-shadow:0 0 0 1px rgba(255,255,255,.08) inset;font-size:1.05rem;}}
.lp-brand-name{{font-size:1.05rem;font-weight:800;color:{_TEXT_HI};letter-spacing:.3px;}}

.lp-badge{{display:inline-flex;align-items:center;gap:7px;position:relative;z-index:1;
          border:1px solid rgba(34,211,238,.3);background:rgba(34,211,238,.07);
          border-radius:999px;padding:5px 13px;margin-top:2.6rem;margin-bottom:1.4rem;}}
.lp-dot{{width:6px;height:6px;border-radius:50%;background:{_ACCENT};
        box-shadow:0 0 6px {_ACCENT};animation:blink 2.2s ease-in-out infinite;flex-shrink:0;display:inline-block;}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:.28}}}}
.lp-badge-txt{{font-size:10px;font-weight:700;letter-spacing:1.5px;
              text-transform:uppercase;color:{_ACCENT};}}

.lp-h1{{font-size:2.35rem;font-weight:800;position:relative;z-index:1;
       line-height:1.14;color:{_TEXT_HI};margin:0 0 .5rem;letter-spacing:-.5px;}}
.lp-h1 .acc{{background:linear-gradient(90deg,{_ACCENT},{_ACCENT2});
            -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}}
.lp-tagline{{font-size:.72rem;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;
            color:{_TEXT_LOW};margin:0 0 1.6rem;position:relative;z-index:1;}}
.lp-desc{{font-size:.88rem;font-weight:400;color:{_TEXT_MID};position:relative;z-index:1;
         line-height:1.75;max-width:340px;margin:0 0 2.4rem;}}

.lp-stats{{display:grid;grid-template-columns:1fr 1fr;gap:9px;position:relative;z-index:1;}}
.lp-stat{{background:rgba(255,255,255,.033);border:1px solid rgba(255,255,255,.07);
         border-radius:12px;padding:13px 15px;}}
.lp-stat-v{{font-family:'JetBrains Mono',monospace;font-size:1.3rem;font-weight:700;
           color:{_ACCENT};line-height:1;margin-bottom:5px;}}
.lp-stat-k{{font-size:.68rem;font-weight:500;color:{_TEXT_LOW};
           letter-spacing:.4px;text-transform:uppercase;}}

.lp-context{{display:flex;gap:9px;align-items:flex-start;margin-top:1.8rem;
            padding:12px 14px;border-radius:11px;position:relative;z-index:1;
            background:rgba(255,255,255,.028);border:1px solid rgba(255,255,255,.065);
            max-width:370px;}}
.lp-context svg{{flex-shrink:0;margin-top:1px;}}
.lp-context p{{font-size:.72rem;line-height:1.6;color:{_TEXT_LOW};margin:0;}}

/* ── right panel elements ── */
.lp-card{{width:100%;max-width:378px;}}
.lp-icon{{width:48px;height:48px;border-radius:13px;background:rgba(34,211,238,.08);
         border:1px solid rgba(34,211,238,.2);display:flex;align-items:center;
         justify-content:center;margin-bottom:1.2rem;}}
.lp-title{{font-size:1.45rem;font-weight:700;
          color:{_TEXT_HI};letter-spacing:-.3px;margin-bottom:5px;}}
.lp-sub{{font-size:.84rem;font-weight:400;color:{_TEXT_MID};margin-bottom:.6rem;}}
.lp-lbl{{display:flex;justify-content:space-between;align-items:center;
        font-size:.73rem;font-weight:600;letter-spacing:.6px;
        text-transform:uppercase;color:{_TEXT_LOW};margin-bottom:6px;margin-top:14px;}}
.lp-hint{{font-size:.68rem;color:{_TEXT_LOW};margin-top:5px;line-height:1.5;}}

/* ── tabs (Sign In / Sign Up) ── */
div[data-testid="stTabs"]{{margin-top:.4rem;}}
div[data-baseweb="tab-list"]{{
  gap:4px!important;background:rgba(255,255,255,.032);
  border:1px solid rgba(255,255,255,.07);border-radius:12px;
  padding:4px!important;width:100%;}}
button[data-baseweb="tab"]{{
  flex:1 1 0;justify-content:center;border-radius:9px!important;
  padding:9px 0!important;background:transparent!important;}}
button[data-baseweb="tab"] p{{
  font-size:.82rem!important;font-weight:600!important;
  color:{_TEXT_LOW}!important;letter-spacing:.2px;}}
button[data-baseweb="tab"][aria-selected="true"]{{
  background:rgba(34,211,238,.10)!important;}}
button[data-baseweb="tab"][aria-selected="true"] p{{color:{_TEXT_HI}!important;}}
div[data-baseweb="tab-highlight"]{{display:none!important;}}
div[data-baseweb="tab-border"]{{background:transparent!important;height:0!important;}}
div[data-baseweb="tab-panel"]{{padding:1.1rem 0 0 0!important;}}

/* show/hide password toggle checkbox */
div[data-testid="stCheckbox"]{{margin-top:-6px;margin-bottom:-6px;}}
div[data-testid="stCheckbox"] label{{gap:5px!important;}}
div[data-testid="stCheckbox"] label p{{font-size:.7rem!important;color:{_TEXT_LOW}!important;
                                       letter-spacing:.3px;text-transform:uppercase;font-weight:600;}}

/* input fields */
div[data-testid="stTextInput"] label{{display:none!important;}}
div[data-baseweb="input"]>div{{
  background:rgba(255,255,255,.038)!important;
  border:1px solid rgba(255,255,255,.09)!important;
  border-radius:11px!important;
  transition:border-color .2s,box-shadow .2s!important;}}
div[data-baseweb="input"]>div:focus-within{{
  border-color:rgba(34,211,238,.45)!important;
  box-shadow:0 0 0 3.5px rgba(34,211,238,.07)!important;
  background:rgba(34,211,238,.025)!important;}}
div[data-baseweb="input"] input{{
  font-family:'Inter',sans-serif!important;
  color:{_TEXT_HI}!important;font-size:.9rem!important;padding:11px 14px!important;}}
div[data-baseweb="input"] input::placeholder{{color:rgba(255,255,255,.18)!important;}}

/* primary buttons (Sign In / Create Account) */
div[data-testid="stButton"]>button[kind="primary"]{{
  width:100%!important;margin-top:14px!important;padding:13px!important;
  background:linear-gradient(135deg,{_ACCENT} 0%,{_ACCENT2} 100%)!important;
  border:none!important;border-radius:11px!important;
  font-size:.92rem!important;
  font-weight:700!important;letter-spacing:.4px!important;color:#04121a!important;
  transition:opacity .2s,transform .15s!important;}}
div[data-testid="stButton"]>button[kind="primary"]:hover{{opacity:.9!important;transform:translateY(-1px)!important;}}
div[data-testid="stButton"]>button[kind="primary"]:focus-visible{{
  outline:2px solid {_ACCENT}!important;outline-offset:2px!important;}}

/* success alert (signup) */
div[data-testid="stAlert"] p{{font-size:.83rem!important;}}
div[data-testid="stSuccess"]{{
  background:rgba(34,197,94,.08)!important;
  border:1px solid rgba(34,197,94,.25)!important;
  border-radius:10px!important;color:#86efac!important;}}

/* error alert */
div[data-testid="stAlert"]{{
  background:rgba(244,63,94,.08)!important;
  border:1px solid rgba(244,63,94,.25)!important;
  border-radius:10px!important;color:#fda4af!important;}}

/* security notice + footer */
.lp-security-note{{display:flex;gap:8px;align-items:flex-start;margin-top:1.5rem;
                   padding:11px 13px;border-radius:10px;
                   background:rgba(34,211,238,.045);border:1px solid rgba(34,211,238,.16);}}
.lp-security-note svg{{flex-shrink:0;margin-top:2px;}}
.lp-security-note p{{font-size:.71rem;line-height:1.55;color:{_TEXT_MID};margin:0;}}

.lp-foot{{margin-top:1.6rem;text-align:center;font-size:.7rem;
         color:{_TEXT_LOW};letter-spacing:.2px;line-height:1.7;}}
.lp-foot b{{color:{_TEXT_MID};}}
</style>
"""


_SHIELD_ICON = """
<svg width="17" height="17" viewBox="0 0 24 24" fill="none"
     stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
</svg>
"""

_LOCK_ICON = """
<svg width="22" height="22" viewBox="0 0 24 24" fill="none"
     stroke="#22d3ee" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="11" width="18" height="11" rx="2"/>
  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
</svg>
"""

_INFO_ICON = f"""
<svg width="15" height="15" viewBox="0 0 24 24" fill="none"
     stroke="{_ACCENT}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
</svg>
"""


def _render_left_panel() -> None:
    st.markdown(f"""<div class="lp-brand">
<div class="lp-logo">{_SHIELD_ICON}</div>
<span class="lp-brand-name">RedLens</span>
</div>

<div class="lp-badge">
<span class="lp-dot"></span>
<span class="lp-badge-txt">System Active</span>
</div>

<div class="lp-h1"><span class="acc">RedLens</span> Security<br>Platform</div>
<div class="lp-tagline">AI-Powered Red Teaming &amp; LLM Security Assessment</div>
<p class="lp-desc">Automated adversarial testing, OWASP LLM Top&nbsp;10 mapping, and vulnerability analysis for language models running locally via Ollama.</p>

<div class="lp-stats">
<div class="lp-stat"><div class="lp-stat-v">10</div><div class="lp-stat-k">OWASP LLM categories</div></div>
<div class="lp-stat"><div class="lp-stat-v">Local</div><div class="lp-stat-k">Model execution</div></div>
<div class="lp-stat"><div class="lp-stat-v">Auto</div><div class="lp-stat-k">Attack scoring</div></div>
<div class="lp-stat"><div class="lp-stat-v">PDF</div><div class="lp-stat-k">Report export</div></div>
</div>

<div class="lp-context">
{_INFO_ICON}
<p>This platform assesses AI/LLM systems for security weaknesses. It is intended for authorized use on models and environments you own or are permitted to test.</p>
</div>
""", unsafe_allow_html=True)


def _render_sign_in_tab() -> None:
    st.markdown("<span class='lp-lbl'>Username</span>", unsafe_allow_html=True)
    username = st.text_input(
        "Username", placeholder="e.g. admin", label_visibility="collapsed",
        key="rt_signin_username",
    )

    st.markdown("<span class='lp-lbl'>Password</span>", unsafe_allow_html=True)
    show_password = st.checkbox(
        "Show password", key="rt_signin_show_pwd", value=False,
        help="Toggle password visibility",
    )
    # Fixed `key`s throughout this page are what keep values intact across
    # reruns — e.g. without one here, flipping `type` on this same widget
    # would make Streamlit treat it as a brand-new widget and silently
    # clear whatever was typed.
    password = st.text_input(
        "Password",
        type="default" if show_password else "password",
        placeholder="Enter your password",
        label_visibility="collapsed",
        key="rt_signin_password",
    )

    submitted = st.button("Sign In  \u2192", width="stretch", type="primary", key="rt_signin_submit")

    if submitted:
        with st.spinner("Verifying credentials\u2026"):
            time.sleep(0.15)  # brief, honest UI feedback — not simulated auth
            is_valid = bool(username) and bool(password) and _check_credentials(username, password)

        if is_valid:
            st.session_state["authenticated"] = True
            st.session_state["current_user"] = username.strip()
            st.rerun()
        elif not username or not password:
            st.error("\u2716  Username and password are both required.")
        else:
            st.error("\u2716  Invalid username or password. Access denied.")


def _render_sign_up_tab() -> None:
    st.markdown("<span class='lp-lbl'>Username</span>", unsafe_allow_html=True)
    new_username = st.text_input(
        "New username", placeholder="Choose a username", label_visibility="collapsed",
        key="rt_signup_username",
    )

    st.markdown("<span class='lp-lbl'>Password</span>", unsafe_allow_html=True)
    show_password = st.checkbox(
        "Show password", key="rt_signup_show_pwd", value=False,
        help="Toggle password visibility for both fields below",
    )
    new_password = st.text_input(
        "New password",
        type="default" if show_password else "password",
        placeholder="Create a password",
        label_visibility="collapsed",
        key="rt_signup_password",
    )

    st.markdown("<span class='lp-lbl'>Confirm Password</span>", unsafe_allow_html=True)
    confirm_password = st.text_input(
        "Confirm password",
        type="default" if show_password else "password",
        placeholder="Re-enter your password",
        label_visibility="collapsed",
        key="rt_signup_confirm",
    )
    st.markdown(
        "<div class='lp-hint'>3-32 characters for the username. "
        "Password needs 8+ characters with at least one letter and one number.</div>",
        unsafe_allow_html=True,
    )

    submitted = st.button("Create Account  \u2192", width="stretch", type="primary", key="rt_signup_submit")

    if submitted:
        error = user_store.validate_new_account(new_username, new_password, confirm_password)
        if error:
            st.error(f"\u2716  {error}")
        else:
            with st.spinner("Creating account\u2026"):
                user_store.register_user(new_username, new_password)
                time.sleep(0.15)
            # Real login, using the account that was just created — not a
            # simulated/fake auth step.
            st.session_state["authenticated"] = True
            st.session_state["current_user"] = new_username.strip().lower()
            st.rerun()


def _render_right_panel() -> None:
    st.markdown(f"""<div class="lp-card">
<div class="lp-icon">{_LOCK_ICON}</div>
<div class="lp-title">Secure Access</div>
<div class="lp-sub">Sign in or create an account to reach the security dashboard</div>
</div>
""", unsafe_allow_html=True)

    tab_signin, tab_signup = st.tabs(["Sign In", "Sign Up"])
    with tab_signin:
        _render_sign_in_tab()
    with tab_signup:
        _render_sign_up_tab()

    st.markdown(f"""<div class="lp-security-note">
{_INFO_ICON}
<p><b style="color:{_TEXT_HI}">Authorized access only.</b> All security assessments are performed within the configured testing environment.</p>
</div>
<div class="lp-foot">
<b>RedLens Security Platform</b> &nbsp;\u00b7&nbsp; AI Security Assessment<br>
&copy; 2026 RedLens Security Platform
</div>
""", unsafe_allow_html=True)


def _render_login_form() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)

    left, right = st.columns([1.15, 1])
    with left:
        _render_left_panel()
    with right:
        _render_right_panel()


def require_login() -> None:
    """Gate the dashboard. Call once at top of main() in dashboard.py."""
    if not st.session_state.get("authenticated", False):
        _render_login_form()
        st.stop()


def logout_button(location: str = "sidebar") -> None:
    """Show logged-in username + Sign Out button."""
    container = st.sidebar if location == "sidebar" else st
    user = st.session_state.get("current_user", "unknown")
    container.markdown(
        f"<div style='font-size:.82rem;color:rgba(255,255,255,.5);padding:4px 0'>"
        f"&#x1F464;&nbsp;<b style='color:#f1f5f9'>{user}</b></div>",
        unsafe_allow_html=True,
    )
    if container.button("Sign Out", key="rt_logout"):
        st.session_state["authenticated"] = False
        st.session_state["current_user"] = ""
        st.rerun()
