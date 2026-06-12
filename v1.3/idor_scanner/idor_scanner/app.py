"""Autonomous IDOR Assessment Agent - local browser dashboard.

Run either way:
    streamlit run app.py
    python app.py            # auto-relaunches under Streamlit and opens a browser

Workflow: confirm authorization -> enter URL(s) -> pick a scan mode -> Scan.
Everything else (crawling, API/parameter/object discovery, authorization testing,
ranking, evidence) is automatic. Read-only and confined to the targets you enter.
"""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


def _ensure_streamlit() -> None:
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        if get_script_run_ctx() is not None:
            return
    except Exception:
        pass
    import subprocess
    print("Launching the IDOR Scanner UI in your browser ...")
    subprocess.run(["streamlit", "run", str(Path(__file__).resolve())] + sys.argv[1:])
    sys.exit(0)


_ensure_streamlit()

import pandas as pd
import streamlit as st

from core.auto_scanner import AutoScanner
from core.browser import SessionBundle
from core.models import ScanMode, ScanResult, ScanStatus
from core.reporting import export_html, export_json, export_pdf
from core.scope import ScopeGuard
from core.storage import Store

REPORTS_DIR = Path("reports")
SESSIONS_DIR = Path("sessions")
SEV_COLOR = {"critical": "#8b1a1a", "high": "#c0431f", "medium": "#b8860b",
             "low": "#3d7a55", "info": "#5b6470"}
VERDICT_COLOR = {"pass": "#eaf3ed", "potential-idor": "#f6e7e4", "blocked": "#fff3df",
                 "review-granted": "#fdf1d6", "review-denied": "#eef0f3",
                 "inconclusive": "#eef0f3"}

st.set_page_config(page_title="Autonomous IDOR Scanner", page_icon="🛡️", layout="wide")

_URL_TOKEN = re.compile(r"[^\s,;\"']+")


def parse_targets(text: str) -> list[str]:
    out = []
    for tok in _URL_TOKEN.findall(text or ""):
        tok = tok.strip()
        if not tok or "." not in tok or tok.lower() in ("url", "target", "host"):
            continue
        if not tok.startswith(("http://", "https://")):
            tok = "https://" + tok
        if urlparse(tok).hostname:
            out.append(tok)
    return list(dict.fromkeys(out))


def load_session_bundles() -> list[SessionBundle]:
    bundles = []
    if SESSIONS_DIR.exists():
        for p in sorted(SESSIONS_DIR.glob("*.json")):
            try:
                bundles.append(SessionBundle.from_json(p.read_text(encoding="utf-8")))
            except Exception:
                pass
    return bundles


def sev_badge(sev: str) -> str:
    return (f"<span style='background:{SEV_COLOR.get(sev,'#5b6470')};color:#fff;"
            f"padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700;"
            f"text-transform:uppercase'>{sev}</span>")


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
st.sidebar.title("🛡️ Autonomous IDOR Scanner")
st.sidebar.caption("Local · read-only · authorized assessments only")

st.sidebar.subheader("1 · Authorization")
authorized = st.sidebar.checkbox("I am authorized to test the targets I enter")
if not authorized:
    st.sidebar.warning("Required before scanning.")

st.sidebar.subheader("2 · Scan mode")
mode_label = st.sidebar.radio(
    "Mode", ["Quick", "Standard", "Deep"], index=1, label_visibility="collapsed",
    captions=["Fast recon, high-confidence checks",
              "Full crawl + object discovery",
              "Max depth + AI reasoning + full reporting"],
)
mode = {"Quick": ScanMode.QUICK, "Standard": ScanMode.STANDARD, "Deep": ScanMode.DEEP}[mode_label]

st.sidebar.subheader("3 · Sessions (optional)")
all_bundles = load_session_bundles()
chosen_bundles: list[SessionBundle] = []
if all_bundles:
    for b in all_bundles:
        if st.sidebar.checkbox(f"{b.name} · {b.role}", value=True, key=f"sb_{b.name}"):
            chosen_bundles.append(b)
else:
    st.sidebar.caption("No captured sessions found.")
with st.sidebar.expander("How to add a login session"):
    st.caption("Run once per user — a browser opens, you log in, it captures the session:")
    st.code("python capture_session.py https://target.example.com user_a --role user\n"
            "python capture_session.py https://target.example.com user_b --role user", language="bash")
    st.caption("Two users enable cross-user IDOR testing. Without sessions, the agent "
               "still runs unauthenticated forced-browsing and enumeration checks.")

with st.sidebar.expander("Advanced"):
    no_sandbox = st.checkbox("Chromium --no-sandbox", value=False,
                             help="Enable on some Linux/container setups if the browser won't launch.")

if "results" not in st.session_state:
    st.session_state["results"] = []
if "store" not in st.session_state:
    st.session_state["store"] = Store("idor_scanner.db")


# --------------------------------------------------------------------------
# Header + target input
# --------------------------------------------------------------------------
st.title("Autonomous IDOR Assessment Agent")
st.caption("Enter a target, click Scan. The agent crawls, discovers APIs/parameters/objects, "
           "and tests object-level authorization automatically · OWASP A01:2021 · CWE-639")

tab_single, tab_multi = st.tabs(["Single target", "Multiple targets"])
targets: list[str] = []
with tab_single:
    one = st.text_input("Target URL", placeholder="https://target.example.com")
    if one:
        targets = parse_targets(one)
with tab_multi:
    c1, c2 = st.columns(2)
    with c1:
        up = st.file_uploader("Upload TXT or CSV of URLs", type=["txt", "csv"])
        if up is not None:
            targets += parse_targets(io.TextIOWrapper(up, encoding="utf-8", errors="ignore").read())
    with c2:
        pasted = st.text_area("…or paste URLs (one per line)", height=120,
                              placeholder="https://app1.example.com\nhttps://app2.example.com")
        if pasted:
            targets += parse_targets(pasted)
    targets = list(dict.fromkeys(targets))
    if targets:
        st.caption(f"Queued {len(targets)} target(s).")

start = st.button(f"▶ Scan ({mode_label})", type="primary", disabled=not (authorized and targets))
if targets and not authorized:
    st.info("Confirm authorization in the sidebar to enable scanning.")


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------
if start:
    launch_args = ["--no-sandbox"] if no_sandbox else []
    guard = ScopeGuard(target_urls=targets, authorized=authorized)
    st.session_state["results"] = []
    overall = st.progress(0, text="Starting…")
    n = len(targets)
    for idx, url in enumerate(targets):
        st.markdown(f"**Scanning** `{url}`  ·  mode: {mode_label}")
        bar = st.progress(0, text="Starting…")
        logbox = st.empty()
        logs: list[str] = []

        def cb(p: int, msg: str, _bar=bar, _logbox=logbox, _logs=logs):
            _bar.progress(min(p, 100), text=msg)
            _logs.append(f"[{p:3d}%] {msg}")
            _logbox.code("\n".join(_logs[-8:]), language="text")

        try:
            result = AutoScanner(url, mode, chosen_bundles, guard, launch_args).run(progress=cb)
        except Exception as exc:  # noqa: BLE001
            result = ScanResult(target=url, status=ScanStatus.ERROR, message=str(exc))
        st.session_state["results"].append(result)
        st.session_state["store"].save(result)
        overall.progress(int(100 * (idx + 1) / n), text=f"Completed {idx + 1}/{n}")
    st.success(f"Assessment complete — {n} target(s) scanned.")


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
results: list[ScanResult] = st.session_state["results"]
if results:
    st.divider()
    labels = [f"{r.target} · {r.status.value} · {r.scan_mode}" for r in results]
    sel = st.selectbox("Scanned target", range(len(results)), format_func=lambda i: labels[i])
    r = results[sel]

    if r.status == ScanStatus.BLOCKED:
        st.error(f"Scan blocked: {r.message}")
    elif r.status == ScanStatus.ERROR:
        st.error(f"Scan error: {r.message}")

    st.markdown("#### Target information")
    info = st.columns(5)
    info[0].metric("Status", r.status.value)
    info[1].metric("Mode", r.scan_mode)
    info[2].metric("Start", r.start_time or "—")
    info[3].metric("End", r.end_time or "—")
    info[4].metric("Contexts", len(r.contexts_tested) or 1)
    st.markdown(f"**URL:** `{r.target}`  ·  **Contexts tested:** {', '.join(r.contexts_tested) or 'anonymous'}")

    st.markdown("#### Scan results")
    cards = st.columns(6)
    cards[0].metric("Pages", r.endpoints)
    cards[1].metric("APIs", r.api_endpoints)
    cards[2].metric("Parameters", r.parameters)
    cards[3].metric("Objects", r.objects)
    cards[4].metric("Requests seen", r.requests_observed)
    cards[5].markdown(f"**Risk rating**<br>{sev_badge(r.risk_rating)}", unsafe_allow_html=True)

    sc = r.severity_counts()
    sev_cols = st.columns(5)
    for col, s in zip(sev_cols, ["critical", "high", "medium", "low", "info"]):
        col.metric(s.capitalize(), sc.get(s, 0))

    if r.candidates:
        st.markdown("#### Ranked IDOR candidates (auto-prioritized)")
        st.dataframe(pd.DataFrame([c.to_row() for c in r.candidates[:25]]),
                     use_container_width=True, hide_index=True)

    st.markdown("#### Findings")
    if r.findings:
        st.dataframe(pd.DataFrame([f.to_row() for f in r.findings]),
                     use_container_width=True, hide_index=True)
        for f in r.findings:
            with st.expander(f"{f.severity.value.upper()} · {f.test_case} · {f.object_id}"):
                st.markdown(f"**Endpoint:** `{f.endpoint}`")
                st.markdown(f"**Parameter:** `{f.parameter}` | **Object ID:** `{f.object_id}` | "
                            f"**Role tested:** `{f.role_tested}` | **Confidence:** `{f.confidence.value}`")
                st.markdown(f"**Description:** {f.description}")
                for e in f.evidence:
                    st.code(f"principal : {e.principal} ({e.role})\nGET {e.request_url}\n"
                            f"status    : {e.status_code}   length: {e.response_length}   "
                            f"sim-to-owner: {e.similarity_to_owner:.0%}\nsnippet   : {e.body_snippet}",
                            language="text")
                st.markdown(f"**Recommendation:** {f.recommendation}")
    else:
        st.info("No confirmed findings within tested scope.")

    st.markdown("#### Authorization matrix")
    if r.matrix:
        mdf = pd.DataFrame([{
            "Principal": c.principal, "Role": c.role, "Object": c.object_label,
            "Object ID": c.object_id, "Expected": c.expected.value,
            "Actual": c.actual.value, "Result": c.result,
        } for c in r.matrix])

        def _style(row):
            return [f"background-color:{VERDICT_COLOR.get(row['Result'], '#fff')}"] * len(row)

        st.dataframe(mdf.style.apply(_style, axis=1), use_container_width=True, hide_index=True)
    else:
        st.caption("No matrix cells recorded.")

    with st.expander("Scan log"):
        st.code("\n".join(r.log), language="text")

    st.markdown("#### Export")
    e1, e2, e3 = st.columns(3)
    out_dir = REPORTS_DIR / (urlparse(r.target).hostname or "target")
    with e1:
        if st.button("Generate HTML report"):
            p = export_html(r, str(out_dir))
            st.download_button("⬇ Download HTML", Path(p).read_bytes(),
                               file_name="idor_report.html", mime="text/html")
    with e2:
        if st.button("Generate JSON report"):
            p = export_json(r, str(out_dir))
            st.download_button("⬇ Download JSON", Path(p).read_bytes(),
                               file_name="idor_report.json", mime="application/json")
    with e3:
        if st.button("Generate PDF report"):
            try:
                p = export_pdf(r, str(out_dir))
                st.download_button("⬇ Download PDF", Path(p).read_bytes(),
                                   file_name="idor_report.pdf", mime="application/pdf")
            except RuntimeError as exc:
                st.warning(str(exc))

with st.expander("Scan history (local database)"):
    hist = st.session_state["store"].history()
    if hist:
        st.dataframe(pd.DataFrame(hist), use_container_width=True, hide_index=True)
    else:
        st.caption("No scans recorded yet.")
