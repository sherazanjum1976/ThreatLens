"""
app.py
======
ThreatLens — Streamlit UI, orchestration, Gemini AI insight, and result display.

DEPENDENCY RULE: this file imports FROM input_helpers.py only. It never
defines source-lookup logic itself — it just loops over input_helpers.SOURCES.
That means adding a new intel source never requires touching this file.

Flow:
  1. User picks indicator type (IP / Domain / URL) + a value + a knowledge level.
  2. validate_input() checks the value.
  3. We loop over every function in input_helpers.SOURCES, collecting results.
  4. We build a knowledge-level-specific prompt and call Gemini for an
     AI Insight summary.
  5. We render a color-coded verdict, the AI Insight card, and an
     expandable raw-data panel per source.
"""

import os
import json

import streamlit as st
import google.generativeai as genai

from input_helpers import validate_input, SOURCES


# ---------------------------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------------------------

st.set_page_config(page_title="ThreatLens", page_icon="🔎", layout="centered")


# ---------------------------------------------------------------------------
# SIDEBAR — API KEYS
# ---------------------------------------------------------------------------

def _get_secret(name: str) -> str:
    """Prefer st.secrets (Colab/Cloud), fall back to an already-set env var."""
    try:
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.environ.get(name, "")


with st.sidebar:
    st.header("🔑 API Keys")
    st.caption("Keys stay only in this browser session — nothing is stored.")

    vt_key_input = st.text_input(
        "VirusTotal API Key", value=_get_secret("VT_API_KEY"), type="password",
        help="Free key from virustotal.com/gui/join-us",
    )
    gemini_key_input = st.text_input(
        "Gemini API Key", value=_get_secret("GEMINI_API_KEY"), type="password",
        help="Free key from aistudio.google.com/apikey",
    )

    # Push keys into env vars so input_helpers.py (which never imports
    # streamlit) can still read them via os.environ.
    os.environ["VT_API_KEY"] = vt_key_input
    os.environ["GEMINI_API_KEY"] = gemini_key_input

    st.divider()
    st.caption("Sources currently active:")
    for name in SOURCES:
        st.markdown(f"- {name}")


# ---------------------------------------------------------------------------
# MAIN INPUT FORM
# ---------------------------------------------------------------------------

st.title("🔎 ThreatLens")
st.caption("Check whether an IP, domain, or URL looks safe — powered by VirusTotal, WHOIS, and Gemini.")

col1, col2 = st.columns([2, 1])
with col1:
    indicator_type = st.radio("Indicator type", ["IP", "Domain", "URL"], horizontal=True)
with col2:
    knowledge_level = st.selectbox("Explain results as...", ["Beginner", "Intermediate", "Expert"])

raw_value = st.text_input(
    f"Enter the {indicator_type.lower()} to check",
    placeholder={"IP": "8.8.8.8", "Domain": "example.com", "URL": "https://example.com/path"}[indicator_type],
)

scan_clicked = st.button("Scan", type="primary", use_container_width=True)


# ---------------------------------------------------------------------------
# COLOR-CODED VERDICT HELPERS  (display-only, lives here not in input_helpers)
# ---------------------------------------------------------------------------

_STATUS_RANK = {"malicious": 3, "suspicious": 2, "unknown": 1, "error": 1, "info": 0, "clean": 0}

_VERDICT_STYLE = {
    "malicious": ("🔴", "#ffe2e2", "#7a0000", "Malicious signals detected"),
    "suspicious": ("🟠", "#fff3cd", "#7a5200", "Some suspicious signals"),
    "clean": ("🟢", "#e3f7e9", "#0a5c2c", "Looks safe"),
    "unclear": ("⚪", "#eeeeee", "#333333", "Not enough data to decide"),
}


def compute_overall_verdict(results: list) -> str:
    """Aggregate every source's status into one overall bucket."""
    statuses = [r["status"] for r in results]
    if "malicious" in statuses:
        return "malicious"
    if "suspicious" in statuses:
        return "suspicious"
    informative = [s for s in statuses if s not in ("error",)]
    if not informative:
        return "unclear"
    if all(s in ("clean", "info") for s in informative):
        return "clean"
    return "unclear"


def render_verdict_banner(verdict: str):
    emoji, bg, fg, label = _VERDICT_STYLE[verdict]
    st.markdown(
        f"""
        <div style="background:{bg};color:{fg};padding:1rem 1.25rem;
                     border-radius:0.6rem;font-size:1.1rem;font-weight:600;
                     margin:0.5rem 0 1rem 0;">
            {emoji} &nbsp; {label}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# GEMINI PROMPT BUILDING + CALL
# ---------------------------------------------------------------------------

_LEVEL_INSTRUCTIONS = {
    "Beginner": (
        "Explain like the reader has never used a security tool before. "
        "Avoid jargon (or define it immediately in plain words). Use short "
        "sentences. Focus on 'is this safe to click/visit?' and one or two "
        "concrete next steps."
    ),
    "Intermediate": (
        "Explain for someone comfortable with basic IT/security concepts "
        "(they know what a domain, IP, or malware is, but isn't a security "
        "analyst). You may use terms like 'malicious', 'reputation', "
        "'registrar' without redefining them, but briefly clarify anything "
        "source-specific."
    ),
    "Expert": (
        "Explain for a security analyst. Be technical and concise. Reference "
        "specific indicators (detection ratios, registration dates, "
        "registrar/WHOIS anomalies, etc). Skip basic definitions. Note any "
        "IOCs or follow-up pivots worth investigating."
    ),
}


def build_gemini_prompt(indicator: str, indicator_type: str, level: str, results: list) -> str:
    condensed = [
        {"source": r["source"], "status": r["status"], "score": r["score"], "summary": r["summary"]}
        for r in results
    ]
    instructions = _LEVEL_INSTRUCTIONS[level]

    return f"""You are a threat-intelligence assistant inside a tool called ThreatLens.

A user checked this {indicator_type}: {indicator}

Here is the structured data collected from each source (JSON):
{json.dumps(condensed, indent=2)}

Audience level: {level}
{instructions}

Write a short "AI Insight" (3-6 sentences) that:
1. States your overall read on whether this indicator looks safe.
2. Explains WHY, referencing what the sources found.
3. Gives one practical recommendation for what the user should do next.

Do not repeat the raw JSON back verbatim. Do not invent data that isn't in
the sources provided. If the data is inconclusive, say so plainly."""


def call_gemini(prompt: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return "_No Gemini API key configured — add one in the sidebar to enable AI Insight._"

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"))
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"_AI Insight unavailable: {e}_"


# ---------------------------------------------------------------------------
# ORCHESTRATION — runs on Scan click
# ---------------------------------------------------------------------------

if scan_clicked:
    validation = validate_input(raw_value, indicator_type)

    if not validation["valid"]:
        st.error(validation["error"])
    else:
        indicator_value = validation["value"]
        # WHOIS/domain-style lookups need the bare host, not a full URL.
        lookup_value_by_source = {
            "IP": indicator_value,
            "Domain": indicator_value,
            "URL": indicator_value,
        }

        results = []
        with st.spinner("Querying sources..."):
            for source_name, source_fn in SOURCES.items():
                # WHOIS needs the bare host even for URLs; other sources
                # (e.g. VirusTotal) want the full URL for URL-type lookups.
                if source_name == "WHOIS" and validation["type"] == "URL":
                    result = source_fn(validation["host"], "Domain")
                else:
                    result = source_fn(indicator_value, validation["type"])
                results.append(result)

        overall = compute_overall_verdict(results)
        render_verdict_banner(overall)

        with st.spinner("Generating AI Insight..."):
            prompt = build_gemini_prompt(indicator_value, validation["type"], knowledge_level, results)
            insight_text = call_gemini(prompt)

        st.subheader("🧠 AI Insight")
        st.markdown(
            f"""<div style="background:#f0f4ff;border-left:4px solid #3b5bdb;
                            padding:1rem 1.25rem;border-radius:0.4rem;">
                    {insight_text}
                </div>""",
            unsafe_allow_html=True,
        )

        st.subheader("📋 Source Results")
        for r in results:
            status_emoji = {
                "malicious": "🔴", "suspicious": "🟠", "clean": "🟢",
                "info": "🔵", "unknown": "⚪", "error": "⚠️",
            }.get(r["status"], "⚪")

            score_txt = f" — score: {r['score']}/100" if r["score"] is not None else ""
            with st.expander(f"{status_emoji} {r['source']}: {r['summary']}{score_txt}"):
                st.json(r["raw"])

st.divider()
st.caption(
    "ThreatLens uses VirusTotal and WHOIS only. New sources can be added by "
    "writing one function in input_helpers.py — see the module docstring."
)
