#run python3 -m streamlit run app.py
from __future__ import annotations

import io
import sys
import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# put src/ on the path so we can import the pipeline modules 
PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from report_generator import generate_report   # noqa: E402  #  UI calls the same backend pipeline as CLI.

#  Page config + minimal CSS (white background, green accent)

st.set_page_config(
    page_title="Firewall Rule Optimiser",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
    <style>
      :root {
          --accent:      #1f7a3a;   /* forest green */
          --accent-soft: #e8f3ec;
          --text:        #222222;
          --muted:       #555555;
          --border:      #e2e4e8;
          --bg:          #ffffff;
      }

      html, body, [data-testid="stAppViewContainer"],
      [data-testid="stHeader"], [data-testid="stSidebar"] {
          background-color: var(--bg) !important;
          color: var(--text) !important;
      }

      h1, h2, h3, h4 { color: var(--text); font-weight: 600; }
      p, label { color: var(--text); }

      /* metric cards */
      [data-testid="stMetric"] {
          background: var(--bg);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 14px 16px;
      }
      [data-testid="stMetricLabel"] { color: var(--muted); font-size: 13px; }
      [data-testid="stMetricValue"] { color: var(--accent); font-weight: 700; }

      /* buttons */
      .stButton > button, .stDownloadButton > button {
          background: var(--accent);
          color: #ffffff;
          border: 1px solid var(--accent);
          border-radius: 4px;
          font-weight: 500;
      }
      .stButton > button:hover, .stDownloadButton > button:hover {
          background: #175c2b;
          border-color: #175c2b;
      }

      /* tabs - active underline in green */
      .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
          color: var(--accent);
          border-bottom-color: var(--accent);
      }

      /* tidy up default spacing */
      .block-container { padding-top: 1.5rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


#  Helpers

RISK_COLOURS = {
    "high":   "#b23a48",   # muted red
    "medium": "#c98b1d",   # muted amber
    "low":    "#1f7a3a",   # the accent green
}


# Streamlit uploads files in memory; this saves one to a temp path for the backend pipeline.
def _save_upload_to_tempfile(uploaded_file) -> str:
    """Streamlit gives us an UploadedFile, pipeline wants a path."""
    suffix = Path(uploaded_file.name).suffix or ".csv"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(uploaded_file.getbuffer())
    tmp.flush()
    tmp.close()
    return tmp.name


# Converts rule dictionaries into a display table for the UI.
def _rules_to_df(rules: list[dict]) -> pd.DataFrame:
    """Build a dataframe with just the columns we want to show."""
    columns = [
        "ID", "Action", "Source", "Destination", "Protocol", "Port",
        "Priority", "ai_score", "ai_level", "ai_reason",
    ]
    if not rules:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(rules)[[c for c in columns if c in rules[0]]]


# Counts high/medium/low rules for the dashboard chart.
def _risk_counts(rules: list[dict]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for rule in rules:
        level = str(rule.get("ai_level", "low")).lower()
        if level in counts:
            counts[level] += 1
    return counts


#  Sidebar: file picker + optional filters

with st.sidebar:
    st.markdown("### Firewall Rule Optimiser")
    st.caption(
        "Upload a firewall rule export (CSV) to detect duplicates, "
        "conflicts and shadowed rules and score each rule for risk."
    )
    st.divider()

    st.markdown("**1. Load rules**")
    uploaded = st.file_uploader(
        "CSV file",
        type=["csv"],
        help="Expected columns: ID, Action, Source, Destination, Protocol, Port",
    )

    use_sample = st.checkbox(
        "Use bundled sample (data/rules.csv)",
        value=not bool(uploaded),
    )

    st.markdown("**2. Filters**")
    level_filter = st.multiselect(
        "Risk level",
        options=["high", "medium", "low"],
        default=["high", "medium", "low"],
    )
    action_filter = st.multiselect(
        "Action",
        options=["permit", "deny"],
        default=["permit", "deny"],
    )

    st.divider()
    st.caption(
        "ML scoring uses scikit-learn IsolationForest "
        "(Liu, Ting & Zhou, 2008)."
    )


#  Resolve input path

rules_path: str | None = None
if uploaded is not None and not use_sample:
    rules_path = _save_upload_to_tempfile(uploaded)
elif use_sample:
    sample = PROJECT_ROOT / "data" / "rules.csv"
    if sample.exists():
        rules_path = str(sample)

if rules_path is None:
    st.title("Firewall Rule Optimiser")
    st.write(
        "Upload a CSV file in the sidebar to begin, or tick "
        "\"Use bundled sample\" to run against the included dataset."
    )
    st.stop()


#  Run the pipeline (cached so re-filtering doesn't retrain)

# Caching stops Streamlit from rerunning ML/detection every time a filter changes.
@st.cache_data(show_spinner="Running pipeline…")
def _run_pipeline(path: str) -> dict:
    return generate_report(path)

# This is where the UI actually runs the firewall analysis pipeline.
result = _run_pipeline(rules_path)

rules      = result["rules"]
duplicates = result["duplicates"]
conflicts  = result["conflicts"]
shadows    = result["shadows"]
stats      = result["stats"]
timings    = result["timings"]
report_txt = result["report_text"]

# apply sidebar filters
# EXAM: Sidebar filters only change what is displayed; they do not rerun the backend analysis.
filtered_rules = [
    r for r in rules
    if str(r.get("ai_level", "")).lower() in level_filter
    and str(r.get("Action",  "")).lower() in action_filter
]
filtered_df = _rules_to_df(filtered_rules)


#  Header + metric row

st.title("Firewall Rule Optimiser")
st.caption(
    f"Analysing **{Path(rules_path).name}** — "
    f"{stats['count_before']} rules before optimisation, "
    f"{stats['count_after']} after."
)

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Rules loaded",       f"{stats['count_before']}")
col2.metric("After dedup",        f"{stats['count_after']}")
col3.metric("Duplicates",         f"{len(duplicates)}")
col4.metric("Conflicts",          f"{len(conflicts)}")
col5.metric("Shadows",            f"{len(shadows)}")

st.divider()


#  Tabs

tab_overview, tab_high, tab_explorer, tab_report, tab_download = st.tabs(
    ["Overview", "High-risk rules", "Rule explorer", "Full report", "Downloads"]
)


#  Overview 
with tab_overview:

    c1, c2 = st.columns([1, 1])

    with c1:
        st.subheader("Risk distribution")
        counts = _risk_counts(filtered_rules)
        dist_df = pd.DataFrame(
            {"level": list(counts.keys()), "count": list(counts.values())}
        )
        fig = px.bar(
            dist_df, x="level", y="count",
            color="level",
            color_discrete_map=RISK_COLOURS,
            text="count",
        )
        fig.update_traces(textposition="outside")
        fig.update_layout(
            showlegend=False,
            plot_bgcolor="white",
            paper_bgcolor="white",
            font=dict(color="#222222"),
            margin=dict(l=10, r=10, t=10, b=10),
            height=320,
            xaxis=dict(title=None),
            yaxis=dict(title=None, gridcolor="#eef0f2"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.subheader("Pipeline timings")
        timings_ms = {
            "Load":       timings.get("load", 0)     * 1000,
            "AI scoring": timings.get("ai", 0)       * 1000,
            "Detection":  timings.get("detect", 0)   * 1000,
            "Optimise":   timings.get("optimise", 0) * 1000,
        }
        timings_df = pd.DataFrame(
            {"stage": list(timings_ms.keys()),
             "ms":    list(timings_ms.values())}
        )
        fig2 = px.bar(
            timings_df, x="stage", y="ms",
            text="ms",
            color_discrete_sequence=["#1f7a3a"],
        )
        fig2.update_traces(texttemplate="%{text:.1f} ms", textposition="outside")
        fig2.update_layout(
            plot_bgcolor="white",
            paper_bgcolor="white",
            font=dict(color="#222222"),
            margin=dict(l=10, r=10, t=10, b=10),
            height=320,
            xaxis=dict(title=None),
            yaxis=dict(title="ms", gridcolor="#eef0f2"),
        )
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Detection summary")
    a, b = st.columns(2)
    with a:
        with st.expander(f"Duplicates ({len(duplicates)})", expanded=False):
            if duplicates:
                for left, right in duplicates[:30]:
                    st.write(f"Rule {left} duplicates Rule {right}")
                if len(duplicates) > 30:
                    st.caption(f"… plus {len(duplicates) - 30} more")
            else:
                st.write("None found.")

        with st.expander(f"Conflicts ({len(conflicts)})", expanded=False):
            if conflicts:
                for left, right in conflicts[:30]:
                    st.write(f"Rule {left} conflicts with Rule {right}")
                if len(conflicts) > 30:
                    st.caption(f"… plus {len(conflicts) - 30} more")
            else:
                st.write("None found.")

    with b:
        with st.expander(f"Shadowed rules ({len(shadows)})", expanded=False):
            if shadows:
                for broad, specific in shadows[:30]:
                    st.write(f"Rule {broad} shadows Rule {specific}")
                if len(shadows) > 30:
                    st.caption(f"… plus {len(shadows) - 30} more")
            else:
                st.write("None found.")


#  High-risk rules 
with tab_high:
    st.subheader("High-risk rules")
    st.caption(
        "Rules that scored 60 / 100 or above, sorted by score. "
        "The reasons come from the hybrid risk model "
        "(IsolationForest anomaly signal + heuristic)."
    )

    high = sorted(
        [r for r in filtered_rules
         if str(r.get("ai_level", "")).lower() == "high"],
        key=lambda r: int(r.get("ai_score", 0)),
        reverse=True,
    )

    if not high:
        st.info("No high-risk rules match the current filters.")
    else:
        for rule in high[:25]:
            with st.container():
                row_cols = st.columns([1, 4, 1])
                row_cols[0].markdown(f"**Rule {rule['ID']}**")
                row_cols[1].markdown(
                    f"`{rule['Action'].upper()}` "
                    f"{rule['Source']} → {rule['Destination']} · "
                    f"{rule['Protocol']}/{rule['Port']}"
                )
                row_cols[2].markdown(f"**{rule['ai_score']} / 100**")
                st.caption(rule.get("ai_reason", ""))
                st.divider()

        if len(high) > 25:
            st.caption(f"Showing top 25 of {len(high)} high-risk rules. "
                       f"Use the Rule Explorer for the full list.")


#  Rule explorer 
with tab_explorer:
    st.subheader("Rule explorer")
    st.caption(
        f"{len(filtered_rules)} rules after filtering. "
        "Use the sidebar to narrow the view."
    )

    if filtered_df.empty:
        st.info("No rules match the current filters.")
    else:
        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
            height=420,
        )

        if "ID" in filtered_df.columns:
            picked = st.selectbox(
                "Inspect a specific rule",
                filtered_df["ID"].astype(str).tolist(),
            )
            row = filtered_df[filtered_df["ID"].astype(str) == str(picked)].iloc[0]
            rule_dict = row.to_dict()

            d1, d2 = st.columns(2)
            with d1:
                st.markdown("**Raw rule data**")
                st.json(rule_dict)
            with d2:
                st.markdown("**Risk interpretation**")
                st.write(f"Level: **{rule_dict.get('ai_level', '-').upper()}**")
                st.write(f"Score: **{rule_dict.get('ai_score', '-')} / 100**")
                st.write("Reasons:")
                for r in str(rule_dict.get("ai_reason", "")).split(";"):
                    if r.strip():
                        st.write(f"  • {r.strip()}")


#  Full report 
with tab_report:
    st.subheader("Full analysis report")
    st.caption("Plain-text summary produced by report_generator.py")
    st.code(report_txt, language=None)


#  Downloads 
with tab_download:
    st.subheader("Downloads")

    report_path = Path(result.get("report_path", "output/report.txt"))
    csv_path    = Path(result.get("cleaned_csv_path",
                                  "output/cleaned_firewall_rules.csv"))

    # filtered CSV produced on the fly
    filtered_buf = io.BytesIO()
    filtered_df.to_csv(filtered_buf, index=False)
    filtered_bytes = filtered_buf.getvalue()

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("**Analysis report**")
        st.caption("Full text report with detections, timings and risk summaries.")
        if report_path.exists():
            st.download_button(
                "Download report.txt",
                data=report_path.read_bytes(),
                file_name="report.txt",
                mime="text/plain",
                use_container_width=True,
            )
        else:
            st.caption("Not available yet.")

    with c2:
        st.markdown("**Cleaned rules**")
        st.caption("Deduped, reordered rules with AI score, level and priority.")
        if csv_path.exists():
            st.download_button(
                "Download cleaned_firewall_rules.csv",
                data=csv_path.read_bytes(),
                file_name="cleaned_firewall_rules.csv",
                mime="text/csv",
                use_container_width=True,
            )
        else:
            st.caption("Not available yet.")

    with c3:
        st.markdown("**Filtered view**")
        st.caption("Rules currently visible in the Rule Explorer tab.")
        st.download_button(
            "Download filtered_rules.csv",
            data=filtered_bytes,
            file_name="filtered_rules.csv",
            mime="text/csv",
            use_container_width=True,
        )


#  Footer


st.divider()
st.caption(
    "Firewall Rule Optimiser · final-year project · "
    "risk scoring powered by scikit-learn IsolationForest "
    "(github.com/scikit-learn/scikit-learn)"
)