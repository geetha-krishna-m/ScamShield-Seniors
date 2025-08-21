
import streamlit as st
import pandas as pd

from scamshield.detector import detect_message_ml
from scamshield.core import analyze_message, analyze_url, analyze_dataframe
from scamshield.explain import verdict_label, badge_color, summarize_reasons
from scamshield.resources import ACTION_STEPS, REPORTING_LINKS

st.set_page_config(page_title="ScamShield Seniors", page_icon="🛡️", layout="centered")

st.markdown("<h1 style='text-align:center'>🛡️ ScamShield Seniors</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; font-size: 1.1rem;'>Paste a message or link. Get a clear verdict, why it’s risky, and what to do next.</p>", unsafe_allow_html=True)

tab1, tab2, tab3,tab4 = st.tabs(["🔎 Single Check", "📄 Batch (CSV)", "🤖 ML Extension", "ℹ️ About"])

with tab1:
    st.subheader("Check a Message or URL")
    text = st.text_area("Paste here", height=140, placeholder="Example: URGENT! Your account is locked. Verify now: http://bank.example-login.com/verify")
    colA, colB = st.columns([1,1])
    with colA:
        if st.button("Analyze Message", use_container_width=True):
            if text.strip():
                res = analyze_message(text.strip())
                color = badge_color(res["score"])
                st.markdown(f"<div style='padding: 12px; border-radius: 12px; border: 2px solid {color}'>"
                            f"<b>Verdict:</b> <span style='color:{color}'>{res['label']} (score {res['score']}/100)</span>"
                            f"</div>", unsafe_allow_html=True)
                st.write("**Top reasons**")
                for r in summarize_reasons(res["reasons"]):
                    st.write(f"- {r}")
                with st.expander("What to do next"):
                    for step in ACTION_STEPS:
                        st.write(f"- {step}")
                    st.write("**Report**")
                    for link in REPORTING_LINKS:
                        st.write(f"- [{link['label']}]({link['url']})")
    with colB:
        if st.button("Analyze URL", use_container_width=True):
            if text.strip():
                res = analyze_url(text.strip())
                color = badge_color(res["score"])
                st.markdown(f"<div style='padding: 12px; border-radius: 12px; border: 2px solid {color}'>"
                            f"<b>Verdict:</b> <span style='color:{color}'>{res['label']} (score {res['score']}/100)</span>"
                            f"</div>", unsafe_allow_html=True)
                st.write("**Top reasons**")
                for r in summarize_reasons(res["reasons"]):
                    st.write(f"- {r}")
                with st.expander("Details"):
                    st.json(res.get("meta", {}))
                with st.expander("What to do next"):
                    for step in ACTION_STEPS:
                        st.write(f"- {step}")
                    st.write("**Report**")
                    for link in REPORTING_LINKS:
                        st.write(f"- [{link['label']}]({link['url']})")

with tab2:
    st.subheader("Batch Triage (CSV)")
    st.caption("Upload a CSV with a `message` column and/or a `url` column.")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded:
        df = pd.read_csv(uploaded)
        st.write("Preview:", df.head())
        text_col = "message" if "message" in df.columns else None
        url_col = "url" if "url" in df.columns else None
        if not text_col and not url_col:
            st.error("CSV must include a 'message' and/or 'url' column.")
        else:
            if st.button("Run batch analysis", use_container_width=True):
                out = analyze_dataframe(df, text_col=text_col, url_col=url_col)
                st.success(f"Analyzed {len(out)} rows.")
                st.dataframe(out)
                # Offer download
                out_csv = out.to_csv(index=False).encode("utf-8")
                st.download_button("Download results CSV", out_csv, file_name="scamshield_results.csv", mime="text/csv")
with tab3:
    st.subheader("ML-based Scam Detection")
    ml_text = st.text_area("Paste message here", height=120, placeholder="Optional: message text")
    ml_url = st.text_input("Paste URL here (optional)", placeholder="Optional: URL to check")

    if st.button("Run ML Analysis", key="ml_ext_button"):
        if not ml_text.strip() and not ml_url.strip():
            st.warning("Please provide a message or URL")
        else:
            res = detect_message_ml(ml_text.strip(), ml_url.strip())
            color = "red" if res["label"]=="malicious" else "green"
            st.markdown(f"<div style='padding:12px; border-radius:12px; border:2px solid {color}'>"
                        f"<b>Verdict:</b> <span style='color:{color}'>{res['label']} (score {res['score']}/100)</span>"
                        f"</div>", unsafe_allow_html=True)
            st.write("**Reasons:**")
            for r in res["reasons"]:
                st.write(f"- {r}")
with tab4:
    st.markdown("""
### About
ScamShield Seniors is a simple triage tool that flags risky messages and links with **explainable heuristics** and clear next steps.

**Design priorities:** accessibility, privacy, and clarity for non-technical users.

**Disclaimer:** Prototype for educational use. Do not rely on it as a sole decision engine.
    """)
