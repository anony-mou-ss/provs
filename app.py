import streamlit as st
import requests
import pandas as pd
import time

API_URL = "https://hierocratic-subumbellate-dionna.ngrok-free.dev/webhook/cyber-news"

st.set_page_config(page_title="Cyber Attack Monitor", layout="wide")

st.title("🛡️ Live Cyber Attack Feed")


def load_news():

    r = requests.get(API_URL)
    data = r.json()

    rows = []

    for item in data:
        if "json" in item:
            rows.append(item["json"])

    return pd.DataFrame(rows)


df = load_news()


if df.empty:
    st.warning("No news available")
else:

    for _, row in df.iterrows():

        severity_color = {
            "Critical": "red",
            "High": "red",
            "Medium": "orange",
            "Low": "green"
        }.get(row["severity"], "white")

        st.markdown(f"""
        ### {row['title']}

        **Threat Actor:** {row['threat_actor']}  
        **Target:** {row['target']}  
        **Type:** {row['type']}  

        <span style="color:{severity_color}; font-weight:bold;">
        Severity: {row['severity']}
        </span>

        **TLP:** {row['tlp']}  

        [Source]({row['source']})
        """, unsafe_allow_html=True)

        st.divider()


time.sleep(60)
st.rerun()
