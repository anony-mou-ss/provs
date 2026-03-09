import streamlit as st
import requests
import pandas as pd
import time

API_URL = "https://hierocratic-subumbellate-dionna.ngrok-free.dev/webhook/cyber-news"

st.set_page_config(
    page_title="Cyber Attack Monitor",
    layout="wide"
)

st.title("🛡️ Live Cyber Attack Feed")

def load_news():

    r = requests.get(API_URL)
    data = r.json()

    # se arriva un singolo oggetto lo trasformiamo in lista
    if isinstance(data, dict):
        data = [data]

    return pd.DataFrame(data)

df = load_news()

for _, row in df.iterrows():

    severity_color = {
        "High": "red",
        "Medium": "orange",
        "Low": "green"
    }.get(row.get("severity"), "white")

    st.markdown(f"""
    ### {row.get('title')}

    **Threat Actor:** {row.get('threat_actor')}  
    **Target:** {row.get('target')}  
    **Type:** {row.get('type')}  

    <span style="color:{severity_color}; font-weight:bold;">
    Severity: {row.get('severity')}
    </span>

    **TLP:** {row.get('tlp')}  

    [Source]({row.get('source')})
    """, unsafe_allow_html=True)

    st.divider()

# refresh ogni 60 secondi
time.sleep(60)
st.rerun()
