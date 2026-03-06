import streamlit as st
import requests
import pandas as pd
import random
import folium
from streamlit_folium import st_folium
from datetime import datetime

# CONFIG
API_KEY = "4e0e9836-5b4d-4017-b21f-6b70e46fc812"
API_URL = "https://api.ransomware.live/8k"

ITALY_BOUNDS = {
    "lat_min": 36.5,
    "lat_max": 47.1,
    "lon_min": 6.6,
    "lon_max": 18.5
}

# STREAMLIT PAGE
st.set_page_config(
    page_title="Italy Ransomware Threat Map",
    layout="wide"
)

st.title("🇮🇹 Italy Ransomware Threat Map")

# FETCH DATA
@st.cache_data(ttl=60)
def fetch_data():

    try:
        response = requests.get(
            API_URL,
            headers={"X-API-KEY": API_KEY},
            timeout=10
        )

        if response.status_code != 200:
            st.error("API connection failed")
            return []

        data = response.json()
        return data

    except Exception as e:
        st.error(f"API error: {e}")
        return []


data = fetch_data()

# CONVERT TO DATAFRAME
df = pd.DataFrame(data)

# RANDOM ITALY COORDINATES
def random_italy_coords():
    lat = random.uniform(ITALY_BOUNDS["lat_min"], ITALY_BOUNDS["lat_max"])
    lon = random.uniform(ITALY_BOUNDS["lon_min"], ITALY_BOUNDS["lon_max"])
    return lat, lon


# SIDEBAR
st.sidebar.title("Threat Intelligence")

total_incidents = len(df)

groups = df["group"].nunique() if "group" in df else 0

st.sidebar.metric("Total Incidents", total_incidents)
st.sidebar.metric("Active Groups", groups)
st.sidebar.write("Last update:", datetime.now().strftime("%H:%M:%S"))

st.sidebar.divider()

st.sidebar.subheader("Incident History")

if not df.empty:
    for _, row in df.head(20).iterrows():

        victim = row.get("victim", "Unknown")
        group = row.get("group", "Unknown")
        date = row.get("date", "Unknown")

        st.sidebar.write(f"**{victim}**")
        st.sidebar.caption(f"{group} | {date}")
        st.sidebar.divider()

# MAP
m = folium.Map(
    location=[43, 12],
    zoom_start=6,
    tiles="CartoDB dark_matter"
)

# MARKERS
if not df.empty:

    for _, row in df.iterrows():

        lat, lon = random_italy_coords()

        victim = row.get("victim", "Unknown")
        group = row.get("group", "Unknown")
        country = row.get("country", "Unknown")
        date = row.get("date", "Unknown")

        popup = f"""
        <b>Victim:</b> {victim}<br>
        <b>Group:</b> {group}<br>
        <b>Country:</b> {country}<br>
        <b>Date:</b> {date}
        """

        folium.CircleMarker(
            location=[lat, lon],
            radius=6,
            color="red",
            fill=True,
            fill_color="red",
            fill_opacity=0.8,
            popup=popup
        ).add_to(m)

# SHOW MAP
st_folium(m, width=1400, height=700)

# AUTO REFRESH
st.caption("Data refresh every 60 seconds")
