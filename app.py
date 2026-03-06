You are a senior Python developer.

Create a ransomware threat intelligence dashboard written in Python using Streamlit.

The entire application must be contained in ONE SINGLE FILE called:

app.py

The app must fetch ransomware incident data from the ransomware.live API.

API configuration

Use this endpoint:

https://api.ransomware.live/8k

Authentication header:

X-API-KEY

Example request:

requests.get(
"https://api.ransomware.live/8k",
headers={"X-API-KEY": "YOUR_API_KEY"}
)

Application requirements

1. Framework

Use Streamlit.

The app must run with:

streamlit run app.py

2. Map

Display an interactive map of Italy.

Use:

streamlit-folium
folium

Center the map on:

Latitude: 43
Longitude: 12

Zoom level: 6

Limit the visible area to Italy.

3. Incident markers

For each ransomware incident returned by the API:

Create a red marker.

Because the API does not contain coordinates, generate random coordinates inside Italy.

Italy bounding box:

Latitude: 36.5 → 47.1
Longitude: 6.6 → 18.5

Each marker popup must show:

Victim name
Ransomware group
Country
Date

4. Sidebar

Create a sidebar dashboard with:

Title:
Italy Ransomware Threat Map

Display:

Total incidents
Active groups
Last update timestamp

Add an incident history list showing:

Victim name
Group
Date

Newest incidents first.

5. Data fetching

Use the Python requests library.

Refresh data every 60 seconds using Streamlit auto refresh.

Avoid duplicates by generating a unique ID for each incident.

Example:

victim + group + date

6. Styling

Use Streamlit dark theme.

Use clear dashboard layout.

Map must occupy most of the screen.

7. Error handling

If the API fails:

Show a Streamlit error message.

Example:

st.error("API connection failed")

8. Dependencies

Use only these libraries:

streamlit
requests
folium
streamlit-folium
pandas

9. Output

Return ONLY the final Python code.

Do not include explanations.

The file must run immediately with:

streamlit run app.py
