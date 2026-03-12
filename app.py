# app.py — Advanced Threat Intelligence Dashboard
import streamlit as st
import pandas as pd
import os
import pydeck as pdk
from datetime import datetime
from threat_lookup import lookup_ip
from multi_threat_lookup import check_abuseipdb, check_virustotal, check_otx
from report_generator import generate_report

st.set_page_config(
    page_title="SOC Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)
# API Keys
# -------------------------------
ABUSEIPDB_KEY = "3259ccd3075ba4eda559ddcd04591ca9c111a1d9b95914015d4b9bfa961d0c90dcb680546a7e6ca1"
VT_KEY = "d6f6b7586a967187fd00d0cb122b419e9634736c90da3b40d26cdbb441c6023d"
OTX_KEY = "8cefcbea66bfced732d9ce10f8c5bdc84db9afbef8efca1a24a9d1c4e32e703e"

# -------------------------------
# Dashboard Title
# -------------------------------
st.title("Cyber Threat Intelligence Dashboard")

# -------------------------------
# Ensure investigation_history.csv exists
# -------------------------------
history_file = "investigation_history.csv"

if not os.path.exists(history_file):
    pd.DataFrame(
        columns=["IP", "Country", "ISP", "Abuse Score", "Reports", "Risk"]
    ).to_csv(history_file, index=False)
# -------------------------------
# Load history
# -------------------------------
history = pd.read_csv(history_file)

# -------------------------------
# High Risk Alert Panel
# -------------------------------
high_risk_ips = history[history["Risk"] == "High Risk 🔴"]

if not high_risk_ips.empty:
    st.error(f"⚠ ALERT: {len(high_risk_ips)} High Risk IP(s) detected! Review immediately.")

    st.subheader("High-Risk IPs")

    st.table(
        high_risk_ips[["IP", "Country", "ISP", "Abuse Score", "Reports"]]
    )

# -------------------------------
# Input IP
# -------------------------------
ioc_type = st.selectbox(
    "Select IOC Type",
    ["IP Address", "Domain", "File Hash"]
)

ioc_value = st.text_input("Enter IOC")

# -------------------------------
# Risk Classification
# -------------------------------
def classify_risk(score):
    if score >= 75:
        return "High Risk 🔴"
    elif score >= 50:
        return "Medium Risk 🟠"
    else:
        return "Low Risk 🟢"

# -------------------------------
# Unified Threat Score
# -------------------------------
def unified_threat_score(abuse_score, vt_data, otx_data):

    score = abuse_score

    vt_malicious = (
        vt_data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
        .get("malicious", 0)
    )

    score += vt_malicious * 10

    otx_count = len(
        otx_data.get("pulse_info", {}).get("pulses", [])
    )

    score += otx_count * 5

    return min(score, 100)

# -------------------------------
# Check Threat
# -------------------------------
if st.button("Check Threat") and ioc_value:

    result = lookup_ip(ioc_value)

    result["Time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    abuse_data = check_abuseipdb(ioc_value, ABUSEIPDB_KEY)
    vt_data = check_virustotal(ioc_value, VT_KEY)
    otx_data = check_otx(ioc_value, OTX_KEY)

    score = unified_threat_score(result["Abuse Score"], vt_data, otx_data)

    result["Unified Threat Score"] = score
    result["Risk"] = classify_risk(score)

    st.subheader("Threat Intelligence Result")
    st.write(result)
    st.write("Unified Threat Score:", score)

    st.subheader("Threat Intelligence Sources")

    st.write("AbuseIPDB Result")
    st.json(abuse_data)

    st.write("VirusTotal Result")
    st.json(vt_data)

    st.write("AlienVault OTX Result")
    st.json(otx_data)

    # -------------------------------
    # Save investigation
    # -------------------------------
    df = pd.DataFrame(
        [result],
        columns=["IP", "Country", "ISP", "Abuse Score", "Reports", "Risk"],
    )

    df.to_csv(history_file, mode="a", index=False, header=False)

    # -------------------------------
    # Report download
    # -------------------------------
    if st.button("Download Report"):
        generate_report(result)
        st.success("Report generated: Threat_Report.pdf")

# -------------------------------
# Reload updated history
# -------------------------------
history = pd.read_csv(history_file)

# -------------------------------
# SOC Threat Summary

st.subheader("SOC Threat Summary")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Investigations", len(history))

col2.metric(
    "High Risk",
    len(history[history["Risk"] == "High Risk 🔴"])
)

col3.metric(
    "Medium Risk",
    len(history[history["Risk"] == "Medium Risk 🟠"])
)

col4.metric(
    "Low Risk",
    len(history[history["Risk"] == "Low Risk 🟢"])
)

st.write("Top Countries:")

st.write(history["Country"].value_counts().head(5))

# -------------------------------
# Investigation History
# -------------------------------
if st.checkbox("Show Investigation History"):

    st.subheader("Investigation History")

    st.write(history)

# -------------------------------
# Threat Statistics
# -------------------------------
st.subheader("Threat Statistics")

if not history.empty:
    st.bar_chart(history["Abuse Score"])

# -------------------------------
# Risk Distribution
# -------------------------------
if not history.empty:

    risk_counts = history["Risk"].value_counts()

    st.subheader("Risk Distribution")

    st.bar_chart(risk_counts)

# -------------------------------
# Top Attacking Countries
# -------------------------------
# -------------------------------
# Top Attacking Countries
# -------------------------------
st.subheader("Top Attacking Countries")

if not history.empty:
    country_counts = history["Country"].value_counts()
    st.bar_chart(country_counts)
# ------------------------------
# Live Threat Feed
# -------------------------------
st.subheader("Live Threat Feed")

if not history.empty:

    latest = history.tail(5)

    for index, row in latest.iterrows():

        st.write(
            f"🚨 IP: {row['IP']} | Country: {row['Country']} | Risk: {row['Risk']} | Abuse Score: {row['Abuse Score']}"
        )

# -------------------------------
# Global Threat Map
# -------------------------------
if not history.empty:

    history_map = history.dropna(subset=["Country"])

    if not history_map.empty:

        import pycountry
        from geopy.geocoders import Nominatim

        geolocator = Nominatim(user_agent="geoapiExercises")

        coords = []

        for country_code in history_map["Country"].unique():

            try:

                loc = geolocator.geocode(country_code)

                if loc:

                    coords.append(
                        {
                            "Country": country_code,
                            "Latitude": loc.latitude,
                            "Longitude": loc.longitude,
                        }
                    )

            except:
                continue

        map_df = pd.DataFrame(coords)

        if not map_df.empty:

            st.subheader("Attacker Country Heatmap")

            st.pydeck_chart(
                pdk.Deck(
                    map_style="mapbox://styles/mapbox/light-v9",
                    initial_view_state=pdk.ViewState(
                        latitude=20,
                        longitude=0,
                        zoom=1,
                    ),
                    layers=[
                        pdk.Layer(
                            "ScatterplotLayer",
                            data=map_df,
                            get_position=["Longitude", "Latitude"],
                            get_color=[255, 0, 0],
                            get_radius=500000,
                            pickable=True,
                        )
                    ],
                )
            )