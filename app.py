# app.py — Advanced Threat Intelligence Dashboard

import streamlit as st
import pandas as pd
import os
import csv
import requests
from datetime import datetime
from threat_lookup import lookup_ip
from multi_threat_lookup import (
    VT_KEY,
    detect_ioc_type,
    check_domain, check_file_hash,
    check_abuseipdb, check_virustotal, check_otx,
    validate_otx_key,
    HIGH_RISK_CATEGORIES, MEDIUM_RISK_CATEGORIES,
)
from report_generator import generate_report

# -------------------------------
# CONFIG
# -------------------------------
st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide")

history_file = "investigation_history.csv"
CSV_HEADERS  = ["Time", "IOC", "IOC Type", "IP", "Country", "ISP",
                "Abuse Score", "Reports", "Risk"]

# -------------------------------
# Risk Classifier
# -------------------------------
def classify_risk(score: int) -> str:
    if score >= 75:
        return "High Risk 🔴"
    elif score >= 40:
        return "Medium Risk 🟠"
    else:
        return "Low Risk 🟢"

# -------------------------------
# Show which categories triggered a boost
# -------------------------------
def explain_category_risk(categories: dict) -> str:
    if not categories:
        return ""
    all_labels = " ".join(str(v) for v in categories.values()).lower()
    triggered = []
    for kw in HIGH_RISK_CATEGORIES:
        if kw in all_labels:
            triggered.append(f"🔴 `{kw}` (high-risk category)")
    for kw in MEDIUM_RISK_CATEGORIES:
        if kw in all_labels and not any(kw in t for t in triggered):
            triggered.append(f"🟠 `{kw}` (medium-risk category)")
    if triggered:
        return "**Category risk triggers:**\n" + "\n".join(f"- {t}" for t in triggered)
    return ""

# -------------------------------
# History helpers
# -------------------------------
def load_history() -> pd.DataFrame:
    if os.path.exists(history_file) and os.path.getsize(history_file) > 0:
        try:
            df = pd.read_csv(history_file)
            return df.fillna("N/A")
        except pd.errors.EmptyDataError:
            pass
    return pd.DataFrame()

def save_to_csv(result: dict):
    file_exists = os.path.isfile(history_file) and os.path.getsize(history_file) > 0
    with open(history_file, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(CSV_HEADERS)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result.get("IOC",         "N/A"),
            result.get("IOC Type",    "N/A"),
            result.get("IP",          "N/A"),
            result.get("Country",     "N/A"),
            result.get("ISP",         "N/A"),
            result.get("Abuse Score", 0),
            result.get("Reports",     0),
            result.get("Risk",        "N/A"),
        ])

# -------------------------------
# Dashboard
# -------------------------------
st.title("Threat Intelligence Dashboard")

# OTX key warning shown once at top
if not validate_otx_key():
    st.sidebar.warning("⚠️ OTX API key not configured or invalid. OTX results will show 0 pulses.")

ioc_type  = st.selectbox("Select IOC Type", ["IP Address", "Domain", "File Hash"])
ioc_value = st.text_input("Enter IOC")

if ioc_value:
    detected = detect_ioc_type(ioc_value.strip())
    if detected != "Unknown" and detected != ioc_type:
        st.warning(
            f"⚠️ Detected IOC type **{detected}** doesn't match selected "
            f"**{ioc_type}**. Auto-correcting."
        )
        ioc_type = detected

history = load_history()

# ================================================================
# CHECK THREAT
# ================================================================
if st.button("Check Threat") and ioc_value:

    result      = {"IOC": ioc_value, "IOC Type": ioc_type}
    save_result = True

    # ── IP Address ──────────────────────────────────────────────
    if ioc_type == "IP Address":

        abuse_data = check_abuseipdb(ioc_value)
        otx_data   = check_otx(ioc_value, ioc_type="IPv4")
        vt_data    = check_virustotal(ioc_value, ioc_type="ip")

        top_score = max(
            abuse_data.get("Abuse Score", 0),
            otx_data.get("Abuse Score",   0),
            vt_data.get("Abuse Score",    0),
        )

        result.update({
            "IP":          abuse_data.get("IP",      ioc_value),
            "Country":     abuse_data.get("Country", "N/A"),
            "ISP":         abuse_data.get("ISP",     "N/A"),
            "Abuse Score": top_score,
            "Reports":     abuse_data.get("Reports", 0),
            "Risk":        classify_risk(top_score),
        })

        if "Error" in abuse_data:
            st.error(f"AbuseIPDB error: {abuse_data['Error']}")
            save_result = False
        else:
            st.subheader("🔍 Threat Intelligence Result")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown("### 🛡️ AbuseIPDB")
                st.json({k: v for k, v in abuse_data.items() if k != "source"})
            with col2:
                st.markdown("### 🔬 VirusTotal")
                st.json({k: v for k, v in vt_data.items() if k != "source"})
            with col3:
                st.markdown("### 👁️ OTX AlienVault")
                st.json({k: v for k, v in otx_data.items() if k != "source"})
                if "Error" in otx_data:
                    st.caption(f"⚠️ {otx_data['Error']}")
            st.markdown(f"### Overall Risk: **{result['Risk']}**")

    # ── Domain ──────────────────────────────────────────────────
    elif ioc_type == "Domain":

        vt_data  = check_domain(ioc_value)
        otx_data = check_otx(ioc_value, ioc_type="domain")

        top_score = max(
            vt_data.get("Abuse Score",  0),
            otx_data.get("Abuse Score", 0),
        )

        result.update({
            "Country":     otx_data.get("Country", "N/A"),
            "ISP":         "N/A",
            "Abuse Score": top_score,
            "Reports":     vt_data.get("Malicious Count", 0),
            "Risk":        classify_risk(top_score),
        })

        st.subheader("🔍 Domain Threat Result")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🔬 VirusTotal")
            vt_display = {k: v for k, v in vt_data.items()
                          if k not in ("source", "Categories")}
            st.json(vt_display)
            undetected = vt_data.get("Undetected", 0)
            harmless   = vt_data.get("Harmless",   0)
            total_eng  = vt_data.get("Total Engines", 0)
            if total_eng > 0 and harmless == 0 and undetected == total_eng:
                st.warning(
                    "⚠️ All engines returned 'Undetected' with zero Harmless verdicts. "
                    "This domain has not been analyzed by any engine — treat as suspicious "
                    "until proven clean."
                )
            cats = vt_data.get("Categories", {})
            if cats:
                st.markdown("**🏷️ VT Categories:**")
                for engine, label in cats.items():
                    st.caption(f"• {engine}: `{label}`")
            explanation = explain_category_risk(cats)
            if explanation:
                st.markdown(explanation)

            if "Error" in vt_data:
                st.error(f"VirusTotal error: {vt_data['Error']}")
            elif "Status" in vt_data:
                st.info(f"ℹ️ {vt_data['Status']}")

        with col2:
            st.markdown("### 👁️ OTX AlienVault")
            st.json({k: v for k, v in otx_data.items() if k != "source"})
            if "Error" in otx_data:
                st.caption(f"⚠️ {otx_data['Error']}")

        st.markdown(f"### Overall Risk: **{result['Risk']}**")

    # ── File Hash ────────────────────────────────────────────────
    elif ioc_type == "File Hash":

        vt_data  = check_file_hash(ioc_value)
        otx_data = check_otx(ioc_value, ioc_type="file")

        top_score = max(
            vt_data.get("Abuse Score",  0),
            otx_data.get("Abuse Score", 0),
        )

        result.update({
            "Country":     "N/A",
            "ISP":         "N/A",
            "Abuse Score": top_score,
            "Reports":     vt_data.get("Malicious Count", 0),
            "Risk":        classify_risk(top_score),
        })

        st.subheader("🔍 File Hash Threat Result")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🔬 VirusTotal")
            st.json({k: v for k, v in vt_data.items() if k != "source"})
            if "Error" in vt_data:
                st.error(f"VirusTotal error: {vt_data['Error']}")
            elif "Status" in vt_data:
                st.info(f"ℹ️ {vt_data['Status']}")

        with col2:
            st.markdown("### 👁️ OTX AlienVault")
            st.json({k: v for k, v in otx_data.items() if k != "source"})
            if "Error" in otx_data:
                st.caption(f"⚠️ {otx_data['Error']}")

        st.markdown(f"### Overall Risk: **{result['Risk']}**")

    # ── Save ─────────────────────────────────────────────────────
    if save_result:
        save_to_csv(result)
        st.session_state["last_result"] = result
        
if "last_result" in st.session_state:
    from report_generator import generate_report
    
    pdf_bytes = generate_report(st.session_state["last_result"])
    
    ioc_name = st.session_state["last_result"].get("IOC", "report").replace("/", "_")
    
    st.download_button(
        label="📄 Download PDF Report",
        data=pdf_bytes,
        file_name=f"threat_report_{ioc_name}.pdf",
        mime="application/pdf",
    )
# ================================================================
# Reload + SOC Summary
# ================================================================
history = load_history()

st.subheader("SOC Threat Summary")
st.write("Total Investigations:", len(history))
if "Risk" in history.columns:
    st.write("High Risk:",   len(history[history["Risk"] == "High Risk 🔴"]))
    st.write("Medium Risk:", len(history[history["Risk"] == "Medium Risk 🟠"]))
    st.write("Low Risk:",    len(history[history["Risk"] == "Low Risk 🟢"]))

if "Country" in history.columns:
    valid_countries = history[
        history["Country"].notna() & (history["Country"] != "N/A")
    ]
    if not valid_countries.empty:
        st.write("Top Countries:")
        st.write(valid_countries["Country"].value_counts().head(5))

if st.checkbox("Show Investigation History"):
    st.subheader("Investigation History")
    st.dataframe(history)

if "Abuse Score" in history.columns and not history.empty:
    st.subheader("Threat Statistics")
    st.bar_chart(history["Abuse Score"])

if "Risk" in history.columns and not history.empty:
    st.subheader("Risk Distribution")
    st.bar_chart(history["Risk"].value_counts())

if "Country" in history.columns and not history.empty:
    valid = history[history["Country"] != "N/A"]
    if not valid.empty:
        st.subheader("Top Attacking Countries")
        st.bar_chart(valid["Country"].value_counts().head(5))

st.subheader("Live Threat Feed")
if not history.empty:
    latest = history.tail(5)
    for _, row in latest.iterrows():
        country = row.get("Country", "N/A")
        if pd.isna(country):
            country = "N/A"
        st.write(
            f"🚨 IOC: {row.get('IOC','N/A')} | "
            f"Type: {row.get('IOC Type','N/A')} | "
            f"Country: {country} | "
            f"Risk: {row.get('Risk','N/A')} | "
            f"Abuse Score: {row.get('Abuse Score','N/A')}"
        )