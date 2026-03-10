import streamlit as st
import pandas as pd
import os
from threat_lookup import lookup_ip

# -------------------------------
# Title
# -------------------------------
st.title("Cyber Threat Intelligence Dashboard")

# -------------------------------
# Ensure investigation_history.csv exists
# -------------------------------
history_file = "investigation_history.csv"
if not os.path.exists(history_file):
    pd.DataFrame(columns=["IP","Country","ISP","Abuse Score","Reports","Risk"]).to_csv(
        history_file, index=False
    )

# -------------------------------
# Input IP Address
# -------------------------------
ip = st.text_input("Enter IP Address")

# -------------------------------
# Risk classification function
# -------------------------------
def classify_risk(score):
    if score >= 75:
        return "High Risk 🔴"
    elif score >= 50:
        return "Medium Risk 🟠"
    else:
        return "Low Risk 🟢"

# -------------------------------
# Investigate IP
# -------------------------------
if st.button("Check Threat") and ip:
    result = lookup_ip(ip)
    
    # Add Risk classification
    result["Risk"] = classify_risk(result["Abuse Score"])
    
    # Show result
    st.subheader("Threat Intelligence Result")
    st.write(result)
    
    # Show bar chart for abuse score
    df = pd.DataFrame([result])
    st.bar_chart(df["Abuse Score"])
    
    # Append to investigation history
    df.to_csv(history_file, mode="a", index=False, header=False)

# -------------------------------
# Show Investigation History
# -------------------------------
if st.checkbox("Show Investigation History"):
    history = pd.read_csv(history_file)
    st.subheader("Investigation History")
    st.write(history)
    
    st.subheader("Threat Statistics")
    if not history.empty:
        st.bar_chart(history["Abuse Score"])