import streamlit as st
import pandas as pd
import os
import time

LOG_FILE = "/home/localuser/dlp-llm-proxy/dlp-proxy/logs/mitmproxy_events.csv"

st.set_page_config(
    page_title="DLP Proxy Dashboard",
    layout="wide"
)

st.title("DLP LLM Proxy Dashboard")

st.write("Live view of mitmproxy traffic inspected by the DLP engine.")

refresh_rate = st.sidebar.slider(
    "Auto Refresh (seconds)",
    2,
    30,
    5
)

if not os.path.exists(LOG_FILE):

    st.warning("No log file found yet. Run mitmproxy traffic first.")
    st.stop()


@st.cache_data(ttl=2)
def load_data():

    df = pd.read_csv(LOG_FILE)

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df


df = load_data()

# -----------------------------
# Sidebar Filters
# -----------------------------
st.sidebar.header("Filters")

action_filter = st.sidebar.multiselect(
    "Action",
    df["action"].unique(),
    default=df["action"].unique()
)

host_filter = st.sidebar.multiselect(
    "Host",
    df["host"].unique(),
    default=df["host"].unique()
)

df = df[df["action"].isin(action_filter)]
df = df[df["host"].isin(host_filter)]

# -----------------------------
# Metrics
# -----------------------------
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", len(df))

col2.metric(
    "Blocked",
    len(df[df["action"] == "BLOCK"])
)

col3.metric(
    "Coached",
    len(df[df["action"] == "COACH"])
)

col4.metric(
    "Allowed",
    len(df[df["action"] == "ALLOW"])
)

st.divider()

# -----------------------------
# Table
# -----------------------------
st.subheader("Traffic Events")

st.dataframe(
    df.sort_values("timestamp", ascending=False),
    use_container_width=True,
    height=600
)

# -----------------------------
# Risk Score Chart
# -----------------------------
st.subheader("Risk Score Distribution")

st.bar_chart(df["risk_score"])

# -----------------------------
# Auto Refresh
# -----------------------------
time.sleep(refresh_rate)

st.rerun()
