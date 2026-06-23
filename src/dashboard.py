import streamlit as st
import pandas as pd
from collections import Counter
from streamlit_autorefresh import st_autorefresh

st.set_page_config(layout="wide")

st_autorefresh(interval=2000, key="refresh")

st.title("IoMT IDS SOC Dashboard")
st.write("Real-Time Intrusion Detection System")

try:

    with open("logs/attack_logs.txt", "r") as f:
        logs = f.readlines()

    attacks = []

    for log in logs:

        parts = log.strip().split("|")

        if len(parts) == 2:
            attacks.append(parts[1].strip())

    counter = Counter(attacks)

    total = sum(counter.values())

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Alerts", total)
    col2.metric("Attack Types", len(counter))

    st.subheader("Attack Statistics")

    stats_df = pd.DataFrame(
        counter.items(),
        columns=["Attack Type", "Count"]
    )

    st.dataframe(stats_df)

    st.subheader("Attack Distribution")

    if not stats_df.empty:
        st.bar_chart(
            stats_df.set_index("Attack Type")
        )

    st.subheader("Latest Alerts")

    for log in logs[-10:][::-1]:
        st.write(log)

except FileNotFoundError:

    st.warning("No logs yet.")

st.sidebar.subheader("Yönetim Paneli")
if st.sidebar.button("Logları ve Grafikleri Sıfırla"):
    try:
        with open("logs/attack_logs.txt", "w") as f:
            f.write("")
        st.success("Loglar başarıyla sıfırlandı! Sayfa yenileniyor...")
        st.rerun()
    except Exception as e:
        st.error(f"Sıfırlama hatası: {e}")


        