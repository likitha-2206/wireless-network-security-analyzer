
import streamlit as st

st.set_page_config(
    page_title="Wi-Fi Security Analyzer",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 Wi-Fi Security Analyzer")
st.write("Wireless Network Security Analysis")

st.divider()

st.subheader("Enter Wi-Fi Configuration")

ssid = st.text_input("Network Name (SSID)")

encryption = st.selectbox(
    "Encryption Type",
    ["WPA3", "WPA2-AES", "WPA2-TKIP", "WEP", "Open Network"]
)

password = st.selectbox(
    "Password Strength",
    ["Strong", "Weak", "Unknown"]
)

wps = st.selectbox(
    "Is WPS enabled?",
    ["No", "Yes", "Unknown"]
)

admin = st.selectbox(
    "Is the default router admin password still used?",
    ["No", "Yes", "Unknown"]
)

if st.button("Analyze Security", type="primary"):

    risks = []
    recommendations = []

    # Check encryption
    if encryption == "Open Network":
        risks.append("Wi-Fi has no encryption")
        recommendations.append(
            "Enable WPA3 or WPA2-AES encryption."
        )

    elif encryption == "WEP":
        risks.append("WEP is outdated and insecure")
        recommendations.append(
            "Replace WEP with WPA3 or WPA2-AES."
        )

    elif encryption == "WPA2-TKIP":
        risks.append("Outdated TKIP encryption")
        recommendations.append(
            "Use WPA3 or WPA2-AES instead."
        )

    # Check password strength
    if password == "Weak":
        risks.append("Weak Wi-Fi password")
        recommendations.append(
            "Use a long, unique password."
        )

    elif password == "Unknown":
        recommendations.append(
            "Verify that the Wi-Fi password is strong."
        )

    # Check WPS
    if wps == "Yes":
        risks.append("WPS is enabled")
        recommendations.append(
            "Disable WPS if it is not required."
        )

    elif wps == "Unknown":
        recommendations.append(
            "Check WPS in your router settings."
        )

    # Check router administrator password
    if admin == "Yes":
        risks.append("Default router admin password is in use")
        recommendations.append(
            "Change the default administrator password."
        )

    elif admin == "Unknown":
        recommendations.append(
            "Verify the router administrator password."
        )

    # Calculate risk level
    if encryption in ["Open Network", "WEP"] or len(risks) >= 2:
        level = "HIGH"
    elif risks or password == "Unknown":
        level = "MEDIUM"
    else:
        level = "LOW"

    st.divider()
    st.subheader("Security Analysis Report")
    st.write("Network:", ssid or "Unnamed network")

    if level == "HIGH":
        st.error("Risk Level: HIGH")
    elif level == "MEDIUM":
        st.warning("Risk Level: MEDIUM")
    else:
        st.success("Risk Level: LOW")

    st.write("Potential issues found:", len(risks))

    if risks:
        st.markdown("### Identified Issues")
        for risk in risks:
            st.write("⚠️", risk)
    else:
        st.success("No major issues found by these basic rules.")

    st.markdown("### Recommendations")
    if recommendations:
        for recommendation in recommendations:
            st.write("✅", recommendation)
    else:
        st.write("Continue maintaining secure Wi-Fi settings.")

    report = f"""
WIRELESS NETWORK SECURITY ANALYSIS
==================================
Network: {ssid or 'Unnamed network'}
Encryption: {encryption}
Password strength: {password}
WPS enabled: {wps}
Default admin password in use: {admin}
Risk level: {level}

Identified issues:
{chr(10).join(risks) if risks else 'No major issues found'}

Recommendations:
{chr(10).join(recommendations) if recommendations else 'Maintain secure settings'}

Note: This is a rule-based assessment using manually
entered information. It is not a live Wi-Fi scan.
"""

    st.download_button(
        "Download Security Report",
        data=report,
        file_name="wifi_security_report.txt",
        mime="text/plain"
    )

st.divider()
st.caption(
    "Educational project | Results depend on the information entered."
)
