
import streamlit as st
import re
from datetime import datetime

st.set_page_config(
    page_title="Wi-Fi Security Analyzer",
    page_icon="🔐",
    layout="wide"
)

# ---------- DESIGN ----------
st.markdown("""
<style>
.main-title {
    font-size: 32px;
    font-weight: 700;
    color: #2563eb;
}
.subtitle {
    color: #64748b;
    font-size: 15px;
}
div[data-testid="stMetric"] {
    background: #f1f5f9;
    padding: 16px;
    border-radius: 12px;
}
</style>
""", unsafe_allow_html=True)

# ---------- SIDEBAR ----------
st.sidebar.title("🔐 Wi-Fi Analyzer")
st.sidebar.caption("Wireless Network Security Analysis")

page = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Password Checker", "Security Analysis", "Recommendations"]
)

st.sidebar.divider()

# ---------- SESSION STATE ----------
if "analysis" not in st.session_state:
    st.session_state.analysis = None

# ---------- PASSWORD CHECK FUNCTION ----------
def check_password(password):
    checks = {
        "At least 12 characters": len(password) >= 12,
        "Uppercase and lowercase letters":
            bool(re.search(r"[A-Z]", password))
            and bool(re.search(r"[a-z]", password)),
        "Contains a number": bool(re.search(r"\d", password)),
        "Contains a special character":
            bool(re.search(r"[^A-Za-z0-9]", password))
    }

    common = [
        "password", "123456", "qwerty", "admin"
    ]

    predictable = any(
        word in password.lower() for word in common
    )

    score = sum(checks.values())

    if len(password) < 8 or predictable or score <= 1:
        strength = "Weak"
    elif score == 2:
        strength = "Medium"
    elif score == 3:
        strength = "Good"
    else:
        strength = "Strong"

    suggestions = []

    for rule, passed in checks.items():
        if not passed:
            suggestions.append(f"Improve: {rule.lower()}.")

    if predictable:
        suggestions.append(
            "Avoid common words and predictable sequences."
        )

    if not suggestions:
        suggestions.append(
            "All basic checks passed. Use a unique password."
        )

    return strength, checks, suggestions


# ---------- ANALYSIS FUNCTION ----------
def analyze_network(data):
    findings = []

    encryption = data["encryption"]
    password_strength = data["password_strength"]
    wps = data["wps"]
    admin = data["admin"]

    if encryption == "Open Network":
        findings.append({
            "property": "Wi-Fi Encryption",
            "status": "Weak",
            "risk": "High",
            "issue": "The network has no Wi-Fi encryption.",
            "recommendation":
                "Enable WPA3 or WPA2-AES with a strong password."
        })

    elif encryption == "WEP":
        findings.append({
            "property": "Wi-Fi Encryption",
            "status": "Weak",
            "risk": "High",
            "issue": "WEP is an outdated encryption method.",
            "recommendation":
                "Replace WEP with WPA3 or WPA2-AES."
        })

    elif encryption == "WPA2-TKIP":
        findings.append({
            "property": "Wi-Fi Encryption",
            "status": "Weak",
            "risk": "Medium",
            "issue": "TKIP is an outdated security option.",
            "recommendation":
                "Use WPA3 or WPA2-AES where supported."
        })

    if password_strength == "Weak":
        findings.append({
            "property": "Wi-Fi Password",
            "status": "Weak",
            "risk": "High",
            "issue": "The password does not meet basic strength rules.",
            "recommendation":
                "Use a long, unique password that is hard to guess."
        })

    elif password_strength == "Medium":
        findings.append({
            "property": "Wi-Fi Password",
            "status": "Needs improvement",
            "risk": "Medium",
            "issue": "The password could be stronger.",
            "recommendation":
                "Increase its length and avoid predictable patterns."
        })

    elif password_strength == "Not checked":
        findings.append({
            "property": "Wi-Fi Password",
            "status": "Not checked",
            "risk": "Unknown",
            "issue": "Password strength has not been evaluated.",
            "recommendation":
                "Use the Password Checker with a sample password."
        })

    if wps == "Yes":
        findings.append({
            "property": "WPS",
            "status": "Needs review",
            "risk": "Medium",
            "issue": "WPS is enabled.",
            "recommendation":
                "Disable WPS if it is not required."
        })
    elif wps == "Unknown":
        findings.append({
            "property": "WPS",
            "status": "Not checked",
            "risk": "Unknown",
            "issue": "WPS status is unknown.",
            "recommendation":
                "Check WPS status in the router settings."
        })

    if admin == "Yes":
        findings.append({
            "property": "Router Admin Password",
            "status": "Weak",
            "risk": "High",
            "issue": "The default administrator password is in use.",
            "recommendation":
                "Change it to a unique, strong password."
        })
    elif admin == "Unknown":
        findings.append({
            "property": "Router Admin Password",
            "status": "Not checked",
            "risk": "Unknown",
            "issue": "Administrator password status is unknown.",
            "recommendation":
                "Verify that the default password has been changed."
        })

    # Simple educational risk classification
    risks = [item["risk"] for item in findings]

    if "High" in risks or risks.count("Medium") >= 2:
        overall = "HIGH"
    elif "Medium" in risks or "Unknown" in risks:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    return overall, findings


# ---------- PAGE: PASSWORD CHECKER ----------
if page == "Password Checker":
    st.markdown(
        '<div class="main-title">Password Strength Checker</div>',
        unsafe_allow_html=True
    )
    st.write("Check password characteristics and get suggestions.")
    st.warning(
        "Wi-Fi password. The checker uses simple rules."
    )

    password = st.text_input(
        "Enter a sample password",
        type="password",
        key="checker_password"
    )

    if password:
        strength, checks, suggestions = check_password(password)

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Password Length", f"{len(password)} characters")

        with col2:
            st.metric("Strength", strength)

        st.progress(sum(checks.values()) / len(checks))

        st.subheader("Security Checklist")
        for rule, passed in checks.items():
            st.write(
                ("✅ " if passed else "❌ ") + rule
            )

        st.subheader("Recommendations")
        for suggestion in suggestions:
            st.write("• " + suggestion)

        st.caption(
            "A strong-looking password can still be compromised "
            "or previously exposed. This is not a breach check."
        )


# ---------- PAGE: SECURITY ANALYSIS ----------
elif page == "Security Analysis":
    st.markdown(
        '<div class="main-title">Security Analysis</div>',
        unsafe_allow_html=True
    )

    st.write("Enter the Wi-Fi configuration to analyze.")

    ssid = st.text_input("Network Name (SSID)")

    encryption = st.selectbox(
        "Encryption Type",
        ["WPA3", "WPA2-AES", "WPA2-TKIP", "WEP", "Open Network"]
    )

    password_strength = st.selectbox(
        "Password Strength",
        ["Strong", "Good", "Medium", "Weak", "Not checked"]
    )

    wps = st.selectbox(
        "Is WPS enabled?",
        ["No", "Yes", "Unknown"]
    )

    admin = st.selectbox(
        "Is the default router administrator password still in use?",
        ["No", "Yes", "Unknown"]
    )

    if st.button("Analyze Security", type="primary"):
        data = {
            "ssid": ssid or "Unnamed network",
            "encryption": encryption,
            "password_strength": password_strength,
            "wps": wps,
            "admin": admin
        }

        overall, findings = analyze_network(data)

        st.session_state.analysis = {
            "data": data,
            "overall": overall,
            "findings": findings
        }

        st.success(
            "Analysis complete. Open Dashboard for the summary "
            "and Recommendations for detailed guidance."
        )


# ---------- GET SAVED ANALYSIS ----------
elif page in ["Dashboard", "Recommendations"]:
    result = st.session_state.analysis

    if result is None:
        st.markdown(
            '<div class="main-title">Wi-Fi Security Dashboard</div>',
            unsafe_allow_html=True
        )
        st.info(
            "No analysis available yet. Open Security Analysis "
            "from the sidebar and submit a configuration first."
        )

    elif page == "Dashboard":
        data = result["data"]
        findings = result["findings"]
        overall = result["overall"]

        st.markdown(
            '<div class="main-title">Wi-Fi Security Dashboard</div>',
            unsafe_allow_html=True
        )
        st.markdown(
            '<div class="subtitle">Security overview and findings</div>',
            unsafe_allow_html=True
        )

        st.write("")
        st.subheader(f"Network: {data['ssid']}")

        high_count = sum(
            f["risk"] == "High" for f in findings
        )
        medium_count = sum(
            f["risk"] == "Medium" for f in findings
        )
        unknown_count = sum(
            f["risk"] == "Unknown" for f in findings
        )

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Overall Risk", overall)
        c2.metric("High-Risk Issues", high_count)
        c3.metric("Medium-Risk Issues", medium_count)
        c4.metric("Needs Checking", unknown_count)

        if overall == "HIGH":
            st.error("High risk: address the identified issues.")
        elif overall == "MEDIUM":
            st.warning("Medium risk: review the findings below.")
        else:
            st.success(
                "Low risk according to the selected basic rules."
            )

        st.subheader("Configuration Summary")

        st.write(f"**Encryption:** {data['encryption']}")
        st.write(f"**Password strength:** {data['password_strength']}")
        st.write(f"**WPS enabled:** {data['wps']}")
        st.write(f"**Default admin password in use:** {data['admin']}")

        st.subheader("Security Findings")

        if not findings:
            st.success("No issues identified by these rules.")
        else:
            for item in findings:
                with st.container(border=True):
                    st.markdown(
                        f"**{item['property']} — {item['status']}**"
                    )
                    st.write(item["issue"])
                    st.caption(
                        f"Risk category: {item['risk']}"
                    )
                    st.write(
                        "**Recommendation:** "
                        + item["recommendation"]
                    )

        # Download report
        report_lines = [
            "WIRELESS NETWORK SECURITY ANALYSIS",
            "=" * 38,
            f"Generated: {datetime.now():%Y-%m-%d %H:%M}",
            f"Network: {data['ssid']}",
            f"Overall risk: {overall}",
            f"Encryption: {data['encryption']}",
            f"Password strength: {data['password_strength']}",
            f"WPS enabled: {data['wps']}",
            f"Default admin password in use: {data['admin']}",
            "",
            "FINDINGS AND RECOMMENDATIONS"
        ]

        for item in findings:
            report_lines.extend([
                "",
                f"Property: {item['property']}",
                f"Status: {item['status']}",
                f"Risk: {item['risk']}",
                f"Issue: {item['issue']}",
                f"Recommendation: {item['recommendation']}"
            ])

        report_lines.extend([
            "",
            "Note: This report uses manually entered information. "
            "It is not a live Wi-Fi scan."
        ])

        st.download_button(
            "Download Security Report",
            data="\n".join(report_lines),
            file_name="wifi_security_report.txt",
            mime="text/plain"
        )

    else:
        st.markdown(
            '<div class="main-title">Security Recommendations</div>',
            unsafe_allow_html=True
        )

        findings = result["findings"]

        if not findings:
            st.success(
                "No issues were identified by the current rules."
            )
        else:
            for item in findings:
                with st.container(border=True):
                    st.subheader(item["property"])
                    st.write("**Finding:** " + item["issue"])
                    st.write("**Status:** " + item["status"])
                    st.write("**Risk:** " + item["risk"])
                    st.info(
                        "Recommended action: "
                        + item["recommendation"]
                    )

        st.caption(
            "Recommendations are based on the submitted settings "
            "and the application's predefined rules."
        )

# ---------- FOOTER ----------
st.divider()

