
import os
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

from predicturl import (
    prepare_url,
    extract_features,
    model,
    feature_columns,
    label_map,
    calculate_risk,
    analyze_url,
    analyze_registered_domain,
)

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide",
)

# --------------------------------------------------
# SOFT CYBER COLOUR PALETTE
# --------------------------------------------------

st.markdown("""
<style>
:root {
    --mint-white: #F0FFFA;
    --soft-mint: #CFF3E8;
    --seafoam: #9FE0D3;
    --sky-blue: #8BB8E9;
    --denim-blue: #5E86C1;
    --midnight-navy: #2F3A5F;
}

.stApp {
    background-color: #F0FFFA;
    color: #2F3A5F;
}

[data-testid="stHeader"] {
    background-color: #F0FFFA;
}

[data-testid="stAppViewContainer"] {
    background-color: #F0FFFA;
}

h1, h2, h3, p, label,
[data-testid="stMarkdownContainer"] {
    color: #2F3A5F;
}

[data-testid="stTextInput"] input {
    background-color: #FFFFFF;
    color: #2F3A5F;
    border: 2px solid #9FE0D3;
    border-radius: 10px;
}

.stButton > button {
    background-color: #5E86C1;
    color: #FFFFFF;
    border: 2px solid #2F3A5F;
    border-radius: 10px;
    font-weight: 600;
    min-height: 45px;
}

.stButton > button:hover {
    background-color: #2F3A5F;
    color: #FFFFFF;
    border-color: #8BB8E9;
}

[data-testid="stMetric"] {
    background-color: #CFF3E8;
    border: 1px solid #9FE0D3;
    padding: 18px;
    border-radius: 12px;
}

[data-testid="stMetricLabel"] {
    color: #2F3A5F;
}

[data-testid="stMetricValue"] {
    color: #2F3A5F;
}

[data-testid="stExpander"] {
    background-color: #FFFFFF;
    border: 1px solid #8BB8E9;
    border-radius: 10px;
}

hr {
    border-color: #9FE0D3;
}

.small-note {
    color: #2F3A5F;
    font-size: 14px;
}

</style>
""", unsafe_allow_html=True)

# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ Phishing URL Detection System")

st.markdown(
    "### Smart URL Analysis • Machine Learning • Cybersecurity"
)

st.write(
    "Analyze URLs using a Random Forest model, URL characteristics, "
    "registered-domain checks, and a provisional trusted-domain list."
)

st.info(
    "Model predictions are estimates. A legitimate prediction or "
    "trusted-list match does not guarantee that a website is safe."
)

st.divider()

# --------------------------------------------------
# URL INPUT
# --------------------------------------------------

url = st.text_input(
    "Enter a URL to analyze",
    placeholder="https://example.com",
)

analyze_button = st.button(
    "🔍 Analyze URL",
    type="primary",
    use_container_width=True,
)

# --------------------------------------------------
# TRUSTED DOMAIN LOADER
# --------------------------------------------------

def load_trusted_domains():
    trusted_domains = set()

    trusted_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "trusted_domains.csv",
    )

    try:
        trusted_df = pd.read_csv(trusted_file)

        if "url" not in trusted_df.columns:
            return trusted_domains

        for item in trusted_df["url"].dropna():
            host = (urlparse(str(item)).hostname or "").lower()

            if host.startswith("www."):
                host = host[4:]

            if host:
                trusted_domains.add(host)

    except (OSError, ValueError, KeyError):
        pass

    return trusted_domains


# --------------------------------------------------
# ANALYZE URL
# --------------------------------------------------

if analyze_button:

    if not url.strip():
        st.error("Please enter a URL to analyze.")

    else:
        try:
            candidate = prepare_url(url)

            features = extract_features(candidate)

            missing = [
                col for col in feature_columns
                if col not in features
            ]

            if missing:
                st.error(f"Missing model features: {missing}")
                st.stop()

            input_data = pd.DataFrame(
                [
                    {
                        col: features[col]
                        for col in feature_columns
                    }
                ],
                columns=feature_columns,
            )

            # Machine learning prediction
            prediction = int(model.predict(input_data)[0])

            if not hasattr(model, "predict_proba"):
                st.error("The model does not support probability estimates.")
                st.stop()

            classes = list(model.classes_)
            probabilities = model.predict_proba(input_data)[0]

            phishing_score = float(
                probabilities[classes.index(1)] * 100
            )

            legitimate_score = float(
                probabilities[classes.index(0)] * 100
            )

            classification = label_map.get(
                prediction,
                str(prediction),
            )

            risk_level = calculate_risk(phishing_score)

            # URL and domain analysis
            findings, detected_words = analyze_url(
                candidate,
                features,
            )

            domain_info = analyze_registered_domain(candidate)

            hostname = (urlparse(candidate).hostname or "").lower()

            if hostname.startswith("www."):
                hostname = hostname[4:]

            trusted_domains = load_trusted_domains()
            trusted_match = hostname in trusted_domains

            # ------------------------------------------
            # RESULTS
            # ------------------------------------------

            st.divider()
            st.header("📊 Analysis Results")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "ML Classification",
                classification,
            )

            col2.metric(
                "Phishing Score",
                f"{phishing_score:.2f}%",
            )

            col3.metric(
                "Risk Band",
                risk_level,
            )

            st.caption(
                f"Model-estimated legitimate score: "
                f"{legitimate_score:.2f}%"
            )

            # Final assessment: preserve ML prediction
            if prediction == 1 and trusted_match:
                st.warning(
                    "⚠️ CONFLICTING SIGNALS: The model flags this URL, "
                    "but its hostname appears in the provisional trusted "
                    "list. Verify the URL independently."
                )

            elif prediction == 1:
                st.error(
                    "🚨 POTENTIALLY PHISHING: The model classified "
                    "this URL as phishing. Avoid interacting with it "
                    "until its legitimacy is verified."
                )

            elif risk_level in ("HIGH", "VERY HIGH") or detected_words:
                st.warning(
                    "⚠️ CAUTION: The model classified this URL as "
                    "legitimate, but additional warning indicators "
                    "were detected."
                )

            else:
                st.success(
                    "The model did not classify this URL as phishing. "
                    "This does not guarantee that it is safe."
                )

            # ------------------------------------------
            # REGISTERED-DOMAIN CHECK
            # ------------------------------------------

            st.subheader("🌐 Registered-Domain Check")

            st.write(
                f"**Registered domain:** "
                f"{domain_info['registered_domain']}"
            )

            st.write(
                "**Trusted-list match:** "
                + (
                    "Yes — provisionally listed"
                    if trusted_match
                    else "No"
                )
            )

            if domain_info["brand_mismatch"]:
                st.error(
                    "Brand/domain mismatch detected: "
                    + ", ".join(
                        domain_info["brand_labels_outside_domain"]
                    )
                )
            else:
                st.write(
                    "No brand/domain mismatch detected by this check."
                )

            # ------------------------------------------
            # URL CHARACTERISTICS
            # ------------------------------------------

            st.subheader("🔎 URL Characteristics")

            feature_col1, feature_col2 = st.columns(2)

            with feature_col1:
                st.write(f"**URL:** `{candidate}`")

                st.write(
                    "**HTTPS enabled:** "
                    + (
                        "Yes"
                        if features.get("has_https", 0)
                        else "No"
                    )
                )

                st.write(
                    "**IP address detected:** "
                    + (
                        "Yes"
                        if features.get("has_ip", 0)
                        else "No"
                    )
                )

                st.write(
                    f"**URL length:** "
                    f"{features.get('url_length', 'N/A')}"
                )

                st.write(
                    f"**Number of dots:** "
                    f"{features.get('num_dots', 'N/A')}"
                )

            with feature_col2:
                st.write(
                    f"**Subdirectories:** "
                    f"{features.get('num_subdirs', 'N/A')}"
                )

                st.write(
                    f"**Parameters:** "
                    f"{features.get('num_params', 'N/A')}"
                )

                st.write(
                    "**Suspicious words:** "
                    + (
                        ", ".join(detected_words)
                        if detected_words
                        else "None"
                    )
                )

                st.write(
                    f"**Special characters:** "
                    f"{features.get('special_char_count', 'N/A')}"
                )

                st.write(
                    f"**Top-level domain:** "
                    f"{features.get('tld', 'N/A')}"
                )

            # ------------------------------------------
            # SECURITY FINDINGS
            # ------------------------------------------

            st.subheader("🧩 Security Findings")

            for finding in findings:
                st.write(f"- {finding}")

            # ------------------------------------------
            # RECOMMENDATIONS
            # ------------------------------------------

            st.subheader("🔐 Security Recommendations")

            if prediction == 1:
                st.write(
                    "- Avoid interacting with this URL until verified."
                )
                st.write(
                    "- Never enter passwords, OTPs, or banking details."
                )
                st.write(
                    "- Visit the official website directly when possible."
                )

            else:
                st.write(
                    "- Verify the domain independently before sharing "
                    "sensitive information."
                )
                st.write(
                    "- A legitimate prediction does not guarantee safety."
                )

            if domain_info["brand_mismatch"]:
                st.write(
                    "- Check the registered domain carefully for "
                    "possible brand impersonation."
                )

            with st.expander("View extracted model features"):
                st.json(features)

            st.caption(
                "The model scores are not calibrated real-world "
                "probabilities. This application does not visit websites "
                "or guarantee their safety."
            )

        except Exception as error:
            st.error(f"Could not analyze this URL: {error}")

# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.markdown(
    """
    <div style="text-align:center; padding:12px;">
        <span style="color:#2F3A5F;">
            🛡️ Phishing URL Detector
            <br>
            Soft Cyber Edition • Machine Learning Security Analysis
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)
