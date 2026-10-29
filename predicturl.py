
import os
import re
import ipaddress
import joblib
import pandas as pd

from urllib.parse import urlparse
from feature import extract_features
from feature_v2 import extract_features_v2


# ==========================================================
# 1. LOAD MODEL
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Default: use the existing model.
# To test another model, set PHISHING_MODEL_FILE in the terminal.
MODEL_FILE = os.environ.get("PHISHING_MODEL_FILE", "phishing_model.pkl")
MODEL_PATH = os.path.join(BASE_DIR, MODEL_FILE)

try:
    saved_data = joblib.load(MODEL_PATH)

    model = saved_data["model"]
    feature_version = saved_data.get("feature_version", 1)
    if feature_version == 2:
        extract_features = extract_features_v2
    feature_columns = saved_data["feature_columns"]
    label_map = saved_data.get(
        "label_map", {0: "Legitimate", 1: "Phishing"}
    )
    model_name = saved_data.get(
        "model_name", "Trained Machine Learning Model"
    )

    if not hasattr(model, "predict"):
        raise ValueError("The saved model does not support prediction.")

    print("Model loaded successfully:", MODEL_FILE)
    print("Algorithm:", model_name)

except FileNotFoundError:
    print(f"Error: Model file not found: {MODEL_PATH}")
    raise SystemExit(1)

except (KeyError, ValueError, TypeError, OSError) as error:
    print("Error loading model:", error)
    raise SystemExit(1)


# ==========================================================
# 2. SECURITY INDICATORS
# ==========================================================

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "password", "confirm", "signin", "paypal",
    "free", "bonus", "wallet", "recover", "suspended",
    "authenticate", "credential", "webscr", "validation",
    "billing"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "ow.ly", "rb.gy"
}


# ==========================================================
# 3. CLEAN, NORMALIZE AND VALIDATE INPUT
# ==========================================================

def prepare_url(url):
    """Normalize a plain URL or a copied Markdown link."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a non-empty URL.")

    candidate = url.strip()

    # Handle a Markdown link such as:
    # [https://example.com/](https://example.com/)
    markdown_match = re.fullmatch(
        r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
        candidate,
        flags=re.IGNORECASE
    )

    if markdown_match:
        visible_url = markdown_match.group(1).strip()
        target_url = markdown_match.group(2).strip()

        # Only accept matching visible and target URLs.
        if visible_url == target_url:
            candidate = target_url
        else:
            raise ValueError(
                "The Markdown link text and destination differ. "
                "Please enter the actual destination URL directly."
            )

    # Handle a URL copied with surrounding angle brackets.
    if candidate.startswith("<") and candidate.endswith(">"):
        candidate = candidate[1:-1].strip()

    # Reject remaining Markdown or embedded whitespace.
    if any(ch.isspace() for ch in candidate):
        raise ValueError(
            "The input contains spaces or unsupported formatting. "
            "Enter a plain URL."
        )

    if any(ch in candidate for ch in "[]<>"):
        raise ValueError(
            "Unsupported link formatting. Enter a plain URL."
        )

    # Add a scheme if the user entered only a domain or path.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate

    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("The URL must contain a valid hostname.")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port number.")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("The URL contains an invalid port number.")

    hostname = parsed.hostname.rstrip(".").lower()

    if not hostname:
        raise ValueError("The hostname is invalid.")

    # Validate IPv4/IPv6 addresses when applicable.
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip:
        if ":" in hostname:
            raise ValueError("The hostname is invalid.")

        if len(hostname) > 253:
            raise ValueError("The hostname is too long.")

        if any(not part for part in hostname.split(".")):
            raise ValueError("The hostname is invalid.")

    # Preserve the path/query, but normalize the scheme and hostname.
    return candidate


# ==========================================================
# 4. MODEL SCORE BAND
# ==========================================================

def calculate_risk(probability):
    if probability < 20:
        return "LOW"
    if probability < 50:
        return "MODERATE"
    if probability < 80:
        return "HIGH"
    return "VERY HIGH"


# ==========================================================
# 5. URL CHARACTERISTICS
# ==========================================================

def analyze_url(url, features):
    findings = []

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    url_lower = url.lower()

    if features.get("has_ip", 0):
        findings.append(
            "The hostname uses an IP address instead of a domain name."
        )

    if parsed.scheme.lower() != "https":
        findings.append("The URL uses HTTP rather than HTTPS.")

    detected_words = [
        word for word in SUSPICIOUS_WORDS if word in url_lower
    ]

    if detected_words:
        findings.append(
            "Potentially suspicious words detected: "
            + ", ".join(detected_words)
        )

    if features.get("url_length", 0) > 100:
        findings.append("The URL is unusually long.")

    if features.get("num_dots", 0) > 4:
        findings.append("The URL contains an unusually high number of dots.")

    if features.get("num_subdirs", 0) > 4:
        findings.append("The URL contains many subdirectories.")

    if features.get("num_params", 0) > 5:
        findings.append("The URL contains many query parameters.")

    if features.get("special_char_count", 0) > 15:
        findings.append("The URL contains many special characters.")

    if features.get("digits_count", 0) > 10:
        findings.append("The URL contains many numerical characters.")

    if "@" in url:
        findings.append(
            "The URL contains an @ symbol, which can obscure the destination."
        )

    if any(
        hostname == shortener or hostname.endswith("." + shortener)
        for shortener in SHORTENERS
    ):
        findings.append(
            "The URL uses a shortening service, so its destination may be hidden."
        )

    if not findings:
        findings.append(
            "No suspicious characteristics were detected by these basic checks."
        )

    return findings, detected_words


# ==========================================================
# REGISTERED-DOMAIN ANALYSIS
# ==========================================================
def analyze_registered_domain(url):
    """Identify brand names in the hostname and report domain mismatches."""
    import tldextract

    extractor = tldextract.TLDExtract(suffix_list_urls=None)
    hostname = (urlparse(url).hostname or "").lower().rstrip(".")
    result = extractor(hostname)

    registered_domain = (
        f"{result.domain}.{result.suffix}"
        if result.domain and result.suffix
        else hostname
    )

    brands = {
        "google", "microsoft", "apple", "amazon", "paypal",
        "facebook", "instagram", "github", "wikipedia",
        "netflix", "adobe", "dropbox", "linkedin", "outlook",
        "icloud", "bankofamerica", "chase", "steam", "youtube",
    }

    labels = hostname.split(".")
    registered_labels = registered_domain.split(".")
    registered_name = result.domain.lower()

    brand_labels_outside_domain = [
        label for label in labels
        if any(brand in label for brand in brands)
        and label not in registered_labels
    ]

    return {
        "hostname": hostname,
        "registered_domain": registered_domain,
        "brand_mismatch": bool(
            brand_labels_outside_domain
            and not any(brand in registered_name for brand in brands)
        ),
        "brand_labels_outside_domain": brand_labels_outside_domain,
    }


# ==========================================================
# 6. RECOMMENDATIONS
# ==========================================================


def generate_recommendations(prediction, risk_level, findings):
    recommendations = []

    if prediction == 1:
        recommendations.extend([
            "Avoid opening this URL until its legitimacy is verified.",
            "Do not enter passwords, OTPs, or banking information.",
            "Visit the official website directly instead of using this link.",
            "If received through email or SMS, verify the sender."
        ])

    if any("IP address" in item for item in findings):
        recommendations.append(
            "Verify the destination through a trusted source."
        )

    if any("shortening service" in item for item in findings):
        recommendations.append(
            "Check the final destination using a trusted security service."
        )

    if prediction == 0:
        recommendations.extend([
            "The model did not classify this URL as phishing; this does not prove it is safe.",
            "Check the domain spelling and verify the website independently.",
            "Avoid entering sensitive information on unexpected websites."
        ])

    if risk_level in ("MODERATE", "HIGH", "VERY HIGH"):
        recommendations.append(
            "Exercise additional caution because the model's estimated "
            "phishing score is elevated."
        )

    if risk_level in ("HIGH", "VERY HIGH"):
        recommendations.append(
            "Consider reporting the URL to your organization's security team."
        )

    return recommendations



# ==========================================================
# 7. PREDICT AND DISPLAY REPORT
# ==========================================================

def predict_url(url):
    try:
        candidate = prepare_url(url)
        features = extract_features(candidate)

        if not isinstance(features, dict):
            raise ValueError("Feature extraction returned invalid data.")

        missing = [
            column for column in feature_columns
            if column not in features
        ]

        if missing:
            raise ValueError(
                f"Missing model features: {missing}"
            )

        # Preserve the exact column names and order expected by the model.
        input_data = pd.DataFrame(
            [{column: features[column] for column in feature_columns}],
            columns=feature_columns
        )

        prediction = int(model.predict(input_data)[0])

        if not hasattr(model, "predict_proba"):
            raise ValueError(
                "This model does not support probability estimates."
            )

        if not hasattr(model, "classes_"):
            raise ValueError("The model does not expose its class labels.")

        classes = list(model.classes_)

        if 0 not in classes or 1 not in classes:
            raise ValueError(
                "Expected model classes 0 (Legitimate) and 1 (Phishing)."
            )

        probabilities = model.predict_proba(input_data)[0]
        phishing_score = float(probabilities[classes.index(1)] * 100)
        legitimate_score = float(probabilities[classes.index(0)] * 100)

        classification = label_map.get(
            prediction,
            label_map.get(str(prediction), "Unknown")
        )

        risk_level = calculate_risk(phishing_score)
        findings, detected_words = analyze_url(candidate, features)
        domain_info = analyze_registered_domain(candidate)
        hostname = (urlparse(candidate).hostname or "").lower()
        trusted_domains = set()

        try:
            trusted_df = pd.read_csv(
                os.path.join(BASE_DIR, "trusted_domains.csv")
            )
            for trusted_url in trusted_df["url"].dropna():
                trusted_host = (urlparse(str(trusted_url)).hostname or "").lower()
                if trusted_host.startswith("www."):
                    trusted_host = trusted_host[4:]
                trusted_domains.add(trusted_host)
        except (OSError, ValueError, KeyError):
            pass

        normalized_host = hostname[4:] if hostname.startswith("www.") else hostname
        trusted_domain_match = normalized_host in trusted_domains

        print("\\nREGISTERED-DOMAIN CHECK")
        print("-" * 65)
        print("Registered Domain:", domain_info["registered_domain"])
        print(
            "Trusted List Match:",
            "Yes (listed as provisionally legitimate)"
            if trusted_domain_match
            else "No"
        )
        if domain_info["brand_mismatch"]:
            warning = (
                "A familiar brand name appears outside the registered domain: "
                + ", ".join(domain_info["brand_labels_outside_domain"])
            )
            print("Domain Warning:", warning)
            findings.append(warning)
        else:
            print("Domain Warning: No brand/domain mismatch detected.")

        recommendations = generate_recommendations(
            prediction, risk_level, findings
        )

        print("\n" + "=" * 65)
        print("          PHISHING URL DETECTION SYSTEM")
        print("       Machine Learning-Based Security Analysis")
        print("=" * 65)

        print("\nInput URL:", candidate)

        print("\n1. WEBSITE CLASSIFICATION")
        print("-" * 65)
        print("Predicted Class :", classification)
        print("Prediction Label:", prediction)

        print("\n2. MACHINE LEARNING PREDICTION")
        print("-" * 65)
        print("Algorithm Used:", model_name)
        print(f"Model-Estimated Phishing Score: {phishing_score:.2f}%")
        print(f"Model-Estimated Legitimate Score: {legitimate_score:.2f}%")
        print("Model Risk Band:", risk_level)
        print(
            "Note: These are model scores, not calibrated real-world "
            "probabilities or a guarantee of website safety."
        )

        print("\n3. EXTRACTED URL FEATURES")
        print("-" * 65)
        print("URL Length:", features.get("url_length", "N/A"))
        print("Number of Dots:", features.get("num_dots", "N/A"))
        print("HTTPS Enabled:", "Yes" if features.get("has_https", 0) else "No")
        print("IP Address Detected:", "Yes" if features.get("has_ip", 0) else "No")
        print("Number of Subdirectories:", features.get("num_subdirs", "N/A"))
        print("Number of Parameters:", features.get("num_params", "N/A"))
        print("Suspicious Words:", ", ".join(detected_words) if detected_words else "None")
        print("Special Character Count:", features.get("special_char_count", "N/A"))
        print("Digit Count:", features.get("digits_count", "N/A"))
        print("Top-Level Domain:", features.get("tld", "N/A"))
        print("URL Entropy:", features.get("entropy", "N/A"))

        print("\n4. URL CHARACTERISTICS ANALYSIS")
        print("-" * 65)
        for finding in findings:
            print("[!] " + finding)

        if prediction == 1:
            print("\nThe model classified this URL as potentially phishing.")
        elif len(findings) > 1 or detected_words:
            print(
                "\nThe model classified this URL as legitimate, but warning "
                "indicators were detected. Exercise caution."
            )
        else:
            print(
                "\nThe model classified this URL as legitimate. "
                "This does not establish that it is safe."
            )

        print("\n5. SECURITY RECOMMENDATIONS")
        print("-" * 65)
        for number, recommendation in enumerate(recommendations, start=1):
            print(f"{number}. {recommendation}")

        print("\n6. FINAL SECURITY ASSESSMENT")
       
        print("-" * 65)
        print("ML Classification:", classification)
        print("Model Risk Band:", risk_level)

        if prediction == 1 and trusted_domain_match:
            print("\nFinal Assessment: CONFLICTING SIGNALS")
            print(
                "Recommended Action: The model flagged this URL, "
                "but it appears in the provisional trusted list. "
                "Verify it independently."
            )
        elif prediction == 1:
            print("\nFinal Assessment: POTENTIALLY PHISHING")
            print("Recommended Action: Avoid interacting with this URL.")
        elif risk_level in ("HIGH", "VERY HIGH") or detected_words:
            print("\nFinal Assessment: CAUTION")
            print("Recommended Action: Verify the URL independently.")
        else:
            print("\nFinal Assessment: NOT CLASSIFIED AS PHISHING")
            print(
                "Recommended Action: Verify the website before sharing "
                "sensitive information."
            )

        print("\nImportant:")
        print(
            "This tool analyzes URL characteristics and machine learning "
            "predictions. It does not visit the website, verify its current "
            "content, or guarantee that it is safe."
        )
        print("=" * 65)


    except (ValueError, TypeError, KeyError) as error:
        print("\nError: The URL could not be analyzed.")
        print("Details:", error)
    except Exception as error:
        print("\nError: Prediction could not be completed.")
        print("Details:", error)


# ==========================================================
# 8. RUN PROGRAM
# ==========================================================

if __name__ == "__main__":
    print("\nPHISHING URL DETECTION SYSTEM")
    print("Enter 'exit' to close the program.")

    while True:
        try:
            url = input("\nEnter URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nProgram terminated.")
            break

        if url.lower() == "exit":
            print("Program terminated.")
            break

        if not url:
            print("Please enter a URL.")
            continue

        predict_url(url)
