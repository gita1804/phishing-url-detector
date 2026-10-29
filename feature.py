
import math
import re
import ipaddress
from collections import Counter
from urllib.parse import urlparse


# --------------------------------------------------
# 1. Suspicious keywords
# --------------------------------------------------

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure",
    "account", "banking", "password", "confirm",
    "signin", "paypal", "free", "bonus",
    "wallet", "recover", "suspended",
    "authenticate", "credential", "webscr",
    "validation", "billing"
]


# --------------------------------------------------
# 2. Calculate URL entropy
# --------------------------------------------------

def calculate_entropy(text):
    """Calculate the character entropy of a URL."""

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )

    return round(entropy, 4)


# --------------------------------------------------
# 3. Extract URL features
# --------------------------------------------------

def extract_features(url):
    """Extract features from a URL for ML prediction."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a valid URL.")

    # Preserve the original URL for feature calculation.
    original_url = url.strip()

    # Prepare the URL for parsing.
    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        original_url
    ):
        url_for_parsing = "http://" + original_url
    else:
        url_for_parsing = original_url

    parsed = urlparse(url_for_parsing)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # --------------------------------------------------
    # Check whether the hostname is an IP address
    # --------------------------------------------------

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    # --------------------------------------------------
    # Extract top-level domain
    # --------------------------------------------------

    if has_ip:
        tld = "IP"
    elif "." in hostname:
        tld = hostname.rsplit(".", 1)[-1]
    else:
        tld = "unknown"

    # --------------------------------------------------
    # Count suspicious keywords
    # --------------------------------------------------

    url_lower = original_url.lower()

    suspicious_words = sum(
        url_lower.count(word)
        for word in SUSPICIOUS_WORDS
    )

    # --------------------------------------------------
    # Count path segments
    # --------------------------------------------------

    num_subdirs = len([
        part
        for part in path.split("/")
        if part
    ])

    # --------------------------------------------------
    # Count query parameters
    # --------------------------------------------------

    num_params = len([
        item
        for item in query.split("&")
        if item
    ])

    # --------------------------------------------------
    # Count special characters
    # --------------------------------------------------

    special_char_count = sum(
        1
        for char in original_url
        if not char.isalnum()
    )

    # --------------------------------------------------
    # Count digits
    # --------------------------------------------------

    digits_count = sum(
        1
        for char in original_url
        if char.isdigit()
    )

    # --------------------------------------------------
    # Detect HTTPS
    # --------------------------------------------------

    has_https = int(
        parsed.scheme.lower() == "https"
    )

    # --------------------------------------------------
    # Build feature dictionary
    # --------------------------------------------------

    features = {
        "url_length": len(original_url),
        "num_dots": original_url.count("."),
        "has_https": has_https,
        "has_ip": has_ip,
        "num_subdirs": num_subdirs,
        "num_params": num_params,
        "suspicious_words": suspicious_words,
        "tld": tld,
        "special_char_count": special_char_count,
        "digits_count": digits_count,
        "entropy": calculate_entropy(original_url)
    }

    return features


# --------------------------------------------------
# 4. Test feature extraction
# --------------------------------------------------

if __name__ == "__main__":

    print("=" * 50)
    print("       PHISHING URL FEATURE EXTRACTION")
    print("=" * 50)

    while True:

        user_url = input(
            "\nEnter a URL to analyze (or type 'exit'): "
        ).strip()

        if user_url.lower() == "exit":
            print("\nProgram closed.")
            break

        try:
            extracted_features = extract_features(user_url)

            print("\nURL Analysis")
            print("-" * 50)
            print("Input URL:", user_url)

            print("\nExtracted Features")
            print("-" * 50)
            print(f"{'Feature':<25} {'Value':<20}")
            print("-" * 50)

            for feature, value in extracted_features.items():
                print(f"{feature:<25} {str(value):<20}")

            print("-" * 50)
            print("Feature extraction completed successfully!")

        except ValueError as error:
            print("\nError:", error)
