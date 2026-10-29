from urllib.parse import urlparse
import ipaddress
import tldextract

from feature import extract_features

EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)

BRAND_NAMES = {
    "google", "microsoft", "apple", "amazon", "paypal",
    "facebook", "instagram", "github", "wikipedia", "netflix",
    "adobe", "dropbox", "linkedin", "outlook", "icloud",
    "bankofamerica", "chase", "steam", "youtube",
}


def extract_features_v2(url):
    features = extract_features(url)

    text = url.strip()
    if "://" not in text:
        text = "https://" + text

    parsed = urlparse(text)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    result = EXTRACTOR(hostname)

    registered_domain = (
        result.domain + "." + result.suffix
        if result.domain and result.suffix
        else hostname
    )

    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    subdomain = result.subdomain.lower()
    registered_name = result.domain.lower()

    features.update({
        "hostname_length": len(hostname),
        "subdomain_count": len([x for x in subdomain.split(".") if x]),
        "registered_domain_length": len(registered_domain),
        "hostname_digit_count": sum(c.isdigit() for c in hostname),
        "hostname_hyphen_count": hostname.count("-"),
        "hostname_is_ip": is_ip,
        "brand_in_subdomain": int(
            any(brand in subdomain.split(".") for brand in BRAND_NAMES)
        ),
        "brand_in_registered_name": int(
            registered_name in BRAND_NAMES
        ),
    })

    return features
