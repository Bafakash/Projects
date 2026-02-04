import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "confirm",
    "signin",
]

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
}

RISKY_TLDS = {
    "xyz",
    "top",
    "icu",
    "click",
    "live",
    "tk",
    "monster",
    "work",
}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

BRAND_ALLOWLIST = {
    # If a domain contains these brand strings but isn't an official domain suffix, add extra risk.
    "paypal": {"paypal.com", "paypal.me"},
}


def _clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))


def check_url(raw_url: str):
    """Return (safe: bool, report: dict) with risk + reasons (codes + optional value)."""

    url = (raw_url or "").strip()
    if not url:
        return False, {
            "message_key": "Invalid URL format",
            "risk": 100,
            "normalized": "",
            "domain": "",
            "reasons": [{"code": "EMPTY_URL"}],
        }

    normalized = url
    if not re.match(r"^https?://", normalized, re.IGNORECASE):
        normalized = "http://" + normalized

    try:
        parsed = urlparse(normalized)
    except Exception:
        return False, {
            "message_key": "Invalid URL format",
            "risk": 100,
            "normalized": normalized,
            "domain": "",
            "reasons": [{"code": "INVALID_URL"}],
        }

    if not parsed.netloc:
        return False, {
            "message_key": "Invalid URL format",
            "risk": 100,
            "normalized": normalized,
            "domain": "",
            "reasons": [{"code": "INVALID_URL"}],
        }

    domain = (parsed.hostname or "").strip(".").lower()
    if not domain:
        return False, {
            "message_key": "Invalid URL format",
            "risk": 100,
            "normalized": normalized,
            "domain": "",
            "reasons": [{"code": "INVALID_URL"}],
        }

    reasons = []
    risk = 0.0

    # Scheme/security
    if (parsed.scheme or "").lower() != "https":
        risk += 12
        reasons.append({"code": "NOT_HTTPS"})

    # Common obfuscation tricks
    if "@" in (parsed.netloc or ""):
        risk += 30
        reasons.append({"code": "HAS_AT_SYMBOL"})

    if _IPV4_RE.match(domain):
        risk += 45
        reasons.append({"code": "IP_ADDRESS_HOST"})

    if domain.startswith("xn--") or ".xn--" in domain:
        risk += 25
        reasons.append({"code": "PUNYCODE_DOMAIN"})

    # Suspicious patterns in host
    dot_count = domain.count(".")
    if dot_count > 3:
        risk += 20
        reasons.append({"code": "TOO_MANY_SUBDOMAINS", "value": str(dot_count + 1)})

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        risk += 12
        reasons.append({"code": "MANY_HYPHENS", "value": str(hyphen_count)})

    # Length-based signals
    if len(normalized) >= 85:
        risk += 10
        reasons.append({"code": "LONG_URL", "value": str(len(normalized))})

    # TLD risk (very rough heuristic)
    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld and tld in RISKY_TLDS:
        risk += 12
        reasons.append({"code": "RISKY_TLD", "value": tld})

    # URL shorteners hide destination
    if domain in URL_SHORTENERS:
        risk += 25
        reasons.append({"code": "URL_SHORTENER"})

    # Keyword match in domain
    keyword_hits = []
    for word in SUSPICIOUS_WORDS:
        if word in domain:
            keyword_hits.append(word)
            risk += 14
            reasons.append({"code": "SUSPICIOUS_KEYWORD", "value": word})

    if len(keyword_hits) >= 2:
        # Multiple sensitive keywords in one domain is a strong phishing signal.
        risk += 15
        reasons.append({"code": "MULTIPLE_SUSPICIOUS_KEYWORDS", "value": str(len(keyword_hits))})

    # Brand impersonation (very small allowlist; educational heuristic).
    for brand, allowed_suffixes in BRAND_ALLOWLIST.items():
        if brand in domain and not any(domain == sfx or domain.endswith("." + sfx) for sfx in allowed_suffixes):
            risk += 35
            reasons.append({"code": "BRAND_IMPERSONATION", "value": brand})

    risk = _clamp(risk, 0, 100)

    if risk >= 70:
        msg_key = "High risk URL"
        safe = False
    elif risk >= 55:
        msg_key = "Suspicious URL"
        safe = False
    else:
        msg_key = "URL looks safe"
        safe = True

    if not reasons and safe:
        reasons = [{"code": "NO_MAJOR_FLAGS"}]

    return safe, {
        "message_key": msg_key,
        "risk": round(risk, 2),
        "normalized": normalized,
        "domain": domain,
        "reasons": reasons,
    }
