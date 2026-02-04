import re

# Lightweight preprocessing for bilingual (Arabic/English) phishing text classification.
# Keep it simple and deterministic so the same logic can be mirrored in the offline app.

URL_RE = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b")

AR_LETTER_RE = re.compile(r"[\u0600-\u06FF]")
# Arabic diacritics (tashkeel) + Quranic marks ranges.
AR_DIACRITICS_RE = re.compile(r"[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED]")

# Basic stopwords only (avoid being overly aggressive; small datasets are sensitive).
AR_STOPWORDS = {
    "في",
    "على",
    "من",
    "الى",
    "إلى",
    "عن",
    "أن",
    "إن",
    "كان",
    "ما",
    "هذا",
    "هذه",
    "ذلك",
    "تلك",
    "هناك",
    "مع",
    "او",
    "أو",
    "ثم",
    "كما",
    "لقد",
}

EN_STOPWORDS = {
    "the",
    "is",
    "in",
    "on",
    "at",
    "and",
    "or",
    "to",
    "of",
    "a",
    "an",
    "for",
    "we",
    "you",
    "your",
    "our",
}


def is_probably_arabic(text: str) -> bool:
    text = text or ""
    return bool(AR_LETTER_RE.search(text))


def normalize_arabic(text: str) -> str:
    s = text or ""
    s = AR_DIACRITICS_RE.sub("", s)
    s = s.replace("\u0640", "")  # tatweel
    # Normalize common letter variants.
    s = s.replace("أ", "ا").replace("إ", "ا").replace("آ", "ا")
    s = s.replace("ى", "ي")
    s = s.replace("ؤ", "و").replace("ئ", "ي")
    # Optional normalization often used in IR/NLP.
    s = s.replace("ة", "ه")
    return s


def clean_text(text: str) -> str:
    s = str(text or "")

    # Keep signals that a URL/email existed, without letting full URLs dominate the vocabulary.
    s = URL_RE.sub(" URLTOKEN ", s)
    s = EMAIL_RE.sub(" EMAILTOKEN ", s)

    if is_probably_arabic(s):
        s = normalize_arabic(s)

    s = s.lower()

    # Keep: latin, digits, underscores, Arabic block, and our *_token placeholders.
    s = re.sub(r"[^a-z0-9_\u0600-\u06FF\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()

    if not s:
        return ""

    tokens = s.split()
    tokens = [
        t
        for t in tokens
        if (t not in EN_STOPWORDS)
        and (t not in AR_STOPWORDS)
        and len(t) > 1
    ]
    return " ".join(tokens)

