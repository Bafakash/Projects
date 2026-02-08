from flask import Flask, render_template, request
from flask import make_response
import joblib
from url_checker import check_url
from flask import redirect, session, url_for
from flask import send_from_directory
from datetime import datetime
import os
import re

from preprocess import clean_text, is_probably_arabic

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")

# Load NLP model correctly (joblib, NOT pickle)
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Optional TensorFlow model (for experimentation / ensemble). Disabled by default.
TF_MODEL_DIR = os.environ.get("SAFESCAN_TF_MODEL_DIR", "tf_model")
USE_TF = os.environ.get("SAFESCAN_USE_TF", "0").strip() == "1"
tf_model = None
if USE_TF:
    try:
        import tensorflow as tf  # type: ignore

        tf_model = tf.keras.models.load_model(TF_MODEL_DIR)
    except Exception:
        tf_model = None

MAX_HISTORY = 12
MAX_ANALYSIS_CHARS = 8000
MAX_HISTORY_SNIPPET_CHARS = 180
MAX_URLS = 10
RISK_CAUTION_MIN = 55
RISK_UNSAFE_MIN = 70
APK_FILENAME = "SafeScan.apk"
DOWNLOADS_DIR = os.path.join(app.root_path, "static", "downloads")

SUSPICIOUS_KEYWORDS_EN_STRONG = {
    "verify",
    "password",
    "login",
    "bank",
    "urgent",
    "suspended",
    "locked",
    "prize",
    "free",
    "click",
    "refund",
    "otp",
}

SUSPICIOUS_KEYWORDS_EN_WEAK = {
    "account",
    "confirm",
    "update",
    "code",
}

SUSPICIOUS_KEYWORDS_AR_STRONG = {
    "تحقق",
    "التحقق",
    "كلمه",
    "كلمة",
    "المرور",
    "بنك",
    "بنكي",
    "ايقاف",
    "إيقاف",
    "تعليق",
    "معلق",
    "جائزه",
    "جائزة",
    "ربحت",
    "اضغط",
    "انقر",
    "رمز",
    "otp",
}

SUSPICIOUS_KEYWORDS_AR_WEAK = {
    "حساب",
    "حسابك",
    "تحديث",
    "تأكيد",
    "تاكيد",
    "تسجيل",
    "الدخول",
    "اربح",
}

BENIGN_HINTS_EN = {
    "thank",
    "thanks",
    "contact",
    "soon",
    "appointment",
    "confirmed",
    "meeting",
    "invoice",
    "order",
    "shipped",
    "report",
    "welcome",
}

BENIGN_HINTS_AR = {
    "شكرا",
    "شكراً",
    "تواصل",
    "سنتواصل",
    "قريبا",
    "قريباً",
    "موعد",
    "الاجتماع",
    "تأكيد",
    "تاكيد",
    "الحجز",
    "اهلا",
    "أهلا",
}

TRANSLATIONS = {
    "en": {
        "title": "SafeScan • Message & URL Safety Checker",
        "brand": "SafeScan",
        "tagline": "Phishing & scam detection",
        "hero_title": "Detect suspicious links and messages in seconds.",
        "hero_text": "Paste a URL, message, or full email. SafeScan runs URL risk checks + NLP analysis and explains the result.",
        "badge_1": "URL risk checks",
        "badge_2": "NLP analysis",
        "badge_3": "Explainable report",
        "example_label": "Example",
        "example_text": "secure-login-paypal.com",
        "feature_1_title": "URL checks",
        "feature_1_text": "Flags suspicious domains, subdomains, and phishing patterns.",
        "feature_2_title": "Text scanning",
        "feature_2_text": "Analyses the message text with an NLP classifier (English + Arabic).",
        "feature_3_title": "Clear results",
        "feature_3_text": "Readable explanations and a simple risk signal.",
        "scan_title": "Scan now",
        "scan_subtitle": "Paste a URL, message, or a full email to analyse.",
        "placeholder": "Enter text or URL...",
        "check": "Check",
        "confidence": "Risk score",
        "nlp_confidence": "NLP confidence",
        "safe": "Safe",
        "caution": "Suspicious",
        "unsafe": "Unsafe",
        "ml_safe_msg": "No major risk signals were detected in the text.",
        "ml_caution_msg": "Some risk signals were found. Be careful and verify before you act.",
        "ml_unsafe_msg": "High risk signals found. This may be phishing or a scam.",
        "privacy_note": "Input is only used to generate this result.",
        "history_title": "History",
        "history_empty": "No scans yet. Your previous checks will appear here.",
        "history_note": "History is stored for this browser session.",
        "clear_history": "Clear",
        "you": "You",
        "url": "URL",
        "urls": "URLs",
        "text": "Text",
        "email": "Email",
        "text_analysis_title": "Text analysis",
        "url_checks_title": "URL checks",
        "urls_none": "No URLs detected in this input.",
        "install": "Install",
        "download_app": "Download",
        "download_title": "Download SafeScan",
        "download_text": "Install SafeScan on your phone (recommended) or download the Android APK.",
        "download_install_hint": "If you see the Install button in the header, tap it to add SafeScan to your home screen.",
        "download_apk": "Download Android APK",
        "apk_note": "If Android blocks the install, enable \"Install unknown apps\" for your browser, then try again.",
        "apk_missing": "APK is not uploaded yet.",
        "back_to_scan": "Back to scanner",
        "footer": "Educational project • Always verify before you click.",
        "toggle": "العربية",
    },
    "ar": {
        "title": "SafeScan • فاحص أمان الرسائل والروابط",
        "brand": "SafeScan",
        "tagline": "كشف التصيّد والاحتيال",
        "hero_title": "اكشف الروابط والرسائل المشبوهة خلال ثوانٍ.",
        "hero_text": "الصق رابطًا أو رسالة أو بريدًا كاملًا. يجمع SafeScan بين فحص الروابط وتحليل NLP ويعرض الأسباب.",
        "badge_1": "فحص الروابط",
        "badge_2": "تحليل NLP",
        "badge_3": "تقرير واضح",
        "example_label": "مثال",
        "example_text": "secure-login-paypal.com",
        "feature_1_title": "فحص الروابط",
        "feature_1_text": "يرصد النطاقات والكلمات والأنماط الشائعة في التصيّد.",
        "feature_2_title": "تحليل الرسائل",
        "feature_2_text": "يحلّل النص باستخدام نموذج NLP (باللغتين العربية والإنجليزية).",
        "feature_3_title": "نتيجة واضحة",
        "feature_3_text": "شرح مبسّط مع إشارة واضحة للمخاطر.",
        "scan_title": "تحقق الآن",
        "scan_subtitle": "الصق رابطًا أو رسالة أو بريدًا كاملًا للتحليل.",
        "placeholder": "اكتب رسالة أو رابط...",
        "check": "تحقق",
        "confidence": "مستوى المخاطر",
        "nlp_confidence": "ثقة نموذج NLP",
        "safe": "آمن",
        "caution": "مشبوه",
        "unsafe": "غير آمن",
        "ml_safe_msg": "لم يتم رصد مؤشرات كبيرة على الخطر في النص.",
        "ml_caution_msg": "تم رصد بعض المؤشرات. كن حذرًا وتحقق قبل اتخاذ أي إجراء.",
        "ml_unsafe_msg": "تم رصد مؤشرات عالية الخطورة. قد يكون هذا تصيّدًا أو احتيالًا.",
        "privacy_note": "يُستخدم الإدخال فقط لإظهار النتيجة.",
        "history_title": "السجل",
        "history_empty": "لا يوجد سجل بعد. ستظهر نتائج التحقق السابقة هنا.",
        "history_note": "يتم حفظ السجل في جلسة المتصفح الحالية.",
        "clear_history": "مسح",
        "you": "أنت",
        "url": "رابط",
        "urls": "الروابط",
        "text": "نص",
        "email": "بريد",
        "text_analysis_title": "تحليل النص",
        "url_checks_title": "فحص الروابط",
        "urls_none": "لم يتم العثور على روابط في هذا النص.",
        "install": "تثبيت",
        "download_app": "تحميل",
        "download_title": "تحميل SafeScan",
        "download_text": "ثبّت التطبيق على هاتفك (مستحسن) أو حمّل ملف APK للأندرويد.",
        "download_install_hint": "إذا ظهر زر التثبيت في الأعلى، اضغط عليه لإضافة SafeScan إلى الشاشة الرئيسية.",
        "download_apk": "تحميل APK للأندرويد",
        "apk_note": "إذا منع الأندرويد التثبيت، فعّل خيار \"تثبيت التطبيقات غير المعروفة\" للمتصفح ثم حاول مرة أخرى.",
        "apk_missing": "لم يتم رفع ملف APK بعد.",
        "back_to_scan": "العودة للفحص",
        "footer": "مشروع تعليمي • تحقّق دائمًا قبل الضغط على أي رابط.",
        "toggle": "English",
    },
}

ARABIC_URL_MESSAGES = {
    "Invalid URL format": "صيغة الرابط غير صحيحة",
    "Suspicious URL": "الرابط مشبوه",
    "High risk URL": "رابط عالي الخطورة",
    "Suspicious keyword found in domain": "تم العثور على كلمة مشبوهة في النطاق",
    "Too many subdomains": "يوجد عدد كبير من النطاقات الفرعية",
    "URL looks safe": "يبدو الرابط آمنًا",
}


def _translate_url_message(message_key: str, lang: str) -> str:
    if lang == "ar":
        return ARABIC_URL_MESSAGES.get(message_key, message_key)
    return message_key


URL_REASON_TEMPLATES = {
    "en": {
        "EMPTY_URL": "Empty URL input.",
        "INVALID_URL": "Invalid URL format.",
        "NOT_HTTPS": "Not using HTTPS (encrypted connection).",
        "HAS_AT_SYMBOL": "Contains '@' in the address (can hide the real destination).",
        "NON_STANDARD_PORT": "Uses a non-standard port: {value}",
        "ENCODED_OBFUSCATION": "Contains heavy URL encoding (possible obfuscation).",
        "IP_ADDRESS_HOST": "Uses an IP address instead of a domain name.",
        "PUNYCODE_DOMAIN": "Punycode domain (possible look-alike domain).",
        "TOO_MANY_SUBDOMAINS": "Too many subdomains ({value}).",
        "MANY_HYPHENS": "Many hyphens in the domain ({value}).",
        "LONG_URL": "Very long URL ({value} characters).",
        "RISKY_TLD": "Risky top-level domain: .{value}",
        "URL_SHORTENER": "URL shortener hides the destination.",
        "SUSPICIOUS_KEYWORD": "Domain contains suspicious keyword: {value}",
        "MULTIPLE_SUSPICIOUS_KEYWORDS": "Multiple suspicious keywords in domain ({value}).",
        "SUSPICIOUS_PATH_KEYWORD": "Path/query contains suspicious keyword: {value}",
        "MULTIPLE_SUSPICIOUS_PATH_KEYWORDS": "Multiple suspicious keywords in path/query ({value}).",
        "EXPLICIT_PHISHING_TERM": "Explicit phishing term detected in URL.",
        "BRAND_IMPERSONATION": "Brand name used in domain (possible impersonation): {value}",
        "NO_MAJOR_FLAGS": "No major red flags detected.",
    },
    "ar": {
        "EMPTY_URL": "لم يتم إدخال رابط.",
        "INVALID_URL": "صيغة الرابط غير صحيحة.",
        "NOT_HTTPS": "لا يستخدم HTTPS (اتصال غير مُشفّر).",
        "HAS_AT_SYMBOL": "يحتوي على الرمز @ (قد يُخفي الوجهة الحقيقية).",
        "NON_STANDARD_PORT": "يستخدم منفذًا غير معتاد: {value}",
        "ENCODED_OBFUSCATION": "يحتوي على ترميز URL كبير (قد يكون تمويهًا).",
        "IP_ADDRESS_HOST": "يستخدم عنوان IP بدلًا من اسم نطاق.",
        "PUNYCODE_DOMAIN": "نطاق Punycode (قد يكون نطاقًا مُشابِهًا).",
        "TOO_MANY_SUBDOMAINS": "عدد كبير من النطاقات الفرعية ({value}).",
        "MANY_HYPHENS": "يوجد عدد كبير من الشرطات في النطاق ({value}).",
        "LONG_URL": "الرابط طويل جدًا ({value} حرفًا).",
        "RISKY_TLD": "امتداد نطاق عالي المخاطر: .{value}",
        "URL_SHORTENER": "رابط مختصر يُخفي الوجهة.",
        "SUSPICIOUS_KEYWORD": "يحتوي النطاق على كلمة مشبوهة: {value}",
        "MULTIPLE_SUSPICIOUS_KEYWORDS": "وجود عدة كلمات مشبوهة في النطاق ({value}).",
        "SUSPICIOUS_PATH_KEYWORD": "يحتوي مسار/استعلام الرابط على كلمة مشبوهة: {value}",
        "MULTIPLE_SUSPICIOUS_PATH_KEYWORDS": "وجود عدة كلمات مشبوهة في مسار/استعلام الرابط ({value}).",
        "EXPLICIT_PHISHING_TERM": "تم العثور على مصطلح تصيّد صريح داخل الرابط.",
        "BRAND_IMPERSONATION": "يحتوي النطاق على اسم علامة تجارية وقد يكون انتحالًا: {value}",
        "NO_MAJOR_FLAGS": "لا توجد مؤشرات كبيرة على الخطر.",
    },
}


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _risk_class(risk_score: float) -> str:
    if risk_score >= RISK_UNSAFE_MIN:
        return "unsafe"
    if risk_score >= RISK_CAUTION_MIN:
        return "caution"
    return "safe"


def _url_reason_text(reason: dict, lang: str) -> str:
    code = (reason or {}).get("code", "")
    value = (reason or {}).get("value", "")

    templates = URL_REASON_TEMPLATES.get(lang, URL_REASON_TEMPLATES["en"])
    template = templates.get(code) or URL_REASON_TEMPLATES["en"].get(code, code or "")
    try:
        return template.format(value=value)
    except Exception:
        return template


_HTTP_URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
_WWW_URL_RE = re.compile(r"\bwww\.[^\s<>\"]+", re.IGNORECASE)
_BARE_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:/[^\s<>\"]*)?\b",
    re.IGNORECASE,
)
_SINGLE_URL_RE = re.compile(
    r"^(?:https?://|www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:/[^\s]*)?$",
    re.IGNORECASE,
)


def _strip_url_punctuation(value: str) -> str:
    value = (value or "").strip()
    value = value.lstrip("<([{\"'")
    value = value.rstrip(")]}>.,;:!?\"'")
    return value.strip()


def _looks_like_single_url(value: str) -> bool:
    value = _strip_url_punctuation(value)
    if not value or re.search(r"\s", value):
        return False
    if "@" in value:
        return False
    return bool(_SINGLE_URL_RE.fullmatch(value))


def _extract_urls(text: str):
    if not text:
        return []

    matches = []
    spans = []

    for regex in (_HTTP_URL_RE, _WWW_URL_RE):
        for m in regex.finditer(text):
            candidate = _strip_url_punctuation(m.group(0))
            if not candidate:
                continue
            lower = candidate.lower()
            if lower.startswith("mailto:"):
                continue

            matches.append((m.start(), candidate))
            spans.append((m.start(), m.end()))

    for m in _BARE_DOMAIN_RE.finditer(text):
        if m.start() > 0 and text[m.start() - 1] == "@":
            continue
        if any(start <= m.start() < end for start, end in spans):
            continue

        candidate = _strip_url_punctuation(m.group(0))
        if not candidate:
            continue

        matches.append((m.start(), candidate))

    matches.sort(key=lambda x: x[0])

    urls = []
    seen = set()
    for _, candidate in matches:
        lower = candidate.lower()
        if lower in seen:
            continue
        seen.add(lower)
        urls.append(candidate)
        if len(urls) >= MAX_URLS:
            break

    return urls


def _analyze_text(text: str, urls: list, ui: dict, lang: str):
    cleaned = clean_text(text)
    X = vectorizer.transform([cleaned])
    proba = model.predict_proba(X)[0]

    class_to_idx = {int(c): i for i, c in enumerate(getattr(model, "classes_", [0, 1]))}
    unsafe_idx = class_to_idx.get(1, 1 if len(proba) > 1 else 0)
    prob_unsafe_sklearn = float(proba[unsafe_idx])

    tf_prob_unsafe = None
    if tf_model is not None:
        try:
            pred = tf_model.predict([cleaned], verbose=0)
            tf_prob_unsafe = float(pred[0][0])
            if not (0.0 <= tf_prob_unsafe <= 1.0):
                tf_prob_unsafe = None
        except Exception:
            tf_prob_unsafe = None

    prob_unsafe = prob_unsafe_sklearn
    if tf_prob_unsafe is not None:
        prob_unsafe = (prob_unsafe_sklearn + tf_prob_unsafe) / 2.0

    nlp_confidence = round(float(max(proba)) * 100, 2)
    risk_score = prob_unsafe * 100.0

    tokens = set(cleaned.split())
    strong_keywords = set()
    weak_keywords = set()

    for kw in SUSPICIOUS_KEYWORDS_EN_STRONG | SUSPICIOUS_KEYWORDS_AR_STRONG:
        if (kw or "").lower() in tokens:
            strong_keywords.add(kw)

    for kw in SUSPICIOUS_KEYWORDS_EN_WEAK | SUSPICIOUS_KEYWORDS_AR_WEAK:
        if (kw or "").lower() in tokens:
            weak_keywords.add(kw)

    found_keywords = strong_keywords | weak_keywords

    benign_hits = 0
    benign_set = BENIGN_HINTS_AR if is_probably_arabic(text) else BENIGN_HINTS_EN
    for kw in benign_set:
        if (kw or "").lower() in tokens:
            benign_hits += 1

    reasons = []
    detected = "ar" if is_probably_arabic(text) else "en"
    if lang == "ar":
        reasons.append(f"اللغة المكتشفة: {'العربية' if detected == 'ar' else 'الإنجليزية'}")
        if tf_prob_unsafe is None:
            reasons.append(f"احتمال الخطر (NLP): {round(prob_unsafe * 100, 2)}%")
        else:
            reasons.append(
                f"احتمال الخطر (NLP): {round(prob_unsafe * 100, 2)}% (سكيلرن: {round(prob_unsafe_sklearn * 100, 2)}% / TensorFlow: {round(tf_prob_unsafe * 100, 2)}%)"
            )
    else:
        reasons.append(f"Detected language: {'Arabic' if detected == 'ar' else 'English'}")
        if tf_prob_unsafe is None:
            reasons.append(f"NLP risk probability: {round(prob_unsafe * 100, 2)}%")
        else:
            reasons.append(
                f"NLP risk probability: {round(prob_unsafe * 100, 2)}% (scikit-learn: {round(prob_unsafe_sklearn * 100, 2)}% / TensorFlow: {round(tf_prob_unsafe * 100, 2)}%)"
            )

    if urls:
        reasons.append(
            (f"تم العثور على {len(urls)} رابط/روابط في النص." if lang == "ar" else f"Found {len(urls)} URL(s) in the text.")
        )
        # URLs are checked separately; keep text risk based mainly on the text itself.

    if found_keywords:
        keywords_sorted = ", ".join(sorted(found_keywords))
        reasons.append(
            (f"كلمات/عبارات مشبوهة: {keywords_sorted}" if lang == "ar" else f"Suspicious keywords: {keywords_sorted}")
        )

        boost = 0.0
        boost += 12.0 * float(len(strong_keywords))
        if len(weak_keywords) >= 2:
            boost += 6.0 * float(len(weak_keywords))
        elif len(weak_keywords) == 1 and strong_keywords:
            boost += 4.0

        risk_score += min(35.0, boost)

    # If we see clear benign intent (and no URLs / suspicious keywords), lower the risk a bit.
    if benign_hits >= 2 and (not urls) and (not found_keywords):
        reasons.append(
            ("يبدو النص عاديًا (شكر/تأكيد/تواصل) ولا يحتوي على روابط." if lang == "ar" else "Text looks benign (thanks/confirmation/contact) and contains no links.")
        )
        risk_score -= 18.0

    # Very short text with no signals should not be rated risky.
    if len(tokens) <= 3 and (not urls) and (not found_keywords):
        risk_score -= 10.0

    # Model explainability (top risk terms) for caution/unsafe results.
    top_terms = []
    try:
        coef = model.coef_[0]
        names = vectorizer.get_feature_names_out()
        row = X.tocsr()
        idxs = row.indices
        data = row.data
        contribs = [(names[i], float(data[j] * coef[i])) for j, i in enumerate(idxs)]
        contribs = [t for t in contribs if t[1] > 0]
        contribs.sort(key=lambda x: x[1], reverse=True)
        top_terms = [t[0] for t in contribs[:5]]
    except Exception:
        top_terms = []

    risk_score = _clamp(risk_score, 0.0, 100.0)
    result_class = _risk_class(risk_score)

    if top_terms and result_class in ("caution", "unsafe"):
        reasons.append(
            (f"أبرز إشارات NLP: {', '.join(top_terms)}" if lang == "ar" else f"Top NLP risk terms: {', '.join(top_terms)}")
        )

    if result_class == "unsafe":
        message = ui["ml_unsafe_msg"]
        icon = "⚠️"
    elif result_class == "caution":
        message = ui.get("ml_caution_msg", ui["ml_unsafe_msg"])
        icon = "⚠️"
    else:
        message = ui["ml_safe_msg"]
        icon = "✅"

    return {
        "result_class": result_class,
        "label": ui.get(result_class, result_class),
        "confidence": nlp_confidence,
        "risk_score": round(risk_score, 2),
        "icon": icon,
        "message": message,
        "reasons": reasons,
    }


def _history_summary_message(
    lang: str,
    ui: dict,
    text_result_class: str,
    urls_total: int,
    urls_unsafe: int,
    urls_caution: int = 0,
):
    text_part = ""
    if text_result_class in ("safe", "caution", "unsafe"):
        text_part = f"{ui['text']}: {ui[text_result_class]}"

    if urls_total:
        if lang == "ar":
            extra = ""
            if urls_caution:
                extra = f" • {ui['caution']}: {urls_caution}"
            urls_part = f"{ui['urls']}: {urls_total} ({ui['unsafe']}: {urls_unsafe}{extra})"
        else:
            extra = f", {urls_caution} suspicious" if urls_caution else ""
            urls_part = f"{ui['urls']}: {urls_total} checked ({urls_unsafe} unsafe{extra})"
    else:
        urls_part = ui["urls_none"]

    if text_part:
        return f"{text_part} • {urls_part}"
    return urls_part


def _build_history_view(history_items, lang: str, ui: dict):
    view = []
    for item in history_items or []:
        result_class = item.get("result_class")
        if result_class not in ("safe", "caution", "unsafe"):
            continue

        kind = item.get("kind", "text")
        message_type = item.get("message_type", "ml")
        message_key = item.get("message_key", "")

        if message_type == "url":
            msg = _translate_url_message(message_key, lang)
        elif message_type == "summary":
            msg = _history_summary_message(
                lang,
                ui,
                item.get("text_result_class", ""),
                int(item.get("urls_total", 0) or 0),
                int(item.get("urls_unsafe", 0) or 0),
                int(item.get("urls_caution", 0) or 0),
            )
        else:
            if result_class == "safe":
                msg = ui["ml_safe_msg"]
            elif result_class == "caution":
                msg = ui.get("ml_caution_msg", ui["ml_unsafe_msg"])
            else:
                msg = ui["ml_unsafe_msg"]

        view.append(
            {
                "at": item.get("at", ""),
                "kind": kind if kind in ("url", "text", "email") else "text",
                "input": item.get("input", ""),
                "result_class": result_class,
                "confidence": item.get("confidence"),
                "icon": "✅" if result_class == "safe" else "⚠️",
                "message": msg,
            }
        )
    return view


@app.route("/sw.js", methods=["GET"])
def service_worker():
    """Serve the service worker from the site root so it can control '/' (PWA install criteria)."""
    resp = make_response(
        send_from_directory(app.static_folder, "sw.js", mimetype="application/javascript")
    )
    # Ensure the browser checks for updated SW on each visit/deploy.
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    # Allow root scope even if a host rewrites SW URLs.
    resp.headers["Service-Worker-Allowed"] = "/"
    return resp


@app.route("/download", methods=["GET"])
def download_page():
    lang = (request.args.get("lang") or "en").lower()
    if lang not in TRANSLATIONS:
        lang = "en"
    ui = TRANSLATIONS[lang]

    apk_path = os.path.join(DOWNLOADS_DIR, APK_FILENAME)
    apk_available = os.path.isfile(apk_path)

    return render_template(
        "download.html",
        ui=ui,
        lang=lang,
        direction="rtl" if lang == "ar" else "ltr",
        toggle_lang="en" if lang == "ar" else "ar",
        apk_available=apk_available,
    )


@app.route("/download/android", methods=["GET"])
def download_android():
    lang = (request.args.get("lang") or "en").lower()
    if lang not in TRANSLATIONS:
        lang = "en"

    apk_path = os.path.join(DOWNLOADS_DIR, APK_FILENAME)
    if not os.path.isfile(apk_path):
        return redirect(url_for("download_page", lang=lang))

    return send_from_directory(
        DOWNLOADS_DIR,
        APK_FILENAME,
        as_attachment=True,
        mimetype="application/vnd.android.package-archive",
    )


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    result_class = None
    confidence = None
    icon = None
    message = ""
    user_input = ""
    text_details = None
    url_details = []

    lang = (request.values.get("lang") or "en").lower()
    if lang not in TRANSLATIONS:
        lang = "en"
    ui = TRANSLATIONS[lang]

    if request.method == "POST" and request.form.get("action") == "clear_history":
        session.pop("history", None)
        return redirect(url_for("home", lang=lang))

    history = session.get("history", [])
    if not isinstance(history, list):
        history = []

    if request.method == "POST" and request.form.get("action") == "scan":
        raw_input = request.form.get("text", "").strip()
        analysis_input = raw_input[:MAX_ANALYSIS_CHARS]
        user_input = analysis_input

        history_input = analysis_input[:MAX_HISTORY_SNIPPET_CHARS]
        urls = _extract_urls(analysis_input)
        is_url_only = _looks_like_single_url(analysis_input) and not re.search(r"\s", analysis_input)

        if is_url_only:
            candidate = _strip_url_punctuation(analysis_input)
            _, report = check_url(candidate)
            url_risk_raw = report.get("risk", 100.0)
            url_risk = float(100.0 if url_risk_raw is None else url_risk_raw)
            msg_key = report.get("message_key", "")

            result_class = _risk_class(url_risk)
            result = ui.get(result_class, result_class)
            icon = "✅" if result_class == "safe" else "⚠️"
            confidence = round(url_risk, 2)
            message = _translate_url_message(msg_key, lang)
            url_reasons = [_url_reason_text(r, lang) for r in (report.get("reasons") or [])]

            url_details = [
                {
                    "url": candidate,
                    "result_class": result_class,
                    "label": ui.get(result_class, result_class),
                    "icon": icon,
                    "confidence": confidence,
                    "message": message,
                    "reasons": url_reasons,
                }
            ]

            if history_input and result_class:
                history.append(
                    {
                        "at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "kind": "url",
                        "input": history_input,
                        "result_class": result_class,
                        "confidence": confidence,
                        "message_type": "url",
                        "message_key": msg_key,
                    }
                )

        else:
            text_details = _analyze_text(analysis_input, urls, ui, lang)

            urls_unsafe = 0
            urls_caution = 0
            url_details = []
            url_risks = []
            for candidate in urls:
                _, report = check_url(candidate)
                url_risk_raw = report.get("risk", 100.0)
                url_risk = float(100.0 if url_risk_raw is None else url_risk_raw)
                url_risks.append(url_risk)
                msg_key = report.get("message_key", "")

                url_result_class = _risk_class(url_risk)
                if url_result_class == "unsafe":
                    urls_unsafe += 1
                elif url_result_class == "caution":
                    urls_caution += 1

                url_details.append(
                    {
                        "url": candidate,
                        "result_class": url_result_class,
                        "label": ui.get(url_result_class, url_result_class),
                        "icon": "✅" if url_result_class == "safe" else "⚠️",
                        "confidence": round(url_risk, 2),
                        "message": _translate_url_message(msg_key, lang),
                        "reasons": [_url_reason_text(r, lang) for r in (report.get("reasons") or [])],
                    }
                )

            urls_total = len(url_details)
            overall_risk = float(text_details.get("risk_score", 0.0) or 0.0)
            if url_risks:
                overall_risk = max(overall_risk, max(url_risks))

            result_class = _risk_class(overall_risk)
            result = ui.get(result_class, result_class)
            icon = "✅" if result_class == "safe" else "⚠️"
            confidence = round(overall_risk, 2)

            if urls_total > 0:
                message = _history_summary_message(
                    lang, ui, text_details["result_class"], urls_total, urls_unsafe, urls_caution
                )
            else:
                message = text_details["message"]

            kind = "email" if ("\n" in analysis_input or urls_total > 0) else "text"
            message_type = "summary" if urls_total > 0 else "ml"

            if history_input and result_class:
                item = {
                    "at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "kind": kind,
                    "input": history_input,
                    "result_class": result_class,
                    "confidence": confidence,
                    "message_type": message_type,
                    "message_key": "",
                }
                if message_type == "summary":
                    item["text_result_class"] = text_details["result_class"]
                    item["urls_total"] = urls_total
                    item["urls_unsafe"] = urls_unsafe
                    item["urls_caution"] = urls_caution

                history.append(item)

        if isinstance(history, list):
            session["history"] = history[-MAX_HISTORY:]
            session.modified = True

    return render_template(
        "index.html",
        ui=ui,
        result=result,
        result_class=result_class,
        confidence=confidence,
        icon=icon,
        message=message,
        user_input=user_input,
        text_details=text_details,
        url_details=url_details,
        history=_build_history_view(session.get("history", []), lang, ui),
        lang=lang,
        direction="rtl" if lang == "ar" else "ltr",
        toggle_lang="en" if lang == "ar" else "ar",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
