
import re
import math
from typing import Dict, List, Tuple, Any
import tldextract
import pandas as pd

SUSPICIOUS_MSG_TERMS = {
    "urgent","immediately","verify","reset","limited","locked","suspend","suspended",
    "click","now","win","winner","gift","free","claim","refund","otp","password",
    "account","bank","wallet","crypto","payment","prize","congratulations"
}

SUSPICIOUS_URL_TERMS = {
    "login","verify","update","secure","signin","reset","support","account",
    "pay","bank","wallet","crypto","gift","free","win","prize","invoice","password",
    "unlock","limited","urgent","confirm","security","payment"
}

RARE_TLDS = {"zip","cam","gq","tk","ml","cf","work","quest","xin","men","party","click","country","science","top","biz"}

LOOKALIKE_MAP = {"0":"o","1":"l","3":"e","5":"s","7":"t","8":"b","l":"i","I":"l","|":"l","@":"a","$":"s"}

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    total = len(s)
    import math
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def has_lookalikes(s: str) -> bool:
    return any(ch in LOOKALIKE_MAP for ch in s)

def has_unicode(s: str) -> bool:
    try:
        s.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True

def analyze_message(msg: str) -> Dict[str, Any]:
    msg = (msg or "").strip()
    lower = msg.lower()

    score = 0
    reasons: List[str] = []

    def add(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(reason)

    # Urgency/pressure
    if any(w in lower for w in ["urgent","immediately","now","asap","minutes","24 hours"]):
        add(12, "Uses urgent/pressure language")

    # Sensitive terms
    triggers = [t for t in SUSPICIOUS_MSG_TERMS if t in lower]
    if triggers:
        add(min(20, 4 * len(triggers)), f"Contains sensitive terms: {', '.join(sorted(triggers))}")

    # All caps streaks
    if re.search(r"[A-Z]{6,}", msg):
        add(6, "Contains ALL-CAPS words")

    # Emoji spam or odd spacing
    if len(re.findall(r"[^\w\s.,:/@-]", msg)) >= 5:
        add(4, "Contains many special characters/emojis")

    # Suspicious short links
    if re.search(r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly)\b", lower):
        add(6, "Contains URL shortener")

    # Phone/OTP pattern prompts
    if "otp" in lower and re.search(r"\b\d{4,8}\b", lower):
        add(4, "Mentions OTP with code in the message")

    # Final label
    label = "Safe"
    if score >= 60:
        label = "Malicious"
    elif score >= 30:
        label = "Suspicious"

    return {
        "type": "message",
        "score": int(min(score, 100)),
        "label": label,
        "reasons": reasons
    }

def analyze_url(url: str) -> Dict[str, Any]:
    u = (url or "").strip()
    lower = u.lower()
    ext = tldextract.extract(u)
    host = ".".join([p for p in [ext.subdomain, ext.domain, ext.suffix] if p])
    domain = ext.domain or ""
    suffix = ext.suffix or ""
    subdomain = ext.subdomain or ""

    score = 0
    reasons: List[str] = []

    def add(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(reason)

    # Protocol
    if not lower.startswith("https://"):
        add(8, "Non-HTTPS protocol")

    # IP host
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        add(20, "IP address used as host")

    # Many dots
    if host.count(".") >= 3:
        add(8, f"Many subdomains ({host.count('.')+1} levels)")

    # '@' trick
    if "@" in u:
        add(12, "'@' present in URL (potential visual confusion)")

    # Punycode/Unicode
    if "xn--" in lower or has_unicode(u):
        add(12, "Punycode/Unicode present")

    # Rare TLD
    if suffix in RARE_TLDS:
        add(6, f"Rare TLD ({suffix})")

    # Lookalikes
    if has_lookalikes(host):
        add(10, "Lookalike characters detected")

    # Long URL / params
    if len(u) > 120:
        add(6, f"Long URL ({len(u)})")

    # Params count
    params = 0
    if "?" in u:
        params = len(u.split("?",1)[-1].split("&"))
        if params >= 3:
            add(4, f"Many query parameters ({params})")

    # Suspicious terms
    trig = [t for t in SUSPICIOUS_URL_TERMS if t in lower]
    if trig:
        add(min(12, 3 * len(trig)), f"Suspicious terms in URL: {', '.join(sorted(trig))}")

    # Final label
    label = "Safe"
    if score >= 60:
        label = "Malicious"
    elif score >= 30:
        label = "Suspicious"

    return {
        "type": "url",
        "score": int(min(score, 100)),
        "label": label,
        "reasons": reasons,
        "meta": {
            "host": host, "domain": domain, "suffix": suffix, "subdomain": subdomain, "params": params
        }
    }

def analyze_dataframe(df: pd.DataFrame, text_col: str = None, url_col: str = None) -> pd.DataFrame:
    out_rows = []
    if text_col and text_col in df.columns:
        for v in df[text_col].astype(str).tolist():
            res = analyze_message(v)
            out_rows.append({"input": v, **res})
    if url_col and url_col in df.columns:
        for v in df[url_col].astype(str).tolist():
            res = analyze_url(v)
            out_rows.append({"input": v, **res})
    return pd.DataFrame(out_rows)
