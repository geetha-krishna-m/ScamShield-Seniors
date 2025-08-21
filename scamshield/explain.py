
def verdict_label(score: int) -> str:
    if score >= 60:
        return "Malicious"
    if score >= 30:
        return "Suspicious"
    return "Safe"

def badge_color(score: int) -> str:
    if score >= 60:
        return "#b91c1c"  # red-700
    if score >= 30:
        return "#f59e0b"  # amber-500
    return "#16a34a"      # green-600

def summarize_reasons(reasons):
    # Keep top 3–5 reasons
    reasons = reasons[:5]
    return reasons
