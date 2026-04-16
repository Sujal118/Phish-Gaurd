"""
PhishGuard — Weighted Risk Scoring Engine
Combines all detection signals into a 0-100 risk score.

Scoring Formula:
    Risk Score (0–100) =
        (SPF Fail × 40)            ← Most reliable signal
      + (Domain Fuzz > 85% × 30)   ← Typosquatting
      + (Unicode Confusable × 20)  ← Visual deception
      + (Hop Anomaly × 10)         ← Header manipulation

Score Bands:
    0–30   → ✅ Low Risk (Green)
    31–60  → ⚠️ Medium Risk (Yellow)
    61–100 → 🔴 High Risk (Red / Phishing)
"""


# Scoring weights
WEIGHTS = {
    "spf_fail": 35,
    "domain_fuzz": 25,
    "unicode_confusable": 20,
    "hop_anomaly": 10,
    "reply_to_mismatch": 10
}

# Thresholds
NORMAL_HOP_COUNT_RANGE = (2, 8)  # Typical hop count for legitimate emails


def calculate_risk_score(spf_result, fuzz_result, unicode_result, parsed_email):
    """
    Calculate a weighted risk score from all detection module outputs.

    Args:
        spf_result (dict): Output from spf_validator.check_spf()
        fuzz_result (dict): Output from domain_fuzzer.fuzz_domain()
        unicode_result (dict): Output from unicode_detector.detect_unicode_confusables()
        parsed_email (dict): Output from header_parser.parse_email_file()

    Returns:
        dict: Risk score breakdown with total score, band, and per-signal details.
    """
    score = 0
    breakdown = []

    # 1. SPF Check (40 points)
    spf_score = 0
    if not spf_result.get("spf_pass", False):
        spf_score = WEIGHTS["spf_fail"]
        breakdown.append({
            "signal": "SPF Validation Failed",
            "points": spf_score,
            "weight": WEIGHTS["spf_fail"],
            "details": spf_result.get("details", ""),
            "severity": "high"
        })
    else:
        breakdown.append({
            "signal": "SPF Validation Passed",
            "points": 0,
            "weight": WEIGHTS["spf_fail"],
            "details": spf_result.get("details", ""),
            "severity": "none"
        })
    score += spf_score

    # 2. Domain Fuzzing (30 points)
    fuzz_score = 0
    if fuzz_result.get("flagged", False):
        fuzz_score = WEIGHTS["domain_fuzz"]
        breakdown.append({
            "signal": "Domain Typosquatting Detected",
            "points": fuzz_score,
            "weight": WEIGHTS["domain_fuzz"],
            "details": fuzz_result.get("details", ""),
            "severity": "high"
        })
    else:
        breakdown.append({
            "signal": "Domain Appears Legitimate",
            "points": 0,
            "weight": WEIGHTS["domain_fuzz"],
            "details": fuzz_result.get("details", ""),
            "severity": "none"
        })
    score += fuzz_score

    # 3. Unicode Confusables (20 points)
    unicode_score = 0
    if unicode_result.get("flagged", False):
        unicode_score = WEIGHTS["unicode_confusable"]
        breakdown.append({
            "signal": "Unicode Confusables Detected",
            "points": unicode_score,
            "weight": WEIGHTS["unicode_confusable"],
            "details": unicode_result.get("details", ""),
            "severity": "medium"
        })
    else:
        breakdown.append({
            "signal": "No Unicode Deception Found",
            "points": 0,
            "weight": WEIGHTS["unicode_confusable"],
            "details": unicode_result.get("details", ""),
            "severity": "none"
        })
    score += unicode_score

    # 4. Hop Count Anomaly (10 points)
    hop_score = 0
    hop_count = parsed_email.get("hop_count", 0)
    if hop_count < NORMAL_HOP_COUNT_RANGE[0] or hop_count > NORMAL_HOP_COUNT_RANGE[1]:
        hop_score = WEIGHTS["hop_anomaly"]
        breakdown.append({
            "signal": "Hop Count Anomaly",
            "points": hop_score,
            "weight": WEIGHTS["hop_anomaly"],
            "details": f"Hop count: {hop_count} (normal range: {NORMAL_HOP_COUNT_RANGE[0]}-{NORMAL_HOP_COUNT_RANGE[1]})",
            "severity": "low"
        })
    else:
        breakdown.append({
            "signal": "Hop Count Normal",
            "points": 0,
            "weight": WEIGHTS["hop_anomaly"],
            "details": f"Hop count: {hop_count}",
            "severity": "none"
        })
    score += hop_score

    # 5. Reply-To Mismatch (10 points)
    reply_to_score = 0
    if parsed_email.get("reply_to_mismatch", False):
        reply_to_score = WEIGHTS["reply_to_mismatch"]
        breakdown.append({
            "signal": "Reply-To Mismatch Detected",
            "points": reply_to_score,
            "weight": WEIGHTS["reply_to_mismatch"],
            "details": "From and Reply-To headers don't match — suspicious",
            "severity": "medium"
        })
    else:
        breakdown.append({
            "signal": "Reply-To Header Normal",
            "points": 0,
            "weight": WEIGHTS["reply_to_mismatch"],
            "details": "Reply-To address is absent or matches sender",
            "severity": "none"
        })
    score += reply_to_score

    # Determine risk band
    band = get_risk_band(score)

    return {
        "total_score": score,
        "max_score": 100,
        "band": band,
        "breakdown": breakdown,
        "summary": f"Risk Score: {score}/100 — {band['label']}"
    }


def get_risk_band(score):
    """Determine the risk band based on score."""
    if score <= 30:
        return {"label": "✅ Low Risk", "color": "green", "level": "low"}
    elif score <= 60:
        return {"label": "⚠️ Medium Risk", "color": "yellow", "level": "medium"}
    else:
        return {"label": "🔴 High Risk", "color": "red", "level": "high"}
