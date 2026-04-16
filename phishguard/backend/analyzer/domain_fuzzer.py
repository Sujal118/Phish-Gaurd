"""
PhishGuard — Domain Fuzzing / Similarity Detection Module
Uses Levenshtein distance to detect typosquatting and domain spoofing.
"""

from Levenshtein import distance, ratio


# Known legitimate domains to compare against
LEGIT_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com",
    "apple.com", "icloud.com", "amazon.com", "paypal.com",
    "facebook.com", "meta.com", "twitter.com", "x.com",
    "linkedin.com", "netflix.com", "dropbox.com", "github.com",
    "yahoo.com", "instagram.com", "whatsapp.com", "telegram.org",
    "chase.com", "wellsfargo.com", "bankofamerica.com",
    "americanexpress.com", "citibank.com"
]

# Common homoglyph substitutions used in phishing
HOMOGLYPH_MAP = {
    'o': '0', '0': 'o',
    'l': '1', '1': 'l',
    'i': 'l', 'rn': 'm',
    'vv': 'w', 'cl': 'd'
}


def fuzz_domain(sender_domain, threshold=0.85):
    """
    Compare sender domain against known legitimate domains
    using Levenshtein similarity ratio.

    Args:
        sender_domain (str): The domain extracted from the email sender.
        threshold (float): Similarity threshold (0-1). Domains above this
                          are flagged as potential typosquats.

    Returns:
        dict: Fuzzing results with similarity scores and flags.
    """
    if not sender_domain:
        return {"flagged": False, "details": "No domain to analyze"}

    sender_domain = sender_domain.lower().strip()
    results = {
        "sender_domain": sender_domain,
        "flagged": False,
        "matches": [],
        "highest_similarity": 0.0,
        "closest_legit_domain": "",
        "details": ""
    }

    for legit in LEGIT_DOMAINS:
        similarity = ratio(sender_domain, legit)
        if similarity > threshold and sender_domain != legit:
            results["matches"].append({
                "legit_domain": legit,
                "similarity": round(similarity * 100, 2),
                "edit_distance": distance(sender_domain, legit)
            })

        if similarity > results["highest_similarity"]:
            results["highest_similarity"] = round(similarity * 100, 2)
            results["closest_legit_domain"] = legit

    if results["matches"]:
        results["flagged"] = True
        top = results["matches"][0]
        results["details"] = (
            f"⚠️ Domain '{sender_domain}' is {top['similarity']}% similar to "
            f"'{top['legit_domain']}' — possible typosquatting!"
        )
    elif sender_domain in LEGIT_DOMAINS:
        results["details"] = f"✅ Domain '{sender_domain}' is a known legitimate domain"
    else:
        results["details"] = f"Domain '{sender_domain}' did not match any known domains closely"

    return results


def detect_homoglyphs(domain):
    """
    Check if a domain contains common homoglyph substitutions.

    Args:
        domain (str): Domain string to check.

    Returns:
        list: List of detected homoglyph patterns.
    """
    detected = []
    for pattern, replacement in HOMOGLYPH_MAP.items():
        if pattern in domain:
            detected.append({
                "pattern": pattern,
                "could_be": replacement,
                "position": domain.index(pattern)
            })
    return detected
