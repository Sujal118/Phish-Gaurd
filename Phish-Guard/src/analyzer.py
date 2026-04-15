from rapidfuzz import fuzz
import tldextract

def analyze_email(sender_email, trusted_domains=["google.com", "paypal.com", "amazon.com"]):
    """
    Core Risk Engine: Validates technical and visual patterns[cite: 232, 234].
    """
    ext = tldextract.extract(sender_email)
    domain = f"{ext.domain}.{ext.suffix}"
    results = {"risk_score": 0, "findings": []}

    for trusted in trusted_domains:
        similarity = fuzz.ratio(domain, trusted)
        
        # Detect Look-alike Domains [cite: 206]
        if 80 <= similarity < 100:
            results["risk_score"] += 40
            results["findings"].append(f"Visual Deception: '{domain}' is {round(similarity)}% similar to '{trusted}'.")

    # Detect Unicode/Homograph Deception [cite: 208]
    if any(ord(char) > 127 for char in domain):
        results["risk_score"] += 50
        results["findings"].append("Unicode Deception: Domain contains non-standard characters used to mimic trusted sites.")

    return results