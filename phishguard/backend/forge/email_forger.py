"""
PhishGuard — Phishing Forge Lab (Email Spoofing Simulator)
Generates spoofed variants of legitimate emails for educational purposes.
Demonstrates common phishing techniques: homoglyphs, header mutation, Unicode tricks.
"""

import email
from email import policy
from email.parser import BytesParser
import copy
import random


# Homoglyph substitution map (Latin → look-alike)
HOMOGLYPH_MAP = {
    'a': 'а',   # Latin a → Cyrillic а (U+0430)
    'e': 'е',   # Latin e → Cyrillic е (U+0435)
    'o': 'о',   # Latin o → Cyrillic о (U+043E)
    'p': 'р',   # Latin p → Cyrillic р (U+0440)
    'c': 'с',   # Latin c → Cyrillic с (U+0441)
    'x': 'х',   # Latin x → Cyrillic х (U+0445)
    'i': 'і',   # Latin i → Ukrainian і (U+0456)
}

# Typosquatting domain mutations
DOMAIN_MUTATIONS = {
    'microsoft.com': ['rn1crosoft.com', 'microsft.com', 'micr0soft.com'],
    'google.com': ['g00gle.com', 'gooogle.com', 'googIe.com'],
    'paypal.com': ['paypa1.com', 'paypaI.com', 'pаypal.com'],
    'apple.com': ['app1e.com', 'аpple.com', 'appIe.com'],
    'amazon.com': ['amaz0n.com', 'аmazon.com', 'amazom.com'],
}


def forge_email_from_file(filepath):
    """
    Read a legitimate .eml file and generate a spoofed version.

    Args:
        filepath (str): Path to the original .eml file.

    Returns:
        dict: Contains original and forged email data with a diff of changes.
    """
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    original_data = _extract_email_data(msg)
    forged_data = _apply_spoofing(original_data)
    diff = _generate_diff(original_data, forged_data)

    return {
        "original": original_data,
        "forged": forged_data,
        "diff": diff,
        "techniques_used": forged_data.get("techniques", [])
    }


def _extract_email_data(msg):
    """Extract key data from an email message."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_content()
                break
    else:
        body = msg.get_content()

    return {
        "from": msg.get('From', ''),
        "to": msg.get('To', ''),
        "reply_to": msg.get('Reply-To', ''),
        "subject": msg.get('Subject', ''),
        "body": body,
        "received": msg.get_all('Received', [])
    }


def _apply_spoofing(original):
    """Apply various spoofing techniques to create a forged email."""
    forged = dict(original)
    techniques = []

    # 1. Domain homoglyph swapping in From header
    from_header = forged["from"]
    if '@' in from_header:
        domain = from_header.split('@')[-1].strip('>')
        mutated_domain = _mutate_domain(domain)
        if mutated_domain != domain:
            forged["from"] = from_header.replace(domain, mutated_domain)
            techniques.append({
                "technique": "Domain Homoglyph Swap",
                "original": domain,
                "forged": mutated_domain,
                "description": f"Replaced '{domain}' with look-alike '{mutated_domain}'"
            })

    # 2. Reply-To mismatch injection
    if not forged.get("reply_to"):
        forged["reply_to"] = "legit-support@scam-domain.com"
        techniques.append({
            "technique": "Reply-To Mismatch",
            "original": "(none)",
            "forged": forged["reply_to"],
            "description": "Added mismatched Reply-To header to redirect responses"
        })

    # 3. Unicode confusables in body
    if forged.get("body"):
        forged["body"], unicode_changes = _inject_unicode_confusables(forged["body"])
        if unicode_changes:
            techniques.append({
                "technique": "Unicode Confusable Injection",
                "changes": unicode_changes,
                "description": "Replaced Latin characters with visually identical Cyrillic ones"
            })

    # 4. Subject line urgency injection
    urgency_prefixes = ["URGENT: ", "ACTION REQUIRED: ", "⚠️ SECURITY ALERT: "]
    prefix = random.choice(urgency_prefixes)
    forged["subject"] = prefix + forged["subject"]
    techniques.append({
        "technique": "Urgency Injection",
        "original": original["subject"],
        "forged": forged["subject"],
        "description": "Added urgency prefix to create false sense of alarm"
    })

    forged["techniques"] = techniques
    return forged


def _mutate_domain(domain):
    """
    Mutate a domain name using homoglyph substitution.
    """
    # Check if we have a predefined mutation
    if domain.lower() in DOMAIN_MUTATIONS:
        return random.choice(DOMAIN_MUTATIONS[domain.lower()])

    # Otherwise, apply random homoglyph substitution
    mutated = list(domain)
    changed = False
    for i, char in enumerate(mutated):
        if char.lower() in HOMOGLYPH_MAP and random.random() > 0.5:
            mutated[i] = HOMOGLYPH_MAP[char.lower()]
            changed = True
            break  # Only swap one character for subtlety

    return ''.join(mutated) if changed else domain


def _inject_unicode_confusables(text, max_replacements=3):
    """
    Replace a few Latin characters with Cyrillic look-alikes.
    """
    changes = []
    count = 0
    result = list(text)

    for i, char in enumerate(result):
        if count >= max_replacements:
            break
        if char in HOMOGLYPH_MAP and random.random() > 0.6:
            original_char = char
            result[i] = HOMOGLYPH_MAP[char]
            changes.append({
                "position": i,
                "original": f"'{original_char}' (U+{ord(original_char):04X})",
                "replaced_with": f"'{result[i]}' (U+{ord(result[i]):04X})"
            })
            count += 1

    return ''.join(result), changes


def _generate_diff(original, forged):
    """Generate a human-readable diff between original and forged emails."""
    diff = []

    for key in ["from", "reply_to", "subject"]:
        if original.get(key) != forged.get(key):
            diff.append({
                "field": key,
                "original": original.get(key, ""),
                "forged": forged.get(key, ""),
                "changed": True
            })
        else:
            diff.append({
                "field": key,
                "original": original.get(key, ""),
                "forged": forged.get(key, ""),
                "changed": False
            })

    return diff
