"""
PhishGuard — Unicode Confusable Character Detection Module
Detects visually deceptive Unicode characters used in phishing attacks.
"""

import unicodedata


# Common confusable character mappings (Cyrillic → Latin lookalikes)
CONFUSABLES = {
    '\u0430': 'a',  # Cyrillic а → Latin a
    '\u0435': 'e',  # Cyrillic е → Latin e
    '\u043e': 'o',  # Cyrillic о → Latin o
    '\u0440': 'p',  # Cyrillic р → Latin p
    '\u0441': 'c',  # Cyrillic с → Latin c
    '\u0443': 'y',  # Cyrillic у → Latin y
    '\u0445': 'x',  # Cyrillic х → Latin x
    '\u0456': 'i',  # Ukrainian і → Latin i
    '\u0461': 'ω',  # Cyrillic ѡ
    '\u04bb': 'h',  # Cyrillic һ → Latin h
    '\u0501': 'd',  # Cyrillic ԁ → Latin d
    '\u051b': 'q',  # Cyrillic ԛ → Latin q
    '\u0222': '3',  # Latin Ȣ
    '\u0261': 'g',  # Latin Script Small G
    '\u01c3': '!',  # Latin Letter Retroflex Click
    '\u2024': '.',  # One Dot Leader
    '\uff0e': '.',  # Fullwidth Full Stop
    '\u2010': '-',  # Hyphen
    '\u2011': '-',  # Non-Breaking Hyphen
    '\uff0d': '-',  # Fullwidth Hyphen-Minus
}


def detect_unicode_confusables(text):
    """
    Scan text for Unicode confusable characters that may be used
    for visual deception in phishing emails.

    Args:
        text (str): The email body or header text to scan.

    Returns:
        dict: Detection results with flagged characters and positions.
    """
    if not text:
        return {"flagged": False, "confusables_found": [], "details": "No text to analyze"}

    found = []
    for i, char in enumerate(text):
        if char in CONFUSABLES:
            char_name = unicodedata.name(char, "UNKNOWN")
            found.append({
                "character": char,
                "unicode_codepoint": f"U+{ord(char):04X}",
                "looks_like": CONFUSABLES[char],
                "unicode_name": char_name,
                "position": i,
                "context": text[max(0, i-10):i+10]
            })

    # Also check for mixed-script text (e.g., Latin + Cyrillic)
    scripts = set()
    for char in text:
        if char.isalpha():
            script = get_script(char)
            if script:
                scripts.add(script)

    mixed_script = len(scripts) > 1

    return {
        "flagged": len(found) > 0 or mixed_script,
        "confusables_found": found,
        "total_confusables": len(found),
        "mixed_script_detected": mixed_script,
        "scripts_found": list(scripts),
        "details": _build_details(found, mixed_script)
    }


def get_script(char):
    """
    Determine the Unicode script of a character.

    Args:
        char (str): A single character.

    Returns:
        str: The script name (e.g., 'LATIN', 'CYRILLIC').
    """
    try:
        name = unicodedata.name(char, '')
        if 'LATIN' in name:
            return 'LATIN'
        elif 'CYRILLIC' in name:
            return 'CYRILLIC'
        elif 'GREEK' in name:
            return 'GREEK'
        elif 'ARABIC' in name:
            return 'ARABIC'
        elif 'CJK' in name:
            return 'CJK'
        else:
            return 'OTHER'
    except ValueError:
        return None


def _build_details(found, mixed_script):
    """Build human-readable details string."""
    parts = []
    if found:
        parts.append(f"⚠️ Found {len(found)} confusable character(s):")
        for item in found[:5]:  # Show first 5
            parts.append(
                f"  • '{item['character']}' ({item['unicode_codepoint']}) "
                f"looks like '{item['looks_like']}' — {item['unicode_name']}"
            )
        if len(found) > 5:
            parts.append(f"  ...and {len(found) - 5} more")

    if mixed_script:
        parts.append("⚠️ Mixed Unicode scripts detected — possible homograph attack")

    if not parts:
        parts.append("✅ No confusable characters detected")

    return "\n".join(parts)
