"""
PhishGuard — SPF/DKIM Validation Module
Queries DNS TXT records to validate SPF and checks DKIM presence.
"""

import dns.resolver


# Known legitimate domains for baseline comparison
KNOWN_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
    "netflix.com", "dropbox.com", "github.com", "yahoo.com"
]


def check_spf(domain):
    """
    Query DNS for SPF record of the given domain.

    Args:
        domain (str): The sender's domain to validate.

    Returns:
        dict: SPF validation result with pass/fail status and details.
    """
    result = {
        "domain": domain,
        "spf_record": None,
        "spf_exists": False,
        "spf_pass": False,
        "details": ""
    }

    if not domain:
        result["details"] = "No domain provided"
        return result

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata)
            if txt_record.startswith('"v=spf1') or 'v=spf1' in txt_record:
                result["spf_record"] = txt_record
                result["spf_exists"] = True
                result["spf_pass"] = True
                result["details"] = f"SPF record found: {txt_record}"
                break

        if not result["spf_exists"]:
            result["details"] = "No SPF record found — potential spoofing risk"

    except dns.resolver.NXDOMAIN:
        result["details"] = f"Domain '{domain}' does not exist (NXDOMAIN)"
    except dns.resolver.NoAnswer:
        result["details"] = f"No TXT records found for '{domain}'"
    except dns.resolver.Timeout:
        result["details"] = f"DNS query timed out for '{domain}'"
    except Exception as e:
        result["details"] = f"DNS query error: {str(e)}"

    return result


def check_dkim(dkim_signature, from_domain):
    """
    Validate DKIM signature presence and domain alignment.

    Args:
        dkim_signature (str): The DKIM-Signature header value.
        from_domain (str): The sender's domain.

    Returns:
        dict: DKIM validation result.
    """
    result = {
        "dkim_present": bool(dkim_signature),
        "dkim_domain_match": False,
        "details": ""
    }

    if not dkim_signature:
        result["details"] = "No DKIM signature found — email authenticity unverified"
        return result

    # Extract domain from DKIM signature (d= tag)
    dkim_domain = ""
    for part in dkim_signature.split(';'):
        part = part.strip()
        if part.startswith('d='):
            dkim_domain = part[2:].strip()
            break

    result["dkim_domain_match"] = (dkim_domain == from_domain)
    if result["dkim_domain_match"]:
        result["details"] = f"DKIM domain ({dkim_domain}) matches sender domain"
    else:
        result["details"] = f"DKIM domain ({dkim_domain}) does NOT match sender ({from_domain})"

    return result
