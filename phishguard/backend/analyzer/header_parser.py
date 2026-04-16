"""
PhishGuard — Email Header Extraction Module
Parses .eml files and extracts key headers for analysis.
"""

import email
from email import policy
from email.parser import BytesParser


def parse_email_file(filepath):
    """
    Parse an .eml file and extract relevant headers and body.

    Args:
        filepath (str): Path to the .eml file.

    Returns:
        dict: Extracted email metadata including headers, body, and derived fields.
    """
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Extract key headers
    from_header = msg.get('From', '')
    to_header = msg.get('To', '')
    reply_to = msg.get('Reply-To', '')
    subject = msg.get('Subject', '')
    date = msg.get('Date', '')
    message_id = msg.get('Message-ID', '')
    received_headers = msg.get_all('Received', [])
    dkim_signature = msg.get('DKIM-Signature', '')
    return_path = msg.get('Return-Path', '')

    # Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                body = part.get_content()
                break
            elif content_type == 'text/html' and not body:
                body = part.get_content()
    else:
        body = msg.get_content()

    # Derive sender domain
    from_domain = ""
    if '@' in from_header:
        from_domain = from_header.split('@')[-1].strip('>')

    # Count hops
    hop_count = len(received_headers)

    # Check From/Reply-To mismatch
    reply_to_mismatch = bool(reply_to and reply_to != from_header)

    return {
        "from": from_header,
        "to": to_header,
        "reply_to": reply_to,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "return_path": return_path,
        "received_headers": received_headers,
        "dkim_signature": dkim_signature,
        "from_domain": from_domain,
        "hop_count": hop_count,
        "reply_to_mismatch": reply_to_mismatch,
        "body": body
    }
