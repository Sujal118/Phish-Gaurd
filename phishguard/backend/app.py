"""
PhishGuard — Flask Backend Main Application
Phishing Email Detection System
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import tempfile
import zipfile

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/')
def index():
    return jsonify({
        "app": "PhishGuard",
        "version": "1.0.0",
        "status": "running",
        "endpoints": ["/upload", "/analyze", "/forge", "/batch", "/report"]
    })


@app.route('/upload', methods=['POST'])
def upload_email():
    """Parse uploaded .eml file."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if not file.filename.endswith('.eml'):
        return jsonify({"error": "Only .eml files are supported"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    from analyzer.header_parser import parse_email_file
    parsed = parse_email_file(filepath)

    return jsonify({"message": "Email uploaded and parsed", "data": parsed})


@app.route('/analyze', methods=['POST'])
def analyze_email():
    """Run all detection modules on an uploaded email."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    from analyzer.header_parser import parse_email_file
    from analyzer.spf_validator import check_spf
    from analyzer.domain_fuzzer import fuzz_domain
    from analyzer.unicode_detector import detect_unicode_confusables
    from analyzer.risk_scorer import calculate_risk_score

    parsed = parse_email_file(filepath)
    spf_result = check_spf(parsed.get("from_domain", ""))
    fuzz_result = fuzz_domain(parsed.get("from_domain", ""))
    unicode_result = detect_unicode_confusables(parsed.get("body", ""))
    risk_score = calculate_risk_score(spf_result, fuzz_result, unicode_result, parsed)

    return jsonify({
        "parsed": parsed,
        "spf": spf_result,
        "domain_fuzz": fuzz_result,
        "unicode": unicode_result,
        "risk_score": risk_score
    })


@app.route('/analyze-text', methods=['POST'])
def analyze_email_text():
    """Run all detection modules on pasted raw email text."""
    data = request.get_json()
    if not data or not data.get('email_text'):
        return jsonify({"error": "No email text provided"}), 400

    email_text = data['email_text']

    # Save pasted text as a temporary .eml file for parsing
    filepath = os.path.join(UPLOAD_FOLDER, 'pasted_email.eml')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(email_text)

    from analyzer.header_parser import parse_email_file
    from analyzer.spf_validator import check_spf
    from analyzer.domain_fuzzer import fuzz_domain
    from analyzer.unicode_detector import detect_unicode_confusables
    from analyzer.risk_scorer import calculate_risk_score

    parsed = parse_email_file(filepath)
    spf_result = check_spf(parsed.get("from_domain", ""))
    fuzz_result = fuzz_domain(parsed.get("from_domain", ""))
    unicode_result = detect_unicode_confusables(parsed.get("body", ""))
    risk_score = calculate_risk_score(spf_result, fuzz_result, unicode_result, parsed)

    return jsonify({
        "parsed": parsed,
        "spf": spf_result,
        "domain_fuzz": fuzz_result,
        "unicode": unicode_result,
        "risk_score": risk_score
    })


@app.route('/forge', methods=['POST'])
def forge_email():
    """Generate a spoofed variant of an uploaded email."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    from forge.email_forger import forge_email_from_file
    forged = forge_email_from_file(filepath)

    return jsonify({"original": filepath, "forged": forged})


@app.route('/batch', methods=['POST'])
def batch_analyze():
    """Handle ZIP upload containing multiple .eml files."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if not file.filename.endswith('.zip'):
        return jsonify({"error": "Only .zip files are supported"}), 400

    zip_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(zip_path)

    from analyzer.header_parser import parse_email_file
    from analyzer.spf_validator import check_spf
    from analyzer.domain_fuzzer import fuzz_domain
    from analyzer.unicode_detector import detect_unicode_confusables
    from analyzer.risk_scorer import calculate_risk_score

    results = []
    with zipfile.ZipFile(zip_path, 'r') as z:
        extract_dir = os.path.join(UPLOAD_FOLDER, 'batch_extract')
        os.makedirs(extract_dir, exist_ok=True)
        z.extractall(extract_dir)

        for name in z.namelist():
            if name.endswith('.eml'):
                eml_path = os.path.join(extract_dir, name)
                try:
                    parsed = parse_email_file(eml_path)
                    spf_result = check_spf(parsed.get("from_domain", ""))
                    fuzz_result = fuzz_domain(parsed.get("from_domain", ""))
                    unicode_result = detect_unicode_confusables(parsed.get("body", ""))
                    risk = calculate_risk_score(spf_result, fuzz_result, unicode_result, parsed)

                    results.append({
                        "file": name,
                        "from": parsed.get("from", ""),
                        "subject": parsed.get("subject", ""),
                        "risk_score": risk.get("total_score", 0),
                        "band": risk.get("band", {}).get("label", "Unknown"),
                        "level": risk.get("band", {}).get("level", "low"),
                        "breakdown": risk.get("breakdown", []),
                        "status": "analyzed"
                    })
                except Exception as e:
                    results.append({
                        "file": name,
                        "risk_score": 0,
                        "status": f"error: {str(e)}"
                    })

    return jsonify({"total": len(results), "results": results})


@app.route('/report', methods=['POST'])
def generate_report():
    """Generate a PDF risk report."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No analysis data provided"}), 400

    from reports.pdf_generator import generate_pdf_report
    pdf_path = generate_pdf_report(data)

    return send_file(pdf_path, as_attachment=True, download_name="phishguard_report.pdf")


if __name__ == '__main__':
    # Disable reloader to prevent infinite restart loops
    # when files are saved to uploads/ during batch analysis
    app.run(debug=True, port=5000, use_reloader=False)
