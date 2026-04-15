def generate_report(analysis_results):
    """
    Converts technical flags into human-readable insights[cite: 237, 243].
    """
    if not analysis_results["findings"]:
        return "Overall Verdict: Safe. No significant phishing patterns detected."
    
    report = f"Overall Verdict: SUSPICIOUS (Risk Score: {analysis_results['risk_score']})\n"
    report += "\nReasoning for Flagging:\n"
    for finding in analysis_results["findings"]:
        report += f"- {finding}\n"
    
    report += "\nActionable Insight: Do not click links or provide credentials to this sender."
    return report