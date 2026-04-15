import sys
import os

# Adds the root directory to the python path so it can find 'src'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
from src.analyzer import analyze_email
from src.reporter import generate_report

st.title("🛡️ Phish-Guard Dashboard")
st.subheader("Cybersecurity & Email Analysis System [cite: 201]")

# Input Section [cite: 228]
email_input = st.text_input("Enter Sender Email Address to Analyze:")

if st.button("Run Security Audit"):
    if email_input:
        # Step 1: Analyze (The Decision Layer) [cite: 231]
        analysis = analyze_email(email_input)
        
        # Step 2: Report (The Explainability Layer) [cite: 235]
        final_report = generate_report(analysis)
        
        # Step 3: Display Risk Scorecard [cite: 208, 242]
        if analysis["risk_score"] > 0:
            st.error(final_report)
        else:
            st.success(final_report)
    else:
        st.warning("Please enter an email address first.")