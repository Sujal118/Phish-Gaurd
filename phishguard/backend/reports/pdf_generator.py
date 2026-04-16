"""
PhishGuard — PDF Risk Report Generator
Generates downloadable PDF reports using ReportLab.
"""

import os
import tempfile
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)


def generate_pdf_report(analysis_data):
    """
    Generate a PDF risk report from analysis results.

    Args:
        analysis_data (dict): The analysis output containing risk score,
                              breakdown, and email metadata.

    Returns:
        str: Path to the generated PDF file.
    """
    # Create temp file for PDF
    pdf_dir = os.path.join(os.path.dirname(__file__), '..', 'generated_reports')
    os.makedirs(pdf_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.join(pdf_dir, f"phishguard_report_{timestamp}.pdf")

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Title'],
        fontSize=24, textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=20
    )
    heading_style = ParagraphStyle(
        'CustomHeading', parent=styles['Heading2'],
        fontSize=14, textColor=colors.HexColor('#16213e'),
        spaceAfter=10, spaceBefore=15
    )
    body_style = styles['BodyText']

    # Title
    elements.append(Paragraph("🛡️ PhishGuard — Risk Analysis Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}",
        body_style
    ))
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=2,
                               color=colors.HexColor('#e94560')))
    elements.append(Spacer(1, 15))

    # Risk Score Summary
    risk_score = analysis_data.get("risk_score", {})
    total = risk_score.get("total_score", 0)
    band = risk_score.get("band", {})

    score_color = {
        "green": colors.HexColor('#27ae60'),
        "yellow": colors.HexColor('#f39c12'),
        "red": colors.HexColor('#e74c3c')
    }.get(band.get("color", "red"), colors.HexColor('#e74c3c'))

    elements.append(Paragraph("Risk Score Summary", heading_style))
    score_data = [
        ["Total Score", f"{total}/100"],
        ["Risk Level", band.get("label", "Unknown")],
    ]
    score_table = Table(score_data, colWidths=[2.5*inch, 4*inch])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 15))

    # Breakdown Table
    breakdown = risk_score.get("breakdown", [])
    if breakdown:
        elements.append(Paragraph("Signal Breakdown", heading_style))
        table_data = [["Signal", "Points", "Weight", "Severity"]]
        for item in breakdown:
            table_data.append([
                item.get("signal", ""),
                str(item.get("points", 0)),
                str(item.get("weight", 0)),
                item.get("severity", "").upper()
            ])

        breakdown_table = Table(table_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.5*inch])
        breakdown_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
        ]))
        elements.append(breakdown_table)
        elements.append(Spacer(1, 15))

    # Email Metadata
    parsed = analysis_data.get("parsed", {})
    if parsed:
        elements.append(Paragraph("Email Metadata", heading_style))
        meta_data = [
            ["From", parsed.get("from", "N/A")],
            ["To", parsed.get("to", "N/A")],
            ["Subject", parsed.get("subject", "N/A")],
            ["Date", parsed.get("date", "N/A")],
            ["Hop Count", str(parsed.get("hop_count", "N/A"))],
            ["Reply-To Mismatch", "Yes ⚠️" if parsed.get("reply_to_mismatch") else "No ✅"],
        ]
        meta_table = Table(meta_data, colWidths=[2*inch, 4.5*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(meta_table)

    # Footer
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    elements.append(Spacer(1, 5))
    elements.append(Paragraph(
        "Report generated by PhishGuard — Phishing Email Detection System | Resonance'26 VIT Pune",
        ParagraphStyle('Footer', parent=body_style, fontSize=8, textColor=colors.grey)
    ))

    # Build PDF
    doc.build(elements)
    return pdf_path
