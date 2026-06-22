from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io
from datetime import datetime


def generate_pdf_report(scan_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=20,
                                 textColor=colors.HexColor('#1a1a2e'), spaceAfter=6)
    section_style = ParagraphStyle('Section', parent=styles['Heading1'], fontSize=14,
                                   textColor=colors.white, spaceAfter=4, spaceBefore=12,
                                   backColor=colors.HexColor('#1a1a2e'),
                                   leftIndent=-0.1 * inch, rightIndent=-0.1 * inch,
                                   borderPad=6)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=12,
                                   textColor=colors.HexColor('#16213e'), spaceAfter=4, spaceBefore=8)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, spaceAfter=4, leading=14)
    bullet_style = ParagraphStyle('Bullet', parent=styles['Normal'], fontSize=10,
                                  spaceAfter=3, leftIndent=16, leading=13)
    small_style = ParagraphStyle('Small', parent=styles['Normal'], fontSize=9,
                                 textColor=colors.HexColor('#555555'), spaceAfter=3)

    priority_colors = {
        'Critical': colors.HexColor('#c0392b'),
        'High': colors.HexColor('#d35400'),
        'Medium': colors.HexColor('#d68910'),
        'Low': colors.HexColor('#1e8449'),
    }
    priority_bg = {
        'Critical': colors.HexColor('#fde8e8'),
        'High': colors.HexColor('#fff0e6'),
        'Medium': colors.HexColor('#fff8e6'),
        'Low': colors.HexColor('#e8f8f2'),
    }

    def priority_para(text, level):
        c = priority_colors.get(level, colors.black)
        return ParagraphStyle(f'P_{level}', parent=styles['Normal'],
                              fontSize=10, textColor=c, spaceAfter=3, leading=13)

    def section_header(title):
        return [
            Spacer(1, 0.15 * inch),
            Paragraph(f'  {title}', section_style),
            Spacer(1, 0.1 * inch),
        ]

    story = []

    story.append(Paragraph('AI-PQC Framework', title_style))
    story.append(Paragraph('Post-Quantum Cryptography Security Report', styles['Heading2']))
    story.append(HRFlowable(width='100%', thickness=2, color=colors.HexColor('#1a1a2e')))
    story.append(Spacer(1, 0.15 * inch))

    domain = scan_data.get('domain', 'Unknown')
    scan_date = scan_data.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M UTC'))
    risk_level = scan_data.get('risk_level', 'Unknown')
    quantum_score = scan_data.get('overall_score', 0)
    migration_priority = scan_data.get('migration_priority', 'Unknown')

    meta_data = [
        ['Domain:', domain],
        ['Scan Date:', str(scan_date)],
        ['Quantum Risk Level:', risk_level],
        ['Migration Priority:', migration_priority],
    ]
    meta_table = Table(meta_data, colWidths=[1.6 * inch, 4.9 * inch])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#16213e')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)

    story += section_header('1. Detected Cryptographic Configuration')

    ssl_data = scan_data.get('ssl', {})
    header_data = scan_data.get('headers', {})
    domain_data = scan_data.get('domain_info', {})
    profile = scan_data.get('profile', {})

    hybrid_pqc = header_data.get('hybrid_pqc_detected', False)
    pqc_headers = header_data.get('pqc_headers', {})
    key_exchange = profile.get('key_exchange', 'Unknown')

    crypto_rows = [
        ['Parameter', 'Detected Value', 'Quantum Status'],
        ['TLS/SSL Version', ssl_data.get('ssl_version', 'N/A'),
         'Modern' if ssl_data.get('ssl_version') == 'TLSv1.3' else
         ('Adequate' if ssl_data.get('ssl_version') == 'TLSv1.2' else 'Vulnerable')],
        ['Certificate Algorithm', ssl_data.get('key_algorithm', 'N/A'),
         'Quantum-Resistant' if profile.get('is_pqc_algo') else 'Quantum-Vulnerable'],
        ['Key Size', f"{ssl_data.get('key_size', 'N/A')} bits",
         'Adequate' if (ssl_data.get('key_size') or 0) >= 2048 else 'Insufficient'],
        ['Key Exchange', key_exchange,
         'Hybrid PQC' if 'ML-KEM' in key_exchange else
         ('Quantum-Safe' if key_exchange in ('X25519', 'ECDHE') else 'Classical')],
        ['Cipher Suite', ssl_data.get('cipher_suite', 'N/A') or 'N/A',
         profile.get('cipher_strength', 'Unknown')],
        ['Hybrid PQC Detected', 'Yes' if hybrid_pqc else 'No',
         'Active' if hybrid_pqc else 'Not Deployed'],
        ['DNSSEC', 'Enabled' if domain_data.get('dnssec_enabled') else 'Not Detected',
         'Protected' if domain_data.get('dnssec_enabled') else 'Unprotected'],
        ['Security Headers Score', f"{header_data.get('score', 0):.0f}%",
         'Strong' if header_data.get('score', 0) >= 70 else
         ('Moderate' if header_data.get('score', 0) >= 40 else 'Weak')],
    ]
    if pqc_headers:
        for k, v in pqc_headers.items():
            crypto_rows.append([k, str(v)[:50], 'PQC Header Present'])

    crypto_table = Table(crypto_rows, colWidths=[1.8 * inch, 2.8 * inch, 1.9 * inch])
    crypto_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
    ]))
    story.append(crypto_table)

    story += section_header('2. Quantum Vulnerability Score')

    score_data = [
        ['Metric', 'Score', 'Assessment'],
        ['Quantum Vulnerability Score', f'{quantum_score:.1%}', risk_level],
        ['Algorithm Vulnerability', f'{profile.get("algorithm_risk", features_from_profile(profile)):.1%}' if False else
         ('Critical' if profile.get('algorithm') in ('RSA', 'ECDSA', 'DSA') else
          ('Resistant' if profile.get('is_pqc_algo') else 'Unknown')),
         _algo_vuln_detail(profile)],
        ['Protocol Readiness', ssl_data.get('ssl_version', 'Unknown'),
         'Supports PQC hybrid groups' if ssl_data.get('ssl_version') == 'TLSv1.3' else 'Upgrade needed for PQC'],
        ['Header Security', f"{header_data.get('score', 0):.0f}%",
         'Strong' if header_data.get('score', 0) >= 70 else 'Needs improvement'],
        ['Hybrid PQC Status', 'Active' if hybrid_pqc else 'Not deployed',
         'Quantum key exchange protected' if hybrid_pqc else 'Harvest-now-decrypt-later risk'],
    ]
    score_table = Table(score_data, colWidths=[2.0 * inch, 1.5 * inch, 3.0 * inch])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
    ]))
    story.append(score_table)

    story += section_header('3. Migration Priority')

    mp_color = priority_colors.get(migration_priority, colors.black)
    mp_bg = priority_bg.get(migration_priority, colors.white)
    mp_label_style = ParagraphStyle('MPLabel', parent=styles['Normal'], fontSize=14,
                                    textColor=mp_color, fontName='Helvetica-Bold', spaceAfter=4)
    story.append(Paragraph(f'Migration Priority: {migration_priority}', mp_label_style))

    migration_rationale = scan_data.get('migration_rationale', '')
    if migration_rationale:
        story.append(Paragraph(migration_rationale, body_style))
    story.append(Spacer(1, 0.1 * inch))

    priority_actions = scan_data.get('priority_actions', [])
    if priority_actions:
        story.append(Paragraph('Priority Actions', heading_style))
        for action in priority_actions:
            pa_style = ParagraphStyle(
                f'PA_{action["priority"]}', parent=styles['Normal'], fontSize=10,
                textColor=priority_colors.get(action['priority'], colors.black),
                fontName='Helvetica-Bold', spaceAfter=2)
            story.append(Paragraph(f'[{action["priority"]}] {action["action"]}', pa_style))
            story.append(Paragraph(action.get('detail', ''), bullet_style))
            story.append(Spacer(1, 0.05 * inch))

    story += section_header('4. AI Recommendation')

    general_recs = scan_data.get('recommendations', [])
    if general_recs:
        for rec in general_recs:
            urgency = rec.get('urgency', 'Low')
            urg_color = priority_colors.get(urgency, colors.HexColor('#333333'))
            cat_style = ParagraphStyle(f'Cat_{urgency}', parent=styles['Normal'], fontSize=10,
                                       textColor=urg_color, fontName='Helvetica-Bold', spaceAfter=2)
            story.append(Paragraph(
                f'[{urgency}] {rec.get("category", "")}: {rec.get("recommendation", "")}',
                cat_style
            ))
            story.append(Paragraph(rec.get('detail', ''), bullet_style))
            if rec.get('standard'):
                story.append(Paragraph(f'Standard: {rec["standard"]}', small_style))
            story.append(Spacer(1, 0.06 * inch))
    else:
        story.append(Paragraph('No specific recommendations generated.', body_style))

    story += section_header('5. AI Decision Explanation')

    ai_decision = scan_data.get('ai_decision', {})
    reasoning = ai_decision.get('reasoning', '')
    if reasoning:
        story.append(Paragraph('Decision Reasoning', heading_style))
        story.append(Paragraph(reasoning, body_style))
        story.append(Spacer(1, 0.1 * inch))

    factors = ai_decision.get('factors', [])
    if factors:
        story.append(Paragraph('Top Contributing Factors', heading_style))
        for f in factors:
            impact = f.get('impact', 'Neutral')
            impact_color = (colors.HexColor('#1e8449') if impact == 'Positive'
                            else colors.HexColor('#c0392b') if impact == 'Negative'
                            else colors.HexColor('#7f8c8d'))
            f_title_style = ParagraphStyle(f'FTitle_{impact}', parent=styles['Normal'],
                                           fontSize=10, textColor=impact_color,
                                           fontName='Helvetica-Bold', spaceAfter=2)
            indicator = '+ ' if impact == 'Positive' else ('- ' if impact == 'Negative' else '~ ')
            story.append(Paragraph(f'{indicator}{f["factor"]}', f_title_style))
            story.append(Paragraph(f.get('detail', ''), bullet_style))
            story.append(Spacer(1, 0.04 * inch))

    pos_count = ai_decision.get('positive_count', 0)
    neg_count = ai_decision.get('negative_count', 0)
    if pos_count or neg_count:
        summary_text = (
            f'Analysis identified {pos_count} positive factor{"s" if pos_count != 1 else ""} '
            f'and {neg_count} negative factor{"s" if neg_count != 1 else ""} '
            f'contributing to the {migration_priority} migration priority determination.'
        )
        story.append(Spacer(1, 0.05 * inch))
        story.append(Paragraph(summary_text, small_style))

    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.grey))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                                  textColor=colors.grey, alignment=TA_CENTER)
    story.append(Paragraph(
        f'AI-PQC Framework — Post-Quantum Cryptography Assessment | '
        f'Generated {datetime.now().strftime("%Y-%m-%d %H:%M UTC")} | '
        f'Standards: NIST FIPS 203/204/205/206',
        footer_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer


def features_from_profile(profile):
    return 0.0


def _algo_vuln_detail(profile):
    algo = profile.get('algorithm', 'Unknown')
    if algo in ('RSA', 'ECDSA', 'DSA'):
        return f'Broken by Shor\'s algorithm'
    elif profile.get('is_pqc_algo'):
        return 'Quantum-resistant (NIST standard)'
    return 'Not assessed'
