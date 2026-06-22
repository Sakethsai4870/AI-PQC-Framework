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
    title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=20, textColor=colors.HexColor('#1a1a2e'), spaceAfter=6)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#16213e'), spaceAfter=4)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, spaceAfter=4)
    risk_critical = ParagraphStyle('RiskCritical', parent=styles['Normal'], fontSize=12, textColor=colors.red, spaceAfter=4)
    risk_high = ParagraphStyle('RiskHigh', parent=styles['Normal'], fontSize=12, textColor=colors.HexColor('#ff6b35'), spaceAfter=4)
    risk_medium = ParagraphStyle('RiskMedium', parent=styles['Normal'], fontSize=12, textColor=colors.HexColor('#f7c59f'), spaceAfter=4)
    risk_low = ParagraphStyle('RiskLow', parent=styles['Normal'], fontSize=12, textColor=colors.green, spaceAfter=4)

    risk_styles = {
        'Critical': risk_critical,
        'High': risk_high,
        'Medium': risk_medium,
        'Low': risk_low,
    }

    story = []

    story.append(Paragraph('AI-PQC Framework', title_style))
    story.append(Paragraph('Post-Quantum Cryptography Security Report', styles['Heading2']))
    story.append(HRFlowable(width='100%', thickness=2, color=colors.HexColor('#1a1a2e')))
    story.append(Spacer(1, 0.2 * inch))

    domain = scan_data.get('domain', 'Unknown')
    scan_date = scan_data.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M UTC'))
    risk_level = scan_data.get('risk_level', 'Unknown')
    overall_score = scan_data.get('overall_score', 0)

    meta_data = [
        ['Domain:', domain],
        ['Scan Date:', str(scan_date)],
        ['Risk Level:', risk_level],
        ['Overall Risk Score:', f'{overall_score:.1%}'],
    ]
    meta_table = Table(meta_data, colWidths=[1.5 * inch, 5 * inch])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#16213e')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph('SSL/TLS Analysis', heading_style))
    ssl_data = scan_data.get('ssl', {})
    ssl_info = [
        ['SSL/TLS Version', ssl_data.get('ssl_version', 'N/A')],
        ['Cipher Suite', ssl_data.get('cipher_suite', 'N/A')],
        ['Key Algorithm', ssl_data.get('key_algorithm', 'N/A')],
        ['Key Size', f"{ssl_data.get('key_size', 'N/A')} bits"],
        ['Certificate Expiry', ssl_data.get('cert_expiry', 'N/A')],
    ]
    ssl_table = Table(ssl_info, colWidths=[2 * inch, 4.5 * inch])
    ssl_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e8eaf6')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ssl_table)
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph('Quantum Risk Assessment', heading_style))
    risk_style = risk_styles.get(risk_level, body_style)
    story.append(Paragraph(f'Risk Level: {risk_level} ({overall_score:.1%})', risk_style))

    explanation = scan_data.get('explanation', {})
    if explanation.get('summary'):
        story.append(Paragraph(explanation['summary'], body_style))
    story.append(Spacer(1, 0.1 * inch))

    contrib = explanation.get('contributions', [])
    if contrib:
        story.append(Paragraph('Risk Factor Breakdown', heading_style))
        contrib_data = [['Risk Factor', 'Value', 'Weight', 'Contribution', 'Impact']]
        for c in contrib:
            contrib_data.append([
                c['feature'],
                f"{c['value']:.1%}",
                f"{c['weight']:.0%}",
                f"{c['contribution']:.1%}",
                c['impact'],
            ])
        contrib_table = Table(contrib_data, colWidths=[2 * inch, 0.8 * inch, 0.8 * inch, 1.1 * inch, 1.8 * inch])
        contrib_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(contrib_table)
        story.append(Spacer(1, 0.15 * inch))

    recs = scan_data.get('recommendations', {})
    priority_actions = recs.get('priority_actions', [])
    if priority_actions:
        story.append(Paragraph('Priority Actions Required', heading_style))
        for action in priority_actions:
            story.append(Paragraph(f"[{action['priority']}] {action['action']}", risk_styles.get(action['priority'], body_style)))
            story.append(Paragraph(action.get('detail', ''), body_style))
            story.append(Spacer(1, 0.05 * inch))

    general_recs = recs.get('recommendations', [])
    if general_recs:
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph('Recommendations', heading_style))
        for rec in general_recs:
            urgency = rec.get('urgency', 'Low')
            story.append(Paragraph(
                f"[{urgency}] {rec['category']}: {rec['recommendation']}",
                risk_styles.get(urgency, body_style)
            ))
            story.append(Paragraph(rec.get('detail', ''), body_style))
            story.append(Spacer(1, 0.05 * inch))

    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.grey))
    story.append(Paragraph(
        f'Report generated by AI-PQC Framework | {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}',
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer
