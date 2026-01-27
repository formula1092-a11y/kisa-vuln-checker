"""PDF report generator service."""
import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from app.schemas.report import ReportSummary


def setup_korean_font():
    """Setup Korean font support."""
    try:
        # Try to register a Korean font (malgun.ttf is common on Windows)
        pdfmetrics.registerFont(TTFont('Malgun', 'C:/Windows/Fonts/malgun.ttf'))
        return 'Malgun'
    except Exception:
        try:
            # Try NanumGothic on Linux/Mac
            pdfmetrics.registerFont(TTFont('NanumGothic', '/usr/share/fonts/truetype/nanum/NanumGothic.ttf'))
            return 'NanumGothic'
        except Exception:
            return 'Helvetica'


def generate_pdf_report(report_data: ReportSummary) -> io.BytesIO:
    """Generate PDF report from report data."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm)

    # Setup font
    font_name = setup_korean_font()

    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontName=font_name,
        fontSize=18,
        spaceAfter=12
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontName=font_name,
        fontSize=14,
        spaceAfter=8,
        spaceBefore=12
    )
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontName=font_name,
        fontSize=10
    )

    elements = []

    # Title
    elements.append(Paragraph("KISA Vulnerability Assessment Report", title_style))
    elements.append(Paragraph(f"Generated: {report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 12))

    # Summary
    elements.append(Paragraph("Executive Summary", heading_style))
    summary_data = [
        ["Total Assets", str(report_data.total_assets)],
        ["Total Items Checked", str(report_data.total_items_checked)],
        ["Overall Compliance Rate", f"{report_data.overall_compliance_rate}%"],
    ]
    summary_table = Table(summary_data, colWidths=[120, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # Asset Summary
    if report_data.asset_summaries:
        elements.append(Paragraph("Asset Summary", heading_style))
        asset_data = [["Asset Name", "Type", "Total", "Pass", "Fail", "Exception", "Compliance"]]
        for asset in report_data.asset_summaries:
            asset_data.append([
                asset.asset_name[:20] + "..." if len(asset.asset_name) > 20 else asset.asset_name,
                asset.asset_type,
                str(asset.total_items),
                str(asset.passed),
                str(asset.failed),
                str(asset.exceptions),
                f"{asset.compliance_rate}%"
            ])

        asset_table = Table(asset_data, colWidths=[80, 50, 40, 40, 40, 50, 50])
        asset_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(asset_table)
        elements.append(Spacer(1, 12))

    # Vulnerable Items
    if report_data.vulnerable_items:
        elements.append(Paragraph("Vulnerable Items", heading_style))
        vuln_data = [["Asset", "Item Code", "Title", "Severity", "Due Date"]]
        for item in report_data.vulnerable_items[:50]:  # Limit to 50 items
            vuln_data.append([
                item.asset_name[:15] + "..." if len(item.asset_name) > 15 else item.asset_name,
                item.item_code,
                item.title[:30] + "..." if len(item.title) > 30 else item.title,
                item.severity,
                item.due_date.strftime("%Y-%m-%d") if item.due_date else "-"
            ])

        vuln_table = Table(vuln_data, colWidths=[70, 40, 150, 50, 60])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(vuln_table)
        elements.append(Spacer(1, 12))

    # Exception Items
    if report_data.exception_items:
        elements.append(Paragraph("Exception Items", heading_style))
        exc_data = [["Asset", "Item Code", "Reason", "Status", "Expires"]]
        for item in report_data.exception_items[:30]:  # Limit to 30 items
            exc_data.append([
                item.asset_name[:15] + "..." if len(item.asset_name) > 15 else item.asset_name,
                item.item_code,
                item.reason[:40] + "..." if len(item.reason) > 40 else item.reason,
                item.status,
                item.expires_at.strftime("%Y-%m-%d") if item.expires_at else "-"
            ])

        exc_table = Table(exc_data, colWidths=[70, 40, 150, 50, 60])
        exc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(exc_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer
