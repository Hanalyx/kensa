"""PDF output formatter."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.output import RunResult

# Check if reportlab is available
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def format_pdf(run_result: RunResult, filepath: str) -> None:
    """Format results as PDF and write to file.

    Unlike other formatters, this writes directly to a file since PDF is binary.

    Requires reportlab library. Install with: pip install reportlab
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "PDF output requires the reportlab library. Install with: pip install reportlab"
        )

    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceAfter=6,
    )
    normal_style = styles["Normal"]

    elements = []

    # Title
    elements.append(Paragraph("Aegis Compliance Report", title_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Summary info
    elements.append(
        Paragraph(f"Timestamp: {run_result.timestamp.isoformat()}", normal_style)
    )
    elements.append(Paragraph(f"Command: {run_result.command}", normal_style))
    elements.append(Spacer(1, 0.1 * inch))

    # Summary table
    summary_data = [
        ["Metric", "Value"],
        ["Hosts", str(run_result.host_count)],
        [
            "Total Checks",
            str(run_result.total_pass + run_result.total_fail + run_result.total_skip),
        ],
        ["Passed", str(run_result.total_pass)],
        ["Failed", str(run_result.total_fail)],
        ["Skipped", str(run_result.total_skip)],
    ]
    if run_result.command == "remediate":
        summary_data.append(["Fixed", str(run_result.total_fixed)])

    summary_table = Table(summary_data, colWidths=[2 * inch, 1.5 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Per-host results
    for host in run_result.hosts:
        elements.append(Paragraph(f"Host: {host.hostname}", heading_style))

        if host.error:
            elements.append(Paragraph(f"Error: {host.error}", normal_style))
            elements.append(Spacer(1, 0.2 * inch))
            continue

        if host.platform_family:
            elements.append(
                Paragraph(
                    f"Platform: {host.platform_family} {host.platform_version or ''}",
                    normal_style,
                )
            )

        # Results table for this host
        if host.results:
            result_data = [["Rule ID", "Status", "Severity", "Title"]]
            for result in host.results:
                if result.skipped:
                    status = "SKIP"
                elif result.passed:
                    status = "PASS"
                else:
                    status = "FAIL"

                # Truncate title if too long
                title = (
                    result.title[:50] + "..."
                    if len(result.title) > 50
                    else result.title
                )
                result_data.append(
                    [result.rule_id, status, result.severity or "", title]
                )

            result_table = Table(
                result_data,
                colWidths=[2.5 * inch, 0.6 * inch, 0.8 * inch, 3.5 * inch],
            )

            # Color-code status cells
            table_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ]

            # Color status cells
            for i, row in enumerate(result_data[1:], start=1):
                status = row[1]
                if status == "PASS":
                    table_style.append(
                        ("BACKGROUND", (1, i), (1, i), colors.lightgreen)
                    )
                elif status == "FAIL":
                    table_style.append(
                        ("BACKGROUND", (1, i), (1, i), colors.lightcoral)
                    )
                else:  # SKIP
                    table_style.append(("BACKGROUND", (1, i), (1, i), colors.lightgrey))

            result_table.setStyle(TableStyle(table_style))
            elements.append(result_table)

        elements.append(Spacer(1, 0.3 * inch))

    doc.build(elements)
