"""Report generation endpoints."""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, joinedload
import io

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.asset import Asset
from app.models.assessment import Assessment, AssessmentStatus
from app.models.checklist import ChecklistItem
from app.models.exception import ExceptionApproval
from app.schemas.report import ReportRequest, ReportSummary, AssetSummary, VulnerableItem, ExceptionItem

router = APIRouter()


def generate_report_data(db: Session, asset_id: Optional[int] = None) -> ReportSummary:
    """Generate report data."""
    # Get assets
    asset_query = db.query(Asset)
    if asset_id:
        asset_query = asset_query.filter(Asset.id == asset_id)
    assets = asset_query.all()

    asset_summaries = []
    vulnerable_items = []
    exception_items = []
    total_items = 0
    total_passed = 0

    for asset in assets:
        assessments = db.query(Assessment).options(
            joinedload(Assessment.checklist_item),
            joinedload(Assessment.exception_approval)
        ).filter(Assessment.asset_id == asset.id).all()

        passed = sum(1 for a in assessments if a.status == AssessmentStatus.PASS)
        failed = sum(1 for a in assessments if a.status == AssessmentStatus.FAIL)
        na = sum(1 for a in assessments if a.status == AssessmentStatus.NA)
        exceptions = sum(1 for a in assessments if a.status == AssessmentStatus.EXCEPTION)
        not_assessed = sum(1 for a in assessments if a.status == AssessmentStatus.NOT_ASSESSED)

        total = len(assessments)
        assessed = passed + failed + exceptions
        compliance_rate = (passed / assessed * 100) if assessed > 0 else 0

        asset_summaries.append(AssetSummary(
            asset_id=asset.id,
            asset_name=asset.name,
            asset_type=asset.asset_type.value,
            total_items=total,
            passed=passed,
            failed=failed,
            na=na,
            exceptions=exceptions,
            not_assessed=not_assessed,
            compliance_rate=round(compliance_rate, 1)
        ))

        total_items += assessed
        total_passed += passed

        # Collect vulnerable items
        for a in assessments:
            if a.status == AssessmentStatus.FAIL:
                vulnerable_items.append(VulnerableItem(
                    asset_name=asset.name,
                    item_code=a.checklist_item.item_code if a.checklist_item else "",
                    title=a.checklist_item.title if a.checklist_item else "",
                    severity=a.checklist_item.severity.value if a.checklist_item else "medium",
                    assessor=a.assessor,
                    due_date=a.due_date,
                    remediation_plan=a.remediation_plan
                ))

            # Collect exception items
            if a.exception_approval:
                exception_items.append(ExceptionItem(
                    asset_name=asset.name,
                    item_code=a.checklist_item.item_code if a.checklist_item else "",
                    title=a.checklist_item.title if a.checklist_item else "",
                    reason=a.exception_approval.reason,
                    requested_by=a.exception_approval.requested_by,
                    approver=a.exception_approval.approver,
                    status=a.exception_approval.status.value,
                    expires_at=a.exception_approval.expires_at
                ))

    overall_compliance = (total_passed / total_items * 100) if total_items > 0 else 0

    return ReportSummary(
        generated_at=datetime.utcnow(),
        total_assets=len(assets),
        total_items_checked=total_items,
        overall_compliance_rate=round(overall_compliance, 1),
        asset_summaries=asset_summaries,
        vulnerable_items=vulnerable_items,
        exception_items=exception_items
    )


@router.get("/summary", response_model=ReportSummary)
async def get_report_summary(
    asset_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get report summary data."""
    return generate_report_data(db, asset_id)


@router.get("/pdf")
async def download_report_pdf(
    asset_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Download report as PDF."""
    from app.services.pdf_generator import generate_pdf_report

    report_data = generate_report_data(db, asset_id)
    pdf_buffer = generate_pdf_report(report_data)

    filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/csv")
async def download_report_csv(
    asset_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Download report as CSV."""
    import csv

    report_data = generate_report_data(db, asset_id)

    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        "Asset Name", "Item Code", "Title", "Status", "Severity",
        "Assessor", "Due Date", "Remediation Plan"
    ])

    # Get all assessments
    asset_query = db.query(Asset)
    if asset_id:
        asset_query = asset_query.filter(Asset.id == asset_id)
    assets = asset_query.all()

    for asset in assets:
        assessments = db.query(Assessment).options(
            joinedload(Assessment.checklist_item)
        ).filter(Assessment.asset_id == asset.id).all()

        for a in assessments:
            writer.writerow([
                asset.name,
                a.checklist_item.item_code if a.checklist_item else "",
                a.checklist_item.title if a.checklist_item else "",
                a.status.value,
                a.checklist_item.severity.value if a.checklist_item else "",
                a.assessor or "",
                a.due_date.strftime("%Y-%m-%d") if a.due_date else "",
                a.remediation_plan or ""
            ])

    output.seek(0)
    filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
