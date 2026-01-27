"""Assessment management endpoints."""
import os
import uuid
import shutil
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.core.config import settings
from app.core.security import get_current_user
from app.models.assessment import Assessment, AssessmentStatus
from app.models.asset import Asset
from app.models.checklist import ChecklistItem
from app.models.exception import ExceptionApproval, ApprovalStatus
from app.schemas.assessment import AssessmentCreate, AssessmentUpdate, AssessmentResponse

router = APIRouter()


def validate_file(file: UploadFile) -> None:
    """Validate uploaded file."""
    # Check file size
    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(0)

    if size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File too large. Maximum size is {settings.MAX_UPLOAD_SIZE // (1024*1024)}MB"
        )

    # Check extension
    ext = Path(file.filename).suffix.lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed types: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )

    # Sanitize filename
    if '..' in file.filename or file.filename.startswith('/'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename"
        )


@router.get("", response_model=List[AssessmentResponse])
async def list_assessments(
    asset_id: Optional[int] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List assessments with filters."""
    query = db.query(Assessment).options(
        joinedload(Assessment.checklist_item),
        joinedload(Assessment.exception_approval)
    )

    if asset_id:
        query = query.filter(Assessment.asset_id == asset_id)
    if status_filter:
        query = query.filter(Assessment.status == status_filter)

    assessments = query.order_by(Assessment.id).all()
    return [AssessmentResponse.model_validate(a) for a in assessments]


@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(
    assessment_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get assessment by ID."""
    assessment = db.query(Assessment).options(
        joinedload(Assessment.checklist_item),
        joinedload(Assessment.exception_approval)
    ).filter(Assessment.id == assessment_id).first()

    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    return AssessmentResponse.model_validate(assessment)


@router.put("/{assessment_id}", response_model=AssessmentResponse)
async def update_assessment(
    assessment_id: int,
    assessment_data: AssessmentUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update an assessment."""
    assessment = db.query(Assessment).options(
        joinedload(Assessment.checklist_item),
        joinedload(Assessment.exception_approval)
    ).filter(Assessment.id == assessment_id).first()

    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    update_data = assessment_data.model_dump(exclude_unset=True)

    # If status is changing to EXCEPTION, check if exception approval exists
    if update_data.get("status") == AssessmentStatus.EXCEPTION:
        if not assessment.exception_approval:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot set status to EXCEPTION without an exception request"
            )
        if assessment.exception_approval.status != ApprovalStatus.APPROVED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Exception request must be approved first"
            )

    for field, value in update_data.items():
        setattr(assessment, field, value)

    db.commit()
    db.refresh(assessment)

    return AssessmentResponse.model_validate(assessment)


@router.post("/{assessment_id}/evidence", response_model=AssessmentResponse)
async def upload_evidence(
    assessment_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Upload evidence file for an assessment."""
    assessment = db.query(Assessment).options(
        joinedload(Assessment.checklist_item),
        joinedload(Assessment.exception_approval)
    ).filter(Assessment.id == assessment_id).first()

    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    validate_file(file)

    # Create storage directory for this assessment
    storage_dir = settings.STORAGE_PATH / str(assessment_id)
    storage_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique filename
    ext = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{ext}"
    file_path = storage_dir / unique_filename

    # Save file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Update assessment
    evidence_paths = assessment.evidence_paths or []
    evidence_paths.append(str(file_path))
    assessment.evidence_paths = evidence_paths

    db.commit()
    db.refresh(assessment)

    return AssessmentResponse.model_validate(assessment)


@router.delete("/{assessment_id}/evidence/{evidence_index}")
async def delete_evidence(
    assessment_id: int,
    evidence_index: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete evidence file from an assessment."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()

    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    evidence_paths = assessment.evidence_paths or []

    if evidence_index < 0 or evidence_index >= len(evidence_paths):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    # Delete file
    file_path = Path(evidence_paths[evidence_index])
    if file_path.exists():
        file_path.unlink()

    # Update assessment
    evidence_paths.pop(evidence_index)
    assessment.evidence_paths = evidence_paths

    db.commit()

    return {"message": "Evidence deleted"}


@router.get("/{assessment_id}/evidence/{evidence_index}")
async def download_evidence(
    assessment_id: int,
    evidence_index: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Download evidence file."""
    from fastapi.responses import FileResponse

    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()

    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    evidence_paths = assessment.evidence_paths or []

    if evidence_index < 0 or evidence_index >= len(evidence_paths):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    file_path = Path(evidence_paths[evidence_index])

    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file not found")

    return FileResponse(file_path, filename=file_path.name)


@router.get("/remediation-script/{asset_id}")
async def generate_remediation_script(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Generate a remediation script for all failed assessments of an asset."""
    from fastapi.responses import PlainTextResponse

    # Get asset
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Get failed assessments with remediation commands
    failed_assessments = db.query(Assessment).options(
        joinedload(Assessment.checklist_item)
    ).filter(
        Assessment.asset_id == asset_id,
        Assessment.status == AssessmentStatus.FAIL,
        Assessment.remediation_command.isnot(None),
        Assessment.remediation_command != ""
    ).all()

    if not failed_assessments:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No failed assessments with remediation commands found"
        )

    # Generate script based on asset type
    if asset.asset_type.value == "windows":
        script = generate_windows_script(asset, failed_assessments)
        filename = f"remediation_{asset.name}.ps1"
        media_type = "text/plain"
    else:
        script = generate_unix_script(asset, failed_assessments)
        filename = f"remediation_{asset.name}.sh"
        media_type = "text/x-shellscript"

    return PlainTextResponse(
        content=script,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


def generate_windows_script(asset, assessments):
    """Generate Windows PowerShell remediation script."""
    lines = [
        "<#",
        f".SYNOPSIS",
        f"    KISA Vulnerability Remediation Script for {asset.name}",
        f".DESCRIPTION",
        f"    Automatically generated remediation script for failed security checks.",
        f"    Generated at: {__import__('datetime').datetime.now().isoformat()}",
        f".NOTES",
        f"    Run this script as Administrator!",
        "#>",
        "",
        "# Check if running as Administrator",
        '$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
        'if (-not $isAdmin) {',
        '    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red',
        '    exit 1',
        '}',
        "",
        'Write-Host "=========================================="',
        'Write-Host "KISA Vulnerability Remediation Script"',
        f'Write-Host "Asset: {asset.name}"',
        'Write-Host "=========================================="',
        'Write-Host ""',
        "",
        "$ErrorActionPreference = 'Continue'",
        "$successCount = 0",
        "$failCount = 0",
        "",
    ]

    for assessment in assessments:
        item = assessment.checklist_item
        lines.extend([
            f"# ===== {item.item_code}: {item.title} =====",
            f'Write-Host "Applying fix for {item.item_code}: {item.title}..."',
            "try {",
            f"    {assessment.remediation_command}",
            f'    Write-Host "[OK] {item.item_code} remediation applied" -ForegroundColor Green',
            "    $successCount++",
            "} catch {",
            f'    Write-Host "[FAIL] {item.item_code} remediation failed: $_" -ForegroundColor Red',
            "    $failCount++",
            "}",
            "",
        ])

    lines.extend([
        'Write-Host ""',
        'Write-Host "=========================================="',
        'Write-Host "Remediation Complete"',
        'Write-Host "  Success: $successCount"',
        'Write-Host "  Failed: $failCount"',
        'Write-Host "=========================================="',
        'Write-Host ""',
        'Write-Host "Please re-run the vulnerability check to verify fixes."',
    ])

    return "\n".join(lines)


def generate_unix_script(asset, assessments):
    """Generate Unix/Linux bash remediation script."""
    lines = [
        "#!/bin/bash",
        "#",
        f"# KISA Vulnerability Remediation Script for {asset.name}",
        f"# Automatically generated remediation script for failed security checks.",
        f"# Generated at: {__import__('datetime').datetime.now().isoformat()}",
        "#",
        "# Run this script as root!",
        "#",
        "",
        "# Check if running as root",
        'if [ "$(id -u)" != "0" ]; then',
        '    echo "ERROR: This script must be run as root!"',
        '    exit 1',
        "fi",
        "",
        'echo "=========================================="',
        'echo "KISA Vulnerability Remediation Script"',
        f'echo "Asset: {asset.name}"',
        'echo "=========================================="',
        'echo ""',
        "",
        "SUCCESS_COUNT=0",
        "FAIL_COUNT=0",
        "",
    ]

    for assessment in assessments:
        item = assessment.checklist_item
        cmd = assessment.remediation_command.replace('"', '\\"')
        lines.extend([
            f"# ===== {item.item_code}: {item.title} =====",
            f'echo "Applying fix for {item.item_code}: {item.title}..."',
            f"if {cmd}; then",
            f'    echo "[OK] {item.item_code} remediation applied"',
            "    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))",
            "else",
            f'    echo "[FAIL] {item.item_code} remediation failed"',
            "    FAIL_COUNT=$((FAIL_COUNT + 1))",
            "fi",
            "",
        ])

    lines.extend([
        'echo ""',
        'echo "=========================================="',
        'echo "Remediation Complete"',
        'echo "  Success: $SUCCESS_COUNT"',
        'echo "  Failed: $FAIL_COUNT"',
        'echo "=========================================="',
        'echo ""',
        'echo "Please re-run the vulnerability check to verify fixes."',
    ])

    return "\n".join(lines)
