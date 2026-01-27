"""Exception approval endpoints."""
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.assessment import Assessment, AssessmentStatus
from app.models.exception import ExceptionApproval, ApprovalStatus
from app.schemas.exception import ExceptionCreate, ExceptionDecision, ExceptionResponse, ExceptionWithAssessment

router = APIRouter()


@router.get("", response_model=List[ExceptionWithAssessment])
async def list_exceptions(
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all exception requests."""
    query = db.query(ExceptionApproval).options(
        joinedload(ExceptionApproval.assessment).joinedload(Assessment.asset),
        joinedload(ExceptionApproval.assessment).joinedload(Assessment.checklist_item)
    )

    if status_filter:
        query = query.filter(ExceptionApproval.status == status_filter)

    exceptions = query.order_by(ExceptionApproval.created_at.desc()).all()

    result = []
    for exc in exceptions:
        data = ExceptionWithAssessment(
            id=exc.id,
            assessment_id=exc.assessment_id,
            reason=exc.reason,
            requested_by=exc.requested_by,
            approver=exc.approver,
            status=exc.status,
            expires_at=exc.expires_at,
            decided_at=exc.decided_at,
            decision_note=exc.decision_note,
            created_at=exc.created_at,
            asset_id=exc.assessment.asset_id if exc.assessment else None,
            asset_name=exc.assessment.asset.name if exc.assessment and exc.assessment.asset else None,
            checklist_item_code=exc.assessment.checklist_item.item_code if exc.assessment and exc.assessment.checklist_item else None,
            checklist_item_title=exc.assessment.checklist_item.title if exc.assessment and exc.assessment.checklist_item else None,
        )
        result.append(data)

    return result


@router.post("", response_model=ExceptionResponse, status_code=status.HTTP_201_CREATED)
async def create_exception(
    exception_data: ExceptionCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new exception request."""
    # Check if assessment exists
    assessment = db.query(Assessment).filter(Assessment.id == exception_data.assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    # Check if exception already exists for this assessment
    existing = db.query(ExceptionApproval).filter(
        ExceptionApproval.assessment_id == exception_data.assessment_id
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Exception request already exists for this assessment"
        )

    exception = ExceptionApproval(
        assessment_id=exception_data.assessment_id,
        reason=exception_data.reason,
        requested_by=current_user["username"],
        expires_at=exception_data.expires_at,
        status=ApprovalStatus.PENDING
    )
    db.add(exception)
    db.commit()
    db.refresh(exception)

    return ExceptionResponse.model_validate(exception)


@router.get("/{exception_id}", response_model=ExceptionWithAssessment)
async def get_exception(
    exception_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get exception by ID."""
    exception = db.query(ExceptionApproval).options(
        joinedload(ExceptionApproval.assessment).joinedload(Assessment.asset),
        joinedload(ExceptionApproval.assessment).joinedload(Assessment.checklist_item)
    ).filter(ExceptionApproval.id == exception_id).first()

    if not exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exception not found")

    return ExceptionWithAssessment(
        id=exception.id,
        assessment_id=exception.assessment_id,
        reason=exception.reason,
        requested_by=exception.requested_by,
        approver=exception.approver,
        status=exception.status,
        expires_at=exception.expires_at,
        decided_at=exception.decided_at,
        decision_note=exception.decision_note,
        created_at=exception.created_at,
        asset_id=exception.assessment.asset_id if exception.assessment else None,
        asset_name=exception.assessment.asset.name if exception.assessment and exception.assessment.asset else None,
        checklist_item_code=exception.assessment.checklist_item.item_code if exception.assessment and exception.assessment.checklist_item else None,
        checklist_item_title=exception.assessment.checklist_item.title if exception.assessment and exception.assessment.checklist_item else None,
    )


@router.put("/{exception_id}/decide", response_model=ExceptionResponse)
async def decide_exception(
    exception_id: int,
    decision: ExceptionDecision,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Approve or reject an exception request."""
    # Only admin can approve/reject
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can approve or reject exceptions"
        )

    exception = db.query(ExceptionApproval).filter(ExceptionApproval.id == exception_id).first()

    if not exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exception not found")

    if exception.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Exception has already been decided"
        )

    exception.status = decision.status
    exception.approver = current_user["username"]
    exception.decided_at = datetime.utcnow()
    exception.decision_note = decision.decision_note

    # If approved, update assessment status to EXCEPTION
    if decision.status == ApprovalStatus.APPROVED:
        assessment = db.query(Assessment).filter(Assessment.id == exception.assessment_id).first()
        if assessment:
            assessment.status = AssessmentStatus.EXCEPTION

    db.commit()
    db.refresh(exception)

    return ExceptionResponse.model_validate(exception)


@router.delete("/{exception_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_exception(
    exception_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete an exception request (only if pending)."""
    exception = db.query(ExceptionApproval).filter(ExceptionApproval.id == exception_id).first()

    if not exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exception not found")

    if exception.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a decided exception"
        )

    # Only requester or admin can delete
    if exception.requested_by != current_user["username"] and current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this exception"
        )

    db.delete(exception)
    db.commit()
