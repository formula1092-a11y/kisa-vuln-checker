"""Exception approval schemas."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

from app.models.exception import ApprovalStatus


class ExceptionBase(BaseModel):
    """Base exception schema."""
    reason: str = Field(..., min_length=1)
    expires_at: Optional[datetime] = None


class ExceptionCreate(ExceptionBase):
    """Exception creation schema."""
    assessment_id: int


class ExceptionDecision(BaseModel):
    """Exception decision schema."""
    status: ApprovalStatus
    decision_note: Optional[str] = None


class ExceptionResponse(ExceptionBase):
    """Exception response schema."""
    id: int
    assessment_id: int
    requested_by: str
    approver: Optional[str] = None
    status: ApprovalStatus
    decided_at: Optional[datetime] = None
    decision_note: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ExceptionWithAssessment(ExceptionResponse):
    """Exception with assessment info schema."""
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    checklist_item_code: Optional[str] = None
    checklist_item_title: Optional[str] = None
