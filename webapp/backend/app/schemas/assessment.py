"""Assessment schemas."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

from app.models.assessment import AssessmentStatus
from app.schemas.checklist import ChecklistItemResponse
from app.schemas.exception import ExceptionResponse


class AssessmentBase(BaseModel):
    """Base assessment schema."""
    status: AssessmentStatus = AssessmentStatus.NOT_ASSESSED
    evidence_note: Optional[str] = None
    assessor: Optional[str] = Field(None, max_length=255)
    remediation_plan: Optional[str] = None
    due_date: Optional[datetime] = None


class AssessmentCreate(AssessmentBase):
    """Assessment creation schema."""
    asset_id: int
    checklist_item_id: int


class AssessmentUpdate(BaseModel):
    """Assessment update schema."""
    status: Optional[AssessmentStatus] = None
    evidence_note: Optional[str] = None
    assessor: Optional[str] = Field(None, max_length=255)
    remediation_plan: Optional[str] = None
    due_date: Optional[datetime] = None


class AssessmentResponse(AssessmentBase):
    """Assessment response schema."""
    id: int
    asset_id: int
    checklist_item_id: int
    evidence_paths: List[str] = []
    check_command: Optional[str] = None
    remediation_command: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    checklist_item: Optional[ChecklistItemResponse] = None
    exception_approval: Optional[ExceptionResponse] = None

    class Config:
        from_attributes = True


class AssessmentWithAsset(AssessmentResponse):
    """Assessment with asset info schema."""
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
