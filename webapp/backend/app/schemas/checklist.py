"""Checklist schemas."""
from typing import Optional, List
from pydantic import BaseModel, Field

from app.models.checklist import Severity


class ChecklistItemBase(BaseModel):
    """Base checklist item schema."""
    item_code: str = Field(..., min_length=1, max_length=20)
    asset_type: str = Field(..., min_length=1, max_length=50)
    category: Optional[str] = Field(None, max_length=100)
    subcategory: Optional[str] = Field(None, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    check_method: Optional[str] = None
    pass_criteria: Optional[str] = None
    fail_criteria: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    remediation: Optional[str] = None
    reference: Optional[str] = Field(None, max_length=255)


class ChecklistItemCreate(ChecklistItemBase):
    """Checklist item creation schema."""
    pass


class ChecklistItemResponse(ChecklistItemBase):
    """Checklist item response schema."""
    id: int

    class Config:
        from_attributes = True


class ChecklistImportResult(BaseModel):
    """Checklist import result schema."""
    total: int
    imported: int
    skipped: int
    errors: List[str]
