"""Report schemas."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class ReportRequest(BaseModel):
    """Report generation request schema."""
    asset_id: Optional[int] = None
    include_passed: bool = True
    include_exceptions: bool = True


class AssetSummary(BaseModel):
    """Asset summary for report."""
    asset_id: int
    asset_name: str
    asset_type: str
    total_items: int
    passed: int
    failed: int
    na: int
    exceptions: int
    not_assessed: int
    compliance_rate: float


class VulnerableItem(BaseModel):
    """Vulnerable item for report."""
    asset_name: str
    item_code: str
    title: str
    severity: str
    assessor: Optional[str]
    due_date: Optional[datetime]
    remediation_plan: Optional[str]


class ExceptionItem(BaseModel):
    """Exception item for report."""
    asset_name: str
    item_code: str
    title: str
    reason: str
    requested_by: str
    approver: Optional[str]
    status: str
    expires_at: Optional[datetime]


class ReportSummary(BaseModel):
    """Report summary schema."""
    generated_at: datetime
    total_assets: int
    total_items_checked: int
    overall_compliance_rate: float
    asset_summaries: List[AssetSummary]
    vulnerable_items: List[VulnerableItem]
    exception_items: List[ExceptionItem]
