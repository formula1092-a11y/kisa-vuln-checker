"""Assessment model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


class AssessmentStatus(str, enum.Enum):
    """Assessment status enumeration."""
    NOT_ASSESSED = "not_assessed"
    PASS = "pass"
    FAIL = "fail"
    NA = "na"
    EXCEPTION = "exception"


class Assessment(Base):
    """Assessment database model."""

    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    checklist_item_id = Column(Integer, ForeignKey("checklist_items.id"), nullable=False, index=True)
    status = Column(Enum(AssessmentStatus), nullable=False, default=AssessmentStatus.NOT_ASSESSED)
    evidence_paths = Column(JSON, nullable=True, default=list)  # List of file paths
    evidence_note = Column(Text, nullable=True)
    check_command = Column(Text, nullable=True)
    remediation_command = Column(Text, nullable=True)
    assessor = Column(String(255), nullable=True)
    remediation_plan = Column(Text, nullable=True)
    due_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    asset = relationship("Asset", back_populates="assessments")
    checklist_item = relationship("ChecklistItem", back_populates="assessments")
    exception_approval = relationship("ExceptionApproval", back_populates="assessment", uselist=False, cascade="all, delete-orphan")
