"""Checklist item model."""
from sqlalchemy import Column, Integer, String, Text, Enum
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


class Severity(str, enum.Enum):
    """Severity level enumeration."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ChecklistItem(Base):
    """Checklist item database model."""

    __tablename__ = "checklist_items"

    id = Column(Integer, primary_key=True, index=True)
    item_code = Column(String(20), unique=True, nullable=False, index=True)  # e.g., W-01, U-01
    asset_type = Column(String(50), nullable=False, index=True)  # windows, unix, etc.
    category = Column(String(100), nullable=True)
    subcategory = Column(String(100), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    check_method = Column(Text, nullable=True)
    pass_criteria = Column(Text, nullable=True)
    fail_criteria = Column(Text, nullable=True)
    severity = Column(Enum(Severity), nullable=False, default=Severity.MEDIUM)
    remediation = Column(Text, nullable=True)
    reference = Column(String(255), nullable=True)

    # Relationships
    assessments = relationship("Assessment", back_populates="checklist_item")
