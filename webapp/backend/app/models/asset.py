"""Asset model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Enum
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


class AssetType(str, enum.Enum):
    """Asset type enumeration."""
    WINDOWS = "windows"
    UNIX = "unix"
    NETWORK = "network"
    DATABASE = "database"
    WEB = "web"
    OTHER = "other"


class Environment(str, enum.Enum):
    """Environment enumeration."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class Criticality(str, enum.Enum):
    """Criticality level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Asset(Base):
    """Asset database model."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    asset_type = Column(Enum(AssetType), nullable=False)
    owner = Column(String(255), nullable=True)
    environment = Column(Enum(Environment), nullable=False, default=Environment.PRODUCTION)
    criticality = Column(Enum(Criticality), nullable=False, default=Criticality.MEDIUM)
    ip_address = Column(String(45), nullable=True)
    hostname = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assessments = relationship("Assessment", back_populates="asset", cascade="all, delete-orphan")
