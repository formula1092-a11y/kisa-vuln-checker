"""Asset schemas."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

from app.models.asset import AssetType, Environment, Criticality


class AssetBase(BaseModel):
    """Base asset schema."""
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: AssetType
    owner: Optional[str] = Field(None, max_length=255)
    environment: Environment = Environment.PRODUCTION
    criticality: Criticality = Criticality.MEDIUM
    ip_address: Optional[str] = Field(None, max_length=45)
    hostname: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = None


class AssetCreate(AssetBase):
    """Asset creation schema."""
    pass


class AssetUpdate(BaseModel):
    """Asset update schema."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    asset_type: Optional[AssetType] = None
    owner: Optional[str] = Field(None, max_length=255)
    environment: Optional[Environment] = None
    criticality: Optional[Criticality] = None
    ip_address: Optional[str] = Field(None, max_length=45)
    hostname: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = None


class AssetResponse(AssetBase):
    """Asset response schema."""
    id: int
    created_at: datetime
    updated_at: datetime
    assessment_count: Optional[int] = 0
    pass_count: Optional[int] = 0
    fail_count: Optional[int] = 0

    class Config:
        from_attributes = True


class AssetListResponse(BaseModel):
    """Asset list response schema."""
    items: List[AssetResponse]
    total: int
    page: int
    size: int
