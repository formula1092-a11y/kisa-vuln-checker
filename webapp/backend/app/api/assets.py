"""Asset management endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.asset import Asset
from app.models.assessment import Assessment, AssessmentStatus
from app.models.checklist import ChecklistItem
from app.schemas.asset import AssetCreate, AssetUpdate, AssetResponse, AssetListResponse
from app.services.remediation import generate_windows_remediation_script, generate_unix_remediation_script

router = APIRouter()


@router.get("", response_model=AssetListResponse)
async def list_assets(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    asset_type: Optional[str] = None,
    environment: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all assets with pagination and filters."""
    query = db.query(Asset)

    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if environment:
        query = query.filter(Asset.environment == environment)
    if search:
        query = query.filter(Asset.name.ilike(f"%{search}%"))

    total = query.count()
    assets = query.offset((page - 1) * size).limit(size).all()

    # Get assessment counts for each asset
    items = []
    for asset in assets:
        assessment_count = db.query(Assessment).filter(Assessment.asset_id == asset.id).count()
        pass_count = db.query(Assessment).filter(
            Assessment.asset_id == asset.id,
            Assessment.status == AssessmentStatus.PASS
        ).count()
        fail_count = db.query(Assessment).filter(
            Assessment.asset_id == asset.id,
            Assessment.status == AssessmentStatus.FAIL
        ).count()

        item = AssetResponse.model_validate(asset)
        item.assessment_count = assessment_count
        item.pass_count = pass_count
        item.fail_count = fail_count
        items.append(item)

    return AssetListResponse(items=items, total=total, page=page, size=size)


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_data: AssetCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new asset."""
    asset = Asset(**asset_data.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get asset by ID."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    assessment_count = db.query(Assessment).filter(Assessment.asset_id == asset.id).count()
    pass_count = db.query(Assessment).filter(
        Assessment.asset_id == asset.id,
        Assessment.status == AssessmentStatus.PASS
    ).count()
    fail_count = db.query(Assessment).filter(
        Assessment.asset_id == asset.id,
        Assessment.status == AssessmentStatus.FAIL
    ).count()

    response = AssetResponse.model_validate(asset)
    response.assessment_count = assessment_count
    response.pass_count = pass_count
    response.fail_count = fail_count

    return response


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: int,
    asset_data: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    update_data = asset_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(asset, field, value)

    db.commit()
    db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    db.delete(asset)
    db.commit()


@router.post("/{asset_id}/initialize-assessments")
async def initialize_assessments(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Initialize assessments for an asset based on its type."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Get checklist items for this asset type
    checklist_items = db.query(ChecklistItem).filter(
        ChecklistItem.asset_type == asset.asset_type.value
    ).all()

    if not checklist_items:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No checklist items found for asset type: {asset.asset_type.value}"
        )

    # Create assessments for items that don't exist yet
    created_count = 0
    for item in checklist_items:
        existing = db.query(Assessment).filter(
            Assessment.asset_id == asset_id,
            Assessment.checklist_item_id == item.id
        ).first()

        if not existing:
            assessment = Assessment(
                asset_id=asset_id,
                checklist_item_id=item.id,
                status=AssessmentStatus.NOT_ASSESSED
            )
            db.add(assessment)
            created_count += 1

    db.commit()

    return {"message": f"Initialized {created_count} assessments", "total_items": len(checklist_items)}


@router.get("/{asset_id}/remediation-script")
async def get_remediation_script(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Generate remediation script for failed assessments."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Get failed assessments with checklist items
    failed_assessments = db.query(Assessment, ChecklistItem).join(
        ChecklistItem, Assessment.checklist_item_id == ChecklistItem.id
    ).filter(
        Assessment.asset_id == asset_id,
        Assessment.status == AssessmentStatus.FAIL
    ).all()

    if not failed_assessments:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No failed assessments found for this asset"
        )

    # Prepare failed items list
    failed_items = [
        {
            "item_code": checklist.item_code,
            "title": checklist.title,
        }
        for assessment, checklist in failed_assessments
    ]

    # Generate script based on asset type
    asset_type = asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)

    if asset_type == "windows":
        script = generate_windows_remediation_script(failed_items)
        filename = f"remediate_{asset.name}_{asset_id}.ps1"
        media_type = "application/octet-stream"
    else:  # unix/linux
        script = generate_unix_remediation_script(failed_items)
        filename = f"remediate_{asset.name}_{asset_id}.sh"
        media_type = "application/x-sh"

    return PlainTextResponse(
        content=script,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "X-Failed-Items": str(len(failed_items)),
        }
    )
