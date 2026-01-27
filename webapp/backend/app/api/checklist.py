"""Checklist management endpoints."""
import csv
import json
import io
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.checklist import ChecklistItem, Severity
from app.schemas.checklist import ChecklistItemCreate, ChecklistItemResponse, ChecklistImportResult

router = APIRouter()


@router.get("", response_model=List[ChecklistItemResponse])
async def list_checklist_items(
    asset_type: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all checklist items with filters."""
    query = db.query(ChecklistItem)

    if asset_type:
        query = query.filter(ChecklistItem.asset_type == asset_type)
    if severity:
        query = query.filter(ChecklistItem.severity == severity)
    if search:
        query = query.filter(
            (ChecklistItem.item_code.ilike(f"%{search}%")) |
            (ChecklistItem.title.ilike(f"%{search}%"))
        )

    items = query.order_by(ChecklistItem.item_code).all()
    return [ChecklistItemResponse.model_validate(item) for item in items]


@router.post("", response_model=ChecklistItemResponse, status_code=status.HTTP_201_CREATED)
async def create_checklist_item(
    item_data: ChecklistItemCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new checklist item."""
    existing = db.query(ChecklistItem).filter(ChecklistItem.item_code == item_data.item_code).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Item code {item_data.item_code} already exists"
        )

    item = ChecklistItem(**item_data.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return ChecklistItemResponse.model_validate(item)


@router.get("/{item_id}", response_model=ChecklistItemResponse)
async def get_checklist_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get checklist item by ID."""
    item = db.query(ChecklistItem).filter(ChecklistItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found")
    return ChecklistItemResponse.model_validate(item)


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_checklist_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a checklist item."""
    item = db.query(ChecklistItem).filter(ChecklistItem.id == item_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found")

    db.delete(item)
    db.commit()


@router.post("/import/csv", response_model=ChecklistImportResult)
async def import_checklist_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Import checklist items from CSV file."""
    if not file.filename.endswith('.csv'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a CSV"
        )

    content = await file.read()
    try:
        # Try UTF-8 with BOM first, then UTF-8
        try:
            text = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            text = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be UTF-8 encoded"
        )

    reader = csv.DictReader(io.StringIO(text))

    total = 0
    imported = 0
    skipped = 0
    errors = []

    # Column mapping from Korean to English
    column_map = {
        "항목코드": "item_code",
        "항목명": "title",
        "자산분류": "asset_type",
        "중요도": "severity",
        "점검내용": "description",
        "점검목적": "check_method",
        "판단기준(양호)": "pass_criteria",
        "판단기준(취약)": "fail_criteria",
        "조치방법": "remediation",
        "참조섹션(페이지/챕터)": "reference",
    }

    severity_map = {
        "상": Severity.HIGH,
        "중": Severity.MEDIUM,
        "하": Severity.LOW,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }

    asset_type_map = {
        "Windows 서버": "windows",
        "Unix 서버": "unix",
        "windows": "windows",
        "unix": "unix",
    }

    for row in reader:
        total += 1
        try:
            # Map columns
            mapped_row = {}
            for kr_col, en_col in column_map.items():
                if kr_col in row:
                    mapped_row[en_col] = row[kr_col]
                elif en_col in row:
                    mapped_row[en_col] = row[en_col]

            # Skip if no item_code
            if not mapped_row.get("item_code"):
                errors.append(f"Row {total}: Missing item_code")
                skipped += 1
                continue

            # Check if already exists
            existing = db.query(ChecklistItem).filter(
                ChecklistItem.item_code == mapped_row["item_code"]
            ).first()

            if existing:
                skipped += 1
                continue

            # Map severity
            severity_val = mapped_row.get("severity", "medium").lower().strip()
            mapped_row["severity"] = severity_map.get(severity_val, Severity.MEDIUM)

            # Map asset type
            asset_type_val = mapped_row.get("asset_type", "").strip()
            mapped_row["asset_type"] = asset_type_map.get(asset_type_val, asset_type_val.lower())

            # Create item
            item = ChecklistItem(
                item_code=mapped_row.get("item_code", ""),
                asset_type=mapped_row.get("asset_type", "other"),
                title=mapped_row.get("title", ""),
                description=mapped_row.get("description"),
                check_method=mapped_row.get("check_method"),
                pass_criteria=mapped_row.get("pass_criteria"),
                fail_criteria=mapped_row.get("fail_criteria"),
                severity=mapped_row.get("severity", Severity.MEDIUM),
                remediation=mapped_row.get("remediation"),
                reference=mapped_row.get("reference"),
            )
            db.add(item)
            imported += 1

        except Exception as e:
            errors.append(f"Row {total}: {str(e)}")
            skipped += 1

    db.commit()

    return ChecklistImportResult(total=total, imported=imported, skipped=skipped, errors=errors[:10])


@router.post("/import/json", response_model=ChecklistImportResult)
async def import_checklist_json(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Import checklist items from JSON file."""
    if not file.filename.endswith('.json'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a JSON"
        )

    content = await file.read()
    try:
        data = json.loads(content.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON file: {str(e)}"
        )

    if not isinstance(data, list):
        data = [data]

    total = len(data)
    imported = 0
    skipped = 0
    errors = []

    for i, item_data in enumerate(data):
        try:
            item_code = item_data.get("item_code")
            if not item_code:
                errors.append(f"Item {i+1}: Missing item_code")
                skipped += 1
                continue

            existing = db.query(ChecklistItem).filter(
                ChecklistItem.item_code == item_code
            ).first()

            if existing:
                skipped += 1
                continue

            # Map severity string to enum
            severity_str = item_data.get("severity", "medium").lower()
            severity = {
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW
            }.get(severity_str, Severity.MEDIUM)

            item = ChecklistItem(
                item_code=item_code,
                asset_type=item_data.get("asset_type", "other"),
                category=item_data.get("category"),
                subcategory=item_data.get("subcategory"),
                title=item_data.get("title", ""),
                description=item_data.get("description"),
                check_method=item_data.get("check_method"),
                pass_criteria=item_data.get("pass_criteria"),
                fail_criteria=item_data.get("fail_criteria"),
                severity=severity,
                remediation=item_data.get("remediation"),
                reference=item_data.get("reference"),
            )
            db.add(item)
            imported += 1

        except Exception as e:
            errors.append(f"Item {i+1}: {str(e)}")
            skipped += 1

    db.commit()

    return ChecklistImportResult(total=total, imported=imported, skipped=skipped, errors=errors[:10])


@router.get("/template/csv")
async def get_csv_template():
    """Get CSV import template."""
    from fastapi.responses import StreamingResponse

    template = """항목코드,항목명,자산분류,중요도,점검내용,점검목적,판단기준(양호),판단기준(취약),조치방법,참조섹션(페이지/챕터)
W-01,Administrator 계정 이름 변경,Windows 서버,상,Administrator 계정 이름 변경 여부 점검,악의적인 공격 차단,계정 이름 변경됨,기본 계정 이름 사용,계정 이름 변경,p.177
U-01,root 계정 원격 접속 제한,Unix 서버,상,root 원격 접속 차단 설정 점검,관리자 계정 보호,원격 접속 차단됨,원격 접속 허용됨,SSH 설정 변경,p.12
"""

    return StreamingResponse(
        io.StringIO(template),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=checklist_template.csv"}
    )


@router.get("/template/json")
async def get_json_template():
    """Get JSON import template."""
    template = [
        {
            "item_code": "W-01",
            "asset_type": "windows",
            "category": "계정관리",
            "title": "Administrator 계정 이름 변경",
            "description": "Administrator 계정 이름 변경 여부 점검",
            "check_method": "제어판 > 관리도구 > 로컬 보안 정책 확인",
            "pass_criteria": "계정 이름이 변경된 경우",
            "fail_criteria": "기본 계정 이름을 사용하는 경우",
            "severity": "high",
            "remediation": "Administrator 계정 이름을 변경",
            "reference": "p.177"
        },
        {
            "item_code": "U-01",
            "asset_type": "unix",
            "category": "계정관리",
            "title": "root 계정 원격 접속 제한",
            "description": "root 계정 원격 접속 차단 설정 점검",
            "check_method": "/etc/ssh/sshd_config 파일 확인",
            "pass_criteria": "원격 접속이 차단된 경우",
            "fail_criteria": "원격 접속이 허용된 경우",
            "severity": "high",
            "remediation": "PermitRootLogin no 설정",
            "reference": "p.12"
        }
    ]

    return template
