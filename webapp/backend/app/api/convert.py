"""PDF to CSV conversion endpoints."""
import csv
import io
import sys
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from fastapi.responses import StreamingResponse

from app.core.security import get_current_user

# Add src directory to path for importing parser
# In Docker: /app/src, Local: ../../../../src from this file
src_paths = [
    Path("/app/src"),  # Docker container path
    Path(__file__).resolve().parent.parent.parent.parent.parent / "src",  # Local dev path
]
for src_path in src_paths:
    if src_path.exists():
        sys.path.insert(0, str(src_path))
        break

router = APIRouter()


@router.post("/pdf")
async def convert_pdf_to_csv(
    file: UploadFile = File(...),
    target: str = Query("all", regex="^(windows|unix|all)$"),
    codes: Optional[str] = Query(None, description="Comma-separated item codes (e.g., W-01,W-02)"),
    from_code: Optional[str] = Query(None, alias="from", description="Start item code"),
    to_code: Optional[str] = Query(None, alias="to", description="End item code"),
    current_user: dict = Depends(get_current_user),
):
    """
    Upload a KISA vulnerability guide PDF and convert to CSV.

    - **target**: Filter by target type (windows, unix, all)
    - **codes**: Specific item codes to extract (comma-separated)
    - **from**: Start item code for range extraction
    - **to**: End item code for range extraction
    """
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are allowed"
        )

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Import parser from src
        from src.parser import PDFParser
        from src.models import CSV_COLUMNS

        parser = PDFParser(tmp_path)

        # Find all item codes in PDF
        all_codes = parser.find_item_codes()

        if not all_codes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No vulnerability items found in the PDF"
            )

        # Filter codes by target
        if target == "windows":
            all_codes = [c for c in all_codes if c.startswith("W")]
        elif target == "unix":
            all_codes = [c for c in all_codes if c.startswith("U")]

        # Filter by specific codes
        if codes:
            requested_codes = [c.strip().upper() for c in codes.split(",")]
            all_codes = [c for c in all_codes if c in requested_codes]

        # Filter by range
        if from_code:
            from_code = from_code.upper()
            try:
                from_idx = all_codes.index(from_code)
                all_codes = all_codes[from_idx:]
            except ValueError:
                pass

        if to_code:
            to_code = to_code.upper()
            try:
                to_idx = all_codes.index(to_code)
                all_codes = all_codes[:to_idx + 1]
            except ValueError:
                pass

        if not all_codes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No items match the specified criteria"
            )

        # Parse items
        items = parser.parse_items(all_codes)

        # Generate CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()

        for item in items:
            writer.writerow(item.to_dict())

        output.seek(0)
        csv_content = output.getvalue()

        # Generate filename
        if target == "windows":
            filename = "windows_vuln.csv"
        elif target == "unix":
            filename = "unix_vuln.csv"
        else:
            filename = "vuln_checklist.csv"

        return StreamingResponse(
            io.BytesIO(csv_content.encode('utf-8-sig')),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Items-Count": str(len(items)),
            }
        )

    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Parser module not available: {str(e)}"
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to process PDF file"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Conversion failed: {str(e)}"
        )
    finally:
        # Clean up temp file
        Path(tmp_path).unlink(missing_ok=True)


@router.post("/pdf/preview")
async def preview_pdf_items(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    """
    Upload a PDF and preview available item codes.

    Returns list of item codes found in the PDF.
    """
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are allowed"
        )

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        from src.parser import PDFParser

        parser = PDFParser(tmp_path)
        all_codes = parser.find_item_codes()

        windows_codes = [c for c in all_codes if c.startswith("W")]
        unix_codes = [c for c in all_codes if c.startswith("U")]

        return {
            "filename": file.filename,
            "total_items": len(all_codes),
            "windows_items": len(windows_codes),
            "unix_items": len(unix_codes),
            "windows_codes": windows_codes,
            "unix_codes": unix_codes,
        }

    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Parser module not available: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Preview failed: {str(e)}"
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)
