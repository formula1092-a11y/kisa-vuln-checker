"""Agent script download endpoints."""
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse

router = APIRouter()

# Agent scripts directory (relative to project root)
AGENTS_DIR = Path(__file__).resolve().parents[3] / "agents"


@router.get("/agents")
async def list_agents():
    """List available agent scripts."""
    agents = []

    # Windows Agent
    windows_script = AGENTS_DIR / "check-windows.ps1"
    if windows_script.exists():
        agents.append({
            "id": "windows",
            "name": "Windows Server Agent",
            "filename": "check-windows.ps1",
            "platform": "Windows",
            "description": "PowerShell script for Windows Server vulnerability check (W-01 ~ W-16)",
            "usage": '.\\check-windows.ps1 -ServerUrl "http://SERVER:8000" -AssetName "MyServer"',
            "requirements": "PowerShell 5.1+, Administrator privileges",
        })

    # Unix Agent
    unix_script = AGENTS_DIR / "check-unix.sh"
    if unix_script.exists():
        agents.append({
            "id": "unix",
            "name": "Unix/Linux Agent",
            "filename": "check-unix.sh",
            "platform": "Linux/Unix",
            "description": "Bash script for Unix/Linux server vulnerability check (U-01 ~ U-16)",
            "usage": './check-unix.sh -s "http://SERVER:8000" -n "MyServer"',
            "requirements": "Bash, curl, root privileges",
        })

    return {"agents": agents}


@router.get("/agents/{agent_id}")
async def download_agent(agent_id: str):
    """Download agent script."""
    if agent_id == "windows":
        script_path = AGENTS_DIR / "check-windows.ps1"
        filename = "check-windows.ps1"
        media_type = "application/octet-stream"
    elif agent_id == "unix":
        script_path = AGENTS_DIR / "check-unix.sh"
        filename = "check-unix.sh"
        media_type = "application/x-sh"
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown agent: {agent_id}"
        )

    if not script_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent script not found: {filename}"
        )

    return FileResponse(
        path=script_path,
        filename=filename,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/agents/{agent_id}/view")
async def view_agent(agent_id: str):
    """View agent script content."""
    if agent_id == "windows":
        script_path = AGENTS_DIR / "check-windows.ps1"
    elif agent_id == "unix":
        script_path = AGENTS_DIR / "check-unix.sh"
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown agent: {agent_id}"
        )

    if not script_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent script not found"
        )

    content = script_path.read_text(encoding="utf-8")
    return PlainTextResponse(content)
