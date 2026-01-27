"""API routers."""
from fastapi import APIRouter

from app.api import auth, assets, checklist, assessments, exceptions, reports, agent, users

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(assets.router, prefix="/assets", tags=["Assets"])
api_router.include_router(checklist.router, prefix="/checklist", tags=["Checklist"])
api_router.include_router(assessments.router, prefix="/assessments", tags=["Assessments"])
api_router.include_router(exceptions.router, prefix="/exceptions", tags=["Exceptions"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(agent.router, prefix="/agent", tags=["Agent"])
