from fastapi import FastAPI

from database import engine, Base
from models.models import User, Audit, Finding, Report

from auth_routes import router as auth_router
from audit_routes import router as audit_router


# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI application
app = FastAPI(
    title="Security Configuration Auditor"
)

# Register authentication routes directly
for route in auth_router.routes:
    app.add_api_route(
        route.path,
        route.endpoint,
        methods=route.methods,
        tags=route.tags
    )

# Register audit routes directly
for route in audit_router.routes:
    app.add_api_route(
        route.path,
        route.endpoint,
        methods=route.methods,
        tags=route.tags
    )


@app.get("/")
def home():
    return {
        "message": "Security Configuration Auditor API is running"
    }