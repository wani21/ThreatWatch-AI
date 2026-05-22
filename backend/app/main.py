from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.routes import auth, alerts, events, users, analysis, anomaly, risk

app = FastAPI(
    title=settings.APP_NAME,
    description="ThreatWatch-AI: AI-Powered Login Threat Detection and Risk Monitoring System Backend",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
# Allows standard local frontend development servers to access backend resources
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production environments to specified domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Threat Alerts"])
app.include_router(events.router, prefix="/api/v1/events", tags=["Login Events"])
app.include_router(users.router, prefix="/api/v1/users", tags=["User Profiles"])
app.include_router(analysis.router, prefix="/api", tags=["Threat Analysis"])
app.include_router(anomaly.router, prefix="/api", tags=["Anomaly Detection"])
app.include_router(risk.router, prefix="/api", tags=["Risk Assessment"])


@app.get("/health", status_code=status.HTTP_200_OK, tags=["Health"])
def health_check():
    """
    Service health probe. Returns status, environment details, and version checks.
    """
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "version": "1.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    # Primarily for ease of execution when launching main.py directly
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
