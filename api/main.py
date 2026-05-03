"""
FastAPI application entry point for the Financial Data Normalizer API.

This module wires together routers, middleware, and the health endpoint.
Vercel's Python runtime imports this file and serves the ``app`` object.

Database: Supabase (Postgres via REST) — no local file system dependencies.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from api.core.config import get_settings
from api.models.schemas import HealthResponse
from api.routers import keys, normalize, webhooks

# ── Logging ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ── Lifespan ──
@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup / shutdown lifecycle hook."""
    settings = get_settings()
    logger.info(
        "Starting %s v%s (debug=%s)",
        settings.APP_NAME,
        settings.APP_VERSION,
        settings.DEBUG,
    )
    # No local DB init needed — Supabase tables are managed via
    # SQL editor or migrations in the Supabase dashboard.
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


# ── Application Factory ──
settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "A machine-to-machine API that normalises raw financial transaction "
        "strings into strictly typed, categorised JSON. Designed for AI agents "
        "and fintech applications consuming Indian banking data.\n\n"
        "**v2.1** — Supabase backend, self-serve key generation with "
        "Stripe customer auto-creation, Gemini LLM fallback, CSV uploads, "
        "and usage auditing."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static Files ──
app.mount("/static", StaticFiles(directory="static"), name="static")

# ── Routers ──
app.include_router(normalize.router)
app.include_router(keys.router)
app.include_router(webhooks.router)


# ── Health Check ──
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health check",
    description="Returns service status, name, and version. No auth required.",
)
async def health_check() -> HealthResponse:
    """Lightweight health probe for uptime monitors and load balancers."""
    return HealthResponse(version=settings.APP_VERSION)


# ── Landing Page ──
@app.get("/")
async def landing():
    return FileResponse("static/index.html")
