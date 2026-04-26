"""
main.py — FastAPI application entry point.

Creates the FastAPI app, mounts static files, includes the API router,
and registers startup/shutdown events.

Run with:
    uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routes import router
from app.database import initialize_database

# from app import serial_service, hardware


# ═══════════════════════════════════════════════════════════════════════════
# Lifespan (startup / shutdown)
# ═══════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    Startup:
        1. Initialize the database (create tables if needed).
        2. Optionally start the serial listener for Arduino communication.

    Shutdown:
        1. Disconnect the serial port.
        2. Clear any active sessions.

    TODO:
        - Uncomment serial_service.connect() and
          serial_service.start_serial_listener(on_pin_attempt=hardware.handle_pin_attempt)
          when Arduino is connected.
    """
    # --- Startup ---
    print("[startup] Initializing database...")
    initialize_database()
    print("[startup] Database ready.")

    # Uncomment when Arduino hardware is connected:
    # try:
    #     serial_service.connect()
    #     serial_service.start_serial_listener(
    #         on_pin_attempt=hardware.handle_pin_attempt
    #     )
    #     print("[startup] Serial listener started.")
    # except Exception as e:
    #     print(f"[startup] Serial not available: {e}")

    yield

    # --- Shutdown ---
    # serial_service.disconnect()
    print("[shutdown] Server stopped.")


# ═══════════════════════════════════════════════════════════════════════════
# App Factory
# ═══════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="The Vault",
    description="Local encrypted password manager with optional Arduino keypad gating.",
    version="0.1.0",
    lifespan=lifespan,
)

# Include API routes (MUST come before the static file mount)
app.include_router(router)

# Mount frontend static files (catch-all, must be last)
_frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.isdir(_frontend_dir):
    app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="frontend")
