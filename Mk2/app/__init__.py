# The Vault
# ─────────────────────────────────────────────────
# A local secure credential vault with RFID + PIN
# and username + passphrase authentication paths.

"""
The Vault — Python Backend Package

Application factory lives here. Import and call ``create_app()``
to get a fully configured Flask application.
"""

from flask import Flask

from app.config import Config
from app.database import init_db
from app.api import api_bp


def create_app(config: Config | None = None) -> Flask:
    """Create and configure the Flask application."""

    if config is None:
        config = Config.from_env()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.secret_key

    # Store our config on the app for easy access in blueprints
    app.config["VAULT_CONFIG"] = config

    # Initialise the database tables (creates if missing)
    init_db(config.database_url)

    # Register the API blueprint
    app.register_blueprint(api_bp, url_prefix="/api")

    return app
