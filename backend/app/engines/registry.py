"""Imports every engine module so that it registers itself. Imported by the API and workers."""

from app.engines import dns_discovery, http_exposure  # noqa: F401
import app.integrations.notify.channels  # noqa: E402,F401
import app.integrations.ticketing.connectors  # noqa: E402,F401
