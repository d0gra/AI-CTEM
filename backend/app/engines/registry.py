"""Imports every engine and connector module so that it registers itself."""

import app.integrations.notify.channels  # noqa: F401
import app.integrations.ticketing.connectors  # noqa: F401
from app.engines import aws_posture, dns_discovery, http_exposure, openapi_analysis, scanners  # noqa: F401
from app.integrations.intel import sources  # noqa: F401
