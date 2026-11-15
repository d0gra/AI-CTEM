"""let the application role read the schema version

The API's readiness check and the image's start-up wait compare the database's migration version
with the one the running build expects; both connect as the application role.

Revision ID: 0007
Revises: 0006
"""
import os

from alembic import op

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("CTEM_APP_DB_ROLE", "ctem_app")


def upgrade() -> None:
    op.execute(f"GRANT SELECT ON alembic_version TO {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"REVOKE SELECT ON alembic_version FROM {APP_ROLE}")
