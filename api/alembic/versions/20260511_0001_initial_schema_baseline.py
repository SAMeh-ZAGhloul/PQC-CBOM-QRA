"""Initial schema baseline.

Revision ID: 20260511_0001
Revises:
Create Date: 2026-05-11 13:33:00
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260511_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Stamp the existing SQL-initialized schema as the baseline."""


def downgrade() -> None:
    """Baseline downgrade is intentionally a no-op."""

