"""Linux enrollment platform binding"""

from alembic import op
import sqlalchemy as sa

revision = 'c98e8cd27531'
down_revision = 'ebb297d2fe32'
branch_labels = None
depends_on = None
def upgrade():
    op.add_column("enrollment_tokens", sa.Column("os", sa.String(length=16), server_default="windows", nullable=False))
def downgrade():
    op.drop_column("enrollment_tokens", "os")
