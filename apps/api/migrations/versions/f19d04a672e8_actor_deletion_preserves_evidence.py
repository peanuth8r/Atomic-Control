"""Keep execution target IDs as immutable historical values after actor deletion."""

import sqlalchemy as sa
from alembic import op

revision = "f19d04a672e8"
down_revision = "e83c195a627b"
branch_labels = None
depends_on = None

NAMING = {"fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"}


def upgrade():
    constraints = sa.inspect(op.get_bind()).get_foreign_keys("execution_runs")
    with op.batch_alter_table("execution_runs", naming_convention=NAMING) as batch:
        for constraint in constraints:
            if constraint["constrained_columns"] in [["actor_id"], ["profile_id"]]:
                name = constraint["name"] or (
                    f"fk_execution_runs_{constraint['constrained_columns'][0]}_{constraint['referred_table']}"
                )
                batch.drop_constraint(name, type_="foreignkey")


def downgrade():
    bind = op.get_bind()
    missing = bind.execute(
        sa.text(
            "SELECT 1 FROM execution_runs r "
            "LEFT JOIN actors a ON a.id = r.actor_id "
            "LEFT JOIN execution_profiles p ON p.id = r.profile_id "
            "WHERE a.id IS NULL OR p.id IS NULL LIMIT 1"
        )
    ).first()
    if missing:
        raise RuntimeError(
            "Cannot restore live actor foreign keys after deletion; restore a pre-deletion backup"
        )
    with op.batch_alter_table("execution_runs", naming_convention=NAMING) as batch:
        batch.create_foreign_key("fk_execution_runs_actor_id_actors", "actors", ["actor_id"], ["id"])
        batch.create_foreign_key(
            "fk_execution_runs_profile_id_execution_profiles", "execution_profiles", ["profile_id"], ["id"]
        )
