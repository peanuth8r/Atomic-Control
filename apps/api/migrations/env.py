from alembic import context

from apps.api.app.config import Settings
from apps.api.app.db import make_engine
from apps.api.app.models import Base

if context.is_offline_mode():
    context.configure(url=Settings().database_url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    with make_engine(Settings().database_url).connect() as connection:
        sqlite = connection.dialect.name == "sqlite"
        if sqlite:
            # Batch migrations may rebuild tables referenced by evidence rows.
            # Disable enforcement only on this migration connection, then validate every FK.
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
        try:
            context.configure(connection=connection, target_metadata=Base.metadata, render_as_batch=True)
            with context.begin_transaction():
                context.run_migrations()
                if sqlite and connection.exec_driver_sql("PRAGMA foreign_key_check").first():
                    raise RuntimeError("Migration left invalid foreign-key references")
        finally:
            if sqlite:
                if connection.in_transaction():
                    connection.rollback()
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
