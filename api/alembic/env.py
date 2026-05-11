import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from cbom_api.config import get_settings
from cbom_api.models.db import Base

config = context.config
settings = get_settings()

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_async_engine(settings.database_url)

    async def do_run() -> None:
        async with connectable.begin() as connection:
            await connection.run_sync(do_run_migrations)

        await connectable.dispose()

    asyncio.run(do_run())


run_migrations_online()
