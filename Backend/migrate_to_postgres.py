from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import MetaData, delete, func, inspect, select, text

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import settings
from Backend.database import Base, build_engine, ensure_schema


def default_sqlite_url() -> str:
    return f"sqlite:///{(ROOT_DIR / 'Backend' / 'sql_app.db').resolve().as_posix()}"


def chunked_rows(result, batch_size: int):
    batch = []
    for row in result:
        batch.append(dict(row))
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def truncate_target_tables(target_conn, target_metadata):
    for table in reversed(target_metadata.sorted_tables):
        target_conn.execute(delete(table))


def reset_postgres_sequences(target_conn, target_metadata):
    for table in target_metadata.sorted_tables:
        if "id" not in table.c:
            continue
        query = text(
            f"SELECT setval(pg_get_serial_sequence('{table.name}', 'id'), "
            f"COALESCE((SELECT MAX(id) FROM {table.name}), 1), "
            f"(SELECT COUNT(*) > 0 FROM {table.name}))"
        )
        target_conn.execute(query)


def migrate(*, source_url: str, target_url: str, truncate: bool, batch_size: int) -> None:
    source_engine = build_engine(source_url)
    target_engine = build_engine(target_url)

    if source_engine.dialect.name != "sqlite":
        raise RuntimeError("Source database must be SQLite for this migration helper")
    if target_engine.dialect.name != "postgresql":
        raise RuntimeError("Target database must be PostgreSQL")

    Base.metadata.create_all(bind=target_engine)
    ensure_schema(target_engine)

    source_metadata = MetaData()
    source_metadata.reflect(bind=source_engine)
    target_metadata = MetaData()
    target_metadata.reflect(bind=target_engine)

    summary: list[tuple[str, int]] = []
    with source_engine.connect() as source_conn, target_engine.begin() as target_conn:
        if truncate:
            truncate_target_tables(target_conn, target_metadata)

        for source_table in source_metadata.sorted_tables:
            target_table = target_metadata.tables.get(source_table.name)
            if target_table is None:
                continue

            source_rows = source_conn.execute(select(source_table)).mappings()
            copied = 0
            common_columns = [column.name for column in target_table.columns if column.name in source_table.c]
            for batch in chunked_rows(
                ({key: row[key] for key in common_columns} for row in source_rows),
                batch_size=batch_size,
            ):
                target_conn.execute(target_table.insert(), batch)
                copied += len(batch)
            summary.append((source_table.name, copied))

        reset_postgres_sequences(target_conn, target_metadata)

    print("[MIGRATE] SQLite -> PostgreSQL complete")
    for table_name, copied in summary:
        print(f"[MIGRATE] {table_name}: {copied} rows")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrate Auto-Shopee backend data from SQLite to PostgreSQL")
    parser.add_argument("--source", default=default_sqlite_url(), help="SQLite DATABASE_URL source")
    parser.add_argument(
        "--target",
        default=settings.database_url,
        help="PostgreSQL DATABASE_URL target (defaults to current DATABASE_URL)",
    )
    parser.add_argument("--truncate", action="store_true", help="Delete target rows before importing")
    parser.add_argument("--batch-size", type=int, default=500, help="Insert batch size")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    migrate(
        source_url=args.source,
        target_url=args.target,
        truncate=bool(args.truncate),
        batch_size=max(100, int(args.batch_size or 500)),
    )


if __name__ == "__main__":
    main()
