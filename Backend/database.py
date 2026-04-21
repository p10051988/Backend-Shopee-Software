from pathlib import Path
import sys

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import settings


SQLALCHEMY_DATABASE_URL = settings.database_url


def build_engine(database_url: str):
    url = make_url(database_url)
    backend_name = url.get_backend_name()
    engine_kwargs = {"pool_pre_ping": True}
    if backend_name == "sqlite":
        engine_kwargs.pop("pool_pre_ping", None)
        connect_args = {}
        if database_url == "sqlite:///:memory:":
            engine_kwargs["poolclass"] = StaticPool
        else:
            connect_args["check_same_thread"] = False
        if connect_args:
            engine_kwargs["connect_args"] = connect_args
    return create_engine(database_url, **engine_kwargs)


engine = build_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def _add_column_if_missing(conn, table_name: str, columns: set[str], column_name: str, ddl: str):
    if column_name not in columns:
        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}"))


def ensure_schema(bind_engine=None):
    bind_engine = bind_engine or engine
    inspector = inspect(bind_engine)
    with bind_engine.begin() as conn:
        table_names = set(inspector.get_table_names())

        if "licenses" in table_names:
            license_columns = {column["name"] for column in inspector.get_columns("licenses")}
            _add_column_if_missing(conn, "licenses", license_columns, "session_id", "VARCHAR")
            _add_column_if_missing(conn, "licenses", license_columns, "session_key", "VARCHAR")
            _add_column_if_missing(conn, "licenses", license_columns, "session_expiration", "TIMESTAMP")
            _add_column_if_missing(conn, "licenses", license_columns, "account_username", "VARCHAR")
            _add_column_if_missing(conn, "licenses", license_columns, "plan_code", "VARCHAR")
            _add_column_if_missing(conn, "licenses", license_columns, "source", "VARCHAR DEFAULT 'legacy'")
            _add_column_if_missing(conn, "licenses", license_columns, "notes", "TEXT")

        if "modules" in table_names:
            module_columns = {column["name"] for column in inspector.get_columns("modules")}
            _add_column_if_missing(conn, "modules", module_columns, "hash_checksum", "VARCHAR")

        if "subscription_plans" in table_names:
            plan_columns = {column["name"] for column in inspector.get_columns("subscription_plans")}
            _add_column_if_missing(conn, "subscription_plans", plan_columns, "duration_label", "VARCHAR")
            _add_column_if_missing(conn, "subscription_plans", plan_columns, "is_trial", "BOOLEAN DEFAULT FALSE")
            _add_column_if_missing(conn, "subscription_plans", plan_columns, "sort_order", "INTEGER DEFAULT 100")
            _add_column_if_missing(conn, "subscription_plans", plan_columns, "price_amount", "INTEGER DEFAULT 0")
            _add_column_if_missing(conn, "subscription_plans", plan_columns, "currency", "VARCHAR DEFAULT 'VND'")
            _add_column_if_missing(conn, "subscription_plans", plan_columns, "external_price_ref", "VARCHAR")

        if "device_activations" in table_names:
            device_columns = {column["name"] for column in inspector.get_columns("device_activations")}
            _add_column_if_missing(conn, "device_activations", device_columns, "device_binding_hash", "VARCHAR")
            _add_column_if_missing(conn, "device_activations", device_columns, "binding_updated_at", "TIMESTAMP")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
