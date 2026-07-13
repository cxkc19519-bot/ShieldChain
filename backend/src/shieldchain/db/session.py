import structlog
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

logger = structlog.get_logger()


def create_engine_from_url(database_url: str) -> Engine:
    is_sqlite = make_url(database_url).get_backend_name() == "sqlite"
    connect_args = {"check_same_thread": False} if is_sqlite else {}
    engine = create_engine(database_url, connect_args=connect_args)
    if is_sqlite:

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=5000")
            finally:
                cursor.close()

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine)


def check_database(engine: Engine) -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        logger.warning("database_check_failed")
        return False
    return True
