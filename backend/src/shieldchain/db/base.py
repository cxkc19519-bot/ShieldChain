from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


import shieldchain.incidents.persistence  # noqa: E402, F401
