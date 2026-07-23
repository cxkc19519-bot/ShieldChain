from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


import shieldchain.agents.persistence  # noqa: E402, F401
import shieldchain.incidents.persistence  # noqa: E402, F401
import shieldchain.rag.persistence  # noqa: E402, F401
import shieldchain.tools.persistence  # noqa: E402, F401
