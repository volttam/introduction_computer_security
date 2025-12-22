from __future__ import annotations

from typing import Generator

from sqlmodel import SQLModel, Session, create_engine
from sqlalchemy.engine import Engine


class DBManager:
    """
    Owns the SQLModel engine and provides DB initialization + sessions.
    """
    def __init__(self, database_url: str = "sqlite:///./data.db", echo: bool = False):
        self.database_url = database_url
        self.echo = echo
        self._initialized: bool = False
        self._engine = create_engine(self.database_url, echo=self.echo,)
        self.init_db()

    @property
    def engine(self) -> Engine:
        return self._engine

    def init_db(self) -> None:
        """
        Create tables if they don't exist.
        """
        if not self._initialized:
            SQLModel.metadata.create_all(self.engine)
            self._initialized = True

    def get_session(self) -> Session:
        """
        Get db session directly.
        """
        session = Session(self.engine)
        return session


