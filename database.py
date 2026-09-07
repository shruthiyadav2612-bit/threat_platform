"""
Database connection.

Production: set DATABASE_URL to your MySQL instance, e.g.
    mysql+pymysql://user:password@localhost:3306/threat_platform

Local/demo (no MySQL server needed): leave DATABASE_URL unset — falls back
to a SQLite file (threat_platform.db) with the same schema, so the whole
app runs with zero external setup. Swapping to MySQL later needs no code
changes, only the environment variable.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./threat_platform.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
