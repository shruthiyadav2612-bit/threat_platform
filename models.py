"""
ORM models. MySQL-compatible (VARCHAR lengths set explicitly since MySQL
requires them for indexed columns; SQLite ignores the length silently).

Schema:
  cases          -- one row per analyzed email
  headers        -- 1:1 with cases, raw header forensics
  iocs           -- N:1 with cases; every IP/domain/URL/hash extracted.
                     This is the table the "seen before" + campaign logic
                     both query.
  campaigns      -- a cluster of cases linked by shared IOCs
  campaign_cases -- many:many join between campaigns and cases
"""

from sqlalchemy import (
    Column, Integer, String, Text, Float, DateTime, ForeignKey, Table
)
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base

campaign_cases = Table(
    "campaign_cases",
    Base.metadata,
    Column("campaign_id", Integer, ForeignKey("campaigns.id"), primary_key=True),
    Column("case_id", Integer, ForeignKey("cases.id"), primary_key=True),
)


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), default="")
    subject = Column(String(500), default="")
    sender = Column(String(255), default="")
    from_domain = Column(String(255), index=True, default="")
    upload_date = Column(DateTime, default=datetime.utcnow)
    threat_score = Column(Float, default=0.0)
    verdict = Column(String(50), default="")
    language = Column(String(50), default="English")
    email_hash = Column(String(64), default="")
    raw_email = Column(Text, default="")

    headers = relationship("EmailHeader", back_populates="case", uselist=False,
                            cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="case", cascade="all, delete-orphan")
    campaigns = relationship("Campaign", secondary=campaign_cases, back_populates="cases")


class EmailHeader(Base):
    __tablename__ = "headers"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), index=True)
    raw_headers = Column(Text, default="")
    spf = Column(String(20), default="none")
    dkim = Column(String(20), default="none")
    dmarc = Column(String(20), default="none")
    reply_to = Column(String(255), default="")
    anomalies = Column(Text, default="")  # JSON-encoded list

    case = relationship("Case", back_populates="headers")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), index=True)
    ioc_type = Column(String(20), index=True)  # ip | domain | url | hash
    value = Column(String(500), index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="iocs")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    shared_ioc = Column(String(500), default="")  # the IOC that linked the cases

    cases = relationship("Case", secondary=campaign_cases, back_populates="campaigns")
