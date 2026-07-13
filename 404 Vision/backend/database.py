"""
CyberShield PostgreSQL Database Module
Manages connection to PostgreSQL and provides ORM models for evidence logs.
"""

from sqlalchemy import create_engine, Column, Integer, String, Text, BigInteger, Boolean, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.sql import func
from urllib.parse import quote_plus
import os

# Database Configuration
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "Roshan@0646")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "cybershield")

# URL-encode the password to handle special characters like @
DATABASE_URL = f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL, pool_pre_ping=True, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class EvidenceLog(Base):
    """ORM model for evidence_logs table — stores all scam/threat reports."""
    __tablename__ = "evidence_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_hash = Column(String(70), unique=True, nullable=False)
    category = Column(String(100), nullable=False)
    reason = Column(Text, nullable=False)
    target = Column(String(500), nullable=False)
    timestamp = Column(BigInteger, nullable=False)
    blockchain_logged = Column(Boolean, default=False)
    tx_hash = Column(String(70), default="")
    reporter = Column(String(100))
    location = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        """Convert ORM record to dictionary (matches the old JSON format for API compatibility)."""
        return {
            "evidence_hash": self.evidence_hash,
            "category": self.category,
            "reason": self.reason,
            "target": self.target,
            "timestamp": self.timestamp,
            "blockchain_logged": self.blockchain_logged,
            "tx_hash": self.tx_hash or "",
            "reporter": self.reporter,
            "location": self.location,
            "latitude": self.latitude,
            "longitude": self.longitude,
        }


def init_db():
    """Create tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Dependency: yields a database session and ensures it's closed after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
