"""Database configuration and session management."""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}  # SQLite specific
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables."""
    from app.models import asset, checklist, assessment, exception, user
    Base.metadata.create_all(bind=engine)

    # Create default admin user if not exists
    _create_default_admin()


def _create_default_admin():
    """Create default admin user if not exists."""
    from app.models.user import User, UserRole
    from app.core.security import get_password_hash
    import logging

    db = SessionLocal()
    try:
        # Check if admin user exists
        admin = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
        if not admin:
            try:
                admin = User(
                    username=settings.ADMIN_USERNAME,
                    hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                    full_name="System Administrator",
                    role=UserRole.ADMIN,
                    is_active=True,
                )
                db.add(admin)
                db.commit()
                logging.info("Default admin user created")
            except Exception as e:
                logging.warning(f"Could not create default admin user: {e}")
                db.rollback()
    except Exception as e:
        logging.warning(f"Error during admin user check: {e}")
    finally:
        db.close()
