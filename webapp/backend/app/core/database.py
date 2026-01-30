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

    # Seed checklist items if empty
    _seed_checklist()


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


def _seed_checklist():
    """Seed checklist items from JSON file if database is empty."""
    from app.models.checklist import ChecklistItem, Severity
    from pathlib import Path
    import json
    import logging

    db = SessionLocal()
    try:
        # Check if checklist already has items
        count = db.query(ChecklistItem).count()
        if count > 0:
            logging.info(f"Checklist already has {count} items, skipping seed")
            return

        # Find seed file - check multiple locations
        seed_paths = [
            Path("/app/seed_checklist.json"),  # Docker
            Path(__file__).resolve().parent.parent.parent / "seed_checklist.json",  # Local
        ]

        seed_file = None
        for path in seed_paths:
            if path.exists():
                seed_file = path
                break

        if not seed_file:
            logging.warning("Seed file not found, skipping checklist seed")
            return

        # Load and insert seed data
        with open(seed_file, "r", encoding="utf-8") as f:
            items = json.load(f)

        severity_map = {
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        for item_data in items:
            item = ChecklistItem(
                item_code=item_data["item_code"],
                asset_type=item_data["asset_type"],
                category=item_data.get("category"),
                title=item_data["title"],
                description=item_data.get("description"),
                severity=severity_map.get(item_data.get("severity", "medium"), Severity.MEDIUM),
            )
            db.add(item)

        db.commit()
        logging.info(f"Seeded {len(items)} checklist items")

    except Exception as e:
        logging.warning(f"Error seeding checklist: {e}")
        db.rollback()
    finally:
        db.close()
