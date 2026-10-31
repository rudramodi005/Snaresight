"""Database initialization seeder for baseline default accounts in development environments.

Creates initial baseline accounts with salted bcrypt hashes if no users exist.
"""

from sqlalchemy.orm import Session
from app.db.models.security import UserModel
from app.modules.security.crypto import hash_password
from app.modules.security.permissions import Role


def seed_default_users(db: Session) -> None:
    """Seeds initial ADMIN, ANALYST, and VIEWER accounts if users table is empty."""
    try:
        count = db.query(UserModel).count()
        if count > 0:
            return

        users = [
            UserModel(
                username="soc_admin",
                email="admin@snaresight.local",
                full_name="SOC Administrator",
                hashed_password=hash_password("SnareAdmin2026!"),
                role=Role.ADMIN.value,
                is_active=True,
            ),
            UserModel(
                username="soc_lead",
                email="soc_lead@snaresight.local",
                full_name="Senior SOC Investigator",
                hashed_password=hash_password("SnareAnalyst2026!"),
                role=Role.ANALYST.value,
                is_active=True,
            ),
            UserModel(
                username="soc_viewer",
                email="viewer@snaresight.local",
                full_name="Security Auditor (Read-Only)",
                hashed_password=hash_password("SnareViewer2026!"),
                role=Role.VIEWER.value,
                is_active=True,
            ),
            UserModel(
                username="analyst",
                email="analyst@snaresight.local",
                full_name="Lead SOC Analyst",
                hashed_password=hash_password("SecurePassword123!"),
                role=Role.ANALYST.value,
                is_active=True,
            ),
        ]
        db.add_all(users)
        db.commit()
    except Exception:
        db.rollback()

