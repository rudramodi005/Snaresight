"""Integration tests for ATT&CK dry-run, transactional import, idempotency, and rollback."""

import json
import unittest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.modules.mitre.exceptions import MitreImportError, MitreVersionError
from app.modules.mitre.importer import MitreImporter
from app.modules.mitre.models import (
    AttackDatasetVersionModel,
    AttackTacticModel,
    AttackTechniqueModel,
    AttackSubtechniqueModel,
    AttackRelationshipModel,
    AttackImportRunModel,
)
from app.modules.mitre.service import MitreService
from app.modules.mitre.versioning import MitreVersioningEngine


class TestMitreImporter(unittest.TestCase):
    """Test suite verifying transactional import, idempotency, diffing, and rollback."""

    def setUp(self):
        """Initializes isolated in-memory database."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        # Load verified sample STIX bundle fixture
        fixture_path = Path(__file__).resolve().parent.parent.parent.parent / "app" / "modules" / "mitre" / "data" / "enterprise-attack-v14.1.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.sample_bundle_json = f.read()
            self.sample_bundle_dict = json.loads(self.sample_bundle_json)

    def tearDown(self):
        self.db.close()

    def test_dry_run_does_not_modify_database(self):
        """IMPORT-01: Dry-run parse produces preview diff without inserting tactics or techniques."""
        preview = MitreImporter.execute_dry_run(
            db=self.db,
            raw_content=self.sample_bundle_json,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
        )
        self.assertTrue(preview.is_valid)
        self.assertGreater(preview.total_objects, 0)
        self.assertEqual(preview.tactics_discovered, 8)
        self.assertGreaterEqual(preview.techniques_discovered, 10)

        # Assert no techniques or tactics committed to DB
        tactic_count = self.db.query(AttackTacticModel).count()
        tech_count = self.db.query(AttackTechniqueModel).count()
        self.assertEqual(tactic_count, 0)
        self.assertEqual(tech_count, 0)

        # Verify dry-run audit entry was recorded
        dry_run_runs = self.db.query(AttackImportRunModel).filter(AttackImportRunModel.is_dry_run.is_(True)).all()
        self.assertEqual(len(dry_run_runs), 1)

    def test_valid_import_succeeds_and_activates_version(self):
        """IMPORT-02: Valid import commits all objects and marks version active."""
        receipt = MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_json,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
            activate_immediately=True,
        )
        self.assertEqual(receipt.status, "COMPLETED")
        self.assertEqual(receipt.dataset_version, "14.1")

        # Verify DB counts
        self.assertEqual(self.db.query(AttackTacticModel).count(), 8)
        self.assertGreaterEqual(self.db.query(AttackTechniqueModel).count(), 10)
        self.assertGreaterEqual(self.db.query(AttackSubtechniqueModel).count(), 4)
        self.assertEqual(self.db.query(AttackRelationshipModel).count(), 4)

        # Verify active version
        active_ver = MitreVersioningEngine.get_active_version(self.db)
        self.assertIsNotNone(active_ver)
        self.assertEqual(active_ver.version, "14.1")
        self.assertTrue(active_ver.is_active)

    def test_repeated_import_is_idempotent(self):
        """IMPORT-03: Repeated import of identical dataset returns cached receipt without duplicates."""
        receipt1 = MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_json,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
        )
        tech_count_1 = self.db.query(AttackTechniqueModel).count()

        receipt2 = MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_json,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
        )
        tech_count_2 = self.db.query(AttackTechniqueModel).count()

        self.assertEqual(tech_count_1, tech_count_2)
        self.assertIn("idempotent", receipt2.import_run_id)

    def test_updated_descriptions_are_detected_and_updated(self):
        """IMPORT-04: Re-importing dataset with modified description updates the technique in place."""
        MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_dict,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
        )

        # Mutate description of T1110 in dict
        mutated_dict = json.loads(json.dumps(self.sample_bundle_dict))
        for obj in mutated_dict["objects"]:
            if obj.get("id") == "attack-pattern--b1732e74-279c-485c-8b83-dbb7ef382b6b":
                obj["description"] = "UPDATED BRUTE FORCE DESCRIPTION"

        receipt_v15 = MitreImporter.execute_import(
            db=self.db,
            raw_content=mutated_dict,
            source_filename="enterprise-attack-v15.0.json",
            dataset_version="15.0",
        )
        self.assertEqual(receipt_v15.status, "COMPLETED")

        t1110 = self.db.query(AttackTechniqueModel).filter(AttackTechniqueModel.technique_id == "T1110").first()
        self.assertEqual(t1110.description, "UPDATED BRUTE FORCE DESCRIPTION")

    def test_rollback_restores_previous_active_version(self):
        """IMPORT-05: Rollback safely reverts active catalogue to prior release."""
        # 1. Import version 14.1
        MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_dict,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
            activate_immediately=True,
        )

        # 2. Import version 15.0 as active
        mutated_v15 = json.loads(json.dumps(self.sample_bundle_dict))
        MitreImporter.execute_import(
            db=self.db,
            raw_content=mutated_v15,
            source_filename="enterprise-attack-v15.0.json",
            dataset_version="15.0",
            activate_immediately=True,
        )

        active = MitreVersioningEngine.get_active_version(self.db)
        self.assertEqual(active.version, "15.0")

        # 3. Rollback
        prev_ver, restored_ver = MitreVersioningEngine.rollback_version(self.db, target_version="14.1")
        self.assertEqual(prev_ver, "15.0")
        self.assertEqual(restored_ver, "14.1")

        active_after = MitreVersioningEngine.get_active_version(self.db)
        self.assertEqual(active_after.version, "14.1")

    def test_failed_import_does_not_corrupt_active_catalogue(self):
        """IMPORT-06: Malformed candidate import aborts and rolls back without touching active version."""
        # Seed good active version 14.1
        MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_dict,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
            activate_immediately=True,
        )

        # Attempt to import bad bundle
        bad_bundle = {"type": "not_a_bundle"}
        with self.assertRaises(MitreImportError):
            MitreImporter.execute_import(
                db=self.db,
                raw_content=bad_bundle,
                source_filename="corrupted.json",
                dataset_version="99.9",
            )

        # Active catalogue remains 14.1
        active = MitreVersioningEngine.get_active_version(self.db)
        self.assertEqual(active.version, "14.1")
        self.assertTrue(active.is_active)


if __name__ == "__main__":
    unittest.main()
