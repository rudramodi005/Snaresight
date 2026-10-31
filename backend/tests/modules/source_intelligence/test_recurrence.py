"""Unit tests for dormancy and recurrence pattern detection."""

import unittest
from datetime import datetime, timezone, timedelta
from app.db.models.correlation import ActivitySessionModel
from app.modules.source_intelligence.recurrence import (
    detect_profile_recurrences,
    format_duration_display,
)


class TestProfileRecurrence(unittest.TestCase):
    """Verifies recurrence detection on returning Observed Source Profiles."""

    def test_duration_formatter(self):
        self.assertEqual(format_duration_display(3600), "1h")
        self.assertEqual(format_duration_display(86400 * 2 + 3600 * 3), "2d 3h")
        self.assertEqual(format_duration_display(120), "2m")

    def test_continuous_sessions_no_recurrence(self):
        t0 = datetime.now(timezone.utc)
        s1 = ActivitySessionModel(
            session_id="SESS-001",
            decoy_id="SSH-001",
            correlation_key="ck-001",
            source_address="198.51.100.10",
            protocol="SSH",
            first_observed_at=t0,
            last_activity_at=t0 + timedelta(minutes=15),
            ended_at=t0 + timedelta(minutes=15),
            first_ingested_at=t0,
            last_ingested_at=t0,
            session_status="CLOSED",
        )
        s2 = ActivitySessionModel(
            session_id="SESS-002",
            decoy_id="SSH-001",
            correlation_key="ck-002",
            source_address="198.51.100.10",
            protocol="SSH",
            first_observed_at=t0 + timedelta(minutes=30),
            last_activity_at=t0 + timedelta(minutes=45),
            ended_at=t0 + timedelta(minutes=45),
            first_ingested_at=t0,
            last_ingested_at=t0,
            session_status="CLOSED",
        )

        recurrences = detect_profile_recurrences("PROF-TEST", [s1, s2], dormancy_threshold_seconds=86400)
        self.assertEqual(len(recurrences), 0)

    def test_dormant_reactivation_detected(self):
        t0 = datetime.now(timezone.utc) - timedelta(days=5)
        s1 = ActivitySessionModel(
            session_id="SESS-OLD",
            decoy_id="WEB-001",
            correlation_key="ck-old",
            source_address="198.51.100.10",
            protocol="HTTP",
            first_observed_at=t0,
            last_activity_at=t0 + timedelta(hours=1),
            ended_at=t0 + timedelta(hours=1),
            first_ingested_at=t0,
            last_ingested_at=t0,
            session_status="CLOSED",
        )
        # 4 days gap
        t1 = t0 + timedelta(days=4)
        s2 = ActivitySessionModel(
            session_id="SESS-NEW",
            decoy_id="WEB-001",
            correlation_key="ck-new",
            source_address="198.51.100.10",
            protocol="HTTP",
            first_observed_at=t1,
            last_activity_at=t1 + timedelta(minutes=30),
            ended_at=t1 + timedelta(minutes=30),
            first_ingested_at=t1,
            last_ingested_at=t1,
            session_status="CLOSED",
        )

        recurrences = detect_profile_recurrences("PROF-TEST", [s1, s2], dormancy_threshold_seconds=86400)
        self.assertEqual(len(recurrences), 1)
        rec = recurrences[0]
        self.assertEqual(rec.profile_id, "PROF-TEST")
        self.assertEqual(rec.reactivation_session_id, "SESS-NEW")
        self.assertIn("3d", rec.dormant_interval_display)
        self.assertAlmostEqual(rec.pattern_similarity, 1.0)
