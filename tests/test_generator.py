"""Unit tests for RCEPayloadGenerator.

Run with: python -m unittest discover -s tests  (no third-party deps required)

These tests lock in the properties that matter to the real consumer of this
tool: every emitted payload should be unique and executable/decodable, the
removed obfuscation transforms must stay removed, and the safety filters and
detection mode must behave as documented.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rce_payload_gen import RCEPayloadGenerator  # noqa: E402


class GeneratorTestCase(unittest.TestCase):
    def setUp(self):
        self.gen = RCEPayloadGenerator()

    def test_templates_loaded(self):
        self.assertTrue(self.gen.payload_categories, "payload categories should load")
        self.assertIn("basic_enum", self.gen.payload_categories)
        self.assertTrue(self.gen.detection_payloads, "detection payloads should load")

    def test_removed_encodings_are_gone(self):
        removed = {"rot13", "rot13_then_base64", "insert_special_chars",
                   "xor_polymorphic", "chunk_shuffle"}
        self.assertEqual(removed & set(self.gen.encoding_methods), set())

    def test_no_garbage_or_non_executable_markers(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"],
            selected_environments=["unix", "windows"],
        ))
        self.assertTrue(records)
        for rec in records:
            self.assertNotIn("XOR(", rec.payload)
            self.assertNotIn("shuffle::", rec.payload)

    def test_payloads_are_unique(self):
        payloads = [r.payload for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum", "file_operations"],
            selected_environments=["unix"],
        )]
        self.assertEqual(len(payloads), len(set(payloads)), "no duplicate payloads")

    def test_random_case_only_for_case_insensitive_runners(self):
        records = [r for r in self.gen.generate_payload_records(
            selected_encodings=["random_case"],
        ) if r.encoding == "random_case"]
        self.assertTrue(records, "random_case should still apply somewhere")
        for rec in records:
            self.assertIn(rec.runner, self.gen.case_insensitive_runners)

    def test_encoding_compatibility_rules(self):
        self.assertFalse(self.gen._encoding_is_compatible("random_case", "sh"))
        self.assertFalse(self.gen._encoding_is_compatible("random_case", "python"))
        self.assertTrue(self.gen._encoding_is_compatible("random_case", "cmd"))
        self.assertTrue(self.gen._encoding_is_compatible("base64", "python"))

    def test_detection_mode_is_safe(self):
        records = list(self.gen.generate_payload_records(
            mode="detection", max_safety="safe",
        ))
        self.assertTrue(records)
        for rec in records:
            self.assertEqual(rec.mode, "detection")
            self.assertEqual(rec.safety, "safe")

    def test_max_safety_excludes_higher_tiers(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["persistence"],
            selected_environments=["unix"],
            max_safety="safe",
        ))
        self.assertEqual(records, [], "persistence is stateful and must be filtered at safe tier")

    def test_blocking_excluded_by_default(self):
        records = list(self.gen.generate_payload_records(
            mode="detection", include_blocking=False, max_safety="stateful",
        ))
        self.assertTrue(all(not r.blocking for r in records))

    def test_watermark_embedded_when_token_present(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"],
            selected_environments=["unix"],
            selected_contexts=["raw"],
            selected_encodings=["none"],
            watermark_token="TESTTOKN",
        ))
        self.assertTrue(records)
        self.assertTrue(any("TESTTOKN" in r.payload for r in records))


if __name__ == "__main__":
    unittest.main()
