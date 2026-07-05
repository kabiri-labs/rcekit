"""Unit tests for RCEPayloadGenerator.

Run with: python -m unittest discover -s tests  (no third-party deps required)

These tests lock in the properties that matter to the real consumer of this
tool: every emitted payload should be unique and executable/decodable, the
removed obfuscation transforms must stay removed, and the safety filters and
detection mode must behave as documented.
"""

import sys
import tempfile
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

    def test_no_watermark_by_default(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum", "code_execution"],
            selected_environments=["unix", "python"],
        ))
        self.assertTrue(records)
        self.assertFalse(any("RCEPayloadGen-ID" in r.payload for r in records))

    def test_code_payloads_not_quote_wrapped(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"],
            selected_environments=["python"],
            selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        payloads = [r.payload for r in records]
        # The raw snippet must appear executable, never wrapped into an inert
        # string literal such as "os.system('whoami')".
        self.assertIn("os.system('whoami')", payloads)
        self.assertNotIn('"os.system(\'whoami\')"', payloads)

    def test_ssti_delimiters_preserved(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"],
            selected_environments=["python", "java"],
            selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        payloads = [r.payload for r in records]
        # SSTI payloads must keep their template delimiters intact.
        self.assertIn("{{7*7}}", payloads)
        self.assertTrue(any(p.startswith("${") for p in payloads))

    def test_waf_bypass_payloads_are_quote_free(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["waf_bypass"],
            selected_environments=["unix"],
            selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        self.assertTrue(records)
        self.assertTrue(any("${IFS}" in r.payload for r in records))
        # The whole point is command injection without quote characters.
        for record in records:
            self.assertNotIn('"', record.payload)
            self.assertNotIn("'", record.payload)

    def test_oob_requires_domain_and_gets_unique_tokens(self):
        # Without an OOB domain, {oob} payloads are dropped entirely.
        without = list(self.gen.generate_payload_records(
            selected_categories=["oob"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
        ))
        self.assertEqual(without, [])

        # With a domain, each record carries a unique correlation token/host.
        with_dom = list(self.gen.generate_payload_records(
            selected_categories=["oob"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
            oob_domain="oast.example.com",
        ))
        self.assertTrue(with_dom)
        tokens = [r.token for r in with_dom]
        self.assertTrue(all(tokens), "every OOB record must carry a token")
        self.assertEqual(len(tokens), len(set(tokens)), "OOB tokens must be unique")
        for record in with_dom:
            self.assertIn(record.oob_host, record.payload)
            self.assertTrue(record.oob_host.endswith(".oast.example.com"))
            self.assertEqual(record.expected_channel, "interactsh")

    def test_mongodb_and_graphql_sinks_present(self):
        mongo = [r for r in self.gen.generate_payload_records(
            selected_categories=["nosql_injection"], selected_environments=["mongodb"],
            selected_contexts=["raw"], selected_encodings=["none"],
        )]
        self.assertTrue(mongo)
        self.assertTrue(all(r.environment == "mongodb" for r in mongo))
        self.assertTrue(any("$where" in r.payload for r in mongo))
        self.assertTrue(any("$function" in r.payload for r in mongo))

        gql = [r for r in self.gen.generate_payload_records(
            selected_categories=["graphql_injection"], selected_environments=["graphql"],
            selected_contexts=["raw"], selected_encodings=["none"],
        )]
        self.assertTrue(gql)
        self.assertTrue(any("__schema" in r.payload for r in gql))
        # GraphQL / Mongo payloads must not be prefixed with shell separators.
        self.assertTrue(all(not r.payload.startswith((";", "|", "&")) for r in mongo + gql))

    def test_java_expression_sinks_added(self):
        sinks = {
            r.sink for r in self.gen.generate_payload_records(
                selected_categories=["code_execution"], selected_environments=["java"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
        }
        self.assertTrue({"spel", "ognl", "groovy"}.issubset(sinks))

    def test_profile_filter_drops_denied_chars_and_long_payloads(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum", "file_operations", "waf_bypass"],
            selected_environments=["unix"], selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        filtered = list(self.gen._filter_by_profile(records, deny_chars="'\"", max_length=40))
        self.assertTrue(filtered)
        self.assertLess(len(filtered), len(records), "the filter must actually drop something")
        for record in filtered:
            self.assertNotIn('"', record.payload)
            self.assertNotIn("'", record.payload)
            self.assertLessEqual(len(record.payload), 40)
        # A quote-free WAF-bypass payload should survive the quote filter.
        self.assertTrue(any("${IFS}" in r.payload for r in filtered))

    def test_target_profile_file_applies_end_to_end(self):
        profile = Path(__file__).resolve().parent.parent / "profiles" / "quote-filtered-unix.json"
        self.assertTrue(profile.exists(), "example profile should ship with the repo")
        import json
        spec = json.loads(profile.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "p.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out),
                deny_chars="".join(spec["deny_chars"]),
                max_length=spec["max_length"],
                selected_environments=spec["environments"],
                selected_contexts=spec["contexts"],
                selected_categories=spec["categories"],
                selected_encodings=spec["encodings"],
                oob_domain=spec.get("oob_domain"),
            )
            lines = out.read_text().splitlines()
            self.assertTrue(lines)
            for line in lines:
                self.assertNotIn('"', line)
                self.assertNotIn("'", line)
                self.assertLessEqual(len(line), spec["max_length"])

    def test_burp_export_writes_context_wordlists(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            count = self.gen.save_payloads_to_file(
                file_path=str(out), output_format="burp",
                selected_categories=["basic_enum"], selected_environments=["unix"],
            )
            self.assertGreater(count, 0)
            outdir = Path(tmp) / "run_burp"
            self.assertTrue((outdir / "payloads-all.txt").exists())
            self.assertTrue((outdir / "request.txt").exists())
            self.assertTrue(any(outdir.glob("payloads-*.txt")))

    def test_nuclei_export_writes_valid_templates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            count = self.gen.save_payloads_to_file(
                file_path=str(out), output_format="nuclei",
                selected_environments=["unix"], mode="detection",
                oob_domain="x.oast.pro", max_safety="stateful", include_blocking=True,
            )
            self.assertGreater(count, 0)
            outdir = Path(tmp) / "run_nuclei"
            templates = list(outdir.glob("*.yaml"))
            self.assertTrue(templates)
            joined = "\n".join(t.read_text() for t in templates)
            # OOB templates must use the interactsh placeholder, not a real host.
            self.assertIn("{{interactsh-url}}", joined)
            self.assertIn("interactsh_protocol", joined)
            # Time templates normalise sleeps and never include hanging tails.
            time_files = list(outdir.glob("*-time.yaml"))
            if time_files:
                time_text = "\n".join(t.read_text() for t in time_files)
                self.assertIn("duration>=6", time_text)
                self.assertNotIn("tail -f", time_text)


if __name__ == "__main__":
    unittest.main()
