"""Unit tests for the coverage benchmark harness (tests/bench/runner.py).

Run with the rest of the suite: python -m unittest discover -s tests

The bench *cases* need Docker and are not run here. The harness itself does not:
a case with no `compose` key points at a target that is already up, so the whole
run-and-judge path is exercised end to end against a local socket. What Docker
would add is `docker compose up` — the one step these tests skip.

The properties locked in are the ones that decide whether the benchmark measures
anything at all: a case without a negative control is rejected, a control that
expects `confirmed` is rejected, and a run that never tested anything is never
reported as a clean negative.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

TESTS_DIR = Path(__file__).resolve().parent
# Repo root for `rcekit`, this directory for `test_generator`'s local_target
# helper, and bench/ for the harness itself. Spelled out so the module imports
# the same way under `unittest discover -s tests` and `-m unittest tests....`.
sys.path.insert(0, str(TESTS_DIR.parent))
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TESTS_DIR / "bench"))

import runner  # noqa: E402
from test_generator import local_target, sh_popen  # noqa: E402

BENCH_ROOT = Path(__file__).resolve().parent / "bench"


def minimal_case(**overrides):
    case = {
        "name": "example",
        "rce_class": "OS command injection",
        "target": "Example 1.0",
        # The default target is a port nothing listens on, which is the point for
        # the tests that use it as-is. It is also why the budget flags are here:
        # a closed loopback port answers with a RST on Linux and is silently
        # *dropped* on Windows, where each probe waits out the SYN retry instead
        # -- measured at ~2s per probe on this loopback. Unbounded, a case runs
        # the whole ladder twice, once for the vulnerable half and once for the
        # control, and pays that 2s every time: the unreachable-target case below
        # measured 1800s that way, against 9.1s bounded. Three probes prove
        # "nothing reached the target" exactly as well as forty do.
        #
        # Tests that override `invocation` with a live target are unaffected.
        "invocation": ["--verify-url", "http://127.0.0.1:1/?x=FUZZ", "--methods", "reflected",
                       "--max-payloads", "3", "--verify-timeout", "1"],
        "expect": "confirmed",
        "negative_control": {"invocation": ["--verify-url", "http://127.0.0.1:1/?y=FUZZ",
                                            "--methods", "reflected",
                                            "--max-payloads", "3", "--verify-timeout", "1"],
                             "expect": "negative"},
    }
    case.update(overrides)
    return case


class CaseValidationTestCase(unittest.TestCase):
    """A malformed case must fail loudly. A benchmark that quietly skips cases
    reports fewer failures than reality — the one thing it must never do."""

    def test_a_well_formed_case_validates(self):
        self.assertEqual(runner.validate_case(minimal_case())["name"], "example")

    def test_every_required_key_is_enforced(self):
        for key in runner.REQUIRED_KEYS:
            case = minimal_case()
            del case[key]
            with self.assertRaises(runner.CaseError, msg=f"missing {key} must be rejected") as ctx:
                runner.validate_case(case)
            self.assertIn(key, str(ctx.exception))

    def test_a_case_without_a_negative_control_is_rejected(self):
        case = minimal_case()
        del case["negative_control"]
        with self.assertRaises(runner.CaseError):
            runner.validate_case(case)

    def test_a_control_that_reuses_the_vulnerable_invocation_is_rejected(self):
        # A "control" that runs the identical command against the identical
        # target measures nothing; it just doubles the runtime.
        case = minimal_case(negative_control={"expect": "negative"})
        with self.assertRaises(runner.CaseError) as ctx:
            runner.validate_case(case)
        self.assertIn("measures nothing", str(ctx.exception))

    def test_an_explicitly_copied_control_invocation_is_rejected_too(self):
        # Key presence is not the test — what the control would actually run is.
        # Spelling the vulnerable invocation out again is the same non-control as
        # omitting it, and this case expects `needs-review`, where a duplicated
        # control would otherwise pass and prove nothing.
        case = minimal_case(
            expect="needs-review",
            negative_control={"invocation": list(minimal_case()["invocation"]),
                              "expect": "needs-review"})
        with self.assertRaises(runner.CaseError) as ctx:
            runner.validate_case(case)
        self.assertIn("measures nothing", str(ctx.exception))

    def test_the_same_invocation_against_a_different_build_is_a_valid_control(self):
        # The patched-build control: identical command, different target. That is
        # the strongest control there is, so the duplication check must not
        # mistake it for a duplicate.
        case = minimal_case(vulhub_path="webmin/CVE-2019-15107",
                            negative_control={"vulhub_path": "webmin/patched",
                                              "expect": "negative"})
        self.assertEqual(runner.validate_case(case)["name"], "example")

    def test_a_control_may_not_expect_an_outcome_that_never_reached_the_target(self):
        # `error` and `nothing-tested` mean nothing was exercised, so such a
        # control would stay green with the detection engine entirely broken.
        for expectation in ("error", "nothing-tested"):
            case = minimal_case(negative_control={"invocation": ["--bogus"],
                                                  "expect": expectation})
            with self.assertRaises(runner.CaseError, msg=expectation) as ctx:
                runner.validate_case(case)
            self.assertIn("never exercised", str(ctx.exception))

    def test_a_control_may_expect_any_exercised_outcome(self):
        for expectation in runner.CONTROL_EXPECTATIONS:
            case = minimal_case(negative_control={"invocation": ["--other"],
                                                  "expect": expectation})
            self.assertEqual(runner.validate_case(case)["name"], "example", expectation)

    def test_the_vulnerable_half_may_still_expect_error(self):
        # Narrowing control expectations must not narrow the case's own: "an
        # unreachable target reports error, not negative" is worth pinning.
        self.assertEqual(runner.validate_case(minimal_case(expect="error"))["name"], "example")

    def test_validation_and_execution_read_the_same_control_plan(self):
        # The duplication the validator rejects must be the duplication the
        # runner would have run, so both go through control_plan.
        case = minimal_case(compose=["docker", "compose", "up", "-d"],
                            negative_control={"invocation": ["--other"], "expect": "negative"})
        invocation, setup = runner.control_plan(case)
        self.assertEqual(invocation, ["--other"])
        self.assertEqual(runner.target_setup(setup), runner.target_setup(case))

    def test_a_control_expecting_confirmed_is_rejected(self):
        case = minimal_case(negative_control={"invocation": ["--x"], "expect": "confirmed"})
        with self.assertRaises(runner.CaseError) as ctx:
            runner.validate_case(case)
        self.assertIn("contradiction", str(ctx.exception))

    def test_an_unknown_expectation_is_rejected(self):
        with self.assertRaises(runner.CaseError):
            runner.validate_case(minimal_case(expect="vulnerable"))

    def test_shipped_cases_all_validate(self):
        paths = runner.discover_cases(BENCH_ROOT / "cases")
        self.assertTrue(paths, "no bench cases found")
        for path in paths:
            runner.load_case(path)

    def test_shipped_cases_reference_files_that_exist(self):
        # A case pointing at a missing captured request fails only once someone
        # has waited for a container to boot. Catch it here instead.
        for path in runner.discover_cases(BENCH_ROOT / "cases"):
            case = runner.load_case(path)
            invocations = [case["invocation"], case["negative_control"].get("invocation", [])]
            for invocation in invocations:
                for arg in runner.expand_paths(invocation):
                    if arg.startswith(str(BENCH_ROOT)):
                        self.assertTrue(Path(arg).exists(), f"{path.name} references {arg}")


class ReportCheckingTestCase(unittest.TestCase):
    """Turning one RCEKit run into pass/fail."""

    def test_matching_verdict_passes(self):
        ok, detail = runner.check_report({"verdict": "confirmed", "counts": {"confirmed": 2}},
                                         "confirmed")
        self.assertTrue(ok)
        self.assertIn("confirmed", detail)

    def test_mismatched_verdict_fails_with_the_counts(self):
        ok, detail = runner.check_report(
            {"verdict": "negative", "counts": {"negative": 9}}, "confirmed")
        self.assertFalse(ok)
        self.assertIn("expected confirmed, got negative", detail)
        self.assertIn("negative=9", detail)

    def test_nothing_tested_is_not_a_negative(self):
        # The distinction the whole harness rests on: a run that built no probes
        # tested nothing, and must not satisfy a case expecting `negative`.
        ok, _ = runner.check_report({"verdict": "nothing-tested", "counts": {}}, "negative")
        self.assertFalse(ok)

    def test_expect_method_pins_the_method_that_confirmed(self):
        report = {"verdict": "confirmed", "counts": {"confirmed": 1},
                  "probes": [{"verdict": "confirmed", "method": "eval",
                              "environment": "unix", "context": "raw"}]}
        self.assertTrue(runner.check_report(report, "confirmed", "eval")[0])
        self.assertTrue(runner.check_report(report, "confirmed", "eval/unix/raw")[0])
        ok, detail = runner.check_report(report, "confirmed", "reflected")
        self.assertFalse(ok, "a confirmation from the wrong method must not satisfy the case")
        self.assertIn("not 'reflected'", detail)


class MarkdownTableTestCase(unittest.TestCase):
    def test_table_shows_verdict_control_and_result(self):
        table = runner.render_markdown([
            {"name": "a", "rce_class": "OS command injection", "target": "Webmin 1.910",
             "verdict": "confirmed", "control_verdict": "needs-review",
             "methods": ["reflected", "reflected/unix/raw"], "passed": True},
            {"name": "b", "rce_class": "Expression injection", "target": "Struts2",
             "verdict": "negative", "control_verdict": "negative",
             "methods": [], "passed": False},
        ])
        self.assertIn("| Webmin 1.910 | `reflected` | **`confirmed`** | `needs-review` | pass |",
                      table)
        self.assertIn("**FAIL**", table)
        # The composite signature is detail for a failure message, not for the
        # README table.
        self.assertNotIn("reflected/unix/raw", table)


class CaseTimeoutTestCase(unittest.TestCase):
    """A case may buy itself more clock, because the methods do not cost alike.

    The Webmin tier-ceiling control fires a timing regression and every probe in
    it is a real sleep: measured at 1174s against the live target, against a
    900s default. Cut short, the run reports `error` — so the case failed as
    though the tool had broken rather than as though the clock had run out, and
    the benchmark said nothing true about the thing it exists to check."""

    def _captured(self, case):
        """The timeout each half would be given, without running anything."""
        seen = []

        def fake_run_rcekit(invocation, python=None, timeout=900.0, run_in=None):
            seen.append(timeout)
            return {"verdict": "negative", "counts": {"negative": 1}, "probes": []}

        original = runner.run_rcekit
        runner.run_rcekit = fake_run_rcekit
        try:
            runner.run_case(case)
        finally:
            runner.run_rcekit = original
        return seen

    def test_without_a_timeout_both_halves_get_the_default(self):
        self.assertEqual(self._captured(minimal_case()), [900.0, 900.0])

    def test_a_case_timeout_covers_both_halves(self):
        self.assertEqual(self._captured(minimal_case(timeout=1500)), [1500, 1500])

    def test_an_explicit_zero_is_honoured_rather_than_defaulted_away(self):
        # `timeout or 900.0` replaced an explicit 0 with the fifteen-minute
        # default, so a case deliberately bounded to no time at all ran far
        # longer than it asked for. Validation does not reject zero and
        # run_rcekit already handles the expiry, so zero has to mean zero.
        self.assertEqual(self._captured(minimal_case(timeout=0)), [0, 0])

    def test_the_control_may_raise_its_own(self):
        # The common shape: the control is the slower half, because the method
        # that must NOT be promoted is usually the expensive one.
        case = minimal_case()
        case["negative_control"]["timeout"] = 2400
        self.assertEqual(self._captured(case), [900.0, 2400])

    def test_a_control_timeout_wins_over_the_case_one(self):
        case = minimal_case(timeout=1200)
        case["negative_control"]["timeout"] = 2400
        self.assertEqual(self._captured(case), [1200, 2400])

    def test_the_shipped_webmin_control_carries_one(self):
        # Without it this case cannot pass on any machine: the measured run is
        # longer than the default allows.
        case = runner.load_case(BENCH_ROOT / "cases" / "webmin-cve-2019-15107.json")
        self.assertGreater(case["negative_control"]["timeout"], 1174,
                           "the control's budget must exceed its measured runtime")


class ContainerisedRunTestCase(unittest.TestCase):
    """`run_in` puts the run inside the target's own network.

    A callback method needs the target's resolver to reach RCEKit's listener,
    and a resolver asks UDP 53. Rather than demand that port on the host, the
    run happens where it is free.
    """

    RUN_IN = {"image": "python:3.11-slim", "network": "bench_net", "ip": "172.28.0.10"}

    def _command(self, invocation, run_in=None, observe=None):
        """The argv run_rcekit would execute, without executing it."""
        seen = {}

        class _FakeSubprocess:
            @staticmethod
            def run(argv, capture_output=False, text=False, timeout=None, cwd=None):
                seen["argv"] = list(argv)
                if observe:
                    observe(argv, seen)
                return SimpleNamespace(returncode=0, stdout="", stderr="")

        original = runner.subprocess
        runner.subprocess = _FakeSubprocess
        try:
            runner.run_rcekit(invocation, run_in=run_in)
        finally:
            runner.subprocess = original
        return seen["argv"]

    def test_without_run_in_the_tool_runs_on_the_host_as_before(self):
        argv = self._command(["--verify-url", "http://x/?a=FUZZ"])
        self.assertNotIn("docker", argv)
        self.assertIn(str(runner.RCEKIT), argv)

    def test_the_container_joins_the_named_network_at_the_named_address(self):
        argv = self._command(["--verify-url", "http://solr:8983/?a=FUZZ"], self.RUN_IN)
        self.assertEqual(argv[:3], ["docker", "run", "--rm"])
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "bench_net")
        self.assertEqual(argv[argv.index("--ip") + 1], "172.28.0.10")
        self.assertIn(self.RUN_IN["image"], argv)

    def test_the_repository_is_mounted_read_only(self):
        # The container runs the tool; it has no business changing it.
        argv = self._command(["--verify-url", "http://solr:8983/?a=FUZZ"], self.RUN_IN)
        mounts = [argv[i + 1] for i, arg in enumerate(argv) if arg == "-v"]
        repo = [m for m in mounts if m.endswith(f"{runner.CONTAINER_REPO}:ro")]
        self.assertTrue(repo, f"the repository is not mounted read-only: {mounts}")

    def test_path_tokens_resolve_to_the_mount_point_not_the_host(self):
        # A host path is meaningless inside the container. This is the whole
        # reason cases name files with tokens rather than paths.
        argv = self._command(["-r", "{bench}/requests/webmin.txt"], self.RUN_IN)
        self.assertIn(f"{runner.CONTAINER_REPO}/tests/bench/requests/webmin.txt",
                      [arg.replace("\\", "/") for arg in argv])
        self.assertNotIn(str(runner.BENCH_ROOT), argv)

    def test_the_results_file_exists_before_the_container_starts(self):
        """The container writes the results, and it is not this process.

        With Docker's user-namespace remapping, container root is a
        subordinate host UID, so a 0700 directory owned by the runner is not
        writable from inside. The file never appeared, `run_rcekit` found no
        JSON, and the case reported `nothing-tested` -- detection found
        nothing, rather than the channel having been shut. Naming the wrong
        cause is the failure this harness exists to avoid.

        Pre-creating the file is what makes it writable without granting the
        directory away, so this pins the file being there when the container
        is launched rather than the mode bits, which Windows does not keep.
        """
        landed = {}

        def observe(argv, seen):
            out = argv[argv.index("--detect-json") + 1]
            # rsplit, not split: a Windows mount reads `C:\\path:/out`, and
            # splitting on every colon eats the drive letter.
            host_dir = [argv[i + 1].rsplit(":", 1)[0] for i, a in enumerate(argv)
                        if a == "-v" and argv[i + 1].endswith(runner.CONTAINER_OUT)]
            landed["container_path"] = out
            landed["exists"] = os.path.isfile(
                os.path.join(host_dir[0], os.path.basename(out)))

        self._command(["--verify-url", "http://solr:8983/?a=FUZZ"], self.RUN_IN,
                      observe=observe)
        self.assertEqual(landed["container_path"],
                         f"{runner.CONTAINER_OUT}/results.json")
        self.assertTrue(landed["exists"],
                        "the results file was not created before the container ran")

    def test_run_in_needs_an_image_and_a_network(self):
        for missing in ("image", "network"):
            run_in = {key: value for key, value in self.RUN_IN.items() if key != missing}
            with self.subTest(missing=missing):
                with self.assertRaises(runner.CaseError) as raised:
                    runner.validate_case(minimal_case(run_in=run_in))
                self.assertIn(missing, str(raised.exception))

    def test_run_in_must_be_an_object(self):
        with self.assertRaises(runner.CaseError):
            runner.validate_case(minimal_case(run_in="python:3.11-slim"))

    def test_a_tier_the_engine_can_emit_is_a_tier_a_case_can_expect(self):
        """The whitelists were written out by hand and had drifted.

        Neither `lookup-sink` nor `deserialization-sink` was in either, so a
        case for `lookup` or `deser` could not be loaded, let alone run -- and
        nobody found out until one was written. Both read from
        DETECTION_METHODS now, so this cannot drift again.
        """
        import rcekit
        for name, method in rcekit.DETECTION_METHODS.items():
            with self.subTest(method=name):
                self.assertIn(method.tier, runner.VALID_EXPECTATIONS)
                if method.tier != "confirmed":
                    # A control may expect it: the target was exercised and the
                    # tool did not claim execution, which is what a control
                    # measures.
                    self.assertIn(method.tier, runner.CONTROL_EXPECTATIONS)
        self.assertNotIn("confirmed", runner.CONTROL_EXPECTATIONS)


class SharedTargetTestCase(unittest.TestCase):
    """Bringing the container up twice is the largest fixed cost in a case, and
    both halves usually hit the same one.

    It is not free to skip. The teardown between the halves is `down -v`, so
    the control has always met a *fresh* target; a case whose vulnerable half
    writes a file or plants a shell would otherwise hand its control a target
    it had already altered, and a control measured against a contaminated
    target measures nothing. So the saving is opt-in, the default is the old
    behaviour, and a case may only opt in when its halves really do resolve to
    the same target.
    """

    class _FakeSubprocess:
        """Stands in for the runner's `subprocess`, recording compose argv."""

        def __init__(self, returncode=0):
            self.calls = []
            self.returncode = returncode

        def run(self, argv, cwd=None, capture_output=False, text=False):
            self.calls.append(list(argv))
            return SimpleNamespace(returncode=self.returncode, stdout="", stderr="")

    def _compose_calls(self, case, returncode=0):
        """Which compose commands a case would run, without running anything."""
        fake = self._FakeSubprocess(returncode)

        def fake_run_rcekit(invocation, python=None, timeout=900.0, run_in=None):
            return {"verdict": "negative", "counts": {"negative": 1}, "probes": []}

        original_sub, original_run = runner.subprocess, runner.run_rcekit
        runner.subprocess, runner.run_rcekit = fake, fake_run_rcekit
        try:
            outcome = runner.run_case(case)
        finally:
            runner.subprocess, runner.run_rcekit = original_sub, original_run
        return [call[-1] for call in fake.calls], outcome

    @staticmethod
    def _composed(**overrides):
        """A case that manages containers, so compose commands are observable."""
        return minimal_case(compose=["docker", "compose", "up", "-d"],
                            compose_down=["docker", "compose", "down", "-v"],
                            **overrides)

    def test_by_default_each_half_gets_a_fresh_target(self):
        # The property the default protects: the control never inherits
        # whatever the vulnerable half did to the target.
        calls, _ = self._compose_calls(self._composed())
        self.assertEqual(calls, ["-d", "-v", "-d", "-v"])

    def test_a_case_may_share_one_target_across_both_halves(self):
        calls, outcome = self._compose_calls(self._composed(share_target=True))
        self.assertEqual(calls, ["-d", "-v"])
        # Both halves still ran and were judged -- the saving is the container,
        # not a skipped control.
        self.assertIn("vulnerable_ok", outcome)
        self.assertIn("control_ok", outcome)
        self.assertIn("control_verdict", outcome)

    def test_a_failed_shared_up_does_not_swallow_the_reason(self):
        # Proceeding with a target that never came up would leave both halves
        # waiting out a readiness timeout and reporting that instead, which
        # names the wrong failure. Each half manages its own and says so.
        calls, outcome = self._compose_calls(self._composed(share_target=True),
                                             returncode=1)
        self.assertEqual(outcome["vulnerable_detail"], "compose up failed")
        self.assertEqual(outcome["control_detail"], "compose up failed")
        self.assertFalse(outcome["passed"])
        # Nothing was torn down, because nothing came up.
        self.assertNotIn("-v", calls)

    def test_keep_up_still_leaves_a_shared_target_running(self):
        fake = self._FakeSubprocess()

        def fake_run_rcekit(invocation, python=None, timeout=900.0, run_in=None):
            return {"verdict": "negative", "counts": {"negative": 1}, "probes": []}

        original_sub, original_run = runner.subprocess, runner.run_rcekit
        runner.subprocess, runner.run_rcekit = fake, fake_run_rcekit
        try:
            runner.run_case(self._composed(share_target=True), keep_up=True)
        finally:
            runner.subprocess, runner.run_rcekit = original_sub, original_run
        self.assertEqual([call[-1] for call in fake.calls], ["-d"])

    def test_sharing_a_target_the_halves_do_not_share_is_rejected(self):
        # A patched-build control brings up its own container, so there is
        # nothing to share. Left set, the key would read as though the two
        # halves met the same target when they never could.
        case = self._composed(share_target=True)
        case["negative_control"]["vulhub_path"] = "struts2/s2-001"
        with self.assertRaises(runner.CaseError) as raised:
            runner.validate_case(case)
        self.assertIn("share_target", str(raised.exception))

    def test_share_target_must_be_a_boolean(self):
        with self.assertRaises(runner.CaseError):
            runner.validate_case(self._composed(share_target="yes"))

    def test_a_case_that_does_not_share_still_validates(self):
        runner.validate_case(self._composed(share_target=False))
        runner.validate_case(self._composed())


class HarnessEndToEndTestCase(unittest.TestCase):
    """The run-and-judge path against a real socket, with no Docker involved.

    A case with no `compose` key targets something already running, which is
    what makes this possible — and is also a real mode for anyone benchmarking
    a target they started by hand."""

    def _case(self, base, **overrides):
        return minimal_case(
            invocation=["--verify-url", f"{base}/?host=FUZZ", "--methods", "reflected"],
            negative_control={"invocation": ["--verify-url", f"{base}/safe?host=FUZZ",
                                             "--methods", "reflected"],
                              "expect": "negative"},
            **overrides)

    def test_a_vulnerable_target_with_a_clean_control_passes(self):
        import os

        def route(method, path, params, headers, body):
            if path.startswith("/safe"):
                return 200, "<html>nothing executes here</html>"
            pipe = sh_popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            outcome = runner.run_case(self._case(base))
        self.assertTrue(outcome["vulnerable_ok"], outcome["vulnerable_detail"])
        self.assertTrue(outcome["control_ok"], outcome["control_detail"])
        self.assertTrue(outcome["passed"])
        self.assertEqual(outcome["verdict"], "confirmed")
        self.assertIn("reflected", outcome["methods"])

    def test_a_control_that_starts_confirming_fails_the_case(self):
        # The failure mode negative controls exist to catch: if the "clean"
        # endpoint also confirms, the case must fail even though the vulnerable
        # half is perfect.
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            outcome = runner.run_case(self._case(base))
        self.assertTrue(outcome["vulnerable_ok"], outcome["vulnerable_detail"])
        self.assertFalse(outcome["control_ok"])
        self.assertFalse(outcome["passed"], "a confirming control must fail the case")

    def test_a_patched_target_fails_the_vulnerable_half(self):
        with local_target(lambda *a: (200, "<html>patched</html>")) as base:
            outcome = runner.run_case(self._case(base))
        self.assertFalse(outcome["vulnerable_ok"])
        self.assertTrue(outcome["control_ok"])
        self.assertFalse(outcome["passed"])

    def test_an_unreachable_target_is_an_error_not_a_negative(self):
        # Reporting a dead target as `negative` would read as "not vulnerable",
        # which is the misreport this whole project exists to avoid.
        case = minimal_case(
            # Bounded for the same reason minimal_case's default is: this proves
            # a dead target reports `error`, and three probes prove it as well as
            # the whole ladder does. On Windows, where a closed port is dropped
            # rather than refused, this test measured 1800s unbounded and 9.1s
            # bounded -- on its own, longer than the other 534 tests together.
            invocation=["--verify-url", "http://127.0.0.1:9/?x=FUZZ", "--methods", "reflected",
                        "--max-payloads", "3", "--verify-timeout", "1"],
            expect="error")
        outcome = runner.run_case(case)
        self.assertEqual(outcome["verdict"], "error")
        self.assertTrue(outcome["vulnerable_ok"], outcome["vulnerable_detail"])


class RunnerCLITestCase(unittest.TestCase):
    def test_list_prints_the_shipped_cases(self):
        import contextlib
        import io
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = runner.main(["--list", "--cases-dir", str(BENCH_ROOT / "cases")])
        self.assertEqual(code, 0)
        self.assertIn("webmin-cve-2019-15107", buffer.getvalue())

    def test_an_unknown_case_name_is_an_error(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            code = runner.main(["--case", "no-such-case", "--cases-dir",
                                str(BENCH_ROOT / "cases")])
        self.assertEqual(code, 2)

    def test_no_selection_is_refused(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runner.main(["--cases-dir", str(BENCH_ROOT / "cases")])


class DetectJsonTestCase(unittest.TestCase):
    """--detect-json is the channel the harness reads. Its contract is tested
    here rather than in the harness, because the harness only trusts it."""

    def test_overall_verdict_prefers_the_finding_over_the_majority(self):
        import rcekit
        many_negatives = [{"verdict": "negative"}] * 99
        self.assertEqual(
            rcekit.overall_detection_verdict(many_negatives + [{"verdict": "confirmed"}]),
            "confirmed")
        self.assertEqual(
            rcekit.overall_detection_verdict(many_negatives + [{"verdict": "needs-review"}]),
            "needs-review")

    def test_no_probes_is_nothing_tested_not_negative(self):
        import rcekit
        self.assertEqual(rcekit.overall_detection_verdict([]), "nothing-tested")

    def test_error_only_when_nothing_reached_the_target(self):
        import rcekit
        self.assertEqual(rcekit.overall_detection_verdict([{"verdict": "error"}] * 3), "error")
        # Some probes errored but others landed and came back clean: that is a
        # real negative, not an untested run.
        self.assertEqual(
            rcekit.overall_detection_verdict([{"verdict": "error"}, {"verdict": "negative"}]),
            "negative")

    def test_written_file_carries_the_verdict_counts_and_probes(self):
        import rcekit
        probes = [{"verdict": "confirmed", "method": "reflected", "environment": "unix",
                   "context": "raw", "payload": "; id", "detail": "computed"},
                  {"verdict": "negative", "method": "reflected", "environment": "unix",
                   "context": "raw", "payload": "| id", "detail": ""}]
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "out.json")
            rcekit.write_detection_json(path, probes, "http://t/FUZZ", ["reflected"])
            with open(path, encoding="utf-8") as handle:
                written = json.load(handle)
        self.assertEqual(written["verdict"], "confirmed")
        self.assertEqual(written["counts"], {"confirmed": 1, "negative": 1})
        self.assertEqual(written["target"], "http://t/FUZZ")
        self.assertEqual(written["methods"], ["reflected"])
        self.assertEqual(len(written["probes"]), 2)
        self.assertEqual(written["rcekit_version"], rcekit.__version__)

    def test_a_payload_containing_a_newline_survives_the_round_trip(self):
        # The reason this channel exists: line-oriented parsing of the text
        # report splits such a payload in half.
        import rcekit
        payload = "\necho RKABCDE$((1+2))RKFGHIJ"
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "out.json")
            rcekit.write_detection_json(
                path, [{"verdict": "confirmed", "method": "reflected", "environment": "unix",
                        "context": "raw", "payload": payload, "detail": ""}],
                "http://t", ["reflected"])
            with open(path, encoding="utf-8") as handle:
                written = json.load(handle)
        self.assertEqual(written["probes"][0]["payload"], payload)


if __name__ == "__main__":
    unittest.main()
