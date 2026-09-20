#!/usr/bin/env python3
"""RCEKit coverage benchmark — run the tool against real vulnerable targets.

The unit tests prove RCEKit builds the right payloads and reaches the right
verdict from a given response. They cannot prove it confirms *Webmin*. This
harness closes that gap: each case points at a real vulnerable build, runs the
tool exactly as an operator would, and checks the verdict against what the
README claims.

Every case carries a **negative control** — a build or an endpoint that is not
vulnerable and must come back clean. That is not paperwork. A benchmark without
negative controls measures nothing: a tool that shouted `confirmed` at every
target would score full marks on the vulnerable half and the harness would call
it progress. A case passes only when both halves land.

Not part of ``python -m unittest discover -s tests``: cases need Docker and pull
real images, so they are opt-in and run by hand or in a dedicated job.

    python tests/bench/runner.py --list
    python tests/bench/runner.py --case webmin-cve-2019-15107
    python tests/bench/runner.py --all --markdown coverage.md

Cases whose target is already running (no ``compose`` key) need no Docker at
all, which is also how the harness itself is tested.

Only point cases at infrastructure you own or are authorised to test. The runner
passes ``--acknowledge-consent`` on your behalf, because a bench case is a
target you started yourself moments earlier.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BENCH_ROOT = Path(__file__).resolve().parent
CASES_DIR = BENCH_ROOT / "cases"
REPO_ROOT = BENCH_ROOT.parent.parent
RCEKIT = REPO_ROOT / "rcekit.py"

# The harness still runs the tool as a subprocess -- the outcome has to come
# from its own machine-readable channel, not from anything imported here. This
# import is for the verdict vocabulary alone, so that a tier the engine can emit
# is a tier a case can expect, without the two being written down twice.
sys.path.insert(0, str(REPO_ROOT))
import rcekit  # noqa: E402

# A case must say what it expects, where to point the tool, and how to prove the
# result is not just an over-eager scanner. The negative control is required by
# design -- see the module docstring.
REQUIRED_KEYS = ("name", "rce_class", "target", "invocation", "expect", "negative_control")
# Read from the engine rather than written out here. The hand-written list had
# drifted: `deser` reports `deserialization-sink` and `lookup` reports
# `lookup-sink`, and neither was in it -- so the harness could not express a
# case for either method at all, and nobody found out until one was written.
# A tier is a property of the class that emits it, so this follows it.
_OUTCOMES_WITHOUT_A_METHOD = ("negative", "inconclusive", "error", "nothing-tested")
VALID_EXPECTATIONS = tuple(sorted(
    {method.tier for method in rcekit.DETECTION_METHODS.values()}
    | set(_OUTCOMES_WITHOUT_A_METHOD)))
# What a control may expect. Narrower than VALID_EXPECTATIONS on purpose:
# `error` and `nothing-tested` both mean the run never exercised the target, so a
# control expecting either proves nothing about false confirmation -- it would
# stay green with the detection engine entirely broken, which is the one thing a
# control exists to catch. `confirmed` is excluded as a contradiction.
#
# The vulnerable half may still expect them: "an unreachable target reports
# `error`, not `negative`" is a real property worth pinning.
#
# A proven-sink tier belongs here for the same reason `needs-review` does. It
# says the target was exercised and the tool did *not* claim execution, which is
# exactly what a tier-ceiling control measures -- "this endpoint deserializes
# attacker data and RCEKit still would not call it RCE" is a control, not a
# contradiction. Only `confirmed` is excluded.
CONTROL_EXPECTATIONS = tuple(sorted(
    ({method.tier for method in rcekit.DETECTION_METHODS.values()} - {"confirmed"})
    | {"negative", "inconclusive"}))


class CaseError(Exception):
    """A case file that cannot be trusted to measure anything."""


def target_setup(case: Dict[str, Any]) -> Tuple[Any, Tuple[str, ...], Tuple[str, ...]]:
    """The part of a case that decides *which* target comes up."""
    return (case.get("vulhub_path"), tuple(case.get("compose", ())),
            tuple(case.get("compose_down", ())))


def control_plan(case: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
    """The control's effective invocation and target setup.

    A control inherits the case's target unless it overrides it — the common
    controls (probe for the wrong class, probe with a weaker method) deliberately
    run against the *same* container, and only a patched-build control brings up
    a different one.

    One function, used by both validation and execution, so the two cannot
    drift: the duplication the validator rejects has to be the same duplication
    the runner would otherwise have run."""
    control = case["negative_control"]
    invocation = list(control.get("invocation", case["invocation"]))
    setup = dict(case)
    for key in ("vulhub_path", "compose", "compose_down"):
        if key in control:
            setup[key] = control[key]
    # A control naming its own vulhub_path without its own compose wants the
    # standard compose commands in that directory, not the parent's explicit ones.
    if "vulhub_path" in control and "compose" not in control:
        setup.pop("compose", None)
        setup.pop("compose_down", None)
    return invocation, setup


def validate_case(case: Dict[str, Any], source: str = "<case>") -> Dict[str, Any]:
    """Reject a case that cannot produce a meaningful result.

    Loud and early: a benchmark that silently skips a malformed case reports a
    smaller number of failures than reality, which is the one failure mode a
    benchmark must not have."""
    missing = [key for key in REQUIRED_KEYS if key not in case]
    if missing:
        raise CaseError(f"{source}: missing required key(s): {', '.join(missing)}")
    if not isinstance(case["invocation"], list) or not case["invocation"]:
        raise CaseError(f"{source}: 'invocation' must be a non-empty list of CLI arguments")
    if case["expect"] not in VALID_EXPECTATIONS:
        raise CaseError(f"{source}: 'expect' must be one of {', '.join(VALID_EXPECTATIONS)}, "
                        f"got {case['expect']!r}")
    control = case["negative_control"]
    if not isinstance(control, dict):
        raise CaseError(f"{source}: 'negative_control' must be an object")
    # Compare what the control would *actually* run, not merely whether it
    # declared a key. Copying the vulnerable invocation into the control passes a
    # key-presence check while running the identical command against the
    # identical target twice, which measures nothing.
    control_invocation, control_setup = control_plan(case)
    if (control_invocation == list(case["invocation"])
            and target_setup(control_setup) == target_setup(case)):
        raise CaseError(f"{source}: the negative control runs the identical invocation against "
                        "an identical target, so it measures nothing — vary the invocation "
                        "(a different method or injection point) or the target (a patched build)")
    if "run_in" in case:
        run_in = case["run_in"]
        if not isinstance(run_in, dict):
            raise CaseError(f"{source}: 'run_in' must be an object")
        missing_keys = [key for key in ("image", "network") if key not in run_in]
        if missing_keys:
            raise CaseError(f"{source}: 'run_in' needs {', '.join(missing_keys)} — a run "
                            "inside a container has to say which image and which network")
    if "share_target" in case:
        if not isinstance(case["share_target"], bool):
            raise CaseError(f"{source}: 'share_target' must be true or false, "
                            f"got {case['share_target']!r}")
        if case["share_target"] and target_setup(control_setup) != target_setup(case):
            raise CaseError(f"{source}: 'share_target' is set, but the control brings up a "
                            "different target — the two halves cannot share a container they "
                            "do not share, and leaving this set would read as though they did")
    control_expect = control.get("expect", "negative")
    if control_expect == "confirmed":
        raise CaseError(f"{source}: a negative control expecting 'confirmed' is a contradiction")
    if control_expect not in CONTROL_EXPECTATIONS:
        raise CaseError(f"{source}: negative_control 'expect' must be one of "
                        f"{', '.join(CONTROL_EXPECTATIONS)} — an outcome that means the target "
                        f"was never exercised cannot show RCEKit avoids a false confirmation; "
                        f"got {control_expect!r}")
    return case


def load_case(path: Path) -> Dict[str, Any]:
    """Read and validate one case file."""
    try:
        with open(path, encoding="utf-8") as handle:
            case = json.load(handle)
    except ValueError as exc:
        raise CaseError(f"{path}: not valid JSON ({exc})")
    return validate_case(case, str(path))


def discover_cases(cases_dir: Path = CASES_DIR) -> List[Path]:
    return sorted(cases_dir.glob("*.json"))


def wait_for_target(url: str, status: int = 200, timeout: float = 120.0,
                    interval: float = 2.0, insecure: bool = True) -> bool:
    """Poll ``url`` until it answers with ``status``, or ``timeout`` elapses.

    A container that is up is not a container that is ready, and running the
    tool against a half-started service produces an `error` verdict that looks
    like a benchmark regression. Any HTTP answer counts as reachable — a 401 or
    500 still means the server is listening — but the case's expected status is
    what ends the wait."""
    context = None
    if insecure and url.lower().startswith("https"):
        import ssl
        import warnings
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # The readiness gate has to be at least as permissive as the tool it
        # gates. A bench target is deliberately old software, and OpenSSL 3.x
        # refuses Webmin 1.910's handshake outright at its default security
        # level — so a stricter probe here reports "target never became ready"
        # about a container that is up and answering, and the case fails with
        # nothing wrong in it.
        try:
            context.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, OSError):
            pass
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10, context=context) as response:
                if response.status == status:
                    return True
        except urllib.error.HTTPError as exc:
            if exc.code == status:
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def expand_paths(invocation: List[str], repo: Optional[str] = None) -> List[str]:
    """Resolve ``{bench}`` / ``{repo}`` in a case's arguments.

    A case that references a captured request file has to name it somehow, and
    both a bare relative path (which breaks the moment the runner is invoked
    from elsewhere) and an absolute one (which breaks on every other machine)
    are wrong. The tokens make the anchor explicit.

    ``repo`` is where the repository lives *from the point of view of the run*.
    It is the host path by default and the mount point when the run happens
    inside a container, which is the whole reason the tokens exist rather than
    the paths."""
    root = REPO_ROOT if repo is None else Path(repo)
    bench = root / "tests" / "bench" if repo is not None else BENCH_ROOT
    return [arg.replace("{bench}", str(bench)).replace("{repo}", str(root))
            for arg in invocation]


CONTAINER_REPO = "/rcekit"
CONTAINER_OUT = "/out"


def container_command(run_in: Dict[str, Any], invocation: List[str],
                      out_dir: str) -> List[str]:
    """The ``docker run`` that puts RCEKit inside the target's own network.

    A callback method needs the target's resolver to reach RCEKit's listener,
    and a resolver asks UDP 53. On a developer machine something already owns
    that port, so rather than demand it, the run happens where the port is
    free: a container on the target's network, at an address the target's
    ``dns:`` points at.

    The repository is mounted read-only. Nothing is built, and the image only
    has to be a Python that can run a dependency-free single module."""
    argv = ["docker", "run", "--rm", "--network", run_in["network"]]
    if run_in.get("ip"):
        argv += ["--ip", run_in["ip"]]
    argv += ["-v", f"{REPO_ROOT}:{CONTAINER_REPO}:ro",
             "-v", f"{out_dir}:{CONTAINER_OUT}",
             run_in["image"], "python", f"{CONTAINER_REPO}/rcekit.py",
             "--acknowledge-consent",
             *expand_paths(invocation, repo=CONTAINER_REPO),
             "--detect-json", f"{CONTAINER_OUT}/results.json"]
    return argv


def run_rcekit(invocation: List[str], python: Optional[str] = None,
               timeout: float = 900.0,
               run_in: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run RCEKit once with the case's arguments and return its JSON results.

    ``--detect-json`` is appended by the harness rather than written into each
    case: the outcome must come from the tool's own machine-readable channel,
    not from scraping a report whose payload lines can contain literal
    newlines.

    ``run_in`` puts that run inside a container on the target's network -- see
    :func:`container_command`. The results file is read back through a bind
    mount, so the channel is the same one either way."""
    out_dir = None
    if run_in:
        out_dir = tempfile.mkdtemp(prefix="rcekit-bench-out-")
        results_path = os.path.join(out_dir, "results.json")
        # The container writes the results here, and it is not this process.
        # With Docker's user-namespace remapping, container root is a
        # subordinate host UID, so a 0700 mkdtemp owned by the runner is not
        # writable from inside -- the file never appears, and the case reports
        # `nothing-tested` as though detection had found nothing rather than as
        # though the channel had been shut. Naming the wrong cause is the
        # failure this harness exists to avoid.
        #
        # The file is pre-created and made writable; the directory gets search
        # permission but not write. Writing an existing file needs permission
        # on the file, so that is all that is granted: nobody else can create,
        # replace or unlink entries here.
        open(results_path, "w").close()
        try:
            os.chmod(out_dir, 0o711)
            os.chmod(results_path, 0o666)
        except OSError:
            # Windows keeps no meaningful mode bits here, and has no
            # remapping to defeat either.
            pass
        command = container_command(run_in, invocation, out_dir)
    else:
        handle, results_path = tempfile.mkstemp(prefix="rcekit-bench-", suffix=".json")
        os.close(handle)
        command = [python or sys.executable, str(RCEKIT), "--acknowledge-consent",
                   *expand_paths(invocation), "--detect-json", results_path]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                   cwd=str(REPO_ROOT))
        try:
            with open(results_path, encoding="utf-8") as results_file:
                report = json.load(results_file)
        except (OSError, ValueError):
            # No JSON means the run never got as far as detecting anything --
            # a bad invocation, a refused consent gate, a crash. Reporting that
            # as `negative` would read as "target not vulnerable".
            return {"verdict": "nothing-tested", "counts": {}, "probes": [],
                    "stdout": completed.stdout, "stderr": completed.stderr,
                    "exit_code": completed.returncode, "command": command}
        report["stdout"] = completed.stdout
        report["stderr"] = completed.stderr
        report["exit_code"] = completed.returncode
        report["command"] = command
        return report
    except subprocess.TimeoutExpired:
        return {"verdict": "error", "counts": {}, "probes": [],
                "stdout": "", "stderr": f"rcekit timed out after {timeout}s",
                "exit_code": None, "command": command}
    finally:
        try:
            os.unlink(results_path)
        except OSError:
            pass
        if out_dir:
            try:
                os.rmdir(out_dir)
            except OSError:
                pass


def method_signatures(report: Dict[str, Any], verdict: str) -> List[str]:
    """The method identifiers behind every probe that reached ``verdict``.

    Both the bare method (``reflected``) and the full carrier
    (``reflected/unix/raw``) are returned, so a case can pin the exact break-out
    that worked or stay at the method level."""
    signatures: List[str] = []
    for probe in report.get("probes", []):
        if probe.get("verdict") != verdict:
            continue
        method = probe.get("method", "")
        signatures.append(method)
        signatures.append("{}/{}/{}".format(method, probe.get("environment", ""),
                                            probe.get("context", "")))
    return signatures


def check_report(report: Dict[str, Any], expect: str,
                 expect_method: Optional[str] = None) -> Tuple[bool, str]:
    """Whether one run matched what the case expected, and why not if it did not."""
    observed = report.get("verdict", "nothing-tested")
    if observed != expect:
        counts = report.get("counts") or {}
        detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no probes"
        return False, f"expected {expect}, got {observed} ({detail})"
    if expect_method:
        signatures = method_signatures(report, expect)
        if expect_method not in signatures:
            return False, (f"verdict {observed} came from "
                           f"{sorted(set(signatures)) or 'no method'}, not {expect_method!r}")
    return True, f"{observed} as expected"


def compose_command(case: Dict[str, Any], action: str) -> Optional[List[str]]:
    """The compose command for a case, or ``None`` when it manages no containers.

    A case may give ``compose`` as a ready-made argv list (full control) or rely
    on ``vulhub_path``, in which case the standard compose invocation is run in
    that directory under ``--vulhub-root``."""
    if "compose" in case:
        argv = expand_paths(list(case["compose"]))
        return argv if action == "up" else expand_paths(list(case.get("compose_down", [])))
    if "vulhub_path" not in case:
        return None
    if action == "up":
        return ["docker", "compose", "up", "-d"]
    return ["docker", "compose", "down", "-v"]


def target_cwd(compose_case: Dict[str, Any],
               vulhub_root: Optional[Path]) -> Tuple[Optional[Path], Optional[str]]:
    """Where a case's compose commands run, or why they cannot."""
    if "vulhub_path" not in compose_case:
        return None, None
    if not vulhub_root:
        return None, "case needs --vulhub-root (it declares a vulhub_path)"
    cwd = vulhub_root / compose_case["vulhub_path"]
    if not cwd.is_dir():
        return None, f"vulhub path not found: {cwd}"
    return cwd, None


def bring_up(compose_case: Dict[str, Any], cwd: Optional[Path],
             verbose: bool = False) -> Tuple[bool, Optional[str]]:
    """Run a case's compose ``up``. Returns ``(started, problem)``; a case that
    manages no containers starts nothing and reports no problem."""
    up = compose_command(compose_case, "up")
    if not up:
        return False, None
    if verbose:
        print(f"    $ {' '.join(up)}" + (f"  (in {cwd})" if cwd else ""))
    started = subprocess.run(up, cwd=str(cwd) if cwd else None,
                             capture_output=True, text=True).returncode == 0
    return started, None if started else "compose up failed"


def take_down(compose_case: Dict[str, Any], cwd: Optional[Path],
              verbose: bool = False) -> None:
    down = compose_command(compose_case, "down")
    if not down:
        return
    if verbose:
        print(f"    $ {' '.join(down)}")
    subprocess.run(down, cwd=str(cwd) if cwd else None,
                   capture_output=True, text=True)


def run_one(case: Dict[str, Any], invocation: List[str], expect: str,
            expect_method: Optional[str], wait_for: Optional[Dict[str, Any]],
            compose_case: Dict[str, Any], vulhub_root: Optional[Path],
            keep_up: bool = False, verbose: bool = False,
            timeout: Optional[float] = None,
            manage_target: bool = True) -> Tuple[bool, str, Dict[str, Any]]:
    """Bring a target up, run RCEKit against it, tear it down, and judge.

    ``timeout`` is how long that one run may take. A case may raise it, because
    the methods do not cost the same: the Webmin tier-ceiling control fires a
    timing regression, and every probe in it is a real sleep. Measured at 1174s
    against the live target, which the 900s default cut short — and a run killed
    part-way reports `error`, so the case failed as though the tool had broken
    rather than as though the clock had run out.

    ``manage_target`` is False when the caller already has the target up and
    will tear it down itself -- see ``run_case`` and a case's ``share_target``.
    The readiness wait still runs: the half before this one may have left the
    application broken, and "never became ready" is the right answer then."""
    cwd, problem = target_cwd(compose_case, vulhub_root)
    if problem:
        return False, problem, {}
    started = False
    try:
        if manage_target:
            started, problem = bring_up(compose_case, cwd, verbose)
            if problem:
                return False, problem, {}
        if wait_for:
            ready = wait_for_target(wait_for["url"], wait_for.get("status", 200),
                                    wait_for.get("timeout", 120))
            if not ready:
                return False, f"target never became ready at {wait_for['url']}", {}
        report = run_rcekit(invocation, timeout=900.0 if timeout is None else timeout,
                            run_in=case.get("run_in"))
        ok, detail = check_report(report, expect, expect_method)
        return ok, detail, report
    finally:
        if manage_target and started and not keep_up:
            take_down(compose_case, cwd, verbose)


def run_case(case: Dict[str, Any], vulhub_root: Optional[Path] = None,
             keep_up: bool = False, verbose: bool = False) -> Dict[str, Any]:
    """Run a case's vulnerable half and its negative control.

    The control runs even when the vulnerable half already failed. A case whose
    vulnerable target stopped confirming *and* whose control started confirming
    is a different problem from either alone, and only running both tells them
    apart."""
    outcome: Dict[str, Any] = {"name": case["name"], "rce_class": case["rce_class"],
                               "target": case["target"]}
    control = case["negative_control"]
    control_invocation, control_case = control_plan(case)

    # Both halves usually hit the same container, and bringing it up twice is
    # the largest fixed cost in a run. It is not free to skip, though: the
    # teardown between them is `down -v`, so today's control meets a *fresh*
    # target. A case where the vulnerable half writes a file, plants a shell or
    # changes a setting would hand its control a target it had already altered,
    # and a control measured against a contaminated target measures nothing.
    # So the case declares it, and only a case whose halves really do resolve
    # to the same target may -- which validation enforces.
    shared = bool(case.get("share_target")) and target_setup(control_case) == target_setup(case)
    cwd, problem = target_cwd(case, vulhub_root)
    started = False
    if shared and not problem:
        started, problem = bring_up(case, cwd, verbose)
        if problem:
            # Let each half manage its own target and report the failure for
            # itself, rather than both timing out on a readiness wait for
            # something that was never going to come up.
            shared = False
    try:
        ok, detail, report = run_one(
            case, case["invocation"], case["expect"], case.get("expect_method"),
            case.get("wait_for"), case, vulhub_root, keep_up, verbose,
            timeout=case.get("timeout"), manage_target=not shared)
        outcome["vulnerable_ok"] = ok
        outcome["vulnerable_detail"] = detail
        outcome["verdict"] = report.get("verdict", "nothing-tested")
        outcome["methods"] = sorted(set(method_signatures(report, outcome["verdict"])))

        control_ok, control_detail, control_report = run_one(
            control_case, control_invocation,
            control.get("expect", "negative"), control.get("expect_method"),
            control.get("wait_for", case.get("wait_for")), control_case, vulhub_root,
            keep_up, verbose,
            # The control gets its own budget: it is often the slower half,
            # because the method that must NOT be promoted is usually the
            # expensive one.
            timeout=control.get("timeout", case.get("timeout")),
            manage_target=not shared)
        outcome["control_ok"] = control_ok
        outcome["control_detail"] = control_detail
        outcome["control_verdict"] = control_report.get("verdict", "nothing-tested")
        outcome["passed"] = bool(ok and control_ok)
        return outcome
    finally:
        if shared and started and not keep_up:
            take_down(case, cwd, verbose)


def render_markdown(outcomes: List[Dict[str, Any]]) -> str:
    """The coverage table, ready to paste into the README.

    The control column is part of the table on purpose: a reader can see that
    every confirmed row was checked against something that must stay clean,
    rather than taking the claim on trust."""
    lines = ["| RCE class | Target | Method | Verdict | Control | Result |",
             "|---|---|---|---|---|---|"]
    for outcome in outcomes:
        methods = ", ".join(f"`{m}`" for m in outcome.get("methods", []) if "/" not in m) or "—"
        verdict = outcome.get("verdict", "—")
        cell = f"**`{verdict}`**" if verdict == "confirmed" else f"`{verdict}`"
        control = f"`{outcome.get('control_verdict', '—')}`"
        result = "pass" if outcome.get("passed") else "**FAIL**"
        lines.append(f"| {outcome['rce_class']} | {outcome['target']} | {methods} | "
                     f"{cell} | {control} | {result} |")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run RCEKit against real vulnerable targets and check the verdicts.")
    parser.add_argument("--case", action="append", default=[],
                        help="Case name (file stem) to run; repeatable.")
    parser.add_argument("--all", action="store_true", help="Run every case.")
    parser.add_argument("--list", action="store_true", help="List available cases and exit.")
    parser.add_argument("--vulhub-root", default=os.environ.get("VULHUB_ROOT"),
                        help="Path to a vulhub checkout; required by cases with a vulhub_path.")
    parser.add_argument("--cases-dir", default=str(CASES_DIR))
    parser.add_argument("--markdown", default=None,
                        help="Write the coverage table to this file as well as stdout.")
    parser.add_argument("--keep-up", action="store_true",
                        help="Leave containers running after the case (for debugging).")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    cases_dir = Path(args.cases_dir)
    paths = discover_cases(cases_dir)
    if args.list:
        for path in paths:
            print(path.stem)
        return 0
    if args.case:
        wanted = set(args.case)
        paths = [p for p in paths if p.stem in wanted]
        unknown = wanted - {p.stem for p in paths}
        if unknown:
            print(f"[!] unknown case(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
    elif not args.all:
        parser.error("choose --case NAME, --all, or --list")
    if not paths:
        print("[!] no cases to run", file=sys.stderr)
        return 2

    vulhub_root = Path(args.vulhub_root) if args.vulhub_root else None
    outcomes: List[Dict[str, Any]] = []
    for path in paths:
        try:
            case = load_case(path)
        except CaseError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2
        print(f"[bench] {case['name']}: {case['target']}")
        outcome = run_case(case, vulhub_root, args.keep_up, args.verbose)
        outcomes.append(outcome)
        mark = "pass" if outcome["passed"] else "FAIL"
        print(f"[bench]   vulnerable: {outcome['vulnerable_detail']}")
        print(f"[bench]   control:    {outcome['control_detail']}")
        print(f"[bench]   -> {mark}")

    table = render_markdown(outcomes)
    print("\n" + table)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(table + "\n")
        print(f"\n[bench] table written to {args.markdown}")
    failed = [o for o in outcomes if not o["passed"]]
    print(f"\n[bench] {len(outcomes) - len(failed)}/{len(outcomes)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
