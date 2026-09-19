"""Documentation integrity tests.

The docs are split across README.md and docs/, which makes them easy to drift
apart: a renamed heading silently breaks a cross-link, and a new CLI flag lands
undocumented. These tests keep the published docs honest without any external
dependency.
"""

import html
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rcekit

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "rcekit.py"
README = REPO_ROOT / "README.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
DOCS_DIR = REPO_ROOT / "docs"

FENCE_RE = re.compile(r"^\s*```", re.MULTILINE)
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
OPTION_RE = re.compile(r"--[A-Za-z][A-Za-z0-9-]*")
# Flag declarations as argparse prints them: two spaces, the flags, then a run of
# whitespace before the description. Reading only this leading segment keeps the
# prose inside each help string — which name planned, not existing, flags — out.
DECLARATION_RE = re.compile(r"^ {2}(-\S[^ ]*(?:[ ,][^ ]+)*?)(?: {2,}|$)")


def markdown_files():
    return [README, CHANGELOG] + sorted(DOCS_DIR.glob("*.md"))


def strip_code_fences(text):
    """Drop fenced blocks so sample output and payloads aren't parsed as markdown."""
    parts = FENCE_RE.split(text)
    return "".join(parts[::2])


def slugify(heading):
    """Reproduce GitHub's heading-anchor algorithm."""
    text = html.unescape(heading)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"[*_]", "", text)
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return text.strip().replace(" ", "-")


def anchors_of(path):
    body = strip_code_fences(path.read_text(encoding="utf-8"))
    found = set()
    for line in body.splitlines():
        match = HEADING_RE.match(line)
        if match:
            found.add(slugify(match.group(2)))
    return found


def links_of(path):
    body = strip_code_fences(path.read_text(encoding="utf-8"))
    return LINK_RE.findall(body)


class VersionBadgeTestCase(unittest.TestCase):
    def test_readme_badge_matches_dunder_version(self):
        """A stale badge misreports which release a reader is looking at."""
        text = README.read_text(encoding="utf-8")
        match = re.search(r"\*\*Version\s+(\d+\.\d+\.\d+)\*\*", text)
        self.assertIsNotNone(match, "README has no '**Version X.Y.Z**' badge")
        self.assertEqual(
            match.group(1),
            rcekit.__version__,
            "README version badge is out of sync with rcekit.__version__",
        )


    def test_cli_version_matches_dunder_version(self):
        """The packaged version and the reported version are the same string.

        `pyproject.toml` reads the release version from `rcekit.__version__`,
        and the publish workflow refuses to build when the git tag disagrees
        with it. So a `--version` that reported anything else would put a
        number on a wheel that the tool itself denies -- and PyPI never lets a
        version be re-uploaded, so the mistake would be permanent."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--version"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        reported = result.stdout.strip().split()[-1]
        self.assertEqual(reported, rcekit.__version__)

    def test_dunder_version_is_a_static_literal(self):
        """Readable without importing the module.

        setuptools reads it with `attr:`, which parses the source when it can
        rather than executing it. A computed value would still work today and
        break the moment the build backend takes the static path."""
        source = SCRIPT.read_text(encoding="utf-8")
        match = re.search(r'^__version__ = "(\d+\.\d+\.\d+)"$', source, re.MULTILINE)
        self.assertIsNotNone(match, "__version__ is not a plain string literal")
        self.assertEqual(match.group(1), rcekit.__version__)


class ImportPurityTestCase(unittest.TestCase):
    """`import rcekit` must do nothing but define names.

    It used to configure logging at module scope, and `logging.FileHandler`
    opens its file on construction -- so importing the module wrote `rcekit.log`
    into whatever directory the interpreter happened to be in. Harmless in a
    repo checkout, indefensible once the module is installed and imported by
    tooling that never intends to run a scan."""

    def test_importing_creates_no_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "rcekit.py"
            script.write_bytes(SCRIPT.read_bytes())
            before = set(os.listdir(tmp))
            result = subprocess.run(
                [sys.executable, "-c", "import rcekit"],
                cwd=tmp, capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            created = set(os.listdir(tmp)) - before - {"__pycache__"}
        self.assertEqual(created, set(), f"import created files: {sorted(created)}")

    def test_importing_writes_nothing_to_stdout(self):
        result = subprocess.run(
            [sys.executable, "-c", "import rcekit"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


class ChangelogTestCase(unittest.TestCase):
    """A release with no changelog entry is a release nobody can read."""

    RELEASE_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)

    @classmethod
    def setUpClass(cls):
        cls.text = CHANGELOG.read_text(encoding="utf-8")

    def test_has_an_unreleased_section(self):
        self.assertIn("## [Unreleased]", self.text)

    def test_latest_entry_matches_dunder_version(self):
        releases = self.RELEASE_RE.findall(self.text)
        self.assertTrue(releases, "CHANGELOG.md documents no released version")
        self.assertEqual(
            releases[0], rcekit.__version__,
            "the newest CHANGELOG entry does not match rcekit.__version__ — "
            "every version bump needs an entry",
        )

    def test_releases_are_in_descending_order(self):
        releases = [tuple(int(p) for p in v.split(".")) for v in self.RELEASE_RE.findall(self.text)]
        self.assertEqual(releases, sorted(releases, reverse=True),
                         "CHANGELOG entries are not newest-first")

    def test_every_release_has_a_link_definition(self):
        defined = set(re.findall(r"^\[(\d+\.\d+\.\d+)\]:", self.text, re.MULTILINE))
        missing = sorted(set(self.RELEASE_RE.findall(self.text)) - defined)
        self.assertEqual(missing, [], f"versions with no link definition: {missing}")


class DocLinkTestCase(unittest.TestCase):
    def test_relative_links_resolve(self):
        broken = []
        for path in markdown_files():
            for target in links_of(path):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                relative = target.split("#", 1)[0]
                if not relative:
                    continue
                if not (path.parent / relative).exists():
                    broken.append(f"{path.name} -> {target}")
        self.assertEqual(broken, [], f"broken relative links: {broken}")

    def test_anchors_resolve(self):
        broken = []
        for path in markdown_files():
            for target in links_of(path):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                if "#" not in target:
                    continue
                relative, anchor = target.split("#", 1)
                if not anchor:
                    continue
                destination = path if not relative else path.parent / relative
                if destination.suffix != ".md" or not destination.exists():
                    continue
                if anchor not in anchors_of(destination):
                    broken.append(f"{path.name} -> {target}")
        self.assertEqual(broken, [], f"links to missing headings: {broken}")

    def test_readme_points_at_every_doc_page(self):
        """A docs page nothing links to is a page nobody finds."""
        linked = {
            target.split("#", 1)[0]
            for target in links_of(README)
            if target.startswith("docs/")
        }
        for page in sorted(DOCS_DIR.glob("*.md")):
            self.assertIn(
                f"docs/{page.name}", linked, f"README does not link to docs/{page.name}"
            )


class ComparisonSectionTestCase(unittest.TestCase):
    """The comparison names other people's tools, so it has to stay checkable."""

    # Every project the section is allowed to name, and where a reader verifies it.
    PROJECTS = {
        "commix": "github.com/commixproject/commix",
        "SSTImap": "github.com/vladko312/SSTImap",
        "tplmap": "github.com/epinna/tplmap",
        "Nuclei": "github.com/projectdiscovery/nuclei",
        "interactsh": "github.com/projectdiscovery/interactsh",
        "sqlmap": "github.com/sqlmapproject/sqlmap",
    }

    @classmethod
    def setUpClass(cls):
        text = README.read_text(encoding="utf-8")
        start = text.find("## How RCEKit compares")
        assert start != -1, "README has no 'How RCEKit compares' section"
        end = text.find("\n## ", start + 1)
        cls.section = text[start:end if end != -1 else len(text)]

    def test_section_has_substance(self):
        self.assertGreater(len(self.section.splitlines()), 30)

    def test_named_projects_are_linked(self):
        """A claim about someone else's tool must ship with a way to check it."""
        unlinked = [
            name for name, url in self.PROJECTS.items()
            if name.lower() in self.section.lower() and url not in self.section
        ]
        self.assertEqual(
            unlinked, [], f"named in the comparison without a link to the project: {unlinked}"
        )

    def test_no_unvetted_project_is_named(self):
        """Adding a rival to the table means adding it here — and linking it."""
        for rival in ("metasploit", "burp suite", "acunetix", "tplmap2"):
            self.assertNotIn(
                rival, self.section.lower(),
                f"'{rival}' appears in the comparison but is not in PROJECTS",
            )


class DemoTierTestCase(unittest.TestCase):
    """The README states each demo's tier three times, and they have to agree.

    Once in the CVE table's verdict column, once in the heading above the
    recording, and once in the recording's alt text. A tier that moves has to
    move in all three; `lookup` moved from `confirmed` to `lookup-sink` in the
    table and the heading below it went on saying `confirmed`, with alt text
    calling the run "auto-confirming a blind Log4Shell RCE". The table row was
    the one anybody looked at.

    Nothing here reads a tier from prose and trusts it: the ceiling comes from
    the method class, and the table is what the other two are checked against.
    """

    ROW_RE = re.compile(r"^\|(.+)\|\s*$")
    ADVISORY_RE = re.compile(r"(CVE-\d{4}-\d{4,}|S2-\d+)")
    TIER_RE = re.compile(r"`([a-z][a-z-]*)`")
    SUMMARY_RE = re.compile(r"<summary>(.*?)</summary>", re.DOTALL)
    DETAILS_RE = re.compile(r"<details[^>]*>(.*?)</details>", re.DOTALL)
    HEADING_TIER_RE = re.compile(r"→\s*<code>([a-z][a-z-]*)</code>")
    METHOD_RE = re.compile(r"<code>([a-z][a-z-]*)</code>")
    ALT_RE = re.compile(r"!\[([^\]]*)\]\(")
    # "never confirmed", "not confirmed on its own" -- a denial is the opposite
    # of the claim being looked for, so it is removed before looking.
    DENIAL_RE = re.compile(r"\b(?:never|not|no)\s+`?confirm\w*`?", re.IGNORECASE)

    def setUp(self):
        self.body = README.read_text(encoding="utf-8")
        self.rows = self._cve_table()
        self.assertTrue(self.rows, "the README's CVE table was not found")

    def _cve_table(self):
        """The CVE table as {(advisory, method): tier}, read from the one table
        whose header ends in a Verdict column."""
        rows = {}
        in_table = False
        for line in self.body.splitlines():
            match = self.ROW_RE.match(line)
            if not match:
                in_table = False
                continue
            cells = [cell.strip() for cell in match.group(1).split("|")]
            if len(cells) == 4 and cells[3] == "Verdict":
                in_table = True
                continue
            if not in_table or len(cells) != 4 or set(cells[0]) <= set("- :"):
                continue
            method = self.TIER_RE.search(cells[1])
            advisory = self.ADVISORY_RE.search(cells[2])
            tier = self.TIER_RE.search(cells[3])
            if method and advisory and tier:
                rows[(advisory.group(1), method.group(1))] = tier.group(1)
        return rows

    def test_every_row_states_the_tier_its_method_reports(self):
        """The table is the source the heading and the alt text are checked
        against, so it has to be checked against the code.

        Only `confirmed` was compared at first, which left the table free to
        drift anywhere below it: a `lookup` row reading `needs-review`, or
        `deserialization-sink` -- a tier that method cannot emit at all --
        would have passed, the heading would have matched the table, the alt
        text would have matched the heading, and all three would have
        disagreed with `LookupCallback.tier` in silence.

        `tier` is a ceiling rather than an exact value: `write` reports
        `needs-review` for a write that is served but not interpreted, and
        `deser` does the same for a shape fingerprint. This asks for equality
        anyway, because every row here is a headline demonstration of a method
        at its ceiling. A row that genuinely belongs below one should widen
        this deliberately -- the failure says so -- rather than be waved
        through by a rule loose enough to miss the case above."""
        for (advisory, method), tier in self.rows.items():
            with self.subTest(advisory=advisory, method=method):
                self.assertIn(method, rcekit.DETECTION_METHODS)
                ceiling = rcekit.DETECTION_METHODS[method].tier
                self.assertEqual(
                    tier, ceiling,
                    f"the {advisory} row says `{method}` reached {tier}, but that "
                    f"method's tier is {ceiling}. If the row is right and the "
                    "demonstration really sat below the method's ceiling, widen this "
                    "test on purpose")

    def test_every_demo_heading_matches_its_row_in_the_table(self):
        seen = 0
        for summary in self.SUMMARY_RE.findall(self.body):
            heading_tier = self.HEADING_TIER_RE.search(summary)
            advisory = self.ADVISORY_RE.search(summary)
            if not (heading_tier and advisory):
                continue
            seen += 1
            with self.subTest(summary=summary):
                candidates = {key: tier for key, tier in self.rows.items()
                              if key[0] == advisory.group(1)}
                self.assertTrue(candidates,
                                "the demo names an advisory the CVE table does not")
                methods = [name for name in self.METHOD_RE.findall(summary)
                           if name in rcekit.DETECTION_METHODS]
                if methods:
                    key = (advisory.group(1), methods[0])
                    self.assertIn(key, candidates,
                                  "the demo pairs a method with an advisory the table "
                                  "does not pair them with")
                    expected = candidates[key]
                else:
                    self.assertEqual(
                        len(candidates), 1,
                        "the demo names no method and its advisory has more than one "
                        "row, so there is nothing to check it against")
                    expected = next(iter(candidates.values()))
                self.assertEqual(
                    heading_tier.group(1), expected,
                    f"the demo heading says {heading_tier.group(1)} where the table "
                    f"says {expected}")
        self.assertGreaterEqual(seen, 3, "no demo headings were checked")

    def test_a_recording_below_confirmed_is_not_described_as_confirming(self):
        """The heading is one claim and the alt text is another.

        Both said `confirmed` for the Log4Shell demo. Changing the heading alone
        would have left "auto-confirming a blind Log4Shell RCE" underneath it,
        which is the sentence a screen reader reads out."""
        seen = 0
        for details in self.DETAILS_RE.findall(self.body):
            heading_tier = self.HEADING_TIER_RE.search(details)
            alt = self.ALT_RE.search(details)
            if not (heading_tier and alt):
                continue
            if heading_tier.group(1) == "confirmed":
                continue
            seen += 1
            with self.subTest(tier=heading_tier.group(1)):
                claim = self.DENIAL_RE.sub("", alt.group(1))
                self.assertNotIn(
                    "confirm", claim.lower(),
                    f"a {heading_tier.group(1)} recording is described as confirming: "
                    f"{alt.group(1)}")
        self.assertGreaterEqual(seen, 1, "no sub-confirmed recordings were checked")


class CLIDocumentationTestCase(unittest.TestCase):
    """Guard against the CLI and its reference page drifting apart."""

    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stderr
        options = set()
        for line in result.stdout.splitlines():
            declaration = DECLARATION_RE.match(line)
            if declaration:
                options.update(OPTION_RE.findall(declaration.group(1)))
        cls.cli_options = options - {"--help"}
        cls.reference_text = (DOCS_DIR / "reference.md").read_text(encoding="utf-8")

    def test_help_output_was_parsed(self):
        # A guard on the test itself: if argparse ever changes its help layout,
        # the two tests below would silently pass on an empty set.
        self.assertGreater(len(self.cli_options), 30)
        self.assertIn("--verify-url", self.cli_options)
        self.assertIn("--request-file", self.cli_options)

    def test_every_cli_option_is_documented(self):
        undocumented = sorted(
            option for option in self.cli_options
            if not re.search(rf"`{re.escape(option)}`", self.reference_text)
        )
        self.assertEqual(
            undocumented, [], f"flags missing from docs/reference.md: {undocumented}"
        )

    def test_reference_documents_no_phantom_options(self):
        # Only flags written as code, so heading anchors like `#safety--consent`
        # aren't mistaken for a documented `--consent`.
        documented = set(re.findall(r"`(--[A-Za-z][A-Za-z0-9-]*)`", self.reference_text))
        phantom = sorted(documented - self.cli_options)
        self.assertEqual(
            phantom, [], f"docs/reference.md documents non-existent flags: {phantom}"
        )


if __name__ == "__main__":
    unittest.main()
