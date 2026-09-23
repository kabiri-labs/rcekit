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


# Markdown escapes a literal pipe inside a cell as `\|`, which
# docs/reference.md already does in three of its tables. Splitting a row on
# every pipe invents a cell, and zipping against the header then shifts every
# column after it -- silently, so a claim in the last column simply stops being
# examined and the tier tests pass without looking at the thing they exist for.
ROW_SPLIT_RE = re.compile(r"(?<!\\)\|")

# A denial is the opposite of the claim being looked for, so it comes out before
# the claim is looked for. "never confirmed" and "without confirmation" disclaim
# it, and so does "unconfirmed" -- which carries its negation inside the word,
# where a rule about preceding words cannot see it.
DENIAL_RE = re.compile(
    r"\b(?:never|not|no|without|cannot(?:\s+be)?)\s+`?confirm\w*`?"
    r"|\bunconfirm\w*",
    re.IGNORECASE)


def row_cells(row_body):
    """The cells of one Markdown table row, keyed on nothing yet."""
    return [cell.strip().replace("\\|", "|") for cell in ROW_SPLIT_RE.split(row_body)]


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
            cells = row_cells(match.group(1))
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
                claim = DENIAL_RE.sub("", alt.group(1))
                self.assertNotIn(
                    "confirm", claim.lower(),
                    f"a {heading_tier.group(1)} recording is described as confirming: "
                    f"{alt.group(1)}")
        self.assertGreaterEqual(seen, 1, "no sub-confirmed recordings were checked")


class TableClaimParsingTestCase(unittest.TestCase):
    """The two helpers every tier check reads its claims through.

    Both failure modes here are silent. A mis-split row shifts the columns and
    the claim in the last one stops being examined; a denial read as a claim
    fails a document that says the right thing. Neither shows up as a wrong
    answer -- one is a test that stops looking, the other a test that objects
    to honest prose.
    """

    def test_an_escaped_pipe_stays_inside_its_cell(self):
        # `docs/reference.md` writes separators this way in three tables.
        self.assertEqual(
            row_cells(r" `--separators` | `; `, `\| `, `&& ` | confirms "),
            ["`--separators`", "`; `, `| `, `&& `", "confirms"])

    def test_a_row_with_no_escapes_is_unchanged(self):
        self.assertEqual(row_cells(" `time` | a regression | `needs-review` only "),
                         ["`time`", "a regression", "`needs-review` only"])

    def test_a_disclaimer_is_not_read_as_a_claim(self):
        for text in ("never confirmed", "not confirmed on its own",
                     "no confirmation", "without confirmation", "unconfirmed",
                     "cannot be confirmed by reflected/eval", "never `confirmed`"):
            with self.subTest(text=text):
                self.assertNotIn("confirm", DENIAL_RE.sub("", text).lower())

    def test_a_claim_survives_in_every_form_it_is_made(self):
        for text in ("confirms", "confirmed execution", "confirming RCE",
                     "proves confirmation", "`confirmed`"):
            with self.subTest(text=text):
                self.assertIn("confirm", DENIAL_RE.sub("", text).lower())


class VerdictTableTestCase(unittest.TestCase):
    """The README's verdict table has to list every verdict a method reports.

    It said "seven verdicts that are never collapsed into each other" and named
    seven rows, while the tool had eight: `lookup-sink` was missing -- from the
    one table whose whole job is to enumerate them, in a README that used the
    word two tables higher in the Log4Shell CVE row and again in the methods
    table. The sentence counted the rows the table had rather than the verdicts
    there are, so the omission never contradicted itself and nothing failed.

    The same shape as every other drift this file was written for: a list
    maintained by hand beside a set the code already knows. So the check asks
    the classes, and the counterexample it has to fail on is a verdict a method
    declares and the table does not carry.
    """

    NUMBER_WORDS = {"three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
                    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}
    COUNT_RE = re.compile(r"\*\*([a-z]+) verdicts that are never collapsed")
    VERDICT_RE = re.compile(r"^\|\s*\*\*`([a-z-]+)`\*\*\s*\|")

    @classmethod
    def setUpClass(cls):
        cls.rows = [m.group(1) for m in
                    (cls.VERDICT_RE.match(line)
                     for line in README.read_text(encoding="utf-8").splitlines())
                    if m]
        cls.reported = set()
        for method in rcekit.DETECTION_METHODS.values():
            cls.reported |= {method.tier} | set(method.also_reports)

    def test_the_table_has_rows_at_all(self):
        # Without this the two checks below pass vacuously on a parser that
        # stopped matching -- which is how a table check dies quietly.
        self.assertGreaterEqual(len(self.rows), 7, self.rows)

    def test_every_verdict_a_method_reports_is_a_row(self):
        missing = sorted(self.reported - set(self.rows))
        self.assertFalse(
            missing,
            f"the verdict table does not carry {missing}, which "
            f"DETECTION_METHODS reports; rows are {self.rows}")

    def test_the_count_in_the_prose_is_the_number_of_rows(self):
        text = README.read_text(encoding="utf-8")
        match = self.COUNT_RE.search(text)
        self.assertIsNotNone(match, "the sentence introducing the table moved")
        word = match.group(1)
        self.assertIn(word, self.NUMBER_WORDS, f"unreadable count: {word!r}")
        self.assertEqual(self.NUMBER_WORDS[word], len(self.rows),
                         f"the prose says {word}, the table has {len(self.rows)}")

    def test_the_rows_are_spelled_the_way_a_verdict_is_spelled(self):
        # A row named `lookup sink` or `Lookup-Sink` would read fine and match
        # nothing, which is the failure mode this whole file exists for.
        for row in self.rows:
            self.assertEqual(row, row.lower().strip())


class MethodTableTierTestCase(unittest.TestCase):
    """The same check as `DemoTierTestCase`, for the two tables under `docs/`.

    Those tables were left out when the README's were pinned, and they carry
    the same claim: `docs/reference.md` names the tier each method can reach,
    and `docs/guide.md` tells an operator which method to run next. A tier
    that moves on the class has to move in both.

    `reference.md` states a *ceiling*, so a cell may also name a weaker tier
    the method really does emit -- `write` reports `needs-review` for a write
    that is served but not interpreted, `deser` for a shape fingerprint. The
    rule is therefore a subset rather than an equality, which is the honest
    shape for that column and the reason the README's stricter rule does not
    apply here.
    """

    REFERENCE = DOCS_DIR / "reference.md"
    GUIDE = DOCS_DIR / "guide.md"
    METHOD_COL = "`--methods` value"

    ROW_RE = re.compile(r"^\|(.+)\|\s*$")
    CODE_RE = re.compile(r"`([^`]+)`")

    @classmethod
    def setUpClass(cls):
        cls.tiers = {name: method.tier
                     for name, method in rcekit.DETECTION_METHODS.items()}
        # What each method really reports, not just its ceiling. Exempting
        # `needs-review` for everyone let `lookup` name a tier it never emits.
        cls.reported = {name: {method.tier} | set(method.also_reports)
                        for name, method in rcekit.DETECTION_METHODS.items()}
        # Every tier any method can report, plus the one weaker tier several of
        # them fall back to. A token outside this set is prose, not a claim.
        cls.known = set(cls.tiers.values()) | {"needs-review"}

    def _rows(self, path, header_ends_with):
        """Rows of the one table whose header's last cell is
        ``header_ends_with``, each as a dict keyed by its column heading.

        Keyed rather than positional because the column a claim lives in is
        the point: the guide's `lookup` row names `oob` in its prose, and
        reading the whole row for method names made that row look like one
        about `oob` and skipped it.
        """
        rows, header = [], None
        for line in path.read_text(encoding="utf-8").splitlines():
            match = self.ROW_RE.match(line)
            if not match:
                header = None
                continue
            cells = row_cells(match.group(1))
            if cells[-1] == header_ends_with:
                header = cells
                continue
            if header and not set(cells[0]) <= set("- :"):
                rows.append(dict(zip(header, cells)))
        return rows

    def test_the_reference_table_documents_every_registered_method(self):
        """A method that lands without a row here is a capability nobody can
        look up, and the table is where an operator checks what a verdict will
        be before spending a run on it."""
        rows = self._rows(self.REFERENCE, "Tier it can reach")
        self.assertTrue(rows, "the reference method table was not found")
        documented = {match.group(1) for row in rows
                      for match in [self.CODE_RE.search(row[self.METHOD_COL])] if match}
        self.assertEqual(
            sorted(set(self.tiers) - documented), [],
            "registered methods with no row in docs/reference.md")

    def test_every_reference_row_names_tiers_its_method_can_reach(self):
        rows = self._rows(self.REFERENCE, "Tier it can reach")
        self.assertTrue(rows, "the reference method table was not found")
        checked = 0
        for row in rows:
            name = self.CODE_RE.search(row[self.METHOD_COL])
            # A row naming something that is not a registered method is a row
            # advertising a `--methods` value the CLI rejects. Skipping it made
            # the completeness test one-way: a method *removed* from
            # DETECTION_METHODS left its row behind, every remaining row still
            # matched, the floor below was still met, and the page went on
            # offering a flag that no longer exists.
            self.assertTrue(
                name and name.group(1) in self.tiers,
                f"docs/reference.md documents `{row[self.METHOD_COL]}`, which is "
                "not a registered method")
            name = name.group(1)
            checked += 1
            tier = self.tiers[name]
            claimed = {token for token in self.CODE_RE.findall(row["Tier it can reach"])
                       if token in self.known}
            with self.subTest(method=name):
                self.assertIn(
                    tier, claimed,
                    f"the `{name}` row never names {tier}, the tier it reports")
                # A ceiling column may name a weaker tier the method really
                # emits -- and only the ones it really does. Exempting
                # `needs-review` for every method let `lookup` name a verdict
                # it never emits and still pass.
                self.assertEqual(
                    sorted(claimed - self.reported[name]), [],
                    f"the `{name}` row names a tier it does not report; it "
                    f"reports {', '.join(sorted(self.reported[name]))}")
        self.assertGreaterEqual(checked, 6, "no reference rows were checked")

    def test_every_reference_row_names_the_rung_its_method_declares(self):
        """The rung is what an operator chooses a run on, so the page has to
        agree with the class about it.

        The same drift as the tier column, one column over: a rung written out
        by hand goes stale the moment a method's changes, and the operator
        acting on the page would be told to pass a flag the tool does not want
        or to skip one it does."""
        rows = self._rows(self.REFERENCE, "Tier it can reach")
        checked = 0
        for row in rows:
            name = self.CODE_RE.search(row[self.METHOD_COL])
            if not name or name.group(1) not in self.tiers:
                continue
            name = name.group(1)
            checked += 1
            declared = rcekit.DETECTION_METHODS[name].safety
            documented = self.CODE_RE.findall(row["Rung"])
            with self.subTest(method=name):
                self.assertEqual(
                    documented, [declared],
                    f"docs/reference.md puts `{name}` at {documented}, but the class "
                    f"declares {declared}")
        self.assertGreaterEqual(checked, 6, "no reference rungs were checked")

    def test_no_guide_row_offers_a_sub_confirmed_method_as_confirming(self):
        """The guide's table is what an operator reads to pick the next run.

        It has no tier column, so there is nothing to require -- but a row that
        promises confirmation for a method that cannot confirm is the same
        overclaim `blind_sink_advice` carried, in the document that tells
        people which method to reach for."""
        rows = self._rows(self.GUIDE, "Cost")
        self.assertTrue(rows, "the guide's method table was not found")
        checked = 0
        for row in rows:
            # Only the `Use` column says what the row recommends. The rest is
            # prose, and the `lookup` row's prose names `oob` -- reading the
            # whole row made this skip the one row it was written for.
            methods = [token.strip() for token in
                       ",".join(self.CODE_RE.findall(row["Use"])).split(",")
                       if token.strip() in self.tiers]
            if not methods or any(self.tiers[m] == "confirmed" for m in methods):
                continue
            checked += 1
            claim = DENIAL_RE.sub("", " ".join(row.values()))
            with self.subTest(methods=methods):
                self.assertNotIn(
                    "confirm", claim.lower(),
                    f"the row for {methods} describes confirmation, but "
                    f"{', '.join(f'{m} reaches {self.tiers[m]}' for m in methods)}")
        self.assertGreaterEqual(checked, 2, "the guide rows for sub-confirmed "
                                            "methods were not reached")


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
        # Newlines joined: argparse wraps help at word boundaries, so a name
        # survives intact but may sit across two lines.
        cls.help_text = " ".join(result.stdout.split())
        # The unjoined lines as well, because the indentation is what separates
        # one flag's help from the next one's.
        cls.help_lines = result.stdout.splitlines()
        cls.reference_text = (DOCS_DIR / "reference.md").read_text(encoding="utf-8")

    @classmethod
    def _option_help(cls, option):
        """The help argparse prints for one flag, its wrapped lines rejoined.

        A question about one flag cannot be asked of the whole page. Every
        detection method's name also occurs somewhere else in `--help` --
        `file` inside `--request-file`, `write` inside `--file-write-path`,
        `deser` inside `--deser-formats`, `time` inside `--time-base` -- so a
        substring test against `help_text` would pass against a `--methods`
        help that named none of them.
        """
        collected, inside = [], False
        for line in cls.help_lines:
            declaration = DECLARATION_RE.match(line)
            if declaration:
                if inside:
                    break              # the next flag begins
                inside = option in OPTION_RE.findall(declaration.group(1))
                if inside:
                    # argparse puts the first words of the description on the
                    # declaration line itself whenever the flag is short.
                    collected.append(line[len(declaration.group(0)):])
                continue
            if inside:
                if not line.strip():
                    break              # the group ends
                collected.append(line)
        return " ".join(" ".join(collected).split())

    def test_the_eval_engines_help_names_every_carrier_the_corpus_ships(self):
        """The help enumerated three engines by hand and two more were added.

        An operator narrowing `--eval-engines` reads that list and nothing else,
        so a stale one tells them an engine needs no carrier when it does --
        and they cut the only probe that could have confirmed it. Every
        hand-written list of this kind in this repository has gone stale; this
        one is held to the corpus instead."""
        carriers = rcekit.RCEKit().eval_carriers
        self.assertTrue(carriers)
        missing = sorted(n for n in carriers if n not in self.help_text)
        self.assertFalse(
            missing, f"--eval-engines help does not name {missing}")

    def test_the_methods_help_names_every_registered_detection_method(self):
        """The help enumerated five of the registered methods by hand.

        `write`, `lookup` and `deser` were registered in `DETECTION_METHODS`
        and had never once been named in the help, so `--help` described a
        whole target class as out of reach -- a write primitive, a
        `${jndi:...}` sink, a deserializing endpoint -- while the method for
        it was already shipping. An operator choosing methods reads that list
        and nothing else. Held to the registry, exactly as `--eval-engines` is
        held to the corpus above."""
        methods = rcekit.DETECTION_METHODS
        self.assertTrue(methods)
        help_text = self._option_help("--methods")
        # Non-vacuity, in both directions: the slice has to be the `--methods`
        # help, and it has to stop before the next flag's -- a helper that
        # returned the whole page would make the assertion below meaningless.
        self.assertIn("Comma-separated", help_text)
        self.assertNotIn("--time-base", help_text)
        # An entry is the name followed by the parenthesis that opens its
        # description, because mere presence is not a claim about the method.
        # A flag named after one would satisfy that -- `--file-read-url` for
        # `file` -- and so would another method's prose: the help said `file`
        # was a "write+read-back", which is how `write` counted as named for
        # as long as it went undocumented.
        missing = sorted(
            name for name in methods
            if not re.search(rf"(?<![\w-]){re.escape(name)} \(", help_text)
        )
        self.assertFalse(missing, f"--methods help does not name {missing}")

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
