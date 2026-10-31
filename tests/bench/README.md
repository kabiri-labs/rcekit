# Coverage benchmark

The unit suite proves RCEKit builds the right payloads and reaches the right
verdict from a given response. It cannot prove RCEKit confirms **Webmin**.

This harness closes that gap. Each case points at a real vulnerable build, runs
the tool the way an operator would, and checks the verdict against what the
README claims. It is what makes a coverage claim checkable instead of asserted.

## Running it

Cases that declare a `vulhub_path` need Docker and a
[vulhub](https://github.com/vulhub/vulhub) checkout:

```bash
git clone https://github.com/vulhub/vulhub.git ~/vulhub

python tests/bench/runner.py --list
python tests/bench/runner.py --case webmin-cve-2019-15107 --vulhub-root ~/vulhub
python tests/bench/runner.py --all --vulhub-root ~/vulhub --markdown coverage.md
```

Exit status is 0 only when every case passed, so this drops into CI as-is.

> These are deliberately vulnerable services. Run them on a machine you control
> and tear them down afterwards. The runner passes `--acknowledge-consent` for
> you, because a bench target is one you started yourself moments earlier — only
> point cases at infrastructure you own.

It is **not** part of `python -m unittest discover -s tests`. Cases pull real
images and take minutes; the default suite must stay fast and dependency-free.
The harness's own tests do run there (`tests/test_bench_runner.py`) and need no
Docker.

## Every case has a control

A benchmark without negative controls measures nothing. A tool that shouted
`executed` at every target would score full marks on the vulnerable half, and
the harness would report that as progress. So a case passes only when **both**
halves land, and `negative_control` is a required key.

The runner refuses to load a case whose control cannot measure anything:

- **No control at all.**
- **A control that expects `executed`** — a contradiction.
- **A control that runs the identical invocation against an identical target.**
  Judged on what it would actually run, not on which keys it declares: copying
  the vulnerable `invocation` into the control is the same non-control as
  omitting it. Vary the invocation (a different method or injection point) or
  the target (a patched build). Reusing the *same* target with a *different*
  invocation is the normal case and is fine.
- **A control that expects `error` or `nothing-tested`.** Both mean the run never
  exercised the target, so such a control would stay green with the detection
  engine entirely broken — exactly what a control exists to catch. A control may
  expect `negative`, `inconclusive`, or any weaker tier. (The vulnerable half may
  still expect `error`: "an unreachable target reports `error`, not `negative`"
  is a real property worth pinning.)

Controls come in 4 kinds, and all of them share one invariant: the control must
not reach `executed`. `kind` is **required**, and the runner checks that it is
one of the values below -- presence and membership, and that is the whole of the
check. That the label *describes* the control is the case author's claim, and a
reviewer is what establishes it.

Deriving it instead -- comparing what the two halves' methods and targets are --
was written and withdrawn. It means modelling rcekit's CLI inside this harness:
its grammar (`--methods x`, `--methods=x`, `-r file`, `-rfile`, a repeat taking
the last value, abbreviations), then which flags constitute "the target", then
which verdicts each method can emit. Seven review findings came out of that in
two days, and the target half of it was unsound anyway: a different
`--verify-url` or request-file name does not establish a different deployment,
let alone a patched one -- two paths on one host are two URLs and one target.

A shared parser and a real definition of target identity are their own piece of
work, not a condition on a label.

| Kind | What it proves | Example |
|---|---|---|
| `patched-build` | The tool does not confirm on a fixed version | same case against a patched image |
| `class-attribution` | The tool names the class, rather than flagging the parameter | S2-001 probed with `reflected` → `negative` |
| `tier-ceiling` | A weaker signal is not promoted on a target where it happens to be right | Webmin probed with `time` → `timing-sink` |
| `channel-isolation` | The verdict rests on the method's own channel, not on the target merely reacting | Webmin's `file` probe writing to an unserved path → `negative` |

`tier-ceiling` is the one people skip, and it is the one that protects the tool's
central promise. Timing produces no computed value; if it were ever promoted to
`executed` on a genuinely vulnerable sink, the erosion would look like a
success.

## Case format

```json
{
  "name": "webmin-cve-2019-15107",
  "rce_class": "OS command injection (results-based)",
  "target": "Webmin 1.910 — CVE-2019-15107",
  "vulhub_path": "webmin/CVE-2019-15107",
  "wait_for": {"url": "https://127.0.0.1:10000/", "status": 200, "timeout": 180},
  "invocation": ["-r", "{bench}/requests/webmin.txt", "-p", "old", "--methods", "reflected"],
  "expect": "executed",
  "expect_method": "reflected",
  "negative_control": {"kind": "tier-ceiling", "invocation": ["..."], "expect": "timing-sink"}
}
```

| Key | Meaning |
|---|---|
| `vulhub_path` | Directory under `--vulhub-root`; the runner runs `docker compose up -d` there |
| `compose` / `compose_down` | Explicit argv, when the standard compose commands are not enough |
| `wait_for` | Poll until the target answers, so a slow boot is not read as a regression |
| `run_in` | Optional. `{image, network, ip}` — run RCEKit **inside a container** on that network instead of on the host, for a method whose callback needs a port the host does not have free. The repository is mounted read-only |
| `share_target` | Optional, default `false`. Bring the container up **once** for both halves instead of once each. The teardown between them is `down -v`, so by default the control meets a *fresh* target -- set this only when neither half changes the target's state, and never for a case whose vulnerable half writes a file or plants a shell. The runner rejects it on a case whose control brings up a different target |
| `timeout` | Seconds one run may take (default 900). `negative_control` may set its own, and usually needs to: the method a tier-ceiling control exercises is the expensive one |
| `invocation` | RCEKit arguments; `--acknowledge-consent` and `--detect-json` are added by the runner |
| `expect` | `executed`, `timing-sink`, `file-write`, `evaluation-sink`, `deserialization-sink`, `lookup-sink`, `needs-review`, `negative`, `inconclusive`, `error`, `nothing-tested` — read off the classes, so a new tier is valid the moment a method reports it |
| `expect_method` | Optional. `reflected`, or the full carrier `reflected/unix/raw` |
| `negative_control` | Required. Its own `invocation` and/or `compose`, plus its `expect` and its `kind` |

`{bench}` and `{repo}` in an `invocation` expand to this directory and the repo
root, so a case can reference a captured request without a fragile relative path.

Omit `vulhub_path` and `compose` to benchmark a target that is **already
running** — useful for a target you brought up by hand, and how the harness's
own tests run without Docker.

## Why the runner reads JSON, not stdout

The runner appends `--detect-json` and reads the result from there. Scraping the
text report cannot be made reliable: a probe payload may contain a literal
newline — the newline separator is a real one — so line-oriented parsing splits
a payload in half, and the detection path exits 0 whether it confirmed or came
back clean.

The overall verdict follows what an operator must not miss, not what is most
frequent: one `executed` among a hundred negatives is the finding. `error` is
reported only when *nothing* reached the target, and a run that built no probes
is `nothing-tested` — never `negative`, which would read as "not vulnerable".

## Adding a case

New detection coverage should arrive with a bench case. Write the case, run it
against the real target, and paste the generated table row into the README next
to the claim it supports. If a class only reaches a weaker tier, say so — the
README table must not outrun the engine.

## Status

The first two cases were executed through this harness against vulhub on Docker,
and that run is what the section above says a first run is: validation of the
case files. Both needed correcting.

`struts2-s2-001` reported `negative` from 700 probes **against a target that is
vulnerable** — the benchmark's own false negative, and the one failure it exists
to prevent. It POSTed only `username`, and the login action throws before it
re-renders the form unless `password` is present too, so every probe got an
HTTP 500 and the injected value was never evaluated. The case now sends both
fields and confirms with 70 of 700 probes through the `%{a*b}` OGNL form, while
its class-attribution control stays clean at 844 probes.

`webmin-cve-2019-15107` confirmed on the vulnerable half but its control was cut
short: a timing regression sends real sleeps, and 1174s of them did not fit the
900s default. The control now carries its own `timeout`, and the case reaches
`timing-sink` there as it always should have.

Reaching Webmin at all needed a fix in the tool rather than the case — a current
OpenSSL refuses its TLS handshake outright, so every probe was reported `error`
until `--insecure` was made to lower the security level as well as the
certificate check.

`python tests/bench/runner.py --all` is green: **10/10, in 55m48s, at 3.0.1**
(2026-10-01). That run is the one 3.0.1 was gated on: retiring a `reflected`
probe shape is squarely in the "touching a method's probe construction" case for
re-running this, and the risk it carries is a false negative on a real shell.
None appeared — Webmin's `reflected` and `file`, Struts2's `eval`, OpenTSDB's
`oob`, Tomcat's `write` and HugeGraph's shell body all still reach `executed`.
The tenth case is new in 3.0.1 and exists for its control: with the retired
shape restored it fails, reporting `executed` where it expects `negative`.

The three cases above were last executed as a set at 2.36.0, and
36 commits touched `rcekit.py` between that run and 2.45.5 — including the
response decoding rewrite in 2.45.4, which is squarely in the "touching
delivery" case for re-running this. None of them regressed against real
software, at 2.45.7 or at 3.0.0.

3.0.0 renamed the verdict every case expects, which is the other reason for
this run: a rename applied to a stored result proves nothing about what the
tool now reports. The table below is what the 3.0.0 run printed. It came in
faster than the 1h36m48s at 2.45.7, and none of that is the tool -- most of
the images were already pulled.

Both of those cases set `share_target`, because neither half writes anything: the
vulnerable halves compute arithmetic through a shell or an OGNL evaluator, and
the controls probe for a class that is not there or hold a timing signal at
its own tier. Measured on `struts2-s2-001` against vulhub on Docker: **33.8s**
bringing the container up for each half, **22.9s** sharing it, with both halves
reaching the same verdicts either way. That is the container start, which on a
fast case is most of the run.

    | RCE class | Target | Method | Verdict | Control | Result |
    |---|---|---|---|---|---|
    | Deserialization sink (fastjson autoType) | Spring Boot on fastjson 1.2.83 | `deser` | `deserialization-sink` | `negative` | pass |
    | Expression injection (Gremlin/Groovy) | Apache HugeGraph 1.2.0 | `eval` | **`executed`** | `negative` | pass |
    | OS command injection | Apache HugeGraph 1.2.0 | `reflected` | **`executed`** | `negative` | pass |
    | Expression-lookup sink (Log4Shell/JNDI) | Apache Solr 8.11.0 -- CVE-2021-44228 | `lookup` | `lookup-sink` | `negative` | pass |
    | Blind command injection (gnuplot) | OpenTSDB 2.4.1 -- CVE-2023-25826 | `oob` | **`executed`** | `timing-sink` | pass |
    | Expression injection (OGNL) | Apache Struts2 -- S2-001 | `eval` | **`executed`** | `negative` | pass |
    | Write primitive (PUT a JSP) | Apache Tomcat 8.5.19 -- CVE-2017-12615 | `write` | **`executed`** | `negative` | pass |
    | OS command injection (self-OOB read-back) | Webmin 1.910 -- CVE-2019-15107 | `file` | **`executed`** | `negative` | pass |
    | OS command injection (results-based) | Webmin 1.910 -- CVE-2019-15107 | `reflected` | **`executed`** | `timing-sink` | pass |

Six more were added after that sweep and each was run on its own, so they are
listed apart from it rather than folded into a figure no run produced. The
count is read off `tests/bench/cases/` rather than incremented by hand, which
is how this paragraph came to say three while the table under it held four and
omitted `argv` altogether:

    | RCE class | Target | Method | Verdict | Control | Result | Time |
    |---|---|---|---|---|---|---|
    | Predicate sink, nothing rendered (Mongo `$where`) | mongo-express 0.53.0 on MongoDB 3.4 | `boolean` | `evaluation-sink` | `negative` | pass | 29.9s |
    | OS command injection, found by enumeration | Webmin 1.910 -- CVE-2019-15107 | `reflected` | **`executed`** | `negative` | pass | 4m32s |
    | Blind command injection, timing as the subject | Webmin 1.910 -- CVE-2019-15107 | `time` | `timing-sink` | `negative` | pass | 21m21s |
    | Argument injection (no-shell `argv` sink) | GitList 0.6.0 -- CVE-2018-1000533 | `argv` | **`executed`** | `negative` | pass | 18.3s |
    | File inclusion, arbitrary read | PHP 7.1.3 inclusion sink | `include` | `file-read` | `negative` | pass | 2.6s |
    | File inclusion reaching execution | ThinkPHP 6.0.12 inclusion sink | `include` | **`executed`** | `negative` | pass | 2.6s |

16 cases now cover the ledger's 15 rows. Both figures are counted from `tests/bench/cases/` and the README table rather than carried forward; the pair here read 13 and 12 while the catalogue already held 14 and 13, which is what a figure maintained by hand does. More cases than rows, in both
directions and for different reasons: the OpenTSDB `time` row is still the
*control* half of that case rather than one of its own, because a tier ceiling
is a claim about a method that must not be promoted and the place that claim
belongs is a control; while `webmin-cve-2019-15107-enumerated` has no row at
all, because what it proves is the enumerator rather than a method or a tier,
and the ledger is organised by method.

### The fourth row now has one, and it needed the harness to grow

Log4Shell. `--methods lookup` proves an expression-lookup sink out of band, and
a case for it could not be written until two things were true.

The first is the port. A JNDI lookup resolves `<token>.<oob-host>` before it
does anything else, and a resolver asks **UDP 53**, so the callback only lands
if RCEKit's listener owns that port on an address the target's resolver uses.
Nothing local gets you there: a bare `--oob-host` IP cannot carry the token as a
DNS label, and a delegated domain is not something a benchmark can arrange.

So the run happens where the port is free. `run_in` puts RCEKit in a container
on the target's own network, at a fixed address, and an override points Solr's
`dns:` at it ([`overrides/log4shell-dns.yml`](overrides/log4shell-dns.yml)). The
repository is mounted read-only and the image is a stock Python; nothing is
built.

The second was the harness's own vocabulary. `VALID_EXPECTATIONS` was written
out by hand and had drifted: neither `lookup-sink` nor `deserialization-sink`
was in it, so a case for either method could not be *loaded*, let alone run.
Both lists are read from `DETECTION_METHODS` now, and a tier the engine can emit
is a tier a case can expect.

**The control is the argument for the method.** `oob` applies to this target --
Solr is Java, and a Java application can shell out -- but every probe it builds
is a shell command, and a sink that interpolates `${jndi:...}` runs none of
them. So `oob` must come back `negative` against a target that *is* exploitable.
That claim is what `lookup` was added for, and until this case ran it rested on
a fixture. It now rests on Solr 8.11.0.


### Four more cases, and what each one had to get right

The four added at 2.45.5 cover the rows that had been measured by hand. None of
them passed on the first run, and not one of the failures was the tool's.

**`opentsdb-cve-2023-25826`** needed the target to hold *state* before a probe
could reach the sink. The injection point is the `key=` parameter, which
OpenTSDB writes into a gnuplot script — but with no data for the queried metric
the request dies in `TSQuery.buildQueries` and answers 500 long before gnuplot
runs. Pointed at an empty target, the tool reports `negative` against a build
that is vulnerable.

There is no `setup` hook here and the case does not need one. A one-shot service
in the override writes the data point, and `wait_for` polls the same query
without an injection — 200 once the point is in, 500 while the metric is absent.
The race closes on a *condition* rather than on a sleep, which is the whole
reason `wait_for` exists.

**`fastjson-1.2.83`** is the `deser` row, and it does not rest on the shape
oracle: fastjson answers a truncated stream exactly as it answers a complete one,
so the shape differential reports `negative` here by design and the DNS gadget is
what reaches the tier. Its control runs `eval` through the same endpoint and must
stay `negative` — parsing an object graph is not evaluating an expression.

**`hugegraph-gremlin-eval` and `hugegraph-gremlin-shell`** are two rows against
one target, and separating them is the point.

The Gremlin API evaluates Groovy unauthenticated by design, so `eval` confirms
and the row carries no advisory: 1.3.0 answers the arithmetic exactly as 1.2.0
does, and the ProcessBuilder body reaches a shell on 1.3.0 too — both measured
against the patched image rather than assumed.

The shell case **must** use the ProcessBuilder body, and writing it against the
plain endpoint would have produced a green case reproducing a false claim. Until
3.0.1 `reflected` confirmed on the plain endpoint too, and wrongly: Groovy reads
`; expr A + B` as the command expression `expr(A + B)`, computes the sum, fails
to resolve the method and echoes the result in its error, with no shell
anywhere. That probe shape is retired, and
[`hugegraph-gremlin-reflected-class`](cases/hugegraph-gremlin-reflected-class.json)
is the case that keeps it retired — same request, same endpoint, `reflected`
required to come back `negative`, and it fails with the shape restored.

What earns the OS-command class here is not the arithmetic but the substitution
collapse — the response carrying `$(echo TAG)` resolved, at HTTP 200, which only
a POSIX shell produces. Measured on this target with every shape mapped: the
ProcessBuilder body confirms through 4 tag-bracketed shapes, the plain endpoint
through none.

Readiness cost three attempts and is worth writing down. HugeGraph runs two
servers: the REST API on 8080, and the Gremlin Server — which every probe here
reaches — as a separate process on 8182 that comes up later and binds the
container's loopback, so it cannot be polled from outside. `/versions` answers
200 at t=12s and `/graphs` at t=18s while the engine is still refusing with
`Connect to 127.0.0.1:8182 failed: Connection refused` wrapped in a 500; all
three agree at t=21s. A case started on `/graphs` ran 240 of 468 probes against
an engine that was not listening and confirmed 2 where a settled target confirms
10 — a pass by luck, and the next slower machine would have read `negative`
against a target that is vulnerable. A GET on `/gremlin` goes through the engine,
so that is what both cases wait on.

**What the harness could not tell us.** Three of these first runs failed with
`compose up failed` and nothing else: a leftover network holding the case's
subnet, and a container from an earlier measurement holding port 5005. The real
messages — `Pool overlaps with other one on this address space`, `Bind for
0.0.0.0:5005 failed: port is already allocated` — never reached the report, so
each one had to be reproduced by hand to find out. For a harness whose whole job
is not to mistake one failure for another, "the target could not start" and "the
tool did not confirm" should not look alike.

**Fixed.** `bring_up` captured compose's output and read only the return code
off it, so the reason was in hand and thrown away. A failure now carries the
last lines compose printed:

```
[bench]   -> FAIL
  compose up failed (exit 1): Error response from daemon: failed to set up
  container networking: Bind for 0.0.0.0:8080 failed: port is already allocated
```

Measured against a real clash rather than a fixture: two compose projects for
`struts2-s2-001` brought up against the same 8080, with the resulting stderr
kept verbatim in the test that pins the trimming.

Both streams are read, and both reductions keep the **end** -- the last few
lines, and the last characters when those are still too long. Container-runtime
errors read outside-in and the actionable part is last, so cutting from the
left discards the thing worth having: the real clash above measured 273
characters with `Bind for ...` starting at 218, and three services failing in
one `up` comes to about 825.

**Nothing is dropped for what it says.** A third reduction used to start the
detail at the first line containing `error`, which turned

```
Bind for 0.0.0.0:5005 failed: port is already allocated
warning: ERROR_LOG variable is not set
```

into the warning alone -- the reason contains no such word and the warning
contains it by accident. What is left is positional and bounded, which can be
reasoned about without reading the text.

**No stream is ever dropped**, and every stream that said anything is
reported, labelled when there is more than one. Two earlier versions chose a
single stream instead and both lost the reason: first stderr unless it was
empty, which let a deprecation warning hide a reason on stdout; then whichever
stream's tail contained `error`, which let `warning: ERROR_LOG variable is not
set` hide `Bind for 0.0.0.0:5005 failed: port is already allocated` -- a line
containing no such word.

A `compose` entry is whatever argv a case gives, so no rule can tell from the
text which stream matters, and a rule that discards on being wrong loses the
thing this exists to carry. What drove both attempts was keeping the common
failure free of build chatter, which is a preference that was allowed to
outrank the guarantee; measured, that chatter is about 60 characters and the
reason still comes first.

The runner also prints how long each case and the whole run took, and
line-buffers its output. Both were worked around from outside -- a figure read
off a file's timestamps and typed into this document by hand, and a remembered
`python -u` -- and neither should have needed remembering.

### `write` has one now, and it cost two fixes in the tool

`tomcat-cve-2017-12615` is the canonical shape for this method and the one its
docstring names. `PUT /rcekit-probe.jsp/` with the content in the body, no
session, no chain: the trailing slash is the bypass, because the DefaultServlet
refuses a `.jsp` target and normalises the path to the same file after the check.
The method substitutes file content and names a read-back URL, and this target
needs exactly those two things.

The control is the argument for the method's existence rather than a formality.
This target **is** exploitable and `write` confirms on it, but nothing in the
vulnerable response is computed -- a PUT answers 204 with an empty body -- so
`reflected` must come back `negative`. Measured: 959 probes, every one answered
204, verdict `negative`. If that control ever confirms, the tiers have run
together.

`share_target` is deliberately absent, which is the first case here to need that.
Both halves write a file into the web root, and the harness never shares a target
whose halves write: a control measured against a target the other half has
altered is measuring something else, whether or not the verdict happens to move.
A fresh container costs 3 seconds here.

The first version of that paragraph said the control left 959 files behind, which
was a guess dressed as a measurement. It does not: the control's URL is fixed and
only the body carries `FUZZ`, so its 959 PUTs overwrite **one** 35-byte file.
Counted in the container before and after -- 1 JSP, then 2, the second being the
control's. The setting is right for the rule's reason, not for the vivid one.

**What this case caught that no fixture could.** Two defects, both in probe
construction, both invisible from the unit suite:

* The probe carried **whitespace** -- `<?= a*b ?>` -- and a sink that tokenises
  before it writes rejects that outright. Found through RRDtool, reached via
  Cacti's `right_axis_label`; fixed in 2.45.6. A fixture stores whatever it is
  given and never splits on spaces.
* The product **overflowed a signed 32-bit int**. JSP and ASPX evaluate `a*b` as
  int32 and RCEKit computed it in Python, so `97233*38786` came back
  `-523688158` against an expected `3771279138`. The old operand range overflowed
  in 56% of runs, drawn once per run, against exactly the JVM and .NET targets
  this method was written for. Fixed in 2.45.7.

The second is the sharper lesson: **a fixture that computes in Python never
disagrees with a tool that computes in Python.** Only an interpreter with a
different integer width does, and only a real target has one.

**One environmental hazard worth recording.** This case and `struts2-s2-001`
both build locally, and a build resolves its base image through the registry even
when the layers are cached. Both were seen failing that resolution -- Tomcat with
a `403` on the manifest HEAD, Struts2 in a full `--all` run that had otherwise
taken 54 minutes -- while `docker pull` of the same tag succeeded immediately.
Pulling `vulhub/tomcat:8.5` and `vulhub/tomcat:8.5.19` first clears both. The
runner reports only `compose up failed` for this -- the same gap described a
section above, and the reason a 54-minute run had to be repeated to find out
whether anything was actually broken.

### `file` needed no new target, and its control is the sharpest here

`webmin-cve-2019-15107-file` reads the injection the `reflected` row already
uses through a different channel. `file` needs no listener and no egress: the
probe makes the target write a random token to a path it also serves, and a
followup fetch reads it back. Webmin's theme ships an `unauthenticated/`
directory that miniserv serves without a session, and the CGI runs as root, so
it is writable. 33 of 195 probes confirm.

No new environment was needed, and that was not luck. The method's docstring is
explicit that the read-back path **does not have to be a web root** -- an LFI
parameter, a download or export handler, a `/tmp`-backed preview all qualify --
so any target with command injection and something readable will do. Three
already in this suite have command injection. Reading that before choosing a
target is what kept this off Cacti CVE-2022-46169, which would have meant
rebuilding an install wizard in SQL.

**The control isolates the channel, not the class, and that is the point.** It
is the identical invocation with the write path moved to `/tmp`, which Webmin
does not serve:

* `negative` across 206 probes, every one reporting `token absent from the
  fetched file`
* while **44 files really did land in /tmp**, the first holding its token

So the command ran, the write landed, the token is on disk -- and the method
still refuses to confirm, because its channel did not carry it. That is the
claim `file` makes and no other method does: the proof is the target *serving
the value back*, not the command running. Nothing else in this suite separates
"the target did something" from "the target returned what I planted".

A class-attribution control was tried first -- `eval` comes back `negative` here
across 840 probes, because a shell is not an expression evaluator. True, and it
defends the wrong claim: `webmin-cve-2019-15107` already separates those classes,
and nothing in it would catch `file` confirming from a response rather than a
fetch.

### `boolean` has a case now, and the target is not the one named here

`--methods boolean` reads a sink that evaluates a predicate and renders nothing
of it. The target that shape was designed against is MongoDB `$where`, and the
case would be a Mongo image with an application in front of it.

The case is `mongo-express-where-boolean`, and `boolean` is no longer the
method without one. The question a fixture could not settle -- "does an ordinary
application's response hold still enough between two requests to carry one bit"
-- is the one this case answers, because this oracle reads the *shape* of a real
response and real responses carry timestamps, counters and pagination that a
fixture only imitates.

**Chartbrew CVE-2026-25887 was the candidate named here and it cannot be
written.** Its sink is behind a login and three setup steps -- project,
connection, dataset -- which a case could not reach when this was written,
because a case can only `docker compose up` and then run one invocation.

That reason has since expired and been replaced by a better one, which is worth
recording so nobody spends a container cycle rediscovering it. The runner has
since gained what it lacked: a chain carries a login and substitutes `{var}`
from an earlier step's `extract`, so those three setup steps are now
expressible. But `boolean` is refused on a chain by name --
`CHAIN_UNSUPPORTED_METHODS` in `rcekit.py` -- because it compares response
*shape* across a shuffled series, and a chain's setup steps and per-probe
session change that shape for reasons that have nothing to do with the sink. So
the obstacle moved from the harness, where it was fixable, to the oracle, where
lifting it would be a change to what a detection method reports.

MongoDB's `$where` on a one-document collection a fresh `mongo:3.4` already
has needs none of it. Measured by hand on
`/db/admin/system.version` before the case was written: a true predicate returns
60 table rows and 19707 bytes, a false one 54 rows and 17452 bytes. Through the
tool, `evaluation-sink` on the `raw` and `html` contexts over 81 probes.

The control is **class attribution**, not the `patched-build` this section used
to specify, and the reason is that `$where` is MongoDB's documented feature
rather than a defect -- no patched build removes it, and mongo-express 0.54.0
fixes a different sink (`/checkValid`, CVE-2019-10758). So the control moves the
payload from `{"$where": ...}` to `{"version": ...}`: same endpoint, same
parameter, same query document, but a position MongoDB compares literally
instead of evaluating. Measured identical for true and false -- 17450 bytes and
54 rows either way -- and `negative` on all three contexts. A differential here
therefore requires an evaluator, not merely a value that reaches the query.
`patched-build` still has no shipped user.

`/checkValid`, the actual CVE-2019-10758 sink, was tried first and measured
`negative` over 129 probes at `--verify-active-risk stateful`. It answers
`Valid` in 5 bytes for a true predicate, a false one and an arbitrary
expression alike. An endpoint that answers yes or no *about* an expression is
not the same thing as one whose answer depends on that expression's value, and
that distinction is worth keeping: it is what sent the first draft of this case
at the wrong endpoint.

### `argv` has a case, and its control is the target's own security property

`gitlist-cve-2018-1000533-argv` passed in 18.3s from a cold `compose down -v`:
`executed` on the vulnerable half in one probe, `negative` on the control.

Most controls here have to be constructed — a different method, a different
endpoint, a payload moved to a position nothing evaluates. This one is not
constructed at all. GitList calls `escapeshellarg($query)` and does it
**correctly**, so the value reaches `git grep -i --line-number <value> <branch>`
as one argv element with no shell anywhere. `--methods reflected` at
`--probe-depth full` sends 37 probes and reports `negative` on every one, on the
same endpoint and the same build that `argv` confirms. The control is the thing
the application got right, which is as close as this harness gets to measuring
a method against the reason it exists.

Three details of the probe were measured against the live target rather than
reasoned, and each is the difference between confirming and reporting a clean
negative on a build that executes:

- **The probe ends in `#`, not the `;` the published write-ups use.** git
  appends the path it would have paged, so `;` leaves `README.md` as a bare
  command: it fails, git exits 255, and GitList's
  `catch (RuntimeException) { return false; }` discards the output. Measured in
  the container, the two forms are exit 255 against exit 0 — the command runs
  either way and only one of them comes back.
- **The pager's output imitates git grep's own `tree:file:line:match` format.**
  Whatever consumes that stdout is an application parsing git grep output;
  GitList matches `([\w-._]+):([^:]+):([0-9]+):(.+)` and renders only group 4,
  so a bare `echo <value>` arrives and is dropped by the app's own regex.
- **The URL's branch segment has to be a pattern that matches file content.**
  Once the query is consumed as an option, the branch becomes git grep's
  *pattern*, and the pager only opens when there is a file to page. The stock
  vulhub repo is a 62-byte README containing `repository` and not `master`, so
  `/example/tree/master/search` finds nothing and the pager never runs against a
  target that is fully exploitable. The case uses
  `/example/tree/repository/search`. That is a property of the fixture, not of
  the method: a real GitList hosts repos whose content contains the branch name
  constantly.

`patched-build` was considered for this case and is still unused. A GitList
patched with commit `87b8c26` — which moves the query behind `-e` — would make
the identical option inert, which is exactly what that control kind is for. It
is not used here because a case carries one control and class attribution is
the stronger of the two: it shows the method reaching a sink no other method
can, rather than showing a patch closing it. A second case could carry it, and
would need an image vulhub does not ship.

### `include` has a case, and the target is the method's own ceiling

`php-inclusion-file-read` passed in 2.6s from a cold `compose down -v`:
`file-read` on the vulnerable half, `negative` on the control.

The sink is `include $_GET['file'];` with nothing around it, which is why the
ledger row claims a method and not a CVE -- there is no patch whose absence the
verdict depends on, so the ledger records no advisory against it, as it records
none for the HugeGraph and fastjson rows.

The control is class attribution and it costs nothing to arrange, because
including a file runs no command: `--methods reflected` at `--probe-depth full`
sends 19 probes and reports `negative` on all 19, on the same URL the vulnerable
half confirms. A results-based shell method has nothing to compute here, and
that is what earns `include` its own name rather than a probe shape inside
`reflected`.

14 of 18 probes reached `file-read`. The four that did not are depths 1 and 2 of
each wrapper, and that is correct rather than a miss: the sink runs from
`/var/www/html`, so a climb needs three `../` before it reaches `/proc`. Depth
is swept for exactly that reason -- which one works is a property of the sink's
own directory, and an absolute path and a relative climb both landed here.

**What this case cannot show is execution, and the target said why in its own
words.** The route from an inclusion sink to execution is a wrapper carrying
code, and PHP answered `data:// wrapper is disabled in the server configuration
by allow_url_include=0`; `php://input` failed the same way. That setting has
defaulted off since PHP 5.2, so the route that works on a released build is
two-step -- poison a log or a session file, then include it -- which is a chain,
and belongs to a case of its own rather than to this one.

The read target is `/proc/version`, not `/etc/passwd`. Proving a read needs
content recognisable enough to difference against a control, not the target's
account names; `/etc/passwd` is declared one safety rung up, so this invocation
never pulls it. Both were measured against this build and only one is sent.

A phpMyAdmin case was the first choice and is not available: `CVE-2018-12613` is
released software with an advisory and an unauthenticated inclusion sink, but
`vulhub/phpmyadmin:4.8.1` and `mysql:5.5` both answer 403 from the registry's
blob store on every attempt, 13 apiece, while `hello-world` and
`vulhub/php:7.1.3-apache` pull normally. That is not a transfer retrying fixes.

### The execution half of `include`, and the route that does not work

`thinkphp-lang-include-execute` passed in 2.6s from a cold `compose down -v`:
`executed` on the vulnerable half, `negative` on the control.

The case exists because the obvious route is unavailable on a released build.
Reaching execution from an inclusion sink means a wrapper carrying code --
`data://`, `php://input` -- and both need `allow_url_include`, which PHP has
defaulted off since 5.2 and which `php-inclusion-file-read`'s target refused in
its own words. So this case takes the two-step route that works without it:
make the sink include a script that *writes*, and hand that script its
arguments through the request. PEAR's `pearcmd.php` ships in the official PHP
images, `register_argc_argv` turns the query string into its argv, and
`config-create` writes its output to a path those arguments name.

Two things about the shape were measured rather than reasoned, and each is the
difference between confirming and reporting a clean negative:

- **The payload is the whole query string, not one parameter's value.** argv is
  built from the query string, so `config-create` and the target filename have
  to sit outside the parameter carrying the traversal. That is why the
  invocation marks `?FUZZ` and passes `--verify-url-location raw`:
  percent-encoding the payload would turn the `&` separating those arguments
  into data, and the write would never happen.
- **The proof is the second request.** The write answers 200 whether or not
  anything interpreted the file, so the verdict comes from fetching it back.
  Measured, the fetch returned 11688702 for 6022*1941 with the source form
  `<?=6022*1941?>` absent -- which is the whole difference between a file that
  was interpreted and one served verbatim, the distinction `write` has drawn
  since 2.31.0 and which this method reports the same way.

**The control is a tier ceiling, and it was chosen by measurement.** The
obvious control was `--methods reflected` on the same URL, and it is the wrong
one: measured, it sends 37 probes and 32 come back `error`, because a shell
payload sent raw into a query string breaks the request before it arrives. A
control whose probes mostly never reach the target says nothing about false
confirmation, which is why the runner refuses `error` as an expectation at all.

So the control removes the one thing the proof rests on and keeps everything
else -- the same vulnerable build, the same risk tier, the same probes, with no
`--include-write-url`. Measured, 16 probes reach the target and all 16 come back
`negative`. That is the statement worth pinning: the execution verdict comes
from reading the written file back, and with nowhere to read it from this method
does not reach `executed` on a target where it otherwise does.

### Second-order has no case, and the reason is no longer the harness

`--observe-url` is advertised in the repository README's comparison matrix as a
reach no other tool in it has: the payload lands on one request and executes on
another, and the observed endpoint is differenced against a snapshot taken
before any probe went out. It still has no case. What stood in the way used to
be this harness, and that is no longer true — the blocker is now the absence of
a target, which is a different thing and worth not confusing with the first.

**The harness is ready, and that is measured rather than argued.** A chain is
now the delivery the engine drives: `--verify-chain` requires `--methods` and
builds a `ChainDelivery` that `run_detection` fires — the same `run_detection`
that owns the observed channel's pre-injection control, its per-probe poll and
`--observe-trigger`. Nothing in the case schema needs to grow: `invocation`
already takes arbitrary flags and `{bench}` already expands, so a case can pass
`--verify-chain {bench}/chains/<name>.json --observe-url …` and the runner reads
the verdict from `--detect-json` exactly as it does for every other case.

Run against a local target whose store is **behind a login** —
`POST /login` hands out a token, `POST /notes` requires it and answers `saved`
with no echo of what it stored, `GET /render` renders the stored value through a
shell:

```
[verify] chain http://127.0.0.1:60052 (2 steps)
[detect] cost: ~19 probe(s) x 2 chain step(s) = at least 40 requests
[detect] sent 1 probes (1 result(s)): executed=1
  [reflected/unix/raw] ; echo RKCPGJB$((583113+788018))RKPCTRX$(echo RKCYQME)RKCPGJB
      (target computed 'RKCPGJB1371131RKPCTRXRKCYQMERKCPGJB' on the OBSERVED
       channel -- second-order execution: the value is absent from that
       endpoint's pre-injection control and cannot be reflected, since the
       payload never carried it)
```

Against the twin endpoint that renders the same stored value and executes
nothing, the same invocation sends 19 probes and reports `negative` on all 19.
So the authenticated-store half of the shape is solved: a chain logs in, carries
the token it extracted, and stores a payload no response echoes.

**What a target must still look like**, now stated precisely enough to screen
one:

- The **store may be authenticated.** A chain handles a login and `{var}`
  substitution from an earlier step's `extract`.
- The **render must be reachable without the chain's session.** `_fire_observed`
  takes the url, method, data and headers the flags gave it and nothing else —
  no cookie jar, no chain state, no `{var}` substitution. `--observe-request` is
  a static file, so a token a chain extracted at run time cannot reach it. An
  unauthenticated render, or one behind a credential the operator can write into
  that file, is in reach; one behind the chain's own freshly minted session is
  not.
- The execution must surface a **computed value.** `_observable` requires an
  expected value the payload does not itself carry, which is what stops a target
  that merely stores and renders from reading as a confirmation — so the
  computed-value methods qualify and the token-carrying ones do not.

**No environment in a vulhub checkout has that shape.** All 332 of them were
screened, and the funnel is recorded because the conclusion is only worth as
much as the search behind it:

| Step | Left |
|---|---|
| Environments with a `docker-compose.yml` | 332 |
| After removing classes that cannot be a deferred *execution* sink — SQL injection (21), deserialization (36), path traversal and file read (48), auth bypass and privilege escalation (42), SSRF (7), information disclosure (7), DoS and memory safety (3), XXE (2), XSS (2) | 164 |
| After keeping only those whose own documentation describes both a **store** and a **later act** on it | 18 |
| After reading each of those 18 | **0** |

The 18 were rejected for seven reasons, grouped by the reason rather than by the
product, because the reason is the part that generalises:

| Why not | Environments |
|---|---|
| **In-band**: the execution surfaces in the injected response, so `reflected` or `eval` confirms it directly and nothing is deferred | `craftcms/CVE-2023-41892` (both gadgets POST the same endpoint), `geoserver/CVE-2022-24816`, `goahead/CVE-2017-17562` (the shared object is POSTed and referenced as `/proc/self/fd/0` in one request), `h2database/CVE-2018-10054`, `h2database/CVE-2022-23221` |
| **`write`'s shape**: the stored file is the thing fetched, which `tomcat/CVE-2017-12615` already covers | `weblogic/CVE-2018-2894`, `tomcat/tomcat8` |
| **Not HTTP** | `zabbix/CVE-2017-2824` (trapper protocol on 10051), `spring/CVE-2018-1270` (STOMP over SockJS), `php/xdebug-rce` (DBGp) |
| **No computed value reaches any response**, so there is nothing for `_observable` to confirm | `solr/CVE-2017-12629-RCE` — a real store-then-trigger, `/config` persisting a `RunExecutableListener` that `/update` fires, whose command output goes nowhere readable — and `comfyui/CVE-2025-67303`, `comfyui/CVE-2026-22777`, config tampering ending in a git clone |
| **No HTTP application at all**: the environment is a library or CLI demo | `python/PIL-CVE-2018-16509`, `imagemagick/CVE-2020-29599` |
| **Interactive setup before the vulnerability exists**, which a case cannot drive reproducibly | `cacti/CVE-2025-24367` — the closest miss: post-auth argument injection stored in a graph template and fired when the graph renders, but its own instructions are "click Next repeatedly" and then three GUI flows carrying per-install ids |
| **Executes client-side**, or the store is not an endpoint of the application under test | `pdfjs/CVE-2024-4367`, `kibana/CVE-2020-7012` (needs a write to the Kibana index) |

The template-injection environments — `flask/ssti`, `confluence/CVE-2019-3396`,
`confluence/CVE-2023-22527`, `jimureport/CVE-2023-4450`,
`craftcms/CVE-2024-56145` — survive the class filter and never reach the
shortlist, because nothing in them is deferred: the render *is* the injected
response.

Worth stating because the alternative is worse: a case built on a target brought
up by hand, which passes on one machine and nowhere else, or a purpose-written
vulnerable app composed under Docker — which is a fixture wearing Docker, and a
fixture is the one thing a bench case exists not to be. The local target above
is evidence that the harness works and is deliberately **not** proposed as a
case, for exactly that reason.

So this row stays open, and what would close it is an image: a released
application with a stored sink whose render is reachable without the store's
session, pinned by a compose file of our own.
