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
`confirmed` at every target would score full marks on the vulnerable half, and
the harness would report that as progress. So a case passes only when **both**
halves land, and `negative_control` is a required key.

The runner refuses to load a case whose control cannot measure anything:

- **No control at all.**
- **A control that expects `confirmed`** — a contradiction.
- **A control that runs the identical invocation against an identical target.**
  Judged on what it would actually run, not on which keys it declares: copying
  the vulnerable `invocation` into the control is the same non-control as
  omitting it. Vary the invocation (a different method or injection point) or
  the target (a patched build). Reusing the *same* target with a *different*
  invocation is the normal case and is fine.
- **A control that expects `error` or `nothing-tested`.** Both mean the run never
  exercised the target, so such a control would stay green with the detection
  engine entirely broken — exactly what a control exists to catch. A control may
  expect `negative`, `inconclusive`, or `needs-review`. (The vulnerable half may
  still expect `error`: "an unreachable target reports `error`, not `negative`"
  is a real property worth pinning.)

Controls come in three kinds. All three share one invariant: the control must
not reach `confirmed`.

| Kind | What it proves | Example |
|---|---|---|
| `patched-build` | The tool does not confirm on a fixed version | same case against a patched image |
| `class-attribution` | The tool names the class, rather than flagging the parameter | S2-001 probed with `reflected` → `negative` |
| `tier-ceiling` | A weaker signal is not promoted on a target where it happens to be right | Webmin probed with `time` → `needs-review` |

The third is the one people skip, and it is the one that protects the tool's
central promise. Timing produces no computed value; if it were ever promoted to
`confirmed` on a genuinely vulnerable sink, the erosion would look like a
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
  "expect": "confirmed",
  "expect_method": "reflected",
  "negative_control": {"kind": "tier-ceiling", "invocation": ["..."], "expect": "needs-review"}
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
| `expect` | `confirmed`, `needs-review`, `negative`, `inconclusive`, `error`, `nothing-tested` |
| `expect_method` | Optional. `reflected`, or the full carrier `reflected/unix/raw` |
| `negative_control` | Required. Its own `invocation` and/or `compose`, plus its `expect` |

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
frequent: one `confirmed` among a hundred negatives is the finding. `error` is
reported only when *nothing* reached the target, and a run that built no probes
is `nothing-tested` — never `negative`, which would read as "not vulnerable".

## Adding a case

New detection coverage should arrive with a bench case. Write the case, run it
against the real target, and paste the generated table row into the README next
to the claim it supports. If a class only reaches `needs-review`, say so — the
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
`needs-review` there as it always should have.

Reaching Webmin at all needed a fix in the tool rather than the case — a current
OpenSSL refuses its TLS handshake outright, so every probe was reported `error`
until `--insecure` was made to lower the security level as well as the
certificate check.

`python tests/bench/runner.py --all` is green: **8/8, in 54m08s, at 2.45.7**
(2026-09-26). The three cases above were last executed as a set at 2.36.0, and
36 commits touched `rcekit.py` between that run and 2.45.5 — including the
response decoding rewrite in 2.45.4, which is squarely in the "touching
delivery" case for re-running this. None of them regressed against real
software, then or at 2.45.7.

Both of those cases set `share_target`, because neither half writes anything: the
vulnerable halves compute arithmetic through a shell or an OGNL evaluator, and
the controls probe for a class that is not there or hold a timing signal at
`needs-review`. Measured on `struts2-s2-001` against vulhub on Docker: **33.8s**
bringing the container up for each half, **22.9s** sharing it, with both halves
reaching the same verdicts either way. That is the container start, which on a
fast case is most of the run.

    | RCE class | Target | Method | Verdict | Control | Result |
    |---|---|---|---|---|---|
    | Deserialization sink (fastjson autoType) | Spring Boot on fastjson 1.2.83 | `deser` | `deserialization-sink` | `negative` | pass |
    | Expression injection (Gremlin/Groovy) | Apache HugeGraph 1.2.0 | `eval` | **`confirmed`** | `negative` | pass |
    | OS command injection | Apache HugeGraph 1.2.0 | `reflected` | **`confirmed`** | `negative` | pass |
    | Expression-lookup sink (Log4Shell/JNDI) | Apache Solr 8.11.0 -- CVE-2021-44228 | `lookup` | `lookup-sink` | `negative` | pass |
    | Blind command injection (gnuplot) | OpenTSDB 2.4.1 -- CVE-2023-25826 | `oob` | **`confirmed`** | `needs-review` | pass |
    | Expression injection (OGNL) | Apache Struts2 -- S2-001 | `eval` | **`confirmed`** | `negative` | pass |
    | Write primitive (PUT a JSP) | Apache Tomcat 8.5.19 -- CVE-2017-12615 | `write` | **`confirmed`** | `negative` | pass |
    | OS command injection (results-based) | Webmin 1.910 -- CVE-2019-15107 | `reflected` | **`confirmed`** | `needs-review` | pass |

That is every row in the repository README's coverage ledger. 8 cases cover its
10 rows, because the two `time` rows are the *control* halves of the Webmin and
OpenTSDB cases rather than cases of their own — a tier ceiling is a claim about
a method that must not be promoted, and the place that claim belongs is a
control.

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
plain endpoint would have produced a green case reproducing a false claim. On the
plain endpoint `reflected` also confirms, and wrongly: Groovy reads `; expr A + B`
as the command expression `expr(A + B)`, computes the sum, fails to resolve the
method and echoes the result in its error. No shell runs. What earns the
OS-command class is not the arithmetic but the substitution collapse — the
response carrying `$(echo TAG)` resolved, at HTTP 200, which only a POSIX shell
produces.

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
Both halves write files into the web root -- the control left 959 of them -- and
the harness's own rule is never to share a target whose halves write. A fresh
container costs 3 seconds here, which is not worth trading for a control measured
against a directory the other half had already filled.

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

### `boolean` ships without a case, and this is the reason

`--methods boolean` reads a sink that evaluates a predicate and renders nothing
of it. The target that shape was designed against is MongoDB `$where`, and the
case would be a Mongo image with an application in front of it.

The runtime is no longer what stands in the way -- 8 cases run under Docker at
2.45.7 -- so the honest statement is narrower: the case is not written yet. The
candidate is Chartbrew CVE-2026-25887, where a Mongo query reaches `Function()`
behind authentication, across a 4-container stack. `boolean` is one of 2 methods
with no case; `file` is the other, and each is queued against a named target
rather than left open.

So the method ships on its unit suite, as the contribution guide allows, and the
gap is worth stating precisely rather than leaving implied. What a fixture
proves here is narrower than usual: this oracle reads the *shape* of a real
response, and real responses carry session tokens, timestamps, counters and
pagination that a fixture only imitates. Its guards were measured against
fixtures wearing that chrome deliberately, and the unit suite keeps them there
-- but the question "does an ordinary application's response hold still enough
between two requests to carry one bit" is exactly the question a fixture cannot
settle, and it is the one this method lives or dies on.

The control, when the case is written, is the point of it. A vulnerable
`$where` endpoint must reach `needs-review`, and a patched build of the same
application must come back `negative` rather than `inconclusive` -- because an
`inconclusive` from a stable target would mean the signature is reading noise
that is not there.
