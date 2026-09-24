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

Both shipped cases have now been executed through this harness, against vulhub
on Docker. The first run is what the section above says it is: validation of the
case files, and both needed correcting.

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

`python tests/bench/runner.py --all` is green: 3/3, in 34m20s.

Both cases set `share_target`, because neither half writes anything: the
vulnerable halves compute arithmetic through a shell or an OGNL evaluator, and
the controls probe for a class that is not there or hold a timing signal at
`needs-review`. Measured on `struts2-s2-001` against vulhub on Docker: **33.8s**
bringing the container up for each half, **22.9s** sharing it, with both halves
reaching the same verdicts either way. That is the container start, which on a
fast case is most of the run.

    | RCE class | Target | Method | Verdict | Control | Result |
    |---|---|---|---|---|---|
    | Expression-lookup sink (Log4Shell/JNDI) | Apache Solr 8.11.0 -- CVE-2021-44228 | `lookup` | `lookup-sink` | `negative` | pass |
    | Expression injection (OGNL) | Apache Struts2 -- S2-001 | `eval` | **`confirmed`** | `negative` | pass |
    | OS command injection (results-based) | Webmin 1.910 -- CVE-2019-15107 | `reflected` | **`confirmed`** | `needs-review` | pass |

That is every row in the repository README's coverage table: the `reflected`
and `eval` confirmations, the `lookup` sink, and the `time` tier ceiling, which
is the Webmin control here.

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


### `boolean` ships without a case, and this is the reason

`--methods boolean` reads a sink that evaluates a predicate and renders nothing
of it. The target that shape was designed against is MongoDB `$where`, and the
case would be a vulhub Mongo image with an application in front of it -- which
needs a container runtime this build environment does not have.

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
