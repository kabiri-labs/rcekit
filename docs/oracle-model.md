# The oracle model

Where to audit the verdict logic, and the invariants it is held to.

RCEKit is one module, and that is a distribution virtue rather than an
accident: `rcekit.py` runs alone on a jump box with nothing beside it. The cost
is that the part a reviewer most wants to read — what makes a verdict a verdict
— sits interleaved with HTTP delivery, CLI parsing, injection-point enumeration
and an embedded payload corpus. This page is the index to that part.

Nothing here is a second copy of a claim made elsewhere. [What a verdict
means](../README.md#what-a-verdict-means) is the verdict table and stays the
only one; this page says what the *model* is, and names the test that holds each
piece of it.

## The sink and the oracle are independent

Two different questions, and conflating them is the mistake most of this design
is shaped against:

- **The sink** is where exploitation happens — the shell, the evaluator, the
  parser, the deserializer, the program whose options your value became.
- **The oracle** is where evidence becomes observable — the response body, a
  header, a second request that fetches a file back, a callback on the
  listener, the shape of a response, a page the payload surfaces on later.

A sink with no oracle is not a clean target. That is why a run that could not
observe anything reports `error`, `blocked` or `nothing-tested` rather than
`negative`, and why `--methods` is a list rather than one best oracle: which
oracle can answer is a property of the target, not of the vulnerability.

The same separation runs the other way. A 5xx means the payload reached
something, so it is never read as "filtered". An application that executes the
payload and then answers 400 with the output in the body has still executed it.

## Where the trust core lives

Three regions of `rcekit.py`, each fenced with the file's own banner style.
They are three rather than one because the first is a set of decisions the
*engine* makes on every method's behalf, and it sits with the engine; bringing
the three together would mean moving code, which the one-file property is there
to avoid.

| Region | Symbols | What it decides |
|---|---|---|
| Delivery facts, in `RCEKit` | `_refusal`, `_refused_but_landed`, `_escalate` | What a filter's answer means, before any oracle sees it |
| The oracle contract | `Probe`, `Verdict`, `Observation`, `DetectionMethod` | What a method may declare, and what one probe carries |
| The verdict vocabulary | `payload_refused`, `response_shape`, `overall_detection_verdict`, `NON_EXECUTION_SECTIONS`, `VERDICT_PRIORITY`, `VERDICT_MEANING`, `DETECTION_METHODS` | What the names mean, and which one describes a whole run |

`_refusal` is on the engine and not on a method on purpose: being refused is a
fact about delivery rather than about what any one method was looking for, so
every method inherits the right answer instead of the current one.

The timeout question is split along the same seam, and the seam is worth
seeing. Whether a probe spent its whole timeout, and what a payload-free
control sent immediately after it answered, are delivery facts the engine
measures. What they *mean* is a verdict, so the oracle decides it — which is
why `reflected`, `eval` and `argv` declare that they read it and the methods
answering from a second request do not.

The oracles themselves are everything between the contract and the vocabulary:
one class per `--methods` value, each turning an `Observation` into a `Verdict`.
[Reference](reference.md#detection-methods) is the per-method page.

## The invariants

Each of these is a property the code is held to, with the test that holds it.
A test named here is the place that fails when the property stops being true —
not documentation of the property, but the guard on it.

| Invariant | Guarded by |
|---|---|
| `executed` means the target executed or computed the input. It rests on a value RCEKit chose at random for that probe, which reflection cannot produce | `DetectionMethodTestCase` (each method must confirm on a `/vuln` route and stay unconfirmed on a `/reflect` one), `ConfirmationContractTestCase` in `test_docs.py` |
| Every signal is differenced against a payload-free control. Evidence the control carries too is `inconclusive`, never a finding | `DetectionMethodTestCase`, `PayloadRefusedTestCase` |
| A refusal never overwrites a positive verdict. `negative` is the only verdict a 4xx contradicts | `RefusalNeverUnmakesEvidenceTestCase` |
| A refusal that did **not** prevent the effect is a property of the finding, not a verdict of its own | `RefusedButLandedTestCase` |
| `error`, `blocked` and `nothing-tested` are not `negative`. A run that tested nothing never reads as a clean target | `FilteredTargetRunTestCase`, `TargetProfileEmptyLadderCLITestCase`, `CallbackMethodRefusalTestCase`, `CLIExitCodeTestCase` |
| A timeout the payload-free control did not share is not an `error`: the request reached the target | `TimeoutAttributionTestCase` |
| Nothing is promoted upward. A weaker tier never becomes `executed`, however clean the measurement | `NonExecutionSectionTestCase`, `DeserShapeVerdictTestCase`, `SyntaxDifferentialTestCase` |
| Nothing is rounded down either. A settled measurement is not reported as a candidate, which is what `needs-review` is reserved for — and no method tops out there | `MethodSafetyRungTestCase.test_needs_review_is_left_to_the_signals_that_really_are_candidates` |
| The collapsed verdict's order is data, written once and read by both the summary line and the report's sections | `NonExecutionSectionTestCase.test_the_priority_is_the_one_written_out_here`, `NonExecutionSectionTestCase.test_each_adjacent_pair_collapses_to_the_stronger_finding` |
| Every verdict the engine can emit is one the vocabulary names | `TierVocabularyTestCase` |
| What a method is, reaches and needs is **declared on the class**, never derived from something that correlates with it today | `DetectionQuestionTestCase`, `WholeSeriesBudgetTestCase.test_which_methods_answer_per_probe_is_read_from_the_class`, `MethodSafetyRungTestCase` |

That last one is the least obvious and the most load-bearing. Four separate
attributes exist because something was once derived from a neighbour that
happened to agree: the question a method asks (`question`), the weaker tiers it
really reports (`also_reports`), where its evidence arrives
(`evidence_off_response`), and whether a timeout differential is any use to it
(`reads_timeout_differential`). Each has a comment recording which derivation
was tried and what it got wrong.

## What a response-shape oracle can and cannot answer

Three verdicts rest on the *shape* of a response rather than on a value:
`evaluation-sink`, `syntax-sink`, and `deser`'s shape fingerprint. They are the
weakest oracles here and their guards are measured rather than argued — the
counts are in each method's docstring, against fixtures built to make the
oracle lie: a target that only echoes its input, a page that drifts on its own,
and a filter that answers the two halves of a differential differently.

The last of those is the guard that matters most on a real engagement. A WAF
that refuses a malformed probe and lets a well-formed one through produces a
perfect differential while nothing on the target ever parsed anything, and
reading that as a parser would be a false positive on exactly the hardened
targets this tool is for.

None of the three can answer about a page whose *structure* changes on its own
between adjacent requests. Where that is measurable the run says
`inconclusive`; where it is not, the residual is recorded as a number in the
method's docstring rather than left as a reassurance.

## Adding an oracle without breaking the model

[CONTRIBUTING.md](../CONTRIBUTING.md) has the mechanics. The model asks three
things of a new one:

1. **Name the verdict for what the target did**, not for how sure the tool is.
   If the answer is "something happened and I cannot attribute it", that is
   `inconclusive`; if it is a real signal that is not proof, `needs-review`
   already exists and is reserved for exactly that; if it is a settled
   measurement, it earns a tier and a place in the priority order.
2. **Measure the guards before claiming the tier.** A differential's guards are
   worth what they were tested against, and the existing oracles quote run
   counts for that reason.
3. **Declare what the engine needs to know.** The registries that make a new
   method state itself twice are deliberate: the question partition, the
   priority tuple written out independently of `VERDICT_PRIORITY`, the
   documented vocabulary, and the per-method tables in the README and
   [reference](reference.md). A method that arrives without them fails the
   suite, which is the point.
