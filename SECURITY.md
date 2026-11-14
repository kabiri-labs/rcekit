# Security Policy

RCEKit is an offensive **RCE testing toolkit for authorised security
testing**. This policy covers vulnerabilities **in the tool itself** — please
read the scope section, because generating attack payloads is the tool's
intended function, not a vulnerability.

## Supported versions

Only the latest released version is supported. Fixes ship in a new version
(see `--version`); please upgrade before reporting.

| Version | Supported |
|---------|-----------|
| latest `3.x` | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security reports.** Instead, report
privately:

- Preferred: GitHub **Private Vulnerability Reporting** —
  *Security → Report a vulnerability* on this repository.
  (Maintainers: enable it under *Settings → Code security and analysis*.)
- Alternatively, contact the maintainer privately at
  `certification.kabiri@gmail.com`.

Please include:

- the version (`python rcekit.py --version`),
- a clear description and minimal steps to reproduce,
- the impact and any suggested fix.

You can expect an acknowledgement within **5 business days**. We aim to
validate and fix confirmed issues promptly and will credit reporters who wish
to be named. Please allow **coordinated disclosure** (a reasonable window to
fix before public details are shared).

## In scope

Genuine flaws in this project's own code, for example:

- the tool doing something the operator did not request (e.g. writing outside
  the intended output path, executing a payload on the operator's own host, or
  making network requests without an explicit flag);
- an unintended **bypass of the safety controls** (the `--acknowledge-consent`
  gate, safety tiers, the destructive-payload guard, or audit logging);
- crashes, path traversal, or injection triggered by untrusted **template**,
  **profile**, or manifest input;
- unsafe handling of files or subprocesses within the tool.

## Out of scope

- **The intended behaviour of the tool** — generating RCE/injection payloads,
  reverse shells, OOB callbacks, etc., is by design and is not a vulnerability.
- **Payloads succeeding against a target you point the tool at** — that is the
  purpose of authorised testing.
- **Misuse by third parties.** The maintainers are not responsible for use of
  this tool against systems without authorisation; such use is illegal and
  unethical.
- Findings that require running the tool against systems you are not
  authorised to test.

## A note on responsible use

This toolkit is provided for authorised penetration testing, security
research, education, and defensive training only. **Never use it against
systems without explicit permission.**

## Expected scanner findings

**RCEKit trips malware heuristics by design, and will keep doing so.** An RCE
detection tool has to contain the things those heuristics look for: reverse
shell one-liners, credential file paths, out-of-band callback builders, and
system-enumeration commands. A scanner that reads a file and asks "does this
look like an attack toolkit?" is reading RCEKit correctly. The label is
accurate about the content and says nothing about the behaviour.

Every current finding resolves to one of two places: the **embedded payload
corpus**, which is inert data the tool transmits and never runs, or the
**detection engine**, which recognises what a target sent back. Neither is
incidental; both are the product. There is no version of this tool that
detects command injection without containing command-injection strings.

This section exists so that a reader who arrives from a red badge can check
that claim instead of taking it.

### What GuardDog reports

[GuardDog](https://github.com/DataDog/guarddog) (Datadog) is the strictest of
the public scanners on this package. Reproduce it against the published
artifact:

```bash
pip install guarddog
guarddog pypi scan rcekit --output-format json
```

GuardDog's dependency tree publishes no Windows wheels, so on Windows use the
container image instead — `docker run --rm ghcr.io/datadog/guarddog pypi scan
rcekit --output-format json` — which produces the same result.

On **3.15.0** that returns a risk score of **10.0/10 `high_risk`** — the top of
the scale — from **44 findings** across **173 issues**. Of the 22 rules that
fire, 9 are `capability-*` rules (one finding each) that inventory what the
file could do; the 13 `threat-*` rules below account for the remaining 35:

| rule | severity | MITRE | findings | what it matched |
|---|---|---|---|---|
| `threat-filesystem-read` | high | credential-access | 5 | `/etc/passwd` — corpus entries, plus the `_COMMAND_SIGNATURES` response matcher |
| `threat-process-sysinfo` | medium | collection | 5 | `system('whoami')`, `exec('whoami')`, `popen('whoami')`, `call(['whoami'])` — corpus entries |
| `threat-filesystem-autostart` | high | persistence | 3 | `.bashrc` in the persistence corpus — **plus two false positives on ordinary file I/O** |
| `threat-network-reverse-shell` | high | command-and-control | 3 | `bash -i >& /dev/tcp/` — reverse-shell corpus entries |
| `threat-process-download-exec` | high | execution | 3 | `urllib.request.urlopen(` — download-cradle corpus entries |
| `threat-runtime-dynamic-loader` | high | defense-evasion | 3 | `__import__(` — SSTI and `exec_ast` corpus entries |
| `threat-network-exfil-sysinfo` | high | exfiltration | 3 | `os.system('whoami')`, `urllib.request.urlopen(` — OOB callback corpus entries |
| `threat-runtime-enumeration` | medium | discovery | 3 | `/proc/` — container-detection corpus entries and `_COMMAND_SIGNATURES` |
| `threat-network-exfiltration` | high | exfiltration | 2 | `http://100.100.100.200` — cloud-metadata IP corpus entries |
| `threat-process-powershell-encoded` | high | execution | 2 | `IEX(New-Object Net.WebClient` — Windows download-cradle corpus entries |
| `threat-network-dns-exfil` | high | exfiltration | 1 | `nslookup $` — the DNS probe builder in the detection engine |
| `threat-runtime-obfuscation-base64exec` | high | defense-evasion | 1 | `@exec(` — the `exec_ast` corpus entry |
| `threat-runtime-obfuscation-steganography` | high | defense-evasion | 1 | `@exec(` — the same `exec_ast` corpus entry |

**30 of those 35 findings are inside a single string literal.** The corpus is
assigned to `EMBEDDED_PAYLOAD_CORPUS` as one raw string; a scanner reading the
file as text cannot tell that from code, which is the whole mechanism behind
the score. The other 5 are in engine code: the `_COMMAND_SIGNATURES` table
(two), the OOB DNS probe builder (one), and the two false positives below.

Line numbers drift with every release, so this section does not pin them except
where a specific claim needs one. Re-run the command above to see the current
set.

### The false positives, by name

Two of the three `threat-filesystem-autostart` hits are the clearest evidence
that the score is heuristic noise rather than observed behaviour. At **3.15.0**
they land on `rcekit.py:1156` and `rcekit.py:2124`:

- `rcekit.py:1156` is a `json.loads()` over an opened template file — the
  corpus read.
- `rcekit.py:2124` is a `.open("w")` that writes the JSONL payload map.

Both matched on the literal token **`open(`**, and both are reported as
`persistence` at high severity. Reading a JSON file and writing a log of what
was generated is ordinary file I/O; nothing at either line touches `.bashrc`,
`crontab`, systemd, or any other autostart location. The rule's third hit is a
genuine match on a persistence payload in the corpus, which is what the rule
is for.

### What you can verify yourself

Each of these is a property of the published artifact, checkable without
trusting this document.

**No install-time hooks.** There is no `setup.py` and no `setup.cfg`, so there
is no arbitrary code path at install time; `pyproject.toml` declares
`build-backend = "setuptools.build_meta"` with no `cmdclass`, and
`dependencies = []`. The wheel ships one module, `rcekit.py`, and pulls in
nothing.

```bash
ls setup.py setup.cfg        # both absent
grep -n "build-backend\|^dependencies" pyproject.toml
```

**Nothing executes at import.** Module level is imports, `re.compile`,
`logging.getLogger`, `frozenset`, and definitions. On 3.15.0 that is 18 import
statements, 66 assignments — whose only calls are `re.compile` (14),
`frozenset` (6) and `logging.getLogger` (1) — 84 functions, 27 classes, and
exactly one top-level `if`, which is the `__main__` guard on the last line.
Nothing opens a socket, reads a file, or spawns a process on import:

```bash
python -c "import ast,collections; t=ast.parse(open('rcekit.py',encoding='utf-8').read()); print(dict(collections.Counter(type(n).__name__ for n in t.body))); print(dict(collections.Counter(ast.unparse(n.value.func) for n in t.body if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call)))); print([ast.unparse(n.test) for n in t.body if isinstance(n,ast.If)])"
```

**The tool never executes a payload locally.** `rcekit.py` does not import
`subprocess`, `pty`, `pickle` or `marshal` anywhere, and contains no call to
`os.system`, `os.popen`, `eval`, `exec` or `compile`. Every occurrence of those
names in the file is a character sequence inside a payload string — which is
exactly why the scanners match on them. The one platform-API import is a lazy
`ctypes` inside `enable_ansi()`, used to turn on ANSI escape handling on a
Windows console and nothing else.

```bash
python -c "import ast; t=ast.parse(open('rcekit.py',encoding='utf-8').read()); D={'os.system','os.popen','eval','exec','compile','subprocess.run','subprocess.call','subprocess.Popen','pickle.loads'}; print('calls:',[(n.lineno,ast.unparse(n.func)) for n in ast.walk(t) if isinstance(n,ast.Call) and ast.unparse(n.func) in D] or 'NONE'); print('imports:',[(n.lineno,a.name) for n in ast.walk(t) if isinstance(n,ast.Import) for a in n.names if a.name in ('subprocess','pty','pickle','marshal')] or 'NONE')"
```

**TLS verification is on by default.** PkgRadar's "Tls Verification Disabled"
signal is real but conditional: `_verify_ssl_context()` returns `None` —
urllib's own certificate-verifying default — and only builds a context with
`check_hostname = False` and `CERT_NONE` when `--insecure` was passed. That is
the single place in the file where verification is lowered, `ssl` is not
imported unless the flag is set, and a run that uses it prints a warning saying
so. [`docs/verify-it-yourself.md`](docs/verify-it-yourself.md) shows why the
flag exists: a self-signed Webmin 1.910 target is unreachable without it, and
RCEKit reports those probes as `error` rather than `negative` — a connectivity
failure is never allowed to read as "not vulnerable".

**The corpus is inert data.** RCEKit sends payloads to the target you name and
inspects the response; it does not run them on the operator's host. The tier
rule is the observable consequence, and
[`docs/verify-it-yourself.md`](docs/verify-it-yourself.md) is a five-minute
reproduction against vulhub containers you control: `confirmed` rests on a
value the *target* computed from operands RCEKit chose at random for that run,
and weaker signals are never promoted into it.

### A high-risk label is the norm for this category

RCEKit is not an outlier among tools that do this job. Scanned the same way:

| package | GuardDog score | findings |
|---|---|---|
| `rcekit` 3.15.0 | 10.0 `high_risk` | 44 |
| `dirsearch` 0.5.0 | 8.8 `high_risk` | 11 |
| `xsrfprobe` 3.0.0 | 6.3 `suspicious` | 4 |

(`commix` is absent from that list because the `commix` package on PyPI is a
3.7 KB stub published as version 0.1; the real tool is not distributed through
PyPI.)

As of November 2026, [PkgRadar](https://pkgradar.com/package/pypi/rcekit) rates
the package **High risk, score 40**, on three signals — "Py Runtime Reverse
Shell" (high), "Tls Verification Disabled" (medium) and "Credential file
access". All three are accounted for above: the reverse-shell and
credential-path signals are corpus entries and `_COMMAND_SIGNATURES` matchers,
and the TLS signal is the `--insecure` opt-in.

[Snyk](https://security.snyk.io/package/pip/rcekit) applies vulnerability data
rather than malware heuristics, and reports **no known security issues — 0
vulnerabilities across all 8 published versions**, with no direct
vulnerabilities in its database for any of them.

The two verdicts are not in conflict. GuardDog and PkgRadar answer "does this
file contain attack tooling?" — yes, deliberately. Snyk answers "are there
known flaws in this code?" — none recorded. A reader deciding whether to run
RCEKit wants the second question answered, plus the checks above for the first.
