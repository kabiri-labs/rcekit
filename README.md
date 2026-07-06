# RCEPayloadGen - Advanced RCE Payload Generator

RCEPayloadGen is a comprehensive Remote Code Execution payload generator designed for penetration testers, security researchers, and red teamers. This tool generates a wide variety of RCE payloads tailored to different environments, contexts, encoding methods, and specific execution sinks.

## Features

- **Multi-Environment Support**: Generate payloads for Unix, Windows, Node.js, Python, PHP, Java, .NET, Ruby, Perl, Go, GraphQL, MongoDB/NoSQL, containerized Docker workloads, and Kubernetes clusters
- **Context-Aware**: Break-out contexts (HTML, JS, SQL, shell-quoted strings) plus transport contexts (JSON, XML, YAML, HTTP header, GraphQL) that escape the payload to survive the wire format and reach the sink intact
- **Sink-Specific Payloads**: Detailed granularity for code execution sinks, including OS commands, template engines (SSTI), and language-specific execution methods, emitted verbatim so each snippet stays syntactically valid for its sink
- **Executable-Only Encoding**: The default encodings run as-is on the channel/sink or carry their own decoder (`base64_decode_exec`). Bare decoder-required blobs (Base64/Hex) are opt-in and warn on text output, and non-runnable transforms (ROT13, XOR/chunk shuffling, byte splicing) are removed — so operators never copy a payload that silently does nothing
- **Modular Templates**: Payload bases are stored in editable JSON/YAML templates so teams can extend coverage without touching Python source code
- **Customizable**: Fine-tune payload generation with various command-line options
- **Built-in Verification Harness**: `--verify-url` fires the payloads at an authorised target and reports which actually executed, using each payload's oracle — closing the generate → deliver → confirm loop from one command
- **Machine-Readable Success Signatures**: Every payload carries a `match` field — the reflected canary/OOB token, or an inferred command-output regex (`id` → `uid=\d+`, `/etc/passwd` → `root:...`) — so a verifier, Nuclei, or Burp macro can auto-confirm execution instead of eyeballing output
- **Out-of-Band (OOB) Support**: Blind-RCE payloads that call back to your collaborator/interactsh domain, each stamped with a unique correlation token and recorded in a `token → payload` manifest so a received callback maps to exactly one payload
- **Tooling Integrations**: Export directly as **Burp/ffuf** wordlists (grouped by injection context, plus a request template) or as runnable **Nuclei** templates with built-in OOB / time-based / reflection oracles
- **Target Profiles**: Describe the target once (environments, contexts, denied characters, max length) and emit only compatible payloads instead of spraying everything
- **WAF-Bypass Payloads**: Quote-free, space-free command-injection variants (`${IFS}`, brace expansion, `cat</etc/passwd`) for targets that reject quotes
- **Detection-Friendly Mode**: Quickly produce benign canary payloads for safe scanning with `--detection-only`
- **No Duplicates**: Intelligent duplicate detection to avoid redundant payloads
- **Production-Ready**: Robust error handling, logging, and performance optimization

## Installation

```bash
# Clone the repository
git clone https://github.com/kabiri-labs/rcpayloadgen.git
cd rcpayloadgen

# Install dependencies (none required beyond standard Python libraries)
# Python 3.6+ required
```

> **Note:** Generated payload files (`rce_payloads.txt`, `*.meta.jsonl`) and runtime
> logs are not committed — they are listed in `.gitignore` and regenerated on demand.

## Testing

The project ships a dependency-free `unittest` suite that locks in payload
uniqueness, the executable-only encoding policy, safety filtering, and detection
mode:

```bash
python -m unittest discover -s tests
```

## Usage

```bash
python rce_payload_gen.py [OPTIONS]
```

### Basic Examples

Generate all payloads with default settings (requires exploitation consent acknowledgement):
```bash
python rce_payload_gen.py --acknowledge-consent
```

Generate only Unix reverse shells with base64 encoding:
```bash
python rce_payload_gen.py --categories reverse_shells --environments unix --encodings base64
```

Generate up to 1000 payloads for PHP contexts:
```bash
python rce_payload_gen.py --contexts php --max-payloads 1000 --acknowledge-consent
```

Generate benign payloads plus a metadata sidecar with indicators:
```bash
python rce_payload_gen.py --detection-only --include-metadata --output detection.txt
```

Blind-RCE payloads with per-payload OOB tokens (writes a `token → payload` map sidecar):
```bash
python rce_payload_gen.py --acknowledge-consent --categories oob \
  --oob-domain your-id.oast.pro --output oob.txt
```

Export Burp/ffuf wordlists (grouped by context) or a runnable Nuclei pack:
```bash
python rce_payload_gen.py --acknowledge-consent --output-format burp --output run.txt
python rce_payload_gen.py --detection-only --output-format nuclei --output run.txt
```

Use custom attacker IP and domain:
```bash
python rce_payload_gen.py --attacker-ip 10.0.0.1 --attacker-domain evil.com --acknowledge-consent
```

Run in safe detection mode with benign payloads:
```bash
python rce_payload_gen.py --detection-only
```

### Full Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output file path | `rce_payloads.txt` |
| `--attacker-ip` | Attacker IP for reverse shells | `192.168.1.100` |
| `--attacker-domain` | Attacker domain for download payloads | `attacker.com` |
| `--max-payloads` | Maximum number of payloads to generate | Unlimited |
| `--contexts` | Contexts to generate (space-separated) | Default language/structural contexts |
| `--categories` | Categories to generate (space-separated) | All categories |
| `--encodings` | Encoding methods to apply (space-separated) | All encodings |
| `--environments` | Environments to generate (space-separated) | All environments |
| `--template-file` | Path to a JSON/YAML template bundle | `templates/payloads.json` |
| `--detection-only` | Generate benign payloads for validation scans | Disabled |
| `--output-format` | `text`, `jsonl`, `burp` (per-context wordlists + request template), or `nuclei` (runnable templates) | `text` |
| `--oob-domain` | Collaborator/interactsh domain for out-of-band payloads; each gets a unique subdomain token | None |
| `--verify-url` | Authorised target URL with a `FUZZ` marker; fire payloads and confirm execution via their oracle | None |
| `--verify-data` / `--verify-header` / `--verify-method` | Request body (with `FUZZ`) / repeatable header / HTTP method for verification | — |
| `--verify-delay` / `--verify-timeout` | Seconds between requests / per-request timeout for verification | `0` / `8` |
| `--include-metadata` | Emit indicators, safety tiers, and notes | Disabled |
| `--max-safety` | Highest safety tier to include (`safe`, `intrusive`, `stateful`) | `safe` in detection, `intrusive` otherwise |
| `--include-blocking` | Include blocking or timing-based probes | Disabled |
| `--acknowledge-consent` | Required confirmation before creating exploitation payloads | Disabled |
| `--watermark` | Embed a traceable watermark token into each exploitation payload (audit logging happens regardless) | Disabled |
| `--target-profile` | JSON profile describing the target; supplies defaults that CLI flags override | None |
| `--deny-chars` | Drop payloads containing any of these characters (e.g. quotes) | None |
| `--max-length` | Drop payloads longer than this many characters | None |

### Available Contexts

A context is more than a prefix/suffix: each one also carries an **escape rule**
that makes the payload valid *inside* its surrounding container (e.g. a payload
placed in a JSON string has its quotes and backslashes escaped so it survives the
wire format and reaches the sink intact). Contexts fall into two families.

**Language & structural break-outs** (the default set when `--contexts` is omitted):

- `raw` - No wrapper; language-native snippets and direct command probes
- `html` - HTML text context
- `attribute` - Quoted HTML attribute break-out
- `attribute_unquoted` - Unquoted HTML attribute break-out
- `javascript` - JavaScript string break-out
- `sql` - SQL string break-out
- `php` - PHP code context
- `unix_shell` / `windows_cmd` / `powershell` - shell contexts
- `shell_single_quoted` / `shell_double_quoted` - break out of a single/double-quoted shell argument (opt-in)
- `graphql_string` - inject into an inline GraphQL string literal (opt-in)

**Transport / serialization contexts** (opt-in via `--contexts`; carry *any*
environment's payload and escape it for the wire format):

- `json` - JSON string value (quotes/backslashes/controls escaped)
- `graphql_variable` - GraphQL variables JSON
- `xml` - XML text/attribute (entity-escaped)
- `xml_cdata` - XML CDATA section
- `yaml` - YAML double-quoted scalar
- `http_header` - HTTP header value (CR/LF neutralised)

Example — deliver a command-injection payload inside a JSON API field:
```bash
python rce_payload_gen.py --acknowledge-consent --contexts json --environments unix
```

### Available Categories

- `basic_enum` - Basic enumeration commands
- `file_operations` - File system operations
- `network_operations` - Network reconnaissance
- `code_execution` - Language-specific code execution (with sink-level granularity)
- `download_execute` - Download and execute payloads
- `reverse_shells` - Reverse shell payloads
- `credential_access` - Credential discovery and secret harvesting primitives
- `privilege_escalation` - Local privilege escalation checks across OS and container targets
- `persistence` - Payloads that create or simulate common persistence mechanisms
- `cloud_metadata` - Cloud service metadata harvesting from on-prem or containerised footholds
- `database_enumeration` - Database discovery and schema inspection helpers
- `lateral_movement` - Post-exploitation lateral movement primitives
- `waf_bypass` - Quote-free / space-free command-injection variants for filtered inputs
- `oob` - Out-of-band callback payloads (requires `--oob-domain`), including DNS/HTTP exfil and JNDI/Log4Shell
- `nosql_injection` - MongoDB/NoSQL operator injection, `$where` server-side JS, and blind time-based probes
- `graphql_injection` - GraphQL introspection, resolver-argument injection (OS/SQL/NoSQL/traversal), and batching

### Available Environments

- `unix` - Unix-like systems
- `windows` - Windows systems
- `nodejs` - Node.js environment
- `python` - Python environment
- `php` - PHP environment
- `java` - Java/JVM environment
- `dotnet` - .NET environment
- `ruby` - Ruby environment
- `perl` - Perl environment
- `go` - Go environment
- `docker` - Container escape research against Docker runtimes
- `kubernetes` - Payloads targeting Kubernetes workloads and control planes
- `graphql` - GraphQL injection surface (introspection, argument-borne injection, batching)
- `mongodb` - MongoDB / NoSQL injection surface (operator injection, `$where`/`$function` server-side JS)

### Available Encoding Methods

Encodings fall into two groups. **Default encodings** run as-is on the receiving
channel/sink (or carry their own decoder), so plain-text output is always
directly usable:

- `none` - No encoding
- `url_encode` - URL encoding (for channels that URL-decode before the sink)
- `double_url_encode` - Double URL encoding
- `random_case` - Random case variation, emitted **only** for case-insensitive runners (Windows `cmd`, PowerShell, SQL); suppressed elsewhere because it would corrupt the command
- `base64_decode_exec` - **Self-contained** base64 that carries its own decoder pipeline (`echo <b64>|base64 -d|sh`); runs as-is on a POSIX shell (shell runners only)

**Decoder-required encodings** are opt-in via `--encodings`. They emit bare blobs
that only execute where the *sink itself* base64/hex-decodes the input (e.g.
`eval(base64_decode(...))`). Because a plain-text blob can look like a working
payload but do nothing on its own, they are excluded from the default set and,
when requested for text output without `--include-metadata`, the tool prints a
warning:

- `base64` - Bare base64 blob
- `hex` - Bare hexadecimal blob
- `base64_then_url` - Base64 then URL encoding
- `double_base64` - Nested base64 layers

> **Removed in an earlier version:** `rot13`, `rot13_then_base64`, `insert_special_chars`,
> `xor_polymorphic`, and `chunk_shuffle`. These produced non-executable output
> (e.g. `rot13("id") -> "vq"`, or literal `XOR(..):` / `shuffle::` debug strings)
> and only inflated the result set with payloads that fail on the target.

> **Removed in this version:** `rot13`, `rot13_then_base64`, `insert_special_chars`,
> `xor_polymorphic`, and `chunk_shuffle`. These produced non-executable output
> (e.g. `rot13("id") -> "vq"`, or literal `XOR(..):` / `shuffle::` debug strings)
> and only inflated the result set with payloads that fail on the target.

## Payload Types

RCEPayloadGen generates payloads across multiple categories:

1. **Basic Enumeration**: Common system reconnaissance commands
2. **File Operations**: File system interaction and sensitive file access
3. **Network Operations**: Network configuration and discovery
4. **Code Execution**: Language-specific code execution patterns with sink-level details
5. **Download & Execute**: Payloads that download and execute remote code
6. **Reverse Shells**: Comprehensive reverse shell payloads for various environments
7. **Credential Access**: Systematic harvesting of credentials, tokens, and configuration secrets
8. **Privilege Escalation**: Coverage for sudo, service, and platform-specific privilege escalation reconnaissance
9. **Persistence**: Command patterns that emulate real-world persistence tradecraft on Unix and Windows hosts
10. **Cloud Metadata Discovery**: Probing public cloud instance metadata services from multiple vantage points
11. **Database Enumeration**: Enumerate SQL/NoSQL backends and dump useful schema information
12. **Lateral Movement**: Validate remote management channels (SSH, WinRM, PsExec, etc.) for expansion
13. **Container Escape Research**: Docker and Kubernetes oriented payloads to validate hardening of container platforms

## Detailed Code Execution Sinks

For the `code_execution` category, payloads are generated at a sink-specific level and emitted verbatim, so each snippet stays syntactically valid for its target sink (encoding variants are applied separately and labelled in metadata). Below is a list of supported sinks per environment:

### Node.js (`nodejs`)
- `child_process_exec`: Executions using child_process module
- `pug_ssti`: Pug template engine SSTI
- `ejs_ssti`: EJS template engine SSTI
- `handlebars_ssti`: Handlebars template engine SSTI

### Python (`python`)
- `os_system`: os.system executions
- `subprocess`: subprocess module executions
- `jinja2_ssti`: Jinja2 template engine SSTI

### PHP (`php`)
- `exec_system`: system/exec/shell_exec/passthru/eval/preg_replace executions

### Java (`java`)
- `runtime_exec`: Runtime.exec and ProcessBuilder
- `freemarker_ssti`: Freemarker template engine SSTI
- `velocity_ssti`: Velocity template engine SSTI
- `thymeleaf_ssti`: Thymeleaf template engine SSTI
- `spel`: Spring Expression Language (SpEL) injection
- `ognl`: OGNL injection (e.g. Struts)
- `groovy`: Groovy expression / dynamic class-loading execution

### .NET (`dotnet`)
- `process_start`: Process.Start executions

### Ruby (`ruby`)
- `kernel_system`: system/backticks/exec executions
- `erb_ssti`: ERB template engine SSTI

### Perl (`perl`)
- `system_backticks`: system/backticks/exec executions

### Go (`go`)
- `os_exec`: exec.Command executions

### MongoDB (`mongodb`, category `nosql_injection`)
- `operator_injection`: query-operator / auth-bypass injection (`$ne`, `$gt`, `$regex`, `$or`)
- `where_js`: `$where` server-side JavaScript (including blind `sleep()` timing)
- `server_side_js`: `$function` / `$accumulator` server-side JS execution (MongoDB 4.4+)

### GraphQL (`graphql`, category `graphql_injection`)
- `introspection`: schema discovery queries
- `injection`: resolver-argument injection reaching OS command / SQL / NoSQL / path-traversal sinks
- `batching`: aliasing brute-force and nested-query amplification

## Target Profiles

Instead of spraying every payload, describe the target once and let the generator
emit only what could actually reach the sink. A profile is a small JSON file:

```json
{
  "name": "quote-filtered-unix",
  "environments": ["unix"],
  "contexts": ["raw"],
  "categories": ["basic_enum", "file_operations", "waf_bypass", "oob"],
  "encodings": ["none", "url_encode"],
  "deny_chars": ["'", "\""],
  "max_length": 256,
  "oob_domain": "your-id.oast.pro"
}
```

```bash
python rce_payload_gen.py --acknowledge-consent --target-profile profiles/quote-filtered-unix.json
```

Profile fields supply defaults; any explicit CLI flag overrides the matching
field. `deny_chars` and `max_length` (also available directly as `--deny-chars`
/ `--max-length`) filter the **final** payload — so a URL-encoded quote survives
a quote filter, because the literal character is gone. An example profile ships
in [`profiles/`](profiles/).

## Verifying Against a Target

`--verify-url` closes the loop: it fires the generated payloads at an
**authorised** target and reports which ones actually executed, using each
payload's built-in oracle (the `match` regex, a reflected canary token, or a
timing delay). Put a `FUZZ` marker where the payload should go.

```bash
python rce_payload_gen.py --acknowledge-consent \
  --environments unix --categories basic_enum file_operations waf_bypass \
  --verify-url "https://target.example/lookup?host=FUZZ"
```

```
[verify] GET https://target.example/lookup?host=FUZZ  (authorised target)
[verify] sent 270 unique payloads: confirmed=44, no-match=86, no-signature=140

[verify] CONFIRMED execution (44):
  [file_operations/raw] ; cat /etc/passwd            (matched /root:.*?:0:0:/)
  [waf_bypass/raw]      ; cat${IFS}/etc/passwd        (matched /root:.*?:0:0:/)
  ...
```

- The `FUZZ` marker also works in `--verify-data` (request body) and repeatable
  `--verify-header` values; method defaults to GET (POST when `--verify-data` is set).
- Rate-limit with `--verify-delay <seconds>` and cap with `--max-payloads`.
- OOB payloads are sent but confirmed out-of-band — watch your listener for their tokens.
- Requires `--acknowledge-consent`; every run is written to `exploit_audit.log`.
  **Only run this against systems you are authorised to test.**

## Output Formats & Integrations

- **`text` / `jsonl`** — a single file of payloads (or JSONL records). A `<output>.map.jsonl` manifest is written for every payload that has an oracle — a correlation `token` (OOB / detection canary) **or** a machine-readable `match` regex — mapping it to its exact payload, context, and expected channel, so a received callback, reflected canary, or command-output signature is traceable to one payload and can be auto-confirmed by a verifier.
- **`burp`** — writes a `<output>_burp/` directory with deduplicated, watermark-free wordlists split per injection context (`payloads-raw.txt`, `payloads-sql.txt`, …), a combined `payloads-all.txt`, and a `request.txt` template with a marked injection point. Load the lists into Burp Intruder, or `ffuf -request request.txt -w payloads-all.txt:FUZZ`.
- **`nuclei`** — writes a `<output>_nuclei/` directory of runnable Nuclei templates grouped by environment and **oracle**:
  - *OOB* templates inject callbacks and match on `interactsh_protocol` (the real host is rewritten to `{{interactsh-url}}`).
  - *Time-based* templates normalise every delay to 6s and match on `duration>=6`.
  - *Reflection* templates inject a fixed canary and match it in the response body.
  - For the fullest pack, run `--detection-only --output-format nuclei` (reflection + time + OOB).

## Logging & Ethical Controls

- Detailed execution logs are stored in `rce_generator.log` with timestamps and severity levels for monitoring.
- Exploitation runs always write an audit entry to `exploit_audit.log` with a unique token, regardless of whether the watermark is embedded.
- Detection mode produces safe canary payloads suitable for authorized scanning and validation activities.
- When `--include-metadata` is enabled, plain-text output keeps raw payloads in the main file and writes a `.meta.jsonl` sidecar with the expected indicator, runner, safety tier, and lint notes for each payload.
- The in-payload watermark is **opt-in** via `--watermark`, so the default exploitation output stays clean and copy-pasteable. When enabled, payloads carry an embedded comment/command referencing the audit token to discourage misuse.

## Ethical Use

This tool is intended for:

- Penetration testing with proper authorization
- Security research and education
- Defensive security training
- Security tool development

**Never use this tool against systems without explicit permission.** Unauthorized testing is illegal and unethical.

## Contributing

Contributions are welcome! Please feel free to submit pull requests with:

- New payload categories or sinks
- Additional encoding methods or constraint handlers
- Bug fixes
- Performance improvements
- Documentation enhancements

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this program.
