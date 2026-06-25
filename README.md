# RCEPayloadGen - Advanced RCE Payload Generator

RCEPayloadGen is a comprehensive Remote Code Execution payload generator designed for penetration testers, security researchers, and red teamers. This tool generates a wide variety of RCE payloads tailored to different environments, contexts, encoding methods, and specific execution sinks.

## Features

- **Multi-Environment Support**: Generate payloads for Unix, Windows, Node.js, Python, PHP, Java, .NET, Ruby, Perl, Go, containerized Docker workloads, and Kubernetes clusters
- **Context-Aware**: Creates payloads for different injection contexts (HTML, JavaScript, SQL, etc.)
- **Sink-Specific Payloads**: Detailed granularity for code execution sinks, including OS commands, template engines (SSTI), and language-specific execution methods, emitted verbatim so each snippet stays syntactically valid for its sink
- **Executable-Only Encoding**: Base64, Hex, single/double URL encoding, and multi-stage Base64 chains — every variant either runs as-is or is a documented decode-and-execute blob. Transforms that produce non-runnable output (ROT13, XOR/chunk shuffling, byte splicing) have been removed so operators never copy a payload that silently does nothing
- **Modular Templates**: Payload bases are stored in editable JSON/YAML templates so teams can extend coverage without touching Python source code
- **Customizable**: Fine-tune payload generation with various command-line options
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
| `--contexts` | Contexts to generate (space-separated) | All contexts |
| `--categories` | Categories to generate (space-separated) | All categories |
| `--encodings` | Encoding methods to apply (space-separated) | All encodings |
| `--environments` | Environments to generate (space-separated) | All environments |
| `--template-file` | Path to a JSON/YAML template bundle | `templates/payloads.json` |
| `--detection-only` | Generate benign payloads for validation scans | Disabled |
| `--output-format` | Output payloads as `text` or `jsonl` records | `text` |
| `--include-metadata` | Emit indicators, safety tiers, and notes | Disabled |
| `--max-safety` | Highest safety tier to include (`safe`, `intrusive`, `stateful`) | `safe` in detection, `intrusive` otherwise |
| `--include-blocking` | Include blocking or timing-based probes | Disabled |
| `--acknowledge-consent` | Required confirmation before creating exploitation payloads | Disabled |
| `--watermark` | Embed a traceable watermark token into each exploitation payload (audit logging happens regardless) | Disabled |

### Available Contexts

- `raw` - No wrapper; best for language-native snippets and direct command probes
- `html` - HTML context
- `attribute` - HTML attribute context
- `javascript` - JavaScript context
- `sql` - SQL injection context
- `php` - PHP code context
- `unix_shell` - Unix shell context
- `windows_cmd` - Windows command context
- `powershell` - PowerShell context

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

### Available Encoding Methods

Every encoding is constrained to output an operator can actually run against the
target. Encodings that need a decoder on the receiving side (Base64/Hex chains)
are flagged in metadata with a "requires a decode-and-execute path" note.

- `none` - No encoding
- `url_encode` - URL encoding (for channels that URL-decode before the sink)
- `double_url_encode` - Double URL encoding
- `base64` - Base64 encoding (pair with a `base64 -d | sh`-style decode wrapper)
- `hex` - Hexadecimal encoding (pair with a hex decode wrapper)
- `random_case` - Random case variation, emitted **only** for case-insensitive runners (Windows `cmd`, PowerShell, SQL); suppressed elsewhere because it would corrupt the command
- `base64_then_url` - Multi-stage base64 followed by URL encoding
- `double_base64` - Nested base64 encoding layers

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

### .NET (`dotnet`)
- `process_start`: Process.Start executions

### Ruby (`ruby`)
- `kernel_system`: system/backticks/exec executions
- `erb_ssti`: ERB template engine SSTI

### Perl (`perl`)
- `system_backticks`: system/backticks/exec executions

### Go (`go`)
- `os_exec`: exec.Command executions

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
