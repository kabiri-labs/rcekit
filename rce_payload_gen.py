#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import random
import string
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("rce_generator.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

SAFETY_ORDER = {"safe": 0, "intrusive": 1, "stateful": 2}


@dataclass(frozen=True)
class PayloadRecord:
    payload: str
    mode: str
    category: str
    environment: str
    context: str
    encoding: str
    sink: Optional[str]
    indicator: str
    safety: str
    expected_channel: str
    runner: Optional[str]
    tags: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
    blocking: bool = False
    stateful: bool = False
    token: Optional[str] = None
    oob_host: Optional[str] = None

class RCEPayloadGenerator:
    def __init__(
        self,
        attacker_ip: str = "192.168.1.100",
        attacker_domain: str = "attacker.com",
        template_path: Optional[Path] = None,
    ):
        self.attacker_ip = attacker_ip
        self.attacker_domain = attacker_domain
        self.template_path = template_path or Path(__file__).parent / "templates" / "payloads.json"
        self.setup_components()

    def setup_components(self):
        """Initialize all payload components"""
        # Injection contexts. Each context has a break-out `prefix`/`suffix` and,
        # crucially, an `escape` rule describing how the payload must be encoded to
        # remain valid *inside* the surrounding container. Two families:
        #   * language / structural break-outs (close a quote, tag, or statement)
        #   * transport / serialization contexts that carry any environment's
        #     payload and only need to survive the wire format (JSON/XML/YAML/...)
        self.contexts = {
            # Language & structural break-outs
            "raw": {"prefix": "", "suffix": "", "escape": "none"},
            "html": {"prefix": "", "suffix": "", "escape": "none"},
            "attribute": {"prefix": "\"", "suffix": "\"", "escape": "none"},
            "attribute_unquoted": {"prefix": " ", "suffix": " ", "escape": "none"},
            "javascript": {"prefix": "';", "suffix": ";//", "escape": "none"},
            "sql": {"prefix": "';", "suffix": "-- ", "escape": "none"},
            "php": {"prefix": "<?php ", "suffix": "?>", "escape": "none"},
            "unix_shell": {"prefix": "", "suffix": "", "escape": "none"},
            "windows_cmd": {"prefix": "", "suffix": "", "escape": "none"},
            "powershell": {"prefix": "", "suffix": "", "escape": "none"},
            "shell_single_quoted": {"prefix": "'; ", "suffix": " #", "escape": "none"},
            "shell_double_quoted": {"prefix": "\"; ", "suffix": " #", "escape": "none"},
            "graphql_string": {"prefix": "", "suffix": "", "escape": "graphql"},
            # Transport / serialization contexts (carry any environment's payload)
            "json": {"prefix": "", "suffix": "", "escape": "json"},
            "graphql_variable": {"prefix": "", "suffix": "", "escape": "json"},
            "xml": {"prefix": "", "suffix": "", "escape": "xml"},
            "xml_cdata": {"prefix": "<![CDATA[", "suffix": "]]>", "escape": "none"},
            "yaml": {"prefix": "\"", "suffix": "\"", "escape": "json"},
            "http_header": {"prefix": "", "suffix": "", "escape": "header"},
        }
        # Contexts that deliver any payload through a serialization layer; they are
        # compatible with every environment, not just shell runners.
        self.transport_contexts = {"json", "graphql_variable", "graphql_string", "xml", "xml_cdata", "yaml", "http_header"}
        # Original language/structural contexts used when no --contexts is given,
        # so default output size and behaviour stay stable; the richer contexts
        # above are opt-in via --contexts.
        self.default_contexts = ["raw", "html", "attribute", "javascript", "sql", "php", "unix_shell", "windows_cmd", "powershell"]
        self.separator_envs = {"unix", "windows", "docker", "kubernetes"}
        self.safe_detection_encodings = ["none", "url_encode", "double_url_encode"]
        # Runners whose target parser is case-insensitive, so random_case is a
        # meaningful keyword/WAF-bypass transform rather than a payload-breaking one.
        self.case_insensitive_runners = {"cmd", "powershell", "sql"}

        # Command separators and chainers for different environments
        self.separators = {
            "unix": ["; ", "| ", "|| ", "& ", "&& ", "%0a", "%0A", "${IFS}", "\\n"],
            "windows": ["&", "|", "%26", "%7C", "`|", "`&"],
            "docker": ["; ", "&& ", "| "],
            "kubernetes": ["; ", "&& "],
        }

        self.payload_categories: Dict[str, Any] = {}
        self.detection_payloads: Dict[str, List[str]] = {}
        self._load_template_payloads()

        # Encoding and obfuscation techniques.
        #
        # Every transform here must yield something an operator can actually run
        # against the target. Two classes are intentionally excluded:
        #   * Transport encodings that the channel decodes before the sink
        #     (url/double-url) and decoder-paired blobs (base64/hex variants,
        #     which carry an explicit "needs a decode-and-execute path" note).
        #   * random_case, which only survives on case-insensitive parsers and
        #     is gated per-runner in _encoding_is_compatible.
        #
        # Removed (previously emitted non-executable noise): rot13,
        # rot13_then_base64, insert_special_chars, xor_polymorphic, chunk_shuffle.
        # e.g. rot13("id") -> "vq" (runs nothing), xor/shuffle emitted literal
        # "XOR(..):"/"shuffle::" debug strings, and insert_special_chars spliced
        # raw %0a bytes into live shell commands.
        self.encoding_methods = {
            "none": lambda x: x,
            "url_encode": lambda x: urllib.parse.quote(x),
            "double_url_encode": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: x.encode().hex(),
            "random_case": lambda x: ''.join(random.choice([c.upper(), c.lower()]) for c in x),
            "base64_then_url": lambda x: urllib.parse.quote(base64.b64encode(x.encode()).decode()),
            "double_base64": lambda x: base64.b64encode(base64.b64encode(x.encode())).decode(),
        }

    def _load_template_payloads(self) -> None:
        """Load payload templates from JSON/YAML files."""
        if not self.template_path.exists():
            logger.warning("Template file %s not found. Using fallback templates.", self.template_path)
            self.payload_categories = {}
            self.detection_payloads = {}
            return

        try:
            with open(self.template_path, "r", encoding="utf-8") as template_file:
                content = template_file.read()

            if self.template_path.suffix in {".yml", ".yaml"}:
                try:
                    import yaml  # type: ignore

                    data = yaml.safe_load(content)
                except Exception as exc:  # pragma: no cover - optional dependency
                    logger.error("Failed to parse YAML template %s: %s", self.template_path, exc)
                    raise
            else:
                data = json.loads(content)

            self.payload_categories = data.get("payload_categories", {})
            self.detection_payloads = data.get("detection_payloads", {})
        except Exception as exc:
            logger.error("Unable to load payload templates: %s", exc)
            self.payload_categories = {}
            self.detection_payloads = {}

    def apply_watermark(self, payload: str, env: str, context_name: str, marker: str) -> str:
        """Embed a watermark comment or command into generated payloads where feasible."""
        watermark_token = f"RCEPayloadGen-ID:{marker}"

        if context_name == "attribute":
            logger.debug("Skipping watermark injection for attribute context due to quoting constraints.")
            return payload

        if env == "windows":
            return f"{payload} & REM {watermark_token}"
        if env in {"unix", "docker", "kubernetes"}:
            return f"{payload} ;# {watermark_token}"
        if env == "php":
            return f"{payload};/* {watermark_token} */"
        if env in {"python", "ruby", "perl"}:
            return f"{payload}  # {watermark_token}"
        if env == "nodejs":
            return f"{payload} // {watermark_token}"
        if env in {"java", "dotnet", "go"}:
            return f"{payload} /* {watermark_token} */"

        return f"{payload} /* {watermark_token} */"

    def _normalize_entry(self, entry: Any) -> Dict[str, Any]:
        if isinstance(entry, str):
            return {"payload": entry}
        if isinstance(entry, dict):
            return dict(entry)
        raise TypeError(f"Unsupported payload entry type: {type(entry)!r}")

    def _infer_runner(self, payload: str, env: str, sink: Optional[str]) -> Optional[str]:
        lower_payload = payload.lower()
        if "powershell" in lower_payload or "get-netipconfiguration" in lower_payload:
            return "powershell"

        runners = {
            "unix": "sh",
            "windows": "cmd",
            "nodejs": "node",
            "python": "python",
            "php": "php",
            "java": "java",
            "dotnet": "dotnet",
            "ruby": "ruby",
            "perl": "perl",
            "go": "go",
            "docker": "sh",
            "kubernetes": "kubectl",
            "sql": "sql",
            "graphql": "graphql",
            "mongodb": "mongo",
            "powershell": "powershell",
        }
        if sink and "ssti" in sink:
            return f"{env}_template"
        return runners.get(env)

    def _infer_expected_channel(self, payload: str, category_name: str, mode: str) -> str:
        lower_payload = payload.lower()
        if mode == "detection" and any(token in lower_payload for token in ["sleep", "timeout", "start-sleep"]):
            return "timing"
        if any(token in lower_payload for token in ["curl ", "wget ", "invoke-webrequest", "invoke-restmethod", "resolve-dnsname", "tcpclient"]):
            return "network"
        if any(token in lower_payload for token in ["console.error", "system.err", "error_log"]):
            return "stderr"
        if category_name in {"reverse_shells", "download_execute", "lateral_movement"}:
            return "network"
        return "response"

    def _infer_indicator(self, payload: str, category_name: str, env: str, mode: str) -> str:
        lower_payload = payload.lower()
        if mode == "detection":
            if any(token in lower_payload for token in ["{canary}", "detection_", "health_", "det:"]):
                return "Look for the generated canary token in the response body, stdout, stderr, or application logs."
            if any(token in lower_payload for token in ["sleep", "timeout", "start-sleep"]):
                return "Look for a reproducible response delay compared with baseline requests."
            if any(token in lower_payload for token in ["kubectl", "curl ", "wget ", "invoke-webrequest", "resolve-dnsname"]):
                return "Look for an authorized network, control-plane, or audit observable in your monitoring sink."
            return "Look for a benign execution marker in the response, logs, or telemetry pipeline."

        category_indicators = {
            "basic_enum": "Expect identity, host, process, or OS inventory data in the response or logs.",
            "file_operations": "Expect file content, directory listings, or permission errors that prove filesystem reachability.",
            "network_operations": "Expect network configuration data or an authorized outbound lookup in your monitoring sink.",
            "code_execution": "Expect proof that the runtime evaluated the snippet, such as command output or a rendered value.",
            "download_execute": "Expect an authorized outbound retrieval event or related telemetry in your monitoring sink.",
            "reverse_shells": "Expect an authorized out-of-band callback or connection attempt in your monitoring sink.",
            "credential_access": "Expect secret material, access-denied responses, or credential-store access telemetry.",
            "privilege_escalation": "Expect privilege inventory, group membership, capability listings, or access-denied signals.",
            "persistence": "Expect a durable artifact or configuration mutation only on an isolated lab target.",
            "cloud_metadata": "Expect metadata documents, cloud identity details, or blocked-access telemetry.",
            "database_enumeration": "Expect schema names, database inventory, or permission errors that confirm DB reachability.",
            "lateral_movement": "Expect an authorized remote-management event, connection attempt, or access-denied telemetry.",
            "container_escape": "Expect evidence of host boundary visibility, namespace access, or orchestrator privilege exposure.",
            "oob": "Expect an out-of-band DNS/HTTP callback to your collaborator/interactsh listener carrying the payload's unique token.",
            "waf_bypass": "Expect the same command output as the plain variant, proving the quote/space-free form slipped past input filtering.",
            "nosql_injection": "Expect authentication bypass, altered result sets, a reproducible delay from server-side JS, or a NoSQL/BSON error confirming operator injection.",
            "graphql_injection": "Expect introspection schema data, downstream command/SQL/NoSQL output reached through a resolver argument, or a GraphQL error revealing the injected value.",
        }
        return category_indicators.get(category_name, f"Expect a controlled {env} execution observable in the response or logs.")

    def _is_blocking(self, payload: str) -> bool:
        lower_payload = payload.lower()
        return any(token in lower_payload for token in ["tail -f", "sleep ", "timeout /t", "start-sleep", "readline()", "while(($i ="])

    def _is_stateful(self, payload: str) -> bool:
        lower_payload = payload.lower()
        return any(
            token in lower_payload
            for token in [
                "crontab",
                "reg add",
                "schtasks",
                "new-itemproperty",
                "set-mppreference",
                "copy ",
                "chmod +x",
                "out-file",
                "kubectl run",
                "docker run",
                "tar -cf",
                ">>",
            ]
        )

    def _classify_safety(self, payload: str, category_name: str, mode: str) -> str:
        lower_payload = payload.lower()
        if self._is_stateful(payload) or category_name == "persistence":
            return "stateful"
        if self._is_blocking(payload):
            return "intrusive"
        if any(token in lower_payload for token in ["curl ", "wget ", "invoke-webrequest", "invoke-restmethod", "ssh ", "scp ", "winrs ", "psexec", "kubectl ", "docker run", "nsenter", "tcpclient", "fsockopen"]):
            return "intrusive"
        if "{oob}" in payload or "jndi:" in lower_payload:
            return "intrusive"
        if mode == "detection":
            return "safe"
        if category_name in {"reverse_shells", "download_execute", "credential_access", "container_escape", "lateral_movement", "oob"}:
            return "intrusive"
        return "safe"

    def _lint_payload(self, payload: str, env: str) -> List[str]:
        lower_payload = payload.lower()
        notes: List[str] = []
        if env == "windows" and payload.strip() == "Get-NetIPConfiguration":
            notes.append("Requires a PowerShell execution surface rather than plain cmd.exe.")
        if env == "python" and "subprocess.call([" in payload and "shell=True" in payload:
            notes.append("Uses shell=True with a list argument; validate runtime semantics before relying on this variant.")
        if env == "java" and "command('bash'" in payload:
            notes.append("Contains Java-style code with single-quoted strings; validate syntax before operational use.")
        if env == "go" and "exec.command('" in lower_payload:
            notes.append("Contains Go-style code with single-quoted strings; validate syntax before operational use.")
        if "process.mainmodule" in lower_payload:
            notes.append("Relies on legacy Node.js process.mainModule behavior that may be absent in newer runtimes.")
        if "nc -e " in lower_payload:
            notes.append("Requires a netcat build that supports -e; many modern distributions disable this flag.")
        return notes

    def _requires_raw_context(self, env: str) -> bool:
        return env in {"python", "php", "java", "dotnet", "ruby", "perl", "go", "nodejs", "sql", "graphql", "mongodb"}

    def _is_context_compatible(self, context_name: str, env: str, raw_context_only: bool) -> bool:
        if context_name == "raw":
            return True
        # Serialization contexts wrap any environment's payload for the wire.
        if context_name in self.transport_contexts:
            return True
        # Shell-quoted break-outs only make sense for shell runners.
        if context_name in {"shell_single_quoted", "shell_double_quoted"}:
            return env in {"unix", "docker", "kubernetes"}
        if raw_context_only:
            if env == "php":
                return context_name == "php"
            if env == "nodejs":
                return context_name == "javascript"
            return False
        if env in {"unix", "windows", "docker", "kubernetes"}:
            return context_name in {"html", "attribute", "attribute_unquoted", "sql", "unix_shell", "windows_cmd", "powershell"}
        return False

    def _passes_filters(self, safety: str, blocking: bool, max_safety: str, include_blocking: bool) -> bool:
        normalized_max = max_safety if max_safety in SAFETY_ORDER else "intrusive"
        normalized_safety = safety if safety in SAFETY_ORDER else "intrusive"
        if SAFETY_ORDER[normalized_safety] > SAFETY_ORDER[normalized_max]:
            return False
        if blocking and not include_blocking:
            return False
        return True

    def _encoding_is_compatible(self, enc_name: str, runner: Optional[str]) -> bool:
        # random_case only survives where the target parser is case-insensitive
        # (Windows cmd, PowerShell, SQL keywords). Anywhere else it corrupts the
        # command (e.g. "id" -> "iD"), so suppress it rather than emit a payload
        # that silently fails for the operator.
        if enc_name == "random_case" and runner not in self.case_insensitive_runners:
            return False
        return True

    def _escape_for_context(self, payload: str, escape: str) -> str:
        """Make a payload valid inside its surrounding container.

        A break-out payload placed verbatim inside JSON/XML/YAML/etc. would
        corrupt the wire format; these rules encode the payload so it survives
        the serialization layer and reaches the sink intact.
        """
        if escape in {"json", "yaml", "graphql"}:
            # JSON string-body escaping (also valid for YAML double-quoted
            # scalars and GraphQL string literals): handles " \\ and controls.
            return json.dumps(payload)[1:-1]
        if escape == "xml":
            return (payload.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))
        if escape == "url":
            return urllib.parse.quote(payload)
        if escape == "header":
            # Keep the payload on a single header line unless the operator is
            # deliberately testing CRLF/header injection.
            return payload.replace("\r", " ").replace("\n", " ")
        return payload

    def generate_payload_records(
        self,
        selected_contexts: Optional[List[str]] = None,
        selected_categories: Optional[List[str]] = None,
        selected_encodings: Optional[List[str]] = None,
        selected_environments: Optional[List[str]] = None,
        mode: str = "exploit",
        watermark_token: Optional[str] = None,
        max_safety: str = "intrusive",
        include_blocking: bool = False,
        oob_domain: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        generated_payloads: Set[str] = set()
        contexts = selected_contexts if selected_contexts else list(self.default_contexts)
        encodings = selected_encodings if selected_encodings else (
            self.safe_detection_encodings if mode == "detection" else list(self.encoding_methods.keys())
        )

        if mode == "detection":
            environments = selected_environments if selected_environments else list(self.detection_payloads.keys())
            for context_name in contexts:
                if context_name not in self.contexts:
                    logger.warning("Unknown context: %s", context_name)
                    continue
                for env in environments:
                    for entry in self.detection_payloads.get(env, []):
                        base = self._normalize_entry(entry)
                        # {canary}/{oob} stay as placeholders here and are given a
                        # fresh per-record correlation token in _encode_record_variants.
                        payload = str(base["payload"]).replace("{attacker_ip}", self.attacker_ip)
                        if "{oob}" in payload and not oob_domain:
                            continue
                        runner = base.get("runner") or self._infer_runner(payload, env, None)
                        blocking = bool(base.get("blocking", self._is_blocking(payload)))
                        safety = base.get("safety") or self._classify_safety(payload, "detection", "detection")
                        raw_context_only = bool(base.get("raw_context_only", self._requires_raw_context(env)))
                        if not self._passes_filters(safety, blocking, max_safety, include_blocking):
                            continue
                        if not self._is_context_compatible(context_name, env, raw_context_only):
                            continue
                        yield from self._encode_record_variants(
                            payload=payload,
                            context_name=context_name,
                            encodings=encodings,
                            generated_payloads=generated_payloads,
                            mode="detection",
                            category="detection",
                            environment=env,
                            sink=None,
                            indicator=base.get("indicator") or self._infer_indicator(payload, "detection", env, "detection"),
                            safety=safety,
                            expected_channel=base.get("expected_channel") or self._infer_expected_channel(payload, "detection", "detection"),
                            runner=runner,
                            tags=tuple(base.get("tags", ())),
                            notes=tuple([*base.get("notes", ()), *self._lint_payload(payload, env)]),
                            blocking=blocking,
                            stateful=bool(base.get("stateful", self._is_stateful(payload))),
                            oob_domain=oob_domain,
                        )
            return

        categories = selected_categories if selected_categories else list(self.payload_categories.keys())
        environments = selected_environments if selected_environments else [
            "unix",
            "windows",
            "nodejs",
            "python",
            "php",
            "java",
            "dotnet",
            "ruby",
            "perl",
            "go",
            "docker",
            "kubernetes",
            "graphql",
            "mongodb",
        ]

        for context_name in contexts:
            if context_name not in self.contexts:
                logger.warning("Unknown context: %s", context_name)
                continue
            for category_name in categories:
                category = self.payload_categories.get(category_name)
                if category is None:
                    logger.warning("Unknown category: %s", category_name)
                    continue
                for env in environments:
                    if env not in category:
                        continue
                    env_payloads = category[env]
                    if isinstance(env_payloads, dict):
                        for sink, payloads in env_payloads.items():
                            for entry in payloads:
                                yield from self._build_record_set(
                                    entry=entry,
                                    category_name=category_name,
                                    env=env,
                                    sink=sink,
                                    context_name=context_name,
                                    encodings=encodings,
                                    generated_payloads=generated_payloads,
                                    mode=mode,
                                    watermark_token=watermark_token,
                                    max_safety=max_safety,
                                    include_blocking=include_blocking,
                                    oob_domain=oob_domain,
                                )
                    else:
                        for entry in env_payloads:
                            yield from self._build_record_set(
                                entry=entry,
                                category_name=category_name,
                                env=env,
                                sink=None,
                                context_name=context_name,
                                encodings=encodings,
                                generated_payloads=generated_payloads,
                                mode=mode,
                                watermark_token=watermark_token,
                                max_safety=max_safety,
                                include_blocking=include_blocking,
                                oob_domain=oob_domain,
                            )

    def _build_record_set(
        self,
        entry: Any,
        category_name: str,
        env: str,
        sink: Optional[str],
        context_name: str,
        encodings: List[str],
        generated_payloads: Set[str],
        mode: str,
        watermark_token: Optional[str],
        max_safety: str,
        include_blocking: bool,
        oob_domain: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        base = self._normalize_entry(entry)
        payload = str(base["payload"]).replace("{attacker_ip}", self.attacker_ip).replace("{attacker_domain}", self.attacker_domain)
        # OOB payloads only make sense with a collaborator domain to call back to.
        if "{oob}" in payload and not oob_domain:
            return
        runner = base.get("runner") or self._infer_runner(payload, env, sink)
        blocking = bool(base.get("blocking", self._is_blocking(payload)))
        safety = base.get("safety") or self._classify_safety(payload, category_name, mode)
        raw_context_only = bool(base.get("raw_context_only", self._requires_raw_context(env)))
        if not self._passes_filters(safety, blocking, max_safety, include_blocking):
            return
        if not self._is_context_compatible(context_name, env, raw_context_only):
            return

        notes = tuple([*base.get("notes", ()), *self._lint_payload(payload, env)])
        tags = tuple(dict.fromkeys([*base.get("tags", ()), category_name, *( [sink] if sink else [] )]))
        variants = [payload]
        # Shell-quoted break-out contexts already supply their own separator, so
        # prepending an env separator would produce ";;" style syntax errors.
        if env in self.separator_envs and context_name not in {"shell_single_quoted", "shell_double_quoted"}:
            variants = [f"{separator}{payload}" for separator in self.separators[env]]
            variants.append(payload)

        for variant in variants:
            final_payload = self.apply_watermark(variant, env, context_name, watermark_token) if watermark_token else variant
            yield from self._encode_record_variants(
                payload=final_payload,
                context_name=context_name,
                encodings=encodings,
                generated_payloads=generated_payloads,
                mode=mode,
                category=category_name,
                environment=env,
                sink=sink,
                indicator=base.get("indicator") or self._infer_indicator(payload, category_name, env, mode),
                safety=safety,
                expected_channel=base.get("expected_channel") or self._infer_expected_channel(payload, category_name, mode),
                runner=runner,
                tags=tags,
                notes=notes,
                blocking=blocking,
                stateful=bool(base.get("stateful", self._is_stateful(payload))),
                oob_domain=oob_domain,
            )

    def _encode_record_variants(
        self,
        payload: str,
        context_name: str,
        encodings: List[str],
        generated_payloads: Set[str],
        mode: str,
        category: str,
        environment: str,
        sink: Optional[str],
        indicator: str,
        safety: str,
        expected_channel: str,
        runner: Optional[str],
        tags: Tuple[str, ...],
        notes: Tuple[str, ...],
        blocking: bool,
        stateful: bool,
        oob_domain: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        context = self.contexts[context_name]
        for enc_name in encodings:
            if enc_name not in self.encoding_methods or not self._encoding_is_compatible(enc_name, runner):
                continue
            try:
                # Give each emitted variant its own correlation token so a received
                # callback or reflected canary maps back to exactly one payload.
                working = payload
                token: Optional[str] = None
                oob_host: Optional[str] = None
                exp_channel = expected_channel
                ind = indicator
                if "{oob}" in working and oob_domain:
                    token = self._generate_oob_token()
                    oob_host = f"{token}.{oob_domain}"
                    working = working.replace("{oob}", oob_host)
                    exp_channel = "interactsh"
                    ind = f"Look for an out-of-band DNS/HTTP callback to {oob_host} in your OOB listener."
                elif "{canary}" in working:
                    token = self._generate_canary()
                    working = working.replace("{canary}", token)

                encoded_payload = self.encoding_methods[enc_name](working)
                escape = context.get("escape", "none")
                escaped_payload = self._escape_for_context(encoded_payload, escape)
                wrapped_payload = f"{context['prefix']}{escaped_payload}{context['suffix']}"
                if wrapped_payload in generated_payloads:
                    continue
                generated_payloads.add(wrapped_payload)

                final_notes = list(notes)
                if enc_name not in {"none", "url_encode", "double_url_encode"}:
                    final_notes.append("This encoded variant requires a decode-and-execute path before the primary indicator is observable.")
                if escape != "none":
                    final_notes.append(f"Payload is escaped for the '{context_name}' serialization context; the sink must decode it before execution.")

                yield PayloadRecord(
                    payload=wrapped_payload,
                    mode=mode,
                    category=category,
                    environment=environment,
                    context=context_name,
                    encoding=enc_name,
                    sink=sink,
                    indicator=ind,
                    safety=safety if safety in SAFETY_ORDER else "intrusive",
                    expected_channel=exp_channel,
                    runner=runner,
                    tags=tags,
                    notes=tuple(dict.fromkeys(final_notes)),
                    blocking=blocking,
                    stateful=stateful,
                    token=token,
                    oob_host=oob_host,
                )
            except Exception as exc:
                logger.error("Error encoding payload with %s: %s", enc_name, exc)

    def _generate_oob_token(self) -> str:
        return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))

    def _generate_canary(self) -> str:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

    def _filter_by_profile(
        self,
        records: Iterator[PayloadRecord],
        deny_chars: Optional[str],
        max_length: Optional[int],
    ) -> Iterator[PayloadRecord]:
        """Keep only payloads a constrained target could actually accept.

        A payload is dropped if it exceeds ``max_length`` or contains any
        character in ``deny_chars``. The check runs on the final, wrapped and
        encoded payload, so an encoded variant (e.g. a URL-encoded quote) is
        correctly retained when the literal character is gone.
        """
        denied = set(deny_chars) if deny_chars else set()
        for record in records:
            if max_length and len(record.payload) > max_length:
                continue
            if denied and any(char in record.payload for char in denied):
                continue
            yield record

    def save_payloads_to_file(
        self,
        file_path: str,
        max_payloads: int = None,
        output_format: str = "text",
        include_metadata: bool = False,
        deny_chars: Optional[str] = None,
        max_length: Optional[int] = None,
        **kwargs,
    ) -> int:
        """
        Generate payloads and write them in the requested output format.

        Formats: ``text`` / ``jsonl`` (single file, plus a ``.meta.jsonl`` and,
        when correlation tokens are present, a ``.map.jsonl`` sidecar),
        ``burp`` (per-context wordlists + request template for Burp/ffuf), and
        ``nuclei`` (runnable Nuclei templates keyed to the payloads' oracle).

        Returns the number of payloads written.
        """
        output_path = Path(file_path)
        records = self.generate_payload_records(**kwargs)
        if deny_chars or max_length:
            records = self._filter_by_profile(records, deny_chars, max_length)

        if output_format == "burp":
            return self._write_burp(output_path, records, max_payloads)
        if output_format == "nuclei":
            return self._write_nuclei(output_path, records, max_payloads)

        count = 0
        manifest: List[Dict[str, Any]] = []
        metadata_path = output_path.with_suffix(f"{output_path.suffix}.meta.jsonl")
        map_path = output_path.with_suffix(f"{output_path.suffix}.map.jsonl")
        try:
            with output_path.open("w", encoding="utf-8") as file:
                metadata_file = metadata_path.open("w", encoding="utf-8") if include_metadata and output_format == "text" else None
                try:
                    for record in records:
                        serialized = json.dumps(asdict(record), ensure_ascii=True)
                        if output_format == "jsonl":
                            file.write(serialized + "\n")
                        else:
                            file.write(record.payload + "\n")
                            if metadata_file:
                                metadata_file.write(serialized + "\n")
                        if record.token:
                            manifest.append({
                                "token": record.token,
                                "oob_host": record.oob_host,
                                "payload": record.payload,
                                "category": record.category,
                                "environment": record.environment,
                                "context": record.context,
                                "sink": record.sink,
                                "encoding": record.encoding,
                                "expected_channel": record.expected_channel,
                                "indicator": record.indicator,
                            })
                        count += 1
                        if max_payloads and count >= max_payloads:
                            break
                finally:
                    if metadata_file:
                        metadata_file.close()

            if manifest:
                with map_path.open("w", encoding="utf-8") as map_file:
                    for entry in manifest:
                        map_file.write(json.dumps(entry, ensure_ascii=True) + "\n")

            logger.info("Successfully generated %s payloads to %s", count, output_path)
            if include_metadata and output_format == "text":
                logger.info("Metadata sidecar written to %s", metadata_path)
            if manifest:
                logger.info("Correlation map (token -> payload) written to %s", map_path)
        except Exception as e:
            logger.error(f"Error writing to file {output_path}: {e}")

        return count

    def _format_outdir(self, output_path: Path, suffix: str) -> Path:
        """Derive an output directory name for multi-file formats."""
        return output_path.with_name(f"{output_path.stem or 'rce_payloads'}_{suffix}")

    def _write_burp(self, output_path: Path, records: Iterator[PayloadRecord], max_payloads: Optional[int]) -> int:
        """Write deduplicated, watermark-free payload wordlists grouped by injection context."""
        outdir = self._format_outdir(output_path, "burp")
        outdir.mkdir(parents=True, exist_ok=True)
        groups: "Dict[str, List[str]]" = {}
        seen: Set[str] = set()
        count = 0
        for record in records:
            # Emit the unencoded payloads; Burp/ffuf apply their own encoding.
            if record.encoding != "none":
                continue
            if record.payload in seen:
                continue
            seen.add(record.payload)
            groups.setdefault(record.context, []).append(record.payload)
            count += 1
            if max_payloads and count >= max_payloads:
                break
        try:
            for context_name, items in groups.items():
                (outdir / f"payloads-{context_name}.txt").write_text("\n".join(items) + "\n", encoding="utf-8")
            all_items = [p for items in groups.values() for p in items]
            (outdir / "payloads-all.txt").write_text("\n".join(all_items) + "\n", encoding="utf-8")
            (outdir / "request.txt").write_text(self._burp_request_template(), encoding="utf-8")
            logger.info("Burp/ffuf wordlists written to %s/ (%s payloads across %s context files)", outdir, count, len(groups))
        except Exception as exc:
            logger.error("Error writing Burp output to %s: %s", outdir, exc)
        return count

    def _burp_request_template(self) -> str:
        return (
            "# Burp Intruder: load payloads-*.txt as a payload set; the injection\n"
            "# point is marked with Burp's position markers (the caret pair below).\n"
            "# ffuf: replace the marked value with the keyword FUZZ and use\n"
            "#   ffuf -request request.txt -w payloads-all.txt:FUZZ\n"
            "POST /vulnerable-endpoint HTTP/1.1\n"
            "Host: TARGET-HOST\n"
            "User-Agent: rcpayloadgen\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Connection: close\n"
            "\n"
            "vulnerable_param=\xa7INJECT\xa7\n"
        )

    def _write_nuclei(self, output_path: Path, records: Iterator[PayloadRecord], max_payloads: Optional[int]) -> int:
        """Emit Nuclei templates grouped by environment and oracle (OOB / time-based / reflection)."""
        import re

        outdir = self._format_outdir(output_path, "nuclei")
        outdir.mkdir(parents=True, exist_ok=True)
        canary = "RCEPGCANARY"
        groups: "Dict[Tuple[str, str], List[str]]" = {}
        seen: "Dict[Tuple[str, str], Set[str]]" = {}
        sleep_tokens = ("sleep", "timeout", "start-sleep", "pg_sleep", "thread.sleep", "time.sleep")
        count = 0
        for record in records:
            # Nuclei url-encodes the payload itself, so only the unencoded form
            # is meaningful (and encoded blobs would hide the OOB host). Inject
            # into a generic URL parameter, so only the raw context applies.
            if record.encoding != "none" or record.context != "raw":
                continue
            payload = record.payload
            lower = payload.lower()
            if record.oob_host:
                payload = payload.replace(record.oob_host, "{{interactsh-url}}")
                oracle = "oob"
            elif any(t in lower for t in sleep_tokens) and "tail" not in lower:
                # Only bounded sleeps give a reliable duration matcher; normalise
                # every delay to 6 seconds so "duration>=6" is meaningful.
                payload = re.sub(r"(?i)(sleep\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(-seconds\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(/t\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(pg_sleep\()\d+", r"\g<1>6", payload)
                oracle = "time"
            elif record.token and record.mode == "detection":
                payload = payload.replace(record.token, canary)
                oracle = "reflect"
            else:
                continue
            key = (record.environment, oracle)
            bucket = seen.setdefault(key, set())
            if payload in bucket:
                continue
            bucket.add(payload)
            groups.setdefault(key, []).append(payload)
            count += 1
            if max_payloads and count >= max_payloads:
                break
        try:
            for (env, oracle), payloads in groups.items():
                template = self._nuclei_template(env, oracle, payloads, canary)
                (outdir / f"rcpg-{env}-{oracle}.yaml").write_text(template, encoding="utf-8")
            logger.info("Nuclei templates written to %s/ (%s templates, %s payloads)", outdir, len(groups), count)
        except Exception as exc:
            logger.error("Error writing Nuclei output to %s: %s", outdir, exc)
        return count

    def _nuclei_template(self, env: str, oracle: str, payloads: List[str], canary: str) -> str:
        plist = "\n".join(f"          - {json.dumps(p)}" for p in payloads)
        if oracle == "oob":
            name = f"Out-of-band RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: word\n"
                "        part: interactsh_protocol\n"
                "        words:\n"
                "          - \"dns\"\n"
                "          - \"http\""
            )
        elif oracle == "time":
            name = f"Time-based blind RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: dsl\n"
                "        dsl:\n"
                "          - \"duration>=6\""
            )
        else:
            name = f"Reflected RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: word\n"
                "        part: body\n"
                "        words:\n"
                f"          - \"{canary}\""
            )
        return (
            f"id: rcpg-{env}-{oracle}\n\n"
            "info:\n"
            f"  name: {name}\n"
            "  author: rcpayloadgen\n"
            "  severity: high\n"
            f"  description: Injects {env} RCE payloads into a URL parameter and confirms execution via the {oracle} oracle.\n"
            f"  tags: rce,rcpayloadgen,{env},{oracle}\n\n"
            "http:\n"
            "  - raw:\n"
            "      - |\n"
            "        GET /?rcpg={{url_encode(payload)}} HTTP/1.1\n"
            "        Host: {{Hostname}}\n\n"
            "    payloads:\n"
            "      payload:\n"
            f"{plist}\n"
            "    attack: batteringram\n"
            "    stop-at-first-match: true\n\n"
            f"{matcher}\n"
        )

    def log_exploitation_usage(self, watermark_token: str, arguments: argparse.Namespace) -> None:
        audit_path = Path("exploit_audit.log")
        try:
            with audit_path.open("a", encoding="utf-8") as audit_file:
                timestamp = datetime.now(timezone.utc).isoformat()
                audit_file.write(
                    f"{timestamp} | token={watermark_token} | ip={self.attacker_ip} | domain={self.attacker_domain} | args={vars(arguments)}\n"
                )
        except Exception as exc:
            logger.error("Unable to log exploitation usage: %s", exc)

def main():
    parser = argparse.ArgumentParser(description="Generate RCE payloads for penetration testing")
    parser.add_argument("-o", "--output", default="rce_payloads.txt",
                       help="Output file path (default: rce_payloads.txt)")
    parser.add_argument("--attacker-ip", default="192.168.1.100",
                       help="Attacker IP for reverse shells (default: 192.168.1.100)")
    parser.add_argument("--attacker-domain", default="attacker.com",
                       help="Attacker domain for download payloads (default: attacker.com)")
    parser.add_argument("--max-payloads", type=int, default=None,
                       help="Maximum number of payloads to generate (default: unlimited)")
    parser.add_argument("--contexts", nargs="+", default=None,
                       help="Contexts to generate, including raw (default: all compatible contexts)")
    parser.add_argument("--categories", nargs="+", default=None,
                       help="Categories to generate (default: all)")
    parser.add_argument("--encodings", nargs="+", default=None,
                       help="Encoding methods to apply (default: mode-specific)")
    parser.add_argument("--environments", nargs="+", default=None,
                       help="Environments to generate (default: all)")
    parser.add_argument("--template-file", type=str, default=None,
                        help="Path to a custom payload template file (JSON or YAML)")
    parser.add_argument("--detection-only", action="store_true",
                        help="Generate benign payloads for detection and validation")
    parser.add_argument("--output-format", choices=["text", "jsonl", "burp", "nuclei"], default="text",
                        help="text/jsonl single file, burp (per-context wordlists + request template), or nuclei (runnable templates)")
    parser.add_argument("--oob-domain", default=None,
                        help="Collaborator/interactsh domain for out-of-band payloads; each payload gets a unique subdomain token")
    parser.add_argument("--include-metadata", action="store_true",
                        help="Write indicator and safety metadata alongside payload output")
    parser.add_argument("--max-safety", choices=["safe", "intrusive", "stateful"], default=None,
                        help="Highest safety tier to include")
    parser.add_argument("--include-blocking", action="store_true",
                        help="Include blocking or timing-based payloads that are excluded by default")
    parser.add_argument("--acknowledge-consent", action="store_true",
                        help="Acknowledge that exploitation payloads will only be used with proper authorization")
    parser.add_argument("--watermark", action="store_true",
                        help="Embed a traceable watermark token into each exploitation payload (audit logging happens either way)")
    parser.add_argument("--target-profile", default=None,
                        help="JSON profile describing the target (environments, contexts, categories, encodings, deny_chars, max_length, oob_domain); CLI flags override it")
    parser.add_argument("--deny-chars", default=None,
                        help="Drop payloads containing any of these characters (e.g. \"'\\\"\" for a target that rejects quotes)")
    parser.add_argument("--max-length", type=int, default=None,
                        help="Drop payloads longer than this many characters")

    args = parser.parse_args()

    # A target profile supplies defaults for the selection and filter options;
    # any explicit CLI flag overrides the matching profile field.
    profile: Dict[str, Any] = {}
    if args.target_profile:
        try:
            with open(args.target_profile, "r", encoding="utf-8") as profile_file:
                profile = json.load(profile_file)
        except Exception as exc:
            print(f"[!] Unable to load target profile {args.target_profile}: {exc}")
            return
        logger.info("Loaded target profile '%s' from %s", profile.get("name", "?"), args.target_profile)

    def from_profile(cli_value, key):
        return cli_value if cli_value is not None else profile.get(key)

    selected_environments = from_profile(args.environments, "environments")
    selected_contexts = from_profile(args.contexts, "contexts")
    selected_categories = from_profile(args.categories, "categories")
    selected_encodings = from_profile(args.encodings, "encodings")
    max_length = from_profile(args.max_length, "max_length")
    deny_chars = args.deny_chars
    if deny_chars is None and profile.get("deny_chars") is not None:
        deny_chars = "".join(profile["deny_chars"])

    template_path = Path(args.template_file) if args.template_file else None
    # Initialize generator
    generator = RCEPayloadGenerator(
        attacker_ip=args.attacker_ip,
        attacker_domain=args.attacker_domain,
        template_path=template_path,
    )

    mode = "detection" if args.detection_only else "exploit"

    if mode == "exploit" and not args.acknowledge_consent:
        print("[!] Exploitation mode requires explicit consent. Re-run with --acknowledge-consent after confirming authorization.")
        return

    watermark_token = None
    if mode == "exploit":
        # Always record an audit entry for accountability. Only embed the token
        # into the payloads themselves when explicitly requested, so the default
        # output stays clean and copy-pasteable for operational use.
        audit_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(audit_token, args)
        if args.watermark:
            watermark_token = audit_token

    max_safety = args.max_safety or ("safe" if mode == "detection" else "intrusive")
    include_blocking = args.include_blocking
    oob_domain = from_profile(args.oob_domain, "oob_domain")
    if args.output_format == "nuclei":
        # Nuclei templates rely on the time-based, OOB, and reflection oracles,
        # so pull in blocking/intrusive payloads and provide a placeholder OOB
        # host that the exporter rewrites to {{interactsh-url}}.
        include_blocking = True
        max_safety = "intrusive"
        if not oob_domain:
            oob_domain = "oob.interact.sh"

    count = generator.save_payloads_to_file(
        file_path=args.output,
        max_payloads=args.max_payloads,
        output_format=args.output_format,
        include_metadata=args.include_metadata or args.output_format == "jsonl",
        deny_chars=deny_chars,
        max_length=max_length,
        selected_contexts=selected_contexts,
        selected_categories=selected_categories,
        selected_encodings=selected_encodings,
        selected_environments=selected_environments,
        mode=mode,
        watermark_token=watermark_token,
        max_safety=max_safety,
        include_blocking=include_blocking,
        oob_domain=oob_domain,
    )

    print(f"Generated {count} payloads to {args.output} in {mode} mode")

if __name__ == "__main__":
    main()
