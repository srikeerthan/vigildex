#!/usr/bin/env python3
"""Copy and redact agent files from a real home directory into fixtures/.

Developer tool, standard library only. Run it as `python3 -I`:

    python3 -I scripts/collect-fixtures.py plan            # dry run (default)
    python3 -I scripts/collect-fixtures.py write           # stage, verify, copy
    python3 -I scripts/collect-fixtures.py churn           # mtimes/sizes, for the churn spike

Safety model (see docs/PRIVACY.md and fixtures/README.md):

* Sources are an explicit allowlist. A denylist (`is_denied`) covers credential
  and content stores; those files are never opened, and symlinks are never
  followed. Where a test needs such a file to exist, a key-names-only stand-in
  is written instead.
* Config files keep their structure and every string (keys included) passes
  through the scrubber. Transcripts are rebuilt from a key whitelist, so only
  usage numbers, enums and metadata survive. Shell profiles are reduced to the
  export lines that matter, with fake values.
* Everything lands in a staging folder first. A verifier scans it for secret
  patterns, the real user name, host names, e-mail addresses, project paths,
  unknown hosts, high-entropy blobs, identifiers and forbidden transcript keys.
  Only a clean staging tree is copied into fixtures/. Nothing is ever
  `git add`ed.
* The script never writes under the agents' directories, never reads an
  environment variable value and never runs an agent. A malformed vendor file
  is a warning, never a crash.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import quote, unquote

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

FAKE_HOME = "/Users/you"
FAKE_USER = "you"
FAKE_HOST = "your-mac"
FAKE_EMAIL = "you@example.com"
FAKE_HOSTNAME = "example.com"
FAKE_REMOTE = "https://github.com/you/example.git"
FAKE_REPO_SHORT = "you/example"
FAKE_UUID = "00000000-0000-4000-8000-000000000000"
FAKE_SHA1 = "0" * 40
FAKE_SHA256 = "0" * 64
FAKE_DATE = "2025-01-01T00:00:00.000Z"
FAKE_MARK = "FAKE"
FAKE_VOLUME = "/Volumes/vol"

# Public organisations whose repository URLs may stay in fixtures.
ALLOWED_ORGS = {"anthropics", "openai", "github", "modelcontextprotocol", "microsoft"}

# Hosts (exact, or any subdomain) that may stay in fixtures. Everything else
# becomes example.com.
ALLOWED_HOST_SUFFIXES = {
    "github.com", "githubusercontent.com", "githubcopilot.com", "anthropic.com", "claude.ai", "claude.com",
    "openai.com", "chatgpt.com", "npmjs.org", "npmjs.com", "pypi.org", "example.com", "localhost",
    "127.0.0.1", "0.0.0.0", "::1", "microsoft.com", "visualstudio.com", "vscode.dev", "cursor.com", "cursor.sh",
    "modelcontextprotocol.io", "context7.com", "hooks.slack.com", "googleapis.com", "google.com", "apple.com",
    "brew.sh", "rust-lang.org", "crates.io", "docs.rs", "cloudflare.com", "vercel.com", "supabase.com",
    "jsdelivr.net", "unpkg.com", "mintlify.com", "mintcdn.com", "x.ai", "mistral.ai", "huggingface.co",
    "openrouter.ai", "deepseek.com", "gemini.google.com", "aistudio.google.com", "code.claude.com",
}

# Top-level home folders that are never project roots.
NON_PROJECT_TOP = {"Library", "Applications", "Public", "Music", "Movies", "Pictures",
                   "go", "node_modules", "bin", "opt", "tmp"}
# Folder prefixes under which the next segments are a project root.
CLOUD_PARENTS = [("Library", "Mobile Documents", "com~apple~CloudDocs"), ("Library", "CloudStorage"),
                 ("Google Drive",), ("Dropbox",), ("OneDrive",), ("iCloud Drive",)]
# Path segments that may stay after a mapped project root; everything else
# becomes an opaque d<n>.
SAFE_SEGMENTS = {"src", "docs", "doc", "crates", "lib", "tests", "test", "scripts", "fixtures", "target", "build",
                 "dist", "node_modules", "bin", "include", "examples", "benches", "assets", "public", "static",
                 "config", "worktrees", "memory", "proj", "*", "**"}
FILE_EXT_RE = re.compile(
    r"\.(rs|py|js|ts|tsx|jsx|mjs|cjs|json|jsonl|md|toml|yaml|yml|sh|zsh|bash|txt|swift|go|java|kt|kts|c|h|cpp|hpp"
    r"|cc|m|mm|lock|html|css|scss|png|jpg|jpeg|gif|svg|pdf|xml|plist|sql|csv|log|cfg|ini|env|sock|key|pem|rb|php"
    r"|cs|dart|proto|graphql|wasm|zip|tar|gz|so|dylib|dll|exe|bak|snap|vue|svelte|ipynb|tex|rst|db|sqlite|mdc"
    r"|code-workspace|xcodeproj|xcworkspace)$", re.IGNORECASE)

# Key names whose values identify the account, machine or organisation.
IDENTITY_KEYS = {
    "accountuuid", "organizationuuid", "userid", "machineid", "owneraccountuuid",
    "ownerorganizationuuid", "hostsessionid", "crash-reporter-id", "account_id",
    "chatgpt_account_id", "chatgpt_user_id", "installationid", "deviceid", "sqmid",
    "organizationid", "orguuid", "workspaceuuid", "telemetryid", "anonymousid",
}
IDENTITY_KEY_RE = re.compile(r"(?i)(uuid|org|account|machine|device|installation|telemetry|anonymous|_id$|id$)")
HASH_KEY_RE = re.compile(r"(?i)(sha|commit|hash|digest)")
# Identifier keys whose values are session/message ids: random, not personal.
SAFE_ID_KEYS = {"sessionid", "uuid", "parentuuid", "leafuuid", "requestid", "lastsessionid", "id", "call_id",
                "item_id", "turn_id", "message_id", "msg_id", "promptid", "sourcetoolassistantuuid", "tool_use_id",
                "bridgesessionid", "agentid", "pid", "parentid", "session_id", "conversation_id", "sub_id",
                "response_id", "previous_response_id"}
SAFE_HASH_KEYS = {"gitcommitsha", "commit_hash", "sha", "hash", "digest", "baseline_sha", "head_at_capture"}

# Keys whose presence in a transcript is a leak regardless of value.
HARD_FORBIDDEN = {"toolUseResult", "pastedContents", "history", "exampleFiles",
                  "signature", "encrypted_content", "wireToolInputs", "wireIngestContext",
                  "serverClassifierContext", "serverClassifierRequest", "thinkingDisplay"}

# Keys that may survive in a transcript only with an empty value (or an
# allowed enum value, see ALLOWED_ENUMS).
SOFT_FORBIDDEN = {"text", "thinking", "input", "display", "lastPrompt", "customTitle",
                  "summary", "instructions", "output", "arguments", "message", "content",
                  "stdout", "stderr", "result", "user_instructions", "base_instructions",
                  "prompt", "last_agent_message", "title", "description", "query", "reason", "name", "cmd",
                  "command", "cwd_hint"}
TURN_ABORT_REASONS = {"interrupted", "replaced", "review_ended", "user_interrupt"}
BUILTIN_TOOLS = {"shell", "shell_command", "exec_command", "apply_patch", "update_plan", "view_image",
                 "web_search", "container.exec", "local_shell", "tool"}
ALLOWED_ENUMS = {"summary": {"auto", "concise", "detailed", "none"}, "reason": TURN_ABORT_REASONS,
                 "name": BUILTIN_TOOLS}

MAX_TRANSCRIPT_STRING = 120
MAX_KEY_LENGTH = 40

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
REMOTE_RE = re.compile(
    r"(?:git@|https?://)(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)[:/]"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/[^\s\"'<>)\]},:]*)?(?=$|[\s\"'<>)\]},:])"
)
SHORT_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REPO_FLAG_RE = re.compile(r"(?i)(--repo[= ]|gh repo clone |github:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
REFERENCE_RE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|op://")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
URL_HOST_RE = re.compile(
    r"(?i)\b((?:https?|wss?|redis|rediss|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|amqp|ftp|sftp|ssh)://"
    r"(?:[^/\s@\"']*@)?)([^/\s:\"'?#)\]},]+)")
DOMAIN_RULE_RE = re.compile(r"(?i)(domain:)([A-Za-z0-9.-]+)")
TILDE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(~|\$HOME|\$\{HOME\})/([^/\s\"')\]},:]+)")

# (name, regex). Order matters: specific prefixes before generic ones.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-project", re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}")),
    ("openrouter", re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}")),
    ("openai", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("github-fine-grained", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("slack", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("aws", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("npm", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("pypi", re.compile(r"pypi-[A-Za-z0-9_-]{30,}")),
    ("huggingface", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("groq", re.compile(r"gsk_[A-Za-z0-9]{40,}")),
    ("replicate", re.compile(r"r8_[A-Za-z0-9]{30,}")),
    ("xai", re.compile(r"xai-[A-Za-z0-9]{40,}")),
    ("perplexity", re.compile(r"pplx-[A-Za-z0-9]{40,}")),
    ("tavily", re.compile(r"tvly-[A-Za-z0-9-]{20,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
]
# Webhooks: keep the host and path prefix, fake the token part.
WEBHOOK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("slack-webhook", re.compile(r"(hooks\.slack\.com/services/)([A-Za-z0-9/]{10,})")),
    ("discord-webhook", re.compile(r"(discord(?:app)?\.com/api/webhooks/)([0-9]+/[A-Za-z0-9_-]+)")),
]
BEARER_RE = re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=-]{20,})")
URL_USERINFO_RE = re.compile(r"(://[^/\s@\"']*:)([^/\s@\"']+)(@)")
URL_QUERY_SECRET_RE = re.compile(r"(?i)([?&](?:key|api_key|apikey|token|access_token|secret|password)=)([^&\s\"'<>]+)")
FLAG_VALUE_RE = re.compile(
    r"(?i)(--?[A-Za-z0-9-]*(?:key|token|secret|password|passwd|auth|credential)[A-Za-z0-9-]*)([= ]+)"
    r"([^\s\"'`]+)")
FLAG_NAME_RE = re.compile(r"(?i)^--?[A-Za-z0-9-]*(?:key|token|secret|password|passwd|auth|credential)[A-Za-z0-9-]*$")
HEADER_VALUE_RE = re.compile(r"(?i)((?:x-|api-)[a-z-]*(?:key|token|auth|secret)[a-z-]*\s*:\s*)([^\s\"'`]+)")

KNOWN_PREFIXES = sorted([
    "sk-ant-api03-", "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-", "sk-or-v1-", "sk-",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
    "AKIA", "AIza", "glpat-", "npm_", "pypi-", "hf_", "gsk_", "r8_", "xai-", "pplx-", "tvly-",
], key=len, reverse=True)

SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|apikey|access[_-]?key|private[_-]?key|secret|passw(?:or)?d|authorization"
    r"|cookie|credential|bearer|(?:^|[_-])key$|(?:^|[_-])token$|^token$|accesstoken|refreshtoken|idtoken)"
)
SECRET_KEY_EXCEPT_RE = re.compile(r"(_env_var|_env|helper|_file|file|_path|path|_url|url|_name|name)$")

SHELL_EXPORT_RE = re.compile(r"^(\s*export\s+)([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
SHELL_RELEVANT_RE = re.compile(r"(KEY|TOKEN|SECRET|BASE_URL|_HOME$|CONFIG_DIR|AUTH|PASSWORD|CREDENTIAL)")

VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}")

CLAUDE_COMMON_KEYS = {
    "type", "uuid", "parentUuid", "sessionId", "timestamp", "requestId", "cwd", "version",
    "gitBranch", "isSidechain", "userType", "entrypoint", "isMeta", "permissionMode", "agentId",
    "apiBlockIndex", "effort", "perTurnEffort", "requestedModel", "thinkingDurationMs", "subtype",
    "level", "leafUuid", "operation", "mode",
}
CLAUDE_MESSAGE_KEYS = {"id", "model", "role", "type", "stop_reason"}
CLAUDE_USAGE_ENUM_KEYS = {"service_tier", "speed", "inference_geo"}
CLAUDE_JSON_TOP_KEEP = [
    "mcpServers", "hasAvailableSubscription", "hasCompletedOnboarding", "hasOpusPlanDefault",
    "installMethod", "autoUpdates", "autoUpdaterStatus", "numStartups", "firstStartTime",
    "lastOnboardingVersion", "migrationVersion", "editorMode", "autoCompactEnabled",
    "claudeCodeFirstTokenDate",
]
CLAUDE_PROJECT_KEEP = {
    "mcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "hasTrustDialogAccepted",
    "hasTrustDialogHooksAccepted", "allowedTools", "hasClaudeMdExternalIncludesApproved",
    "hasClaudeMdExternalIncludesWarningShown", "ignorePatterns", "lastCost", "lastDuration",
    "lastAPIDuration", "lastTotalInputTokens", "lastTotalOutputTokens",
    "lastTotalCacheCreationInputTokens", "lastTotalCacheReadInputTokens",
    "lastTotalWebSearchRequests", "lastSessionId", "lastModelUsage", "lastVersionBase",
    "mcpContextUris", "projectOnboardingSeenCount",
}
ACCOUNT_ENUM_KEYS = {"seattier", "billingtype", "organizationrole", "organizationtype", "workspacerole",
                     "userratelimittier", "organizationratelimittier", "subscriptiontype", "ratelimittier"}
CODEX_SESSION_META_KEEP = {"id", "timestamp", "cli_version", "originator", "cwd", "model_provider"}
CODEX_TURN_CONTEXT_KEEP = {"cwd", "approval_policy", "model", "effort", "summary", "model_provider", "turn_id"}
CODEX_PAYLOAD_ID_KEYS = {"id", "call_id", "item_id", "turn_id", "sub_id", "role", "status", "kind"}
VSCODE_KEEP_PREFIXES = ("chat.", "github.copilot", "security.workspace.", "mcp", "terminal.integrated.env.")
ARG_CONTEXT_KEYS = {"args", "command", "env", "headers", "http_headers", "env_http_headers", "hooks", "url",
                    "script", "allow", "deny", "ask"}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def fill_fake(n: int) -> str:
    """`FAKE` repeated and cut to exactly `n` characters."""
    if n <= 0:
        return ""
    return (FAKE_MARK * (n // len(FAKE_MARK) + 1))[:n]


def fake_same_shape(value: str) -> str:
    """Replace a secret with a fake of the same length and recognisable prefix."""
    if value.count(".") == 2 and value.startswith("eyJ"):
        parts = value.split(".")
        head = "eyJ" + fill_fake(len(parts[0]) - 3)
        return ".".join([head] + [fill_fake(len(p)) for p in parts[1:]])
    for prefix in KNOWN_PREFIXES:
        if value.startswith(prefix):
            return prefix + fill_fake(len(value) - len(prefix))
    return fill_fake(len(value))


def fake_identity(value: str) -> str:
    """A fixed fake for identifiers, keeping the UUID or hash shape."""
    if UUID_RE.match(value):
        return FAKE_UUID
    if HEX_RE.match(value) and len(value) == 64:
        return FAKE_SHA256
    if HEX_RE.match(value) and len(value) == 40:
        return FAKE_SHA1
    if HEX_RE.match(value):
        return "0" * len(value)
    return fill_fake(len(value))


def looks_like_secret_key(name: str) -> bool:
    """True when a key name suggests its value is a secret, not a pointer to one."""
    lowered = name.lower()
    if SECRET_KEY_EXCEPT_RE.search(lowered):
        return False
    return bool(SECRET_KEY_RE.search(lowered))


def is_reference(value: str) -> bool:
    """True for `${VAR}`, `${env:X}`, `$VAR/...`, `op://...` style references."""
    stripped = value.strip()
    return bool(re.fullmatch(r"\$\{[^}]+\}", stripped)
                or re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*(?:/.*)?", stripped)
                or stripped.startswith("op://"))


def contains_reference(value: str) -> bool:
    return bool(REFERENCE_RE.search(value))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def encode_path(path: str) -> str:
    """Claude Code's project-directory encoding: every non-alphanumeric → `-`."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def is_file_name(segment: str) -> bool:
    return bool(FILE_EXT_RE.search(segment))


def host_allowed(host: str) -> bool:
    h = host.lower().strip("[]")
    if h in ALLOWED_HOST_SUFFIXES:
        return True
    return any(h.endswith("." + suffix) for suffix in ALLOWED_HOST_SUFFIXES)


def find_secrets(text: str) -> list[tuple[str, str]]:
    found = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            found.append((name, m.group(0)))
    for name, rx in WEBHOOK_PATTERNS:
        for m in rx.finditer(text):
            found.append((name, m.group(2)))
    if PRIVATE_KEY_RE.search(text):
        found.append(("private-key", "-----BEGIN PRIVATE KEY-----"))
    return found


def version_key(v: str) -> tuple:
    """Type-stable sort key: numeric parts sort before textual ones."""
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.-]", v))


def is_safe_version(v: Any) -> bool:
    return isinstance(v, str) and bool(VERSION_RE.fullmatch(v)) and ".." not in v


def key_needs_placeholder(key: str) -> bool:
    return len(key) > MAX_KEY_LENGTH or any(ch in key for ch in "/:\\ ") or key.startswith(("~", "."))


def blank_shape(value: Any, keep_keys: Iterable[str] = (), keep_anywhere: Iterable[str] = (),
                top: bool = True) -> Any:
    """Keep structure, non-string scalars and enum-like keys; blank every other string.

    `keep_keys` apply to string values at the top level only; `keep_anywhere`
    at any depth; `type` is always kept. Hard-forbidden keys are dropped, and
    keys that look like paths, URLs or prose become `key_<n>`.
    """
    keep = set(keep_keys)
    keep_any = set(keep_anywhere) | {"type"}
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        n = 0
        for k, v in value.items():
            if not isinstance(k, str):
                k = str(k)
            if k in HARD_FORBIDDEN:
                continue
            if key_needs_placeholder(k):
                n += 1
                k = f"key_{n}"
            if isinstance(v, str):
                if k in keep_any or (top and k in keep):
                    out[k] = "main" if k == "gitBranch" else v
                else:
                    out[k] = ""
            elif isinstance(v, (dict, list)):
                out[k] = blank_shape(v, keep, keep_any, top=False)
            else:
                out[k] = v
        return out
    if isinstance(value, list):
        return [blank_shape(v, keep, keep_any, top=False) for v in value]
    if isinstance(value, str):
        return ""
    return value


# --------------------------------------------------------------------------- #
# Identity and scrubber
# --------------------------------------------------------------------------- #

@dataclass
class Identity:
    home: Path
    username: str
    hostname: str
    hostnames: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        names = [self.hostname] + list(self.hostnames)
        self.hostnames = [n for n in dict.fromkeys(n.strip() for n in names) if n and len(n) >= 4]

    @classmethod
    def detect(cls, home: Path, hostname: str | None = None) -> "Identity":
        names: list[str] = []
        if hostname:
            names.append(hostname)
        try:
            names.append(socket.gethostname().split(".")[0])
        except OSError:
            pass
        for key in ("ComputerName", "LocalHostName", "HostName"):
            try:
                out = subprocess.run(["scutil", "--get", key], capture_output=True, text=True, timeout=3)
                if out.returncode == 0 and out.stdout.strip():
                    names.append(out.stdout.strip())
            except (OSError, subprocess.SubprocessError):
                pass
        names = [n for n in names if n and n.lower() not in ("localhost", "mac", "macbook")]
        primary = names[0] if names else ""
        return cls(home=home, username=home.name, hostname=primary, hostnames=names)


@dataclass
class Scrubber:
    identity: Identity
    project_map: dict[str, str] = field(default_factory=dict)
    segment_map: dict[str, str] = field(default_factory=dict)
    marketplace_map: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=lambda: {
        "secrets": 0, "paths": 0, "emails": 0, "identities": 0, "remotes": 0, "hosts": 0, "urlhosts": 0})

    def __post_init__(self) -> None:
        user = re.escape(self.identity.username)
        # A path: a prefix, then segments. Spaces are allowed inside a segment
        # unless followed by a shell operator or a flag.
        seg = r"(?:[^\s\"'`<>|;:,)\]}]|[ ](?![&|;<>$-]))"
        self._home_re = re.compile(r"(?P<prefix>/Users/" + user + r"|(?<![A-Za-z0-9~])~|\$\{HOME\}|\$HOME)"
                                   r"(?P<rest>(?:/" + seg + r"*)?)(?=$|[^A-Za-z0-9_])")
        self._volume_re = re.compile(r"(?<![A-Za-z0-9])/Volumes/(?P<disk>[^/\s\"'`<>|;:,)\]}]+)"
                                     r"(?P<rest>(?:/" + seg + r"*)?)")
        self._encoded_home_re = re.compile(r"(?i)%2FUsers%2F" + user + r"(?:%2F[A-Za-z0-9._~!*()+-]*)*")
        self._enc_prefix_re = re.compile(r"-Users-" + user + r"-")
        self._enc_prefix_nodash_re = re.compile(r"(?<![A-Za-z0-9-])Users-" + user + r"-")
        self._user_re = re.compile(r"(?i)(?<![A-Za-z0-9])" + user)
        self._host_res = []
        for host in self.identity.hostnames:
            variants = {host, host.replace("'", "\u2019"), host.replace("\u2019", "'")}
            for v in variants:
                self._host_res.append(re.compile(r"(?i)(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])"))

    # -- registration -------------------------------------------------------- #

    def register_project(self, real_root: str, fake_prefix: str = FAKE_HOME) -> str:
        if real_root not in self.project_map:
            self.project_map[real_root] = f"{fake_prefix}/proj/{len(self.project_map) + 1}"
        return self.project_map[real_root]

    def register_marketplace(self, name: str) -> str:
        if name == "claude-plugins-official" or not name:
            return name
        if name not in self.marketplace_map:
            self.marketplace_map[name] = f"marketplace-{len(self.marketplace_map) + 1}"
        return self.marketplace_map[name]

    def _opaque_segment(self, segment: str) -> str:
        if segment in SAFE_SEGMENTS or segment.startswith(".") or is_file_name(segment) \
                or any(ch in segment for ch in "*?{}"):
            return segment
        if segment not in self.segment_map:
            self.segment_map[segment] = f"d{len(self.segment_map) + 1}"
        return self.segment_map[segment]

    def _map_segments(self, segs: list[str], real_prefix: str, fake_prefix: str) -> str:
        """Map `segs` (no leading slash) that live directly under a project parent."""
        root_len = 2 if len(segs) >= 2 else 1
        if root_len == len(segs) and is_file_name(segs[-1]):
            root_len -= 1
        if root_len == 0:
            return "/".join(segs)
        real_root = real_prefix + "/" + "/".join(segs[:root_len])
        fake_root = self.register_project(real_root, fake_prefix)
        self.counters["paths"] += 1
        rest = [self._opaque_segment(s) for s in segs[root_len:]]
        suffix = fake_root[len(fake_prefix):]  # "/proj/N"
        return suffix.lstrip("/") + ("/" + "/".join(rest) if rest else "")

    def _map_rest(self, rest: str, real_prefix: str, fake_prefix: str) -> str:
        """`rest` follows the home prefix (empty or starting with `/`)."""
        if not rest or rest == "/":
            return rest
        trailing = "/" if rest.endswith("/") else ""
        segs = rest.strip("/").split("/")
        if segs[0] == "proj" and len(segs) >= 2 and segs[1].isdigit():
            return rest  # already mapped
        if segs[0].startswith("."):
            return rest
        for parent in CLOUD_PARENTS:
            n = len(parent)
            if tuple(segs[:n]) == parent:
                head = list(parent)
                tail = segs[n:]
                if parent == ("Library", "CloudStorage") and tail:
                    head.append("provider")
                    tail = tail[1:]
                if not tail:
                    return "/" + "/".join(head) + trailing
                mapped = self._map_segments(tail, real_prefix + "/" + "/".join(parent), fake_prefix)
                return "/" + "/".join(head) + "/" + mapped + trailing
        if segs[0] in NON_PROJECT_TOP:
            return rest
        return "/" + self._map_segments(segs, real_prefix, fake_prefix) + trailing

    def _sub_home(self, m: re.Match) -> str:
        prefix, rest = m.group("prefix"), m.group("rest")
        fake_prefix = FAKE_HOME if prefix.startswith("/Users/") else prefix
        real_prefix = f"/Users/{self.identity.username}"
        return fake_prefix + self._map_rest(rest, real_prefix, FAKE_HOME)

    def _sub_volume(self, m: re.Match) -> str:
        disk, rest = m.group("disk"), m.group("rest")
        if disk == "vol":
            return m.group(0)
        segs = rest.strip("/").split("/") if rest.strip("/") else []
        if not segs:
            return FAKE_VOLUME
        trailing = "/" if rest.endswith("/") else ""
        # The disk is the container, the next segment the project root.
        return FAKE_VOLUME + "/" + self._map_segments([disk] + segs, "/Volumes", FAKE_VOLUME) + trailing

    def _sub_encoded_home(self, m: re.Match) -> str:
        decoded = unquote(m.group(0))
        return quote(self.scrub_string(decoded), safe="")

    # -- string scrubbing ---------------------------------------------------- #

    def _fake_secret(self, m: re.Match) -> str:
        value = m.group(0)
        if FAKE_MARK not in value:
            self.counters["secrets"] += 1
        return fake_same_shape(value)

    def _fake_remote(self, m: re.Match) -> str:
        if m.group(1) in ALLOWED_ORGS:
            return m.group(0)
        if m.group(0) != FAKE_REMOTE:
            self.counters["remotes"] += 1
        return FAKE_REMOTE

    def _fake_flag_value(self, m: re.Match) -> str:
        flag, sep, value = m.groups()
        if value.startswith(("-", "/", "~", "$", ".", "@")) or contains_reference(value) or FAKE_MARK in value:
            return m.group(0)
        self.counters["secrets"] += 1
        return flag + sep + fake_same_shape(value)

    def _fake_host(self, m: re.Match) -> str:
        scheme, host = m.group(1), m.group(2)
        if host_allowed(host):
            return m.group(0)
        self.counters["urlhosts"] += 1
        return scheme + FAKE_HOSTNAME

    def _fake_domain_rule(self, m: re.Match) -> str:
        if host_allowed(m.group(2)):
            return m.group(0)
        self.counters["urlhosts"] += 1
        return m.group(1) + FAKE_HOSTNAME

    def fake_value(self, value: str) -> str:
        """Fake a value known to be a secret (by key name or position)."""
        if not value or contains_reference(value) or FAKE_MARK in value:
            return value
        self.counters["secrets"] += 1
        return fake_same_shape(value)

    def scrub_string(self, s: str) -> str:
        if not s:
            return s
        for _name, rx in SECRET_PATTERNS:
            s = rx.sub(self._fake_secret, s)
        for _name, rx in WEBHOOK_PATTERNS:
            s = rx.sub(lambda m: m.group(1) + (m.group(2) if FAKE_MARK in m.group(2) else fill_fake(len(m.group(2)))), s)
        s = BEARER_RE.sub(lambda m: m.group(1) + fake_same_shape(m.group(2)), s)
        s = URL_USERINFO_RE.sub(lambda m: m.group(1) + fill_fake(len(m.group(2))) + m.group(3), s)
        s = URL_QUERY_SECRET_RE.sub(lambda m: m.group(1) + fill_fake(len(m.group(2))), s)
        s = FLAG_VALUE_RE.sub(self._fake_flag_value, s)
        s = HEADER_VALUE_RE.sub(lambda m: m.group(1) + fake_same_shape(m.group(2)), s)
        s = REMOTE_RE.sub(self._fake_remote, s)
        s = REPO_FLAG_RE.sub(lambda m: m.group(0) if m.group(2).split("/")[0] in ALLOWED_ORGS
                             else m.group(1) + FAKE_REPO_SHORT, s)
        s = self._encoded_home_re.sub(self._sub_encoded_home, s)
        s = self._home_re.sub(self._sub_home, s)
        s = self._volume_re.sub(self._sub_volume, s)
        for real_root in sorted(self.project_map, key=len, reverse=True):
            enc_real = encode_path(real_root)
            enc_fake = encode_path(self.project_map[real_root])
            s = s.replace(enc_real, enc_fake)
            s = re.sub(r"(?<![A-Za-z0-9-])" + re.escape(enc_real[1:]), enc_fake[1:], s)
        s = self._enc_prefix_re.sub(f"-Users-{FAKE_USER}-", s)
        s = self._enc_prefix_nodash_re.sub(f"Users-{FAKE_USER}-", s)
        for real, fake in self.marketplace_map.items():
            s = re.sub(r"(?<![A-Za-z0-9-])" + re.escape(real) + r"(?![A-Za-z0-9-])", fake, s)
        s = URL_HOST_RE.sub(self._fake_host, s)
        s = DOMAIN_RULE_RE.sub(self._fake_domain_rule, s)
        for rx in self._host_res:
            s, n = rx.subn(FAKE_HOST, s)
            self.counters["hosts"] += n
        s = self._user_re.sub(FAKE_USER, s)
        s, n = EMAIL_RE.subn(lambda m: m.group(0) if m.group(0) == FAKE_EMAIL else FAKE_EMAIL, s)
        self.counters["emails"] += n
        return s

    # -- JSON scrubbing ------------------------------------------------------ #

    def scrub_json(self, obj: Any, key: str | None = None) -> Any:
        if isinstance(obj, dict):
            return {self.scrub_string(str(k)): self._scrub_json_value(str(k), v) for k, v in obj.items()}
        if isinstance(obj, list):
            return self._scrub_list(obj)
        if isinstance(obj, str):
            return self.scrub_string(obj)
        return obj

    def _scrub_list(self, items: list) -> list:
        out = []
        previous: Any = None
        for item in items:
            if isinstance(item, str) and isinstance(previous, str) and FLAG_NAME_RE.match(previous) \
                    and not item.startswith(("-", "/", "~", "$", ".", "@")):
                out.append(self.fake_value(item))
            else:
                out.append(self.scrub_json(item))
            previous = item
        return out

    def _scrub_json_value(self, key: str, value: Any) -> Any:
        if isinstance(value, str):
            lowered = key.lower()
            if lowered in IDENTITY_KEYS:
                self.counters["identities"] += 1
                return fake_identity(value)
            if lowered not in SAFE_ID_KEYS and UUID_RE.match(value) and IDENTITY_KEY_RE.search(key):
                self.counters["identities"] += 1
                return fake_identity(value)
            if lowered not in SAFE_ID_KEYS and HASH_KEY_RE.search(key) and HEX_RE.match(value) and len(value) >= 20:
                self.counters["identities"] += 1
                return fake_identity(value)
            if key == "repo" and SHORT_REPO_RE.match(value):
                return value if value.split("/")[0] in ALLOWED_ORGS else FAKE_REPO_SHORT
            if looks_like_secret_key(key) and value and not contains_reference(value):
                return self.fake_value(value)
            return self.scrub_string(value)
        if isinstance(value, dict):
            return self.scrub_json(value)
        if isinstance(value, list):
            return self._scrub_list(value)
        return value


# --------------------------------------------------------------------------- #
# Transcript skeletons
# --------------------------------------------------------------------------- #

def _content_shape(content: Any) -> Any:
    if isinstance(content, list):
        return [{"type": b.get("type") if isinstance(b.get("type"), str) else None} if isinstance(b, dict)
                else {"type": None} for b in content]
    if isinstance(content, str):
        return ""
    return None


def skeletonize_claude_record(rec: Any, scrubber: Scrubber) -> dict | None:
    if not isinstance(rec, dict) or not isinstance(rec.get("type"), str):
        return None
    rtype = rec["type"]
    out: dict[str, Any]
    if rtype in ("assistant", "user", "system"):
        out = {k: rec[k] for k in CLAUDE_COMMON_KEYS if k in rec and not isinstance(rec[k], (dict, list))}
        if isinstance(out.get("gitBranch"), str):
            out["gitBranch"] = "main"
        msg = rec.get("message")
        if isinstance(msg, dict):
            new_msg = {k: msg[k] for k in CLAUDE_MESSAGE_KEYS if k in msg and not isinstance(msg[k], (dict, list))}
            if "content" in msg:
                new_msg["content"] = _content_shape(msg["content"])
            if isinstance(msg.get("usage"), dict):
                new_msg["usage"] = blank_shape(msg["usage"], CLAUDE_USAGE_ENUM_KEYS)
            out["message"] = new_msg
    else:
        out = blank_shape(rec, CLAUDE_COMMON_KEYS)
    return scrubber.scrub_json(out)


def skeletonize_codex_record(rec: Any, scrubber: Scrubber) -> dict | None:
    if not isinstance(rec, dict) or not isinstance(rec.get("type"), str):
        return None
    rtype = rec["type"]
    payload = rec.get("payload")
    out: dict[str, Any] = {k: rec[k] for k in ("timestamp", "type") if isinstance(rec.get(k), str)}
    if not isinstance(payload, dict):
        out["payload"] = blank_shape(payload)
        return scrubber.scrub_json(out)

    ptype = payload.get("type") if isinstance(payload.get("type"), str) else None
    if rtype == "session_meta":
        new = {k: payload[k] for k in CODEX_SESSION_META_KEEP if k in payload and not isinstance(payload[k], (dict, list))}
        if "source" in payload:
            new["source"] = payload["source"] if isinstance(payload["source"], str) else blank_shape(payload["source"])
        if "instructions" in payload:
            new["instructions"] = ""
        git = payload.get("git")
        if isinstance(git, dict):
            new_git = {}
            if "branch" in git:
                new_git["branch"] = "main"
            if "commit_hash" in git:
                new_git["commit_hash"] = FAKE_SHA1
            if "repository_url" in git:
                new_git["repository_url"] = FAKE_REMOTE
            new["git"] = new_git
        out["payload"] = new
    elif rtype == "turn_context":
        new = {k: payload[k] for k in CODEX_TURN_CONTEXT_KEEP if k in payload and not isinstance(payload[k], (dict, list))}
        if isinstance(payload.get("sandbox_policy"), dict):
            new["sandbox_policy"] = blank_shape(payload["sandbox_policy"], {"mode"})
        out["payload"] = new
    elif rtype == "event_msg" and ptype == "token_count":
        out["payload"] = blank_shape(payload, keep_anywhere={"plan_type", "limit_id", "limit_name"})
    elif rtype == "event_msg" and ptype == "turn_aborted":
        new = blank_shape(payload)
        reason = payload.get("reason")
        if isinstance(reason, str) and reason in TURN_ABORT_REASONS:
            new["reason"] = reason
        out["payload"] = new
    elif rtype == "response_item":
        new = blank_shape(payload, CODEX_PAYLOAD_ID_KEYS)
        if ptype in ("function_call", "custom_tool_call", "local_shell_call") and isinstance(payload.get("name"), str):
            new["name"] = payload["name"] if payload["name"] in BUILTIN_TOOLS else "tool"
        if ptype == "message" and "content" in payload:
            new["content"] = _content_shape(payload["content"])
        out["payload"] = new
    else:
        out["payload"] = blank_shape(payload, CODEX_PAYLOAD_ID_KEYS)
    return scrubber.scrub_json(out)


def skeletonize_generic_record(rec: Any, scrubber: Scrubber) -> dict | None:
    """For formats we do not know yet (Copilot events): shape, numbers and ids only."""
    if not isinstance(rec, dict) or not isinstance(rec.get("type"), str):
        return None
    return scrubber.scrub_json(blank_shape(rec, {"id", "parentId", "timestamp"}))


# --------------------------------------------------------------------------- #
# Config reducers
# --------------------------------------------------------------------------- #

def _fake_oauth_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _fake_oauth_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_fake_oauth_value(key, v) for v in value]
    if not isinstance(value, str):
        return value
    lowered = key.lower()
    if "email" in lowered or EMAIL_RE.search(value):
        return FAKE_EMAIL
    if UUID_RE.match(value) or "uuid" in lowered or lowered.endswith("id"):
        return fake_identity(value)
    if lowered == "fullname":
        return "You Example"
    if lowered == "displayname":
        return "You"
    if lowered.endswith("name"):
        return "Example Org"
    if lowered.endswith("at") or lowered.endswith("date"):
        return FAKE_DATE
    if lowered in ACCOUNT_ENUM_KEYS:
        return value
    return "redacted"


def reduce_claude_json(obj: dict, scrubber: Scrubber, max_projects: int = 5) -> dict:
    out: dict[str, Any] = {}
    for k in CLAUDE_JSON_TOP_KEEP:
        if k in obj:
            out[k] = scrubber.scrub_json(obj[k])
    account = obj.get("oauthAccount")
    if isinstance(account, dict):
        out["oauthAccount"] = scrubber.scrub_json({k: _fake_oauth_value(k, v) for k, v in account.items()})
    responses = obj.get("customApiKeyResponses")
    if isinstance(responses, dict):
        out["customApiKeyResponses"] = {k: [] for k in responses}
    for k in ("userID", "machineID"):
        if isinstance(obj.get(k), str):
            out[k] = fake_identity(obj[k])
    projects = obj.get("projects")
    if isinstance(projects, dict):
        ordered = sorted(projects.items(),
                         key=lambda kv: (0 if isinstance(kv[1], dict) and kv[1].get("mcpServers") else 1))
        chosen = ordered[:max_projects]
        for path, _conf in sorted(chosen, key=lambda kv: kv[0]):
            scrubber.scrub_string(path)  # register roots in a stable order
        out_projects: dict[str, Any] = {}
        for path, conf in chosen:
            new_path = scrubber.scrub_string(path)
            if isinstance(conf, dict):
                out_projects[new_path] = scrubber.scrub_json({k: v for k, v in conf.items() if k in CLAUDE_PROJECT_KEEP})
            else:
                out_projects[new_path] = conf
        out["projects"] = out_projects
    return out


MAX_SETTINGS_STRING = 200


def _blank_long_strings(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _blank_long_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_blank_long_strings(v) for v in value]
    if isinstance(value, str) and len(value) > MAX_SETTINGS_STRING:
        return ""
    return value


def reduce_settings(settings: dict, max_rules: int) -> dict:
    """Cap permission lists and drop prose Claude Code writes into settings.

    `autoMode.environment` is a free-text description of the repository and
    its remotes; any other string over MAX_SETTINGS_STRING is treated as prose.
    """
    perms = settings.get("permissions")
    if isinstance(perms, dict):
        for k in ("allow", "ask", "deny"):
            if isinstance(perms.get(k), list):
                # Rules longer than the prose limit are inline scripts; drop them.
                rules = [r for r in perms[k] if not (isinstance(r, str) and len(r) > MAX_SETTINGS_STRING)]
                perms[k] = rules[:max_rules]
    if isinstance(settings.get("autoMode"), dict):
        settings["autoMode"] = blank_shape(settings["autoMode"])
    return _blank_long_strings(settings)


def cap_permission_lists(settings: dict, max_rules: int) -> dict:
    return reduce_settings(settings, max_rules)


def reduce_vscode_settings(obj: dict, scrubber: Scrubber) -> dict:
    out: dict[str, Any] = {}
    for k, v in obj.items():
        if not isinstance(k, str) or not k.startswith(VSCODE_KEEP_PREFIXES):
            continue
        if k.startswith("terminal.integrated.env.") and isinstance(v, dict):
            out[k] = {name: fill_fake(len(val)) if isinstance(val, str) else val for name, val in v.items()}
        elif re.search(r"(?i)(instruction|prompt)", k):
            out[scrubber.scrub_string(k)] = blank_shape(v) if isinstance(v, (dict, list, str)) else v
        else:
            out[scrubber.scrub_string(k)] = scrubber.scrub_json(v)
    return out


def extract_shell_exports(text: str, scrubber: Scrubber) -> str:
    lines = ["# Trimmed by scripts/collect-fixtures.py: only agent-relevant export lines are kept",
             "# and every value is a fake of the same shape. Nothing else from the real profile is here."]
    for line in text.splitlines():
        m = SHELL_EXPORT_RE.match(line)
        if not m:
            continue
        prefix, name, raw = m.group(1), m.group(2), m.group(3)
        if not SHELL_RELEVANT_RE.search(name):
            continue
        quote_ch = ""
        value = raw
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
            quote_ch, value = raw[0], raw[1:-1]
        if looks_like_secret_key(name) and value and not contains_reference(value):
            value = scrubber.fake_value(value)
        else:
            value = scrubber.scrub_string(value)
        lines.append(f"{prefix}{name}={quote_ch}{value}{quote_ch}")
    return "\n".join(lines) + "\n"


_TOML_KV_RE = re.compile(r'^(\s*)("[^"]+"|[A-Za-z0-9_.-]+)(\s*=\s*)(.*)$')
_TOML_INLINE_KV_RE = re.compile(r'("?)([A-Za-z0-9_.-]+)\1(\s*=\s*)"([^"]*)"')


def redact_toml(text: str, scrubber: Scrubber) -> str:
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") or stripped.startswith("#") or not stripped:
            out.append(scrubber.scrub_string(line))
            continue
        m = _TOML_KV_RE.match(line)
        if not m:
            out.append(scrubber.scrub_string(line))
            continue
        indent, key, eq, value = m.groups()
        bare_key = key.strip('"')
        header_table = bare_key.endswith(("headers", "_headers")) or bare_key == "env"
        if looks_like_secret_key(bare_key) and value.startswith('"') and value.rstrip().endswith('"'):
            inner = value.strip()[1:-1]
            value = f'"{scrubber.fake_value(inner)}"'
        else:
            def _inline(m2: re.Match) -> str:
                q, k2, eq2, v2 = m2.groups()
                if (header_table or looks_like_secret_key(k2)) and v2 and not contains_reference(v2):
                    return f'{q}{k2}{q}{eq2}"{scrubber.fake_value(v2)}"'
                return m2.group(0)
            value = _TOML_INLINE_KV_RE.sub(_inline, value)
            value = scrubber.scrub_string(value)
        out.append(f"{indent}{key}{eq}{value}")
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


_JSONC_KV_RE = re.compile(r'^(\s*)"([^"]+)"(\s*:\s*)"([^"]*)"(.*)$')


def redact_jsonc(text: str, scrubber: Scrubber) -> str:
    out = []
    for line in text.splitlines():
        m = _JSONC_KV_RE.match(line)
        if m:
            indent, key, sep, value, rest = m.groups()
            if key.lower() in IDENTITY_KEYS or (UUID_RE.match(value) and IDENTITY_KEY_RE.search(key)):
                value = fake_identity(value)
            elif looks_like_secret_key(key) and value and not contains_reference(value):
                value = scrubber.fake_value(value)
            else:
                value = scrubber.scrub_string(value)
            out.append(f'{indent}"{scrubber.scrub_string(key)}"{sep}"{value}"{rest}')
        else:
            out.append(scrubber.scrub_string(line))
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


# --------------------------------------------------------------------------- #
# Denylist
# --------------------------------------------------------------------------- #

DENIED_NAMES = {".credentials.json", "auth.json", "state.vscdb", "session-store.db", "hosts.json",
                "apps.json", "versions.json", "history.jsonl", "storage.json", ".ds_store",
                "command-history-state.json", "ide_state.json"}
DENIED_SUFFIXES = (".key", ".vscdb", ".db", ".sqlite", ".sqlite3", ".pem", ".p12", ".keychain",
                   ".keychain-db", ".log", ".bak")
DENIED_DIRS = {"shell-snapshots", "session-env", "file-history", "paste-cache", "security", "telemetry",
               "memory", "mcp-secrets", "mcp-oauth-config", "github-copilot", "log", "logs", "debug",
               "feedback", "chrome", "synced", "ide", "statsig", "todos", "sidebar-sessions-state"}


def is_denied(path: Path) -> bool:
    name = path.name.lower()
    if name in DENIED_NAMES or name.startswith(".credentials.json"):
        return True
    if name.endswith(DENIED_SUFFIXES):
        return True
    parts = [p.lower() for p in path.parts]
    if name == "config.json" and len(parts) >= 2 and parts[-2] == ".copilot":
        return True
    for i, part in enumerate(parts[:-1]):
        if part in DENIED_DIRS:
            return True
        if part == "cache" and i > 0 and parts[i - 1] == ".claude":
            return True
    return False


def open_allowed(path: Path):
    """Open a source file for reading. Refuses denylisted paths and any symlink."""
    if is_denied(path):
        raise PermissionError(f"refusing to open denylisted path: {path}")
    if path.is_symlink():
        raise PermissionError(f"refusing to follow symlink: {path}")
    real = Path(os.path.realpath(path))
    if real != path and is_denied(real):
        raise PermissionError(f"refusing to open path that resolves to a denylisted file: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    return os.fdopen(fd, "r", encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# Verifier
# --------------------------------------------------------------------------- #

def _mask(value: str) -> str:
    return value[:4] + "…" + value[-3:] if len(value) > 10 else "…"


def _path_like(token: str) -> bool:
    """Paths, flags and identifiers that the entropy check must not treat as secrets."""
    if token.startswith(("/", "~", ".", "-", "$", "@")) or "://" in token:
        return True
    if re.fullmatch(r"[A-Za-z]+", token):
        return True  # camelCase identifiers and key names
    if "/" in token:
        first = token.split("/")[0]
        if first in {"Users", "private", "Volumes", "tmp", "var", "opt", "usr", "etc", "home", "Library",
                     "Applications", "fixtures", "docs", "src", "crates", "scripts"}:
            return True
        # Hyphenated or mostly-lowercase slash-separated words are paths or
        # package names; base64 secrets with slashes are mixed case and unhyphenated.
        if "-" in token or sum(ch.isupper() for ch in token) <= 2:
            return True
    return False


@dataclass
class Verifier:
    identity: Identity
    scrubber: Scrubber
    public_names: set[str] = field(default_factory=set)

    def check_text(self, path: Path, text: str, skip_entropy: bool = False) -> list[str]:
        findings: list[str] = []
        where = str(path)
        # Occurrences of our own fake project paths must not count as hits for a
        # real project that happens to share a name with them (e.g. "proj").
        text_without_fakes = re.sub(r"\S*" + FAKE_MARK + r"\S*", "", text)
        for fake in self.scrubber.project_map.values():
            enc = encode_path(fake)
            text_without_fakes = text_without_fakes.replace(fake, "").replace(enc, "").replace(enc[1:], "")
        for name, value in find_secrets(text):
            if FAKE_MARK not in value:
                findings.append(f"{where}: secret pattern {name}: {_mask(value)}")
        views = [("", text)]
        if "%2f" in text.lower():
            views.append((" (url-encoded)", unquote(text)))
        for label, view in views:
            if re.search(r"(?i)(?<![A-Za-z0-9])" + re.escape(self.identity.username), view):
                findings.append(f"{where}: username present{label}")
            for host in self.identity.hostnames:
                for variant in {host, host.replace("'", "\u2019")}:
                    if re.search(r"(?i)(?<![A-Za-z0-9])" + re.escape(variant), view):
                        findings.append(f"{where}: hostname present{label}")
                        break
            for real_root in self.scrubber.project_map:
                if real_root in view:
                    findings.append(f"{where}: project path present{label}: {real_root}")
                    continue
                for seg in real_root.split("/")[3:]:
                    if seg in self.public_names:
                        continue
                    if len(seg) >= 4 and re.search(r"(?<![A-Za-z0-9])" + re.escape(seg) + r"(?![A-Za-z0-9])",
                                                   text_without_fakes if not label else view):
                        findings.append(f"{where}: project path name present{label}: {seg}")
        for m in EMAIL_RE.finditer(text):
            if m.group(0) != FAKE_EMAIL:
                findings.append(f"{where}: email present")
                break
        for m in URL_HOST_RE.finditer(text):
            if not host_allowed(m.group(2)):
                findings.append(f"{where}: unknown host in URL: {m.group(2)}")
        for m in DOMAIN_RULE_RE.finditer(text):
            if not host_allowed(m.group(2)):
                findings.append(f"{where}: unknown host in domain rule: {m.group(2)}")
        for m in TILDE_PATH_RE.finditer(text):
            seg = m.group(2)
            if not seg.startswith(".") and seg != "proj":
                findings.append(f"{where}: home-relative path not mapped: {m.group(1)}/{seg}")
        if skip_entropy:
            return findings
        for m in re.finditer(r"[A-Za-z0-9+/_-]{32,}={0,2}", text):
            token = m.group(0)
            if FAKE_MARK in token or UUID_RE.match(token) or HEX_RE.match(token):
                continue
            if _path_like(token) or re.match(r"^-?(Users|private|Volumes|var|tmp)-", token):
                continue
            if re.match(r"^[a-z]{1,6}_[0-9a-f]{20,}$", token):
                continue
            digits_and_dashes = sum(ch.isdigit() or ch == "-" for ch in token)
            if digits_and_dashes / len(token) >= 0.6:
                continue
            if shannon_entropy(token) > 4.0:
                findings.append(f"{where}: high entropy string: {_mask(token)}")
        return findings

    def check_jsonl_record(self, rec: Any) -> list[str]:
        findings: list[str] = []
        self._walk(rec, "", findings)
        return findings

    def _walk(self, value: Any, path: str, findings: list[str]) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                sub = f"{path}.{k}" if path else k
                if k in HARD_FORBIDDEN:
                    findings.append(f"forbidden key {k} at {sub}")
                    continue
                if k in SOFT_FORBIDDEN and isinstance(v, str) and v != "" and v not in ALLOWED_ENUMS.get(k, ()):
                    findings.append(f"non-empty {k} at {sub}")
                    continue
                if isinstance(k, str) and key_needs_placeholder(k) and not k.startswith("key_"):
                    findings.append(f"path-like key at {sub}")
                self._walk(v, sub, findings)
        elif isinstance(value, list):
            for i, v in enumerate(value):
                self._walk(v, f"{path}[{i}]", findings)
        elif isinstance(value, str) and len(value) > MAX_TRANSCRIPT_STRING:
            findings.append(f"long string at {path} ({len(value)} chars)")

    def check_json_config(self, path: Path, obj: Any) -> list[str]:
        """Structural checks for config files: identifiers and secret-like args."""
        findings: list[str] = []
        self._walk_config(obj, "", False, findings, str(path))
        return findings

    def _walk_config(self, value: Any, path: str, in_args: bool, findings: list[str], where: str) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                sub = f"{path}.{k}" if path else str(k)
                ctx = in_args or (isinstance(k, str) and k in ARG_CONTEXT_KEYS)
                if isinstance(v, str):
                    self._check_config_string(str(k), v, sub, ctx, findings, where)
                else:
                    self._walk_config(v, sub, ctx, findings, where)
        elif isinstance(value, list):
            for i, v in enumerate(value):
                if isinstance(v, str):
                    self._check_config_string("", v, f"{path}[{i}]", in_args, findings, where)
                else:
                    self._walk_config(v, f"{path}[{i}]", in_args, findings, where)

    def _check_config_string(self, key: str, value: str, sub: str, in_args: bool,
                             findings: list[str], where: str) -> None:
        lowered = key.lower()
        if UUID_RE.match(value) and value != FAKE_UUID and lowered not in SAFE_ID_KEYS:
            findings.append(f"{where}: uuid under non-id key at {sub}")
        if HEX_RE.match(value) and len(value) >= 32 and set(value) != {"0"} and lowered not in SAFE_HASH_KEYS \
                and lowered not in SAFE_ID_KEYS:
            findings.append(f"{where}: hex blob under {sub}")
        if in_args:
            for token in re.split(r"[\s\"'`=]+", value):
                token = token.strip("'\"`,;:()[]{}")
                if len(token) < 20 or FAKE_MARK in token or contains_reference(token) or _path_like(token):
                    continue
                if HEX_RE.match(token) and len(token) >= 32 and set(token) != {"0"}:
                    findings.append(f"{where}: hex blob in {sub}")
                    continue
                if re.fullmatch(r"[A-Za-z0-9._@/+-]+", token) and shannon_entropy(token) >= 3.5 \
                        and not re.fullmatch(r"[A-Za-z0-9.@/-]*\d+(\.\d+)+[A-Za-z0-9.-]*", token) \
                        and not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}(/.*)?", token):
                    findings.append(f"{where}: secret-like token in {sub}: {_mask(token)}")

    def verify_tree(self, root: Path) -> list[str]:
        findings: list[str] = []
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(root)
            findings.extend(self.check_text(Path("name:") / rel, str(rel), skip_entropy=True))
            try:
                text = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                findings.append(f"{rel}: not UTF-8 text")
                continue
            findings.extend(self.check_text(rel, text))
            if p.suffix == ".jsonl":
                for n, line in enumerate(text.splitlines(), 1):
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except (ValueError, RecursionError):
                        findings.append(f"{rel}:{n}: invalid JSON")
                        continue
                    findings.extend(f"{rel}:{n}: {f}" for f in self.check_jsonl_record(rec))
                    findings.extend(f"{n}: {f}" for f in self.check_json_config(rel, rec))
            elif p.suffix == ".json":
                try:
                    obj = json.loads(text)
                except (ValueError, RecursionError):
                    continue  # JSONC files such as argv.json are checked as text only
                findings.extend(self.check_json_config(rel, obj))
        return findings


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #

@dataclass
class Job:
    agent: str
    src: Path | None
    dst_rel: str
    note: str
    run: Callable[[Path], None]


@dataclass
class Collector:
    home: Path
    date: str
    scrubber: Scrubber
    staging: Path
    max_records: int = 150
    max_projects: int = 5
    max_rules: int = 15
    max_transcripts: int = 4
    quiet: bool = False
    jobs: list[Job] = field(default_factory=list)
    written: list[tuple[str, int]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # -- helpers -------------------------------------------------------------- #

    def _warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def _safe_iterdir(self, d: Path) -> list[Path]:
        try:
            return sorted(d.iterdir())
        except OSError as err:
            self._warn(f"{d}: {err}")
            return []

    def _safe_glob(self, d: Path, pattern: str) -> list[Path]:
        try:
            return sorted(d.glob(pattern))
        except OSError as err:
            self._warn(f"{d}: {err}")
            return []

    def _is_file(self, p: Path) -> bool:
        try:
            return p.is_file() and not p.is_symlink()
        except OSError as err:
            self._warn(f"{p}: {err}")
            return False

    def _is_dir(self, p: Path) -> bool:
        try:
            return p.is_dir() and not p.is_symlink()
        except OSError as err:
            self._warn(f"{p}: {err}")
            return False

    def _mtime(self, p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError as err:
            self._warn(f"{p}: {err}")
            return 0.0

    def _size(self, p: Path) -> int:
        try:
            return p.stat().st_size
        except OSError as err:
            self._warn(f"{p}: {err}")
            return 0

    def _version_or_date(self, v: Any) -> str:
        if is_safe_version(v):
            return v
        if v is not None:
            self._warn(f"unsafe version string {str(v)[:40]!r}; using the date instead")
        return self.date

    def _write(self, dst_rel: str, text: str) -> None:
        dst = (self.staging / dst_rel)
        resolved_staging = self.staging.resolve()
        if not dst.resolve().is_relative_to(resolved_staging):
            raise ValueError(f"refusing to write outside staging: {dst_rel}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = text.encode("utf-8", "replace").decode("utf-8")
        dst.write_text(text, encoding="utf-8")
        self.written.append((dst_rel, len(text.encode("utf-8"))))

    def _write_json(self, dst_rel: str, obj: Any) -> None:
        self._write(dst_rel, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")

    def _read_json(self, path: Path) -> Any | None:
        try:
            with open_allowed(path) as fh:
                return json.load(fh)
        except (OSError, ValueError, RecursionError) as err:
            self._warn(f"{path}: {err}")
            return None

    def _read_text(self, path: Path) -> str | None:
        try:
            with open_allowed(path) as fh:
                return fh.read()
        except OSError as err:
            self._warn(f"{path}: {err}")
            return None

    def _first_record(self, path: Path, limit: int = 50) -> dict | None:
        """First JSON object in a .jsonl file that has a `type` (or any object)."""
        try:
            with open_allowed(path) as fh:
                for _ in range(limit):
                    line = fh.readline()
                    if not line:
                        break
                    try:
                        rec = json.loads(line)
                    except (ValueError, RecursionError):
                        continue
                    if isinstance(rec, dict):
                        return rec
        except OSError as err:
            self._warn(f"{path}: {err}")
        return None

    def _claude_meta(self, path: Path) -> tuple[str | None, str | None]:
        """(version, cwd) from the first records of a Claude transcript."""
        version = cwd = None
        try:
            with open_allowed(path) as fh:
                for _ in range(50):
                    line = fh.readline()
                    if not line:
                        break
                    try:
                        rec = json.loads(line)
                    except (ValueError, RecursionError):
                        continue
                    if not isinstance(rec, dict):
                        continue
                    version = version or (rec.get("version") if isinstance(rec.get("version"), str) else None)
                    cwd = cwd or (rec.get("cwd") if isinstance(rec.get("cwd"), str) else None)
                    if version and cwd:
                        break
        except OSError as err:
            self._warn(f"{path}: {err}")
        return version, cwd

    def _add(self, agent: str, src: Path | None, dst_rel: str, note: str, run: Callable[[Path], None]) -> None:
        if src is not None and (is_denied(src) or src.is_symlink()):
            self._warn(f"skipped denylisted or symlinked source: {src}")
            return
        self.jobs.append(Job(agent, src, dst_rel, note, run))

    @staticmethod
    def _spread(items: list, limit: int) -> list:
        if len(items) <= limit:
            return items
        if limit <= 1:
            return items[:1]
        idx = sorted({round(i * (len(items) - 1) / (limit - 1)) for i in range(limit)})
        return [items[i] for i in idx]

    # -- planning ------------------------------------------------------------- #

    def plan(self) -> None:
        self._preregister()
        self._plan_claude()
        self._plan_codex()
        self._plan_cursor()
        self._plan_copilot()
        self._plan_shared()

    def _preregister(self) -> None:
        """Register marketplaces and project roots from structured sources first,
        so numbering is stable and free-text scrubbing sees them."""
        cdir = self.home / ".claude"
        names: set[str] = set()
        km = cdir / "plugins" / "known_marketplaces.json"
        if self._is_file(km):
            obj = self._read_json(km)
            if isinstance(obj, dict):
                names.update(k for k in obj if isinstance(k, str))
        settings = self._read_json(cdir / "settings.json") if self._is_file(cdir / "settings.json") else None
        if isinstance(settings, dict):
            extra = settings.get("extraKnownMarketplaces")
            if isinstance(extra, dict):
                names.update(k for k in extra if isinstance(k, str))
            enabled = settings.get("enabledPlugins")
            if isinstance(enabled, dict):
                names.update(k.split("@", 1)[1] for k in enabled if isinstance(k, str) and "@" in k)
        for name in sorted(names):
            self.scrubber.register_marketplace(name)
        roots: set[str] = set()
        config = self.home / ".codex" / "config.toml"
        if self._is_file(config):
            text = self._read_text(config) or ""
            roots.update(re.findall(r'^\s*\[projects\."([^"]+)"\]', text, flags=re.M))
        for marker in self._safe_glob(self.home / ".cursor" / "projects", "*/.workspace-trusted"):
            obj = self._read_json(marker) if self._is_file(marker) else None
            if isinstance(obj, dict) and isinstance(obj.get("workspacePath"), str):
                roots.add(obj["workspacePath"])
        for root in sorted(roots):
            self.scrubber.scrub_string(root)

    # Claude Code ------------------------------------------------------------ #

    def _plan_claude(self) -> None:
        home = self.home
        cdir = home / ".claude"
        transcripts = self._pick_claude_transcripts(cdir / "projects")
        versions = sorted({v for v, _p, _c, _r in transcripts if v}, key=version_key)
        current = versions[-1] if versions else self.date
        base = f"claude/{current}"

        settings = cdir / "settings.json"
        if self._is_file(settings):
            self._add("claude", settings, f"{base}/settings.json", "scrub, cap permission lists",
                      lambda p, d=f"{base}/settings.json": self._do_settings(p, d))
        local = cdir / "settings.local.json"
        if self._is_file(local):
            self._add("claude", local, f"{base}/settings.local.json", "scrub",
                      lambda p, d=f"{base}/settings.local.json": self._do_scrub_json(p, d))
        state = home / ".claude.json"
        if self._is_file(state):
            self._add("claude", state, f"{base}/claude.json", "whitelist keys, fake account",
                      lambda p, d=f"{base}/claude.json": self._do_claude_json(p, d))
        for name in ("installed_plugins.json", "known_marketplaces.json", "config.json"):
            p = cdir / "plugins" / name
            if self._is_file(p):
                self._add("claude", p, f"{base}/plugins/{name}", "scrub",
                          lambda pp, d=f"{base}/plugins/{name}": self._do_scrub_json(pp, d))
        for manifest in self._pick_plugin_manifests(cdir / "plugins" / "cache" / "claude-plugins-official"):
            rel = manifest.relative_to(cdir / "plugins")
            self._add("claude", manifest, f"{base}/plugins/{rel}", "scrub (official marketplace)",
                      lambda pp, d=f"{base}/plugins/{rel}": self._do_scrub_json(pp, d))
        sessions = cdir / "sessions"
        locks = [p for p in self._safe_glob(sessions, "*.json") if self._is_file(p)] if self._is_dir(sessions) else []
        if locks:
            lock = max(locks, key=self._mtime)
            self._add("claude", lock, f"{base}/sessions/{lock.name}", "scrub, blank name",
                      lambda p, d=f"{base}/sessions/{lock.name}": self._do_session_lock(p, d))
        for version, path, cwd, rel in transcripts:
            v = self._version_or_date(version) if version else current
            if cwd:
                dirname = encode_path(self.scrubber.scrub_string(cwd))
            else:
                dirname = self.scrubber.scrub_string(path.parent.name)
            dst = f"claude/{v}/projects/{dirname}/{rel}"
            note = f"skeletonize {'subagent ' if 'subagents' in rel.split('/') else ''}transcript (v{v})"
            self._add("claude", path, dst, note, lambda p, d=dst: self._do_claude_transcript(p, d))

    def _pick_claude_transcripts(self, projects: Path) -> list[tuple[str | None, Path, str | None, str]]:
        """Returns (version, path, cwd, path relative to its project dir)."""
        if not self._is_dir(projects):
            return []
        by_version: dict[str, tuple[float, Path, str | None, str]] = {}
        sub_candidates: list[tuple[float, Path, str]] = []
        for pdir in self._safe_iterdir(projects):
            if not self._is_dir(pdir) or is_denied(pdir / "x"):
                continue
            for f in self._safe_glob(pdir, "*.jsonl"):
                if is_denied(f) or not self._is_file(f):
                    continue
                version, cwd = self._claude_meta(f)
                if not version:
                    continue
                mtime = self._mtime(f)
                if version not in by_version or by_version[version][0] < mtime:
                    by_version[version] = (mtime, f, cwd, f.name)
            for f in self._safe_glob(pdir, "*/subagents/**/*.jsonl"):
                if self._is_file(f) and not is_denied(f):
                    sub_candidates.append((self._mtime(f), f, str(f.relative_to(pdir))))
        versions = sorted(by_version, key=version_key)
        chosen = [(v, by_version[v][1], by_version[v][2], by_version[v][3])
                  for v in self._spread(versions, self.max_transcripts)]
        if sub_candidates:
            _m, newest, rel = max(sub_candidates, key=lambda t: t[0])
            version, cwd = self._claude_meta(newest)
            chosen.append((version, newest, cwd, rel))
        for cwd in sorted({c for _v, _p, c, _r in chosen if c}):
            self.scrubber.scrub_string(cwd)
        return chosen

    def _pick_plugin_manifests(self, cache: Path, limit: int = 3) -> list[Path]:
        if not self._is_dir(cache):
            return []
        picked: list[Path] = []
        plugins_done = 0
        for plugin in self._safe_iterdir(cache):
            if not self._is_dir(plugin):
                continue
            versions = [v for v in self._safe_iterdir(plugin) if self._is_dir(v)]
            if not versions:
                continue
            vdir = max(versions, key=self._mtime)
            files = [vdir / ".claude-plugin" / "plugin.json", vdir / "hooks" / "hooks.json", vdir / ".mcp.json"]
            present = [f for f in files if self._is_file(f)]
            if len(present) >= 2:
                picked.extend(present)
                plugins_done += 1
                if plugins_done >= limit:
                    break
        return picked

    def _do_settings(self, src: Path, dst: str) -> None:
        obj = self._read_json(src)
        if isinstance(obj, dict):
            self._write_json(dst, cap_permission_lists(self.scrubber.scrub_json(obj), self.max_rules))

    def _do_scrub_json(self, src: Path, dst: str) -> None:
        obj = self._read_json(src)
        if obj is not None:
            self._write_json(dst, self.scrubber.scrub_json(obj))

    def _do_claude_json(self, src: Path, dst: str) -> None:
        obj = self._read_json(src)
        if isinstance(obj, dict):
            self._write_json(dst, reduce_claude_json(obj, self.scrubber, self.max_projects))

    def _do_session_lock(self, src: Path, dst: str) -> None:
        obj = self._read_json(src)
        if isinstance(obj, dict):
            if isinstance(obj.get("cwd"), str):
                self.scrubber.scrub_string(obj["cwd"])  # register before other keys see it
            if isinstance(obj.get("name"), str):
                obj["name"] = ""
            self._write_json(dst, self.scrubber.scrub_json(obj))

    def _do_claude_transcript(self, src: Path, dst: str) -> None:
        self._do_transcript(src, dst, skeletonize_claude_record, ("assistant", "user", "system"))

    def _do_transcript(self, src: Path, dst: str, skeleton: Callable, main_types: tuple[str, ...]) -> None:
        kept: list[str] = []
        seen_side: set[str] = set()
        main_count = 0
        try:
            with open_allowed(src) as fh:
                for line in fh:
                    if main_count >= self.max_records:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (ValueError, RecursionError):
                        self._warn(f"{src}: skipped a malformed line")
                        continue
                    out = skeleton(rec, self.scrubber)
                    if out is None:
                        continue
                    rtype = str(out.get("type"))
                    payload = out.get("payload")
                    ptype = str(payload.get("type")) if isinstance(payload, dict) and payload.get("type") else ""
                    kind = f"{rtype}/{ptype}" if ptype else rtype
                    if rtype in main_types:
                        main_count += 1
                    elif kind in seen_side:
                        continue
                    else:
                        seen_side.add(kind)
                    kept.append(json.dumps(out, ensure_ascii=False, separators=(",", ":")))
        except OSError as err:
            self._warn(f"{src}: {err}")
            return
        if kept:
            self._write(dst, "\n".join(kept) + "\n")

    # Codex -------------------------------------------------------------------- #

    def _plan_codex(self) -> None:
        cdir = self.home / ".codex"
        if not self._is_dir(cdir):
            return
        rollouts = self._pick_codex_rollouts(cdir / "sessions")
        versions = sorted({v for v, _p in rollouts if v}, key=version_key)
        current = self._version_or_date(versions[-1]) if versions else self.date
        base = f"codex/{current}"
        config = cdir / "config.toml"
        if self._is_file(config):
            self._add("codex", config, f"{base}/config.toml", "redact TOML (paths, secret values)",
                      lambda p, d=f"{base}/config.toml": self._do_toml(p, d))
        p = cdir / "version.json"
        if self._is_file(p):
            self._add("codex", p, f"{base}/version.json", "scrub",
                      lambda pp, d=f"{base}/version.json": self._do_scrub_json(pp, d))
        for name in ("config.json", "update-check.json"):
            p = cdir / name
            if self._is_file(p):
                self._add("codex", p, f"{base}/legacy/{name}", "scrub (TypeScript-era file)",
                          lambda pp, d=f"{base}/legacy/{name}": self._do_scrub_json(pp, d))
        jwt = fake_same_shape("eyJ" + "x" * 40 + "." + "y" * 60 + "." + "z" * 43)
        tokens = {"id_token": jwt, "access_token": jwt, "refresh_token": fill_fake(48), "account_id": FAKE_UUID}
        self._add("codex", None, f"{base}/auth.chatgpt.json", "synthesized stand-in, key names only",
                  lambda _p, d=f"{base}/auth.chatgpt.json": self._write_json(d, {
                      "OPENAI_API_KEY": None, "tokens": tokens, "last_refresh": FAKE_DATE}))
        self._add("codex", None, f"{base}/auth.api-key.json", "synthesized stand-in, key names only",
                  lambda _p, d=f"{base}/auth.api-key.json": self._write_json(d, {
                      "OPENAI_API_KEY": fake_same_shape("sk-proj-" + "x" * 48)}))
        self._add("codex", None, f"{base}/auth.current.json", "synthesized stand-in (auth_mode key, current main)",
                  lambda _p, d=f"{base}/auth.current.json": self._write_json(d, {
                      "auth_mode": "chatgpt", "OPENAI_API_KEY": None, "tokens": tokens, "last_refresh": FAKE_DATE}))
        for version, path in rollouts:
            v = self._version_or_date(version) if version else current
            rel = path.relative_to(cdir / "sessions")
            dst = f"codex/{v}/sessions/{rel}"
            self._add("codex", path, dst, f"skeletonize rollout (v{v})",
                      lambda p, d=dst: self._do_transcript(p, d, skeletonize_codex_record,
                                                           ("event_msg", "turn_context")))

    def _pick_codex_rollouts(self, sessions: Path) -> list[tuple[str | None, Path]]:
        if not self._is_dir(sessions):
            return []
        by_version: dict[str, tuple[int, Path]] = {}
        tiny: tuple[float, Path] | None = None
        cwds: set[str] = set()
        for f in self._safe_glob(sessions, "**/rollout-*.jsonl"):
            if is_denied(f) or not self._is_file(f):
                continue
            first = self._first_record(f, limit=3)
            payload = first.get("payload") if isinstance(first, dict) else None
            if not isinstance(payload, dict):
                continue
            version = payload.get("cli_version") if is_safe_version(payload.get("cli_version")) else None
            if isinstance(payload.get("cwd"), str):
                cwds.add(payload["cwd"])
            size = self._size(f)
            # Prefer the largest rollout per version: it has the most token_count
            # events. Tiny no-turn sessions are picked separately below.
            if version and (version not in by_version or by_version[version][0] < size):
                by_version[version] = (size, f)
            if size < 100_000:
                try:
                    with open_allowed(f) as fh:
                        n = sum(1 for _ in fh)
                except OSError:
                    n = 999
                mtime = self._mtime(f)
                if n <= 3 and (tiny is None or tiny[0] < mtime):
                    tiny = (mtime, f)
        versions = sorted(by_version, key=version_key)
        chosen = [(v, by_version[v][1]) for v in self._spread(versions, self.max_transcripts)]
        if tiny and all(p != tiny[1] for _v, p in chosen):
            first = self._first_record(tiny[1], limit=3)
            v = first.get("payload", {}).get("cli_version") if isinstance(first, dict) else None
            chosen.append((v if is_safe_version(v) else None, tiny[1]))
        for cwd in sorted(cwds):
            self.scrubber.scrub_string(cwd)
        return chosen

    def _do_toml(self, src: Path, dst: str) -> None:
        text = self._read_text(src)
        if text is not None:
            self._write(dst, redact_toml(text, self.scrubber))

    # Cursor ------------------------------------------------------------------- #

    def _plan_cursor(self) -> None:
        cdir = self.home / ".cursor"
        if not self._is_dir(cdir):
            return
        base = f"cursor/{self.date}"
        for name in ("mcp.json", "hooks.json", "cli-config.json", "cli.json"):
            p = cdir / name
            if self._is_file(p):
                self._add("cursor", p, f"{base}/{name}", "scrub",
                          lambda pp, d=f"{base}/{name}": self._do_scrub_json(pp, d))
        argv = cdir / "argv.json"
        if self._is_file(argv):
            self._add("cursor", argv, f"{base}/argv.json", "redact JSONC, fake crash-reporter id",
                      lambda p, d=f"{base}/argv.json": self._do_jsonc(p, d))
        projects = cdir / "projects"
        if self._is_dir(projects):
            markers = [p for p in self._safe_glob(projects, "*/.workspace-trusted") if self._is_file(p)]
            for marker in markers[:self.max_projects]:
                slug = self.scrubber.scrub_string(marker.parent.name)
                dst = f"{base}/projects/{slug}/.workspace-trusted"
                self._add("cursor", marker, dst, "scrub trust marker",
                          lambda p, d=dst: self._do_scrub_json(p, d))

    def _do_jsonc(self, src: Path, dst: str) -> None:
        text = self._read_text(src)
        if text is not None:
            self._write(dst, redact_jsonc(text, self.scrubber))

    # Copilot ------------------------------------------------------------------ #

    def _plan_copilot(self) -> None:
        base = f"copilot/{self.date}"
        cdir = self.home / ".copilot"
        if self._is_dir(cdir):
            for name in ("settings.json", "permissions-config.json", "mcp-config.json", "providers.json"):
                p = cdir / name
                if self._is_file(p):
                    self._add("copilot", p, f"{base}/{name}", "scrub",
                              lambda pp, d=f"{base}/{name}": self._do_scrub_json(pp, d))
            states = cdir / "session-state"
            if self._is_dir(states):
                events = [p for p in self._safe_glob(states, "*/events.jsonl") if self._is_file(p)]
                if events:
                    newest = max(events, key=self._mtime)
                    dst = f"{base}/session-state/{self.scrubber.scrub_string(newest.parent.name)}/events.jsonl"
                    self._add("copilot", newest, dst, "generic skeleton (unknown format)",
                              lambda p, d=dst: self._do_transcript(p, d, skeletonize_generic_record, ()))
        vscode = self.home / "Library" / "Application Support" / "Code" / "User"
        settings = vscode / "settings.json"
        if self._is_file(settings):
            self._add("copilot", settings, f"{base}/vscode-user-settings.json",
                      "keep chat./github.copilot/security.workspace/mcp/terminal env keys only",
                      lambda p, d=f"{base}/vscode-user-settings.json": self._do_vscode(p, d))
        mcp = vscode / "mcp.json"
        if self._is_file(mcp):
            self._add("copilot", mcp, f"{base}/vscode-user-mcp.json", "scrub",
                      lambda p, d=f"{base}/vscode-user-mcp.json": self._do_scrub_json(p, d))

    def _do_vscode(self, src: Path, dst: str) -> None:
        obj = self._read_json(src)
        if isinstance(obj, dict):
            self._write_json(dst, reduce_vscode_settings(obj, self.scrubber))

    # Shared ------------------------------------------------------------------- #

    def _plan_shared(self) -> None:
        base = f"shared/{self.date}"
        for name in (".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile"):
            p = self.home / name
            if self._is_file(p):
                self._add("shared", p, f"{base}/{name}", "export lines only, fake values",
                          lambda pp, d=f"{base}/{name}": self._do_shell(pp, d))

    def _do_shell(self, src: Path, dst: str) -> None:
        text = self._read_text(src)
        if text is None:
            return
        out = extract_shell_exports(text, self.scrubber)
        if out.count("\n") > 2:
            self._write(dst, out)

    # -- execution -------------------------------------------------------------- #

    def run(self) -> None:
        for job in self.jobs:
            if job.src is not None and (is_denied(job.src) or job.src.is_symlink()):
                self._warn(f"skipped denylisted or symlinked source: {job.src}")
                continue
            try:
                job.run(job.src if job.src is not None else Path("/nonexistent"))
            except Exception as err:  # noqa: BLE001 - one bad file must not stop the run
                self._warn(f"{job.dst_rel}: {type(err).__name__}: {err}")


# --------------------------------------------------------------------------- #
# Reporting and CLI
# --------------------------------------------------------------------------- #

def manifest_paths(home: Path) -> list[Path]:
    """Config files whose mtimes matter for the churn spike (existing files only)."""
    rels = [
        ".claude.json", ".claude/settings.json", ".claude/settings.local.json", ".claude/history.jsonl",
        ".claude/stats-cache.json", ".claude/plugins/installed_plugins.json", ".claude/plugins/known_marketplaces.json",
        ".codex/config.toml", ".codex/auth.json", ".codex/history.jsonl", ".codex/version.json", ".codex/hooks.json",
        ".cursor/mcp.json", ".cursor/hooks.json", ".cursor/cli-config.json", ".cursor/argv.json",
        ".copilot/settings.json", ".copilot/permissions-config.json", ".copilot/config.json", ".copilot/mcp-config.json",
        "Library/Application Support/Code/User/settings.json", "Library/Application Support/Code/User/mcp.json",
        "Library/Application Support/Cursor/User/settings.json",
        "Library/Application Support/Cursor/User/globalStorage/state.vscdb",
    ]
    return [home / r for r in rels if (home / r).exists()]


def churn_snapshot(home: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"taken_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"), "files": {}}
    for p in manifest_paths(home):
        st = p.stat()
        out["files"][str(p.relative_to(home))] = {
            "mtime": _dt.datetime.fromtimestamp(st.st_mtime, _dt.timezone.utc).isoformat(timespec="seconds"),
            "size": st.st_size, "mode": oct(st.st_mode & 0o777)}
    for rel in (".claude/backups", ".claude/sessions", ".claude/shell-snapshots", ".codex/sessions",
                ".claude/projects", ".copilot/session-state"):
        d = home / rel
        if d.is_dir():
            files = [f for f in d.rglob("*") if f.is_file()]
            newest = max((f.stat().st_mtime for f in files), default=None)
            out["files"][rel + "/"] = {
                "count": len(files),
                "newest": _dt.datetime.fromtimestamp(newest, _dt.timezone.utc).isoformat(timespec="seconds") if newest else None}
    return out


def print_plan(collector: Collector) -> None:
    print(f"home:    {collector.home}")
    print(f"staging: {collector.staging}")
    print(f"{len(collector.jobs)} files would be produced:\n")
    width = max((len(j.dst_rel) for j in collector.jobs), default=10)
    for j in collector.jobs:
        src = str(j.src).replace(str(collector.home), "~") if j.src else "(synthesized)"
        size = f"{j.src.stat().st_size:>10,} B" if j.src and j.src.exists() else f"{'-':>12}"
        print(f"  {j.agent:<8} {j.dst_rel:<{width}}  {size}  <- {src}  [{j.note}]")
    if collector.warnings:
        print("\nwarnings:")
        for w in collector.warnings:
            print(f"  {w}")


def print_report(collector: Collector, out_dir: Path) -> None:
    total = sum(n for _p, n in collector.written)
    print(f"\nwrote {len(collector.written)} files, {total:,} bytes, into {out_dir}")
    for rel, n in collector.written:
        print(f"  {n:>9,} B  {rel}")
    c = collector.scrubber.counters
    print("\nredactions: "
          f"{c['secrets']} secret values, {c['paths']} project paths, {c['identities']} identifiers, "
          f"{c['emails']} e-mail addresses, {c['remotes']} git remotes, {c['urlhosts']} URL hosts, "
          f"{c['hosts']} host names")
    if collector.scrubber.project_map:
        print("\nproject mapping (terminal only, not written anywhere):")
        for real, fake in collector.scrubber.project_map.items():
            print(f"  {fake:<24} <- {real}")
    if collector.scrubber.marketplace_map:
        print("\nmarketplace mapping (terminal only):")
        for real, fake in collector.scrubber.marketplace_map.items():
            print(f"  {fake:<24} <- {real}")
    if collector.warnings:
        print("\nwarnings:")
        for w in collector.warnings:
            print(f"  {w}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Copy and redact agent files into fixtures/.")
    ap.add_argument("command", nargs="?", choices=["plan", "write", "churn"], default="plan")
    ap.add_argument("--home", type=Path, default=Path.home(), help="home directory to read (default: yours)")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "fixtures",
                    help="fixtures directory to copy into after verification")
    ap.add_argument("--staging", type=Path, default=None, help="staging directory (default: a new temp dir)")
    ap.add_argument("--date", default=_dt.date.today().isoformat(), help="ISO date used for date-versioned folders")
    ap.add_argument("--hostname", default=None, help="extra host name to scrub (detected names are always used)")
    ap.add_argument("--max-records", type=int, default=150)
    ap.add_argument("--max-projects", type=int, default=5)
    ap.add_argument("--max-rules", type=int, default=15)
    ap.add_argument("--max-transcripts", type=int, default=4)
    ap.add_argument("--keep-staging", action="store_true", help="do not delete the staging dir after a clean copy")
    ap.add_argument("--public-name", action="append", default=[], metavar="NAME",
                    help="a project name that is public and may stay in fixtures (repeatable)")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--inject-verifier-failure", action="store_true", help=argparse.SUPPRESS)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = args.home.expanduser().resolve()
    if not home.is_dir():
        print(f"error: home {home} is not a directory", file=sys.stderr)
        return 2
    identity = Identity.detect(home, args.hostname)
    scrubber = Scrubber(identity)

    if args.command == "churn":
        print(json.dumps(churn_snapshot(home), indent=2))
        return 0

    auto_staging = args.staging is None
    staging = args.staging if args.staging else Path(tempfile.mkdtemp(prefix="vigildex-fixtures-"))
    staging.mkdir(parents=True, exist_ok=True)
    collector = Collector(home=home, date=args.date, scrubber=scrubber, staging=staging,
                          max_records=args.max_records, max_projects=args.max_projects,
                          max_rules=args.max_rules, max_transcripts=args.max_transcripts, quiet=args.quiet)
    collector.plan()

    if args.command == "plan":
        if not args.quiet:
            print_plan(collector)
        if auto_staging:
            shutil.rmtree(staging, ignore_errors=True)
        return 0

    try:
        collector.run()
        if args.inject_verifier_failure:
            (staging / "injected.txt").write_text("ghp_" + "Zq9" * 12 + "\n")
        verifier = Verifier(identity, scrubber, set(args.public_name))
        findings = verifier.verify_tree(staging)
    except Exception:
        print(f"error during staging; unverified staging kept at {staging}", file=sys.stderr)
        raise
    if findings:
        print(f"verification FAILED with {len(findings)} finding(s); nothing copied. Staging kept at {staging}",
              file=sys.stderr)
        for f in findings[:200]:
            print(f"  {f}", file=sys.stderr)
        if len(findings) > 200:
            print(f"  … and {len(findings) - 200} more", file=sys.stderr)
        return 1

    out_dir = args.out.resolve()
    staging_resolved = staging.resolve()
    for rel, _n in collector.written:
        dst = out_dir / rel
        if not dst.resolve().is_relative_to(out_dir):
            print(f"error: refusing to copy outside {out_dir}: {rel}", file=sys.stderr)
            return 1
        if dst.exists() and not dst.is_file():
            print(f"error: destination exists and is not a regular file: {dst}; nothing copied", file=sys.stderr)
            return 1
        if not (staging_resolved / rel).is_file():
            print(f"error: staged file missing: {rel}; nothing copied", file=sys.stderr)
            return 1
    for rel, _n in collector.written:
        dst = out_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(staging / rel, dst)
    if not args.quiet:
        print_report(collector, out_dir)
    if not args.keep_staging and auto_staging:
        shutil.rmtree(staging, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
