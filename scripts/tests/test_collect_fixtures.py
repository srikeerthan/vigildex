"""Tests for scripts/collect-fixtures.py.

Everything here runs on synthetic data under a temporary directory. The
tests never read the developer's real home.

Run with:  python3 -I -m unittest discover -s scripts/tests -v
"""

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "collect-fixtures.py"


def load_module():
    spec = importlib.util.spec_from_file_location("collect_fixtures", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["collect_fixtures"] = module
    spec.loader.exec_module(module)
    return module


cf = load_module()

HOME = Path("/Users/jdoe")


def fake_slack_webhook() -> str:
    """A synthetic webhook URL, assembled at runtime so the raw test file never
    contains the full shape that GitHub push protection scans for."""
    return "/".join(["https://hooks.slack.com/services", "T0ABCDEFG", "B0HIJKLMN", "aBcDeFgHiJkLmNoPqRsTuVwX"])


def identity(home=HOME):
    return cf.Identity(home=home, username="jdoe", hostname="jdoes-mbp")


def scrubber(home=HOME):
    return cf.Scrubber(identity(home))


class FakeSameShapeTests(unittest.TestCase):
    def test_keeps_length_and_known_prefix(self):
        real = "sk-ant-api03-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6"
        fake = cf.fake_same_shape(real)
        self.assertEqual(len(fake), len(real))
        self.assertTrue(fake.startswith("sk-ant-api03-"))
        self.assertIn("FAKE", fake)
        self.assertNotIn("a1B2c3D4", fake)

    def test_github_token_keeps_prefix(self):
        real = "ghp_" + "x" * 36
        fake = cf.fake_same_shape(real)
        self.assertEqual(len(fake), 40)
        self.assertTrue(fake.startswith("ghp_FAKE"))

    def test_jwt_keeps_three_segments_and_lengths(self):
        real = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        fake = cf.fake_same_shape(real)
        self.assertEqual(fake.count("."), 2)
        self.assertEqual([len(p) for p in fake.split(".")], [len(p) for p in real.split(".")])
        self.assertTrue(fake.startswith("eyJ"))
        self.assertIn("FAKE", fake)

    def test_unknown_shape_is_all_fake_of_same_length(self):
        fake = cf.fake_same_shape("hunter2hunter2")
        self.assertEqual(len(fake), 14)
        self.assertEqual(fake, "FAKEFAKEFAKEFA")


class SecretKeyNameTests(unittest.TestCase):
    def test_recognises_secret_key_names(self):
        for name in ["OPENAI_API_KEY", "apiKey", "GITHUB_PERSONAL_ACCESS_TOKEN", "password",
                     "Authorization", "client_secret", "refresh_token", "cookie", "private_key"]:
            self.assertTrue(cf.looks_like_secret_key(name), name)

    def test_ignores_names_that_point_at_secrets_instead_of_holding_them(self):
        for name in ["bearer_token_env_var", "apiKeyHelper", "token_file", "key_path",
                     "allowedHttpHookUrls", "model", "cwd", "tokens_used"]:
            self.assertFalse(cf.looks_like_secret_key(name), name)

    def test_references_are_recognised(self):
        for value in ["${GITHUB_TOKEN}", "${VAR:-default}", "${env:OPENAI_API_KEY}",
                      "${input:github-token}", "op://vault/item/field", "$HOME/.secret",
                      "${file:/etc/token}"]:
            self.assertTrue(cf.is_reference(value), value)
        self.assertFalse(cf.is_reference("ghp_abcdefghijklmnopqrstuvwxyz0123456789"))


class ScrubStringTests(unittest.TestCase):
    def test_replaces_home_and_username(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("/Users/jdoe/.claude/settings.json"),
                         "/Users/you/.claude/settings.json")
        self.assertEqual(s.scrub_string("owner jdoe:staff"), "owner you:staff")

    def test_replaces_hostname_and_email(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("host jdoes-mbp.local"), "host your-mac.local")
        self.assertEqual(s.scrub_string("mail jane.doe+x@example.org ok"), "mail you@example.com ok")

    def test_maps_project_paths_consistently(self):
        s = scrubber()
        a = s.scrub_string("/Users/jdoe/Development/secret-client")
        b = s.scrub_string("/Users/jdoe/Development/secret-client/src/main.rs")
        c = s.scrub_string("/Users/jdoe/Development/other")
        self.assertEqual(a, "/Users/you/proj/1")
        self.assertEqual(b, "/Users/you/proj/1/src/main.rs")
        self.assertEqual(c, "/Users/you/proj/2")
        self.assertEqual(s.project_map["/Users/jdoe/Development/secret-client"], "/Users/you/proj/1")

    def test_maps_encoded_project_directory_names(self):
        s = scrubber()
        s.scrub_string("/Users/jdoe/Development/secret-client")
        self.assertEqual(s.scrub_string("-Users-jdoe-Development-secret-client"), "-Users-you-proj-1")
        self.assertEqual(s.scrub_string("Users-jdoe-Development-secret-client"), "Users-you-proj-1")

    def test_known_secret_patterns_become_fakes_of_same_length(self):
        s = scrubber()
        real = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        out = s.scrub_string(f"token={real} end")
        self.assertNotIn(real, out)
        self.assertIn("ghp_FAKE", out)
        self.assertEqual(len(out), len(f"token={real} end"))

    def test_preserves_env_references(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("${GITHUB_TOKEN}"), "${GITHUB_TOKEN}")
        self.assertEqual(s.scrub_string("${env:OPENAI_API_KEY}"), "${env:OPENAI_API_KEY}")

    def test_replaces_git_remotes_and_branches(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("git@github.com:acme/secret-repo.git"),
                         "https://github.com/you/example.git")
        self.assertEqual(s.scrub_string("https://github.com/acme/secret-repo.git"),
                         "https://github.com/you/example.git")

    def test_is_idempotent(self):
        s = scrubber()
        once = s.scrub_string("/Users/jdoe/Development/x sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef jane@x.io")
        twice = s.scrub_string(once)
        self.assertEqual(once, twice)


class ScrubJsonTests(unittest.TestCase):
    def test_fakes_values_under_secret_key_names(self):
        s = scrubber()
        out = s.scrub_json({"env": {"GITHUB_TOKEN": "notapatternjustaword", "PATH": "/usr/bin"}})
        self.assertEqual(out["env"]["GITHUB_TOKEN"], "FAKEFAKEFAKEFAKEFAKE")
        self.assertEqual(out["env"]["PATH"], "/usr/bin")

    def test_keeps_references_under_secret_key_names(self):
        s = scrubber()
        out = s.scrub_json({"headers": {"Authorization": "Bearer ${env:TOKEN}"}})
        self.assertEqual(out["headers"]["Authorization"], "Bearer ${env:TOKEN}")

    def test_keeps_env_var_name_keys(self):
        s = scrubber()
        out = s.scrub_json({"bearer_token_env_var": "GITHUB_TOKEN"})
        self.assertEqual(out["bearer_token_env_var"], "GITHUB_TOKEN")

    def test_scrubs_nested_lists_and_keeps_numbers(self):
        s = scrubber()
        out = s.scrub_json({"args": ["--root", "/Users/jdoe/x"], "n": 3, "b": True, "z": None})
        self.assertEqual(out["args"], ["--root", "/Users/you/proj/1"])
        self.assertEqual(out["n"], 3)
        self.assertIs(out["b"], True)
        self.assertIsNone(out["z"])

    def test_fakes_uuid_like_identity_keys(self):
        s = scrubber()
        out = s.scrub_json({"accountUuid": "123e4567-e89b-42d3-a456-426614174000",
                            "sessionId": "123e4567-e89b-42d3-a456-426614174001"})
        self.assertEqual(out["accountUuid"], cf.FAKE_UUID)
        self.assertEqual(out["sessionId"], "123e4567-e89b-42d3-a456-426614174001")


class ClaudeTranscriptSkeletonTests(unittest.TestCase):
    def assistant_record(self):
        return {
            "type": "assistant", "uuid": "u1", "parentUuid": "u0", "sessionId": "s1",
            "timestamp": "2026-10-01T00:00:00Z", "requestId": "req_1", "cwd": "/Users/jdoe/Development/p",
            "version": "2.1.296", "gitBranch": "feature/secret-name", "isSidechain": False,
            "userType": "external", "entrypoint": "cli", "slug": "happy-otter",
            "attributionSkill": "x",
            "message": {
                "id": "msg_1", "model": "claude-opus-5-5", "role": "assistant", "type": "message",
                "stop_reason": "end_turn",
                "content": [{"type": "thinking", "thinking": "SECRET THOUGHTS", "signature": "abc"},
                            {"type": "text", "text": "SECRET ANSWER"},
                            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "rm -rf"}}],
                "usage": {"input_tokens": 1, "output_tokens": 2, "cache_creation_input_tokens": 3,
                          "cache_read_input_tokens": 4,
                          "cache_creation": {"ephemeral_5m_input_tokens": 1, "ephemeral_1h_input_tokens": 2},
                          "output_tokens_details": {"thinking_tokens": 1}, "service_tier": "standard"},
            },
        }

    def test_assistant_keeps_usage_and_drops_content_text(self):
        out = cf.skeletonize_claude_record(self.assistant_record(), scrubber())
        self.assertEqual(out["message"]["usage"]["cache_creation"]["ephemeral_1h_input_tokens"], 2)
        self.assertEqual(out["message"]["content"], [{"type": "thinking"}, {"type": "text"}, {"type": "tool_use"}])
        self.assertEqual(out["message"]["id"], "msg_1")
        self.assertEqual(out["cwd"], "/Users/you/proj/1")
        self.assertEqual(out["gitBranch"], "main")
        self.assertNotIn("slug", out)
        self.assertNotIn("attributionSkill", out)
        self.assertNotIn("SECRET", json.dumps(out))

    def test_user_record_drops_tool_result_and_blanks_string_content(self):
        rec = {"type": "user", "uuid": "u2", "parentUuid": "u1", "sessionId": "s1", "timestamp": "t",
               "cwd": "/Users/jdoe/Development/p", "version": "2.1.296", "isMeta": False,
               "permissionMode": "default",
               "message": {"role": "user", "content": "my secret prompt"},
               "toolUseResult": {"stdout": "SECRET OUTPUT"}}
        out = cf.skeletonize_claude_record(rec, scrubber())
        self.assertEqual(out["message"], {"role": "user", "content": ""})
        self.assertNotIn("toolUseResult", out)
        self.assertEqual(out["permissionMode"], "default")

    def test_side_record_types_keep_only_shape(self):
        rec = {"type": "custom-title", "customTitle": "Fixing the secret thing", "sessionId": "s1"}
        out = cf.skeletonize_claude_record(rec, scrubber())
        self.assertEqual(out, {"type": "custom-title", "customTitle": "", "sessionId": "s1"})

    def test_queue_operation_content_is_blanked(self):
        rec = {"type": "queue-operation", "operation": "enqueue", "content": "secret prompt",
               "sessionId": "s1", "timestamp": "t"}
        out = cf.skeletonize_claude_record(rec, scrubber())
        self.assertEqual(out["content"], "")
        self.assertEqual(out["operation"], "enqueue")

    def test_record_without_type_is_dropped(self):
        self.assertIsNone(cf.skeletonize_claude_record({"display": "prompt"}, scrubber()))


class CodexRolloutSkeletonTests(unittest.TestCase):
    def test_session_meta_blanks_instructions_and_fakes_git(self):
        rec = {"timestamp": "t", "type": "session_meta", "payload": {
            "id": "sid", "timestamp": "t", "cwd": "/Users/jdoe/Development/p", "originator": "codex_cli_rs",
            "cli_version": "0.46.0", "source": "cli", "instructions": "AGENTS.md prose " * 100,
            "git": {"commit_hash": "0123456789abcdef0123456789abcdef01234567", "branch": "wip/secret",
                    "repository_url": "git@github.com:acme/secret.git"}}}
        out = cf.skeletonize_codex_record(rec, scrubber())
        self.assertEqual(out["payload"]["instructions"], "")
        self.assertEqual(out["payload"]["cwd"], "/Users/you/proj/1")
        self.assertEqual(out["payload"]["git"]["branch"], "main")
        self.assertEqual(out["payload"]["git"]["repository_url"], "https://github.com/you/example.git")
        self.assertEqual(out["payload"]["git"]["commit_hash"], cf.FAKE_SHA1)
        self.assertEqual(out["payload"]["cli_version"], "0.46.0")

    def test_token_count_is_kept_whole(self):
        payload = {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 10, "cached_input_tokens": 5,
                   "output_tokens": 3, "reasoning_output_tokens": 1, "total_tokens": 13},
                   "last_token_usage": {"input_tokens": 10, "cached_input_tokens": 5, "output_tokens": 3,
                                        "reasoning_output_tokens": 1, "total_tokens": 13},
                   "model_context_window": 272000},
                   "rate_limits": {"primary": {"used_percent": 9.0, "window_minutes": 299, "resets_in_seconds": 100},
                                   "secondary": {"used_percent": 3.0, "window_minutes": 10079, "resets_in_seconds": 5}}}
        rec = {"timestamp": "t", "type": "event_msg", "payload": payload}
        out = cf.skeletonize_codex_record(rec, scrubber())
        self.assertEqual(out["payload"], payload)

    def test_prose_events_are_blanked_not_dropped(self):
        rec = {"timestamp": "t", "type": "event_msg", "payload": {"type": "agent_message", "message": "secret"}}
        out = cf.skeletonize_codex_record(rec, scrubber())
        self.assertEqual(out["payload"], {"type": "agent_message", "message": ""})

    def test_response_items_are_blanked(self):
        rec = {"timestamp": "t", "type": "response_item", "payload": {
            "type": "function_call", "name": "shell", "call_id": "c1", "arguments": "{\"cmd\":\"cat ~/.ssh/id_rsa\"}"}}
        out = cf.skeletonize_codex_record(rec, scrubber())
        self.assertEqual(out["payload"], {"type": "function_call", "name": "shell", "call_id": "c1", "arguments": ""})
        rec2 = {"timestamp": "t", "type": "response_item", "payload": {
            "type": "message", "role": "user", "content": [{"type": "input_text", "text": "secret"}]}}
        out2 = cf.skeletonize_codex_record(rec2, scrubber())
        self.assertEqual(out2["payload"], {"type": "message", "role": "user", "content": [{"type": "input_text"}]})

    def test_turn_context_keeps_policies_and_maps_cwd(self):
        rec = {"timestamp": "t", "type": "turn_context", "payload": {
            "cwd": "/Users/jdoe/Development/p", "approval_policy": "on-request", "model": "gpt-5", "effort": "high",
            "sandbox_policy": {"mode": "workspace-write", "network_access": False}, "summary": "auto",
            "user_instructions": "secret prose"}}
        out = cf.skeletonize_codex_record(rec, scrubber())
        self.assertEqual(out["payload"]["cwd"], "/Users/you/proj/1")
        self.assertEqual(out["payload"]["sandbox_policy"]["mode"], "workspace-write")
        self.assertNotIn("user_instructions", out["payload"])


class ClaudeJsonReductionTests(unittest.TestCase):
    def test_keeps_only_whitelisted_keys_and_fakes_account(self):
        obj = {
            "oauthAccount": {"accountUuid": "123e4567-e89b-42d3-a456-426614174000", "emailAddress": "jane@acme.io",
                             "fullName": "Jane Doe", "organizationName": "Acme", "hasExtraUsageEnabled": True,
                             "subscriptionCreatedAt": "2025-01-01T00:00:00Z", "seatTier": "max"},
            "hasAvailableSubscription": True, "hasCompletedOnboarding": True,
            "customApiKeyResponses": {"approved": ["ab12"], "rejected": ["cd34"]},
            "userID": "deadbeef" * 8, "machineID": "cafebabe" * 8,
            "tipsHistory": {"x": 1}, "cachedStatsigGates": {"g": True},
            "projects": {"/Users/jdoe/Development/a": {"mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg"]}},
                                                      "hasTrustDialogAccepted": True, "allowedTools": [],
                                                      "history": [{"display": "secret prompt"}],
                                                      "lastCost": 1.5, "exampleFiles": ["x.rs"]}},
        }
        out = cf.reduce_claude_json(obj, scrubber(), max_projects=5)
        self.assertEqual(set(out) & {"tipsHistory", "cachedStatsigGates"}, set())
        self.assertEqual(out["oauthAccount"]["emailAddress"], "you@example.com")
        self.assertEqual(out["oauthAccount"]["accountUuid"], cf.FAKE_UUID)
        self.assertEqual(out["oauthAccount"]["fullName"], "You Example")
        self.assertIs(out["oauthAccount"]["hasExtraUsageEnabled"], True)
        self.assertEqual(out["oauthAccount"]["seatTier"], "max")
        self.assertEqual(out["customApiKeyResponses"], {"approved": [], "rejected": []})
        self.assertEqual(out["userID"], cf.FAKE_SHA256)
        proj = out["projects"]["/Users/you/proj/1"]
        self.assertNotIn("history", proj)
        self.assertNotIn("exampleFiles", proj)
        self.assertEqual(proj["lastCost"], 1.5)
        self.assertEqual(proj["mcpServers"]["s"]["command"], "npx")

    def test_caps_projects(self):
        obj = {"projects": {f"/Users/jdoe/p{i}": {"hasTrustDialogAccepted": True} for i in range(10)}}
        out = cf.reduce_claude_json(obj, scrubber(), max_projects=3)
        self.assertEqual(len(out["projects"]), 3)


class SettingsProseTests(unittest.TestCase):
    def test_auto_mode_environment_and_long_strings_are_blanked(self):
        settings = {"autoMode": {"environment": "**Repository visibility**: PUBLIC — acme/secret-repo ...", "enabled": True},
                    "permissions": {"allow": ["Bash(ls:*)", "Bash(python3 -c '" + "y" * 300 + "')"]},
                    "note": "x" * 201, "model": "opus"}
        out = cf.reduce_settings(settings, 15)
        self.assertEqual(out["autoMode"], {"environment": "", "enabled": True})
        self.assertEqual(out["note"], "")
        self.assertEqual(out["model"], "opus")
        self.assertEqual(out["permissions"]["allow"], ["Bash(ls:*)"])


class DenylistTests(unittest.TestCase):
    def test_credential_and_content_paths_are_denied(self):
        home = HOME
        for rel in [".claude/.credentials.json", ".codex/auth.json", ".copilot/config.json",
                    "Library/Application Support/Cursor/User/globalStorage/state.vscdb",
                    ".copilot/session-store.db", ".claude/sessions/123.abcdef.key",
                    ".claude/shell-snapshots/snapshot-zsh-1.sh", ".claude/session-env/s/x.sh",
                    ".claude/file-history/s/h@v1", ".claude/paste-cache/x.txt", ".claude/security/log.txt",
                    ".claude/telemetry/x.json", ".claude/projects/-p/memory/MEMORY.md", ".claude/history.jsonl",
                    ".codex/history.jsonl", ".codex/log/codex-tui.log", ".config/github-copilot/hosts.json",
                    ".copilot/mcp-secrets/x", ".claude/.credentials.json.bak"]:
            self.assertTrue(cf.is_denied(home / rel), rel)

    def test_ordinary_config_is_allowed(self):
        for rel in [".claude/settings.json", ".claude.json", ".codex/config.toml", ".cursor/cli-config.json",
                    ".claude/projects/-p/abc.jsonl"]:
            self.assertFalse(cf.is_denied(HOME / rel), rel)


class ShellProfileTests(unittest.TestCase):
    def test_extracts_only_agent_relevant_exports_with_fake_values(self):
        text = "\n".join([
            "# my zshrc", "export PATH=/Users/jdoe/bin:$PATH", "alias ll='ls -l'",
            "export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
            'export GITHUB_TOKEN="ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
            "export ANTHROPIC_BASE_URL=https://proxy.internal.acme.io/v1",
            "export CODEX_HOME=/Users/jdoe/.codex-alt", "export EDITOR=vim",
            "source ~/.secrets",
        ])
        out = cf.extract_shell_exports(text, scrubber())
        self.assertNotIn("alias", out)
        self.assertNotIn("EDITOR", out)
        self.assertNotIn("source", out)
        self.assertIn("export OPENAI_API_KEY=sk-proj-FAKE", out)
        self.assertIn('export GITHUB_TOKEN="ghp_FAKE', out)
        self.assertIn("export ANTHROPIC_BASE_URL=https://example.com/v1", out)  # unknown hosts are replaced
        self.assertIn("export CODEX_HOME=/Users/you/.codex-alt", out)
        self.assertNotIn("abcdefghij", out)
        self.assertTrue(out.startswith("#"))


class TomlAndJsoncTests(unittest.TestCase):
    def test_toml_table_paths_and_secret_values_are_scrubbed(self):
        text = 'model = "gpt-5"\n\n[projects."/Users/jdoe/Development/p"]\ntrust_level = "trusted"\n\n' \
               '[mcp_servers.gh]\ncommand = "npx"\nenv = { GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789" }\n' \
               'bearer_token_env_var = "GH_TOKEN"\n'
        out = cf.redact_toml(text, scrubber())
        self.assertIn('[projects."/Users/you/proj/1"]', out)
        self.assertIn('trust_level = "trusted"', out)
        self.assertIn("ghp_FAKE", out)
        self.assertNotIn("abcdefghij", out)
        self.assertIn('bearer_token_env_var = "GH_TOKEN"', out)

    def test_jsonc_keeps_comments_and_fakes_machine_ids(self):
        text = '// This configuration file allows you to pass permanent command line arguments\n{\n' \
               '\t// crash reporter\n\t"crash-reporter-id": "123e4567-e89b-42d3-a456-426614174000",\n' \
               '\t"enable-crash-reporter": true\n}\n'
        out = cf.redact_jsonc(text, scrubber())
        self.assertIn("// This configuration file", out)
        self.assertIn(cf.FAKE_UUID, out)
        self.assertNotIn("123e4567", out)


class VerifierTests(unittest.TestCase):
    def verifier(self):
        s = scrubber()
        s.scrub_string("/Users/jdoe/Development/secret-client")
        return cf.Verifier(identity(), s)

    def test_clean_text_passes(self):
        v = self.verifier()
        clean = json.dumps({"env": {"GITHUB_TOKEN": "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"},
                            "cwd": "/Users/you/proj/1", "id": "123e4567-e89b-42d3-a456-426614174001",
                            "sha": "0123456789abcdef0123456789abcdef01234567"})
        self.assertEqual(v.check_text(Path("x.json"), clean), [])

    def test_flags_real_secret_username_project_email_and_hostname(self):
        v = self.verifier()
        bad = ("ghp_abcdefghijklmnopqrstuvwxyz0123456789 /Users/jdoe/x secret-client jane@acme.io jdoes-mbp "
               "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        findings = " ".join(v.check_text(Path("x.json"), bad))
        for needle in ["secret pattern", "username", "project path", "email", "hostname"]:
            self.assertIn(needle, findings)

    def test_flags_high_entropy_blob(self):
        v = self.verifier()
        blob = "Qm9yZWQgb2YgYmVpbmcgYSBzZWNyZXQgYmxvYiBpbiBhIHRlc3Q9PT0"
        self.assertTrue(any("entropy" in f for f in v.check_text(Path("x.json"), blob)))
        self.assertEqual(v.check_text(Path("x.json"), "FAKE" * 20), [])

    def test_flags_forbidden_transcript_keys_and_long_strings(self):
        v = self.verifier()
        rec = {"type": "assistant", "message": {"content": [{"type": "text", "text": "leak"}]}}
        self.assertTrue(any("text" in f for f in v.check_jsonl_record(rec)))
        rec2 = {"type": "user", "toolUseResult": {}}
        self.assertTrue(any("toolUseResult" in f for f in v.check_jsonl_record(rec2)))
        rec3 = {"type": "session_meta", "payload": {"instructions": "x" * 10}}
        self.assertTrue(any("instructions" in f for f in v.check_jsonl_record(rec3)))
        rec4 = {"type": "user", "note": "a" * 121}
        self.assertTrue(any("long string" in f for f in v.check_jsonl_record(rec4)))
        self.assertEqual(v.check_jsonl_record({"type": "assistant", "message": {"usage": {"input_tokens": 1},
                                                                                 "content": [{"type": "text"}]}}), [])


class EndToEndTests(unittest.TestCase):
    """Builds a synthetic home, runs `write`, and checks nothing leaks."""

    SECRETS = {
        "anthropic": "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "github": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "openai": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
    }

    def build_home(self, root: Path):
        home = root / "home" / "jdoe"
        (home / ".claude" / "projects" / "-Users-jdoe-Development-proj" / "11111111-1111-4111-8111-111111111111" / "subagents").mkdir(parents=True)
        (home / ".claude" / "backups").mkdir()
        (home / ".claude" / "sessions").mkdir()
        (home / ".claude" / "plugins").mkdir()
        (home / ".codex" / "sessions" / "2025" / "10" / "10").mkdir(parents=True)
        (home / ".cursor" / "projects" / "Users-jdoe-Development-proj").mkdir(parents=True)
        (home / "Library" / "Application Support" / "Code" / "User").mkdir(parents=True)
        cwd = "/Users/jdoe/Development/proj"

        (home / ".claude" / "settings.json").write_text(json.dumps({
            "permissions": {"allow": [f"Bash(cat /Users/jdoe/x:*)"] * 20},
            "env": {"ANTHROPIC_API_KEY": self.SECRETS["anthropic"]},
            "enabledPlugins": {"a@b": True}}))
        (home / ".claude" / "settings.local.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/Users/jdoe/hook.sh"}]}]}}))
        (home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "jane@acme.io", "accountUuid": "123e4567-e89b-42d3-a456-426614174000"},
            "hasAvailableSubscription": True, "tipsHistory": {"x": 1},
            "customApiKeyResponses": {"approved": ["abcd"], "rejected": []},
            "projects": {cwd: {"hasTrustDialogAccepted": True, "history": [{"display": "my prompt"}],
                              "mcpServers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": self.SECRETS["github"]}}}}}}))
        (home / ".claude" / ".credentials.json").write_text(json.dumps({"claudeAiOauth": {"accessToken": "REALTOKEN"}}))
        (home / ".claude" / "history.jsonl").write_text(json.dumps({"display": "my prompt", "project": cwd}) + "\n")
        (home / ".claude" / "sessions" / "123.json").write_text(json.dumps({"pid": 123, "cwd": cwd, "name": "sess"}))
        (home / ".claude" / "sessions" / "123.abc.key").write_text("REALKEY")
        (home / ".claude" / "plugins" / "installed_plugins.json").write_text(json.dumps(
            {"version": 2, "plugins": {"a@b": {"installPath": "/Users/jdoe/.claude/plugins/cache/b/a/1.0"}}}))
        tdir = home / ".claude" / "projects" / "-Users-jdoe-Development-proj"
        lines = []
        for i in range(5):
            lines.append(json.dumps({"type": "user", "uuid": f"u{i}", "parentUuid": None, "sessionId": "11111111-1111-4111-8111-111111111111",
                                     "timestamp": "2026-10-01T00:00:00Z", "cwd": cwd, "version": "2.1.296",
                                     "message": {"role": "user", "content": "SECRET PROMPT"}}))
            lines.append(json.dumps({"type": "assistant", "uuid": f"a{i}", "parentUuid": f"u{i}", "sessionId": "11111111-1111-4111-8111-111111111111",
                                     "timestamp": "2026-10-01T00:00:01Z", "cwd": cwd, "version": "2.1.296", "requestId": f"req_{i}",
                                     "message": {"id": f"msg_{i}", "model": "claude-opus-5-5", "role": "assistant",
                                                 "content": [{"type": "text", "text": "SECRET ANSWER"}],
                                                 "usage": {"input_tokens": 1, "output_tokens": 2}}}))
        lines.append(json.dumps({"type": "custom-title", "customTitle": "SECRET TITLE", "sessionId": "11111111-1111-4111-8111-111111111111"}))
        (tdir / "11111111-1111-4111-8111-111111111111.jsonl").write_text("\n".join(lines) + "\n")
        (tdir / "11111111-1111-4111-8111-111111111111" / "subagents" / "agent-abc.jsonl").write_text(lines[1] + "\n")
        (tdir / "memory").mkdir()
        (tdir / "memory" / "MEMORY.md").write_text("SECRET NOTES")

        (home / ".codex" / "config.toml").write_text(f'model = "gpt-5"\n\n[projects."{cwd}"]\ntrust_level = "trusted"\n')
        (home / ".codex" / "auth.json").write_text(json.dumps({"OPENAI_API_KEY": None, "tokens": {"access_token": "REALTOKEN"}}))
        (home / ".codex" / "history.jsonl").write_text(json.dumps({"session_id": "x", "text": "SECRET", "ts": 1}) + "\n")
        rollout = [
            {"timestamp": "t", "type": "session_meta", "payload": {"id": "rid", "cwd": cwd, "cli_version": "0.46.0",
                                                                  "instructions": "SECRET AGENTS.md", "originator": "codex_cli_rs", "source": "cli",
                                                                  "git": {"branch": "wip", "commit_hash": "0" * 40, "repository_url": "git@github.com:acme/x.git"}}},
            {"timestamp": "t", "type": "turn_context", "payload": {"cwd": cwd, "model": "gpt-5", "approval_policy": "on-request"}},
            {"timestamp": "t", "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "SECRET PROMPT"}]}},
            {"timestamp": "t", "type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 5}}}},
        ]
        (home / ".codex" / "sessions" / "2025" / "10" / "10" / "rollout-2025-10-10T13-46-23-0199cd31-4a62-7bc0-b411-9d5a2a198039.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rollout) + "\n")

        (home / ".cursor" / "cli-config.json").write_text(json.dumps({"version": 1, "permissions": {"allow": ["Shell(ls)"], "deny": []}}))
        (home / ".cursor" / "argv.json").write_text('// comment\n{\n\t"crash-reporter-id": "123e4567-e89b-42d3-a456-426614174000"\n}\n')
        (home / ".cursor" / "projects" / "Users-jdoe-Development-proj" / ".workspace-trusted").write_text(
            json.dumps({"trustedAt": "2025-09-16T00:00:00Z", "workspacePath": cwd}))
        (home / "Library" / "Application Support" / "Code" / "User" / "settings.json").write_text(json.dumps({
            "chat.tools.global.autoApprove": True, "python.x": "/Users/jdoe/secret", "terminal.integrated.env.osx": {"TOK": "realvalue"}}))
        (home / ".zshrc").write_text(f"export OPENAI_API_KEY={self.SECRETS['openai']}\nexport EDITOR=vim\n")
        return home

    def test_write_produces_clean_fixtures_and_never_opens_denied_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            # Make the credential files unreadable: opening them would raise.
            for rel in [".claude/.credentials.json", ".codex/auth.json", ".claude/sessions/123.abc.key",
                        ".claude/history.jsonl", ".codex/history.jsonl"]:
                os.chmod(home / rel, 0)
            out = root / "fixtures"
            staging = root / "staging"
            code = cf.main(["write", "--home", str(home), "--out", str(out), "--staging", str(staging),
                            "--date", "2026-10-13", "--hostname", "jdoes-mbp", "--quiet"])
            self.assertEqual(code, 0)
            written = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
            self.assertIn("claude/2.1.296/settings.json", written)
            self.assertIn("claude/2.1.296/claude.json", written)
            self.assertIn("claude/2.1.296/projects/-Users-you-proj-1/11111111-1111-4111-8111-111111111111.jsonl", written)
            self.assertIn("codex/0.46.0/config.toml", written)
            self.assertIn("codex/0.46.0/auth.chatgpt.json", written)
            self.assertIn("cursor/2026-10-13/projects/Users-you-proj-1/.workspace-trusted", written)
            self.assertIn("shared/2026-10-13/.zshrc", written)
            self.assertIn("copilot/2026-10-13/vscode-user-settings.json", written)
            blob = "\n".join((out / p).read_text() for p in written)
            for secret in self.SECRETS.values():
                self.assertNotIn(secret, blob)
            for leak in ["SECRET", "REALTOKEN", "REALKEY", "jdoe", "jane@acme.io", "realvalue", "my prompt", "abcd"]:
                self.assertNotIn(leak, blob, leak)
            self.assertIn("sk-ant-api03-FAKE", blob)
            self.assertIn("ghp_FAKE", blob)
            for name in ["credentials.json", "auth.json", "123.abc.key", "history.jsonl", "MEMORY.md"]:
                self.assertFalse(any(name in p for p in written if not p.endswith(("auth.chatgpt.json", "auth.api-key.json", "auth.current.json"))), name)
            # A second run over the output must be a no-op (idempotent redaction).
            v = cf.Verifier(identity(home), cf.Scrubber(identity(home)))
            self.assertEqual(v.verify_tree(out), [])

    def test_plan_is_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            out = root / "fixtures"
            code = cf.main(["plan", "--home", str(home), "--out", str(out), "--date", "2026-10-13", "--quiet"])
            self.assertEqual(code, 0)
            self.assertFalse(out.exists())

    def test_write_refuses_when_verifier_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            out = root / "fixtures"
            staging = root / "staging"
            # Inject a verifier failure through the test hook: a secret that no scrub rule knows.
            code = cf.main(["write", "--home", str(home), "--out", str(out), "--staging", str(staging),
                            "--date", "2026-10-13", "--quiet", "--inject-verifier-failure"])
            self.assertEqual(code, 1)
            self.assertFalse(out.exists())


class ReviewRegressionScrubTests(unittest.TestCase):
    """Cases from the adversarial review of the first version."""

    def test_tilde_and_home_variable_paths_are_mapped(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("Bash(cat ~/Development/secret-client/*:*)"), "Bash(cat ~/proj/1/*:*)")
        self.assertEqual(s.scrub_string("Edit($HOME/Development/beta/**)"), "Edit($HOME/proj/2/**)")
        self.assertEqual(s.scrub_string("${HOME}/Development/beta/x.rs"), "${HOME}/proj/2/x.rs")
        self.assertEqual(s.scrub_string("~/.claude/settings.json"), "~/.claude/settings.json")

    def test_paths_with_spaces_are_mapped_whole(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("/Users/jdoe/My Projects/Acme Client/src"), "/Users/you/proj/1/src")
        self.assertEqual(s.scrub_string('Read(/Users/jdoe/My Projects/Acme Client/**)'), "Read(/Users/you/proj/1/**)")
        self.assertEqual(s.scrub_string("cd /Users/jdoe/Development/x && make"), "cd /Users/you/proj/2 && make")

    def test_cloud_folders_are_project_parents(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("/Users/jdoe/Library/Mobile Documents/com~apple~CloudDocs/Epsilon/a.rs"),
                         "/Users/you/Library/Mobile Documents/com~apple~CloudDocs/proj/1/a.rs")
        self.assertEqual(s.scrub_string("/Users/jdoe/Google Drive/clients/acme-corp"),
                         "/Users/you/Google Drive/proj/2")

    def test_deep_paths_get_opaque_segments(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("/Users/jdoe/Code/clients/zeta-deep/app/**"), "/Users/you/proj/1/d1/d2/**")
        self.assertEqual(s.scrub_string("/Users/jdoe/Code/clients/zeta-deep/app/main.rs"), "/Users/you/proj/1/d1/d2/main.rs")
        self.assertEqual(s.scrub_string("/Users/jdoe/Code/clients/src/lib.rs"), "/Users/you/proj/1/src/lib.rs")
        self.assertEqual(s.scrub_string("/Users/jdoe/Sites/acme-client.com"), "/Users/you/proj/2")
        self.assertEqual(s.scrub_string("/Users/jdoe/secret-client.app"), "/Users/you/proj/3")

    def test_volume_paths_are_mapped(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("Read(/Volumes/Work/theta-volume/**)"), "Read(/Volumes/vol/proj/1/**)")
        self.assertEqual(s.scrub_string("/Volumes/Work/theta-volume"), "/Volumes/vol/proj/1")

    def test_url_encoded_paths_are_mapped(self):
        s = scrubber()
        out = s.scrub_string("vscode://file/%2FUsers%2Fjdoe%2FDevelopment%2Fsecret-client%2Fsrc")
        self.assertNotIn("jdoe", out)
        self.assertNotIn("secret-client", out)
        self.assertIn("%2FUsers%2Fyou%2Fproj%2F1%2Fsrc", out)

    def test_dict_keys_are_scrubbed(self):
        s = scrubber()
        out = s.scrub_json({"/Users/jdoe/Development/secret-client": {"x": 1}, "~/Development/other/.prompts": True})
        self.assertEqual(list(out), ["/Users/you/proj/1", "~/proj/2/.prompts"])

    def test_marketplace_names_are_renamed(self):
        s = scrubber()
        s.register_marketplace("acme-mkt")
        out = s.scrub_json({"enabledPlugins": {"tool@acme-mkt": True, "ctx@claude-plugins-official": True},
                            "extraKnownMarketplaces": {"acme-mkt": {"source": {"repo": "acme/mkt"}}},
                            "installLocation": "/Users/jdoe/.claude/plugins/marketplaces/acme-mkt"})
        self.assertEqual(out["enabledPlugins"], {"tool@marketplace-1": True, "ctx@claude-plugins-official": True})
        self.assertEqual(list(out["extraKnownMarketplaces"]), ["marketplace-1"])
        self.assertEqual(out["extraKnownMarketplaces"]["marketplace-1"]["source"]["repo"], "you/example")
        self.assertEqual(out["installLocation"], "/Users/you/.claude/plugins/marketplaces/marketplace-1")

    def test_nested_identity_values_are_faked(self):
        s = scrubber()
        out = s.scrub_json({"forceLoginOrgUUID": "9f1c2b3a-4d5e-4f60-8a71-b2c3d4e5f607",
                            "telemetryId": "9f1c2b3a-4d5e-4f60-8a71-b2c3d4e5f608",
                            "gitCommitSha": "0123456789abcdef0123456789abcdef01234567",
                            "sessionId": "9f1c2b3a-4d5e-4f60-8a71-b2c3d4e5f609"})
        self.assertEqual(out["forceLoginOrgUUID"], cf.FAKE_UUID)
        self.assertEqual(out["telemetryId"], cf.FAKE_UUID)
        self.assertEqual(out["gitCommitSha"], cf.FAKE_SHA1)
        self.assertEqual(out["sessionId"], "9f1c2b3a-4d5e-4f60-8a71-b2c3d4e5f609")
        acct = cf.reduce_claude_json({"oauthAccount": {"organization": {"name": "Nu Org", "uuid": "9f1c2b3a-4d5e-4f60-8a71-b2c3d4e5f610"},
                                                       "handle": "jdoe-handle"}}, s)["oauthAccount"]
        self.assertEqual(acct["organization"]["uuid"], cf.FAKE_UUID)
        self.assertNotIn("Nu Org", json.dumps(acct))
        self.assertNotIn("jdoe-handle", json.dumps(acct))

    def test_flag_values_and_url_passwords_and_webhooks_are_faked(self):
        s = scrubber()
        out = s.scrub_json({"args": ["--api-key", "3f9a1c2e4b5d6f7a8b9c0d1e2f3a4b5c", "--token=q7Lm2xP9vK4nR8tW1yB6cZ0d", "--verbose"],
                            "env": {"REDIS_URL": "redis://:S3cretRedisPass@localhost:6379/0",
                                    "SLACK_WEBHOOK_URL": fake_slack_webhook()}})
        self.assertEqual(out["args"][1], "FAKE" * 8)
        self.assertEqual(out["args"][2], "--token=" + cf.fill_fake(24))
        self.assertEqual(out["args"][3], "--verbose")
        self.assertEqual(out["env"]["REDIS_URL"], "redis://:" + cf.fill_fake(15) + "@localhost:6379/0")
        self.assertNotIn("aBcDeFgHiJkLmNoPqRsTuVwX", out["env"]["SLACK_WEBHOOK_URL"])
        self.assertTrue(out["env"]["SLACK_WEBHOOK_URL"].startswith("https://hooks.slack.com/services/"))
        rule = s.scrub_string("Bash(aws s3 ls --secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY:*)")
        self.assertNotIn("wJalrXUtnFEMI", rule)

    def test_unknown_hosts_become_example_com(self):
        s = scrubber()
        self.assertEqual(s.scrub_string("https://llm-gateway.acme-internal.corp/v1"), "https://example.com/v1")
        self.assertEqual(s.scrub_string("WebFetch(domain:jira.acme-internal.corp)"), "WebFetch(domain:example.com)")
        self.assertEqual(s.scrub_string("https://api.anthropic.com/v1"), "https://api.anthropic.com/v1")
        self.assertEqual(s.scrub_string("http://localhost:8080/x"), "http://localhost:8080/x")
        self.assertEqual(s.scrub_string("https://github.com/anthropics/claude-plugins-official/tree/main"),
                         "https://github.com/anthropics/claude-plugins-official/tree/main")
        self.assertEqual(s.scrub_string("Bash(open https://github.com/acme/iota-tree/tree/main:*)"),
                         "Bash(open https://github.com/you/example.git:*)")
        self.assertEqual(s.scrub_string("gh pr create --repo jdoe/gamma-repo"), "gh pr create --repo you/example")

    def test_hostname_variants_are_scrubbed(self):
        ident = cf.Identity(home=HOME, username="jdoe", hostname="MacBook-Pro-3",
                            hostnames=["MacBook-Pro-3", "Janes-MacBook-Pro", "Jane's MacBook Pro"])
        s = cf.Scrubber(ident)
        self.assertEqual(s.scrub_string("host Janes-MacBook-Pro.local"), "host your-mac.local")
        self.assertEqual(s.scrub_string("Jane's MacBook Pro"), "your-mac")

    def test_toml_quoted_inline_keys_are_faked(self):
        out = cf.redact_toml('http_headers = { "X-Api-Key" = "a1b2c3d4e5f60718293a4b5c6d7e8f90" }\n', scrubber())
        self.assertNotIn("a1b2c3d4", out)
        self.assertIn('"X-Api-Key" = "FAKE', out)

    def test_version_strings_are_validated(self):
        self.assertTrue(cf.is_safe_version("2.1.296"))
        self.assertTrue(cf.is_safe_version("0.46.0-alpha.1"))
        self.assertFalse(cf.is_safe_version("../x"))
        self.assertFalse(cf.is_safe_version("2.1.296/../../evil"))
        self.assertFalse(cf.is_safe_version(""))
        self.assertEqual(sorted(["2.1.296", "2.1.dev", "0.46.0-alpha.1", "0.46.0"], key=cf.version_key),
                         ["0.46.0", "0.46.0-alpha.1", "2.1.296", "2.1.dev"])


class ReviewRegressionTranscriptTests(unittest.TestCase):
    def test_codex_reason_and_tool_names_do_not_leak(self):
        rec = {"timestamp": "t", "type": "event_msg", "payload": {"type": "exec_approval_request",
               "reason": "I need to delete the old migration", "risk": {"reason": "prose", "level": "high"},
               "parsed_cmd": [{"type": "read", "cmd": "cat secret.txt", "name": "client-config.rs"}]}}
        out = cf.skeletonize_codex_record(rec, scrubber())
        self.assertEqual(out["payload"]["reason"], "")
        self.assertEqual(out["payload"]["risk"]["reason"], "")
        self.assertEqual(out["payload"]["parsed_cmd"], [{"type": "read", "cmd": "", "name": ""}])
        aborted = cf.skeletonize_codex_record({"timestamp": "t", "type": "event_msg",
                                               "payload": {"type": "turn_aborted", "reason": "interrupted"}}, scrubber())
        self.assertEqual(aborted["payload"]["reason"], "interrupted")
        call = cf.skeletonize_codex_record({"timestamp": "t", "type": "response_item",
                                            "payload": {"type": "function_call", "name": "mcp__acme-server__search",
                                                        "call_id": "c1", "arguments": "{}"}}, scrubber())
        self.assertEqual(call["payload"]["name"], "tool")
        shell = cf.skeletonize_codex_record({"timestamp": "t", "type": "response_item",
                                             "payload": {"type": "function_call", "name": "shell", "call_id": "c1", "arguments": "{}"}}, scrubber())
        self.assertEqual(shell["payload"]["name"], "shell")

    def test_token_count_keeps_numbers_and_enums_only(self):
        payload = {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 10}},
                   "rate_limits": {"plan_type": "plus", "limit_id": "codex", "limit_name": "Weekly",
                                   "primary": {"used_percent": 9.0}, "credits": {"note": "prose", "balance": 3}}}
        out = cf.skeletonize_codex_record({"timestamp": "t", "type": "event_msg", "payload": payload}, scrubber())
        self.assertEqual(out["payload"]["info"]["total_token_usage"]["input_tokens"], 10)
        self.assertEqual(out["payload"]["rate_limits"]["plan_type"], "plus")
        self.assertEqual(out["payload"]["rate_limits"]["credits"], {"note": "", "balance": 3})

    def test_claude_usage_subobjects_keep_numbers_only(self):
        rec = {"type": "assistant", "uuid": "u", "sessionId": "s", "timestamp": "t", "cwd": "/Users/jdoe/x", "version": "2.1.296",
               "message": {"id": "m", "model": "claude-opus-5-5", "role": "assistant", "stop_sequence": "SECRET",
                           "content": [], "usage": {"input_tokens": 1, "service_tier": "standard", "inference_geo": "us",
                                                    "iterations": [{"type": "x", "note": "SECRET NOTE", "n": 2}],
                                                    "server_tool_use": {"web_search_requests": 1, "last_query": "SECRET"},
                                                    "fallback_credit": {"reason": "SECRET"}}}}
        out = cf.skeletonize_claude_record(rec, scrubber())
        self.assertNotIn("SECRET", json.dumps(out))
        self.assertEqual(out["message"]["usage"]["iterations"], [{"type": "x", "note": "", "n": 2}])
        self.assertEqual(out["message"]["usage"]["service_tier"], "standard")
        self.assertNotIn("stop_sequence", out["message"])

    def test_nested_keep_keys_do_not_apply_inside_side_records(self):
        rec = {"type": "attachment", "sessionId": "s", "attachment": {"type": "diag", "gitBranch": "feat/secret",
               "cwd": "/Volumes/x/secret", "mode": "SECRET MODE", "level": "SECRET", "nested": {"version": "SECRET"}}}
        out = cf.skeletonize_claude_record(rec, scrubber())
        self.assertNotIn("SECRET", json.dumps(out))
        self.assertNotIn("feat/secret", json.dumps(out))
        self.assertEqual(out["attachment"]["type"], "diag")
        self.assertEqual(cf.skeletonize_claude_record({"type": "pr-link", "prNumber": "SECRET"}, scrubber())["prNumber"], "")

    def test_path_like_dict_keys_become_placeholders(self):
        rec = {"type": "file-history-snapshot", "snapshot": {"trackedFileBackups": {"/private/tmp/secret/a.rs": {"v": 1},
                                                                                     "/opt/other/b.rs": {"v": 2}}}}
        out = cf.skeletonize_claude_record(rec, scrubber())
        self.assertEqual(sorted(out["snapshot"]["trackedFileBackups"]), ["key_1", "key_2"])

    def test_generic_record_keeps_timestamp_and_blanks_names(self):
        rec = {"id": "1", "parentId": None, "timestamp": "2026-10-13T00:00:00Z", "type": "assistant.message",
               "data": {"name": "SECRET", "event": "SECRET", "currentTokens": 12, "toolRequests": [{"name": "SECRET"}]}}
        out = cf.skeletonize_generic_record(rec, scrubber())
        self.assertEqual(out["timestamp"], "2026-10-13T00:00:00Z")
        self.assertEqual(out["type"], "assistant.message")
        self.assertNotIn("SECRET", json.dumps(out))
        self.assertEqual(out["data"]["currentTokens"], 12)
        self.assertIsNone(cf.skeletonize_generic_record({"type": ["weird"]}, scrubber()))


class ReviewRegressionVerifierTests(unittest.TestCase):
    def verifier(self):
        return cf.Verifier(identity(), scrubber())

    def test_enum_values_under_soft_keys_are_allowed(self):
        v = self.verifier()
        self.assertEqual(v.check_jsonl_record({"type": "turn_context", "payload": {"summary": "auto"}}), [])
        self.assertEqual(v.check_jsonl_record({"type": "event_msg", "payload": {"type": "turn_aborted", "reason": "interrupted"}}), [])
        self.assertTrue(v.check_jsonl_record({"type": "turn_context", "payload": {"summary": "my secret summary"}}))

    def test_codex_item_ids_pass_entropy_check(self):
        v = self.verifier()
        self.assertEqual(v.check_text(Path("x.jsonl"), '"id":"rs_0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071"'), [])

    def test_hex_and_uuid_under_non_id_keys_are_flagged_in_json(self):
        v = self.verifier()
        bad = {"mcpServers": {"dd": {"args": ["--api-key", "3f9a1c2e4b5d6f7a8b9c0d1e2f3a4b5c"]}},
               "forceLoginOrgUUID": "9f1c2b3a-4d5e-4f60-8a71-b2c3d4e5f607"}
        findings = v.check_json_config(Path("settings.json"), bad)
        self.assertTrue(any("hex" in f for f in findings), findings)
        self.assertTrue(any("uuid" in f.lower() for f in findings), findings)
        ok = {"lastSessionId": "9f1c2b3a-4d5e-4f60-8a71-b2c3d4e5f607", "gitCommitSha": cf.FAKE_SHA1}
        self.assertEqual(v.check_json_config(Path("x.json"), ok), [])

    def test_secret_like_strings_in_arg_contexts_are_flagged(self):
        v = self.verifier()
        bad = {"args": ["--token", "q7Lm2xP9vK4nR8tW1yB6cZ0d"], "hooks": {"PreToolUse": [{"hooks": [{"command": "curl -H 'X-Auth: wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY'"}]}]}}
        findings = v.check_json_config(Path("settings.json"), bad)
        self.assertTrue(len(findings) >= 2, findings)
        self.assertEqual(v.check_json_config(Path("x.json"), {"args": ["--root", "/Users/you/proj/1/src/main.rs", "-y", "@scope/pkg@1.2.3"]}), [])

    def test_webhooks_unknown_hosts_and_tilde_paths_are_flagged(self):
        v = self.verifier()
        text = fake_slack_webhook() + " https://llm-gateway.acme-internal.corp/v1 ~/Clients/acme-payroll"
        joined = " ".join(v.check_text(Path("x.json"), text))
        self.assertIn("webhook", joined)
        self.assertIn("host", joined)
        self.assertIn("home-relative path", joined)
        self.assertEqual(v.check_text(Path("x.json"), "~/proj/1/src ~/.claude/x https://example.com/v1 https://api.openai.com/v1"), [])

    def test_encoded_dir_tokens_do_not_trip_entropy(self):
        v = self.verifier()
        self.assertEqual(v.check_text(Path("x.json"), "-Users-you-proj-2--claude-worktrees-peaceful-matsumoto-dc3d74"), [])
        self.assertEqual(v.check_text(Path("x.json"), "/private/tmp/claude-502/-Users-you-proj-3/abc/msg.sock"), [])

    def test_identifiers_and_relative_paths_pass_entropy_check(self):
        v = self.verifier()
        text = ('"hasClaudeMdExternalIncludesWarningShown": true '
                '"claude-plugins-official/frontend-design/f359d43b4060" "anthropics/claude-plugins-official"')
        self.assertEqual(v.check_text(Path("x.json"), text), [])
        self.assertTrue(v.check_text(Path("x.json"), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))

    def test_public_names_are_not_flagged(self):
        s = scrubber()
        s.scrub_string("/Users/jdoe/MacApps/vigildex")
        v = cf.Verifier(identity(), s, {"vigildex"})
        self.assertEqual(v.check_text(Path("x.json"), "Bash(cargo run -p vigildex-cli:*)"), [])
        self.assertTrue(cf.Verifier(identity(), s).check_text(Path("x.json"), "Bash(cargo run -p vigildex-cli:*)"))

    def test_url_encoded_username_is_flagged(self):
        v = self.verifier()
        self.assertTrue(v.check_text(Path("x.json"), "vscode://file/%2FUsers%2Fjdoe%2Fx"))


class ReviewRegressionCollectorTests(unittest.TestCase):
    def build_home(self, root: Path) -> Path:
        home = EndToEndTests().build_home(root)
        return home

    def run_write(self, root: Path, home: Path, extra=()):
        out = root / "fixtures"
        staging = root / "staging"
        code = cf.main(["write", "--home", str(home), "--out", str(out), "--staging", str(staging),
                        "--date", "2026-10-13", "--hostname", "jdoes-mbp", "--quiet", *extra])
        return code, out, staging

    def test_symlinked_credential_file_is_never_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            target = home / ".claude" / ".credentials.json"
            os.chmod(target, 0o600)
            link = home / ".claude" / "settings.local.json"
            link.unlink()
            link.symlink_to(target)
            (home / ".codex" / "version.json").symlink_to(home / ".codex" / "auth.json")
            code, out, _ = self.run_write(root, home)
            self.assertEqual(code, 0)
            written = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
            self.assertNotIn("claude/2.1.296/settings.local.json", written)
            self.assertNotIn("codex/0.46.0/version.json", written)
            self.assertNotIn("REALTOKEN", "\n".join((out / p).read_text() for p in written))

    def test_version_traversal_cannot_escape_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            tdir = home / ".claude" / "projects" / "-Users-jdoe-Development-proj"
            evil = tdir / "22222222-2222-4222-8222-222222222222.jsonl"
            evil.write_text(json.dumps({"type": "user", "uuid": "u", "sessionId": "s", "timestamp": "t",
                                        "cwd": "/Users/jdoe/Development/proj", "version": "2.1.296/../../../../evil",
                                        "message": {"role": "user", "content": "x"}}) + "\n")
            before = {p for p in root.rglob("*")}
            code, out, staging = self.run_write(root, home)
            self.assertEqual(code, 0)
            escaped = [p for p in root.rglob("*") if p not in before and not str(p).startswith((str(out), str(staging)))]
            self.assertEqual(escaped, [])
            self.assertFalse((root / "evil").exists())

    def test_mixed_version_strings_do_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            tdir = home / ".claude" / "projects" / "-Users-jdoe-Development-proj"
            (tdir / "33333333-3333-4333-8333-333333333333.jsonl").write_text(
                json.dumps({"type": "user", "uuid": "u", "sessionId": "s", "timestamp": "t",
                            "cwd": "/Users/jdoe/Development/proj", "version": "2.1.dev",
                            "message": {"role": "user", "content": "x"}}) + "\n")
            code, out, _ = self.run_write(root, home)
            self.assertEqual(code, 0)

    def test_real_shaped_codex_rollout_passes_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            rollout = home / ".codex" / "sessions" / "2025" / "10" / "10" / "rollout-2025-10-10T13-46-23-0199cd31-4a62-7bc0-b411-9d5a2a198039.jsonl"
            rows = [json.loads(l) for l in rollout.read_text().splitlines()]
            rows[1]["payload"]["summary"] = "auto"
            rows[1]["payload"]["effort"] = "high"
            rows.append({"timestamp": "t", "type": "turn_context", "payload": {"cwd": "/Users/jdoe/Development/proj", "model": "gpt-5", "summary": "auto"}})
            rows.append({"timestamp": "t", "type": "response_item", "payload": {"type": "reasoning", "id": "rs_" + "0a1b2c3d4e5f6071" * 3,
                                                                                 "summary": [{"type": "summary_text", "text": "SECRET"}], "encrypted_content": "SECRET"}})
            rows.append({"timestamp": "t", "type": "event_msg", "payload": {"type": "turn_aborted", "reason": "interrupted"}})
            rollout.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            code, out, _ = self.run_write(root, home)
            self.assertEqual(code, 0)
            text = (out / "codex" / "0.46.0" / "sessions" / "2025" / "10" / "10" / rollout.name).read_text()
            self.assertEqual(text.count('"type":"turn_context"'), 2)
            self.assertNotIn("SECRET", text)

    def test_subagent_fixture_keeps_session_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            code, out, _ = self.run_write(root, home)
            self.assertEqual(code, 0)
            self.assertTrue((out / "claude/2.1.296/projects/-Users-you-proj-1/11111111-1111-4111-8111-111111111111/subagents/agent-abc.jsonl").is_file())

    def test_malformed_inputs_are_warnings_not_crashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            (home / ".claude" / "settings.local.json").write_text('{"hooks": {"note": "bad \\ud800 char"}}')
            deep = "[" * 100000 + "]" * 100000
            (home / ".claude" / "plugins" / "config.json").write_text(deep)
            events_dir = home / ".copilot" / "session-state" / "s1"
            events_dir.mkdir(parents=True)
            (events_dir / "events.jsonl").write_text('{"id":"1","type":"session.start","timestamp":"t","data":{}}\n{"id":"2","type":["weird"],"data":{}}\n')
            locked = home / ".claude" / "plugins" / "cache" / "claude-plugins-official" / "beta" / "1.0.0"
            locked.mkdir(parents=True)
            (locked / ".mcp.json").write_text("{}")
            os.chmod(locked, 0)
            try:
                code, out, _ = self.run_write(root, home)
            finally:
                os.chmod(locked, 0o700)
            self.assertEqual(code, 0)
            self.assertTrue((out / "claude/2.1.296/settings.local.json").is_file())

    def test_copy_refuses_when_a_destination_is_not_a_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self.build_home(root)
            out = root / "fixtures"
            (out / "codex" / "0.46.0" / "config.toml").mkdir(parents=True)
            code, out, _ = self.run_write(root, home)
            self.assertEqual(code, 1)
            self.assertFalse((out / "claude").exists())


if __name__ == "__main__":
    unittest.main()
