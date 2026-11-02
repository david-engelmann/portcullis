"""Tests for the portcullis decision engine and its command line.

Every test here pins one claim of the contract in CONTRACT.md and
can fail for a real reason. The fixtures are synthetic and written
for this repo.
"""

import hashlib
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from portcullis import core  # noqa: E402

AT = "2026-11-02T10:00:00+00:00"


def policy_doc(rules, default="deny"):
    return {"format": "portcullis-policy/1", "default": default, "rules": rules}


def rule(rule_id, kind, action, match, reason="a reason", substitute=None):
    doc = {
        "id": rule_id,
        "kind": kind,
        "action": action,
        "reason": reason,
        "match": match,
    }
    if substitute is not None:
        doc["substitute"] = substitute
    return doc


def shell_call(argv, **extra):
    doc = {"format": "portcullis-call/1", "kind": "shell", "argv": argv}
    doc.update(extra)
    return doc


def file_call(operation, path, **extra):
    doc = {
        "format": "portcullis-call/1",
        "kind": "file",
        "operation": operation,
        "path": path,
    }
    doc.update(extra)
    return doc


def network_call(method, host, port):
    return {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": method,
        "host": host,
        "port": port,
    }


def decide(doc, rules, default="deny"):
    policy = core.load_policy(policy_doc(rules, default))
    return core.evaluate(policy, None, doc, AT)


def write_json(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def run_cli(arguments, stdin_text=None):
    return subprocess.run(
        [sys.executable, "-m", "portcullis", *arguments],
        cwd=ROOT,
        input=stdin_text,
        capture_output=True,
        text=True,
    )


# --- the evaluation order battery ---------------------------------------


def test_deny_beats_allow_on_a_call_matching_both():
    rules = [
        rule("allow-rm", "shell", "allow", {"argv0": {"exact": "rm"}}),
        rule("deny-rm", "shell", "deny", {"argv0": {"exact": "rm"}}),
    ]
    decision = decide(shell_call(["rm", "x"]), rules)
    assert decision["decision"] == "deny"
    assert decision["source"] == {"type": "rule", "rule": "deny-rm"}


def test_first_matching_deny_rule_is_the_one_named():
    rules = [
        rule("deny-one", "shell", "deny", {"argv0": {"exact": "rm"}}),
        rule("deny-two", "shell", "deny", {"argv0": {"glob": "r*"}}),
    ]
    decision = decide(shell_call(["rm", "x"]), rules)
    assert decision["source"] == {"type": "rule", "rule": "deny-one"}


def test_a_rewrite_never_rescues_a_denied_call():
    rules = [
        rule(
            "soften-rm",
            "shell",
            "rewrite",
            {"argv0": {"exact": "rm"}},
            substitute={"argv": ["ls"]},
        ),
        rule("deny-rm", "shell", "deny", {"argv0": {"exact": "rm"}}),
    ]
    decision = decide(shell_call(["rm", "x"]), rules)
    assert decision["decision"] == "deny"
    assert decision["source"] == {"type": "rule", "rule": "deny-rm"}
    assert decision["rewritten_call"] is None


def test_first_matching_allow_wins_and_swapping_the_order_swaps_the_winner():
    first = rule("allow-a", "shell", "allow", {"argv0": {"glob": "l*"}})
    second = rule("allow-b", "shell", "allow", {"argv0": {"exact": "ls"}})
    call = shell_call(["ls"])
    assert decide(call, [first, second])["source"]["rule"] == "allow-a"
    assert decide(call, [second, first])["source"]["rule"] == "allow-b"


def test_the_default_is_named_when_no_rule_matches():
    rules = [rule("allow-ls", "shell", "allow", {"argv0": {"exact": "ls"}})]
    decision = decide(shell_call(["cat", "f"]), rules)
    assert decision["decision"] == "deny"
    assert decision["source"] == {"type": "default"}
    assert decision["reason"] is None


def test_a_declared_allow_default_allows_an_unmatched_call():
    decision = decide(shell_call(["cat", "f"]), [], default="allow")
    assert decision["decision"] == "allow"
    assert decision["source"] == {"type": "default"}


def test_malformed_is_denied_before_any_rule_fires_on_its_fields():
    rules = [rule("deny-rm", "shell", "deny", {"argv0": {"exact": "rm"}})]
    broken = shell_call(["rm", "x"])
    broken["argv"] = "rm x"
    decision = decide(broken, rules)
    assert decision["decision"] == "deny"
    assert decision["source"] == {"type": "malformed"}


def test_a_rule_for_another_kind_never_fires():
    rules = [rule("deny-rm", "shell", "deny", {"argv0": {"glob": "*"}})]
    decision = decide(file_call("read", "rm"), rules)
    assert decision["source"] == {"type": "default"}


# --- fail closed ----------------------------------------------------------


def test_an_invalid_rule_means_the_policy_does_not_load():
    doc = policy_doc([rule("bad", "shell", "allow", {})])
    with pytest.raises(core.PolicyError):
        core.load_policy(doc)


def test_every_schema_valid_call_is_denied_when_the_policy_cannot_load():
    doc = shell_call(["ls"])
    decision = core.evaluate(None, "the policy carries a rule of no use", doc, AT)
    assert decision["decision"] == "deny"
    assert decision["source"] == {
        "type": "policy error",
        "detail": "the policy carries a rule of no use",
    }


def test_a_malformed_call_is_malformed_even_when_the_policy_cannot_load():
    broken = shell_call(["ls"])
    broken["kind"] = "shell"
    broken["argv"] = []
    decision = core.evaluate(None, "the policy does not parse", broken, AT)
    assert decision["source"] == {"type": "malformed"}


def test_an_unparseable_policy_fails_closed_at_the_command_line(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{not json", encoding="utf-8")
    call_path = write_json(tmp_path / "call.json", shell_call(["ls"]))
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    assert result.returncode == 1
    decision = json.loads(result.stdout)
    assert decision["decision"] == "deny"
    assert decision["source"]["type"] == "policy error"
    assert decision["source"]["detail"]


def test_a_policy_with_duplicate_keys_fails_closed_at_the_command_line(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        '{"format": "portcullis-policy/1", "default": "deny", '
        '"default": "allow", "rules": []}',
        encoding="utf-8",
    )
    call_path = write_json(tmp_path / "call.json", shell_call(["ls"]))
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    assert result.returncode == 1
    decision = json.loads(result.stdout)
    assert decision["source"]["type"] == "policy error"


def test_an_unreadable_policy_file_fails_closed_at_the_command_line(tmp_path):
    call_path = write_json(tmp_path / "call.json", shell_call(["ls"]))
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        [
            "check",
            "--policy",
            str(tmp_path / "missing.json"),
            "--log",
            str(log_path),
            str(call_path),
        ]
    )
    assert result.returncode == 1
    decision = json.loads(result.stdout)
    assert decision["decision"] == "deny"
    assert decision["source"]["type"] == "policy error"


# --- rewrites ---------------------------------------------------------------


def test_a_rewrite_carries_the_complete_call_with_other_fields_intact():
    rules = [
        rule(
            "stage-writes",
            "file",
            "rewrite",
            {"operation": {"exact": "write"}, "path": {"prefix": "/work/out/"}},
            reason="writes land in staging",
            substitute={"path": "/work/staging/out.txt"},
        )
    ]
    decision = decide(file_call("write", "/work/out/report.txt"), rules)
    assert decision["decision"] == "rewrite"
    assert decision["source"] == {"type": "rule", "rule": "stage-writes"}
    assert decision["reason"] == "writes land in staging"
    rewritten = decision["rewritten_call"]
    assert rewritten["path"] == "/work/staging/out.txt"
    assert rewritten["operation"] == "write"
    assert rewritten["kind"] == "file"
    assert rewritten["format"] == "portcullis-call/1"


def test_a_shell_rewrite_replaces_argv_and_keeps_cwd():
    rules = [
        rule(
            "calm-curl",
            "shell",
            "rewrite",
            {"argv0": {"exact": "curl"}},
            substitute={"argv": ["curl", "--fail", "--silent"]},
        )
    ]
    decision = decide(shell_call(["curl", "http://x"], cwd="/work"), rules)
    assert decision["decision"] == "rewrite"
    assert decision["rewritten_call"]["argv"] == ["curl", "--fail", "--silent"]
    assert decision["rewritten_call"]["cwd"] == "/work"


def test_a_rewrite_whose_result_fails_validation_denies_with_the_rule_named():
    rules = [
        rule(
            "careless-move",
            "file",
            "rewrite",
            {"operation": {"exact": "read"}},
            substitute={"operation": "move"},
        )
    ]
    decision = decide(file_call("read", "/work/a.txt"), rules)
    assert decision["decision"] == "deny"
    assert decision["source"] == {"type": "rule", "rule": "careless-move"}
    assert decision["rewritten_call"] is None


def test_a_rewrite_of_a_url_call_emits_the_explicit_form():
    rules = [
        rule(
            "pin-port",
            "network",
            "rewrite",
            {"host": {"exact": "api.example.test"}},
            substitute={"port": 8443},
        )
    ]
    call = {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "GET",
        "url": "https://api.example.test/items",
    }
    decision = decide(call, rules)
    assert decision["decision"] == "rewrite"
    rewritten = decision["rewritten_call"]
    assert rewritten["host"] == "api.example.test"
    assert rewritten["port"] == 8443
    assert rewritten["method"] == "GET"
    assert "url" not in rewritten


# --- the interpreter marker ---------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", "-c", "ls"],
        ["bash", "-c", "ls"],
        ["/bin/sh", "-c", "ls"],
        ["/usr/bin/bash", "script.sh"],
        ["./zsh", "-l"],
    ],
)
def test_interpreter_calls_are_flagged(argv):
    decision = decide(shell_call(argv), [], default="allow")
    assert decision["interpreter"] is True


@pytest.mark.parametrize(
    "argv",
    [
        ["ls", "-la"],
        ["python3", "-c", "print(1)"],
        ["shellcheck", "x"],
        ["rm", "x"],
    ],
)
def test_non_interpreter_calls_are_not_flagged(argv):
    decision = decide(shell_call(argv), [], default="allow")
    assert decision["interpreter"] is False


def test_a_malformed_shell_call_is_not_flagged():
    broken = shell_call(["sh", "-c", "ls"])
    broken["argv"] = "sh -c ls"
    decision = decide(broken, [], default="allow")
    assert decision["source"] == {"type": "malformed"}
    assert decision["interpreter"] is False


def test_file_and_network_calls_are_not_flagged():
    assert decide(file_call("read", "/bin/sh"), [], default="allow")["interpreter"] is False
    net = decide(network_call("GET", "example.test", 443), [], default="allow")
    assert net["interpreter"] is False


# --- matching -----------------------------------------------------------------


def test_a_path_rule_fires_on_the_given_form():
    rules = [
        rule("deny-raw", "file", "deny", {"path": {"glob": "*/../secret.txt"}})
    ]
    decision = decide(file_call("read", "a/../secret.txt"), rules)
    assert decision["decision"] == "deny"
    assert decision["source"]["rule"] == "deny-raw"


def test_a_path_rule_fires_only_on_the_normalized_form():
    rules = [rule("deny-secret", "file", "deny", {"path": {"exact": "secret.txt"}})]
    decision = decide(file_call("read", "a/../secret.txt"), rules)
    assert decision["decision"] == "deny"
    assert decision["source"]["rule"] == "deny-secret"


def test_a_path_prefix_matches_the_normalized_form():
    rules = [
        rule("deny-etc", "file", "deny", {"path": {"prefix": "/etc/"}})
    ]
    decision = decide(file_call("write", "/tmp/../etc/hosts"), rules)
    assert decision["decision"] == "deny"


def test_an_argument_condition_fails_when_argv_is_too_short():
    rules = [
        rule(
            "deny-third",
            "shell",
            "deny",
            {"args": [{"index": 3, "match": {"exact": "x"}}]},
        )
    ]
    decision = decide(shell_call(["tool", "a"]), rules)
    assert decision["source"] == {"type": "default"}


def test_an_argument_condition_matches_at_its_position():
    rules = [
        rule(
            "deny-flag",
            "shell",
            "deny",
            {"args": [{"index": 2, "match": {"exact": "--force"}}]},
        )
    ]
    decision = decide(shell_call(["tool", "run", "--force"]), rules)
    assert decision["decision"] == "deny"


def test_host_matching_folds_case_on_both_sides():
    rules = [
        rule("allow-api", "network", "allow", {"host": {"exact": "API.example.TEST"}})
    ]
    decision = decide(network_call("GET", "api.EXAMPLE.test", 443), rules)
    assert decision["decision"] == "allow"


def test_method_matching_is_case_sensitive_as_given():
    rules = [rule("allow-get", "network", "allow", {"method": {"exact": "GET"}})]
    assert decide(network_call("get", "h.test", 80), rules)["decision"] == "deny"
    assert decide(network_call("GET", "h.test", 80), rules)["decision"] == "allow"


def test_a_port_matcher_matches_the_exact_port_only():
    rules = [rule("allow-tls", "network", "allow", {"port": {"exact": 443}})]
    assert decide(network_call("GET", "h.test", 443), rules)["decision"] == "allow"
    assert decide(network_call("GET", "h.test", 8443), rules)["decision"] == "deny"


def test_a_url_call_reads_its_host_and_default_port():
    rules = [
        rule(
            "allow-https",
            "network",
            "allow",
            {"host": {"exact": "example.test"}, "port": {"exact": 443}},
        )
    ]
    call = {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "GET",
        "url": "https://EXAMPLE.test/items",
    }
    assert decide(call, rules)["decision"] == "allow"


def test_a_url_call_reads_an_explicit_port():
    rules = [rule("allow-alt", "network", "allow", {"port": {"exact": 8080}})]
    call = {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "GET",
        "url": "http://example.test:8080/items",
    }
    assert decide(call, rules)["decision"] == "allow"


# --- strict reading of calls ----------------------------------------------------


MALFORMED_CALLS = [
    {"format": "portcullis-call/1", "kind": "shell"},
    {"format": "portcullis-call/1", "kind": "shell", "argv": []},
    {"format": "portcullis-call/1", "kind": "shell", "argv": ["ls", 3]},
    {"format": "portcullis-call/1", "kind": "shell", "argv": ["ls"], "path": "x"},
    {"format": "portcullis-call/1", "kind": "file", "operation": "read"},
    {"format": "portcullis-call/1", "kind": "file", "operation": "peek", "path": "x"},
    {"format": "portcullis-call/1", "kind": "file", "operation": "move", "path": "x"},
    {
        "format": "portcullis-call/1",
        "kind": "file",
        "operation": "read",
        "path": "x",
        "path2": "y",
    },
    {"format": "portcullis-call/1", "kind": "file", "operation": "read", "path": ""},
    {"format": "other/9", "kind": "shell", "argv": ["ls"]},
    {"format": "portcullis-call/1", "kind": "teleport", "argv": ["ls"]},
    {"format": "portcullis-call/1", "kind": "network", "method": "GET"},
    {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "GET",
        "host": "h.test",
        "port": True,
    },
    {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "GET",
        "host": "h.test",
        "port": 70000,
    },
    {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "GET",
        "host": "h.test",
        "port": 443,
        "url": "https://h.test/",
    },
    {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "GET",
        "url": "https://user:pw@h.test/",
    },
    {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "GET",
        "url": "gopher://h.test/",
    },
    ["not", "an", "object"],
]


@pytest.mark.parametrize("document", MALFORMED_CALLS)
def test_malformed_call_shapes_are_denied_as_malformed(document):
    decision = decide(document, [], default="allow")
    assert decision["decision"] == "deny"
    assert decision["source"] == {"type": "malformed"}


def test_a_call_with_duplicate_keys_never_reaches_a_decision(tmp_path):
    call_path = tmp_path / "call.json"
    call_path.write_text(
        '{"format": "portcullis-call/1", "kind": "shell", '
        '"kind": "shell", "argv": ["ls"]}',
        encoding="utf-8",
    )
    policy_path = write_json(tmp_path / "policy.json", policy_doc([]))
    result = run_cli(
        [
            "check",
            "--policy",
            str(policy_path),
            "--log",
            str(tmp_path / "audit.jsonl"),
            str(call_path),
        ]
    )
    assert result.returncode == 2
    assert result.stdout == ""


def test_a_call_with_a_nonstandard_constant_is_a_caller_error(tmp_path):
    call_path = tmp_path / "call.json"
    call_path.write_text(
        '{"format": "portcullis-call/1", "kind": "shell", "argv": [NaN]}',
        encoding="utf-8",
    )
    policy_path = write_json(tmp_path / "policy.json", policy_doc([]))
    result = run_cli(
        [
            "check",
            "--policy",
            str(policy_path),
            "--log",
            str(tmp_path / "audit.jsonl"),
            str(call_path),
        ]
    )
    assert result.returncode == 2


# --- strict reading of policies -------------------------------------------


BAD_POLICIES = [
    {"format": "portcullis-policy/1", "rules": []},
    {"format": "portcullis-policy/1", "default": "rewrite", "rules": []},
    {"format": "portcullis-policy/1", "default": "deny", "rules": [], "extra": 1},
    {"format": "other/9", "default": "deny", "rules": []},
    policy_doc(
        [
            rule("dup", "shell", "allow", {"argv0": {"exact": "ls"}}),
            rule("dup", "shell", "deny", {"argv0": {"exact": "rm"}}),
        ]
    ),
    policy_doc([rule("empty", "shell", "allow", {})]),
    policy_doc(
        [rule("two-forms", "shell", "allow", {"argv0": {"exact": "ls", "prefix": "l"}})]
    ),
    policy_doc(
        [
            rule(
                "no-sub",
                "shell",
                "rewrite",
                {"argv0": {"exact": "ls"}},
            )
        ]
    ),
    policy_doc(
        [
            rule(
                "stray-sub",
                "shell",
                "allow",
                {"argv0": {"exact": "ls"}},
                substitute={"argv": ["ls"]},
            )
        ]
    ),
    policy_doc([rule("quiet", "shell", "allow", {"argv0": {"exact": "ls"}}, reason="")]),
    policy_doc(
        [rule("bad-port", "network", "allow", {"port": {"glob": "44*"}})]
    ),
    policy_doc(
        [
            rule(
                "bad-index",
                "shell",
                "allow",
                {"args": [{"index": 0, "match": {"exact": "x"}}]},
            )
        ]
    ),
    policy_doc(
        [rule("bad-kind", "teleport", "allow", {"argv0": {"exact": "ls"}})]
    ),
]


@pytest.mark.parametrize("document", BAD_POLICIES)
def test_bad_policy_shapes_never_load(document):
    with pytest.raises(core.PolicyError):
        core.load_policy(document)


def test_a_policy_with_duplicate_keys_does_not_parse_strictly():
    text = (
        '{"format": "portcullis-policy/1", "default": "deny", '
        '"rules": [{"id": "a", "id": "a", "kind": "shell", "action": "allow", '
        '"reason": "r", "match": {"argv0": {"exact": "ls"}}}]}'
    )
    with pytest.raises(ValueError):
        core.strict_parse(text)


# --- the decision record -----------------------------------------------------


def test_the_decision_record_carries_every_field_of_the_contract():
    rules = [rule("allow-ls", "shell", "allow", {"argv0": {"exact": "ls"}})]
    decision = decide(shell_call(["ls"]), rules)
    assert set(decision) == {
        "format",
        "at",
        "call_digest",
        "decision",
        "source",
        "reason",
        "interpreter",
        "rewritten_call",
    }
    assert decision["format"] == "portcullis-decision/1"
    assert decision["at"] == AT
    canonical = json.dumps(
        shell_call(["ls"]), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert decision["call_digest"] == "sha256:" + hashlib.sha256(canonical).hexdigest()
    assert decision["reason"] == "a reason"
    assert decision["rewritten_call"] is None


def test_the_same_policy_and_call_decide_the_same_apart_from_the_instant():
    rules = [rule("allow-ls", "shell", "allow", {"argv0": {"exact": "ls"}})]
    policy = core.load_policy(policy_doc(rules))
    call = shell_call(["ls"])
    first = core.evaluate(policy, None, call, "2026-11-02T10:00:00+00:00")
    second = core.evaluate(policy, None, call, "2026-11-02T11:00:00+00:00")
    first.pop("at")
    second.pop("at")
    assert first == second


# --- the audit log -------------------------------------------------------------


def test_appended_decisions_read_back_whole(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    decision = decide(shell_call(["ls"]), [], default="allow")
    core.append_decision(log_path, decision)
    records = core.read_log(log_path)
    assert records == [decision]


def _parallel_check_worker(task):
    policy_path, call_path, log_path = task
    return run_cli(
        ["check", "--policy", policy_path, "--log", log_path, call_path]
    ).returncode


def test_parallel_checks_append_whole_lines_only(tmp_path):
    policy_path = write_json(
        tmp_path / "policy.json",
        policy_doc([rule("allow-ls", "shell", "allow", {"argv0": {"exact": "ls"}})]),
    )
    call_path = write_json(tmp_path / "call.json", shell_call(["ls"]))
    log_path = tmp_path / "audit.jsonl"
    tasks = [(str(policy_path), str(call_path), str(log_path))] * 40
    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(_parallel_check_worker, tasks))
    assert codes == [0] * 40
    records = core.read_log(log_path)
    assert len(records) == 40
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 40
    for line in lines:
        json.loads(line)


def test_a_torn_final_line_is_reported_at_its_line(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    decision = decide(shell_call(["ls"]), [], default="allow")
    core.append_decision(log_path, decision)
    core.append_decision(log_path, decision)
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write('{"format": "portcullis-decision/1", "at": "2026-')
    result = run_cli(["log", "--log", str(log_path)])
    assert result.returncode == 1
    assert "line 3" in result.stderr


def test_a_spoiled_middle_line_is_reported_at_its_line(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    decision = decide(shell_call(["ls"]), [], default="allow")
    core.append_decision(log_path, decision)
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write('{"format": "portcullis-decision/1"}\n')
    core.append_decision(log_path, decision)
    result = run_cli(["log", "--log", str(log_path)])
    assert result.returncode == 1
    assert "line 2" in result.stderr


def test_a_decision_that_cannot_be_appended_is_not_delivered(tmp_path):
    policy_path = write_json(tmp_path / "policy.json", policy_doc([]))
    call_path = write_json(tmp_path / "call.json", shell_call(["ls"]))
    log_path = tmp_path / "no-such-dir" / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "could not be appended" in result.stderr


def test_the_log_command_prints_verified_records(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    decision = decide(shell_call(["ls"]), [], default="allow")
    core.append_decision(log_path, decision)
    result = run_cli(["log", "--log", str(log_path)])
    assert result.returncode == 0
    printed = [json.loads(line) for line in result.stdout.splitlines()]
    assert printed == [decision]


def test_the_log_command_treats_a_missing_log_as_a_caller_error(tmp_path):
    result = run_cli(["log", "--log", str(tmp_path / "missing.jsonl")])
    assert result.returncode == 2


# --- the command line -----------------------------------------------------------


def _cli_check(tmp_path, call_doc, rules, default="deny", stdin=False):
    policy_path = write_json(tmp_path / "policy.json", policy_doc(rules, default))
    log_path = tmp_path / "audit.jsonl"
    if stdin:
        return run_cli(
            ["check", "--policy", str(policy_path), "--log", str(log_path)],
            stdin_text=json.dumps(call_doc),
        )
    call_path = write_json(tmp_path / "call.json", call_doc)
    return run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )


def test_cli_allow_exits_zero(tmp_path):
    result = _cli_check(
        tmp_path,
        shell_call(["ls"]),
        [rule("allow-ls", "shell", "allow", {"argv0": {"exact": "ls"}})],
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["decision"] == "allow"


def test_cli_rewrite_exits_zero(tmp_path):
    result = _cli_check(
        tmp_path,
        file_call("write", "/work/out/a.txt"),
        [
            rule(
                "stage",
                "file",
                "rewrite",
                {"path": {"prefix": "/work/out/"}},
                substitute={"path": "/work/staging/a.txt"},
            )
        ],
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["decision"] == "rewrite"


def test_cli_deny_by_rule_exits_one(tmp_path):
    result = _cli_check(
        tmp_path,
        shell_call(["rm", "x"]),
        [rule("deny-rm", "shell", "deny", {"argv0": {"exact": "rm"}})],
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["decision"] == "deny"


def test_cli_malformed_exits_one(tmp_path):
    result = _cli_check(tmp_path, {"format": "portcullis-call/1", "kind": "shell"}, [])
    assert result.returncode == 1
    assert json.loads(result.stdout)["source"] == {"type": "malformed"}


def test_cli_reads_a_call_from_standard_input(tmp_path):
    result = _cli_check(
        tmp_path,
        shell_call(["ls"]),
        [rule("allow-ls", "shell", "allow", {"argv0": {"exact": "ls"}})],
        stdin=True,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["decision"] == "allow"


def test_cli_an_unparseable_call_exits_two(tmp_path):
    policy_path = write_json(tmp_path / "policy.json", policy_doc([]))
    call_path = tmp_path / "call.json"
    call_path.write_text("this is not json", encoding="utf-8")
    result = run_cli(
        [
            "check",
            "--policy",
            str(policy_path),
            "--log",
            str(tmp_path / "audit.jsonl"),
            str(call_path),
        ]
    )
    assert result.returncode == 2
    assert result.stdout == ""


def test_cli_a_missing_call_file_exits_two(tmp_path):
    policy_path = write_json(tmp_path / "policy.json", policy_doc([]))
    result = run_cli(
        [
            "check",
            "--policy",
            str(policy_path),
            "--log",
            str(tmp_path / "audit.jsonl"),
            str(tmp_path / "missing.json"),
        ]
    )
    assert result.returncode == 2


def test_cli_bad_arguments_exit_two(tmp_path):
    result = run_cli(["check", "--log", str(tmp_path / "audit.jsonl")])
    assert result.returncode == 2


def test_cli_check_appends_the_decision_it_prints(tmp_path):
    policy_path = write_json(tmp_path / "policy.json", policy_doc([]))
    call_path = write_json(tmp_path / "call.json", shell_call(["ls"]))
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    printed = json.loads(result.stdout)
    assert core.read_log(log_path) == [printed]


# --- repair pass pins ---------------------------------------------------------


def test_rewrite_into_an_interpreter_call_is_flagged():
    rules = [
        rule(
            "become-shell",
            "shell",
            "rewrite",
            {"argv0": {"exact": "ls"}},
            substitute={"argv": ["sh", "-c", "id"]},
        )
    ]
    decision = decide(shell_call(["ls"]), rules)
    assert decision["decision"] == "rewrite"
    assert decision["rewritten_call"]["argv"] == ["sh", "-c", "id"]
    assert decision["interpreter"] is True


def test_an_interpreter_call_rewritten_to_a_harmless_call_stays_flagged():
    rules = [
        rule(
            "calm-shell",
            "shell",
            "rewrite",
            {"argv0": {"exact": "sh"}},
            substitute={"argv": ["echo", "hi"]},
        )
    ]
    decision = decide(shell_call(["sh", "-c", "ls"]), rules)
    assert decision["decision"] == "rewrite"
    assert decision["rewritten_call"]["argv"] == ["echo", "hi"]
    assert decision["interpreter"] is True


def _write_log_lines(log_path, records):
    with open(log_path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    return log_path


def _valid_allow_record():
    rules = [rule("allow-ls", "shell", "allow", {"argv0": {"exact": "ls"}})]
    return decide(shell_call(["ls"]), rules)


def _valid_rewrite_record():
    rules = [
        rule(
            "stage",
            "shell",
            "rewrite",
            {"argv0": {"exact": "ls"}},
            substitute={"argv": ["ls", "-la"]},
        )
    ]
    return decide(shell_call(["ls"]), rules)


def _assert_corruption_at_line_two(tmp_path, tampered):
    log_path = tmp_path / "audit.jsonl"
    _write_log_lines(log_path, [_valid_allow_record(), tampered])
    with pytest.raises(core.LogCorruptionError) as caught:
        core.read_log(log_path)
    assert caught.value.line_number == 2


def test_a_rewrite_record_with_an_invalid_rewritten_call_is_corruption(tmp_path):
    tampered = _valid_rewrite_record()
    tampered["rewritten_call"] = {
        "format": "portcullis-call/1",
        "kind": "shell",
        "argv": [],
    }
    _assert_corruption_at_line_two(tmp_path, tampered)


def test_a_non_rewrite_record_carrying_a_rewritten_call_is_corruption(tmp_path):
    tampered = _valid_allow_record()
    tampered["rewritten_call"] = shell_call(["ls"])
    _assert_corruption_at_line_two(tmp_path, tampered)


def _tamper(**changes):
    record = _valid_allow_record()
    record.update(changes)
    return record


CROSS_FIELD_TAMPERS = [
    _tamper(source={"type": "malformed"}),
    _tamper(
        decision="deny", source={"type": "malformed"}, reason="a reason"
    ),
    _tamper(
        decision="deny", source={"type": "malformed"}, interpreter=True
    ),
    _tamper(source={"type": "policy error", "detail": "a failure"}),
    _tamper(reason=None),
    _tamper(reason=""),
    _tamper(
        decision="deny", source={"type": "default"}, reason="a reason"
    ),
]


@pytest.mark.parametrize("tampered", CROSS_FIELD_TAMPERS)
def test_log_records_whose_fields_disagree_are_corruption(tmp_path, tampered):
    _assert_corruption_at_line_two(tmp_path, tampered)


def test_a_rewrite_record_with_a_default_source_is_corruption(tmp_path):
    tampered = _valid_rewrite_record()
    tampered["source"] = {"type": "default"}
    tampered["reason"] = None
    _assert_corruption_at_line_two(tmp_path, tampered)


def test_a_log_record_with_a_non_hex_digest_is_corruption(tmp_path):
    tampered = _tamper(call_digest="sha256:" + "z" * 64)
    _assert_corruption_at_line_two(tmp_path, tampered)


def test_a_policy_with_invalid_utf8_fails_closed_at_the_command_line(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(b"\xff\xfe\xfd")
    call_path = write_json(tmp_path / "call.json", shell_call(["ls"]))
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    decision = json.loads(result.stdout)
    assert decision["decision"] == "deny"
    assert decision["source"]["type"] == "policy error"
    assert len(core.read_log(log_path)) == 1


def test_a_call_with_invalid_utf8_is_a_caller_error_at_the_command_line(tmp_path):
    policy_path = write_json(tmp_path / "policy.json", policy_doc([]))
    call_path = tmp_path / "call.json"
    call_path.write_bytes(b"\xff\xfe\xfd")
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert result.stderr.count("\n") == 1
    assert not log_path.exists()


def test_strict_parse_refuses_a_lone_surrogate():
    text = '{"format": "portcullis-call/1", "kind": "shell", "argv": ["\\ud800"]}'
    with pytest.raises(ValueError):
        core.strict_parse(text)


def test_a_call_with_a_lone_surrogate_is_a_caller_error(tmp_path):
    policy_path = write_json(tmp_path / "policy.json", policy_doc([]))
    call_path = tmp_path / "call.json"
    call_path.write_text(
        '{"format": "portcullis-call/1", "kind": "shell", "argv": ["\\ud800"]}',
        encoding="utf-8",
    )
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert not log_path.exists()


def test_a_policy_with_a_lone_surrogate_fails_closed(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        '{"format": "portcullis-policy/1", "default": "deny", "rules": '
        '[{"id": "a", "kind": "shell", "action": "allow", '
        '"reason": "\\ud800", "match": {"argv0": {"exact": "ls"}}}]}',
        encoding="utf-8",
    )
    call_path = write_json(tmp_path / "call.json", shell_call(["ls"]))
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    decision = json.loads(result.stdout)
    assert decision["decision"] == "deny"
    assert decision["source"]["type"] == "policy error"


@pytest.mark.parametrize(
    "condition",
    [
        {"match": {"exact": "x"}},
        {"index": 1},
    ],
)
def test_an_argument_condition_missing_a_key_never_loads(condition):
    doc = policy_doc(
        [rule("bad-cond", "shell", "allow", {"args": [condition]})]
    )
    with pytest.raises(core.PolicyError):
        core.load_policy(doc)


@pytest.mark.parametrize(
    "condition",
    [
        {"match": {"exact": "x"}},
        {"index": 1},
    ],
)
def test_an_argument_condition_missing_a_key_fails_closed_at_the_cli(
    tmp_path, condition
):
    policy_path = write_json(
        tmp_path / "policy.json",
        policy_doc([rule("bad-cond", "shell", "allow", {"args": [condition]})]),
    )
    call_path = write_json(tmp_path / "call.json", shell_call(["ls", "x"]))
    log_path = tmp_path / "audit.jsonl"
    result = run_cli(
        ["check", "--policy", str(policy_path), "--log", str(log_path), str(call_path)]
    )
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    decision = json.loads(result.stdout)
    assert decision["decision"] == "deny"
    assert decision["source"]["type"] == "policy error"


def test_an_undecodable_log_line_is_corruption_at_its_line(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    decision = _valid_allow_record()
    core.append_decision(log_path, decision)
    with open(log_path, "ab") as handle:
        handle.write(b"\xff\xfe\n")
    with pytest.raises(core.LogCorruptionError) as caught:
        core.read_log(log_path)
    assert caught.value.line_number == 2
    result = run_cli(["log", "--log", str(log_path)])
    assert result.returncode == 1
    assert "line 2" in result.stderr


def test_an_empty_file_path_message_is_truthful():
    with pytest.raises(core.MalformedCall) as caught:
        core.validate_call(file_call("read", ""))
    assert "of no use" in str(caught.value)
    assert "is not a string" not in str(caught.value)


def test_an_empty_network_method_message_is_truthful():
    with pytest.raises(core.MalformedCall) as caught:
        core.validate_call(network_call("", "h.test", 80))
    assert "of no use" in str(caught.value)
    assert "is not a string" not in str(caught.value)


def test_an_empty_network_host_message_is_truthful():
    with pytest.raises(core.MalformedCall) as caught:
        core.validate_call(network_call("GET", "", 80))
    assert "of no use" in str(caught.value)
    assert "is not a string" not in str(caught.value)


def test_an_empty_rule_reason_message_is_truthful():
    doc = policy_doc(
        [rule("quiet", "shell", "allow", {"argv0": {"exact": "ls"}}, reason="")]
    )
    with pytest.raises(core.PolicyError) as caught:
        core.load_policy(doc)
    assert "of no use" in str(caught.value)
    assert "is not a string" not in str(caught.value)
