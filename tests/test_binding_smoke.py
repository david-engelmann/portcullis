"""Consumer proof for the portcullis Python binding.

The Rust suite is the gate. This suite proves the binding
carries the library's behaviour to a Python caller unchanged,
decisions, digests, log records, and refusal texts alike, and
that a log written on one surface reads back whole on the
other. It runs against the binding built by maturin, and it
drives the command line binary for the cross surface checks.
"""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

import portcullis

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
AT = "2026-11-02T10:00:00+00:00"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def cli_binary():
    named = os.environ.get("PORTCULLIS_BIN")
    if named:
        return Path(named)
    subprocess.run(
        ["cargo", "build", "--bin", "portcullis"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    target = os.environ.get("CARGO_TARGET_DIR")
    candidates = []
    if target:
        candidates.append(Path(target) / "debug" / "portcullis")
    candidates.append(REPO_ROOT / "target" / "debug" / "portcullis")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise AssertionError("the portcullis binary did not build")


def run_cli(*args, stdin_text=None):
    return subprocess.run(
        [str(cli_binary()), *args],
        input=stdin_text,
        capture_output=True,
        text=True,
    )


class IndexOnly:
    """An object that offers an index and no integer value."""

    def __index__(self):
        return 443


class ForgedBytesInt(int):
    """An int whose to_bytes claims the value is one byte."""

    def to_bytes(self, length, byteorder, *, signed=False):
        return b"\x01"


class EmptyBytesInt(int):
    """An int whose to_bytes hands back no bytes at all."""

    def to_bytes(self, length, byteorder, *, signed=False):
        return b""


class ForgedBitLengthInt(int):
    """An int whose bit_length claims the value is tiny."""

    def bit_length(self):
        return 8


class LyingDict(dict):
    """A dict whose items method invents pairs it does not hold."""

    def items(self):
        return [("format", "portcullis-call/1"), ("kind", "file")]


def network_call(port):
    return {
        "format": "portcullis-call/1",
        "kind": "network",
        "method": "POST",
        "host": "hooks.example.test",
        "port": port,
    }


def test_the_fixture_outcomes_come_back_unchanged(tmp_path):
    policy = fixture("policy-full.json")
    log = tmp_path / "audit.jsonl"
    pairs = [
        ("call-shell-deny.json", "policy-full--call-shell-deny.json"),
        ("call-shell-allow.json", "policy-full--call-shell-allow.json"),
        ("call-file-rewrite.json", "policy-full--call-file-rewrite.json"),
        ("call-malformed.json", "policy-full--call-malformed.json"),
        ("call-network-url.json", "policy-full--call-network-url.json"),
    ]
    for call_name, expected_name in pairs:
        decision = portcullis.check(policy, fixture(call_name), log, AT)
        assert decision == fixture(f"expected/{expected_name}")
    records = portcullis.read_log(log)
    assert [record["decision"] for record in records] == [
        "deny",
        "allow",
        "rewrite",
        "deny",
        "allow",
    ]


def test_deny_beats_allow_on_a_call_matching_both(tmp_path):
    policy = {
        "format": "portcullis-policy/1",
        "default": "deny",
        "rules": [
            {
                "id": "allow-rm",
                "kind": "shell",
                "action": "allow",
                "reason": "removal is allowed by this rule",
                "match": {"argv0": {"exact": "rm"}},
            },
            {
                "id": "deny-rm",
                "kind": "shell",
                "action": "deny",
                "reason": "removal is not run directly",
                "match": {"argv0": {"exact": "rm"}},
            },
        ],
    }
    call = {"format": "portcullis-call/1", "kind": "shell", "argv": ["rm", "x"]}
    decision = portcullis.check(policy, call, tmp_path / "audit.jsonl", AT)
    assert decision["decision"] == "deny"
    assert decision["source"] == {"rule": "deny-rm", "type": "rule"}
    assert decision["reason"] == "removal is not run directly"


def test_a_rewrite_is_delivered_without_reevaluation(tmp_path):
    policy = {
        "format": "portcullis-policy/1",
        "default": "deny",
        "rules": [
            {
                "id": "deny-staging",
                "kind": "file",
                "action": "deny",
                "reason": "the staging path is never written directly",
                "match": {"path": {"exact": "/work/staging/out.txt"}},
            },
            {
                "id": "stage-writes",
                "kind": "file",
                "action": "rewrite",
                "reason": "writes land in staging",
                "match": {
                    "operation": {"exact": "write"},
                    "path": {"prefix": "/work/out/"},
                },
                "substitute": {"path": "/work/staging/out.txt"},
            },
        ],
    }
    call = {
        "format": "portcullis-call/1",
        "kind": "file",
        "operation": "write",
        "path": "/work/out/report.txt",
    }
    log = tmp_path / "audit.jsonl"
    decision = portcullis.check(policy, call, log, AT)
    assert decision["decision"] == "rewrite"
    assert decision["source"] == {"rule": "stage-writes", "type": "rule"}
    assert decision["rewritten_call"]["path"] == "/work/staging/out.txt"
    direct = portcullis.check(
        policy,
        {
            "format": "portcullis-call/1",
            "kind": "file",
            "operation": "write",
            "path": "/work/staging/out.txt",
        },
        log,
        AT,
    )
    assert direct["decision"] == "deny"
    assert direct["source"] == {"rule": "deny-staging", "type": "rule"}


def test_a_broken_policy_denies_everything_as_a_policy_error(tmp_path):
    log = tmp_path / "audit.jsonl"
    decision = portcullis.check(
        fixture("policy-broken.json"), fixture("call-shell-allow.json"), log, AT
    )
    assert decision["decision"] == "deny"
    assert decision["source"] == {
        "detail": "the match of rule empty holds no condition",
        "type": "policy error",
    }
    assert decision["reason"] is None
    assert decision["rewritten_call"] is None
    assert portcullis.read_log(log) == [decision]


def test_a_scalar_policy_denies_as_a_policy_error(tmp_path):
    decision = portcullis.check(
        42, fixture("call-shell-allow.json"), tmp_path / "audit.jsonl", AT
    )
    assert decision["decision"] == "deny"
    assert decision["source"] == {
        "detail": "the policy is not a JSON object",
        "type": "policy error",
    }


def test_a_scalar_call_is_a_malformed_deny(tmp_path):
    decision = portcullis.check(
        fixture("policy-full.json"), ["rm", "x"], tmp_path / "audit.jsonl", AT
    )
    assert decision["decision"] == "deny"
    assert decision["source"] == {"type": "malformed"}
    assert decision["reason"] is None


def test_a_wide_integer_in_the_policy_denies_as_a_policy_error(tmp_path):
    policy = {
        "format": "portcullis-policy/1",
        "default": "deny",
        "rules": [
            {
                "id": "wide-port",
                "kind": "network",
                "action": "allow",
                "reason": "a wide port",
                "match": {
                    "host": {"exact": "hooks.example.test"},
                    "port": {"exact": 10**5000},
                },
            }
        ],
    }
    log = tmp_path / "audit.jsonl"
    decision = portcullis.check(policy, network_call(8443), log, AT)
    assert decision["decision"] == "deny"
    assert decision["source"] == {
        "detail": "the document carries an integer too wide to parse",
        "type": "policy error",
    }
    assert portcullis.read_log(log) == [decision]


def test_the_instant_is_recorded_verbatim(tmp_path):
    log = tmp_path / "audit.jsonl"
    policy = fixture("policy-full.json")
    call = fixture("call-shell-allow.json")
    first = portcullis.check(policy, call, log, "2031-03-04T05:06:07+00:00")
    second = portcullis.check(policy, call, log, "1999-12-31T23:59:59+00:00")
    assert first["at"] == "2031-03-04T05:06:07+00:00"
    assert second["at"] == "1999-12-31T23:59:59+00:00"
    assert [record["at"] for record in portcullis.read_log(log)] == [
        "2031-03-04T05:06:07+00:00",
        "1999-12-31T23:59:59+00:00",
    ]


def test_the_log_agrees_between_the_binding_and_the_cli(tmp_path):
    policy = fixture("policy-full.json")
    log = tmp_path / "audit.jsonl"
    decisions = [
        portcullis.check(policy, fixture("call-shell-allow.json"), log, AT),
        portcullis.check(policy, fixture("call-shell-deny.json"), log, AT),
        portcullis.check(policy, fixture("call-file-rewrite.json"), log, AT),
    ]
    assert portcullis.read_log(log) == decisions
    shown = run_cli("log", "--log", str(log))
    assert shown.returncode == 0, shown.stderr
    assert [json.loads(line) for line in shown.stdout.splitlines()] == decisions

    cli_log = tmp_path / "cli-audit.jsonl"
    policy_path = tmp_path / "policy.json"
    call_path = tmp_path / "call.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    call_path.write_text(
        json.dumps(fixture("call-shell-deny.json")), encoding="utf-8"
    )
    judged = run_cli(
        "check", "--policy", str(policy_path), "--log", str(cli_log), str(call_path)
    )
    assert judged.returncode == 1, judged.stderr
    printed = json.loads(judged.stdout)
    records = portcullis.read_log(cli_log)
    assert len(records) == 1
    assert records[0] == printed
    via_binding = portcullis.check(
        policy, fixture("call-shell-deny.json"), tmp_path / "other.jsonl", AT
    )
    shared = {
        key: value for key, value in via_binding.items() if key != "at"
    }
    assert {key: value for key, value in records[0].items() if key != "at"} == shared

    follow_up = portcullis.check(
        policy, fixture("call-shell-allow.json"), cli_log, AT
    )
    shown = run_cli("log", "--log", str(cli_log))
    assert shown.returncode == 0, shown.stderr
    lines = [json.loads(line) for line in shown.stdout.splitlines()]
    assert lines == [records[0], follow_up]


def test_a_missing_log_and_a_corrupt_log_refuse_with_the_cli_words(tmp_path):
    missing = tmp_path / "no-log.jsonl"
    with pytest.raises(portcullis.CallerError) as caught:
        portcullis.read_log(missing)
    assert str(caught.value) == f"the audit log at {missing} does not stand"
    assert isinstance(caught.value, portcullis.PortcullisError)

    log = tmp_path / "audit.jsonl"
    portcullis.check(
        fixture("policy-full.json"), fixture("call-shell-allow.json"), log, AT
    )
    with log.open("a", encoding="utf-8") as handle:
        handle.write("not a record\n")
    with pytest.raises(portcullis.LogCorruptionError) as caught:
        portcullis.read_log(log)
    expected = (
        "the audit log is corrupt at line 2, "
        "the record at line 2 does not parse"
    )
    assert str(caught.value) == expected
    assert isinstance(caught.value, portcullis.PortcullisError)
    shown = run_cli("log", "--log", str(log))
    assert shown.returncode == 1
    assert shown.stderr == f"error: {expected}\n"


def test_an_append_failure_raises_and_delivers_nothing(tmp_path):
    log = tmp_path / "missing-dir" / "audit.jsonl"
    with pytest.raises(portcullis.LogAppendError) as caught:
        portcullis.check(
            fixture("policy-full.json"), fixture("call-shell-allow.json"), log, AT
        )
    assert str(caught.value).startswith(
        f"the decision could not be appended to the audit log at {log}, "
    )
    assert isinstance(caught.value, portcullis.PortcullisError)
    with pytest.raises(portcullis.CallerError):
        portcullis.read_log(log)


def test_a_boolean_port_is_judged_malformed_and_never_matched_as_one(tmp_path):
    policy = {
        "format": "portcullis-policy/1",
        "default": "deny",
        "rules": [
            {
                "id": "allow-port-one",
                "kind": "network",
                "action": "allow",
                "reason": "port one on this host is fine",
                "match": {
                    "host": {"exact": "hooks.example.test"},
                    "port": {"exact": 1},
                },
            }
        ],
    }
    log = tmp_path / "audit.jsonl"
    judged = portcullis.check(policy, network_call(True), log, AT)
    assert judged["decision"] == "deny"
    assert judged["source"] == {"type": "malformed"}
    control = portcullis.check(policy, network_call(1), log, AT)
    assert control["decision"] == "allow"
    assert control["source"] == {"rule": "allow-port-one", "type": "rule"}
    other = portcullis.check(policy, network_call(2), log, AT)
    assert other["decision"] == "deny"
    assert other["source"] == {"type": "default"}


def test_a_boolean_argument_index_is_no_index_at_all(tmp_path):
    policy = {
        "format": "portcullis-policy/1",
        "default": "deny",
        "rules": [
            {
                "id": "indexed",
                "kind": "shell",
                "action": "allow",
                "reason": "an indexed argument",
                "match": {"args": [{"index": True, "match": {"exact": "x"}}]},
            }
        ],
    }
    decision = portcullis.check(
        policy, fixture("call-shell-deny.json"), tmp_path / "audit.jsonl", AT
    )
    assert decision["decision"] == "deny"
    assert decision["source"] == {
        "detail": "the match of rule indexed names an argument position below 1",
        "type": "policy error",
    }


def test_integer_discipline_at_the_document_edge(tmp_path):
    policy = fixture("policy-full.json")
    log = tmp_path / "audit.jsonl"
    wide_values = [
        10**5000,
        -(10**5000),
        ForgedBytesInt(10**5000),
        EmptyBytesInt(10**5000),
        ForgedBitLengthInt(10**5000),
    ]
    for wide in wide_values:
        with pytest.raises(portcullis.CallerError) as caught:
            portcullis.check(policy, network_call(wide), log, AT)
        assert str(caught.value) == (
            "the document carries an integer too wide to parse"
        )
    assert not log.exists()

    judged = portcullis.check(policy, network_call(10**100), log, AT)
    assert judged["decision"] == "deny"
    assert judged["source"] == {"type": "malformed"}
    assert portcullis.read_log(log) == [judged]

    with pytest.raises(TypeError):
        portcullis.check(policy, network_call(IndexOnly()), log, AT)
    assert portcullis.read_log(log) == [judged]


def test_hostile_shapes_refuse_cleanly(tmp_path):
    policy = fixture("policy-full.json")
    call = fixture("call-shell-deny.json")
    log = tmp_path / "audit.jsonl"

    with pytest.raises(TypeError):
        portcullis.check(policy, {1: "x"}, log, AT)
    with pytest.raises(TypeError):
        portcullis.check(
            policy,
            {"format": "portcullis-call/1", "kind": "shell", "argv": {"rm"}},
            log,
            AT,
        )
    with pytest.raises(TypeError):
        portcullis.check({"policy"}, call, log, AT)
    with pytest.raises(portcullis.CallerError) as caught:
        portcullis.check(
            policy,
            {"format": "portcullis-call/1", "kind": "shell", "argv": ["rm\ud800"]},
            log,
            AT,
        )
    assert str(caught.value) == (
        "the document carries a string that is not encodable text"
    )
    assert not log.exists()

    lying = LyingDict(call)
    decision = portcullis.check(policy, lying, log, AT)
    assert decision == fixture("expected/policy-full--call-shell-deny.json")


def test_the_many_starred_glob_answers_inside_its_bound(tmp_path):
    policy = {
        "format": "portcullis-policy/1",
        "default": "deny",
        "rules": [
            {
                "id": "starred",
                "kind": "shell",
                "action": "allow",
                "reason": "the starred name is fine",
                "match": {"argv0": {"glob": "*a*a*a*a*a*a*a*a*a*a*x"}},
            }
        ],
    }
    log = tmp_path / "audit.jsonl"
    long_name = "a" * 5000
    started = time.monotonic()
    missed = portcullis.check(
        policy,
        {"format": "portcullis-call/1", "kind": "shell", "argv": [long_name]},
        log,
        AT,
    )
    missed_elapsed = time.monotonic() - started
    assert missed["decision"] == "deny"
    assert missed["source"] == {"type": "default"}
    assert missed_elapsed < 10.0

    started = time.monotonic()
    hit = portcullis.check(
        policy,
        {"format": "portcullis-call/1", "kind": "shell", "argv": [long_name + "x"]},
        log,
        AT,
    )
    hit_elapsed = time.monotonic() - started
    assert hit["decision"] == "allow"
    assert hit["source"] == {"rule": "starred", "type": "rule"}
    assert hit_elapsed < 10.0


def test_not_a_number_refuses_as_the_reader_refuses_it(tmp_path):
    policy = fixture("policy-full.json")
    log = tmp_path / "audit.jsonl"
    with pytest.raises(portcullis.CallerError) as caught:
        portcullis.check(policy, network_call(float("nan")), log, AT)
    assert str(caught.value) == "the document does not parse"
    assert not log.exists()

    nan_policy = {
        "format": "portcullis-policy/1",
        "default": "deny",
        "rules": [
            {
                "id": "nan-port",
                "kind": "network",
                "action": "allow",
                "reason": "a port that is not a number",
                "match": {"port": {"exact": float("nan")}},
            }
        ],
    }
    decision = portcullis.check(nan_policy, network_call(8443), log, AT)
    assert decision["decision"] == "deny"
    assert decision["source"] == {
        "detail": "the document does not parse",
        "type": "policy error",
    }

    overflowed = portcullis.check(policy, network_call(float("inf")), log, AT)
    assert overflowed["decision"] == "deny"
    assert overflowed["source"] == {"type": "malformed"}

    call_path = tmp_path / "nan-call.json"
    call_path.write_text(
        '{"format": "portcullis-call/1", "kind": "network", "method": "POST",'
        ' "host": "hooks.example.test", "port": NaN}',
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    judged = run_cli(
        "check",
        "--policy",
        str(policy_path),
        "--log",
        str(tmp_path / "cli.jsonl"),
        str(call_path),
    )
    assert judged.returncode == 2
    assert judged.stderr == (
        "error: the call document does not parse as strict JSON\n"
    )


def test_the_exceptions_form_one_family():
    assert issubclass(portcullis.PortcullisError, Exception)
    for cls in (
        portcullis.CallerError,
        portcullis.LogAppendError,
        portcullis.LogCorruptionError,
    ):
        assert issubclass(cls, portcullis.PortcullisError)
