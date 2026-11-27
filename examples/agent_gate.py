#!/usr/bin/env python3
"""Standalone standard-library CLI gate walkthrough for portcullis.

Evaluates allowed, rewritten, denied, and model-referred tool calls against
examples/policies/coding_agent_policy.json in a temporary directory, verifies
the audit log, and runs risk-ranked audit sampling.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def resolve_portcullis_bin(explicit: str | None) -> str:
    if explicit:
        return explicit
    env_bin = os.environ.get("CARGO_BIN_EXE_portcullis")
    if env_bin:
        return env_bin
    repo_root = Path(__file__).resolve().parent.parent
    exe_name = "portcullis.exe" if os.name == "nt" else "portcullis"
    for profile in ("debug", "release"):
        candidate = repo_root / "target" / profile / exe_name
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("portcullis")
    if found:
        return found
    raise RuntimeError(
        "portcullis binary not found; build with `cargo build --bin portcullis` or pass --portcullis-bin"
    )


def run_portcullis(
    portcullis_bin: str, expected_rc: int, *args: str
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [portcullis_bin, *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != expected_rc:
        raise RuntimeError(
            f"portcullis {' '.join(args)} exited {proc.returncode} (expected {expected_rc}): stdout={proc.stdout.strip()} stderr={proc.stderr.strip()}"
        )
    return proc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent_gate.py",
        description="Run a standalone CLI tool-call gate walkthrough with portcullis.",
    )
    parser.add_argument(
        "--portcullis-bin",
        default=None,
        help="Path to the portcullis binary (defaults to CARGO_BIN_EXE_portcullis, target/debug, or PATH)",
    )
    ns = parser.parse_args(argv)
    portcullis_bin = resolve_portcullis_bin(ns.portcullis_bin)
    repo_root = Path(__file__).resolve().parent.parent
    policy_path = repo_root / "examples" / "policies" / "coding_agent_policy.json"

    with tempfile.TemporaryDirectory(prefix="portcullis-gate-") as tmp:
        tmp_dir = Path(tmp)
        log_path = tmp_dir / "audit.jsonl"

        # 1. Allowed workspace read (exit 0)
        read_path = tmp_dir / "call-read.json"
        read_path.write_text(
            json.dumps(
                {
                    "format": "portcullis-call/1",
                    "kind": "file",
                    "operation": "read",
                    "path": "/work/README.md",
                }
            ),
            encoding="utf-8",
        )
        r1 = json.loads(
            run_portcullis(
                portcullis_bin,
                0,
                "check",
                "--policy",
                str(policy_path),
                "--log",
                str(log_path),
                str(read_path),
            ).stdout
        )
        assert r1["decision"] == "allow", r1
        print("1. read /work/README.md ->", r1["decision"])

        # 2. Rewritten output write (exit 0)
        write_path = tmp_dir / "call-write.json"
        write_path.write_text(
            json.dumps(
                {
                    "format": "portcullis-call/1",
                    "kind": "file",
                    "operation": "write",
                    "path": "/work/out/patch.diff",
                }
            ),
            encoding="utf-8",
        )
        r2 = json.loads(
            run_portcullis(
                portcullis_bin,
                0,
                "check",
                "--policy",
                str(policy_path),
                "--log",
                str(log_path),
                str(write_path),
            ).stdout
        )
        assert r2["decision"] == "rewrite", r2
        assert r2["rewritten_call"]["path"] == "/work/staging/out.txt", r2
        print("2. write /work/out/patch.diff ->", r2["decision"], r2["rewritten_call"]["path"])

        # 3. Denied move into /etc via path2 (exit 1)
        move_path = tmp_dir / "call-move.json"
        move_path.write_text(
            json.dumps(
                {
                    "format": "portcullis-call/1",
                    "kind": "file",
                    "operation": "move",
                    "path": "/work/tmp.conf",
                    "path2": "/etc/hosts",
                }
            ),
            encoding="utf-8",
        )
        r3 = json.loads(
            run_portcullis(
                portcullis_bin,
                1,
                "check",
                "--policy",
                str(policy_path),
                "--log",
                str(log_path),
                str(move_path),
            ).stdout
        )
        assert r3["decision"] == "deny", r3
        assert r3["source"] == {"type": "rule", "rule": "deny-move-into-etc"}, r3
        print("3. move -> /etc/hosts ->", r3["decision"], r3["source"]["rule"])

        # 4. Referred shell call using an offline Python helper script (exit 0)
        reply_script = tmp_dir / "offline_judge.py"
        reply_script.write_text(
            "import json, sys\n"
            "_ = sys.stdin.read()\n"
            "print(json.dumps({\n"
            '  "model": "jev-1.14.0",\n'
            '  "answers": {\n'
            '    "verdict": {"type": "choice", "choice": "allow", "confidence": 0.91,\n'
            '                "probabilities": {"allow": 0.91, "deny": 0.03, "escalate": 0.05, "other": 0.01}},\n'
            '    "risk": {"type": "score", "score": 2.1, "probabilities": {}}\n'
            "  },\n"
            '  "usage": {"input_tokens": 10, "output_tokens": 5}\n'
            "}))\n",
            encoding="utf-8",
        )
        shell_path = tmp_dir / "call-shell.json"
        shell_path.write_text(
            json.dumps(
                {
                    "format": "portcullis-call/1",
                    "kind": "shell",
                    "argv": ["git", "status"],
                }
            ),
            encoding="utf-8",
        )
        judge_cmd = f'"{sys.executable}" "{reply_script}"'
        r4 = json.loads(
            run_portcullis(
                portcullis_bin,
                0,
                "check",
                "--policy",
                str(policy_path),
                "--log",
                str(log_path),
                "--judge",
                judge_cmd,
                str(shell_path),
            ).stdout
        )
        assert r4["decision"] == "allow", r4
        assert r4["model"]["model"] == "jev-1.14.0", r4
        print("4. shell git status ->", r4["decision"], f"({r4['model']['model']})")

        # 5. Verify log and risk-ranked audit sampling
        log_lines = run_portcullis(
            portcullis_bin, 0, "log", "--log", str(log_path)
        ).stdout.splitlines()
        assert len(log_lines) == 4, log_lines

        audit = json.loads(
            run_portcullis(
                portcullis_bin, 0, "audit", "--log", str(log_path), "--sample", "2"
            ).stdout
        )
        assert audit["returned"] == 1, audit
        print("5. audit sample returned", audit["returned"], "scored allow")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
