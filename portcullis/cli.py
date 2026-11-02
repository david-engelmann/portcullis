"""The command line for portcullis, a thin shell over the core.

The two commands are check and log. The check command reads one
policy and one call, prints the decision record as one canonical
JSON line, and appends that record to the audit log before the
decision counts as delivered. Exit codes carry the outcome. Zero
for an allow or a rewrite, one for a deny from any source and for
corruption found by the log command, and two for a caller error.
"""

import argparse
import sys
from datetime import datetime, timezone

from . import core


def _fail(message):
    print(f"error: {message}", file=sys.stderr)


def _read_call_text(path):
    if path is None:
        try:
            return sys.stdin.read()
        except OSError as exc:
            raise core.CallerError(f"the call document cannot be read, {exc}") from exc
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise core.CallerError(
            f"the call document at {path} cannot be read, {exc}"
        ) from exc


def _load_policy(path):
    """Return the loaded policy and a load failure detail, one of them None."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        return None, f"the policy at {path} cannot be read, {exc}"
    try:
        document = core.strict_parse(text)
    except ValueError:
        return None, f"the policy at {path} does not parse as strict JSON"
    try:
        return core.load_policy(document), None
    except core.PolicyError as exc:
        return None, str(exc)


def _check(args):
    try:
        call_text = _read_call_text(args.call)
    except core.CallerError as exc:
        _fail(str(exc))
        return 2
    try:
        document = core.strict_parse(call_text)
    except ValueError:
        _fail("the call document does not parse as strict JSON")
        return 2
    policy, policy_error = _load_policy(args.policy)
    at = datetime.now(timezone.utc).isoformat()
    decision = core.evaluate(policy, policy_error, document, at)
    try:
        core.append_decision(args.log, decision)
    except core.LogAppendError as exc:
        _fail(
            f"the decision could not be appended to the audit log "
            f"at {args.log}, {exc}"
        )
        return 2
    print(core.canonical(decision).decode("utf-8"))
    return 0 if decision["decision"] in ("allow", "rewrite") else 1


def _log(args):
    try:
        records = core.read_log(args.log)
    except core.LogCorruptionError as exc:
        _fail(f"the audit log is corrupt at {exc}")
        return 1
    except core.CallerError as exc:
        _fail(str(exc))
        return 2
    for record in records:
        print(core.canonical(record).decode("utf-8"))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="portcullis",
        description="Decide whether a proposed tool call may proceed.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    check = subcommands.add_parser("check", help="decide one call against a policy")
    check.add_argument("--policy", required=True, help="path to the policy document")
    check.add_argument("--log", required=True, help="path to the audit log")
    check.add_argument(
        "call",
        nargs="?",
        help="path to the call document, or standard input when omitted",
    )
    log = subcommands.add_parser("log", help="read the audit log back and verify it")
    log.add_argument("--log", required=True, help="path to the audit log")
    args = parser.parse_args(argv)
    if args.command == "check":
        return _check(args)
    return _log(args)


if __name__ == "__main__":
    raise SystemExit(main())
