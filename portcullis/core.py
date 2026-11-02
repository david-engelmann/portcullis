"""Core logic for portcullis, the tool call gate.

One policy document and one call document go in and one decision
record comes out. The decision is reached in the order the contract
states. Schema validation first, then the deny rules in policy order,
then the allow and rewrite rules in policy order, then the declared
default. The gate never executes a call and never touches the
filesystem at a path a call names. Its only write is the audit log
append, and that append is part of delivering a decision.

Time is an input. The caller passes the instant a decision is given
at, and this module reads no wall clock for the decision itself.
"""

import fcntl
import hashlib
import json
import os
import posixpath
from fnmatch import fnmatchcase
from urllib.parse import urlparse

CALL_FORMAT = "portcullis-call/1"
POLICY_FORMAT = "portcullis-policy/1"
DECISION_FORMAT = "portcullis-decision/1"

KINDS = ("shell", "file", "network")
FILE_OPERATIONS = ("read", "write", "delete", "move", "list")
ACTIONS = ("allow", "deny", "rewrite")
DEFAULTS = ("allow", "deny")
MATCHER_KEYS = ("exact", "prefix", "glob")
INTERPRETERS = frozenset(
    ("sh", "bash", "dash", "ash", "zsh", "ksh", "csh", "tcsh", "fish")
)
SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}
PORT_MIN = 1
PORT_MAX = 65535


class CallerError(Exception):
    """Input to the tool is bad and no decision is made for it."""


class PolicyError(Exception):
    """The policy cannot be loaded and the gate must fail closed."""


class MalformedCall(Exception):
    """A parsed call document fails schema validation."""


class LogAppendError(Exception):
    """A decision could not be appended to the audit log."""


class LogCorruptionError(Exception):
    """A line of the audit log fails to parse or to validate."""

    def __init__(self, line_number, detail):
        super().__init__(f"line {line_number}, {detail}")
        self.line_number = line_number
        self.detail = detail


class _DuplicateKeyError(ValueError):
    pass


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _refuse_constant(name):
    raise ValueError(f"the constant {name} is not strict JSON")


def strict_parse(text):
    """Parse one JSON document strictly or raise ValueError.

    Duplicate keys at any level, the non standard constants, trailing
    data, and nesting past the interpreter limit are all refused, so
    a document this function returns is the whole input and nothing
    in it was silently overwritten or extended.
    """
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_refuse_constant,
        )
    except RecursionError:
        raise ValueError("the document nests too deeply to parse") from None


def canonical(document):
    """The canonical form of a JSON document as UTF-8 bytes."""
    text = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return text.encode("utf-8")


def call_digest(document):
    """The recorded digest of a parsed call document."""
    return "sha256:" + hashlib.sha256(canonical(document)).hexdigest()


def _is_int(value):
    return type(value) is int


def _is_text(value):
    return isinstance(value, str)


def _check_keys(document, allowed, required, what):
    keys = set(document)
    unknown = keys - allowed
    if unknown:
        raise ValueError(f"{what} carries the unknown field {sorted(unknown)[0]}")
    missing = required - keys
    if missing:
        raise ValueError(f"{what} is missing the field {sorted(missing)[0]}")


def _valid_port(value):
    return _is_int(value) and PORT_MIN <= value <= PORT_MAX


# --- call validation ---------------------------------------------------


def _validate_shell(document):
    _check_keys(
        document,
        {"format", "kind", "argv", "cwd"},
        {"format", "kind", "argv"},
        "a shell call",
    )
    argv = document["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or any(not _is_text(token) for token in argv)
    ):
        raise MalformedCall("a shell call carries an argv of one or more strings")
    if "cwd" in document and not _is_text(document["cwd"]):
        raise MalformedCall("a shell call carries a cwd that is not a string")
    return dict(document)


def _validate_file(document):
    _check_keys(
        document,
        {"format", "kind", "operation", "path", "path2"},
        {"format", "kind", "operation", "path"},
        "a file call",
    )
    if document["operation"] not in FILE_OPERATIONS:
        raise MalformedCall("a file call names an operation outside the set")
    if not _is_text(document["path"]) or not document["path"]:
        raise MalformedCall("a file call carries a path that is not a string")
    if document["operation"] == "move":
        if "path2" not in document:
            raise MalformedCall("a move call carries no second path")
        if not _is_text(document["path2"]) or not document["path2"]:
            raise MalformedCall("a move call carries a second path of no use")
    elif "path2" in document:
        raise MalformedCall("a file call that is not a move carries a second path")
    return dict(document)


def _validate_network(document):
    _check_keys(
        document,
        {"format", "kind", "method", "host", "port", "url"},
        {"format", "kind", "method"},
        "a network call",
    )
    if not _is_text(document["method"]) or not document["method"]:
        raise MalformedCall("a network call carries a method that is not a string")
    has_url = "url" in document
    has_host = "host" in document
    has_port = "port" in document
    if has_url and (has_host or has_port):
        raise MalformedCall("a network call carries both a url and a host or port")
    if has_url:
        return _network_from_url(document)
    if not (has_host and has_port):
        raise MalformedCall("a network call carries neither a url nor a host and port")
    if not _is_text(document["host"]) or not document["host"]:
        raise MalformedCall("a network call carries a host that is not a string")
    if not _valid_port(document["port"]):
        raise MalformedCall("a network call carries a port outside its range")
    result = dict(document)
    result["host"] = result["host"].lower()
    return result


def _network_from_url(document):
    url = document["url"]
    if not _is_text(url):
        raise MalformedCall("a network call carries a url that is not a string")
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        raise MalformedCall("a network call carries a url that does not parse") from None
    if parsed.username is not None or parsed.password is not None:
        raise MalformedCall("a network call carries a url holding userinfo")
    host = parsed.hostname
    if not host:
        raise MalformedCall("a network call carries a url with no host")
    if port is None:
        port = SCHEME_DEFAULT_PORTS.get(parsed.scheme)
    if port is None or not _valid_port(port):
        raise MalformedCall("a network call carries a url with no usable port")
    return {
        "format": document["format"],
        "kind": "network",
        "method": document["method"],
        "host": host,
        "port": port,
    }


def validate_call(document):
    """Validate a parsed call document or raise MalformedCall.

    The returned call is normalized, so a network call given by url
    comes back in the explicit method and host and port form and a
    host always stands folded to lowercase.
    """
    if not isinstance(document, dict):
        raise MalformedCall("a call is not a JSON object")
    try:
        _check_keys(
            document,
            {"format", "kind", "argv", "cwd", "operation", "path", "path2",
             "method", "host", "port", "url"},
            {"format", "kind"},
            "a call",
        )
    except ValueError as exc:
        raise MalformedCall(str(exc)) from None
    if document["format"] != CALL_FORMAT:
        raise MalformedCall("a call names a format this gate does not read")
    kind = document["kind"]
    try:
        if kind == "shell":
            return _validate_shell(document)
        if kind == "file":
            return _validate_file(document)
        if kind == "network":
            return _validate_network(document)
    except ValueError as exc:
        raise MalformedCall(str(exc)) from None
    raise MalformedCall("a call names a kind this gate does not judge")


def is_interpreter_call(call):
    """Whether a validated call runs a shell interpreter."""
    if call["kind"] != "shell":
        return False
    basename = call["argv"][0].rsplit("/", 1)[-1]
    return basename in INTERPRETERS


# --- policy loading ----------------------------------------------------


def _validate_matcher(value, what, fold=False):
    if not isinstance(value, dict) or len(value) != 1:
        raise PolicyError(f"{what} is not a matcher holding exactly one form")
    form = next(iter(value))
    if form not in MATCHER_KEYS:
        raise PolicyError(f"{what} names a match form this gate does not use")
    pattern = value[form]
    if not _is_text(pattern):
        raise PolicyError(f"{what} carries a pattern that is not a string")
    if fold:
        pattern = pattern.lower()
    return {form: pattern}


def _validate_port_matcher(value, what):
    if not isinstance(value, dict) or set(value) != {"exact"}:
        raise PolicyError(f"{what} is not a port matcher holding one exact port")
    if not _valid_port(value["exact"]):
        raise PolicyError(f"{what} carries a port outside its range")
    return {"exact": value["exact"]}


def _validate_match(kind, match, rule_id):
    what = f"the match of rule {rule_id}"
    if not isinstance(match, dict) or not match:
        raise PolicyError(f"{what} holds no condition")
    if kind == "shell":
        _check_policy_keys(match, {"argv0", "args"}, what)
        result = {}
        if "argv0" in match:
            result["argv0"] = _validate_matcher(match["argv0"], f"{what} on argv0")
        if "args" in match:
            result["args"] = _validate_arg_conditions(match["args"], what)
        return result
    if kind == "file":
        _check_policy_keys(match, {"operation", "path"}, what)
        result = {}
        if "operation" in match:
            result["operation"] = _validate_matcher(
                match["operation"], f"{what} on the operation"
            )
        if "path" in match:
            result["path"] = _validate_matcher(match["path"], f"{what} on the path")
        return result
    _check_policy_keys(match, {"method", "host", "port"}, what)
    result = {}
    if "method" in match:
        result["method"] = _validate_matcher(match["method"], f"{what} on the method")
    if "host" in match:
        result["host"] = _validate_matcher(
            match["host"], f"{what} on the host", fold=True
        )
    if "port" in match:
        result["port"] = _validate_port_matcher(match["port"], f"{what} on the port")
    return result


def _validate_arg_conditions(value, what):
    if not isinstance(value, list) or not value:
        raise PolicyError(f"{what} carries an argument condition list of no use")
    result = []
    for entry in value:
        if not isinstance(entry, dict):
            raise PolicyError(f"{what} carries an argument condition that is not an object")
        _check_policy_keys(entry, {"index", "match"}, f"{what} argument condition")
        if not _is_int(entry["index"]) or entry["index"] < 1:
            raise PolicyError(f"{what} names an argument position below 1")
        result.append(
            {
                "index": entry["index"],
                "match": _validate_matcher(entry["match"], f"{what} argument matcher"),
            }
        )
    return result


def _check_policy_keys(document, allowed, what):
    try:
        _check_keys(document, allowed, set(), what)
    except ValueError as exc:
        raise PolicyError(str(exc)) from None


def _validate_substitute(kind, substitute, rule_id):
    what = f"the substitute of rule {rule_id}"
    if not isinstance(substitute, dict) or not substitute:
        raise PolicyError(f"{what} names no replacement value")
    if kind == "shell":
        _check_policy_keys(substitute, {"argv", "cwd"}, what)
        result = {}
        if "argv" in substitute:
            argv = substitute["argv"]
            if (
                not isinstance(argv, list)
                or not argv
                or any(not _is_text(token) for token in argv)
            ):
                raise PolicyError(f"{what} carries an argv of no use")
            result["argv"] = list(argv)
        if "cwd" in substitute:
            if not _is_text(substitute["cwd"]):
                raise PolicyError(f"{what} carries a cwd that is not a string")
            result["cwd"] = substitute["cwd"]
        return result
    if kind == "file":
        _check_policy_keys(substitute, {"operation", "path", "path2"}, what)
        result = {}
        if "operation" in substitute:
            if substitute["operation"] not in FILE_OPERATIONS:
                raise PolicyError(f"{what} names an operation outside the set")
            result["operation"] = substitute["operation"]
        for field in ("path", "path2"):
            if field in substitute:
                if not _is_text(substitute[field]) or not substitute[field]:
                    raise PolicyError(f"{what} carries a {field} of no use")
                result[field] = substitute[field]
        return result
    _check_policy_keys(substitute, {"method", "host", "port"}, what)
    result = {}
    if "method" in substitute:
        if not _is_text(substitute["method"]) or not substitute["method"]:
            raise PolicyError(f"{what} carries a method of no use")
        result["method"] = substitute["method"]
    if "host" in substitute:
        if not _is_text(substitute["host"]) or not substitute["host"]:
            raise PolicyError(f"{what} carries a host of no use")
        result["host"] = substitute["host"].lower()
    if "port" in substitute:
        if not _valid_port(substitute["port"]):
            raise PolicyError(f"{what} carries a port outside its range")
        result["port"] = substitute["port"]
    return result


def _validate_rule(rule, position, seen_ids):
    what = f"rule at position {position}"
    if not isinstance(rule, dict):
        raise PolicyError(f"the {what} is not an object")
    _check_policy_keys(
        rule, {"id", "kind", "action", "reason", "match", "substitute"}, f"the {what}"
    )
    for field in ("id", "kind", "action", "reason", "match"):
        if field not in rule:
            raise PolicyError(f"the {what} is missing the field {field}")
    rule_id = rule["id"]
    if not _is_text(rule_id) or not rule_id:
        raise PolicyError(f"the {what} carries an id of no use")
    what = f"rule {rule_id}"
    if rule_id in seen_ids:
        raise PolicyError(f"the policy carries the rule id {rule_id} twice")
    seen_ids.add(rule_id)
    if rule["kind"] not in KINDS:
        raise PolicyError(f"{what} names a kind this gate does not judge")
    if rule["action"] not in ACTIONS:
        raise PolicyError(f"{what} names an action outside the set")
    if not _is_text(rule["reason"]) or not rule["reason"]:
        raise PolicyError(f"{what} carries a reason that is not a string")
    result = {
        "id": rule_id,
        "kind": rule["kind"],
        "action": rule["action"],
        "reason": rule["reason"],
        "match": _validate_match(rule["kind"], rule["match"], rule_id),
    }
    if rule["action"] == "rewrite":
        if "substitute" not in rule:
            raise PolicyError(f"{what} rewrites and carries no substitute")
        result["substitute"] = _validate_substitute(
            rule["kind"], rule["substitute"], rule_id
        )
    elif "substitute" in rule:
        raise PolicyError(f"{what} carries a substitute and does not rewrite")
    return result


def load_policy(document):
    """Validate a parsed policy document or raise PolicyError.

    Validation of every rule happens here, so a policy object that
    comes back is wholly usable and a policy with any invalid part
    never produces one.
    """
    if not isinstance(document, dict):
        raise PolicyError("the policy is not a JSON object")
    _check_policy_keys(
        document, {"format", "default", "rules"}, "the policy"
    )
    for field in ("format", "default", "rules"):
        if field not in document:
            raise PolicyError(f"the policy is missing the field {field}")
    if document["format"] != POLICY_FORMAT:
        raise PolicyError("the policy names a format this gate does not read")
    if document["default"] not in DEFAULTS:
        raise PolicyError("the policy declares a default outside allow and deny")
    if not isinstance(document["rules"], list):
        raise PolicyError("the policy carries a rules field that is not a list")
    seen_ids = set()
    rules = [
        _validate_rule(rule, position, seen_ids)
        for position, rule in enumerate(document["rules"])
    ]
    return {"default": document["default"], "rules": rules}


# --- matching and evaluation -------------------------------------------


def _match_text(matcher, value):
    if "exact" in matcher:
        return value == matcher["exact"]
    if "prefix" in matcher:
        return value.startswith(matcher["prefix"])
    return fnmatchcase(value, matcher["glob"])


def _rule_matches(rule, call):
    match = rule["match"]
    kind = call["kind"]
    if kind == "shell":
        if "argv0" in match and not _match_text(match["argv0"], call["argv"][0]):
            return False
        for condition in match.get("args", []):
            index = condition["index"]
            if index >= len(call["argv"]):
                return False
            if not _match_text(condition["match"], call["argv"][index]):
                return False
        return True
    if kind == "file":
        if "operation" in match and not _match_text(
            match["operation"], call["operation"]
        ):
            return False
        if "path" in match:
            given = call["path"]
            normalized = posixpath.normpath(given)
            if not (
                _match_text(match["path"], given)
                or _match_text(match["path"], normalized)
            ):
                return False
        return True
    if "method" in match and not _match_text(match["method"], call["method"]):
        return False
    if "host" in match and not _match_text(match["host"], call["host"]):
        return False
    if "port" in match and call["port"] != match["port"]["exact"]:
        return False
    return True


def _decision(at, digest, outcome, source, reason, interpreter, rewritten_call):
    return {
        "format": DECISION_FORMAT,
        "at": at,
        "call_digest": digest,
        "decision": outcome,
        "source": source,
        "reason": reason,
        "interpreter": interpreter,
        "rewritten_call": rewritten_call,
    }


def evaluate(policy, policy_error, document, at):
    """Decide one parsed call document against a loaded policy.

    policy is the object load_policy returned, or None when the
    policy could not be loaded, in which case policy_error states
    the load failure and every schema valid call is denied with
    the policy error source. at is the instant string to record.
    """
    digest = call_digest(document)
    try:
        call = validate_call(document)
    except MalformedCall:
        return _decision(
            at, digest, "deny", {"type": "malformed"}, None, False, None
        )
    interpreter = is_interpreter_call(call)
    if policy is None:
        return _decision(
            at,
            digest,
            "deny",
            {"type": "policy error", "detail": policy_error},
            None,
            interpreter,
            None,
        )
    own = [rule for rule in policy["rules"] if rule["kind"] == call["kind"]]
    for rule in own:
        if rule["action"] == "deny" and _rule_matches(rule, call):
            return _decision(
                at,
                digest,
                "deny",
                {"type": "rule", "rule": rule["id"]},
                rule["reason"],
                interpreter,
                None,
            )
    for rule in own:
        if rule["action"] == "deny":
            continue
        if not _rule_matches(rule, call):
            continue
        if rule["action"] == "allow":
            return _decision(
                at,
                digest,
                "allow",
                {"type": "rule", "rule": rule["id"]},
                rule["reason"],
                interpreter,
                None,
            )
        rewritten = dict(call)
        rewritten.update(rule["substitute"])
        try:
            rewritten = validate_call(rewritten)
        except MalformedCall:
            return _decision(
                at,
                digest,
                "deny",
                {"type": "rule", "rule": rule["id"]},
                rule["reason"],
                interpreter,
                None,
            )
        return _decision(
            at,
            digest,
            "rewrite",
            {"type": "rule", "rule": rule["id"]},
            rule["reason"],
            interpreter,
            rewritten,
        )
    return _decision(
        at,
        digest,
        policy["default"],
        {"type": "default"},
        None,
        interpreter,
        None,
    )


# --- the audit log -------------------------------------------------------


def append_decision(log_path, decision):
    """Append one decision record to the audit log as one whole line."""
    line = canonical(decision).decode("utf-8") + "\n"
    try:
        with open(log_path, "a", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError as exc:
        raise LogAppendError(str(exc)) from exc


def _validate_decision_record(record, line_number):
    what = f"the record at line {line_number}"
    if not isinstance(record, dict):
        raise LogCorruptionError(line_number, f"{what} is not an object")
    expected = {
        "format", "at", "call_digest", "decision",
        "source", "reason", "interpreter", "rewritten_call",
    }
    if set(record) != expected:
        raise LogCorruptionError(line_number, f"{what} carries the wrong fields")
    if record["format"] != DECISION_FORMAT:
        raise LogCorruptionError(line_number, f"{what} names the wrong format")
    if not _is_text(record["at"]):
        raise LogCorruptionError(line_number, f"{what} carries an instant of no use")
    digest = record["call_digest"]
    if (
        not _is_text(digest)
        or not digest.startswith("sha256:")
        or len(digest) != len("sha256:") + 64
    ):
        raise LogCorruptionError(line_number, f"{what} carries a digest of no use")
    if record["decision"] not in ("allow", "deny", "rewrite"):
        raise LogCorruptionError(line_number, f"{what} names a decision outside the set")
    source = record["source"]
    if not isinstance(source, dict) or "type" not in source:
        raise LogCorruptionError(line_number, f"{what} carries a source of no use")
    source_type = source["type"]
    if source_type == "rule":
        if set(source) != {"type", "rule"} or not _is_text(source["rule"]):
            raise LogCorruptionError(line_number, f"{what} carries a rule source of no use")
    elif source_type == "policy error":
        if set(source) != {"type", "detail"} or not _is_text(source["detail"]):
            raise LogCorruptionError(line_number, f"{what} carries a policy error source of no use")
    elif source_type in ("malformed", "default"):
        if set(source) != {"type"}:
            raise LogCorruptionError(line_number, f"{what} carries a source of no use")
    else:
        raise LogCorruptionError(line_number, f"{what} names a source outside the set")
    if record["reason"] is not None and not _is_text(record["reason"]):
        raise LogCorruptionError(line_number, f"{what} carries a reason of no use")
    if type(record["interpreter"]) is not bool:
        raise LogCorruptionError(line_number, f"{what} carries an interpreter flag of no use")
    rewritten = record["rewritten_call"]
    if record["decision"] == "rewrite":
        if not isinstance(rewritten, dict):
            raise LogCorruptionError(line_number, f"{what} rewrites and carries no call")
    elif rewritten is not None:
        raise LogCorruptionError(line_number, f"{what} carries a rewritten call and does not rewrite")
    return record


def read_log(log_path):
    """Read and verify every record in the audit log at log_path.

    Raises CallerError when the file does not stand and
    LogCorruptionError naming the first line that fails.
    """
    try:
        text = open(log_path, encoding="utf-8").read()
    except FileNotFoundError:
        raise CallerError(f"the audit log at {log_path} does not stand") from None
    except OSError as exc:
        raise CallerError(f"the audit log at {log_path} cannot be read, {exc}") from exc
    records = []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for number, line in enumerate(lines, start=1):
        try:
            record = strict_parse(line)
        except ValueError:
            raise LogCorruptionError(
                number, f"the record at line {number} does not parse"
            ) from None
        records.append(_validate_decision_record(record, number))
    return records
