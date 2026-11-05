"""The Python face of portcullis, the local tool call gate.

Importing the package loads the native module and re-exports
its whole surface under the package name. The functions are
check and read_log and audit_log. The function check takes a policy
document and a call document as Python values, an audit log
path, and the instant of the decision as ISO 8601 text, and
it returns the decision as a plain dictionary in the
portcullis-decision/1 shape after the library has appended
that decision to the log. An optional transport keyword on
check hands the library a callable judge transport for
policies whose rules refer calls to a decision model, and a
decision the model influenced is returned in the
portcullis-decision/2 shape. The function read_log takes an
audit log path and returns its records as a list of plain
dictionaries in log order. The function audit_log takes an
audit log path and a sample size and returns the sampling
report as a plain dictionary in the portcullis-audit/1
shape, and it writes nothing.

The refusals form one family under PortcullisError. A
CallerError carries a caller error of the library, in the
class the command line tool answers at exit 2. A
LogAppendError carries the sentence the command line tool
prints when a decision could not be appended to the audit
log. A LogCorruptionError carries the sentence the command
line tool prints when an audit log does not read back whole.

The binding is a thin translation layer over the Rust crate.
The evaluation order, the rule matching, and the audit rules
live in the crate and nowhere else, and no decision is made
in Python.
"""

from portcullis._portcullis import (
    CallerError,
    LogAppendError,
    LogCorruptionError,
    PortcullisError,
    audit_log,
    check,
    read_log,
)

__all__ = [
    "CallerError",
    "LogAppendError",
    "LogCorruptionError",
    "PortcullisError",
    "audit_log",
    "check",
    "read_log",
]
