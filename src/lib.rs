//! Core logic for portcullis, the tool call gate.
//!
//! One policy document and one call document go in and one
//! decision record comes out. The decision is reached in the
//! order the contract states. Schema validation first, then the
//! deny rules in policy order, then the allow and rewrite and
//! judge rules in policy order, then the declared default. The gate never
//! executes a call and never touches the filesystem at a path a
//! call names. Its only write is the audit log append, and that
//! append is part of delivering a decision.
//!
//! Time is an input. The caller passes the instant a decision is
//! given at, and this module reads no wall clock for the decision
//! itself.
//!
//! Documents are held in a small hand written value model rather
//! than a general JSON library, for three reasons the gate report
//! records. A duplicated key must be refused as the document is
//! read, at every level, and a reader that keeps the last value
//! of a repeated key cannot carry that. An integer is held as its
//! canonical decimal text, so a literal of any width is judged by
//! the same bounds the Python reader judged, including its 4300
//! digit parse limit, and a boolean is never an integer and a
//! float is never an integer. And the canonical writer must
//! reproduce the byte layout of the Python canonical form, keys
//! sorted, no spaces, UTF-8 without ASCII escaping, floats
//! rendered as the Python repr renders them, because decision
//! digests and audit log lines are those bytes.

pub mod audit;
pub mod call;
pub mod errors;
pub mod evaluate;
pub mod matching;
pub mod policy;
pub mod reader;
pub mod referral;
pub mod transport;
pub mod value;
pub mod writer;

pub const CALL_FORMAT: &str = "portcullis-call/1";
pub const POLICY_FORMAT: &str = "portcullis-policy/1";
pub const DECISION_FORMAT: &str = "portcullis-decision/1";
pub const DECISION_FORMAT_2: &str = "portcullis-decision/2";
pub const AUDIT_FORMAT: &str = "portcullis-audit/1";

/// The models a policy judgment block may name in this build.
pub const JUDGE_MODELS: [&str; 1] = ["jev-1.13.0"];

/// The bound a subprocess transport gives a judge command to
/// answer in, in seconds, fixed by the library so no caller can
/// widen it.
pub const JUDGE_TIMEOUT_SECONDS: u64 = 30;

const VERDICT_LABELS: [&str; 4] = ["allow", "deny", "escalate", "other"];

const KINDS: [&str; 3] = ["shell", "file", "network"];
const FILE_OPERATIONS: [&str; 5] = ["read", "write", "delete", "move", "list"];
const ACTIONS: [&str; 4] = ["allow", "deny", "rewrite", "judge"];
const DEFAULTS: [&str; 2] = ["allow", "deny"];
const MATCHER_KEYS: [&str; 3] = ["exact", "prefix", "glob"];
const INTERPRETERS: [&str; 9] = [
    "sh", "bash", "dash", "ash", "zsh", "ksh", "csh", "tcsh", "fish",
];
const PORT_MIN: i64 = 1;
const PORT_MAX: i64 = 65535;
const INT_DIGIT_LIMIT: usize = 4300;
const MAX_DEPTH: usize = 1000;

pub use audit::{append_decision, audit_log, read_log};
pub use call::{is_interpreter_call, validate_call};
pub use errors::{
    CallerError, LogAppendError, LogCorruptionError, LogReadError, MalformedCall, PolicyError,
};
pub use evaluate::{evaluate, evaluate_with_transport};
pub use matching::normpath;
pub use policy::{load_policy, ArgCondition, Judgment, Match, Matcher, Policy, Rule, Substitute};
pub use reader::strict_parse;
pub use transport::{FixtureTransport, JudgeTransport, SubprocessTransport, TransportError};
pub use value::Value;
pub use writer::{call_digest, canonical};
