//! Self-contained Rust quickstart for portcullis.
//!
//! Strictly parses and loads examples/policies/coding_agent_policy.json,
//! evaluates an allowed workspace read, a staged file write rewrite, a
//! denied move into /etc via path2, and a model-referred shell call over an
//! offline jev-1.14.0 transport, appends every decision to a temporary audit
//! log, verifies log reading and risk-ranked sampling, and cleans up on exit.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use portcullis::{
    append_decision, audit_log, evaluate_with_transport, load_policy, read_log, strict_parse,
    JudgeTransport, TransportError, Value,
};

struct TempDir(PathBuf);

impl TempDir {
    fn create(prefix: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct OfflineAllowJudge;

impl JudgeTransport for OfflineAllowJudge {
    fn consult(&self, _request: &Value) -> Result<String, TransportError> {
        Ok(r#"{"model": "jev-1.14.0", "answers": {"verdict": {"type": "choice", "choice": "allow", "confidence": 0.92, "probabilities": {"allow": 0.92, "deny": 0.03, "escalate": 0.04, "other": 0.01}}, "risk": {"type": "score", "score": 2.4, "probabilities": {}}}, "usage": {"input_tokens": 12, "output_tokens": 6}}"#.to_string())
    }
}

pub fn run_quickstart() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let policy_path = repo_root.join("examples/policies/coding_agent_policy.json");
    let policy_text = std::fs::read_to_string(&policy_path)?;
    let policy_doc = strict_parse(&policy_text)?;
    let policy = load_policy(&policy_doc)?;

    let temp = TempDir::create("portcullis-quickstart")?;
    let log_path = temp.0.join("audit.jsonl");
    let judge_impl = OfflineAllowJudge;
    let judge: &dyn JudgeTransport = &judge_impl;
    let at = "2031-05-04T12:00:00+00:00";

    // 1. Workspace read -> allow
    let read_call = strict_parse(
        r#"{"format":"portcullis-call/1","kind":"file","operation":"read","path":"/work/src/lib.rs"}"#,
    )?;
    let d1 = evaluate_with_transport(Some(&policy), None, &read_call, at, Some(judge));
    assert_eq!(d1.get("decision").and_then(Value::as_str), Some("allow"));
    append_decision(&log_path, &d1)?;
    println!("1. workspace read -> allow");

    // 2. Output write -> rewrite into /work/staging/out.txt
    let write_call = strict_parse(
        r#"{"format":"portcullis-call/1","kind":"file","operation":"write","path":"/work/out/report.txt"}"#,
    )?;
    let d2 = evaluate_with_transport(Some(&policy), None, &write_call, at, Some(judge));
    assert_eq!(d2.get("decision").and_then(Value::as_str), Some("rewrite"));
    let rewritten_path = d2
        .get("rewritten_call")
        .and_then(|v| v.get("path"))
        .and_then(Value::as_str);
    assert_eq!(rewritten_path, Some("/work/staging/out.txt"));
    append_decision(&log_path, &d2)?;
    println!("2. output write -> rewrite (/work/staging/out.txt)");

    // 3. Move into /etc via traversal -> deny via path2 normalization
    let move_call = strict_parse(
        r#"{"format":"portcullis-call/1","kind":"file","operation":"move","path":"/work/draft.conf","path2":"/var/../etc/app.conf"}"#,
    )?;
    let d3 = evaluate_with_transport(Some(&policy), None, &move_call, at, Some(judge));
    assert_eq!(d3.get("decision").and_then(Value::as_str), Some("deny"));
    append_decision(&log_path, &d3)?;
    println!("3. move into /etc -> deny (deny-move-into-etc)");

    // 4. Open shell call -> referred to offline jev-1.14.0 judge -> allow
    let shell_call = strict_parse(
        r#"{"format":"portcullis-call/1","kind":"shell","argv":["cargo","test","--offline"]}"#,
    )?;
    let d4 = evaluate_with_transport(Some(&policy), None, &shell_call, at, Some(judge));
    assert_eq!(d4.get("decision").and_then(Value::as_str), Some("allow"));
    assert_eq!(
        d4.get("format").and_then(Value::as_str),
        Some("portcullis-decision/2")
    );
    append_decision(&log_path, &d4)?;
    println!("4. shell cargo test -> model allow (jev-1.14.0)");

    // 5. Read back log and sample risk-ranked model allows
    let entries = read_log(&log_path)?;
    assert_eq!(entries.len(), 4);
    let report = audit_log(&log_path, 2)?;
    assert_eq!(report.get("returned"), Some(&Value::Int("1".to_string())));
    println!("5. audit log verified (4 entries, 1 risk-ranked sample)");

    Ok(())
}

#[allow(dead_code)]
fn main() -> ExitCode {
    match run_quickstart() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}
