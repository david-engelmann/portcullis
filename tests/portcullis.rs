//! Tests for the portcullis decision engine and its command
//! line, translated pin for pin from the Python suite of
//! Round 1, which collected 118 tests on main. Every test here
//! pins one claim of the contract in CONTRACT.md and can fail
//! for a real reason. The fixtures are synthetic and written
//! for this repo.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use portcullis::{
    canonical, evaluate, load_policy, read_log, strict_parse, LogReadError, Policy, Value,
};
use sha2::{Digest, Sha256};

const AT: &str = "2026-11-02T10:00:00+00:00";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("portcullis-test-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn s(text: &str) -> Value {
    Value::text(text)
}

fn arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}

fn policy_doc(rules: Vec<Value>, default: &str) -> Value {
    Value::obj(vec![
        ("format", s("portcullis-policy/1")),
        ("default", s(default)),
        ("rules", arr(rules)),
    ])
}

fn rule(
    rule_id: &str,
    kind: &str,
    action: &str,
    match_: Value,
    reason: &str,
    substitute: Option<Value>,
) -> Value {
    let mut pairs = vec![
        ("id", s(rule_id)),
        ("kind", s(kind)),
        ("action", s(action)),
        ("reason", s(reason)),
        ("match", match_),
    ];
    if let Some(substitute) = substitute {
        pairs.push(("substitute", substitute));
    }
    Value::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn plain_rule(rule_id: &str, kind: &str, action: &str, match_: Value) -> Value {
    rule(rule_id, kind, action, match_, "a reason", None)
}

fn shell_call(argv: &[&str]) -> Value {
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("shell")),
        ("argv", arr(argv.iter().map(|token| s(token)).collect())),
    ])
}

fn shell_call_cwd(argv: &[&str], cwd: &str) -> Value {
    let mut doc = shell_call(argv);
    if let Value::Object(pairs) = &mut doc {
        pairs.push(("cwd".to_string(), s(cwd)));
    }
    doc
}

fn file_call(operation: &str, path: &str) -> Value {
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("file")),
        ("operation", s(operation)),
        ("path", s(path)),
    ])
}

fn network_call(method: &str, host: &str, port: Value) -> Value {
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s(method)),
        ("host", s(host)),
        ("port", port),
    ])
}

fn matcher(form: &str, pattern: &str) -> Value {
    Value::obj(vec![(form, s(pattern))])
}

fn decide(doc: &Value, rules: Vec<Value>, default: &str) -> Value {
    let policy = load_policy(&policy_doc(rules, default)).unwrap();
    evaluate(Some(&policy), None, doc, AT)
}

fn field<'a>(doc: &'a Value, key: &str) -> &'a Value {
    doc.get(key).unwrap()
}

fn write_json(path: &Path, document: &Value) -> PathBuf {
    std::fs::write(path, canonical(document)).unwrap();
    path.to_path_buf()
}

fn write_text(path: &Path, text: &str) -> PathBuf {
    std::fs::write(path, text).unwrap();
    path.to_path_buf()
}

struct CliOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(arguments: &[&str], stdin_text: Option<&str>) -> CliOutput {
    run_cli_bytes(arguments, stdin_text.map(|text| text.as_bytes().to_vec()))
}

fn run_cli_bytes(arguments: &[&str], stdin_bytes: Option<Vec<u8>>) -> CliOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_portcullis"));
    command
        .args(arguments)
        .current_dir(root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_bytes.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().unwrap();
    if let Some(bytes) = stdin_bytes {
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn parse_line(text: &str) -> Value {
    strict_parse(text.trim_end()).unwrap()
}

// --- the evaluation order battery --------------------------------------

#[test]
fn deny_beats_allow_on_a_call_matching_both() {
    let rules = vec![
        plain_rule(
            "allow-rm",
            "shell",
            "allow",
            Value::obj(vec![("argv0", matcher("exact", "rm"))]),
        ),
        plain_rule(
            "deny-rm",
            "shell",
            "deny",
            Value::obj(vec![("argv0", matcher("exact", "rm"))]),
        ),
    ];
    let decision = decide(&shell_call(&["rm", "x"]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("rule")), ("rule", s("deny-rm"))])
    );
}

#[test]
fn first_matching_deny_rule_is_the_one_named() {
    let rules = vec![
        plain_rule(
            "deny-one",
            "shell",
            "deny",
            Value::obj(vec![("argv0", matcher("exact", "rm"))]),
        ),
        plain_rule(
            "deny-two",
            "shell",
            "deny",
            Value::obj(vec![("argv0", matcher("glob", "r*"))]),
        ),
    ];
    let decision = decide(&shell_call(&["rm", "x"]), rules, "deny");
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("rule")), ("rule", s("deny-one"))])
    );
}

#[test]
fn a_rewrite_never_rescues_a_denied_call() {
    let rules = vec![
        rule(
            "soften-rm",
            "shell",
            "rewrite",
            Value::obj(vec![("argv0", matcher("exact", "rm"))]),
            "a reason",
            Some(Value::obj(vec![("argv", arr(vec![s("ls")]))])),
        ),
        plain_rule(
            "deny-rm",
            "shell",
            "deny",
            Value::obj(vec![("argv0", matcher("exact", "rm"))]),
        ),
    ];
    let decision = decide(&shell_call(&["rm", "x"]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("rule")), ("rule", s("deny-rm"))])
    );
    assert_eq!(field(&decision, "rewritten_call"), &Value::Null);
}

#[test]
fn first_matching_allow_wins_and_swapping_the_order_swaps_the_winner() {
    let first = plain_rule(
        "allow-a",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("glob", "l*"))]),
    );
    let second = plain_rule(
        "allow-b",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("exact", "ls"))]),
    );
    let call = shell_call(&["ls"]);
    let one = decide(&call, vec![first.clone(), second.clone()], "deny");
    assert_eq!(field(&one, "source").get("rule"), Some(&s("allow-a")));
    let two = decide(&call, vec![second, first], "deny");
    assert_eq!(field(&two, "source").get("rule"), Some(&s("allow-b")));
}

#[test]
fn the_default_is_named_when_no_rule_matches() {
    let rules = vec![plain_rule(
        "allow-ls",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("exact", "ls"))]),
    )];
    let decision = decide(&shell_call(&["cat", "f"]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("default"))])
    );
    assert_eq!(field(&decision, "reason"), &Value::Null);
}

#[test]
fn a_declared_allow_default_allows_an_unmatched_call() {
    let decision = decide(&shell_call(&["cat", "f"]), vec![], "allow");
    assert_eq!(field(&decision, "decision"), &s("allow"));
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("default"))])
    );
}

#[test]
fn malformed_is_denied_before_any_rule_fires_on_its_fields() {
    let rules = vec![plain_rule(
        "deny-rm",
        "shell",
        "deny",
        Value::obj(vec![("argv0", matcher("exact", "rm"))]),
    )];
    let mut broken = shell_call(&["rm", "x"]);
    set_field(&mut broken, "argv", s("rm x"));
    let decision = decide(&broken, rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("malformed"))])
    );
}

#[test]
fn a_rule_for_another_kind_never_fires() {
    let rules = vec![plain_rule(
        "deny-rm",
        "shell",
        "deny",
        Value::obj(vec![("argv0", matcher("glob", "*"))]),
    )];
    let decision = decide(&file_call("read", "rm"), rules, "deny");
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("default"))])
    );
}

fn set_field(doc: &mut Value, key: &str, value: Value) {
    if let Value::Object(pairs) = doc {
        match pairs.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => pairs.push((key.to_string(), value)),
        }
    }
}

fn remove_field(doc: &mut Value, key: &str) {
    if let Value::Object(pairs) = doc {
        pairs.retain(|(k, _)| k != key);
    }
}

// --- fail closed ---------------------------------------------------------

#[test]
fn an_invalid_rule_means_the_policy_does_not_load() {
    let doc = policy_doc(
        vec![plain_rule("bad", "shell", "allow", Value::obj(vec![]))],
        "deny",
    );
    assert!(load_policy(&doc).is_err());
}

#[test]
fn every_schema_valid_call_is_denied_when_the_policy_cannot_load() {
    let doc = shell_call(&["ls"]);
    let decision = evaluate(None, Some("the policy carries a rule of no use"), &doc, AT);
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![
            ("type", s("policy error")),
            ("detail", s("the policy carries a rule of no use")),
        ])
    );
}

#[test]
fn a_malformed_call_is_malformed_even_when_the_policy_cannot_load() {
    let mut broken = shell_call(&["ls"]);
    set_field(&mut broken, "argv", arr(vec![]));
    let decision = evaluate(None, Some("the policy does not parse"), &broken, AT);
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("malformed"))])
    );
}

#[test]
fn an_unparseable_policy_fails_closed_at_the_command_line() {
    let dir = temp_dir("unparseable-policy");
    let policy_path = write_text(&dir.join("policy.json"), "{not json");
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let log_path = dir.join("audit.jsonl");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 1);
    let decision = parse_line(&result.stdout);
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source").get("type"),
        Some(&s("policy error"))
    );
    assert!(field(&decision, "source").get("detail").is_some());
}

#[test]
fn a_policy_with_duplicate_keys_fails_closed_at_the_command_line() {
    let dir = temp_dir("duplicate-policy");
    let policy_path = write_text(
        &dir.join("policy.json"),
        "{\"format\": \"portcullis-policy/1\", \"default\": \"deny\", \
         \"default\": \"allow\", \"rules\": []}",
    );
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let log_path = dir.join("audit.jsonl");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 1);
    let decision = parse_line(&result.stdout);
    assert_eq!(
        field(&decision, "source").get("type"),
        Some(&s("policy error"))
    );
}

#[test]
fn an_unreadable_policy_file_fails_closed_at_the_command_line() {
    let dir = temp_dir("unreadable-policy");
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let log_path = dir.join("audit.jsonl");
    let missing = dir.join("missing.json");
    let result = run_cli(
        &[
            "check",
            "--policy",
            missing.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 1);
    let decision = parse_line(&result.stdout);
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source").get("type"),
        Some(&s("policy error"))
    );
}

// --- rewrites --------------------------------------------------------------

#[test]
fn a_rewrite_carries_the_complete_call_with_other_fields_intact() {
    let rules = vec![rule(
        "stage-writes",
        "file",
        "rewrite",
        Value::obj(vec![
            ("operation", matcher("exact", "write")),
            ("path", matcher("prefix", "/work/out/")),
        ]),
        "writes land in staging",
        Some(Value::obj(vec![("path", s("/work/staging/out.txt"))])),
    )];
    let decision = decide(&file_call("write", "/work/out/report.txt"), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("rewrite"));
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("rule")), ("rule", s("stage-writes"))])
    );
    assert_eq!(field(&decision, "reason"), &s("writes land in staging"));
    let rewritten = field(&decision, "rewritten_call");
    assert_eq!(field(rewritten, "path"), &s("/work/staging/out.txt"));
    assert_eq!(field(rewritten, "operation"), &s("write"));
    assert_eq!(field(rewritten, "kind"), &s("file"));
    assert_eq!(field(rewritten, "format"), &s("portcullis-call/1"));
}

#[test]
fn a_shell_rewrite_replaces_argv_and_keeps_cwd() {
    let rules = vec![rule(
        "calm-curl",
        "shell",
        "rewrite",
        Value::obj(vec![("argv0", matcher("exact", "curl"))]),
        "a reason",
        Some(Value::obj(vec![(
            "argv",
            arr(vec![s("curl"), s("--fail"), s("--silent")]),
        )])),
    )];
    let decision = decide(
        &shell_call_cwd(&["curl", "http://x"], "/work"),
        rules,
        "deny",
    );
    assert_eq!(field(&decision, "decision"), &s("rewrite"));
    let rewritten = field(&decision, "rewritten_call");
    assert_eq!(
        field(rewritten, "argv"),
        &arr(vec![s("curl"), s("--fail"), s("--silent")])
    );
    assert_eq!(field(rewritten, "cwd"), &s("/work"));
}

#[test]
fn a_rewrite_whose_result_fails_validation_denies_with_the_rule_named() {
    let rules = vec![rule(
        "careless-move",
        "file",
        "rewrite",
        Value::obj(vec![("operation", matcher("exact", "read"))]),
        "a reason",
        Some(Value::obj(vec![("operation", s("move"))])),
    )];
    let decision = decide(&file_call("read", "/work/a.txt"), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("rule")), ("rule", s("careless-move"))])
    );
    assert_eq!(field(&decision, "rewritten_call"), &Value::Null);
}

#[test]
fn a_rewrite_of_a_url_call_emits_the_explicit_form() {
    let rules = vec![rule(
        "pin-port",
        "network",
        "rewrite",
        Value::obj(vec![("host", matcher("exact", "api.example.test"))]),
        "a reason",
        Some(Value::obj(vec![("port", Value::int(8443))])),
    )];
    let call = Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
        ("url", s("https://api.example.test/items")),
    ]);
    let decision = decide(&call, rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("rewrite"));
    let rewritten = field(&decision, "rewritten_call");
    assert_eq!(field(rewritten, "host"), &s("api.example.test"));
    assert_eq!(field(rewritten, "port"), &Value::int(8443));
    assert_eq!(field(rewritten, "method"), &s("GET"));
    assert!(rewritten.get("url").is_none());
}

// --- the interpreter marker --------------------------------------------------

macro_rules! interpreter_flagged {
    ($name:ident, $argv:expr) => {
        #[test]
        fn $name() {
            let decision = decide(&shell_call($argv), vec![], "allow");
            assert_eq!(field(&decision, "interpreter"), &Value::Bool(true));
        }
    };
}

interpreter_flagged!(interpreter_calls_are_flagged_sh, &["sh", "-c", "ls"]);
interpreter_flagged!(interpreter_calls_are_flagged_bash, &["bash", "-c", "ls"]);
interpreter_flagged!(
    interpreter_calls_are_flagged_bin_sh,
    &["/bin/sh", "-c", "ls"]
);
interpreter_flagged!(
    interpreter_calls_are_flagged_usr_bin_bash,
    &["/usr/bin/bash", "script.sh"]
);
interpreter_flagged!(interpreter_calls_are_flagged_dot_zsh, &["./zsh", "-l"]);

macro_rules! interpreter_not_flagged {
    ($name:ident, $argv:expr) => {
        #[test]
        fn $name() {
            let decision = decide(&shell_call($argv), vec![], "allow");
            assert_eq!(field(&decision, "interpreter"), &Value::Bool(false));
        }
    };
}

interpreter_not_flagged!(non_interpreter_calls_are_not_flagged_ls, &["ls", "-la"]);
interpreter_not_flagged!(
    non_interpreter_calls_are_not_flagged_python3,
    &["python3", "-c", "print(1)"]
);
interpreter_not_flagged!(
    non_interpreter_calls_are_not_flagged_shellcheck,
    &["shellcheck", "x"]
);
interpreter_not_flagged!(non_interpreter_calls_are_not_flagged_rm, &["rm", "x"]);

#[test]
fn a_malformed_shell_call_is_not_flagged() {
    let mut broken = shell_call(&["sh", "-c", "ls"]);
    set_field(&mut broken, "argv", s("sh -c ls"));
    let decision = decide(&broken, vec![], "allow");
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("malformed"))])
    );
    assert_eq!(field(&decision, "interpreter"), &Value::Bool(false));
}

#[test]
fn file_and_network_calls_are_not_flagged() {
    let file = decide(&file_call("read", "/bin/sh"), vec![], "allow");
    assert_eq!(field(&file, "interpreter"), &Value::Bool(false));
    let net = decide(
        &network_call("GET", "example.test", Value::int(443)),
        vec![],
        "allow",
    );
    assert_eq!(field(&net, "interpreter"), &Value::Bool(false));
}

// --- matching ------------------------------------------------------------------

#[test]
fn a_path_rule_fires_on_the_given_form() {
    let rules = vec![plain_rule(
        "deny-raw",
        "file",
        "deny",
        Value::obj(vec![("path", matcher("glob", "*/../secret.txt"))]),
    )];
    let decision = decide(&file_call("read", "a/../secret.txt"), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(field(&decision, "source").get("rule"), Some(&s("deny-raw")));
}

#[test]
fn a_path_rule_fires_only_on_the_normalized_form() {
    let rules = vec![plain_rule(
        "deny-secret",
        "file",
        "deny",
        Value::obj(vec![("path", matcher("exact", "secret.txt"))]),
    )];
    let decision = decide(&file_call("read", "a/../secret.txt"), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source").get("rule"),
        Some(&s("deny-secret"))
    );
}

#[test]
fn a_path_prefix_matches_the_normalized_form() {
    let rules = vec![plain_rule(
        "deny-etc",
        "file",
        "deny",
        Value::obj(vec![("path", matcher("prefix", "/etc/"))]),
    )];
    let decision = decide(&file_call("write", "/tmp/../etc/hosts"), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
}

#[test]
fn an_argument_condition_fails_when_argv_is_too_short() {
    let rules = vec![plain_rule(
        "deny-third",
        "shell",
        "deny",
        Value::obj(vec![(
            "args",
            arr(vec![Value::obj(vec![
                ("index", Value::int(3)),
                ("match", matcher("exact", "x")),
            ])]),
        )]),
    )];
    let decision = decide(&shell_call(&["tool", "a"]), rules, "deny");
    assert_eq!(
        field(&decision, "source"),
        &Value::obj(vec![("type", s("default"))])
    );
}

#[test]
fn an_argument_condition_matches_at_its_position() {
    let rules = vec![plain_rule(
        "deny-flag",
        "shell",
        "deny",
        Value::obj(vec![(
            "args",
            arr(vec![Value::obj(vec![
                ("index", Value::int(2)),
                ("match", matcher("exact", "--force")),
            ])]),
        )]),
    )];
    let decision = decide(&shell_call(&["tool", "run", "--force"]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
}

#[test]
fn host_matching_folds_case_on_both_sides() {
    let rules = vec![plain_rule(
        "allow-api",
        "network",
        "allow",
        Value::obj(vec![("host", matcher("exact", "API.example.TEST"))]),
    )];
    let decision = decide(
        &network_call("GET", "api.EXAMPLE.test", Value::int(443)),
        rules,
        "deny",
    );
    assert_eq!(field(&decision, "decision"), &s("allow"));
}

#[test]
fn method_matching_is_case_sensitive_as_given() {
    let rules = vec![plain_rule(
        "allow-get",
        "network",
        "allow",
        Value::obj(vec![("method", matcher("exact", "GET"))]),
    )];
    let lower = decide(
        &network_call("get", "h.test", Value::int(80)),
        rules.clone(),
        "deny",
    );
    assert_eq!(field(&lower, "decision"), &s("deny"));
    let upper = decide(
        &network_call("GET", "h.test", Value::int(80)),
        rules,
        "deny",
    );
    assert_eq!(field(&upper, "decision"), &s("allow"));
}

#[test]
fn a_port_matcher_matches_the_exact_port_only() {
    let rules = vec![plain_rule(
        "allow-tls",
        "network",
        "allow",
        Value::obj(vec![("port", Value::obj(vec![("exact", Value::int(443))]))]),
    )];
    let tls = decide(
        &network_call("GET", "h.test", Value::int(443)),
        rules.clone(),
        "deny",
    );
    assert_eq!(field(&tls, "decision"), &s("allow"));
    let alt = decide(
        &network_call("GET", "h.test", Value::int(8443)),
        rules,
        "deny",
    );
    assert_eq!(field(&alt, "decision"), &s("deny"));
}

#[test]
fn a_url_call_reads_its_host_and_default_port() {
    let rules = vec![plain_rule(
        "allow-https",
        "network",
        "allow",
        Value::obj(vec![
            ("host", matcher("exact", "example.test")),
            ("port", Value::obj(vec![("exact", Value::int(443))])),
        ]),
    )];
    let call = Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
        ("url", s("https://EXAMPLE.test/items")),
    ]);
    let decision = decide(&call, rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("allow"));
}

#[test]
fn a_url_call_reads_an_explicit_port() {
    let rules = vec![plain_rule(
        "allow-alt",
        "network",
        "allow",
        Value::obj(vec![(
            "port",
            Value::obj(vec![("exact", Value::int(8080))]),
        )]),
    )];
    let call = Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
        ("url", s("http://example.test:8080/items")),
    ]);
    let decision = decide(&call, rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("allow"));
}

// --- strict reading of calls ---------------------------------------------------

macro_rules! malformed_case {
    ($name:ident, $doc:expr) => {
        #[test]
        fn $name() {
            let decision = decide(&$doc, vec![], "allow");
            assert_eq!(field(&decision, "decision"), &s("deny"));
            assert_eq!(
                field(&decision, "source"),
                &Value::obj(vec![("type", s("malformed"))])
            );
        }
    };
}

malformed_case!(
    malformed_call_shapes_shell_without_argv,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("shell"))
    ])
);
malformed_case!(
    malformed_call_shapes_shell_with_empty_argv,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("shell")),
        ("argv", arr(vec![])),
    ])
);
malformed_case!(
    malformed_call_shapes_shell_with_a_number_in_argv,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("shell")),
        ("argv", arr(vec![s("ls"), Value::int(3)])),
    ])
);
malformed_case!(
    malformed_call_shapes_shell_with_a_path_field,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("shell")),
        ("argv", arr(vec![s("ls")])),
        ("path", s("x")),
    ])
);
malformed_case!(
    malformed_call_shapes_file_without_a_path,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("file")),
        ("operation", s("read")),
    ])
);
malformed_case!(
    malformed_call_shapes_file_with_an_unknown_operation,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("file")),
        ("operation", s("peek")),
        ("path", s("x")),
    ])
);
malformed_case!(
    malformed_call_shapes_move_without_a_second_path,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("file")),
        ("operation", s("move")),
        ("path", s("x")),
    ])
);
malformed_case!(
    malformed_call_shapes_read_with_a_second_path,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("file")),
        ("operation", s("read")),
        ("path", s("x")),
        ("path2", s("y")),
    ])
);
malformed_case!(
    malformed_call_shapes_file_with_an_empty_path,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("file")),
        ("operation", s("read")),
        ("path", s("")),
    ])
);
malformed_case!(
    malformed_call_shapes_with_an_unknown_format,
    Value::obj(vec![
        ("format", s("other/9")),
        ("kind", s("shell")),
        ("argv", arr(vec![s("ls")])),
    ])
);
malformed_case!(
    malformed_call_shapes_with_an_unknown_kind,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("teleport")),
        ("argv", arr(vec![s("ls")])),
    ])
);
malformed_case!(
    malformed_call_shapes_network_without_host_or_url,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
    ])
);
malformed_case!(
    malformed_call_shapes_network_with_a_boolean_port,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
        ("host", s("h.test")),
        ("port", Value::Bool(true)),
    ])
);
malformed_case!(
    malformed_call_shapes_network_with_a_port_out_of_range,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
        ("host", s("h.test")),
        ("port", Value::int(70000)),
    ])
);
malformed_case!(
    malformed_call_shapes_network_with_url_and_host,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
        ("host", s("h.test")),
        ("port", Value::int(443)),
        ("url", s("https://h.test/")),
    ])
);
malformed_case!(
    malformed_call_shapes_network_with_userinfo_in_the_url,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
        ("url", s("https://user:pw@h.test/")),
    ])
);
malformed_case!(
    malformed_call_shapes_network_with_an_unknown_scheme,
    Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("network")),
        ("method", s("GET")),
        ("url", s("gopher://h.test/")),
    ])
);
malformed_case!(
    malformed_call_shapes_a_document_that_is_not_an_object,
    arr(vec![s("not"), s("an"), s("object")])
);

#[test]
fn a_call_with_duplicate_keys_never_reaches_a_decision() {
    let dir = temp_dir("duplicate-call");
    let call_path = write_text(
        &dir.join("call.json"),
        "{\"format\": \"portcullis-call/1\", \"kind\": \"shell\", \
         \"kind\": \"shell\", \"argv\": [\"ls\"]}",
    );
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(vec![], "deny"));
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            dir.join("audit.jsonl").to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 2);
    assert_eq!(result.stdout, "");
}

#[test]
fn a_call_with_a_nonstandard_constant_is_a_caller_error() {
    let dir = temp_dir("constant-call");
    let call_path = write_text(
        &dir.join("call.json"),
        "{\"format\": \"portcullis-call/1\", \"kind\": \"shell\", \"argv\": [NaN]}",
    );
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(vec![], "deny"));
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            dir.join("audit.jsonl").to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 2);
}

// --- strict reading of policies ------------------------------------------------

macro_rules! bad_policy_case {
    ($name:ident, $doc:expr) => {
        #[test]
        fn $name() {
            assert!(load_policy(&$doc).is_err());
        }
    };
}

bad_policy_case!(
    bad_policy_shapes_without_a_default,
    Value::obj(vec![
        ("format", s("portcullis-policy/1")),
        ("rules", arr(vec![])),
    ])
);
bad_policy_case!(
    bad_policy_shapes_with_a_rewrite_default,
    policy_doc(vec![], "rewrite")
);
bad_policy_case!(
    bad_policy_shapes_with_an_extra_field,
    Value::obj(vec![
        ("format", s("portcullis-policy/1")),
        ("default", s("deny")),
        ("rules", arr(vec![])),
        ("extra", Value::int(1)),
    ])
);
bad_policy_case!(
    bad_policy_shapes_with_an_unknown_format,
    Value::obj(vec![
        ("format", s("other/9")),
        ("default", s("deny")),
        ("rules", arr(vec![])),
    ])
);
bad_policy_case!(
    bad_policy_shapes_with_a_duplicate_rule_id,
    policy_doc(
        vec![
            plain_rule(
                "dup",
                "shell",
                "allow",
                Value::obj(vec![("argv0", matcher("exact", "ls"))])
            ),
            plain_rule(
                "dup",
                "shell",
                "deny",
                Value::obj(vec![("argv0", matcher("exact", "rm"))])
            ),
        ],
        "deny",
    )
);
bad_policy_case!(
    bad_policy_shapes_with_an_empty_match,
    policy_doc(
        vec![plain_rule("empty", "shell", "allow", Value::obj(vec![]))],
        "deny",
    )
);
bad_policy_case!(
    bad_policy_shapes_with_two_matcher_forms,
    policy_doc(
        vec![plain_rule(
            "two-forms",
            "shell",
            "allow",
            Value::obj(vec![(
                "argv0",
                Value::obj(vec![("exact", s("ls")), ("prefix", s("l"))]),
            )]),
        )],
        "deny",
    )
);
bad_policy_case!(
    bad_policy_shapes_rewrite_without_a_substitute,
    policy_doc(
        vec![plain_rule(
            "no-sub",
            "shell",
            "rewrite",
            Value::obj(vec![("argv0", matcher("exact", "ls"))]),
        )],
        "deny",
    )
);
bad_policy_case!(
    bad_policy_shapes_allow_with_a_substitute,
    policy_doc(
        vec![rule(
            "stray-sub",
            "shell",
            "allow",
            Value::obj(vec![("argv0", matcher("exact", "ls"))]),
            "a reason",
            Some(Value::obj(vec![("argv", arr(vec![s("ls")]))])),
        )],
        "deny",
    )
);
bad_policy_case!(
    bad_policy_shapes_with_an_empty_reason,
    policy_doc(
        vec![rule(
            "quiet",
            "shell",
            "allow",
            Value::obj(vec![("argv0", matcher("exact", "ls"))]),
            "",
            None,
        )],
        "deny",
    )
);
bad_policy_case!(
    bad_policy_shapes_with_a_glob_port_matcher,
    policy_doc(
        vec![plain_rule(
            "bad-port",
            "network",
            "allow",
            Value::obj(vec![("port", matcher("glob", "44*"))]),
        )],
        "deny",
    )
);
bad_policy_case!(
    bad_policy_shapes_with_an_argument_index_of_zero,
    policy_doc(
        vec![plain_rule(
            "bad-index",
            "shell",
            "allow",
            Value::obj(vec![(
                "args",
                arr(vec![Value::obj(vec![
                    ("index", Value::int(0)),
                    ("match", matcher("exact", "x")),
                ])]),
            )]),
        )],
        "deny",
    )
);
bad_policy_case!(
    bad_policy_shapes_with_an_unknown_kind,
    policy_doc(
        vec![plain_rule(
            "bad-kind",
            "teleport",
            "allow",
            Value::obj(vec![("argv0", matcher("exact", "ls"))]),
        )],
        "deny",
    )
);

#[test]
fn a_policy_with_duplicate_keys_does_not_parse_strictly() {
    let text = "{\"format\": \"portcullis-policy/1\", \"default\": \"deny\", \
        \"rules\": [{\"id\": \"a\", \"id\": \"a\", \"kind\": \"shell\", \
        \"action\": \"allow\", \"reason\": \"r\", \
        \"match\": {\"argv0\": {\"exact\": \"ls\"}}}]}";
    assert!(strict_parse(text).is_err());
}

// --- the decision record ---------------------------------------------------------

#[test]
fn the_decision_record_carries_every_field_of_the_contract() {
    let rules = vec![plain_rule(
        "allow-ls",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("exact", "ls"))]),
    )];
    let call = shell_call(&["ls"]);
    let decision = decide(&call, rules, "deny");
    let mut keys: Vec<&str> = decision
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, _)| key.as_str())
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "at",
            "call_digest",
            "decision",
            "format",
            "interpreter",
            "reason",
            "rewritten_call",
            "source",
        ]
    );
    assert_eq!(field(&decision, "format"), &s("portcullis-decision/1"));
    assert_eq!(field(&decision, "at"), &s(AT));
    let canonical_text = "{\"argv\":[\"ls\"],\"format\":\"portcullis-call/1\",\"kind\":\"shell\"}";
    let digest = Sha256::digest(canonical_text.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        field(&decision, "call_digest"),
        &s(&format!("sha256:{hex}"))
    );
    assert_eq!(field(&decision, "reason"), &s("a reason"));
    assert_eq!(field(&decision, "rewritten_call"), &Value::Null);
}

#[test]
fn the_same_policy_and_call_decide_the_same_apart_from_the_instant() {
    let rules = vec![plain_rule(
        "allow-ls",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("exact", "ls"))]),
    )];
    let policy: Policy = load_policy(&policy_doc(rules, "deny")).unwrap();
    let call = shell_call(&["ls"]);
    let mut first = evaluate(Some(&policy), None, &call, "2026-11-02T10:00:00+00:00");
    let mut second = evaluate(Some(&policy), None, &call, "2026-11-02T11:00:00+00:00");
    remove_field(&mut first, "at");
    remove_field(&mut second, "at");
    assert_eq!(first, second);
}

// --- the audit log -----------------------------------------------------------------

#[test]
fn appended_decisions_read_back_whole() {
    let dir = temp_dir("append-read");
    let log_path = dir.join("audit.jsonl");
    let decision = decide(&shell_call(&["ls"]), vec![], "allow");
    portcullis::append_decision(&log_path, &decision).unwrap();
    let records = read_log(&log_path).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(canonical(&records[0]), canonical(&decision));
}

fn parallel_check_worker(task: (String, String, String)) -> i32 {
    let (policy_path, call_path, log_path) = task;
    run_cli(
        &[
            "check",
            "--policy",
            &policy_path,
            "--log",
            &log_path,
            &call_path,
        ],
        None,
    )
    .status
}

#[test]
fn parallel_checks_append_whole_lines_only() {
    let dir = temp_dir("parallel");
    let policy_path = write_json(
        &dir.join("policy.json"),
        &policy_doc(
            vec![plain_rule(
                "allow-ls",
                "shell",
                "allow",
                Value::obj(vec![("argv0", matcher("exact", "ls"))]),
            )],
            "deny",
        ),
    );
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let log_path = dir.join("audit.jsonl");
    let task = (
        policy_path.to_str().unwrap().to_string(),
        call_path.to_str().unwrap().to_string(),
        log_path.to_str().unwrap().to_string(),
    );
    let mut handles = Vec::new();
    for _ in 0..8 {
        let task = task.clone();
        handles.push(std::thread::spawn(move || {
            (0..5)
                .map(|_| parallel_check_worker(task.clone()))
                .collect::<Vec<i32>>()
        }));
    }
    let mut codes: Vec<i32> = Vec::new();
    for handle in handles {
        codes.extend(handle.join().unwrap());
    }
    assert_eq!(codes, [0; 40]);
    let records = read_log(&log_path).unwrap();
    assert_eq!(records.len(), 40);
    let text = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 40);
    for line in lines {
        strict_parse(line).unwrap();
    }
}

#[test]
fn a_torn_final_line_is_reported_at_its_line() {
    let dir = temp_dir("torn");
    let log_path = dir.join("audit.jsonl");
    let decision = decide(&shell_call(&["ls"]), vec![], "allow");
    portcullis::append_decision(&log_path, &decision).unwrap();
    portcullis::append_decision(&log_path, &decision).unwrap();
    let mut handle = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    handle
        .write_all(b"{\"format\": \"portcullis-decision/1\", \"at\": \"2026-")
        .unwrap();
    drop(handle);
    let result = run_cli(&["log", "--log", log_path.to_str().unwrap()], None);
    assert_eq!(result.status, 1);
    assert!(result.stderr.contains("line 3"), "{}", result.stderr);
}

#[test]
fn a_spoiled_middle_line_is_reported_at_its_line() {
    let dir = temp_dir("spoiled");
    let log_path = dir.join("audit.jsonl");
    let decision = decide(&shell_call(&["ls"]), vec![], "allow");
    portcullis::append_decision(&log_path, &decision).unwrap();
    let mut handle = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    handle
        .write_all(b"{\"format\": \"portcullis-decision/1\"}\n")
        .unwrap();
    drop(handle);
    portcullis::append_decision(&log_path, &decision).unwrap();
    let result = run_cli(&["log", "--log", log_path.to_str().unwrap()], None);
    assert_eq!(result.status, 1);
    assert!(result.stderr.contains("line 2"), "{}", result.stderr);
}

#[test]
fn a_decision_that_cannot_be_appended_is_not_delivered() {
    let dir = temp_dir("no-append");
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(vec![], "deny"));
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let log_path = dir.join("no-such-dir").join("audit.jsonl");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 2);
    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("could not be appended"),
        "{}",
        result.stderr
    );
}

#[test]
fn the_log_command_prints_verified_records() {
    let dir = temp_dir("log-prints");
    let log_path = dir.join("audit.jsonl");
    let decision = decide(&shell_call(&["ls"]), vec![], "allow");
    portcullis::append_decision(&log_path, &decision).unwrap();
    let result = run_cli(&["log", "--log", log_path.to_str().unwrap()], None);
    assert_eq!(result.status, 0);
    let printed: Vec<Value> = result
        .stdout
        .lines()
        .map(|line| strict_parse(line).unwrap())
        .collect();
    assert_eq!(printed.len(), 1);
    assert_eq!(canonical(&printed[0]), canonical(&decision));
}

#[test]
fn the_log_command_treats_a_missing_log_as_a_caller_error() {
    let dir = temp_dir("log-missing");
    let result = run_cli(
        &["log", "--log", dir.join("missing.jsonl").to_str().unwrap()],
        None,
    );
    assert_eq!(result.status, 2);
}

// --- the command line ---------------------------------------------------------------

fn cli_check(
    dir: &Path,
    call_doc: &Value,
    rules: Vec<Value>,
    default: &str,
    stdin: bool,
) -> CliOutput {
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(rules, default));
    let log_path = dir.join("audit.jsonl");
    if stdin {
        let text = String::from_utf8(canonical(call_doc)).unwrap();
        run_cli(
            &[
                "check",
                "--policy",
                policy_path.to_str().unwrap(),
                "--log",
                log_path.to_str().unwrap(),
            ],
            Some(&text),
        )
    } else {
        let call_path = write_json(&dir.join("call.json"), call_doc);
        run_cli(
            &[
                "check",
                "--policy",
                policy_path.to_str().unwrap(),
                "--log",
                log_path.to_str().unwrap(),
                call_path.to_str().unwrap(),
            ],
            None,
        )
    }
}

#[test]
fn cli_allow_exits_zero() {
    let dir = temp_dir("cli-allow");
    let result = cli_check(
        &dir,
        &shell_call(&["ls"]),
        vec![plain_rule(
            "allow-ls",
            "shell",
            "allow",
            Value::obj(vec![("argv0", matcher("exact", "ls"))]),
        )],
        "deny",
        false,
    );
    assert_eq!(result.status, 0);
    assert_eq!(field(&parse_line(&result.stdout), "decision"), &s("allow"));
}

#[test]
fn cli_rewrite_exits_zero() {
    let dir = temp_dir("cli-rewrite");
    let result = cli_check(
        &dir,
        &file_call("write", "/work/out/a.txt"),
        vec![rule(
            "stage",
            "file",
            "rewrite",
            Value::obj(vec![("path", matcher("prefix", "/work/out/"))]),
            "a reason",
            Some(Value::obj(vec![("path", s("/work/staging/a.txt"))])),
        )],
        "deny",
        false,
    );
    assert_eq!(result.status, 0);
    assert_eq!(
        field(&parse_line(&result.stdout), "decision"),
        &s("rewrite")
    );
}

#[test]
fn cli_deny_by_rule_exits_one() {
    let dir = temp_dir("cli-deny");
    let result = cli_check(
        &dir,
        &shell_call(&["rm", "x"]),
        vec![plain_rule(
            "deny-rm",
            "shell",
            "deny",
            Value::obj(vec![("argv0", matcher("exact", "rm"))]),
        )],
        "deny",
        false,
    );
    assert_eq!(result.status, 1);
    assert_eq!(field(&parse_line(&result.stdout), "decision"), &s("deny"));
}

#[test]
fn cli_malformed_exits_one() {
    let dir = temp_dir("cli-malformed");
    let broken = Value::obj(vec![
        ("format", s("portcullis-call/1")),
        ("kind", s("shell")),
    ]);
    let result = cli_check(&dir, &broken, vec![], "deny", false);
    assert_eq!(result.status, 1);
    assert_eq!(
        field(&parse_line(&result.stdout), "source"),
        &Value::obj(vec![("type", s("malformed"))])
    );
}

#[test]
fn cli_reads_a_call_from_standard_input() {
    let dir = temp_dir("cli-stdin");
    let result = cli_check(
        &dir,
        &shell_call(&["ls"]),
        vec![plain_rule(
            "allow-ls",
            "shell",
            "allow",
            Value::obj(vec![("argv0", matcher("exact", "ls"))]),
        )],
        "deny",
        true,
    );
    assert_eq!(result.status, 0);
    assert_eq!(field(&parse_line(&result.stdout), "decision"), &s("allow"));
}

#[test]
fn cli_an_unparseable_call_exits_two() {
    let dir = temp_dir("cli-unparseable");
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(vec![], "deny"));
    let call_path = write_text(&dir.join("call.json"), "this is not json");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            dir.join("audit.jsonl").to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 2);
    assert_eq!(result.stdout, "");
}

#[test]
fn cli_a_missing_call_file_exits_two() {
    let dir = temp_dir("cli-missing-call");
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(vec![], "deny"));
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            dir.join("audit.jsonl").to_str().unwrap(),
            dir.join("missing.json").to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 2);
}

#[test]
fn cli_bad_arguments_exit_two() {
    let dir = temp_dir("cli-bad-args");
    let result = run_cli(
        &["check", "--log", dir.join("audit.jsonl").to_str().unwrap()],
        None,
    );
    assert_eq!(result.status, 2);
}

#[test]
fn cli_check_appends_the_decision_it_prints() {
    let dir = temp_dir("cli-appends");
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(vec![], "deny"));
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let log_path = dir.join("audit.jsonl");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    let printed = parse_line(&result.stdout);
    assert_eq!(read_log(&log_path).unwrap(), [printed]);
}

// --- repair pass pins -------------------------------------------------------------

#[test]
fn rewrite_into_an_interpreter_call_is_flagged() {
    let rules = vec![rule(
        "become-shell",
        "shell",
        "rewrite",
        Value::obj(vec![("argv0", matcher("exact", "ls"))]),
        "a reason",
        Some(Value::obj(vec![(
            "argv",
            arr(vec![s("sh"), s("-c"), s("id")]),
        )])),
    )];
    let decision = decide(&shell_call(&["ls"]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("rewrite"));
    assert_eq!(
        field(field(&decision, "rewritten_call"), "argv"),
        &arr(vec![s("sh"), s("-c"), s("id")])
    );
    assert_eq!(field(&decision, "interpreter"), &Value::Bool(true));
}

#[test]
fn an_interpreter_call_rewritten_to_a_harmless_call_stays_flagged() {
    let rules = vec![rule(
        "calm-shell",
        "shell",
        "rewrite",
        Value::obj(vec![("argv0", matcher("exact", "sh"))]),
        "a reason",
        Some(Value::obj(vec![("argv", arr(vec![s("echo"), s("hi")]))])),
    )];
    let decision = decide(&shell_call(&["sh", "-c", "ls"]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("rewrite"));
    assert_eq!(
        field(field(&decision, "rewritten_call"), "argv"),
        &arr(vec![s("echo"), s("hi")])
    );
    assert_eq!(field(&decision, "interpreter"), &Value::Bool(true));
}

fn write_log_lines(log_path: &Path, records: &[Value]) {
    let mut text = String::new();
    for record in records {
        text.push_str(&String::from_utf8(canonical(record)).unwrap());
        text.push('\n');
    }
    std::fs::write(log_path, text).unwrap();
}

fn valid_allow_record() -> Value {
    let rules = vec![plain_rule(
        "allow-ls",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("exact", "ls"))]),
    )];
    decide(&shell_call(&["ls"]), rules, "deny")
}

fn valid_rewrite_record() -> Value {
    let rules = vec![rule(
        "stage",
        "shell",
        "rewrite",
        Value::obj(vec![("argv0", matcher("exact", "ls"))]),
        "a reason",
        Some(Value::obj(vec![("argv", arr(vec![s("ls"), s("-la")]))])),
    )];
    decide(&shell_call(&["ls"]), rules, "deny")
}

fn assert_corruption_at_line_two(tag: &str, tampered: Value) {
    let dir = temp_dir(tag);
    let log_path = dir.join("audit.jsonl");
    write_log_lines(&log_path, &[valid_allow_record(), tampered]);
    match read_log(&log_path) {
        Err(LogReadError::Corruption(exc)) => assert_eq!(exc.line_number, 2),
        other => panic!("expected corruption at line 2, got {other:?}"),
    }
}

#[test]
fn a_rewrite_record_with_an_invalid_rewritten_call_is_corruption() {
    let mut tampered = valid_rewrite_record();
    set_field(
        &mut tampered,
        "rewritten_call",
        Value::obj(vec![
            ("format", s("portcullis-call/1")),
            ("kind", s("shell")),
            ("argv", arr(vec![])),
        ]),
    );
    assert_corruption_at_line_two("tamper-bad-rewrite", tampered);
}

#[test]
fn a_non_rewrite_record_carrying_a_rewritten_call_is_corruption() {
    let mut tampered = valid_allow_record();
    set_field(&mut tampered, "rewritten_call", shell_call(&["ls"]));
    assert_corruption_at_line_two("tamper-stray-rewrite", tampered);
}

fn tamper(changes: Vec<(&str, Value)>) -> Value {
    let mut record = valid_allow_record();
    for (key, value) in changes {
        set_field(&mut record, key, value);
    }
    record
}

macro_rules! cross_field_tamper {
    ($name:ident, $tag:expr, $changes:expr) => {
        #[test]
        fn $name() {
            assert_corruption_at_line_two($tag, tamper($changes));
        }
    };
}

cross_field_tamper!(
    log_records_whose_fields_disagree_malformed_source_on_an_allow,
    "tamper-cross-1",
    vec![("source", Value::obj(vec![("type", s("malformed"))]))]
);
cross_field_tamper!(
    log_records_whose_fields_disagree_malformed_with_a_reason,
    "tamper-cross-2",
    vec![
        ("decision", s("deny")),
        ("source", Value::obj(vec![("type", s("malformed"))])),
        ("reason", s("a reason")),
    ]
);
cross_field_tamper!(
    log_records_whose_fields_disagree_malformed_with_interpreter_set,
    "tamper-cross-3",
    vec![
        ("decision", s("deny")),
        ("source", Value::obj(vec![("type", s("malformed"))])),
        ("interpreter", Value::Bool(true)),
    ]
);
cross_field_tamper!(
    log_records_whose_fields_disagree_policy_error_source_on_an_allow,
    "tamper-cross-4",
    vec![(
        "source",
        Value::obj(vec![
            ("type", s("policy error")),
            ("detail", s("a failure")),
        ]),
    )]
);
cross_field_tamper!(
    log_records_whose_fields_disagree_rule_source_without_a_reason,
    "tamper-cross-5",
    vec![("reason", Value::Null)]
);
cross_field_tamper!(
    log_records_whose_fields_disagree_rule_source_with_an_empty_reason,
    "tamper-cross-6",
    vec![("reason", s(""))]
);
cross_field_tamper!(
    log_records_whose_fields_disagree_default_source_with_a_reason,
    "tamper-cross-7",
    vec![
        ("decision", s("deny")),
        ("source", Value::obj(vec![("type", s("default"))])),
        ("reason", s("a reason")),
    ]
);

#[test]
fn a_rewrite_record_with_a_default_source_is_corruption() {
    let mut tampered = valid_rewrite_record();
    set_field(
        &mut tampered,
        "source",
        Value::obj(vec![("type", s("default"))]),
    );
    set_field(&mut tampered, "reason", Value::Null);
    assert_corruption_at_line_two("tamper-rewrite-default", tampered);
}

#[test]
fn a_log_record_with_a_non_hex_digest_is_corruption() {
    let tampered = tamper(vec![(
        "call_digest",
        s(&format!("sha256:{}", "z".repeat(64))),
    )]);
    assert_corruption_at_line_two("tamper-digest", tampered);
}

#[test]
fn a_policy_with_invalid_utf8_fails_closed_at_the_command_line() {
    let dir = temp_dir("policy-utf8");
    let policy_path = dir.join("policy.json");
    std::fs::write(&policy_path, b"\xff\xfe\xfd").unwrap();
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let log_path = dir.join("audit.jsonl");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 1);
    assert!(!result.stderr.contains("Traceback"));
    let decision = parse_line(&result.stdout);
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source").get("type"),
        Some(&s("policy error"))
    );
    assert_eq!(read_log(&log_path).unwrap().len(), 1);
}

#[test]
fn a_call_with_invalid_utf8_is_a_caller_error_at_the_command_line() {
    let dir = temp_dir("call-utf8");
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(vec![], "deny"));
    let call_path = dir.join("call.json");
    std::fs::write(&call_path, b"\xff\xfe\xfd").unwrap();
    let log_path = dir.join("audit.jsonl");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 2);
    assert_eq!(result.stdout, "");
    assert!(!result.stderr.contains("Traceback"));
    assert_eq!(result.stderr.matches('\n').count(), 1, "{}", result.stderr);
    assert!(!log_path.exists());
}

#[test]
fn strict_parse_refuses_a_lone_surrogate() {
    let text = "{\"format\": \"portcullis-call/1\", \"kind\": \"shell\", \"argv\": [\"\\ud800\"]}";
    assert!(strict_parse(text).is_err());
}

#[test]
fn a_call_with_a_lone_surrogate_is_a_caller_error() {
    let dir = temp_dir("call-surrogate");
    let policy_path = write_json(&dir.join("policy.json"), &policy_doc(vec![], "deny"));
    let call_path = write_text(
        &dir.join("call.json"),
        "{\"format\": \"portcullis-call/1\", \"kind\": \"shell\", \"argv\": [\"\\ud800\"]}",
    );
    let log_path = dir.join("audit.jsonl");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 2);
    assert_eq!(result.stdout, "");
    assert!(!result.stderr.contains("Traceback"));
    assert!(!log_path.exists());
}

#[test]
fn a_policy_with_a_lone_surrogate_fails_closed() {
    let dir = temp_dir("policy-surrogate");
    let policy_path = write_text(
        &dir.join("policy.json"),
        "{\"format\": \"portcullis-policy/1\", \"default\": \"deny\", \"rules\": \
         [{\"id\": \"a\", \"kind\": \"shell\", \"action\": \"allow\", \
         \"reason\": \"\\ud800\", \"match\": {\"argv0\": {\"exact\": \"ls\"}}}]}",
    );
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let log_path = dir.join("audit.jsonl");
    let result = run_cli(
        &[
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--log",
            log_path.to_str().unwrap(),
            call_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(result.status, 1);
    assert!(!result.stderr.contains("Traceback"));
    let decision = parse_line(&result.stdout);
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert_eq!(
        field(&decision, "source").get("type"),
        Some(&s("policy error"))
    );
}

macro_rules! arg_condition_missing {
    ($name:ident, $condition:expr) => {
        #[test]
        fn $name() {
            let doc = policy_doc(
                vec![plain_rule(
                    "bad-cond",
                    "shell",
                    "allow",
                    Value::obj(vec![("args", arr(vec![$condition]))]),
                )],
                "deny",
            );
            assert!(load_policy(&doc).is_err());
        }
    };
}

arg_condition_missing!(
    an_argument_condition_missing_a_key_never_loads_without_index,
    Value::obj(vec![("match", matcher("exact", "x"))])
);
arg_condition_missing!(
    an_argument_condition_missing_a_key_never_loads_without_match,
    Value::obj(vec![("index", Value::int(1))])
);

macro_rules! arg_condition_missing_cli {
    ($name:ident, $tag:expr, $condition:expr) => {
        #[test]
        fn $name() {
            let dir = temp_dir($tag);
            let policy_path = write_json(
                &dir.join("policy.json"),
                &policy_doc(
                    vec![plain_rule(
                        "bad-cond",
                        "shell",
                        "allow",
                        Value::obj(vec![("args", arr(vec![$condition]))]),
                    )],
                    "deny",
                ),
            );
            let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls", "x"]));
            let log_path = dir.join("audit.jsonl");
            let result = run_cli(
                &[
                    "check",
                    "--policy",
                    policy_path.to_str().unwrap(),
                    "--log",
                    log_path.to_str().unwrap(),
                    call_path.to_str().unwrap(),
                ],
                None,
            );
            assert_eq!(result.status, 1);
            assert!(!result.stderr.contains("Traceback"));
            let decision = parse_line(&result.stdout);
            assert_eq!(field(&decision, "decision"), &s("deny"));
            assert_eq!(
                field(&decision, "source").get("type"),
                Some(&s("policy error"))
            );
        }
    };
}

arg_condition_missing_cli!(
    an_argument_condition_missing_a_key_fails_closed_at_the_cli_without_index,
    "arg-cond-cli-1",
    Value::obj(vec![("match", matcher("exact", "x"))])
);
arg_condition_missing_cli!(
    an_argument_condition_missing_a_key_fails_closed_at_the_cli_without_match,
    "arg-cond-cli-2",
    Value::obj(vec![("index", Value::int(1))])
);

#[test]
fn an_undecodable_log_line_is_corruption_at_its_line() {
    let dir = temp_dir("undecodable-log");
    let log_path = dir.join("audit.jsonl");
    let decision = valid_allow_record();
    portcullis::append_decision(&log_path, &decision).unwrap();
    let mut handle = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    handle.write_all(b"\xff\xfe\n").unwrap();
    drop(handle);
    match read_log(&log_path) {
        Err(LogReadError::Corruption(exc)) => assert_eq!(exc.line_number, 2),
        other => panic!("expected corruption at line 2, got {other:?}"),
    }
    let result = run_cli(&["log", "--log", log_path.to_str().unwrap()], None);
    assert_eq!(result.status, 1);
    assert!(result.stderr.contains("line 2"), "{}", result.stderr);
}

#[test]
fn an_empty_file_path_message_is_truthful() {
    let error = portcullis::validate_call(&file_call("read", "")).unwrap_err();
    assert!(error.0.contains("of no use"), "{}", error.0);
    assert!(!error.0.contains("is not a string"), "{}", error.0);
}

#[test]
fn an_empty_network_method_message_is_truthful() {
    let error = portcullis::validate_call(&network_call("", "h.test", Value::int(80))).unwrap_err();
    assert!(error.0.contains("of no use"), "{}", error.0);
    assert!(!error.0.contains("is not a string"), "{}", error.0);
}

#[test]
fn an_empty_network_host_message_is_truthful() {
    let error = portcullis::validate_call(&network_call("GET", "", Value::int(80))).unwrap_err();
    assert!(error.0.contains("of no use"), "{}", error.0);
    assert!(!error.0.contains("is not a string"), "{}", error.0);
}

#[test]
fn an_empty_rule_reason_message_is_truthful() {
    let doc = policy_doc(
        vec![rule(
            "quiet",
            "shell",
            "allow",
            Value::obj(vec![("argv0", matcher("exact", "ls"))]),
            "",
            None,
        )],
        "deny",
    );
    let error = load_policy(&doc).unwrap_err();
    assert!(error.0.contains("of no use"), "{}", error.0);
    assert!(!error.0.contains("is not a string"), "{}", error.0);
}

// --- CodeRabbit repair pins ---------------------------------------------

cross_field_tamper!(
    log_records_whose_fields_disagree_rule_source_with_an_empty_rule,
    "tamper-cross-11",
    vec![(
        "source",
        Value::obj(vec![("type", s("rule")), ("rule", s(""))]),
    )]
);
cross_field_tamper!(
    log_records_whose_fields_disagree_policy_error_with_a_reason,
    "tamper-cross-12",
    vec![
        ("decision", s("deny")),
        (
            "source",
            Value::obj(vec![
                ("type", s("policy error")),
                ("detail", s("a failure")),
            ]),
        ),
    ]
);

#[test]
fn a_rewrite_record_whose_interpreter_flag_denies_its_rewritten_call_is_corruption() {
    let rules = vec![rule(
        "become-shell",
        "shell",
        "rewrite",
        Value::obj(vec![("argv0", matcher("exact", "ls"))]),
        "a reason",
        Some(Value::obj(vec![(
            "argv",
            arr(vec![s("sh"), s("-c"), s("id")]),
        )])),
    )];
    let mut tampered = decide(&shell_call(&["ls"]), rules, "deny");
    assert_eq!(field(&tampered, "interpreter"), &Value::Bool(true));
    set_field(&mut tampered, "interpreter", Value::Bool(false));
    assert_corruption_at_line_two("tamper-cross-13", tampered);
}

#[test]
fn a_many_starred_glob_against_a_long_token_answers() {
    // The scan backtracks through the last star alone and the
    // position that star has consumed up to only advances, so
    // this pair is answered by one walk of the pattern and the
    // text, not by a retry of every split at every star.
    let rules = vec![plain_rule(
        "many-stars",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("glob", "*a*a*a*a*a*a*a*a*a*a*b"))]),
    )];
    let near_miss = "a".repeat(400);
    let decision = decide(&shell_call(&[near_miss.as_str()]), rules.clone(), "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    let hit = format!("{near_miss}b");
    let policy = load_policy(&policy_doc(rules, "deny")).unwrap();
    let decision = evaluate(Some(&policy), None, &shell_call(&[hit.as_str()]), AT);
    assert_eq!(field(&decision, "decision"), &s("allow"));
}

#[test]
fn a_glob_of_fifty_thousand_literal_characters_still_answers() {
    // The scan is one forward pass when the pattern holds no
    // star, so a literal pattern this long answers like a short
    // one. The recursive matcher before the repair recursed
    // once per matched character, and this pair overflowed its
    // stack and aborted the process without an answer.
    let pattern = "a".repeat(50_000);
    let rules = vec![plain_rule(
        "long-literal",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("glob", pattern.as_str()))]),
    )];
    let decision = decide(&shell_call(&[pattern.as_str()]), rules.clone(), "deny");
    assert_eq!(field(&decision, "decision"), &s("allow"));
    let near_miss = format!("{}b", "a".repeat(49_999));
    let decision = decide(&shell_call(&[near_miss.as_str()]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
}

#[test]
fn ten_stars_against_five_thousand_characters_answer_within_ten_seconds() {
    // The ten second bound is generous on purpose and is the
    // claim this pin makes. The scan this pins answers this
    // pair in well under a second in the debug profile the
    // gate builds, while the memoized recursive matcher before
    // the repair did not answer it in that profile within two
    // minutes, because each of its star states scanned every
    // remaining text position.
    let rules = vec![plain_rule(
        "ten-stars",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("glob", "**********x"))]),
    )];
    let token = "a".repeat(5_000);
    let started = std::time::Instant::now();
    let decision = decide(&shell_call(&[token.as_str()]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn twenty_five_starred_pairs_against_five_thousand_characters_answer_within_ten_seconds() {
    // The same bound and the same reasoning as the ten star pin
    // above, on the alternating shape whose stars cannot
    // collapse into one star atom.
    let pattern = format!("{}b", "*a".repeat(25));
    let rules = vec![plain_rule(
        "starred-pairs",
        "shell",
        "allow",
        Value::obj(vec![("argv0", matcher("glob", pattern.as_str()))]),
    )];
    let token = "a".repeat(5_000);
    let started = std::time::Instant::now();
    let decision = decide(&shell_call(&[token.as_str()]), rules, "deny");
    assert_eq!(field(&decision, "decision"), &s("deny"));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[cfg(unix)]
#[test]
fn an_inline_option_value_keeps_its_os_bytes() {
    use std::os::unix::ffi::OsStringExt;
    let dir = temp_dir("inline-os-bytes");
    let policy = policy_doc(
        vec![plain_rule(
            "allow-ls",
            "shell",
            "allow",
            Value::obj(vec![("argv0", matcher("exact", "ls"))]),
        )],
        "deny",
    );
    let policy_path = write_json(&dir.join("policy.json"), &policy);
    let call_path = write_json(&dir.join("call.json"), &shell_call(&["ls"]));
    let mut log_name = dir.join("audit").into_os_string().into_vec();
    log_name.extend_from_slice(&[0xFF, b'.', b'l', b'o', b'g']);
    let log_os = std::ffi::OsString::from_vec(log_name);
    let log_path = PathBuf::from(&log_os);
    let mut policy_arg = std::ffi::OsString::from("--policy=");
    policy_arg.push(&policy_path);
    let mut log_arg = std::ffi::OsString::from("--log=");
    log_arg.push(&log_os);
    let output = Command::new(env!("CARGO_BIN_EXE_portcullis"))
        .arg("check")
        .arg(policy_arg)
        .arg(log_arg)
        .arg(&call_path)
        .current_dir(root())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(log_path.exists());
    assert_eq!(read_log(&log_path).unwrap().len(), 1);
}
