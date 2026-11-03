//! Equivalence checks over the frozen fixtures.
//!
//! Every document in tests/fixtures was written by the Python
//! implementation of Round 1, and the manifest beside them
//! records their hashes, their productions, and their truths.
//! This suite checks the hashes, loads each policy and compares
//! the broken one's refusal message with the record, evaluates
//! each recorded case and compares the decision against the
//! expected file field by field, reads the audit log back
//! whole, and appends the network decision to a copy of the
//! log and compares the bytes against the continued log the
//! Python implementation produced.

use std::path::{Path, PathBuf};

use portcullis::{append_decision, evaluate, load_policy, read_log, strict_parse, Value};
use sha2::{Digest, Sha256};

const AT: &str = "2026-11-02T10:00:00+00:00";

const INVENTORY: [(&str, &str, usize); 23] = [
    (
        "audit-log-continued.jsonl",
        "f8cbfc1f515dca0e0b82bf5114ed4d98f2777462559fba854144a9989b6ec176",
        1538,
    ),
    (
        "audit-log.jsonl",
        "16a3c21631e8066197d91d74f38d4a53fd09aa3e2b79593e8b6392ffd92769cf",
        1235,
    ),
    (
        "call-file-normalized.json",
        "8e4fd30cc0d11d183e9e5e7ff0082071dc367d9fcf21b06c86fd986bae409191",
        106,
    ),
    (
        "call-file-rewrite.json",
        "cf05a0122cee77987d1df9e8c4ac70458b76e567c9d3399375c2e38e7cd28327",
        112,
    ),
    (
        "call-malformed.json",
        "7055719efa41d98fb164d77bdda4dfce22a13edcf4af519e8b08a9b44715ec61",
        55,
    ),
    (
        "call-network-explicit.json",
        "6ddfd168e8c6a848249da037519b165ffac77619f4c10ec2bf69e9a2df2feab9",
        125,
    ),
    (
        "call-network-url.json",
        "25be65a336093492b879d9a291d284d4c29e01a2554727f857a96903f58796a9",
        119,
    ),
    (
        "call-shell-allow.json",
        "7496d770f3317c16720a718917af89a31cbb31a0063287fbc33587381913fcb3",
        92,
    ),
    (
        "call-shell-deny.json",
        "516880845b9c63666a60b705f9a4810a674973ee84b92b1e9cfb1bb2d654b2a3",
        90,
    ),
    (
        "call-shell-interpreter.json",
        "7649bc9685ea3f1cd55a68e36b1e6770a6d73a09e9eec5be4b9d6be1d9fca1cb",
        106,
    ),
    (
        "expected/policy-default-allow--call-file-normalized.json",
        "37d3b25b3677bf9243f25eccca6e77000d5afc2fafe97a754b48dbb3670c68d7",
        301,
    ),
    (
        "expected/policy-default-allow--call-shell-allow.json",
        "46cf9298abb2c59796e3e7c59e663504c8f3f6fbcc4c2933670963da21c92ba5",
        301,
    ),
    (
        "expected/policy-full--call-file-normalized.json",
        "88272481011c7273fdd2da5ab187333a796e5e2304799d50fc4ddd4f61c71d61",
        351,
    ),
    (
        "expected/policy-full--call-file-rewrite.json",
        "b755502cc321d860d9126e0d9fb82b2767ace71ad83462b454e027dc68f6ed60",
        466,
    ),
    (
        "expected/policy-full--call-malformed.json",
        "f06e67147eca065a5074675a7c551c65e9f6179df6b201d2dc3d3ee93efcc112",
        302,
    ),
    (
        "expected/policy-full--call-network-explicit.json",
        "4d6c7a446d345b6b51a73b84088b50b54004610bc581d28d8e9014cac1b6fc59",
        300,
    ),
    (
        "expected/policy-full--call-network-url.json",
        "4e89e76e82ce26a1d98f541e41645b2722127f2dc94547c3db89511c3c8d0c6a",
        351,
    ),
    (
        "expected/policy-full--call-shell-allow.json",
        "6e36c65b1e112ed50d84c0bf5903f140968d7925906a503cf00672101ace5cd9",
        335,
    ),
    (
        "expected/policy-full--call-shell-deny.json",
        "952d056c133c09b3a0b2832e1993ab085664d513f443e3c7d504cd1d53dd3204",
        345,
    ),
    (
        "expected/policy-full--call-shell-interpreter.json",
        "6a80cd81d4e1b9dcdd8c4782b2169dee26c2ccde793b0ea40d2813eaaf9343d2",
        299,
    ),
    (
        "policy-broken.json",
        "e397d1f051f94cb498bb0dd5f40b61b0077907e199a0c125a484799605d7be7c",
        204,
    ),
    (
        "policy-default-allow.json",
        "c76ea76282cc9fd33009ac9f3d02f091928a435cfb3f2a9e439b30d2ff9f05fe",
        294,
    ),
    (
        "policy-full.json",
        "c39b69ef36b7af9cbef08aae70fa8b60b4cf7ecd645a60ce27a3738858a7b15f",
        1333,
    ),
];

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(name)).unwrap()
}

fn parse_fixture(name: &str) -> Value {
    let bytes = read_fixture(name);
    let text = String::from_utf8(bytes).unwrap();
    strict_parse(&text).unwrap()
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "portcullis-fixtures-test-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn fixture_hashes_match_the_manifest() {
    for (name, expected_hash, expected_len) in INVENTORY {
        let bytes = read_fixture(name);
        assert_eq!(bytes.len(), expected_len, "{name}");
        let digest = Sha256::digest(&bytes);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, expected_hash, "{name}");
    }
}

#[test]
fn fixture_policies_load_and_the_broken_one_refuses_with_the_recorded_message() {
    load_policy(&parse_fixture("policy-full.json")).unwrap();
    load_policy(&parse_fixture("policy-default-allow.json")).unwrap();
    let error = load_policy(&parse_fixture("policy-broken.json")).unwrap_err();
    assert_eq!(error.0, "the match of rule empty holds no condition");
}

const CASES: [(&str, &str); 10] = [
    ("policy-full", "call-shell-allow"),
    ("policy-full", "call-shell-deny"),
    ("policy-full", "call-shell-interpreter"),
    ("policy-full", "call-file-rewrite"),
    ("policy-full", "call-file-normalized"),
    ("policy-full", "call-network-url"),
    ("policy-full", "call-network-explicit"),
    ("policy-full", "call-malformed"),
    ("policy-default-allow", "call-shell-allow"),
    ("policy-default-allow", "call-file-normalized"),
];

#[test]
fn fixture_cases_decide_as_the_python_implementation_decided() {
    for (policy_name, call_name) in CASES {
        let policy = load_policy(&parse_fixture(&format!("{policy_name}.json"))).unwrap();
        let call = parse_fixture(&format!("{call_name}.json"));
        let expected = parse_fixture(&format!("expected/{policy_name}--{call_name}.json"));
        let decision = evaluate(Some(&policy), None, &call, AT);
        assert_eq!(
            portcullis::canonical(&decision),
            portcullis::canonical(&expected),
            "{policy_name} with {call_name}"
        );
    }
}

#[test]
fn fixture_audit_log_reads_back_whole() {
    let dir = temp_dir("read-log");
    let log_path = dir.join("audit.jsonl");
    std::fs::write(&log_path, read_fixture("audit-log.jsonl")).unwrap();
    let records = read_log(&log_path).unwrap();
    assert_eq!(records.len(), 4);
    let outcomes: Vec<&str> = records
        .iter()
        .map(|record| record.get("decision").unwrap().as_str().unwrap())
        .collect();
    assert_eq!(outcomes, ["allow", "deny", "rewrite", "deny"]);
}

#[test]
fn a_rust_append_continues_the_python_log_byte_for_byte() {
    let dir = temp_dir("append-log");
    let log_path = dir.join("audit.jsonl");
    std::fs::write(&log_path, read_fixture("audit-log.jsonl")).unwrap();
    let policy = load_policy(&parse_fixture("policy-full.json")).unwrap();
    let call = parse_fixture("call-network-url.json");
    let decision = evaluate(Some(&policy), None, &call, AT);
    append_decision(&log_path, &decision).unwrap();
    let continued = std::fs::read(&log_path).unwrap();
    assert_eq!(continued, read_fixture("audit-log-continued.jsonl"));
    let records = read_log(&log_path).unwrap();
    assert_eq!(records.len(), 5);
}

#[test]
fn the_fixture_paths_are_relative_in_the_manifest() {
    let manifest = std::fs::read_to_string(fixtures_dir().join("MANIFEST.md")).unwrap();
    assert!(!manifest.contains("/home/"));
    assert!(!Path::new("tests/fixtures/MANIFEST.md").is_absolute());
}
