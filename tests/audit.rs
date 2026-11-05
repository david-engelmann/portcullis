//! Tests for the sampling audit slice, obligations PC-21 to
//! PC-25. Every test here is offline and no test performs a
//! network call. The mixed log at the centre of the suite is
//! built by the gate itself, by replaying the recorded
//! judgment fixtures through the fixture transport and
//! appending the decisions, and by deciding one battery under
//! a judgment free policy into the same log, so the log
//! carries records of all four classes in counts the suite
//! computes from the fixture documents themselves. The
//! classification the suite expects is computed here from the
//! words of obligation PC-21, as a second reading beside the
//! one the library carries, so a drift in either reading
//! fails a pin.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use portcullis::{
    append_decision, audit_log, call_digest, canonical, evaluate, evaluate_with_transport,
    load_policy, read_log, strict_parse, FixtureTransport, JudgeTransport, LogReadError,
    TransportError, Value,
};

const AT: &str = "2026-11-04T10:00:00+00:00";
const BATTERY_AT: &str = "2026-11-02T10:00:00+00:00";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("portcullis-audit-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn s(text: &str) -> Value {
    Value::text(text)
}

fn field<'a>(doc: &'a Value, key: &str) -> &'a Value {
    doc.get(key).unwrap()
}

fn score_of(record: &Value) -> Option<f64> {
    match record.get("model")?.get("risk_score")? {
        Value::Float(number) => Some(*number),
        Value::Int(text) => text.parse::<f64>().ok(),
        _ => None,
    }
}

/// The class of one record under the words of obligation
/// PC-21, computed here as the second reading the header
/// names. The order of the classes in the report is ranked
/// and scored_not_allowed and unscored and first_format.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Ranked,
    ScoredNotAllowed,
    Unscored,
    FirstFormat,
}

fn class_of(record: &Value) -> Class {
    if field(record, "format") == &s("portcullis-decision/1") {
        return Class::FirstFormat;
    }
    assert_eq!(field(record, "format"), &s("portcullis-decision/2"));
    match (field(record, "decision").as_str(), score_of(record)) {
        (Some("allow"), Some(_)) => Class::Ranked,
        (Some("deny"), Some(_)) | (Some("escalate"), Some(_)) => Class::ScoredNotAllowed,
        _ => Class::Unscored,
    }
}

fn counts_of(records: &[Value]) -> (usize, usize, usize, usize) {
    let mut counts = (0, 0, 0, 0);
    for record in records {
        match class_of(record) {
            Class::Ranked => counts.0 += 1,
            Class::ScoredNotAllowed => counts.1 += 1,
            Class::Unscored => counts.2 += 1,
            Class::FirstFormat => counts.3 += 1,
        }
    }
    counts
}

/// The ranked order of obligation PC-22 over the given
/// records, as line and score pairs in rank order, computed
/// here from the words of the obligation.
fn ranked_order(records: &[Value]) -> Vec<(usize, f64)> {
    let mut order: Vec<(usize, f64)> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| class_of(record) == Class::Ranked)
        .map(|(index, record)| (index + 1, score_of(record).unwrap()))
        .collect();
    order.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap().then(a.0.cmp(&b.0)));
    order
}

/// Check the report against the shape obligation PC-23 fixes,
/// field by field, with the exact key sets standing at every
/// level and the coherence rules holding throughout.
fn check_report_shape(report: &Value) {
    let mut keys: Vec<&str> = report
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, _)| key.as_str())
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        ["counts", "format", "requested", "returned", "sample"]
    );
    assert_eq!(field(report, "format"), &s("portcullis-audit/1"));
    let counts = field(report, "counts");
    let mut count_keys: Vec<&str> = counts
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, _)| key.as_str())
        .collect();
    count_keys.sort();
    assert_eq!(
        count_keys,
        [
            "first_format",
            "lines",
            "ranked",
            "scored_not_allowed",
            "unscored"
        ]
    );
    let count = |key: &str| match field(counts, key) {
        Value::Int(text) => text.parse::<usize>().unwrap(),
        other => panic!("count {key} is not an integer, {other:?}"),
    };
    let (lines, ranked, scored, unscored, first) = (
        count("lines"),
        count("ranked"),
        count("scored_not_allowed"),
        count("unscored"),
        count("first_format"),
    );
    assert_eq!(ranked + scored + unscored + first, lines);
    let requested = match field(report, "requested") {
        Value::Int(text) => text.parse::<usize>().unwrap(),
        other => panic!("requested is not an integer, {other:?}"),
    };
    let returned = match field(report, "returned") {
        Value::Int(text) => text.parse::<usize>().unwrap(),
        other => panic!("returned is not an integer, {other:?}"),
    };
    assert_eq!(returned, requested.min(ranked));
    let sample = field(report, "sample").as_array().unwrap();
    assert_eq!(sample.len(), returned);
    let mut seen_lines = std::collections::HashSet::new();
    let mut previous_score: Option<f64> = None;
    for (offset, entry) in sample.iter().enumerate() {
        let mut entry_keys: Vec<&str> = entry
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        entry_keys.sort();
        assert_eq!(entry_keys, ["line", "rank", "record", "risk_score"]);
        assert_eq!(field(entry, "rank"), &Value::int((offset + 1) as i64));
        let line = match field(entry, "line") {
            Value::Int(text) => text.parse::<usize>().unwrap(),
            other => panic!("line is not an integer, {other:?}"),
        };
        assert!(seen_lines.insert(line), "line {line} stands twice");
        let score = score_of(field(entry, "record")).unwrap();
        assert_eq!(
            field(entry, "risk_score"),
            field(field(entry, "record"), "model")
                .get("risk_score")
                .unwrap()
        );
        if let Some(previous) = previous_score {
            assert!(score <= previous, "scores stand out of ranked order");
        }
        previous_score = Some(score);
        assert_eq!(class_of(field(entry, "record")), Class::Ranked);
    }
}

// --- building one mixed log with the gate itself ------------------------------

struct StubTransport {
    outcome: Result<String, String>,
    requests: RefCell<Vec<Value>>,
}

impl StubTransport {
    fn replying(body: &str) -> StubTransport {
        StubTransport {
            outcome: Ok(body.to_string()),
            requests: RefCell::new(Vec::new()),
        }
    }
}

impl JudgeTransport for StubTransport {
    fn consult(&self, request: &Value) -> Result<String, TransportError> {
        self.requests.borrow_mut().push(request.clone());
        match &self.outcome {
            Ok(body) => Ok(body.clone()),
            Err(detail) => Err(TransportError(detail.clone())),
        }
    }
}

fn fixture_text(relative: &str) -> String {
    std::fs::read_to_string(root().join("tests").join("fixtures").join(relative)).unwrap()
}

/// Replay every recorded judgment fixture through the
/// fixture transport and append each decision to the log at
/// the path, then decide the battery under the judgment free
/// policy into the same log. Returns the records the log
/// holds, in log order, each checked against the document
/// that stands as its truth.
fn build_mixed_log(log_path: &Path) -> Vec<Value> {
    let fixtures_dir = root().join("tests").join("fixtures").join("judgment");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&fixtures_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    names.sort();
    assert!(names.len() >= 54, "the judgment fixture folder is short");
    let mut records = Vec::new();
    for path in names {
        let text = std::fs::read_to_string(&path).unwrap();
        let fixture = strict_parse(&text).unwrap();
        let policy = load_policy(field(&fixture, "policy")).unwrap();
        let call = field(&fixture, "call");
        let at = field(&fixture, "at").as_str().unwrap();
        let reply = field(&fixture, "reply").as_str().unwrap();
        let expected = field(&fixture, "expected");
        let capture = StubTransport::replying(reply);
        evaluate_with_transport(Some(&policy), None, call, at, Some(&capture));
        let requests = capture.requests.borrow();
        assert_eq!(requests.len(), 1, "fixture {}", path.display());
        let digest = call_digest(&requests[0]);
        drop(requests);
        let transport = FixtureTransport::new(vec![(digest, reply.to_string())]);
        let decision = evaluate_with_transport(Some(&policy), None, call, at, Some(&transport));
        assert_eq!(canonical(&decision), canonical(expected));
        append_decision(log_path, &decision).unwrap();
        records.push(decision);
    }
    let policy = load_policy(&strict_parse(&fixture_text("policy-full.json")).unwrap()).unwrap();
    for call_name in [
        "call-shell-allow.json",
        "call-shell-deny.json",
        "call-file-rewrite.json",
        "call-network-url.json",
    ] {
        let call = strict_parse(&fixture_text(call_name)).unwrap();
        let expected = strict_parse(&fixture_text(&format!(
            "expected/policy-full--{}",
            call_name
        )))
        .unwrap();
        let decision = evaluate(Some(&policy), None, &call, BATTERY_AT);
        assert_eq!(canonical(&decision), canonical(&expected));
        append_decision(log_path, &decision).unwrap();
        records.push(decision);
    }
    records
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

// --- the population, PC-21 ------------------------------------------------------

#[test]
fn the_mixed_log_audits_to_its_four_counts_and_their_sum() {
    let dir = temp_dir("mixed-counts");
    let log_path = dir.join("audit.jsonl");
    let records = build_mixed_log(&log_path);
    assert_eq!(read_log(&log_path).unwrap().len(), records.len());
    let (ranked, scored, unscored, first) = counts_of(&records);
    assert!(ranked >= 7, "the ranked class holds {ranked} records");
    assert!(scored > 0, "the scored class beyond the ranked holds none");
    assert!(unscored > 0, "the unscored class holds none");
    assert_eq!(first, 4, "the battery stands at four first format records");
    let report = audit_log(&log_path, ranked).unwrap();
    check_report_shape(&report);
    let counts = field(&report, "counts");
    assert_eq!(field(counts, "lines"), &Value::int(records.len() as i64));
    assert_eq!(field(counts, "ranked"), &Value::int(ranked as i64));
    assert_eq!(
        field(counts, "scored_not_allowed"),
        &Value::int(scored as i64)
    );
    assert_eq!(field(counts, "unscored"), &Value::int(unscored as i64));
    assert_eq!(field(counts, "first_format"), &Value::int(first as i64));
}

#[test]
fn a_log_of_only_first_format_records_reads_as_its_own_class() {
    let dir = temp_dir("only-first");
    let log_path = dir.join("audit.jsonl");
    std::fs::copy(root().join("tests/fixtures/audit-log.jsonl"), &log_path).unwrap();
    let report = audit_log(&log_path, 3).unwrap();
    check_report_shape(&report);
    let counts = field(&report, "counts");
    assert_eq!(field(counts, "lines"), &Value::int(4));
    assert_eq!(field(counts, "first_format"), &Value::int(4));
    assert_eq!(field(counts, "ranked"), &Value::int(0));
    assert_eq!(field(counts, "scored_not_allowed"), &Value::int(0));
    assert_eq!(field(counts, "unscored"), &Value::int(0));
    assert_eq!(field(&report, "returned"), &Value::int(0));
    assert!(field(&report, "sample").as_array().unwrap().is_empty());
}

#[test]
fn a_log_of_only_unscored_records_reads_as_its_own_class() {
    let dir = temp_dir("only-unscored");
    let log_path = dir.join("audit.jsonl");
    // Stand three referrals that obtain no score answer. One
    // is decided with no transport at all, and two are decided
    // through recorded replies whose bodies carry no usable
    // score, the empty body of k01 and the doubled document
    // of k03, whose expected records both carry a null score.
    let mut records = Vec::new();
    let policy_doc = strict_parse(&fixture_text("judgment/a11.json")).unwrap();
    let policy = load_policy(field(&policy_doc, "policy")).unwrap();
    let call = field(&policy_doc, "call").clone();
    let no_transport = evaluate(Some(&policy), None, &call, AT);
    append_decision(&log_path, &no_transport).unwrap();
    records.push(no_transport);
    for name in ["k01", "k03"] {
        let fixture = strict_parse(&fixture_text(&format!("judgment/{name}.json"))).unwrap();
        let fixture_policy = load_policy(field(&fixture, "policy")).unwrap();
        let fixture_call = field(&fixture, "call");
        let at = field(&fixture, "at").as_str().unwrap();
        let reply = field(&fixture, "reply").as_str().unwrap();
        let capture = StubTransport::replying(reply);
        evaluate_with_transport(
            Some(&fixture_policy),
            None,
            fixture_call,
            at,
            Some(&capture),
        );
        let requests = capture.requests.borrow();
        let digest = call_digest(&requests[0]);
        drop(requests);
        let transport = FixtureTransport::new(vec![(digest, reply.to_string())]);
        let decision = evaluate_with_transport(
            Some(&fixture_policy),
            None,
            fixture_call,
            at,
            Some(&transport),
        );
        assert_eq!(canonical(&decision), canonical(field(&fixture, "expected")));
        append_decision(&log_path, &decision).unwrap();
        records.push(decision);
    }
    for record in &records {
        assert_eq!(
            class_of(record),
            Class::Unscored,
            "a builder record is scored"
        );
    }
    let report = audit_log(&log_path, 2).unwrap();
    check_report_shape(&report);
    let counts = field(&report, "counts");
    assert_eq!(field(counts, "lines"), &Value::int(3));
    assert_eq!(field(counts, "unscored"), &Value::int(3));
    assert_eq!(field(counts, "ranked"), &Value::int(0));
    assert_eq!(field(&report, "returned"), &Value::int(0));
    assert!(field(&report, "sample").as_array().unwrap().is_empty());
}

#[test]
fn a_corrupt_line_after_ranked_lines_refuses_the_audit_whole_and_names_the_line() {
    let dir = temp_dir("corrupt-after");
    let log_path = dir.join("audit.jsonl");
    let records = build_mixed_log(&log_path);
    // Break the second line by hand. The second line of the
    // built log is a second format record, and naming it a
    // rewrite is a shape the landed reader refuses, so the
    // audit must refuse whole at that line and rank nothing.
    let mut text = String::from_utf8(read_bytes(&log_path)).unwrap();
    let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();
    let second = strict_parse(&lines[1]).unwrap();
    assert_eq!(field(&second, "format"), &s("portcullis-decision/2"));
    let mut pairs: Vec<(String, Value)> = second.as_object().unwrap().clone();
    for (key, value) in pairs.iter_mut() {
        if key == "decision" {
            *value = s("rewrite");
        }
    }
    lines[1] = String::from_utf8(canonical(&Value::Object(pairs))).unwrap();
    text = lines.join("\n");
    text.push('\n');
    std::fs::write(&log_path, text).unwrap();
    let ranked_before = records
        .iter()
        .take(1)
        .filter(|record| class_of(record) == Class::Ranked)
        .count();
    assert_eq!(ranked_before, 1, "the first line stands ranked");
    match audit_log(&log_path, 5) {
        Err(LogReadError::Corruption(error)) => {
            assert_eq!(error.line_number, 2);
        }
        other => panic!("the audit did not refuse the corrupt log, {other:?}"),
    }
}

// --- the ranking rule, PC-22 ----------------------------------------------------

#[test]
fn the_sample_stands_in_the_ranked_order_the_obligation_states() {
    let dir = temp_dir("ranked-order");
    let log_path = dir.join("audit.jsonl");
    let records = build_mixed_log(&log_path);
    let order = ranked_order(&records);
    assert!(order.len() >= 5, "the ranked class is too small to sample");
    let report = audit_log(&log_path, 5).unwrap();
    check_report_shape(&report);
    let sample = field(&report, "sample").as_array().unwrap();
    assert_eq!(sample.len(), 5);
    for (offset, entry) in sample.iter().enumerate() {
        let (line, score) = order[offset];
        assert_eq!(field(entry, "line"), &Value::int(line as i64));
        assert_eq!(score_of(field(entry, "record")), Some(score));
        assert_eq!(
            canonical(field(entry, "record")),
            canonical(&records[line - 1])
        );
    }
}

#[test]
fn an_audit_of_one_log_twice_returns_the_same_report_byte_for_byte() {
    let dir = temp_dir("twice");
    let log_path = dir.join("audit.jsonl");
    build_mixed_log(&log_path);
    let one = audit_log(&log_path, 4).unwrap();
    let two = audit_log(&log_path, 4).unwrap();
    assert_eq!(canonical(&one), canonical(&two));
}

#[test]
fn a_size_of_zero_is_a_caller_error_refused_before_any_read() {
    let dir = temp_dir("zero-size");
    let missing = dir.join("no-such-log.jsonl");
    match audit_log(&missing, 0) {
        Err(LogReadError::Caller(error)) => {
            assert_eq!(error.0, "the sample size must stand at one or above");
        }
        other => panic!("a size of zero did not refuse as a caller error, {other:?}"),
    }
    // The same refusal stands over a log that does stand, so
    // the refusal owes nothing to the read either way.
    let log_path = dir.join("audit.jsonl");
    std::fs::copy(root().join("tests/fixtures/audit-log.jsonl"), &log_path).unwrap();
    match audit_log(&log_path, 0) {
        Err(LogReadError::Caller(error)) => {
            assert_eq!(error.0, "the sample size must stand at one or above");
        }
        other => panic!("a size of zero did not refuse over a standing log, {other:?}"),
    }
}

#[test]
fn a_size_above_the_population_returns_the_whole_population_with_both_counts() {
    let dir = temp_dir("clamp");
    let log_path = dir.join("audit.jsonl");
    let records = build_mixed_log(&log_path);
    let (ranked, _, _, _) = counts_of(&records);
    let report = audit_log(&log_path, ranked + 10).unwrap();
    check_report_shape(&report);
    assert_eq!(
        field(&report, "requested"),
        &Value::Int((ranked + 10).to_string())
    );
    assert_eq!(field(&report, "returned"), &Value::int(ranked as i64));
    assert_eq!(field(&report, "sample").as_array().unwrap().len(), ranked);
}

/// One ranked record with its score replaced, a hand built
/// line for the boundary shapes. The record stays a record
/// the landed reader accepts, because no agreement the reader
/// checks reads the score.
fn with_score(record: &Value, score: f64) -> Value {
    let mut pairs: Vec<(String, Value)> = record.as_object().unwrap().clone();
    for (key, value) in pairs.iter_mut() {
        if key == "model" {
            let mut model_pairs: Vec<(String, Value)> = value.as_object().unwrap().clone();
            for (model_key, model_value) in model_pairs.iter_mut() {
                if model_key == "risk_score" {
                    *model_value = Value::Float(score);
                }
            }
            *value = Value::Object(model_pairs);
        }
    }
    Value::Object(pairs)
}

fn one_ranked_record() -> Value {
    let fixture = strict_parse(&fixture_text("judgment/a01.json")).unwrap();
    let policy = load_policy(field(&fixture, "policy")).unwrap();
    let call = field(&fixture, "call");
    let at = field(&fixture, "at").as_str().unwrap();
    let reply = field(&fixture, "reply").as_str().unwrap();
    let capture = StubTransport::replying(reply);
    evaluate_with_transport(Some(&policy), None, call, at, Some(&capture));
    let requests = capture.requests.borrow();
    let digest = call_digest(&requests[0]);
    drop(requests);
    let transport = FixtureTransport::new(vec![(digest, reply.to_string())]);
    let decision = evaluate_with_transport(Some(&policy), None, call, at, Some(&transport));
    assert_eq!(class_of(&decision), Class::Ranked);
    decision
}

#[test]
fn two_records_at_one_score_rank_the_earlier_line_first() {
    let dir = temp_dir("tie");
    let log_path = dir.join("audit.jsonl");
    let record = one_ranked_record();
    append_decision(&log_path, &with_score(&record, 9.5)).unwrap();
    append_decision(&log_path, &with_score(&record, 9.5)).unwrap();
    append_decision(&log_path, &with_score(&record, 9.4)).unwrap();
    // A sample of one cuts between the two records at the tied
    // score, and the earlier line is the one inside it.
    let one = audit_log(&log_path, 1).unwrap();
    let sample = field(&one, "sample").as_array().unwrap();
    assert_eq!(sample.len(), 1);
    assert_eq!(field(&sample[0], "line"), &Value::int(1));
    let two = audit_log(&log_path, 2).unwrap();
    check_report_shape(&two);
    let sample = field(&two, "sample").as_array().unwrap();
    assert_eq!(field(&sample[0], "line"), &Value::int(1));
    assert_eq!(field(&sample[1], "line"), &Value::int(2));
    assert_eq!(score_of(field(&sample[1], "record")), Some(9.5));
}

// --- the report, PC-23 ------------------------------------------------------------

#[test]
fn the_audit_writes_nothing_and_the_log_stands_byte_for_byte() {
    let dir = temp_dir("writes-nothing");
    let log_path = dir.join("audit.jsonl");
    build_mixed_log(&log_path);
    let before = read_bytes(&log_path);
    let mut entries_before: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries_before.sort();
    let report = audit_log(&log_path, 3).unwrap();
    check_report_shape(&report);
    assert_eq!(read_bytes(&log_path), before);
    let mut entries_after: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries_after.sort();
    assert_eq!(entries_before, entries_after);
}

#[test]
fn an_empty_log_audits_to_a_report_of_zeroes() {
    let dir = temp_dir("empty");
    let log_path = dir.join("audit.jsonl");
    std::fs::write(&log_path, "").unwrap();
    let report = audit_log(&log_path, 4).unwrap();
    check_report_shape(&report);
    let counts = field(&report, "counts");
    assert_eq!(field(counts, "lines"), &Value::int(0));
    assert_eq!(field(counts, "ranked"), &Value::int(0));
    assert_eq!(field(&report, "requested"), &Value::int(4));
    assert_eq!(field(&report, "returned"), &Value::int(0));
    assert!(field(&report, "sample").as_array().unwrap().is_empty());
}

#[test]
fn a_missing_log_is_the_landed_caller_error() {
    let dir = temp_dir("missing");
    let missing = dir.join("no-such-log.jsonl");
    match audit_log(&missing, 2) {
        Err(LogReadError::Caller(error)) => {
            assert_eq!(
                error.0,
                format!("the audit log at {} does not stand", missing.display())
            );
        }
        other => panic!("a missing log did not refuse as a caller error, {other:?}"),
    }
}

// --- the command line surface, PC-24 ----------------------------------------------

struct CliOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(arguments: &[&str]) -> CliOutput {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_portcullis"))
        .args(arguments)
        .current_dir(root())
        .output()
        .unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn write_hand_log(dir: &Path) -> PathBuf {
    let log_path = dir.join("audit.jsonl");
    let record = one_ranked_record();
    append_decision(&log_path, &with_score(&record, 8.0)).unwrap();
    append_decision(&log_path, &with_score(&record, 9.0)).unwrap();
    append_decision(&log_path, &with_score(&record, 9.0)).unwrap();
    log_path
}

#[test]
fn the_audit_subcommand_prints_the_library_report_byte_for_byte() {
    let dir = temp_dir("cli-report");
    let log_path = dir.join("audit.jsonl");
    build_mixed_log(&log_path);
    let library = audit_log(&log_path, 3).unwrap();
    let result = run_cli(&[
        "audit",
        "--log",
        log_path.to_str().unwrap(),
        "--sample",
        "3",
    ]);
    assert_eq!(result.status, 0, "stderr {}", result.stderr);
    let printed = format!("{}\n", String::from_utf8(canonical(&library)).unwrap());
    assert_eq!(result.stdout, printed);
}

#[test]
fn the_audit_subcommand_answers_a_corrupt_log_at_exit_one_with_the_log_sentence() {
    let dir = temp_dir("cli-corrupt");
    let log_path = write_hand_log(&dir);
    let mut text = String::from_utf8(read_bytes(&log_path)).unwrap();
    let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();
    let second = strict_parse(&lines[1]).unwrap();
    let mut pairs: Vec<(String, Value)> = second.as_object().unwrap().clone();
    for (key, value) in pairs.iter_mut() {
        if key == "decision" {
            *value = s("rewrite");
        }
    }
    lines[1] = String::from_utf8(canonical(&Value::Object(pairs))).unwrap();
    text = lines.join("\n");
    text.push('\n');
    std::fs::write(&log_path, text).unwrap();
    let result = run_cli(&[
        "audit",
        "--log",
        log_path.to_str().unwrap(),
        "--sample",
        "2",
    ]);
    assert_eq!(result.status, 1);
    assert!(
        result
            .stderr
            .contains("error: the audit log is corrupt at line 2,"),
        "stderr {}",
        result.stderr
    );
}

#[test]
fn the_audit_subcommand_answers_a_missing_log_at_exit_two() {
    let dir = temp_dir("cli-missing");
    let missing = dir.join("no-such-log.jsonl");
    let result = run_cli(&["audit", "--log", missing.to_str().unwrap(), "--sample", "2"]);
    assert_eq!(result.status, 2);
    assert!(
        result.stderr.contains("does not stand"),
        "stderr {}",
        result.stderr
    );
}

#[test]
fn the_audit_subcommand_refuses_bad_sample_arguments_at_exit_two() {
    let dir = temp_dir("cli-bad-sample");
    let log_path = write_hand_log(&dir);
    let log = log_path.to_str().unwrap();
    for arguments in [
        vec!["audit", "--log", log, "--sample", "0"],
        vec!["audit", "--log", log, "--sample", "two"],
        vec!["audit", "--log", log],
    ] {
        let result = run_cli(&arguments);
        assert_eq!(result.status, 2, "arguments {arguments:?}");
    }
    let zero = run_cli(&["audit", "--log", log, "--sample", "0"]);
    assert!(
        zero.stderr
            .contains("the sample size must stand at one or above"),
        "stderr {}",
        zero.stderr
    );
    for token in ["two", "99999999999999999999999999999999"] {
        let result = run_cli(&["audit", "--log", log, "--sample", token]);
        assert_eq!(result.status, 2, "token {token}");
        assert!(
            result
                .stderr
                .contains(&format!("argument --sample: unusable count value: {token}")),
            "stderr {}",
            result.stderr
        );
    }
}

#[test]
fn the_audit_help_states_the_ranking_and_that_it_decides_nothing() {
    let result = run_cli(&["audit", "-h"]);
    assert_eq!(result.status, 0);
    assert!(
        result
            .stdout
            .contains("usage: portcullis audit [-h] --log LOG --sample SAMPLE"),
        "stdout {}",
        result.stdout
    );
    assert!(
        result
            .stdout
            .contains("ranks recorded calls by their recorded scores and decides nothing"),
        "stdout {}",
        result.stdout
    );
    let main = run_cli(&["-h"]);
    assert_eq!(main.status, 0);
    assert!(
        main.stdout.contains("{check,log,audit}"),
        "stdout {}",
        main.stdout
    );
}
