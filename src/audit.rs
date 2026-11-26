//! The audit log, decisions appended, read back, and audited.

use crate::call::{is_interpreter_call, is_text, validate_call};
use crate::errors::{CallerError, LogAppendError, LogCorruptionError, LogReadError};
use crate::reader::strict_parse;
use crate::referral::number_f64;
use crate::value::Value;
use crate::writer::canonical;
use crate::{
    is_valid_model_name, AUDIT_FORMAT, DECISION_FORMAT, DECISION_FORMAT_2, VERDICT_LABELS,
};
use fs2::FileExt;
use std::collections::HashSet;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Append one decision record to the audit log as one whole
/// line, under an exclusive lock on the log file.
///
/// The lock is verified as the file standing at the log path.
/// After the lock is taken its device and inode are checked
/// against the path, once on each attempt, with a bounded
/// retry while the path settles, and the line is written on
/// the attempt whose check passes. An append whose held lock
/// is not the file at the path fails instead of writing into
/// an unlinked file no reader will ever see, and the decision
/// it carried is not delivered.
pub fn append_decision(log_path: &Path, decision: &Value) -> Result<(), LogAppendError> {
    let mut line = canonical(decision);
    line.push(b'\n');
    let mut last_error: Option<std::io::Error> = None;
    for _ in 0..5 {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).create(true).append(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0x00000001 | 0x00000002);
        }
        let mut handle = match options.open(log_path) {
            Ok(handle) => handle,
            Err(exc) => {
                return Err(LogAppendError(io_detail(&exc)));
            }
        };
        if let Err(exc) = handle.lock_exclusive() {
            return Err(LogAppendError(io_detail(&exc)));
        }
        match lock_identity_holds(&handle, log_path) {
            Ok(true) => {
                let outcome = handle
                    .write_all(&line)
                    .and_then(|_| handle.sync_all())
                    .map_err(|exc| LogAppendError(io_detail(&exc)));
                let _ = handle.unlock();
                return outcome;
            }
            Ok(false) => {
                let _ = handle.unlock();
                continue;
            }
            Err(exc) => {
                let _ = handle.unlock();
                last_error = Some(exc);
                continue;
            }
        }
    }
    match last_error {
        Some(exc) => Err(LogAppendError(io_detail(&exc))),
        None => Err(LogAppendError(format!(
            "the lock file at {} is not the file this command locked, so the decision was not delivered",
            log_path.display()
        ))),
    }
}

/// Whether the file a lock is held on is the file standing at
/// the lock path, judged by device and inode. Where the
/// platform cannot report an identity the check passes, because
/// the comparison has nothing to judge.
fn lock_identity_holds(handle: &std::fs::File, path: &Path) -> Result<bool, std::io::Error> {
    #[cfg(unix)]
    {
        let held = handle.metadata()?;
        let standing = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(exc) if exc.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(exc) => return Err(exc),
        };
        Ok(held.dev() == standing.dev() && held.ino() == standing.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (handle, path);
        Ok(true)
    }
}

/// The detail text of an operating system failure, as the
/// system layer words it.
fn io_detail(exc: &std::io::Error) -> String {
    exc.to_string()
}

fn validate_decision_record(record: &Value, line_number: usize) -> Result<(), LogCorruptionError> {
    let what = format!("the record at line {line_number}");
    let corruption = |detail: String| LogCorruptionError {
        line_number,
        detail,
    };
    if let Some(format) = record.get("format") {
        if format == &Value::text(DECISION_FORMAT_2) {
            return validate_model_record(record, line_number);
        }
    }
    let pairs = match record.as_object() {
        Some(pairs) => pairs,
        None => {
            return Err(corruption(format!("{what} is not an object")));
        }
    };
    let expected: HashSet<&str> = [
        "format",
        "at",
        "call_digest",
        "decision",
        "source",
        "reason",
        "interpreter",
        "rewritten_call",
    ]
    .into_iter()
    .collect();
    let present: HashSet<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
    if present != expected {
        return Err(corruption(format!("{what} carries the wrong fields")));
    }
    if record.get("format").unwrap() != &Value::text(DECISION_FORMAT) {
        return Err(corruption(format!("{what} names the wrong format")));
    }
    if !is_text(record.get("at").unwrap()) {
        return Err(corruption(format!("{what} carries an instant of no use")));
    }
    let digest = record.get("call_digest").unwrap();
    if !digest_form_ok(digest) {
        return Err(corruption(format!("{what} carries a digest of no use")));
    }
    let decision_value = record.get("decision").unwrap();
    if !matches!(decision_value, Value::Str(d) if ["allow", "deny", "rewrite"].contains(&d.as_str()))
    {
        return Err(corruption(format!(
            "{what} names a decision outside the set"
        )));
    }
    let source = record.get("source").unwrap();
    let source_pairs = match source.as_object() {
        Some(pairs) => pairs,
        None => {
            return Err(corruption(format!("{what} carries a source of no use")));
        }
    };
    if source.get("type").is_none() {
        return Err(corruption(format!("{what} carries a source of no use")));
    }
    let source_type = source.get("type").unwrap().as_str().unwrap_or("");
    let source_keys: HashSet<&str> = source_pairs.iter().map(|(key, _)| key.as_str()).collect();
    match source_type {
        "rule" => {
            if source_keys != HashSet::from(["type", "rule"])
                || !is_text(source.get("rule").unwrap())
                || source.get("rule").unwrap().as_str() == Some("")
            {
                return Err(corruption(format!(
                    "{what} carries a rule source of no use"
                )));
            }
        }
        "policy error" => {
            if source_keys != HashSet::from(["type", "detail"])
                || !is_text(source.get("detail").unwrap())
            {
                return Err(corruption(format!(
                    "{what} carries a policy error source of no use"
                )));
            }
        }
        "malformed" | "default" => {
            if source_keys != HashSet::from(["type"]) {
                return Err(corruption(format!("{what} carries a source of no use")));
            }
        }
        _ => {
            return Err(corruption(format!("{what} names a source outside the set")));
        }
    }
    let reason = record.get("reason").unwrap();
    if *reason != Value::Null && !is_text(reason) {
        return Err(corruption(format!("{what} carries a reason of no use")));
    }
    if !matches!(record.get("interpreter").unwrap(), Value::Bool(_)) {
        return Err(corruption(format!(
            "{what} carries an interpreter flag of no use"
        )));
    }
    let interpreter = record.get("interpreter").unwrap() == &Value::Bool(true);
    match source_type {
        "malformed" => {
            if decision_value.as_str() != Some("deny") || *reason != Value::Null || interpreter {
                return Err(corruption(format!(
                    "{what} carries fields that disagree with a malformed source"
                )));
            }
        }
        "policy error" => {
            if decision_value.as_str() != Some("deny") || *reason != Value::Null {
                return Err(corruption(format!(
                    "{what} carries fields that disagree with a policy error source"
                )));
            }
        }
        "rule" => {
            if !is_text(reason) || reason.as_str() == Some("") {
                return Err(corruption(format!(
                    "{what} carries a rule source with no reason"
                )));
            }
        }
        _ => {
            if *reason != Value::Null {
                return Err(corruption(format!(
                    "{what} carries a default source with a reason"
                )));
            }
        }
    }
    if decision_value.as_str() == Some("rewrite") && source_type != "rule" {
        return Err(corruption(format!("{what} rewrites without a rule source")));
    }
    let rewritten = record.get("rewritten_call").unwrap();
    if decision_value.as_str() == Some("rewrite") {
        if rewritten.as_object().is_none() {
            return Err(corruption(format!("{what} rewrites and carries no call")));
        }
        if validate_call(rewritten).is_err() {
            return Err(corruption(format!(
                "{what} carries a rewritten call that fails call validation"
            )));
        }
        if is_interpreter_call(rewritten) && !interpreter {
            return Err(corruption(format!(
                "{what} carries an interpreter flag that disagrees with the rewritten call"
            )));
        }
    } else if *rewritten != Value::Null {
        return Err(corruption(format!(
            "{what} carries a rewritten call and does not rewrite"
        )));
    }
    Ok(())
}

fn digest_form_ok(value: &Value) -> bool {
    match value.as_str() {
        Some(text) => {
            text.starts_with("sha256:")
                && text.len() == "sha256:".len() + 64
                && text[7..].chars().all(|c| c.is_ascii_hexdigit())
        }
        None => false,
    }
}

fn record_number_in_range(value: &Value, low: f64, high: f64) -> bool {
    match number_f64(value) {
        Some(number) => number >= low && number <= high,
        None => false,
    }
}

/// Validate one decision record of the second format, the
/// record a model influenced. The checks mirror the agreement
/// the contract states among the decision and the verdict and
/// the fallback and the failure, so a record whose fields
/// disagree is corruption at its line.
fn validate_model_record(record: &Value, line_number: usize) -> Result<(), LogCorruptionError> {
    let what = format!("the record at line {line_number}");
    let corruption = |detail: String| LogCorruptionError {
        line_number,
        detail,
    };
    let pairs = match record.as_object() {
        Some(pairs) => pairs,
        None => {
            return Err(corruption(format!("{what} is not an object")));
        }
    };
    let expected: HashSet<&str> = [
        "format",
        "at",
        "call_digest",
        "decision",
        "source",
        "reason",
        "interpreter",
        "rewritten_call",
        "model",
    ]
    .into_iter()
    .collect();
    let present: HashSet<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
    if present != expected {
        return Err(corruption(format!("{what} carries the wrong fields")));
    }
    if !is_text(record.get("at").unwrap()) {
        return Err(corruption(format!("{what} carries an instant of no use")));
    }
    if !digest_form_ok(record.get("call_digest").unwrap()) {
        return Err(corruption(format!("{what} carries a digest of no use")));
    }
    let decision_value = record.get("decision").unwrap();
    if !matches!(decision_value, Value::Str(d) if ["allow", "deny", "escalate"].contains(&d.as_str()))
    {
        return Err(corruption(format!(
            "{what} names a decision outside the set"
        )));
    }
    let decision_text = decision_value.as_str().unwrap();
    let source = record.get("source").unwrap();
    let source_pairs = match source.as_object() {
        Some(pairs) => pairs,
        None => {
            return Err(corruption(format!("{what} carries a source of no use")));
        }
    };
    let source_keys: HashSet<&str> = source_pairs.iter().map(|(key, _)| key.as_str()).collect();
    if source_keys != HashSet::from(["type", "rule"])
        || source.get("type").unwrap() != &Value::text("model")
        || !is_text(source.get("rule").unwrap())
        || source.get("rule").unwrap().as_str() == Some("")
    {
        return Err(corruption(format!(
            "{what} carries a model source of no use"
        )));
    }
    let reason = record.get("reason").unwrap();
    if !is_text(reason) || reason.as_str() == Some("") {
        return Err(corruption(format!(
            "{what} carries a model source with no reason"
        )));
    }
    if !matches!(record.get("interpreter").unwrap(), Value::Bool(_)) {
        return Err(corruption(format!(
            "{what} carries an interpreter flag of no use"
        )));
    }
    if *record.get("rewritten_call").unwrap() != Value::Null {
        return Err(corruption(format!(
            "{what} carries a rewritten call on a model record"
        )));
    }
    let model = record.get("model").unwrap();
    let model_pairs = match model.as_object() {
        Some(pairs) => pairs,
        None => {
            return Err(corruption(format!(
                "{what} carries a model field of no use"
            )));
        }
    };
    let model_keys: HashSet<&str> = model_pairs.iter().map(|(key, _)| key.as_str()).collect();
    let expected_model_keys: HashSet<&str> = [
        "model",
        "verdict",
        "confidence",
        "probabilities",
        "risk_score",
        "fallback",
        "failure",
        "request_digest",
    ]
    .into_iter()
    .collect();
    if model_keys != expected_model_keys {
        return Err(corruption(format!(
            "{what} carries a model field with the wrong fields"
        )));
    }
    if !matches!(model.get("model").unwrap(), Value::Str(name) if is_valid_model_name(name)) {
        return Err(corruption(format!(
            "{what} carries a model name this gate does not carry"
        )));
    }
    let verdict = model.get("verdict").unwrap();
    let verdict_text = match verdict {
        Value::Null => None,
        Value::Str(label) if VERDICT_LABELS.contains(&label.as_str()) => Some(label.as_str()),
        _ => {
            return Err(corruption(format!("{what} carries a verdict of no use")));
        }
    };
    let confidence = model.get("confidence").unwrap();
    if *confidence != Value::Null && !record_number_in_range(confidence, 0.0, 1.0) {
        return Err(corruption(format!("{what} carries a confidence of no use")));
    }
    let probabilities = model.get("probabilities").unwrap();
    if *probabilities != Value::Null {
        let probability_pairs = match probabilities.as_object() {
            Some(pairs) if pairs.len() == 4 => pairs,
            _ => {
                return Err(corruption(format!(
                    "{what} carries probabilities of no use"
                )));
            }
        };
        let probability_keys: HashSet<&str> = probability_pairs
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        if probability_keys != VERDICT_LABELS.iter().copied().collect::<HashSet<&str>>() {
            return Err(corruption(format!(
                "{what} carries probabilities of no use"
            )));
        }
        for label in VERDICT_LABELS {
            if !record_number_in_range(probabilities.get(label).unwrap(), 0.0, 1.0) {
                return Err(corruption(format!(
                    "{what} carries probabilities of no use"
                )));
            }
        }
    }
    if (verdict_text.is_none()) != (*confidence == Value::Null)
        || (verdict_text.is_none()) != (*probabilities == Value::Null)
    {
        return Err(corruption(format!(
            "{what} carries model fields that disagree"
        )));
    }
    if let Some(label) = verdict_text {
        let carried = probabilities.get(label).unwrap();
        if number_f64(confidence) != number_f64(carried) {
            return Err(corruption(format!(
                "{what} carries a confidence that disagrees with its probabilities"
            )));
        }
    }
    let confidence_number = match verdict_text {
        Some(_) => number_f64(confidence),
        None => None,
    };
    let risk_score = model.get("risk_score").unwrap();
    if *risk_score != Value::Null && !record_number_in_range(risk_score, 1.0, 10.0) {
        return Err(corruption(format!("{what} carries a risk score of no use")));
    }
    if !digest_form_ok(model.get("request_digest").unwrap()) {
        return Err(corruption(format!(
            "{what} carries a request digest of no use"
        )));
    }
    let fallback = match model.get("fallback").unwrap().as_str() {
        Some(name) => name,
        None => {
            return Err(corruption(format!("{what} carries a fallback of no use")));
        }
    };
    let failure = model.get("failure").unwrap();
    let failure_text = match failure {
        Value::Null => None,
        Value::Str(name) => Some(name.as_str()),
        _ => {
            return Err(corruption(format!("{what} carries a failure of no use")));
        }
    };
    let fallback_outcome = decision_text == "escalate" || decision_text == "deny";
    let agrees = match (fallback, failure_text) {
        ("none", None) => {
            verdict_text.is_some()
                && (decision_text == verdict_text.unwrap()
                    || (verdict_text == Some("escalate") && decision_text == "deny"))
                && (verdict_text == Some("escalate")
                    || confidence_number.is_some_and(|number| number > 0.0))
        }
        ("threshold", None) => {
            matches!(verdict_text, Some("allow") | Some("deny"))
                && fallback_outcome
                && confidence_number.is_some_and(|number| number < 1.0)
        }
        ("abstention", Some("abstention")) => verdict_text == Some("other") && fallback_outcome,
        ("silence", Some("silence"))
        | ("malformed", Some("malformed"))
        | ("transport", Some("transport"))
        | ("no transport", Some("no transport")) => verdict_text.is_none() && fallback_outcome,
        _ => false,
    };
    if !agrees {
        return Err(corruption(format!(
            "{what} carries a fallback and a failure that disagree"
        )));
    }
    Ok(())
}

/// Read and verify every record in the audit log at the path.
///
/// Raises a caller error when the file does not stand and a
/// corruption error naming the first line that fails.
pub fn read_log(log_path: &Path) -> Result<Vec<Value>, LogReadError> {
    let data = match std::fs::read(log_path) {
        Ok(data) => data,
        Err(exc) if exc.kind() == std::io::ErrorKind::NotFound => {
            return Err(LogReadError::Caller(CallerError(format!(
                "the audit log at {} does not stand",
                log_path.display()
            ))));
        }
        Err(exc) => {
            return Err(LogReadError::Caller(CallerError(format!(
                "the audit log at {} cannot be read, {}",
                log_path.display(),
                io_detail(&exc)
            ))));
        }
    };
    let mut raw_lines: Vec<&[u8]> = data.split(|byte| *byte == b'\n').collect();
    if let Some(last) = raw_lines.last() {
        if last.is_empty() {
            raw_lines.pop();
        }
    }
    let mut records = Vec::new();
    for (index, raw_line) in raw_lines.iter().enumerate() {
        let number = index + 1;
        let corruption = |detail: String| LogCorruptionError {
            line_number: number,
            detail,
        };
        let line = match std::str::from_utf8(raw_line) {
            Ok(line) => line,
            Err(_) => {
                return Err(LogReadError::Corruption(corruption(format!(
                    "the record at line {number} does not decode as UTF-8"
                ))));
            }
        };
        let record = match strict_parse(line) {
            Ok(record) => record,
            Err(_) => {
                return Err(LogReadError::Corruption(corruption(format!(
                    "the record at line {number} does not parse"
                ))));
            }
        };
        match validate_decision_record(&record, number) {
            Ok(()) => records.push(record),
            Err(exc) => return Err(LogReadError::Corruption(exc)),
        }
    }
    Ok(records)
}

// --- the sampling audit -------------------------------------------------------

/// Audit the log at the path and return the report document
/// of the sampling slice, in the format portcullis-audit/1.
///
/// The named size is judged before the log is read, and a
/// size of zero is a caller error. The log is then read whole
/// through read_log unchanged, so a log that does not stand
/// and a log corrupt at a named line refuse the audit with the
/// error the log reading already stands on. Every record the
/// reader returns stands in exactly one of the four classes
/// obligation PC-21 names. The ranked class, the second format
/// records whose decision names allow and whose risk score
/// stands as a number, orders by the score descending, and
/// records whose scores stand equal keep their line order, the
/// earlier line first, because the sort is stable over records
/// gathered in line order. A named size above the ranked class
/// returns the whole class, with the named size and the
/// returned count both standing in the report. The audit
/// writes nothing and decides nothing, and the report it
/// returns exists only where a caller prints or keeps it.
pub fn audit_log(log_path: &Path, sample_size: usize) -> Result<Value, LogReadError> {
    if sample_size == 0 {
        return Err(LogReadError::Caller(CallerError(
            "the sample size must stand at one or above".to_string(),
        )));
    }
    let records = read_log(log_path)?;
    let line_count = records.len();
    let mut ranked: Vec<(usize, f64, Value, Value)> = Vec::new();
    let mut scored_not_allowed: usize = 0;
    let mut unscored: usize = 0;
    let mut first_format: usize = 0;
    for (index, record) in records.into_iter().enumerate() {
        let line = index + 1;
        match record.get("format") {
            Some(format) if format == &Value::text(DECISION_FORMAT_2) => {
                let score = record
                    .get("model")
                    .and_then(|model| model.get("risk_score"))
                    .and_then(|value| number_f64(value).map(|number| (value.clone(), number)));
                match (
                    record.get("decision").and_then(|value| value.as_str()),
                    score,
                ) {
                    (Some("allow"), Some((score_value, number))) => {
                        ranked.push((line, number, score_value, record));
                    }
                    (Some("deny") | Some("escalate"), Some(_)) => {
                        scored_not_allowed += 1;
                    }
                    _ => {
                        unscored += 1;
                    }
                }
            }
            _ => {
                first_format += 1;
            }
        }
    }
    let ranked_count = ranked.len();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let returned = sample_size.min(ranked_count);
    let mut sample = Vec::with_capacity(returned);
    for (offset, (line, _number, risk_score, record)) in
        ranked.into_iter().take(returned).enumerate()
    {
        sample.push(Value::obj(vec![
            ("rank", Value::int((offset + 1) as i64)),
            ("line", Value::int(line as i64)),
            ("risk_score", risk_score),
            ("record", record),
        ]));
    }
    Ok(Value::obj(vec![
        ("format", Value::text(AUDIT_FORMAT)),
        ("requested", Value::Int(sample_size.to_string())),
        ("returned", Value::int(returned as i64)),
        (
            "counts",
            Value::obj(vec![
                ("lines", Value::int(line_count as i64)),
                ("ranked", Value::int(ranked_count as i64)),
                ("scored_not_allowed", Value::int(scored_not_allowed as i64)),
                ("unscored", Value::int(unscored as i64)),
                ("first_format", Value::int(first_format as i64)),
            ]),
        ),
        ("sample", Value::Array(sample)),
    ]))
}
