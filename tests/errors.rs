//! Tests for the library's public error family, finding PC-A13
//! of the audit register. Every error type the library hands a
//! caller implements std::error::Error, and LogReadError, the
//! error read_log and audit_log return, implements Display by
//! delegating to the error it carries and chains to that error
//! as its source. Every test here can fail for a real reason:
//! the trait-surface test does not compile against a family
//! without the Error implementations, and the Display and
//! source tests read the exact text and the exact chain the
//! implementations produce. The fixtures are synthetic and
//! written for this repo.

use std::error::Error;

use portcullis::{
    CallerError, LogAppendError, LogCorruptionError, LogReadError, MalformedCall, PolicyError,
    TransportError,
};

#[test]
fn every_public_error_type_stands_behind_the_error_trait() {
    let caller: &dyn Error = &CallerError("caller text".to_string());
    let policy: &dyn Error = &PolicyError("policy text".to_string());
    let malformed: &dyn Error = &MalformedCall("malformed text".to_string());
    let append: &dyn Error = &LogAppendError("append text".to_string());
    let corruption: &dyn Error = &LogCorruptionError {
        line_number: 2,
        detail: "detail text".to_string(),
    };
    let transport: &dyn Error = &TransportError("transport text".to_string());
    let read: &dyn Error = &LogReadError::Caller(CallerError("caller text".to_string()));
    assert_eq!(caller.to_string(), "caller text");
    assert_eq!(policy.to_string(), "policy text");
    assert_eq!(malformed.to_string(), "malformed text");
    assert_eq!(append.to_string(), "append text");
    assert_eq!(corruption.to_string(), "line 2, detail text");
    assert_eq!(transport.to_string(), "transport text");
    assert_eq!(read.to_string(), "caller text");
}

#[test]
fn a_corruption_read_error_displays_the_line_and_detail_it_carries() {
    let error = LogReadError::Corruption(LogCorruptionError {
        line_number: 2,
        detail: "the record at line 2 does not parse".to_string(),
    });
    assert_eq!(
        error.to_string(),
        "line 2, the record at line 2 does not parse"
    );
}

#[test]
fn a_caller_read_error_displays_the_caller_text_it_carries() {
    let error = LogReadError::Caller(CallerError(
        "the sample size must stand at one or above".to_string(),
    ));
    assert_eq!(
        error.to_string(),
        "the sample size must stand at one or above"
    );
}

#[test]
fn a_read_error_chains_to_the_error_it_carries() {
    let corruption = LogReadError::Corruption(LogCorruptionError {
        line_number: 2,
        detail: "detail text".to_string(),
    });
    let source = corruption
        .source()
        .expect("a corruption read error carries its error as its source");
    assert_eq!(source.to_string(), "line 2, detail text");
    assert!(source.downcast_ref::<LogCorruptionError>().is_some());

    let caller = LogReadError::Caller(CallerError("caller text".to_string()));
    let source = caller
        .source()
        .expect("a caller read error carries its error as its source");
    assert_eq!(source.to_string(), "caller text");
    assert!(source.downcast_ref::<CallerError>().is_some());
}

#[test]
fn the_leaf_error_types_report_no_source() {
    assert!(CallerError("caller text".to_string()).source().is_none());
    assert!(PolicyError("policy text".to_string()).source().is_none());
    assert!(MalformedCall("malformed text".to_string())
        .source()
        .is_none());
    assert!(LogAppendError("append text".to_string()).source().is_none());
    assert!(LogCorruptionError {
        line_number: 2,
        detail: "detail text".to_string(),
    }
    .source()
    .is_none());
    assert!(TransportError("transport text".to_string())
        .source()
        .is_none());
}
