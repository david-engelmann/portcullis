//! The referral builder, taking a consultation to the record of its outcome.

use crate::call::is_interpreter_call;
use crate::policy::{Judgment, Rule};
use crate::reader::strict_parse;
use crate::transport::{
    JudgeTransport, RISK_INSTRUCTIONS, RISK_LEVELS, STATE_CLOSING, VERDICT_INSTRUCTIONS,
};
use crate::value::Value;
use crate::writer::{call_digest, canonical};
use crate::{DECISION_FORMAT_2, VERDICT_LABELS};

/// Build the exact request document a referral hands to a
/// transport. The state is built from the validated call and the
/// referring rule and nothing else, so a referral is a pure
/// function of the policy document and the call document.
fn build_request(call: &Value, rule: &Rule, model: &str) -> Value {
    let canonical_call = String::from_utf8(canonical(call)).unwrap();
    let mut lines: Vec<String> = vec![
        "A deterministic gate has referred one proposed tool call for judgment.".to_string(),
        "The deterministic rules have already refused everything they cover, so the call below is one whose safety turns on authority and intent rather than on form.".to_string(),
        "Apply the doctrine stated in the questions to the call below and to nothing else.".to_string(),
        String::new(),
        format!("The referring rule is {}.", rule.id),
        format!("The rule states: {}", rule.reason),
        String::new(),
        "The proposed call, in canonical form:".to_string(),
        canonical_call,
    ];
    if is_interpreter_call(call) {
        lines.push(
            "The call runs a shell interpreter, and its command string is one opaque argument the gate does not parse."
                .to_string(),
        );
    }
    lines.push(String::new());
    lines.push(STATE_CLOSING.to_string());
    let state = lines.join("\n");
    let verdict_question = Value::obj(vec![
        (
            "criteria",
            Value::obj(vec![
                (
                    "allow",
                    Value::text(
                        "Ordinary work inside the granted scope with a stated purpose is an allow.",
                    ),
                ),
                (
                    "deny",
                    Value::text(
                        "A denial is reserved for a call that is itself the harm, meaning destruction or disclosure that no plausible reading of the stated task covers.",
                    ),
                ),
                (
                    "escalate",
                    Value::text(
                        "Any of the boundary conditions the doctrine names, or any doubt the judge cannot resolve from the state, is an escalation.",
                    ),
                ),
                (
                    "other",
                    Value::text("None of the listed options is the correct decision."),
                ),
            ]),
        ),
        ("instructions", Value::text(VERDICT_INSTRUCTIONS)),
        ("type", Value::text("choice")),
    ]);
    let risk_question = Value::obj(vec![
        (
            "criteria",
            Value::Array(RISK_LEVELS.iter().map(|level| Value::text(level)).collect()),
        ),
        ("instructions", Value::text(RISK_INSTRUCTIONS)),
        ("type", Value::text("score")),
    ]);
    Value::obj(vec![
        ("model", Value::text(model)),
        (
            "questions",
            Value::obj(vec![("risk", risk_question), ("verdict", verdict_question)]),
        ),
        ("state", Value::text(&state)),
    ])
}

/// The numeric value of a document number, or None when the
/// value is no number or stands outside the width the checks
/// here judge. A boolean is never a number.
pub(crate) fn number_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Float(number) if number.is_finite() => Some(*number),
        Value::Int(text) => text.parse::<i64>().ok().map(|number| number as f64),
        _ => None,
    }
}

/// The risk score a reply carries, moved onto the one to ten
/// scale of the levels the risk question declares, or None when
/// the reply carries no usable score answer. The reply carries
/// the score as a position on a zero based scale over its ten
/// levels, so the recorded score is that position plus one. A
/// missing or defective score never spoils a verdict.
fn extract_risk_score(document: &Value) -> Option<f64> {
    let risk = document.get("answers")?.get("risk")?;
    risk.as_object()?;
    let number = number_f64(risk.get("score")?)?;
    if (0.0..=9.0).contains(&number) {
        Some(number + 1.0)
    } else {
        None
    }
}

/// What a reply body classifies as under the reply grammar.
enum Classified {
    Verdict {
        label: String,
        confidence_value: Value,
        confidence_number: f64,
        probabilities: Value,
        risk: Option<f64>,
    },
    Abstention {
        confidence_value: Value,
        probabilities: Value,
        risk: Option<f64>,
    },
    Silence {
        risk: Option<f64>,
    },
    Malformed {
        risk: Option<f64>,
    },
}

/// Classify one reply body. The confidence of a verdict is the
/// probability of the chosen label read from the probabilities
/// map, and a confidence field the reply also carries is not
/// read, because it is a separate measurement. Fields the
/// grammar does not name are not read.
fn classify_reply(body: &str) -> Classified {
    if body.trim().is_empty() {
        return Classified::Silence { risk: None };
    }
    let document = match strict_parse(body) {
        Ok(document) => document,
        Err(_) => return Classified::Malformed { risk: None },
    };
    let risk = extract_risk_score(&document);
    let entry = match document
        .get("answers")
        .and_then(|answers| answers.get("verdict"))
    {
        None => return Classified::Silence { risk },
        Some(entry) => entry,
    };
    if entry.as_object().is_none() {
        return Classified::Malformed { risk };
    }
    let choice = match entry.get("choice") {
        Some(Value::Str(choice)) if VERDICT_LABELS.contains(&choice.as_str()) => choice.clone(),
        _ => return Classified::Malformed { risk },
    };
    let probabilities = match entry.get("probabilities") {
        Some(probabilities)
            if probabilities
                .as_object()
                .is_some_and(|pairs| pairs.len() == 4) =>
        {
            probabilities.clone()
        }
        _ => return Classified::Malformed { risk },
    };
    for label in VERDICT_LABELS {
        match probabilities.get(label) {
            Some(value) => match number_f64(value) {
                Some(number) if (0.0..=1.0).contains(&number) => {}
                _ => return Classified::Malformed { risk },
            },
            None => return Classified::Malformed { risk },
        }
    }
    let confidence_value = probabilities.get(&choice).unwrap().clone();
    let confidence_number = number_f64(&confidence_value).unwrap();
    if choice == "other" {
        Classified::Abstention {
            confidence_value,
            probabilities,
            risk,
        }
    } else {
        Classified::Verdict {
            label: choice,
            confidence_value,
            confidence_number,
            probabilities,
            risk,
        }
    }
}

/// The referral one record speaks of, grouped once so the
/// record constructors take the shared inputs as one value
/// rather than repeating them at every call site.
struct ReferralContext<'a> {
    judgment: &'a Judgment,
    rule: &'a Rule,
    digest: &'a str,
    at: &'a str,
    interpreter: bool,
    request_digest: &'a str,
}

/// The decided outcome of one referral and the model field
/// values its record carries, grouped so the record
/// constructor takes the shape of the landed decision
/// constructor rather than a long argument list of its own.
struct ReferralParts<'a> {
    outcome: &'a str,
    verdict: Value,
    confidence: Value,
    probabilities: Value,
    risk_score: Value,
    fallback: &'a str,
    failure: Option<&'a str>,
}

/// One model decision record, in the second format, carrying
/// the eight landed fields and the model field.
fn referral_record(context: &ReferralContext<'_>, parts: ReferralParts<'_>) -> Value {
    let model = Value::obj(vec![
        ("model", Value::text(&context.judgment.model)),
        ("verdict", parts.verdict),
        ("confidence", parts.confidence),
        ("probabilities", parts.probabilities),
        ("risk_score", parts.risk_score),
        ("fallback", Value::text(parts.fallback)),
        (
            "failure",
            match parts.failure {
                Some(name) => Value::text(name),
                None => Value::Null,
            },
        ),
        ("request_digest", Value::text(context.request_digest)),
    ]);
    Value::obj(vec![
        ("format", Value::text(DECISION_FORMAT_2)),
        ("at", Value::text(context.at)),
        ("call_digest", Value::text(context.digest)),
        ("decision", Value::text(parts.outcome)),
        (
            "source",
            Value::obj(vec![
                ("type", Value::text("model")),
                ("rule", Value::text(&context.rule.id)),
            ]),
        ),
        ("reason", Value::text(&context.rule.reason)),
        ("interpreter", Value::Bool(context.interpreter)),
        ("rewritten_call", Value::Null),
        ("model", model),
    ])
}

/// The recorded risk score value of one referral, the score
/// on its one to ten scale, or null when the reply carried no
/// usable score answer.
fn risk_score_value(risk: Option<f64>) -> Value {
    match risk {
        Some(score) => Value::Float(score),
        None => Value::Null,
    }
}

/// The record of a referral that landed on its fallback
/// outcome under one of the failure classes of the contract.
/// The class names both the fallback and the failure, and the
/// verdict and the confidence and the probabilities stand
/// null, because no verdict was obtained. The risk score is
/// the one the reply carried, where a reply stood to carry
/// one at all.
fn referral_failure_record(
    context: &ReferralContext<'_>,
    fallback_outcome: &str,
    class: &str,
    risk: Option<f64>,
) -> Value {
    referral_record(
        context,
        ReferralParts {
            outcome: fallback_outcome,
            verdict: Value::Null,
            confidence: Value::Null,
            probabilities: Value::Null,
            risk_score: risk_score_value(risk),
            fallback: class,
            failure: Some(class),
        },
    )
}

/// Decide one referred call. The transport is consulted once,
/// its reply is classified, and the combination rule of the
/// contract is applied. With no transport the referral is
/// decided on the no transport fallback and no consultation
/// happens at all.
pub(crate) fn judge_decision(
    judgment: &Judgment,
    rule: &Rule,
    call: &Value,
    digest: &str,
    at: &str,
    interpreter: bool,
    transport: Option<&dyn JudgeTransport>,
) -> Value {
    let request = build_request(call, rule, &judgment.model);
    let request_digest = call_digest(&request);
    let fallback_outcome = if judgment.escalation == "queue" {
        "escalate"
    } else {
        "deny"
    };
    let context = ReferralContext {
        judgment,
        rule,
        digest,
        at,
        interpreter,
        request_digest: &request_digest,
    };
    let transport = match transport {
        None => {
            return referral_failure_record(&context, fallback_outcome, "no transport", None);
        }
        Some(transport) => transport,
    };
    let body = match transport.consult(&request) {
        Ok(body) => body,
        Err(_) => {
            return referral_failure_record(&context, fallback_outcome, "transport", None);
        }
    };
    match classify_reply(&body) {
        Classified::Verdict {
            label,
            confidence_value,
            confidence_number,
            probabilities,
            risk,
        } => {
            let (outcome, fallback) = if label == "escalate" {
                (fallback_outcome, "none")
            } else if confidence_number >= judgment.threshold {
                (label.as_str(), "none")
            } else {
                (fallback_outcome, "threshold")
            };
            referral_record(
                &context,
                ReferralParts {
                    outcome,
                    verdict: Value::text(&label),
                    confidence: confidence_value,
                    probabilities,
                    risk_score: risk_score_value(risk),
                    fallback,
                    failure: None,
                },
            )
        }
        Classified::Abstention {
            confidence_value,
            probabilities,
            risk,
            ..
        } => referral_record(
            &context,
            ReferralParts {
                outcome: fallback_outcome,
                verdict: Value::text("other"),
                confidence: confidence_value,
                probabilities,
                risk_score: risk_score_value(risk),
                fallback: "abstention",
                failure: Some("abstention"),
            },
        ),
        Classified::Silence { risk } => {
            referral_failure_record(&context, fallback_outcome, "silence", risk)
        }
        Classified::Malformed { risk } => {
            referral_failure_record(&context, fallback_outcome, "malformed", risk)
        }
    }
}

// --- the audit log ------------------------------------------------------------
