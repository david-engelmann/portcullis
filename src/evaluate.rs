//! The evaluator, taking one call and one policy to one decision.

use crate::call::{is_interpreter_call, validate_call};
use crate::matching::{apply_substitute, decision, rule_matches, source_rule};
use crate::policy::Policy;
use crate::referral::judge_decision;
use crate::transport::JudgeTransport;
use crate::value::Value;
use crate::writer::call_digest;

/// Decide one parsed call document against a loaded policy.
///
/// The policy is the object load_policy returned, or None when
/// the policy could not be loaded, in which case the policy
/// error states the load failure and every schema valid call is
/// denied with the policy error source. The final argument is
/// the instant string to record.
pub fn evaluate(
    policy: Option<&Policy>,
    policy_error: Option<&str>,
    document: &Value,
    at: &str,
) -> Value {
    evaluate_inner(policy, policy_error, document, at, None)
}

/// Decide one parsed call document against a loaded policy,
/// consulting the given transport on a referral.
///
/// This is the judging entry point. It differs from evaluate
/// only in the transport it is handed, and with no transport it
/// decides every referral on the no transport fallback, exactly
/// as evaluate does.
pub fn evaluate_with_transport(
    policy: Option<&Policy>,
    policy_error: Option<&str>,
    document: &Value,
    at: &str,
    transport: Option<&dyn JudgeTransport>,
) -> Value {
    evaluate_inner(policy, policy_error, document, at, transport)
}

fn evaluate_inner(
    policy: Option<&Policy>,
    policy_error: Option<&str>,
    document: &Value,
    at: &str,
    transport: Option<&dyn JudgeTransport>,
) -> Value {
    let digest = call_digest(document);
    let call = match validate_call(document) {
        Ok(call) => call,
        Err(_) => {
            return decision(
                at,
                &digest,
                "deny",
                Value::obj(vec![("type", Value::text("malformed"))]),
                None,
                false,
                None,
            );
        }
    };
    let interpreter = is_interpreter_call(&call);
    let policy = match policy {
        Some(policy) => policy,
        None => {
            return decision(
                at,
                &digest,
                "deny",
                Value::obj(vec![
                    ("type", Value::text("policy error")),
                    ("detail", Value::text(policy_error.unwrap_or(""))),
                ]),
                None,
                interpreter,
                None,
            );
        }
    };
    let kind = call.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    for rule in policy.rules.iter().filter(|rule| rule.kind == kind) {
        if rule.action == "deny" && rule_matches(rule, &call) {
            return decision(
                at,
                &digest,
                "deny",
                source_rule(&rule.id),
                Some(&rule.reason),
                interpreter,
                None,
            );
        }
    }
    for rule in policy.rules.iter().filter(|rule| rule.kind == kind) {
        if rule.action == "deny" {
            continue;
        }
        if !rule_matches(rule, &call) {
            continue;
        }
        if rule.action == "allow" {
            return decision(
                at,
                &digest,
                "allow",
                source_rule(&rule.id),
                Some(&rule.reason),
                interpreter,
                None,
            );
        }
        if rule.action == "judge" {
            match &policy.judgment {
                Some(judgment) => {
                    return judge_decision(
                        judgment,
                        rule,
                        &call,
                        &digest,
                        at,
                        interpreter,
                        transport,
                    );
                }
                // load_policy refuses a judge rule with no block,
                // so this arm only stands for a policy object a
                // caller built by hand, and there the rule simply
                // never fires.
                None => continue,
            }
        }
        let substitute = match &rule.substitute {
            Some(substitute) => substitute,
            // load_policy refuses a rewrite rule with no
            // substitute, so this arm only stands for a policy
            // object a caller built by hand, and there the rule
            // simply never fires.
            None => continue,
        };
        let rewritten = apply_substitute(&call, substitute, kind);
        let rewritten = match validate_call(&rewritten) {
            Ok(rewritten) => rewritten,
            Err(_) => {
                return decision(
                    at,
                    &digest,
                    "deny",
                    source_rule(&rule.id),
                    Some(&rule.reason),
                    interpreter,
                    None,
                );
            }
        };
        let rewritten_interpreter = is_interpreter_call(&rewritten);
        return decision(
            at,
            &digest,
            "rewrite",
            source_rule(&rule.id),
            Some(&rule.reason),
            interpreter || rewritten_interpreter,
            Some(rewritten),
        );
    }
    decision(
        at,
        &digest,
        &policy.default.clone(),
        Value::obj(vec![("type", Value::text("default"))]),
        None,
        interpreter,
        None,
    )
}

// --- judgment -----------------------------------------------------------------
//
// A judge rule refers a call to the model the policy judgment
// block names. The referral is built here, the reply is
// classified here, and the combination of the verdict with the
// policy threshold and escalation value is ordinary code here.
// A transport moves text only and classifies nothing.
