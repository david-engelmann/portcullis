//! The policy model and its validator: a policy document to a policy.

use crate::call::{argv_form_ok, check_keys, is_text, valid_port};
use crate::errors::PolicyError;
use crate::value::Value;
use crate::{ACTIONS, DEFAULTS, FILE_OPERATIONS, JUDGE_MODELS, KINDS, MATCHER_KEYS, POLICY_FORMAT};
use std::collections::HashSet;

/// One text matcher, holding exactly one form.
#[derive(Clone, Debug, PartialEq)]
pub enum Matcher {
    Exact(String),
    Prefix(String),
    Glob(String),
}

/// One argument condition of a shell match.
#[derive(Clone, Debug, PartialEq)]
pub struct ArgCondition {
    pub index: usize,
    pub matcher: Matcher,
}

/// The conditions of one rule, by the kind the rule speaks to.
/// Only the fields of that kind ever stand.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Match {
    pub argv0: Option<Matcher>,
    pub args: Vec<ArgCondition>,
    pub operation: Option<Matcher>,
    pub path: Option<Matcher>,
    pub method: Option<Matcher>,
    pub host: Option<Matcher>,
    pub port: Option<i64>,
}

/// The replacement values of a rewrite rule, by kind.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Substitute {
    pub argv: Option<Value>,
    pub cwd: Option<Value>,
    pub operation: Option<Value>,
    pub path: Option<Value>,
    pub path2: Option<Value>,
    pub method: Option<Value>,
    pub host: Option<Value>,
    pub port: Option<Value>,
}

/// One validated rule of a policy.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub id: String,
    pub kind: String,
    pub action: String,
    pub reason: String,
    pub match_: Match,
    pub substitute: Option<Substitute>,
}

/// The judgment block of a policy, the model referrals go to,
/// the confidence bar a verdict must clear, and the fallback
/// outcome family the policy declares for uncertainty.
#[derive(Clone, Debug, PartialEq)]
pub struct Judgment {
    pub model: String,
    pub threshold: f64,
    pub escalation: String,
}

/// A policy that loaded whole, with its declared default.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub default: String,
    pub rules: Vec<Rule>,
    pub judgment: Option<Judgment>,
}

fn check_policy_keys(document: &Value, allowed: &[&str], what: &str) -> Result<(), PolicyError> {
    check_keys(document, allowed, &[], what).map_err(PolicyError)
}

fn validate_matcher(value: &Value, what: &str, fold: bool) -> Result<Matcher, PolicyError> {
    let pairs = match value.as_object() {
        Some(pairs) if pairs.len() == 1 => pairs,
        _ => {
            return Err(PolicyError(format!(
                "{what} is not a matcher holding exactly one form"
            )));
        }
    };
    let (form, pattern) = &pairs[0];
    if !MATCHER_KEYS.contains(&form.as_str()) {
        return Err(PolicyError(format!(
            "{what} names a match form this gate does not use"
        )));
    }
    if !is_text(pattern) {
        return Err(PolicyError(format!(
            "{what} carries a pattern that is not a string"
        )));
    }
    let mut pattern = pattern.as_str().unwrap().to_string();
    if fold {
        pattern = pattern.to_lowercase();
    }
    Ok(match form.as_str() {
        "exact" => Matcher::Exact(pattern),
        "prefix" => Matcher::Prefix(pattern),
        _ => Matcher::Glob(pattern),
    })
}

fn validate_port_matcher(value: &Value, what: &str) -> Result<i64, PolicyError> {
    let pairs = match value.as_object() {
        Some(pairs) if pairs.len() == 1 && pairs[0].0 == "exact" => pairs,
        _ => {
            return Err(PolicyError(format!(
                "{what} is not a port matcher holding one exact port"
            )));
        }
    };
    if !valid_port(&pairs[0].1) {
        return Err(PolicyError(format!(
            "{what} carries a port outside its range"
        )));
    }
    Ok(pairs[0].1.int_i64().unwrap())
}

fn validate_arg_conditions(value: &Value, what: &str) -> Result<Vec<ArgCondition>, PolicyError> {
    let items = match value.as_array() {
        Some(items) if !items.is_empty() => items,
        _ => {
            return Err(PolicyError(format!(
                "{what} carries an argument condition list of no use"
            )));
        }
    };
    let mut result = Vec::new();
    for entry in items {
        if entry.as_object().is_none() {
            return Err(PolicyError(format!(
                "{what} carries an argument condition that is not an object"
            )));
        }
        let entry_what = format!("{what} argument condition");
        check_policy_keys(entry, &["index", "match"], &entry_what)?;
        if entry.get("index").is_none() {
            return Err(PolicyError(format!(
                "{what} carries an argument condition with no index"
            )));
        }
        if entry.get("match").is_none() {
            return Err(PolicyError(format!(
                "{what} carries an argument condition with no match"
            )));
        }
        let index = entry.get("index").unwrap();
        if !index.is_int() {
            return Err(PolicyError(format!(
                "{what} carries an argument condition whose index is not an integer"
            )));
        }
        let index_value = index.int_usize_saturated();
        if index_value == Some(0) {
            return Err(PolicyError(format!(
                "{what} names an argument position below 1"
            )));
        }
        result.push(ArgCondition {
            index: index_value.unwrap(),
            matcher: validate_matcher(
                entry.get("match").unwrap(),
                &format!("{what} argument matcher"),
                false,
            )?,
        });
    }
    Ok(result)
}

fn validate_match(kind: &str, match_value: &Value, rule_id: &str) -> Result<Match, PolicyError> {
    let what = format!("the match of rule {rule_id}");
    if match_value.as_object().is_none() || match_value.as_object().unwrap().is_empty() {
        return Err(PolicyError(format!("{what} holds no condition")));
    }
    let mut result = Match::default();
    match kind {
        "shell" => {
            check_policy_keys(match_value, &["argv0", "args"], &what)?;
            if let Some(argv0) = match_value.get("argv0") {
                result.argv0 = Some(validate_matcher(argv0, &format!("{what} on argv0"), false)?);
            }
            if let Some(args) = match_value.get("args") {
                result.args = validate_arg_conditions(args, &what)?;
            }
        }
        "file" => {
            check_policy_keys(match_value, &["operation", "path"], &what)?;
            if let Some(operation) = match_value.get("operation") {
                result.operation = Some(validate_matcher(
                    operation,
                    &format!("{what} on the operation"),
                    false,
                )?);
            }
            if let Some(path) = match_value.get("path") {
                result.path = Some(validate_matcher(
                    path,
                    &format!("{what} on the path"),
                    false,
                )?);
            }
        }
        _ => {
            check_policy_keys(match_value, &["method", "host", "port"], &what)?;
            if let Some(method) = match_value.get("method") {
                result.method = Some(validate_matcher(
                    method,
                    &format!("{what} on the method"),
                    false,
                )?);
            }
            if let Some(host) = match_value.get("host") {
                result.host = Some(validate_matcher(
                    host,
                    &format!("{what} on the host"),
                    true,
                )?);
            }
            if let Some(port) = match_value.get("port") {
                result.port = Some(validate_port_matcher(port, &format!("{what} on the port"))?);
            }
        }
    }
    Ok(result)
}

fn validate_substitute(
    kind: &str,
    substitute: &Value,
    rule_id: &str,
) -> Result<Substitute, PolicyError> {
    let what = format!("the substitute of rule {rule_id}");
    if substitute.as_object().is_none() || substitute.as_object().unwrap().is_empty() {
        return Err(PolicyError(format!("{what} names no replacement value")));
    }
    let mut result = Substitute::default();
    match kind {
        "shell" => {
            check_policy_keys(substitute, &["argv", "cwd"], &what)?;
            if let Some(argv) = substitute.get("argv") {
                if !argv_form_ok(argv) {
                    return Err(PolicyError(format!("{what} carries an argv of no use")));
                }
                result.argv = Some(argv.clone());
            }
            if let Some(cwd) = substitute.get("cwd") {
                if !is_text(cwd) {
                    return Err(PolicyError(format!(
                        "{what} carries a cwd that is not a string"
                    )));
                }
                result.cwd = Some(cwd.clone());
            }
        }
        "file" => {
            check_policy_keys(substitute, &["operation", "path", "path2"], &what)?;
            if let Some(operation) = substitute.get("operation") {
                if !matches!(operation, Value::Str(op) if FILE_OPERATIONS.contains(&op.as_str())) {
                    return Err(PolicyError(format!(
                        "{what} names an operation outside the set"
                    )));
                }
                result.operation = Some(operation.clone());
            }
            for field in ["path", "path2"] {
                if let Some(value) = substitute.get(field) {
                    if !is_text(value) || value.as_str() == Some("") {
                        return Err(PolicyError(format!("{what} carries a {field} of no use")));
                    }
                    match field {
                        "path" => result.path = Some(value.clone()),
                        _ => result.path2 = Some(value.clone()),
                    }
                }
            }
        }
        _ => {
            check_policy_keys(substitute, &["method", "host", "port"], &what)?;
            if let Some(method) = substitute.get("method") {
                if !is_text(method) || method.as_str() == Some("") {
                    return Err(PolicyError(format!("{what} carries a method of no use")));
                }
                result.method = Some(method.clone());
            }
            if let Some(host) = substitute.get("host") {
                if !is_text(host) || host.as_str() == Some("") {
                    return Err(PolicyError(format!("{what} carries a host of no use")));
                }
                result.host = Some(Value::Str(host.as_str().unwrap().to_lowercase()));
            }
            if let Some(port) = substitute.get("port") {
                if !valid_port(port) {
                    return Err(PolicyError(format!(
                        "{what} carries a port outside its range"
                    )));
                }
                result.port = Some(port.clone());
            }
        }
    }
    Ok(result)
}

fn validate_rule(
    rule: &Value,
    position: usize,
    seen_ids: &mut HashSet<String>,
) -> Result<Rule, PolicyError> {
    let position_what = format!("rule at position {position}");
    if rule.as_object().is_none() {
        return Err(PolicyError(format!("the {position_what} is not an object")));
    }
    check_policy_keys(
        rule,
        &["id", "kind", "action", "reason", "match", "substitute"],
        &format!("the {position_what}"),
    )?;
    for field in ["id", "kind", "action", "reason", "match"] {
        if rule.get(field).is_none() {
            return Err(PolicyError(format!(
                "the {position_what} is missing the field {field}"
            )));
        }
    }
    let rule_id_value = rule.get("id").unwrap();
    if !is_text(rule_id_value) || rule_id_value.as_str() == Some("") {
        return Err(PolicyError(format!(
            "the {position_what} carries an id of no use"
        )));
    }
    let rule_id = rule_id_value.as_str().unwrap().to_string();
    let what = format!("rule {rule_id}");
    if !seen_ids.insert(rule_id.clone()) {
        return Err(PolicyError(format!(
            "the policy carries the rule id {rule_id} twice"
        )));
    }
    let kind = rule.get("kind").unwrap();
    if !matches!(kind, Value::Str(k) if KINDS.contains(&k.as_str())) {
        return Err(PolicyError(format!(
            "{what} names a kind this gate does not judge"
        )));
    }
    let action = rule.get("action").unwrap();
    if !matches!(action, Value::Str(a) if ACTIONS.contains(&a.as_str())) {
        return Err(PolicyError(format!(
            "{what} names an action outside the set"
        )));
    }
    let reason = rule.get("reason").unwrap();
    if !is_text(reason) || reason.as_str() == Some("") {
        return Err(PolicyError(format!("{what} carries a reason of no use")));
    }
    let kind = kind.as_str().unwrap();
    let action = action.as_str().unwrap();
    let mut result = Rule {
        id: rule_id.clone(),
        kind: kind.to_string(),
        action: action.to_string(),
        reason: reason.as_str().unwrap().to_string(),
        match_: validate_match(kind, rule.get("match").unwrap(), &rule_id)?,
        substitute: None,
    };
    if action == "rewrite" {
        match rule.get("substitute") {
            None => {
                return Err(PolicyError(format!(
                    "{what} rewrites and carries no substitute"
                )));
            }
            Some(substitute) => {
                result.substitute = Some(validate_substitute(kind, substitute, &rule_id)?);
            }
        }
    } else if rule.get("substitute").is_some() {
        return Err(PolicyError(format!(
            "{what} carries a substitute and does not rewrite"
        )));
    }
    Ok(result)
}

/// Validate the judgment block of a policy document.
///
/// The block holds exactly the keys model and threshold and
/// escalation. The model must be one this build carries, the
/// threshold a number above zero and at most one with a boolean
/// never counting as a number, and the escalation one of queue
/// and none.
fn validate_judgment_block(block: &Value) -> Result<Judgment, PolicyError> {
    if block.as_object().is_none() {
        return Err(PolicyError(
            "the judgment block is not a JSON object".to_string(),
        ));
    }
    check_keys(
        block,
        &["model", "threshold", "escalation"],
        &["model", "threshold", "escalation"],
        "the judgment block",
    )
    .map_err(PolicyError)?;
    let model = block.get("model").unwrap();
    if !matches!(model, Value::Str(name) if JUDGE_MODELS.contains(&name.as_str())) {
        return Err(PolicyError(
            "the judgment block names a model this gate does not carry".to_string(),
        ));
    }
    let threshold = match block.get("threshold").unwrap() {
        Value::Float(value) if value.is_finite() && *value > 0.0 && *value <= 1.0 => Some(*value),
        Value::Int(text) => match text.parse::<i64>() {
            Ok(1) => Some(1.0),
            _ => None,
        },
        _ => None,
    };
    let threshold = match threshold {
        Some(threshold) => threshold,
        None => {
            return Err(PolicyError(
                "the judgment block carries a threshold outside the range above zero and at most one"
                    .to_string(),
            ));
        }
    };
    let escalation = block.get("escalation").unwrap();
    if !matches!(escalation, Value::Str(name) if ["queue", "none"].contains(&name.as_str())) {
        return Err(PolicyError(
            "the judgment block names an escalation outside queue and none".to_string(),
        ));
    }
    Ok(Judgment {
        model: model.as_str().unwrap().to_string(),
        threshold,
        escalation: escalation.as_str().unwrap().to_string(),
    })
}

/// Validate a parsed policy document or raise PolicyError.
///
/// Validation of every rule happens here, so a policy object
/// that comes back is wholly usable and a policy with any
/// invalid part never produces one.
pub fn load_policy(document: &Value) -> Result<Policy, PolicyError> {
    if document.as_object().is_none() {
        return Err(PolicyError("the policy is not a JSON object".to_string()));
    }
    check_policy_keys(
        document,
        &["format", "default", "rules", "judgment"],
        "the policy",
    )?;
    for field in ["format", "default", "rules"] {
        if document.get(field).is_none() {
            return Err(PolicyError(format!(
                "the policy is missing the field {field}"
            )));
        }
    }
    if document.get("format").unwrap() != &Value::text(POLICY_FORMAT) {
        return Err(PolicyError(
            "the policy names a format this gate does not read".to_string(),
        ));
    }
    let default = document.get("default").unwrap();
    if !matches!(default, Value::Str(d) if DEFAULTS.contains(&d.as_str())) {
        return Err(PolicyError(
            "the policy declares a default outside allow and deny".to_string(),
        ));
    }
    let rules_value = document.get("rules").unwrap();
    let rules_array = match rules_value.as_array() {
        Some(rules) => rules,
        None => {
            return Err(PolicyError(
                "the policy carries a rules field that is not a list".to_string(),
            ));
        }
    };
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut rules = Vec::new();
    for (position, rule) in rules_array.iter().enumerate() {
        rules.push(validate_rule(rule, position, &mut seen_ids)?);
    }
    let judgment = match document.get("judgment") {
        Some(block) => Some(validate_judgment_block(block)?),
        None => None,
    };
    if judgment.is_none() && rules.iter().any(|rule| rule.action == "judge") {
        return Err(PolicyError(
            "the policy carries a judge rule and no judgment block".to_string(),
        ));
    }
    Ok(Policy {
        default: default.as_str().unwrap().to_string(),
        rules,
        judgment,
    })
}

// --- matching and evaluation --------------------------------------------------
