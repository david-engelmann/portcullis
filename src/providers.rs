//! Pure zero-network wire codecs for System One decision model providers under PC-35.
//!
//! Every function in this module is a deterministic document transformation
//! with no network client, no clock, and no credential access. External judge
//! helpers use these functions to translate canonical PC-26 referral requests
//! into provider wire formats and normalize raw provider responses back into
//! canonical PC-26 reply bodies.

use crate::errors::CallerError;
use crate::is_valid_model_name;
use crate::reader::strict_parse;
use crate::referral::number_f64;
use crate::value::Value;
use crate::writer::canonical;
use crate::{DEFAULT_JUDGE_MODEL, VERDICT_LABELS};

/// One of the five supported System One decision model provider dialects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionProvider {
    TypeSafe,
    Google,
    OpenAi,
    Perplexity,
    Cloudflare,
}

impl DecisionProvider {
    /// Canonical lowercase provider identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            DecisionProvider::TypeSafe => "typesafe",
            DecisionProvider::Google => "google",
            DecisionProvider::OpenAi => "openai",
            DecisionProvider::Perplexity => "perplexity",
            DecisionProvider::Cloudflare => "cloudflare",
        }
    }

    /// Parse a canonical lowercase provider identifier.
    pub fn from_name(name: &str) -> Option<DecisionProvider> {
        match name {
            "typesafe" => Some(DecisionProvider::TypeSafe),
            "google" => Some(DecisionProvider::Google),
            "openai" => Some(DecisionProvider::OpenAi),
            "perplexity" => Some(DecisionProvider::Perplexity),
            "cloudflare" => Some(DecisionProvider::Cloudflare),
            _ => None,
        }
    }

    /// Default HTTPS endpoint for this provider family.
    pub fn default_endpoint(&self) -> &'static str {
        match self {
            DecisionProvider::TypeSafe => "https://api.typesafe.ai/v1/systemone",
            DecisionProvider::Google => "https://generativelanguage.googleapis.com/v1beta/decisions",
            DecisionProvider::OpenAi => "https://api.openai.com/v1/decisions",
            DecisionProvider::Perplexity => "https://api.perplexity.ai/v1/decisions",
            DecisionProvider::Cloudflare => {
                "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/@cf/cloudflare/clef"
            }
        }
    }
}

/// Auto-detect the System One provider dialect from a model identifier.
pub fn detect_provider(model: &str) -> DecisionProvider {
    if model.starts_with("typesafe/") || model.starts_with("jev-") {
        DecisionProvider::TypeSafe
    } else if model.starts_with("google/")
        || model.starts_with("models/gemini-decision-")
        || model.starts_with("gemini-decision-")
    {
        DecisionProvider::Google
    } else if model.starts_with("openai/")
        || model.starts_with("gpt-6-")
        || model.starts_with("gpt-oss-safeguard")
    {
        DecisionProvider::OpenAi
    } else if model.starts_with("perplexity/") || model.starts_with("pplx-decider") {
        DecisionProvider::Perplexity
    } else if model.starts_with("cloudflare/")
        || model.starts_with("@cf/cloudflare/clef")
        || model.starts_with("clef")
    {
        DecisionProvider::Cloudflare
    } else {
        DecisionProvider::TypeSafe
    }
}

/// Resolve the JSON body model identifier sent inside a provider request payload.
pub fn wire_model_name(provider: DecisionProvider, model: &str) -> String {
    match provider {
        DecisionProvider::TypeSafe => model.strip_prefix("typesafe/").unwrap_or(model).to_string(),
        DecisionProvider::Google => {
            let stripped = model.strip_prefix("google/").unwrap_or(model);
            stripped
                .strip_prefix("models/")
                .unwrap_or(stripped)
                .to_string()
        }
        DecisionProvider::OpenAi => model.strip_prefix("openai/").unwrap_or(model).to_string(),
        DecisionProvider::Perplexity => model
            .strip_prefix("perplexity/")
            .unwrap_or(model)
            .to_string(),
        DecisionProvider::Cloudflare => {
            let stripped = model.strip_prefix("cloudflare/").unwrap_or(model);
            match stripped {
                "@cf/cloudflare/clef" => "clef".to_string(),
                "@cf/cloudflare/clef-flash" => "clef-flash".to_string(),
                "@cf/cloudflare/clef-omni" => "clef-omni".to_string(),
                other => other.to_string(),
            }
        }
    }
}

/// Resolve the Cloudflare Workers AI URL route identifier for a model name.
pub fn cloudflare_route_model(model: &str) -> String {
    let stripped = model.strip_prefix("cloudflare/").unwrap_or(model);
    match stripped {
        "clef" => "@cf/cloudflare/clef".to_string(),
        "clef-flash" => "@cf/cloudflare/clef-flash".to_string(),
        "clef-omni" => "@cf/cloudflare/clef-omni".to_string(),
        other => other.to_string(),
    }
}

fn valid_cloudflare_account_id(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() <= 128
        && account_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_cloudflare_route(route: &str) -> bool {
    if route.is_empty() || route.starts_with('/') || route.ends_with('/') {
        return false;
    }
    for seg in route.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return false;
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
        {
            return false;
        }
    }
    true
}

/// Build and validate the Cloudflare Workers AI HTTPS endpoint URL for an account and model.
pub fn cloudflare_endpoint(account_id: &str, model: &str) -> Result<String, CallerError> {
    if !valid_cloudflare_account_id(account_id) {
        return Err(CallerError(
            "the Cloudflare account identifier contains invalid characters or is empty".to_string(),
        ));
    }
    if !is_valid_model_name(model) {
        return Err(CallerError(
            "the Cloudflare model identifier is not valid".to_string(),
        ));
    }
    let route = cloudflare_route_model(model);
    if !valid_cloudflare_route(&route) {
        return Err(CallerError(
            "the Cloudflare model route contains disallowed path or query characters".to_string(),
        ));
    }
    Ok(format!(
        "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{route}"
    ))
}

/// Format a canonical PC-26 referral request JSON text into the wire JSON for a provider.
pub fn format_provider_request(
    canonical_request: &str,
    provider: Option<DecisionProvider>,
) -> Result<String, CallerError> {
    let doc = strict_parse(canonical_request)
        .map_err(|err| CallerError(format!("the referral request is not valid JSON, {err}")))?;
    if doc.as_object().is_none() {
        return Err(CallerError(
            "the referral request is not a JSON object".to_string(),
        ));
    }
    let model = match doc.get("model").and_then(Value::as_str) {
        Some(name) if is_valid_model_name(name) => name,
        _ => {
            return Err(CallerError(
                "the referral request carries an invalid model identifier".to_string(),
            ));
        }
    };
    let state = doc
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| CallerError("the referral request carries no state text".to_string()))?;
    let questions = doc.get("questions").ok_or_else(|| {
        CallerError("the referral request carries no questions object".to_string())
    })?;
    if questions.as_object().is_none() {
        return Err(CallerError(
            "the referral request questions field is not an object".to_string(),
        ));
    }
    let verdict = questions.get("verdict").ok_or_else(|| {
        CallerError("the referral request carries no verdict question".to_string())
    })?;
    let verdict_criteria = verdict
        .get("criteria")
        .filter(|v| v.as_object().is_some())
        .ok_or_else(|| {
            CallerError("the referral request verdict criteria is not an object".to_string())
        })?;
    for label in VERDICT_LABELS {
        if verdict_criteria
            .get(label)
            .and_then(Value::as_str)
            .is_none()
        {
            return Err(CallerError(format!(
                "the referral request verdict criteria is missing {label}"
            )));
        }
    }
    let verdict_instructions = verdict
        .get("instructions")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CallerError("the referral request verdict carries no instructions".to_string())
        })?;
    let risk = questions
        .get("risk")
        .ok_or_else(|| CallerError("the referral request carries no risk question".to_string()))?;
    let risk_levels = risk
        .get("criteria")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 10 && items.iter().all(|v| v.as_str().is_some()))
        .ok_or_else(|| {
            CallerError(
                "the referral request risk criteria must hold ten level strings".to_string(),
            )
        })?;
    let risk_instructions = risk
        .get("instructions")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CallerError("the referral request risk carries no instructions".to_string())
        })?;

    let resolved = provider.unwrap_or_else(|| detect_provider(model));
    let wire_model = wire_model_name(resolved, model);
    if wire_model.is_empty() || wire_model.starts_with('/') || wire_model.ends_with('/') {
        return Err(CallerError(
            "the model identifier resolves to an empty provider model name".to_string(),
        ));
    }

    let canonical_verdict_criteria = Value::obj(
        VERDICT_LABELS
            .iter()
            .map(|&label| {
                let text = verdict_criteria.get(label).and_then(Value::as_str).unwrap();
                (label, Value::text(text))
            })
            .collect(),
    );
    let canonical_verdict = Value::obj(vec![
        ("criteria", canonical_verdict_criteria),
        ("instructions", Value::text(verdict_instructions)),
        ("type", Value::text("choice")),
    ]);
    let canonical_risk = Value::obj(vec![
        ("criteria", Value::Array(risk_levels.clone())),
        ("instructions", Value::text(risk_instructions)),
        ("type", Value::text("score")),
    ]);

    let out_doc = match resolved {
        DecisionProvider::TypeSafe
        | DecisionProvider::Perplexity
        | DecisionProvider::Cloudflare => Value::obj(vec![
            ("model", Value::text(&wire_model)),
            (
                "questions",
                Value::obj(vec![
                    ("risk", canonical_risk),
                    ("verdict", canonical_verdict),
                ]),
            ),
            ("state", Value::text(state)),
        ]),
        DecisionProvider::Google => Value::obj(vec![
            ("input", Value::text(state)),
            ("model", Value::text(&wire_model)),
            (
                "questions",
                Value::obj(vec![
                    ("risk", canonical_risk),
                    ("verdict", canonical_verdict),
                ]),
            ),
        ]),
        DecisionProvider::OpenAi => {
            let mut choices = Vec::with_capacity(VERDICT_LABELS.len());
            for label in VERDICT_LABELS {
                let description = verdict_criteria.get(label).and_then(Value::as_str).unwrap();
                choices.push(Value::obj(vec![
                    ("description", Value::text(description)),
                    ("value", Value::text(label)),
                ]));
            }
            let verdict_item = Value::obj(vec![
                ("choices", Value::Array(choices)),
                ("instructions", Value::text(verdict_instructions)),
                ("name", Value::text("verdict")),
                ("type", Value::text("choice")),
            ]);
            let mut levels = Vec::with_capacity(risk_levels.len());
            for (index, item) in risk_levels.iter().enumerate() {
                let description = item.as_str().unwrap_or("");
                levels.push(Value::obj(vec![
                    ("description", Value::text(description)),
                    ("label", Value::text(&index.to_string())),
                ]));
            }
            let risk_item = Value::obj(vec![
                ("instructions", Value::text(risk_instructions)),
                ("levels", Value::Array(levels)),
                ("name", Value::text("risk")),
                ("type", Value::text("score")),
            ]);
            Value::obj(vec![
                ("input", Value::text(state)),
                ("model", Value::text(&wire_model)),
                ("questions", Value::Array(vec![verdict_item, risk_item])),
            ])
        }
    };

    Ok(String::from_utf8(canonical(&out_doc)).expect("canonical JSON is UTF-8"))
}

fn extract_named_items<'a>(items: &'a [Value], target: &str) -> Result<Option<&'a Value>, ()> {
    let mut found: Option<&'a Value> = None;
    for item in items {
        let Some(_) = item.as_object() else {
            return Err(());
        };
        if item.get("name").and_then(Value::as_str) == Some(target) {
            if found.is_some() {
                return Err(());
            }
            found = Some(item);
        }
    }
    Ok(found)
}

fn parse_level_index(item: &Value) -> Option<usize> {
    let val_opt = match item.get("value") {
        None => None,
        Some(v) => {
            let num = number_f64(v)?;
            if num.fract() != 0.0 || !(0.0..=9.0).contains(&num) {
                return None;
            }
            Some(num as usize)
        }
    };
    let lbl_opt = match item.get("label") {
        None => None,
        Some(Value::Str(s)) => {
            let idx = s.parse::<usize>().ok()?;
            if idx >= 10 || s != &idx.to_string() {
                return None;
            }
            Some(idx)
        }
        Some(_) => return None,
    };
    match (val_opt, lbl_opt) {
        (Some(v), Some(l)) if v == l => Some(v),
        (Some(_), Some(_)) => None,
        (Some(v), None) => Some(v),
        (None, Some(l)) => Some(l),
        (None, None) => None,
    }
}

fn weighted_level_score(probs: &Value) -> Option<f64> {
    if let Some(items) = probs.as_array() {
        if items.len() != 10 {
            return None;
        }
        let mut weighted = 0.0;
        let mut total = 0.0;
        if items[0].as_object().is_some() {
            let mut seen = [false; 10];
            for item in items {
                item.as_object()?;
                let lvl = parse_level_index(item)?;
                if seen[lvl] {
                    return None;
                }
                seen[lvl] = true;
                let p = item.get("probability").and_then(number_f64)?;
                if !(0.0..=1.0).contains(&p) {
                    return None;
                }
                weighted += (lvl as f64) * p;
                total += p;
            }
        } else {
            for (index, item) in items.iter().enumerate() {
                if item.as_object().is_some() {
                    return None;
                }
                let p = number_f64(item)?;
                if !(0.0..=1.0).contains(&p) {
                    return None;
                }
                weighted += (index as f64) * p;
                total += p;
            }
        }
        return if (0.99..=1.01).contains(&total) {
            Some((weighted / total).clamp(0.0, 9.0))
        } else {
            None
        };
    }
    if let Some(pairs) = probs.as_object() {
        if pairs.len() != 10 {
            return None;
        }
        let mut weighted = 0.0;
        let mut total = 0.0;
        for index in 0..10usize {
            let key = index.to_string();
            let item = probs.get(&key)?;
            let p = number_f64(item)?;
            if !(0.0..=1.0).contains(&p) {
                return None;
            }
            weighted += (index as f64) * p;
            total += p;
        }
        return if (0.99..=1.01).contains(&total) {
            Some((weighted / total).clamp(0.0, 9.0))
        } else {
            None
        };
    }
    None
}

fn sanitize_scalar(value: &Value) -> Value {
    match value {
        Value::Float(n) if !n.is_finite() => Value::Float(2.0),
        Value::Array(_) | Value::Object(_) => Value::text("non-scalar"),
        other => other.clone(),
    }
}

fn normalize_choice_probabilities(raw: &Value) -> Value {
    if let Some(items) = raw.as_array() {
        let mut pairs: Vec<(String, Value)> = Vec::with_capacity(items.len());
        for item in items {
            let Some(_) = item.as_object() else {
                return Value::text("malformed-probabilities");
            };
            let label = item
                .get("value")
                .and_then(Value::as_str)
                .or_else(|| item.get("label").and_then(Value::as_str));
            let Some(label) = label else {
                return Value::text("malformed-probabilities");
            };
            if pairs.iter().any(|(existing, _)| existing == label) {
                return Value::text("duplicate-probability-label");
            }
            let Some(prob_val) = item.get("probability") else {
                return Value::text("malformed-probabilities");
            };
            pairs.push((label.to_string(), sanitize_scalar(prob_val)));
        }
        return Value::Object(pairs);
    }
    if let Some(pairs) = raw.as_object() {
        let sanitized: Vec<(String, Value)> = pairs
            .iter()
            .map(|(k, v)| (k.clone(), sanitize_scalar(v)))
            .collect();
        return Value::Object(sanitized);
    }
    sanitize_scalar(raw)
}

fn normalize_verdict_entry(entry: &Value) -> Value {
    if entry.as_object().is_none() {
        return sanitize_scalar(entry);
    }
    let choice_val = entry
        .get("choice")
        .or_else(|| entry.get("selected"))
        .map(sanitize_scalar)
        .unwrap_or(Value::Null);
    let probs_val = entry
        .get("probabilities")
        .or_else(|| entry.get("distribution"))
        .map(normalize_choice_probabilities)
        .unwrap_or(Value::Null);
    Value::obj(vec![
        ("choice", choice_val),
        ("probabilities", probs_val),
        ("type", Value::text("choice")),
    ])
}

fn normalize_risk_entry(entry: &Value) -> Option<Value> {
    entry.as_object()?;
    let mut raw_score: Option<f64> = None;
    for key in ["score", "expected_score", "expected"] {
        if let Some(val) = entry.get(key) {
            if *val == Value::Null {
                continue;
            }
            let num = number_f64(val)?;
            if !(0.0..=9.0).contains(&num) {
                return None;
            }
            raw_score = Some(num);
            break;
        }
    }
    let resolved = match raw_score {
        Some(score) => score,
        None => entry
            .get("probabilities")
            .or_else(|| entry.get("distribution"))
            .and_then(weighted_level_score)?,
    };
    Some(Value::obj(vec![
        ("probabilities", Value::Object(Vec::new())),
        ("score", Value::Float(resolved)),
        ("type", Value::text("score")),
    ]))
}

/// Normalize a raw System One provider response JSON text into a canonical PC-26 reply JSON text.
pub fn normalize_provider_reply(
    raw_reply: &str,
    provider: Option<DecisionProvider>,
    pinned_model: Option<&str>,
) -> Result<String, CallerError> {
    if let Some(name) = pinned_model {
        if !is_valid_model_name(name) {
            return Err(CallerError(
                "the pinned model identifier is outside the valid ASCII shape".to_string(),
            ));
        }
    }
    if raw_reply.trim().is_empty() {
        return Ok(String::new());
    }
    let root = strict_parse(raw_reply)
        .map_err(|err| CallerError(format!("the provider reply is not valid JSON, {err}")))?;
    if root.as_object().is_none() {
        let fallback_model = pinned_model.unwrap_or(DEFAULT_JUDGE_MODEL);
        let silence = Value::obj(vec![
            ("answers", Value::int(0)),
            ("model", Value::text(fallback_model)),
        ]);
        return Ok(String::from_utf8(canonical(&silence)).unwrap());
    }

    let root_model = root.get("model").and_then(Value::as_str);
    let effective_provider = provider.or_else(|| {
        pinned_model
            .or(root_model)
            .filter(|m| is_valid_model_name(m))
            .map(detect_provider)
    });

    if let Some(success_val) = root.get("success") {
        if *success_val != Value::Bool(true) {
            return Err(CallerError(
                "the provider envelope reported an unsuccessful call".to_string(),
            ));
        }
        if root.get("result").and_then(Value::as_object).is_none() {
            return Err(CallerError(
                "the provider envelope carries no result object".to_string(),
            ));
        }
    }
    let payload = if root.get("success") == Some(&Value::Bool(true)) {
        root.get("result").expect("result object verified above")
    } else if effective_provider == Some(DecisionProvider::Cloudflare) {
        match root.get("result") {
            Some(result) if result.as_object().is_some() => result,
            Some(_) => {
                return Err(CallerError(
                    "the provider envelope carries a non-object result".to_string(),
                ));
            }
            None => &root,
        }
    } else {
        &root
    };

    let out_model = match pinned_model {
        Some(name) => name.to_string(),
        None => payload
            .get("model")
            .and_then(Value::as_str)
            .or(root_model)
            .filter(|name| is_valid_model_name(name))
            .unwrap_or(DEFAULT_JUDGE_MODEL)
            .to_string(),
    };

    let container = payload
        .get("answers")
        .or_else(|| payload.get("decisions"))
        .or_else(|| payload.get("output"));

    let Some(container) = container else {
        let silence = Value::obj(vec![
            ("answers", Value::Object(Vec::new())),
            ("model", Value::text(&out_model)),
        ]);
        return Ok(String::from_utf8(canonical(&silence)).unwrap());
    };

    let (verdict_opt, risk_opt, malformed_verdict) = if container.as_object().is_some() {
        (
            container.get("verdict"),
            container.get("risk").or_else(|| container.get("score")),
            false,
        )
    } else if let Some(items) = container.as_array() {
        let risk_res = match (
            extract_named_items(items, "risk"),
            extract_named_items(items, "score"),
        ) {
            (Err(()), _) | (_, Err(())) => None,
            (Ok(Some(_)), Ok(Some(_))) => None,
            (Ok(Some(r)), Ok(None)) => Some(r),
            (Ok(None), Ok(Some(s))) => Some(s),
            (Ok(None), Ok(None)) => None,
        };
        match extract_named_items(items, "verdict") {
            Ok(v) => (v, risk_res, false),
            Err(()) => (None, risk_res, true),
        }
    } else {
        let silence = Value::obj(vec![
            ("answers", Value::int(0)),
            ("model", Value::text(&out_model)),
        ]);
        return Ok(String::from_utf8(canonical(&silence)).unwrap());
    };

    let mut answers_pairs: Vec<(&str, Value)> = Vec::new();
    if let Some(risk_raw) = risk_opt {
        if let Some(risk_norm) = normalize_risk_entry(risk_raw) {
            answers_pairs.push(("risk", risk_norm));
        }
    }
    if malformed_verdict {
        answers_pairs.push(("verdict", Value::text("malformed")));
    } else if let Some(verdict_raw) = verdict_opt {
        answers_pairs.push(("verdict", normalize_verdict_entry(verdict_raw)));
    }

    let normalized = Value::obj(vec![
        ("answers", Value::obj(answers_pairs)),
        ("model", Value::text(&out_model)),
    ]);
    Ok(String::from_utf8(canonical(&normalized)).unwrap())
}
