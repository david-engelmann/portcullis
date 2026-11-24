//! The call validator, checking a call document against its schema.

use crate::errors::MalformedCall;
use crate::value::Value;
use crate::{CALL_FORMAT, FILE_OPERATIONS, INTERPRETERS, PORT_MAX, PORT_MIN};

pub(crate) fn check_keys(
    document: &Value,
    allowed: &[&str],
    required: &[&str],
    what: &str,
) -> Result<(), String> {
    let pairs = document.as_object().expect("an object document");
    let mut unknown: Vec<&str> = pairs
        .iter()
        .map(|(key, _)| key.as_str())
        .filter(|key| !allowed.contains(key))
        .collect();
    unknown.sort();
    unknown.dedup();
    if !unknown.is_empty() {
        return Err(format!("{what} carries the unknown field {}", unknown[0]));
    }
    let mut missing: Vec<&str> = required
        .iter()
        .filter(|key| !pairs.iter().any(|(present, _)| present == *key))
        .copied()
        .collect();
    missing.sort();
    if !missing.is_empty() {
        return Err(format!("{what} is missing the field {}", missing[0]));
    }
    Ok(())
}

pub(crate) fn valid_port(value: &Value) -> bool {
    match value.int_i64() {
        Some(port) => (PORT_MIN..=PORT_MAX).contains(&port),
        None => false,
    }
}

pub(crate) fn is_text(value: &Value) -> bool {
    matches!(value, Value::Str(_))
}

// --- call validation -------------------------------------------------------

pub(crate) fn argv_form_ok(argv: &Value) -> bool {
    match argv.as_array() {
        Some(items) => !items.is_empty() && items.iter().all(is_text),
        None => false,
    }
}

fn validate_shell(document: &Value) -> Result<Value, MalformedCall> {
    check_keys(
        document,
        &["format", "kind", "argv", "cwd"],
        &["format", "kind", "argv"],
        "a shell call",
    )
    .map_err(MalformedCall)?;
    let argv = document.get("argv").unwrap();
    if !argv_form_ok(argv) {
        return Err(MalformedCall(
            "a shell call carries an argv of one or more strings".to_string(),
        ));
    }
    if let Some(cwd) = document.get("cwd") {
        if !is_text(cwd) {
            return Err(MalformedCall(
                "a shell call carries a cwd that is not a string".to_string(),
            ));
        }
    }
    Ok(document.clone())
}

fn validate_file(document: &Value) -> Result<Value, MalformedCall> {
    check_keys(
        document,
        &["format", "kind", "operation", "path", "path2"],
        &["format", "kind", "operation", "path"],
        "a file call",
    )
    .map_err(MalformedCall)?;
    let operation = document.get("operation").unwrap();
    if !matches!(operation, Value::Str(op) if FILE_OPERATIONS.contains(&op.as_str())) {
        return Err(MalformedCall(
            "a file call names an operation outside the set".to_string(),
        ));
    }
    let path = document.get("path").unwrap();
    if !is_text(path) || path.as_str() == Some("") {
        return Err(MalformedCall(
            "a file call carries a path of no use".to_string(),
        ));
    }
    if operation.as_str() == Some("move") {
        match document.get("path2") {
            None => {
                return Err(MalformedCall(
                    "a move call carries no second path".to_string(),
                ));
            }
            Some(path2) => {
                if !is_text(path2) || path2.as_str() == Some("") {
                    return Err(MalformedCall(
                        "a move call carries a second path of no use".to_string(),
                    ));
                }
            }
        }
    } else if document.get("path2").is_some() {
        return Err(MalformedCall(
            "a file call that is not a move carries a second path".to_string(),
        ));
    }
    Ok(document.clone())
}

fn validate_network(document: &Value) -> Result<Value, MalformedCall> {
    check_keys(
        document,
        &["format", "kind", "method", "host", "port", "url"],
        &["format", "kind", "method"],
        "a network call",
    )
    .map_err(MalformedCall)?;
    let method = document.get("method").unwrap();
    if !is_text(method) || method.as_str() == Some("") {
        return Err(MalformedCall(
            "a network call carries a method of no use".to_string(),
        ));
    }
    let has_url = document.get("url").is_some();
    let has_host = document.get("host").is_some();
    let has_port = document.get("port").is_some();
    if has_url && (has_host || has_port) {
        return Err(MalformedCall(
            "a network call carries both a url and a host or port".to_string(),
        ));
    }
    if has_url {
        return network_from_url(document);
    }
    if !(has_host && has_port) {
        return Err(MalformedCall(
            "a network call carries neither a url nor a host and port".to_string(),
        ));
    }
    let host = document.get("host").unwrap();
    if !is_text(host) || host.as_str() == Some("") {
        return Err(MalformedCall(
            "a network call carries a host of no use".to_string(),
        ));
    }
    if !valid_port(document.get("port").unwrap()) {
        return Err(MalformedCall(
            "a network call carries a port outside its range".to_string(),
        ));
    }
    let mut result = document.clone();
    if let Value::Object(pairs) = &mut result {
        for (key, value) in pairs.iter_mut() {
            if key == "host" {
                if let Value::Str(text) = value {
                    *text = text.to_lowercase();
                }
            }
        }
    }
    Ok(result)
}

struct ParsedUrl {
    scheme: String,
    username: Option<String>,
    password: Option<String>,
    hostname: Option<String>,
    port: Result<Option<i64>, ()>,
}

/// The subset of the standard URL split the gate depends on,
/// following the Python urlparse behaviour. The scheme is folded
/// to lowercase, the hostname is folded to lowercase, userinfo is
/// reported as its own fields, and a port the URL carries is
/// judged when it is read, as the Python port property judges it.
fn parse_url(raw: &str) -> Result<ParsedUrl, ()> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let url = cleaned.trim_start_matches(|c: char| (c as u32) <= 0x20);
    let bytes = url.as_bytes();
    let mut scheme = String::new();
    if !bytes.is_empty() && bytes[0].is_ascii_alphabetic() {
        let mut index = 1;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'+' | b'-' | b'.'))
        {
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b':' {
            scheme = url[..index].to_lowercase();
        }
    }
    let after_scheme = if scheme.is_empty() {
        url
    } else {
        &url[scheme.len() + 1..]
    };
    let mut netloc = "";
    if let Some(rest) = after_scheme.strip_prefix("//") {
        let end = rest
            .find(|c| ['/', '?', '#'].contains(&c))
            .unwrap_or(rest.len());
        netloc = &rest[..end];
    }
    let (userinfo, hostinfo) = match netloc.rfind('@') {
        Some(at) => (Some(&netloc[..at]), &netloc[at + 1..]),
        None => (None, netloc),
    };
    let (username, password) = match userinfo {
        Some(info) => match info.split_once(':') {
            Some((user, pass)) => (Some(user.to_string()), Some(pass.to_string())),
            None => (Some(info.to_string()), None),
        },
        None => (None, None),
    };
    let (hostname_raw, port_text) = split_hostinfo(hostinfo)?;
    let hostname = hostname_raw
        .filter(|host| !host.is_empty())
        .map(|host| host.to_lowercase());
    let port = match port_text {
        None => Ok(None),
        Some(text) => {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                Err(())
            } else {
                match text.parse::<i64>() {
                    Ok(value) if (0..=65535).contains(&value) => Ok(Some(value)),
                    _ => Err(()),
                }
            }
        }
    };
    Ok(ParsedUrl {
        scheme,
        username,
        password,
        hostname,
        port,
    })
}

fn split_hostinfo(hostinfo: &str) -> Result<(Option<&str>, Option<&str>), ()> {
    if let Some(after_open) = hostinfo.strip_prefix('[') {
        match after_open.find(']') {
            Some(close) => {
                let host = &after_open[..close];
                let rest = &after_open[close + 1..];
                if !rest.is_empty() && !rest.starts_with(':') {
                    return Err(());
                }
                let port = rest.strip_prefix(':').filter(|text| !text.is_empty());
                Ok((Some(host), port))
            }
            None => Err(()),
        }
    } else {
        if hostinfo.contains('[') || hostinfo.contains(']') {
            return Err(());
        }
        match hostinfo.split_once(':') {
            Some((host, port)) => Ok((Some(host), if port.is_empty() { None } else { Some(port) })),
            None => Ok((Some(hostinfo), None)),
        }
    }
}

fn network_from_url(document: &Value) -> Result<Value, MalformedCall> {
    let url = document.get("url").unwrap();
    if !is_text(url) {
        return Err(MalformedCall(
            "a network call carries a url that is not a string".to_string(),
        ));
    }
    let does_not_parse =
        || MalformedCall("a network call carries a url that does not parse".to_string());
    let parsed = parse_url(url.as_str().unwrap()).map_err(|()| does_not_parse())?;
    let port = parsed.port.map_err(|()| does_not_parse())?;
    if parsed.username.is_some() || parsed.password.is_some() {
        return Err(MalformedCall(
            "a network call carries a url holding userinfo".to_string(),
        ));
    }
    let host = match parsed.hostname {
        Some(host) => host,
        None => {
            return Err(MalformedCall(
                "a network call carries a url with no host".to_string(),
            ));
        }
    };
    let port = match port {
        Some(port) => Some(port),
        None => match parsed.scheme.as_str() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        },
    };
    let port = match port {
        Some(port) if (PORT_MIN..=PORT_MAX).contains(&port) => port,
        _ => {
            return Err(MalformedCall(
                "a network call carries a url with no usable port".to_string(),
            ));
        }
    };
    Ok(Value::obj(vec![
        ("format", document.get("format").unwrap().clone()),
        ("kind", Value::text("network")),
        ("method", document.get("method").unwrap().clone()),
        ("host", Value::Str(host)),
        ("port", Value::int(port)),
    ]))
}

/// Validate a parsed call document or raise MalformedCall.
///
/// The returned call is normalized, so a network call given by
/// url comes back in the explicit method and host and port form
/// and a host always stands folded to lowercase.
pub fn validate_call(document: &Value) -> Result<Value, MalformedCall> {
    if document.as_object().is_none() {
        return Err(MalformedCall("a call is not a JSON object".to_string()));
    }
    check_keys(
        document,
        &[
            "format",
            "kind",
            "argv",
            "cwd",
            "operation",
            "path",
            "path2",
            "method",
            "host",
            "port",
            "url",
        ],
        &["format", "kind"],
        "a call",
    )
    .map_err(MalformedCall)?;
    if document.get("format").unwrap() != &Value::text(CALL_FORMAT) {
        return Err(MalformedCall(
            "a call names a format this gate does not read".to_string(),
        ));
    }
    match document.get("kind").unwrap().as_str() {
        Some("shell") => validate_shell(document),
        Some("file") => validate_file(document),
        Some("network") => validate_network(document),
        _ => Err(MalformedCall(
            "a call names a kind this gate does not judge".to_string(),
        )),
    }
}

/// Whether a validated call runs a shell interpreter.
pub fn is_interpreter_call(call: &Value) -> bool {
    if call.get("kind").and_then(|v| v.as_str()) != Some("shell") {
        return false;
    }
    let argv = match call.get("argv").and_then(|v| v.as_array()) {
        Some(argv) => argv,
        None => return false,
    };
    let first = match argv.first().and_then(|v| v.as_str()) {
        Some(first) => first,
        None => return false,
    };
    let basename = first.rsplit('/').next().unwrap_or(first);
    INTERPRETERS.contains(&basename)
}

// --- policy loading ---------------------------------------------------------
