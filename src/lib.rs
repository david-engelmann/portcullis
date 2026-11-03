//! Core logic for portcullis, the tool call gate.
//!
//! One policy document and one call document go in and one
//! decision record comes out. The decision is reached in the
//! order the contract states. Schema validation first, then the
//! deny rules in policy order, then the allow and rewrite rules
//! in policy order, then the declared default. The gate never
//! executes a call and never touches the filesystem at a path a
//! call names. Its only write is the audit log append, and that
//! append is part of delivering a decision.
//!
//! Time is an input. The caller passes the instant a decision is
//! given at, and this module reads no wall clock for the decision
//! itself.
//!
//! Documents are held in a small hand written value model rather
//! than a general JSON library, for three reasons the gate report
//! records. A duplicated key must be refused as the document is
//! read, at every level, and a reader that keeps the last value
//! of a repeated key cannot carry that. An integer is held as its
//! canonical decimal text, so a literal of any width is judged by
//! the same bounds the Python reader judged, including its 4300
//! digit parse limit, and a boolean is never an integer and a
//! float is never an integer. And the canonical writer must
//! reproduce the byte layout of the Python canonical form, keys
//! sorted, no spaces, UTF-8 without ASCII escaping, floats
//! rendered as the Python repr renders them, because decision
//! digests and audit log lines are those bytes.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use fs2::FileExt;
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub const CALL_FORMAT: &str = "portcullis-call/1";
pub const POLICY_FORMAT: &str = "portcullis-policy/1";
pub const DECISION_FORMAT: &str = "portcullis-decision/1";

const KINDS: [&str; 3] = ["shell", "file", "network"];
const FILE_OPERATIONS: [&str; 5] = ["read", "write", "delete", "move", "list"];
const ACTIONS: [&str; 3] = ["allow", "deny", "rewrite"];
const DEFAULTS: [&str; 2] = ["allow", "deny"];
const MATCHER_KEYS: [&str; 3] = ["exact", "prefix", "glob"];
const INTERPRETERS: [&str; 9] = [
    "sh", "bash", "dash", "ash", "zsh", "ksh", "csh", "tcsh", "fish",
];
const PORT_MIN: i64 = 1;
const PORT_MAX: i64 = 65535;
const INT_DIGIT_LIMIT: usize = 4300;
const MAX_DEPTH: usize = 1000;

/// Input to the tool is bad and no decision is made for it.
#[derive(Debug)]
pub struct CallerError(pub String);

/// The policy cannot be loaded and the gate must fail closed.
#[derive(Debug)]
pub struct PolicyError(pub String);

/// A parsed call document fails schema validation.
#[derive(Debug)]
pub struct MalformedCall(pub String);

/// A decision could not be appended to the audit log.
#[derive(Debug)]
pub struct LogAppendError(pub String);

/// A line of the audit log fails to parse or to validate.
#[derive(Debug)]
pub struct LogCorruptionError {
    pub line_number: usize,
    pub detail: String,
}

impl std::fmt::Display for CallerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for MalformedCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for LogAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for LogCorruptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}, {}", self.line_number, self.detail)
    }
}

/// A failure of the log command, either a caller error or
/// corruption at a named line.
#[derive(Debug)]
pub enum LogReadError {
    Caller(CallerError),
    Corruption(LogCorruptionError),
}

// --- the document model ------------------------------------------------

/// One JSON document. An integer is held as its canonical
/// decimal text, so a literal of any width keeps the value the
/// Python reader held and the bounds checks judge the same
/// numbers. Object entries keep their document order here, and
/// the canonical writer sorts the keys when it writes.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Object(
            pairs
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        )
    }

    pub fn text(value: &str) -> Value {
        Value::Str(value.to_string())
    }

    pub fn int(value: i64) -> Value {
        Value::Int(value.to_string())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Object(pairs) => Some(pairs),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    fn is_int(&self) -> bool {
        matches!(self, Value::Int(_))
    }

    /// The value of an integer held at i64 width, or None when
    /// the text stands outside that width, in which case every
    /// bounded check in this crate judges it out of range.
    fn int_i64(&self) -> Option<i64> {
        match self {
            Value::Int(text) => text.parse::<i64>().ok(),
            _ => None,
        }
    }

    /// The value of an integer as an argument position, saturated
    /// at the width of the machine word, because a position only
    /// ever compares against the length of an argv.
    fn int_usize_saturated(&self) -> Option<usize> {
        match self {
            Value::Int(text) => Some(parse_usize_saturated(text)),
            _ => None,
        }
    }
}

fn parse_usize_saturated(text: &str) -> usize {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if negative {
        return 0;
    }
    let mut value: usize = 0;
    for byte in digits.bytes() {
        let digit = (byte - b'0') as usize;
        value = value.saturating_mul(10).saturating_add(digit);
    }
    value
}

// --- the strict reader ---------------------------------------------------

/// Parse one JSON document strictly or raise an error.
///
/// A duplicated key at any level, the non standard constants,
/// trailing data, and nesting past the depth bound are all
/// refused, so a document this function returns is the whole
/// input and nothing in it was silently overwritten or extended.
/// A string holding an unpaired surrogate escape is refused with
/// the text the Python reader produced for it, so a document
/// whose strings are not encodable text does not parse.
pub fn strict_parse(text: &str) -> Result<Value, String> {
    let mut parser = Parser {
        chars: text.chars().collect(),
        pos: 0,
    };
    parser.skip_whitespace();
    let document = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.pos != parser.chars.len() {
        return Err("trailing data after the document".to_string());
    }
    Ok(document)
}

const NOT_ENCODABLE: &str = "the document carries a string that is not encodable text";

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err("the document nests too deeply to parse".to_string());
        }
        match self.peek() {
            Some('{') => self.parse_object(depth),
            Some('[') => self.parse_array(depth),
            Some('"') => Ok(Value::Str(self.parse_string()?)),
            Some('t') => self.parse_literal("true", Value::Bool(true)),
            Some('f') => self.parse_literal("false", Value::Bool(false)),
            Some('n') => self.parse_literal("null", Value::Null),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err("the document does not parse".to_string()),
        }
    }

    fn parse_literal(&mut self, word: &str, value: Value) -> Result<Value, String> {
        for expected in word.chars() {
            if self.peek() != Some(expected) {
                return Err("the document does not parse".to_string());
            }
            self.pos += 1;
        }
        Ok(value)
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, String> {
        self.pos += 1;
        let mut pairs: Vec<(String, Value)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(Value::Object(pairs));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some('"') {
                return Err("the document does not parse".to_string());
            }
            let key = self.parse_string()?;
            if !seen.insert(key.clone()) {
                return Err(format!("a key stands twice in the document, {key}"));
            }
            self.skip_whitespace();
            if self.peek() != Some(':') {
                return Err("the document does not parse".to_string());
            }
            self.pos += 1;
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            pairs.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some('}') => {
                    self.pos += 1;
                    return Ok(Value::Object(pairs));
                }
                _ => return Err("the document does not parse".to_string()),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            items.push(value);
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some(']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err("the document does not parse".to_string()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return Err("the document does not parse".to_string()),
            };
            self.pos += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let escape = match self.peek() {
                        Some(c) => c,
                        None => return Err("the document does not parse".to_string()),
                    };
                    self.pos += 1;
                    match escape {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let unit = self.parse_hex4()?;
                            if (0xD800..0xDC00).contains(&unit) {
                                if self.peek() == Some('\\')
                                    && self.chars.get(self.pos + 1) == Some(&'u')
                                {
                                    self.pos += 2;
                                    let low = self.parse_hex4()?;
                                    if (0xDC00..0xE000).contains(&low) {
                                        let combined =
                                            0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                                        out.push(
                                            char::from_u32(combined)
                                                .ok_or("the document does not parse")?,
                                        );
                                    } else {
                                        return Err(NOT_ENCODABLE.to_string());
                                    }
                                } else {
                                    return Err(NOT_ENCODABLE.to_string());
                                }
                            } else if (0xDC00..0xE000).contains(&unit) {
                                return Err(NOT_ENCODABLE.to_string());
                            } else {
                                out.push(
                                    char::from_u32(unit).ok_or("the document does not parse")?,
                                );
                            }
                        }
                        _ => return Err("the document does not parse".to_string()),
                    }
                }
                c if (c as u32) < 0x20 => {
                    return Err("the document does not parse".to_string());
                }
                c => out.push(c),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let c = match self.peek() {
                Some(c) => c,
                None => return Err("the document does not parse".to_string()),
            };
            let digit = match c.to_digit(16) {
                Some(d) => d,
                None => return Err("the document does not parse".to_string()),
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        match self.peek() {
            Some('0') => {
                self.pos += 1;
            }
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err("the document does not parse".to_string()),
        }
        let mut is_float = false;
        if self.peek() == Some('.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err("the document does not parse".to_string());
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err("the document does not parse".to_string());
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let literal: String = self.chars[start..self.pos].iter().collect();
        if is_float {
            let value: f64 = literal
                .parse()
                .map_err(|_| "the document does not parse".to_string())?;
            Ok(Value::Float(value))
        } else {
            let digits = literal.trim_start_matches('-');
            if digits.len() > INT_DIGIT_LIMIT {
                return Err("the document carries an integer too wide to parse".to_string());
            }
            let normalized = if literal == "-0" { "0" } else { &literal };
            Ok(Value::Int(normalized.to_string()))
        }
    }
}

// --- the canonical form --------------------------------------------------

/// The canonical form of a JSON document as UTF-8 bytes, keys
/// sorted, no spaces, and the text encoded as UTF-8 without
/// ASCII escaping, the form the Python writer produces.
pub fn canonical(document: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_canonical(document, &mut out);
    out.into_bytes()
}

fn write_canonical(document: &Value, out: &mut String) {
    match document {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(text) => out.push_str(text),
        Value::Float(value) => out.push_str(&python_float_text(*value)),
        Value::Str(text) => write_json_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(pairs) => {
            let mut sorted: Vec<&(String, Value)> = pairs.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (index, (key, value)) in sorted.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical(value, out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Render a float the way the Python repr renders it, the
/// shortest text that round trips, in fixed notation while the
/// decimal exponent stands between minus four and fifteen and
/// in exponent notation outside that range, with the word the
/// Python writer uses for an unbounded value.
fn python_float_text(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }
    let negative = value < 0.0;
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent_text) = scientific.split_once('e').unwrap();
    let exponent: i32 = exponent_text.parse().unwrap();
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let body = if (-4..16).contains(&exponent) {
        if exponent >= 0 {
            let split = (exponent + 1) as usize;
            if digits.len() <= split {
                let mut text = digits.clone();
                while text.len() < split {
                    text.push('0');
                }
                text.push_str(".0");
                text
            } else {
                format!("{}.{}", &digits[..split], &digits[split..])
            }
        } else {
            let mut text = "0.".to_string();
            for _ in 0..(-exponent - 1) {
                text.push('0');
            }
            text.push_str(&digits);
            text
        }
    } else {
        let mantissa_text = if digits.len() == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!(
            "{}e{}{:02}",
            mantissa_text,
            if exponent < 0 { "-" } else { "+" },
            exponent.abs()
        )
    };
    if negative {
        format!("-{body}")
    } else {
        body
    }
}

/// The recorded digest of a parsed call document.
pub fn call_digest(document: &Value) -> String {
    let digest = Sha256::digest(canonical(document));
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

// --- shared validation helpers --------------------------------------------

fn check_keys(
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

fn valid_port(value: &Value) -> bool {
    match value.int_i64() {
        Some(port) => (PORT_MIN..=PORT_MAX).contains(&port),
        None => false,
    }
}

fn is_text(value: &Value) -> bool {
    matches!(value, Value::Str(_))
}

// --- call validation -------------------------------------------------------

fn validate_shell(document: &Value) -> Result<Value, MalformedCall> {
    check_keys(
        document,
        &["format", "kind", "argv", "cwd"],
        &["format", "kind", "argv"],
        "a shell call",
    )
    .map_err(MalformedCall)?;
    let argv = document.get("argv").unwrap();
    let argv_ok = match argv.as_array() {
        Some(items) => !items.is_empty() && items.iter().all(is_text),
        None => false,
    };
    if !argv_ok {
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
        Some(text) => match text.parse::<i64>() {
            Ok(value) if (0..=65535).contains(&value) => Ok(Some(value)),
            _ => Err(()),
        },
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
    let parsed = match parse_url(url.as_str().unwrap()) {
        Ok(parsed) => parsed,
        Err(()) => {
            return Err(MalformedCall(
                "a network call carries a url that does not parse".to_string(),
            ));
        }
    };
    let port = match parsed.port {
        Ok(port) => port,
        Err(()) => {
            return Err(MalformedCall(
                "a network call carries a url that does not parse".to_string(),
            ));
        }
    };
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

/// A policy that loaded whole, with its declared default.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub default: String,
    pub rules: Vec<Rule>,
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
        Some(pairs) => pairs,
        None => {
            return Err(PolicyError(format!(
                "{what} is not a port matcher holding one exact port"
            )));
        }
    };
    if pairs.len() != 1 || pairs[0].0 != "exact" {
        return Err(PolicyError(format!(
            "{what} is not a port matcher holding one exact port"
        )));
    }
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
        let index_value = index.int_usize_saturated();
        if !index.is_int() || index_value == Some(0) {
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
                let argv_ok = match argv.as_array() {
                    Some(items) => !items.is_empty() && items.iter().all(is_text),
                    None => false,
                };
                if !argv_ok {
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

/// Validate a parsed policy document or raise PolicyError.
///
/// Validation of every rule happens here, so a policy object
/// that comes back is wholly usable and a policy with any
/// invalid part never produces one.
pub fn load_policy(document: &Value) -> Result<Policy, PolicyError> {
    if document.as_object().is_none() {
        return Err(PolicyError("the policy is not a JSON object".to_string()));
    }
    check_policy_keys(document, &["format", "default", "rules"], "the policy")?;
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
    Ok(Policy {
        default: default.as_str().unwrap().to_string(),
        rules,
    })
}

// --- matching and evaluation --------------------------------------------------

/// Lexical path normalization with no filesystem access, the
/// posixpath.normpath behaviour, resolving dot segments exactly
/// as that function resolves them.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let mut initial_slashes = usize::from(path.starts_with('/'));
    if initial_slashes == 1 && path.starts_with("//") && !path.starts_with("///") {
        initial_slashes = 2;
    }
    let mut new_comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".."
            || (initial_slashes == 0 && new_comps.is_empty())
            || new_comps.last() == Some(&"..")
        {
            new_comps.push(comp);
        } else if !new_comps.is_empty() {
            new_comps.pop();
        }
    }
    let joined = new_comps.join("/");
    let result = if initial_slashes > 0 {
        format!("{}{}", "/".repeat(initial_slashes), joined)
    } else {
        joined
    };
    if result.is_empty() {
        ".".to_string()
    } else {
        result
    }
}

/// Case sensitive glob matching in which the star crosses path
/// separators, the fnmatch.fnmatchcase behaviour. The pattern
/// language is a star for any run of characters, a question mark
/// for exactly one character, and a bracket class holding single
/// characters and ranges, negated by a leading exclamation mark.
/// A backslash is an ordinary character.
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    match pattern[0] {
        '*' => {
            for skip in 0..=text.len() {
                if glob_match(&pattern[1..], &text[skip..]) {
                    return true;
                }
            }
            false
        }
        '?' => !text.is_empty() && glob_match(&pattern[1..], &text[1..]),
        '[' => match parse_class(pattern) {
            Some((negated, items, rest)) => {
                if text.is_empty() {
                    return false;
                }
                let c = text[0];
                let inside = items.iter().any(|item| match item {
                    ClassItem::Single(member) => *member == c,
                    ClassItem::Range(lo, hi) => *lo <= c && c <= *hi,
                });
                (inside != negated) && glob_match(rest, &text[1..])
            }
            None => !text.is_empty() && text[0] == '[' && glob_match(&pattern[1..], &text[1..]),
        },
        first => !text.is_empty() && text[0] == first && glob_match(&pattern[1..], &text[1..]),
    }
}

enum ClassItem {
    Single(char),
    Range(char, char),
}

/// Parse a bracket class at the head of a pattern, returning its
/// negation, its members, and the pattern past the closing
/// bracket, or None when the bracket never closes and stands as
/// a literal character, as the glob translator reads it.
fn parse_class(pattern: &[char]) -> Option<(bool, Vec<ClassItem>, &[char])> {
    let mut index = 1;
    let mut negated = false;
    if index < pattern.len() && pattern[index] == '!' {
        negated = true;
        index += 1;
    }
    let mut members: Vec<char> = Vec::new();
    if index < pattern.len() && pattern[index] == ']' {
        members.push(']');
        index += 1;
    }
    while index < pattern.len() && pattern[index] != ']' {
        members.push(pattern[index]);
        index += 1;
    }
    if index >= pattern.len() {
        return None;
    }
    let mut items = Vec::new();
    let mut position = 0;
    while position < members.len() {
        if position + 2 < members.len() && members[position + 1] == '-' {
            items.push(ClassItem::Range(members[position], members[position + 2]));
            position += 3;
        } else {
            items.push(ClassItem::Single(members[position]));
            position += 1;
        }
    }
    Some((negated, items, &pattern[index + 1..]))
}

fn match_text(matcher: &Matcher, value: &str) -> bool {
    match matcher {
        Matcher::Exact(pattern) => value == pattern,
        Matcher::Prefix(pattern) => value.starts_with(pattern.as_str()),
        Matcher::Glob(pattern) => {
            let pattern_chars: Vec<char> = pattern.chars().collect();
            let value_chars: Vec<char> = value.chars().collect();
            glob_match(&pattern_chars, &value_chars)
        }
    }
}

fn text_field<'a>(call: &'a Value, key: &str) -> &'a str {
    call.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn rule_matches(rule: &Rule, call: &Value) -> bool {
    let match_ = &rule.match_;
    match call.get("kind").and_then(|v| v.as_str()).unwrap_or("") {
        "shell" => {
            if let Some(argv0) = &match_.argv0 {
                let argv = call.get("argv").and_then(|v| v.as_array()).unwrap();
                let first = argv.first().and_then(|v| v.as_str()).unwrap_or("");
                if !match_text(argv0, first) {
                    return false;
                }
            }
            let argv = call.get("argv").and_then(|v| v.as_array()).unwrap();
            for condition in &match_.args {
                if condition.index >= argv.len() {
                    return false;
                }
                let token = argv[condition.index].as_str().unwrap_or("");
                if !match_text(&condition.matcher, token) {
                    return false;
                }
            }
            true
        }
        "file" => {
            if let Some(operation) = &match_.operation {
                if !match_text(operation, text_field(call, "operation")) {
                    return false;
                }
            }
            if let Some(path) = &match_.path {
                let given = text_field(call, "path");
                let normalized = normpath(given);
                if !match_text(path, given) && !match_text(path, &normalized) {
                    return false;
                }
            }
            true
        }
        _ => {
            if let Some(method) = &match_.method {
                if !match_text(method, text_field(call, "method")) {
                    return false;
                }
            }
            if let Some(host) = &match_.host {
                if !match_text(host, text_field(call, "host")) {
                    return false;
                }
            }
            if let Some(port) = &match_.port {
                if call.get("port").and_then(|v| v.int_i64()) != Some(*port) {
                    return false;
                }
            }
            true
        }
    }
}

fn apply_substitute(call: &Value, substitute: &Substitute, kind: &str) -> Value {
    let mut pairs: Vec<(String, Value)> = call.as_object().unwrap().clone();
    let replacements: Vec<(&str, &Option<Value>)> = match kind {
        "shell" => vec![("argv", &substitute.argv), ("cwd", &substitute.cwd)],
        "file" => vec![
            ("operation", &substitute.operation),
            ("path", &substitute.path),
            ("path2", &substitute.path2),
        ],
        _ => vec![
            ("method", &substitute.method),
            ("host", &substitute.host),
            ("port", &substitute.port),
        ],
    };
    for (key, replacement) in replacements {
        if let Some(value) = replacement {
            match pairs.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value.clone(),
                None => pairs.push((key.to_string(), value.clone())),
            }
        }
    }
    Value::Object(pairs)
}

fn decision(
    at: &str,
    digest: &str,
    outcome: &str,
    source: Value,
    reason: Option<&str>,
    interpreter: bool,
    rewritten_call: Option<Value>,
) -> Value {
    Value::obj(vec![
        ("format", Value::text(DECISION_FORMAT)),
        ("at", Value::text(at)),
        ("call_digest", Value::text(digest)),
        ("decision", Value::text(outcome)),
        ("source", source),
        (
            "reason",
            match reason {
                Some(reason) => Value::text(reason),
                None => Value::Null,
            },
        ),
        ("interpreter", Value::Bool(interpreter)),
        (
            "rewritten_call",
            match rewritten_call {
                Some(call) => call,
                None => Value::Null,
            },
        ),
    ])
}

fn source_rule(rule_id: &str) -> Value {
    Value::obj(vec![
        ("type", Value::text("rule")),
        ("rule", Value::text(rule_id)),
    ])
}

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
        let rewritten = apply_substitute(&call, rule.substitute.as_ref().unwrap(), kind);
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

// --- the audit log ------------------------------------------------------------

/// Append one decision record to the audit log as one whole
/// line, under an exclusive lock on the log file.
///
/// The lock is verified as the file standing at the log path.
/// After the lock is taken its device and inode are checked
/// against the path, with a bounded retry while the path
/// settles, and the identity is checked again immediately
/// before the line is written. An append whose held lock is not
/// the file at the path fails instead of writing into an
/// unlinked file no reader will ever see, and the decision it
/// carried is not delivered.
pub fn append_decision(log_path: &Path, decision: &Value) -> Result<(), LogAppendError> {
    let mut line = canonical(decision);
    line.push(b'\n');
    let mut last_error: Option<std::io::Error> = None;
    for _ in 0..5 {
        let mut handle = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
        {
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

fn validate_decision_record(
    record: &Value,
    line_number: usize,
) -> Result<Value, LogCorruptionError> {
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
    let digest_ok = match digest.as_str() {
        Some(text) => {
            text.starts_with("sha256:")
                && text.len() == "sha256:".len() + 64
                && text[7..].chars().all(|c| c.is_ascii_hexdigit())
        }
        None => false,
    };
    if !digest_ok {
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
            if decision_value.as_str() != Some("deny") {
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
    } else if *rewritten != Value::Null {
        return Err(corruption(format!(
            "{what} carries a rewritten call and does not rewrite"
        )));
    }
    Ok(record.clone())
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
        let line = match std::str::from_utf8(raw_line) {
            Ok(line) => line,
            Err(_) => {
                return Err(LogReadError::Corruption(LogCorruptionError {
                    line_number: number,
                    detail: format!("the record at line {number} does not decode as UTF-8"),
                }));
            }
        };
        let record = match strict_parse(line) {
            Ok(record) => record,
            Err(_) => {
                return Err(LogReadError::Corruption(LogCorruptionError {
                    line_number: number,
                    detail: format!("the record at line {number} does not parse"),
                }));
            }
        };
        match validate_decision_record(&record, number) {
            Ok(record) => records.push(record),
            Err(exc) => return Err(LogReadError::Corruption(exc)),
        }
    }
    Ok(records)
}
