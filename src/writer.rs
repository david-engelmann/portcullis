//! The canonical writer, taking a value to the exact bytes the contract fixes.

use crate::value::Value;
use sha2::{Digest, Sha256};

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
