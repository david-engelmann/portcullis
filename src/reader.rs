//! The strict reader: text to a value, refusing what the contract refuses.

use crate::value::Value;
use crate::{INT_DIGIT_LIMIT, MAX_DEPTH};
use std::collections::HashSet;

pub(crate) fn parse_usize_saturated(text: &str) -> usize {
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
