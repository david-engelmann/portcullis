//! The value model every document in the gate is held in.

use crate::reader::parse_usize_saturated;

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

    pub(crate) fn is_int(&self) -> bool {
        matches!(self, Value::Int(_))
    }

    /// The value of an integer held at i64 width, or None when
    /// the text stands outside that width, in which case every
    /// bounded check in this crate judges it out of range.
    pub(crate) fn int_i64(&self) -> Option<i64> {
        match self {
            Value::Int(text) => text.parse::<i64>().ok(),
            _ => None,
        }
    }

    /// The value of an integer as an argument position, saturated
    /// at the width of the machine word, because a position only
    /// ever compares against the length of an argv.
    pub(crate) fn int_usize_saturated(&self) -> Option<usize> {
        match self {
            Value::Int(text) => Some(parse_usize_saturated(text)),
            _ => None,
        }
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        let mut stack: Vec<Value> = Vec::new();
        match self {
            Value::Array(items) => stack.extend(std::mem::take(items)),
            Value::Object(pairs) => {
                stack.extend(std::mem::take(pairs).into_iter().map(|(_, v)| v));
            }
            _ => return,
        }
        while let Some(mut node) = stack.pop() {
            match &mut node {
                Value::Array(items) => stack.extend(std::mem::take(items)),
                Value::Object(pairs) => {
                    stack.extend(std::mem::take(pairs).into_iter().map(|(_, v)| v));
                }
                _ => {}
            }
        }
    }
}
