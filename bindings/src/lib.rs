//! The thin Python binding over the portcullis crate.
//!
//! The binding carries two operations and no logic of its own.
//! The function `check` takes a policy document and a call
//! document as ordinary Python values, converts each one into
//! the library's document model, and hands both to the library
//! exactly as the command line tool hands it the documents it
//! reads from files. The library loads the policy, evaluates
//! the call, and the binding appends the decision to the audit
//! log through the library before returning the decision as a
//! plain dictionary in the portcullis-decision/1 shape. The
//! function `read_log` returns the records of an audit log as a
//! list of plain dictionaries and refuses a corrupt log with
//! the same words the command line tool refuses it with.
//!
//! The instant is a required argument of `check`, taken as ISO
//! 8601 text and recorded verbatim, because the library reads
//! no wall clock for a decision and exposes no clock of its
//! own. The command line tool stamps the current UTC instant
//! in its own front end, and a second clock inside the binding
//! would be a second implementation of the same fact, so the
//! caller states the instant the way the other bindings of
//! this fleet state theirs.
//!
//! A document crosses as the Python value itself rather than
//! as JSON text, because the strict reader's work on a file is
//! parsing, and a Python value is already parsed. The
//! conversion mirrors the reader's refusals one for one. A
//! string the reader would refuse as text that is not
//! encodable refuses with the reader's own words, an integer
//! wider than the reader's bound refuses with the reader's own
//! words, and nesting deeper than the reader's bound refuses
//! with the reader's own words. A float that is not a number
//! refuses with the reader's own parse words, because no
//! document the reader accepts can hold one, while the
//! infinities cross, because an overflowing number literal in
//! a document the reader accepts produces them. Object keys come from the
//! dictionary itself, so a subclass cannot invent keys the
//! dictionary does not hold, and a key that is not a string is
//! a type error, as is any value that is not a JSON document
//! value at all. Integers cross through the int type's own
//! methods, never through a method the value's class supplies,
//! so a subclass that lies about its bytes or its bit length
//! cannot stand in for the digits it carries. A boolean is a
//! JSON boolean and crosses as one, never as the integer one,
//! so a port written as True is judged by the library as a
//! malformed call rather than matched as port 1.
//!
//! A refusal of the call document raises at once, in the
//! caller error class the command line tool exits 2 on,
//! because an unparseable call is a caller error there. A
//! refusal of the policy document is captured as the policy
//! loading detail and lands in the decision as a policy error
//! deny, because every policy side failure on the command line
//! lands there and the gate fails closed. Two of the library's
//! error kinds never become exceptions here. A malformed call
//! and a policy refusal are consumed by the evaluation into
//! the decision record itself, exactly as the command line
//! tool delivers them as printed decisions, so an exception
//! class for either would be dead surface. An append failure
//! raises with the full sentence the command line tool prints
//! for it, and a corrupt log raises with the full sentence the
//! command line tool prints for it. The evaluation order is
//! the security property and lives only in the library.

use std::path::PathBuf;

use portcullis_core::{
    append_decision, evaluate, evaluate_with_transport, load_policy, JudgeTransport, LogReadError,
    TransportError, Value,
};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

create_exception!(
    portcullis,
    PortcullisError,
    PyException,
    "The base class of every refusal the portcullis binding raises."
);
create_exception!(portcullis, CallerError, PortcullisError, "A caller error, carrying the words of the library error the command line tool answers at exit 2.");
create_exception!(portcullis, LogAppendError, PortcullisError, "A decision that could not be appended to the audit log, carrying the full sentence the command line tool prints for the failure.");
create_exception!(portcullis, LogCorruptionError, PortcullisError, "An audit log that does not read back whole, carrying the full sentence the command line tool prints for the corruption.");

// The reader's own bounds and refusal words, mirrored because
// the conversion stands in for the reader on this surface.
// The digit bound and the depth bound are the values the
// library's strict parser enforces, and the three sentences
// are the refusals that parser raises at them.
const INT_DIGIT_LIMIT: usize = 4300;
const MAX_DEPTH: usize = 1000;
const TOO_WIDE_TEXT: &str = "the document carries an integer too wide to parse";
const TOO_DEEP_TEXT: &str = "the document nests too deeply to parse";
const DOES_NOT_PARSE_TEXT: &str = "the document does not parse";
const NOT_ENCODABLE_TEXT: &str = "the document carries a string that is not encodable text";

// A bit count past which an integer certainly carries more
// digits than the reader accepts. A value of 2 raised to the
// 14286 carries 4301 digits, so a wider value is refused on
// its bit length alone and never converted at all.
const INT_BIT_LIMIT: usize = 14_286;

/// Why a Python value did not cross into a document.
///
/// A value of the wrong type is no document at all and lands
/// on the interpreter's type error, while a value that is
/// shaped as a document and refused the way the strict reader
/// refuses one carries the reader's own words, so the caller
/// of `check` can land it in the class the command line tool
/// lands it in for each side of the operation.
enum ConvertError {
    Type(String),
    Reader(String),
}

fn type_name(value: &Bound<'_, PyAny>) -> String {
    match value.get_type().name() {
        Ok(name) => name.to_string(),
        Err(_) => "unnameable".to_string(),
    }
}

/// The decimal text of one integer value, kept whole.
///
/// The digits come from the int type itself, through its
/// unbound `bit_length` and `to_bytes` methods, so an int
/// subclass that overrides either method cannot stand in for
/// the value it carries, cannot shrink the value under a bound
/// it would otherwise trip, and cannot raise a panic shape out
/// of a conversion of bytes it forged. No string conversion of
/// the value is ever called, so an overridden `__str__` cannot
/// put forged digits into a document or a refusal either.
fn decimal_text(value: &Bound<'_, PyAny>) -> PyResult<String> {
    let int_type = value.py().get_type::<PyInt>();
    let bits: usize = int_type.call_method1("bit_length", (value,))?.extract()?;
    let byte_count = bits / 8 + 2;
    let bytes: Vec<u8> = int_type
        .call_method(
            "to_bytes",
            (value, byte_count, "big"),
            Some(&[("signed", true)].into_py_dict(value.py())?),
        )?
        .extract()?;
    let negative = bytes.first().map(|b| b & 0x80 != 0).unwrap_or(false);
    // Work with the magnitude as a big unsigned byte string,
    // then convert it to decimal digits by repeated division.
    let mut magnitude: Vec<u8> = bytes.clone();
    if negative {
        // Two's complement negation over the same width gives
        // the magnitude bytes.
        for byte in magnitude.iter_mut() {
            *byte = !*byte;
        }
        let mut carry = 1u16;
        for byte in magnitude.iter_mut().rev() {
            let sum = *byte as u16 + carry;
            *byte = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }
    // Drop leading zero bytes, keeping one byte for zero.
    let first_nonzero = magnitude
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(magnitude.len().saturating_sub(1));
    let magnitude = &magnitude[first_nonzero..];
    // A zero magnitude converts to the text 0 outright, so the
    // scan below never has to stand in for it. The magnitudes
    // reaching the scan are never empty, because an all zero
    // byte string means the value itself is zero.
    if magnitude.iter().all(|b| *b == 0) {
        return Ok("0".to_string());
    }
    let mut digits_be: Vec<u8> = magnitude.to_vec();
    let mut decimal: Vec<u8> = Vec::new();
    loop {
        let mut remainder = 0u32;
        let mut quotient: Vec<u8> = Vec::with_capacity(digits_be.len());
        for byte in &digits_be {
            let current = (remainder << 8) | *byte as u32;
            let q = (current / 10) as u8;
            remainder = current % 10;
            if !quotient.is_empty() || q != 0 {
                quotient.push(q);
            }
        }
        decimal.push(b'0' + remainder as u8);
        if quotient.is_empty() {
            break;
        }
        digits_be = quotient;
    }
    decimal.reverse();
    let body = String::from_utf8(decimal).expect("decimal digits are ascii");
    if negative {
        Ok(format!("-{body}"))
    } else {
        Ok(body)
    }
}

/// One integer value as a document integer.
///
/// The width is judged twice, once on the bit length before
/// any conversion and once on the digit count after it, and
/// both judgements read values the int type reports about the
/// value rather than values the value's class reports, so a
/// subclass that forges a small bit length is still refused on
/// the true digits its type level conversion produces. A value
/// wider than the reader's own bound refuses with the reader's
/// own words, so a document the binding accepts is always a
/// document the command line tool could have read.
fn integer_value(value: &Bound<'_, PyAny>) -> Result<Value, ConvertError> {
    let int_type = value.py().get_type::<PyInt>();
    let unreadable =
        || ConvertError::Type("an integer in the document could not be read".to_string());
    let bits: usize = int_type
        .call_method1("bit_length", (value,))
        .map_err(|_| unreadable())?
        .extract()
        .map_err(|_| unreadable())?;
    if bits > INT_BIT_LIMIT {
        return Err(ConvertError::Reader(TOO_WIDE_TEXT.to_string()));
    }
    let text = decimal_text(value).map_err(|_| unreadable())?;
    let digits = text.strip_prefix('-').unwrap_or(&text).len();
    if digits > INT_DIGIT_LIMIT {
        return Err(ConvertError::Reader(TOO_WIDE_TEXT.to_string()));
    }
    Ok(Value::Int(text))
}

fn key_text(key: &Bound<'_, PyAny>) -> Result<String, ConvertError> {
    match key.cast::<PyString>() {
        Ok(text) => match text.extract::<String>() {
            Ok(text) => Ok(text),
            Err(_) => Err(ConvertError::Reader(NOT_ENCODABLE_TEXT.to_string())),
        },
        Err(_) => Err(ConvertError::Type(format!(
            "a document key is of type {}, and the keys of a document are strings",
            type_name(key)
        ))),
    }
}

/// One Python value as a document in the library's model.
///
/// The depth bound mirrors the reader's, and it is also what
/// keeps a value that contains itself from recursing without
/// end. Tuples cross as arrays beside lists, a recorded
/// widening of shape only, since a tuple is an immutable list
/// to the caller and the document it becomes is the same.
fn to_value(value: &Bound<'_, PyAny>, depth: usize) -> Result<Value, ConvertError> {
    if depth > MAX_DEPTH {
        return Err(ConvertError::Reader(TOO_DEEP_TEXT.to_string()));
    }
    if value.is_none() {
        return Ok(Value::Null);
    }
    if value.is_instance_of::<PyBool>() {
        let flag: bool = value.extract().map_err(|_| {
            ConvertError::Type("a boolean in the document could not be read".to_string())
        })?;
        return Ok(Value::Bool(flag));
    }
    if value.is_instance_of::<PyInt>() {
        return integer_value(value);
    }
    if value.is_instance_of::<PyFloat>() {
        let number: f64 = value.extract().map_err(|_| {
            ConvertError::Type("a number in the document could not be read".to_string())
        })?;
        if number.is_nan() {
            return Err(ConvertError::Reader(DOES_NOT_PARSE_TEXT.to_string()));
        }
        return Ok(Value::Float(number));
    }
    if let Ok(text) = value.cast::<PyString>() {
        return match text.extract::<String>() {
            Ok(text) => Ok(Value::Str(text)),
            Err(_) => Err(ConvertError::Reader(NOT_ENCODABLE_TEXT.to_string())),
        };
    }
    if let Ok(list) = value.cast::<PyList>() {
        let mut items = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(to_value(&item, depth + 1)?);
        }
        return Ok(Value::Array(items));
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        let mut items = Vec::with_capacity(tuple.len());
        for item in tuple.iter() {
            items.push(to_value(&item, depth + 1)?);
        }
        return Ok(Value::Array(items));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut pairs = Vec::with_capacity(dict.len());
        for (key, item) in dict.iter() {
            pairs.push((key_text(&key)?, to_value(&item, depth + 1)?));
        }
        return Ok(Value::Object(pairs));
    }
    Err(ConvertError::Type(format!(
        "a value of type {} is not a document value",
        type_name(value)
    )))
}

/// One document back as a plain Python value.
///
/// An integer comes back through the int type applied to its
/// stored text, which is always within the width the reader
/// and this conversion both enforce, so the interpreter's own
/// digit bound is never tripped by a document the library
/// itself produced.
fn value_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    Ok(match value {
        Value::Null => py.None(),
        Value::Bool(flag) => PyBool::new(py, *flag).to_owned().into_any().unbind(),
        Value::Int(text) => py.get_type::<PyInt>().call1((text,))?.unbind(),
        Value::Float(number) => PyFloat::new(py, *number).into_any().unbind(),
        Value::Str(text) => PyString::new(py, text).into_any().unbind(),
        Value::Array(items) => {
            let mut converted = Vec::with_capacity(items.len());
            for item in items {
                converted.push(value_to_py(py, item)?);
            }
            PyList::new(py, converted)?.into_any().unbind()
        }
        Value::Object(pairs) => {
            let dict = PyDict::new(py);
            for (key, item) in pairs {
                dict.set_item(key, value_to_py(py, item)?)?;
            }
            dict.into_any().unbind()
        }
    })
}

/// One decision or log record as a plain dictionary.
///
/// Decisions and log records are objects by the library's own
/// construction and validation, so a value of any other shape
/// here is a breach of the library's contract, and it is
/// reported as one rather than papered over with an empty
/// dictionary.
fn dict_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyDict>> {
    let Some(pairs) = value.as_object() else {
        return Err(PyTypeError::new_err(
            "the library produced a record that is not an object",
        ));
    };
    let dict = PyDict::new(py);
    for (key, item) in pairs {
        dict.set_item(key, value_to_py(py, item)?)?;
    }
    Ok(dict.unbind())
}

/// A Python callable standing as a judge transport.
///
/// The callable receives the request document as one plain
/// dictionary and answers with the reply body as text. A
/// callable that raises, or that answers with a value that is
/// not text, is a transport failure, and the library records
/// the referral under the transport class.
struct PyJudgeTransport {
    callable: Py<PyAny>,
}

impl JudgeTransport for PyJudgeTransport {
    fn consult(&self, request: &Value) -> Result<String, TransportError> {
        Python::attach(|py| {
            let argument = value_to_py(py, request).map_err(|_| {
                TransportError("the request document could not cross to the transport".to_string())
            })?;
            let result = self
                .callable
                .bind(py)
                .call1((argument,))
                .map_err(|_| TransportError("the transport callable raised".to_string()))?;
            result.extract::<String>().map_err(|_| {
                TransportError(
                    "the transport callable returned a value that is not text".to_string(),
                )
            })
        })
    }
}

/// Judge one call against one policy and record the decision.
///
/// The policy document and the call document cross as Python
/// values, dicts in the common case, and the instant is stated
/// as ISO 8601 text and recorded verbatim. The decision comes
/// back as a plain dictionary in the portcullis-decision/1
/// shape, and it stands in the audit log at the given path
/// before the function returns, appended by the library under
/// its lock exactly as the command line tool appends it. The
/// optional transport keyword hands the library a callable
/// judge transport, and a decision the model influenced then
/// comes back in the portcullis-decision/2 shape.
#[pyfunction]
#[pyo3(signature = (policy, call, log, at, transport=None))]
fn check(
    py: Python<'_>,
    policy: &Bound<'_, PyAny>,
    call: &Bound<'_, PyAny>,
    log: PathBuf,
    at: &str,
    transport: Option<Py<PyAny>>,
) -> PyResult<Py<PyDict>> {
    let call_document = to_value(call, 0).map_err(|error| match error {
        ConvertError::Reader(message) => CallerError::new_err(message),
        ConvertError::Type(message) => PyTypeError::new_err(message),
    })?;
    let (policy_document, policy_detail) = match to_value(policy, 0) {
        Ok(document) => (Some(document), None),
        Err(ConvertError::Reader(message)) => (None, Some(message)),
        Err(ConvertError::Type(message)) => return Err(PyTypeError::new_err(message)),
    };
    let at_text = at.to_string();
    if let Some(callable) = transport {
        let (policy, detail) = match &policy_document {
            Some(document) => match load_policy(document) {
                Ok(policy) => (Some(policy), None),
                Err(error) => (None, Some(error.0)),
            },
            None => (None, policy_detail.clone()),
        };
        let wrapper = PyJudgeTransport { callable };
        let decision = evaluate_with_transport(
            policy.as_ref(),
            detail.as_deref(),
            &call_document,
            &at_text,
            Some(&wrapper),
        );
        append_decision(&log, &decision).map_err(|error| {
            LogAppendError::new_err(format!(
                "the decision could not be appended to the audit log at {}, {}",
                log.display(),
                error.0
            ))
        })?;
        return dict_to_py(py, &decision);
    }
    let outcome = py.detach(|| {
        let (policy, detail) = match &policy_document {
            Some(document) => match load_policy(document) {
                Ok(policy) => (Some(policy), None),
                Err(error) => (None, Some(error.0)),
            },
            None => (None, policy_detail.clone()),
        };
        let decision = evaluate(policy.as_ref(), detail.as_deref(), &call_document, &at_text);
        append_decision(&log, &decision)
            .map(|()| decision)
            .map_err(|error| {
                format!(
                    "the decision could not be appended to the audit log at {}, {}",
                    log.display(),
                    error.0
                )
            })
    });
    let decision = outcome.map_err(LogAppendError::new_err)?;
    dict_to_py(py, &decision)
}

/// Read the records of one audit log back as plain dicts.
///
/// A log that does not stand raises in the caller error class
/// with the library's own words, and a log with a bad line
/// raises in the corruption class with the full sentence the
/// command line tool prints for it, line number included.
#[pyfunction]
fn read_log(py: Python<'_>, log: PathBuf) -> PyResult<Vec<Py<PyDict>>> {
    let records = py
        .detach(|| portcullis_core::read_log(&log))
        .map_err(|error| match error {
            LogReadError::Caller(caller) => CallerError::new_err(caller.0),
            LogReadError::Corruption(corruption) => LogCorruptionError::new_err(format!(
                "the audit log is corrupt at line {}, {}",
                corruption.line_number, corruption.detail
            )),
        })?;
    let mut converted = Vec::with_capacity(records.len());
    for record in &records {
        converted.push(dict_to_py(py, record)?);
    }
    Ok(converted)
}

#[pymodule]
fn _portcullis(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(check, m)?)?;
    m.add_function(wrap_pyfunction!(read_log, m)?)?;
    m.add("PortcullisError", m.py().get_type::<PortcullisError>())?;
    m.add("CallerError", m.py().get_type::<CallerError>())?;
    m.add("LogAppendError", m.py().get_type::<LogAppendError>())?;
    m.add(
        "LogCorruptionError",
        m.py().get_type::<LogCorruptionError>(),
    )?;
    Ok(())
}
