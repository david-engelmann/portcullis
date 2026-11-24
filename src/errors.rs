//! The error types the gate raises, one per surface that can refuse.

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

impl std::error::Error for CallerError {}

impl std::error::Error for PolicyError {}

impl std::error::Error for MalformedCall {}

impl std::error::Error for LogAppendError {}

impl std::error::Error for LogCorruptionError {}

/// A failure of the log command, either a caller error or
/// corruption at a named line.
#[derive(Debug)]
pub enum LogReadError {
    Caller(CallerError),
    Corruption(LogCorruptionError),
}

impl std::fmt::Display for LogReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogReadError::Caller(error) => std::fmt::Display::fmt(error, f),
            LogReadError::Corruption(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for LogReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LogReadError::Caller(error) => Some(error),
            LogReadError::Corruption(error) => Some(error),
        }
    }
}

// --- the document model ------------------------------------------------
