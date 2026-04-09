extern crate alloc;
use alloc::string::String;

#[derive(Debug, Clone)]
pub struct JsError {
    pub kind: JsErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsErrorKind {
    Error,
    TypeError,
    RangeError,
    SyntaxError,
    ReferenceError,
    EvalError,
    UriError,
}

impl JsError {
    pub fn new(kind: JsErrorKind, message: &str) -> Self {
        Self { kind, message: String::from(message) }
    }

    pub fn type_error(message: &str) -> Self {
        Self::new(JsErrorKind::TypeError, message)
    }

    pub fn reference_error(message: &str) -> Self {
        Self::new(JsErrorKind::ReferenceError, message)
    }

    pub fn range_error(message: &str) -> Self {
        Self::new(JsErrorKind::RangeError, message)
    }

    pub fn syntax_error(message: &str) -> Self {
        Self::new(JsErrorKind::SyntaxError, message)
    }

    pub fn name(&self) -> &'static str {
        match self.kind {
            JsErrorKind::Error => "Error",
            JsErrorKind::TypeError => "TypeError",
            JsErrorKind::RangeError => "RangeError",
            JsErrorKind::SyntaxError => "SyntaxError",
            JsErrorKind::ReferenceError => "ReferenceError",
            JsErrorKind::EvalError => "EvalError",
            JsErrorKind::UriError => "URIError",
        }
    }
}

impl core::fmt::Display for JsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.name(), self.message)
    }
}
