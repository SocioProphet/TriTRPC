use std::fmt;

/// Error type for v4 frame and primitive operations.
#[derive(Debug, PartialEq, Eq)]
pub struct V4Error(pub String);

impl V4Error {
    pub fn new(msg: impl Into<String>) -> Self {
        V4Error(msg.into())
    }
}

impl fmt::Display for V4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for V4Error {}

impl From<String> for V4Error {
    fn from(s: String) -> Self {
        V4Error(s)
    }
}

impl From<&str> for V4Error {
    fn from(s: &str) -> Self {
        V4Error(s.to_string())
    }
}
