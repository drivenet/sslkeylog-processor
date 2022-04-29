use std::fmt;

#[derive(Debug)]
pub(crate) struct TerminatedError {
    stage: String,
}

impl fmt::Display for TerminatedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Terminated at {}", self.stage)
    }
}

impl TerminatedError {
    pub(crate) fn new<T: Into<String>>(stage: T) -> Self {
        Self { stage: stage.into() }
    }
}
