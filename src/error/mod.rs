//! Error details, cleanup composition, and caller recovery decisions.

use crate::Strategy;

/// An injection or validation failure.
///
/// Use [`Self::is_pending`] and [`Self::must_not_resume`] before deciding how
/// to recover. Neither method returning `false` certifies that retry or resume
/// is safe; the caller's loader-state and synchronization contract still applies.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("the DLL path does not exist: {0}")]
    DllNotFound(std::path::PathBuf),
    #[error("the strategy {strategy:?} is not available: {reason}")]
    StrategyUnavailable {
        strategy: Strategy,
        reason: &'static str,
    },
    #[error("this strategy needs the target main-thread handle")]
    MissingThreadHandle,
    #[error(
        "the injector and target bitness differ (injector_64={injector_64}, target_64={target_64})"
    )]
    BitnessMismatch { injector_64: bool, target_64: bool },
    #[error("could not confirm the injected module in the target")]
    ModuleNotFound,
    #[error("PE parse error: {0}")]
    Pe(String),
    #[error("the remote thread timed out; outcome pending; do not retry")]
    RemoteTimeout,
    #[error("the remote wait failed; outcome pending; allocation retained: {0}")]
    RemotePending(#[source] std::io::Error),
    #[error("invalid target or state: {0}")]
    InvalidTarget(&'static str),
    #[error("could not identify the primary thread unambiguously")]
    AmbiguousPrimaryThread,
    #[error("unsupported machine type: {0:#06x}")]
    UnsupportedMachine(u16),
    #[error("unsupported payload path: {0}")]
    UnsupportedPath(&'static str),
    #[error("IAT rollback failed; the target is modified and must not resume")]
    IatRollbackFailed,
    #[error("protection restoration failed; do not resume: {0}")]
    ProtectionRestore(#[source] Box<Error>),
    #[error("operation failed: {operation}; cleanup also failed: {cleanup}")]
    Cleanup {
        #[source]
        operation: Box<Error>,
        cleanup: Box<Error>,
    },
    #[error("{operation} failed for {}: {source}", path.display())]
    Io {
        operation: &'static str,
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("payload file exceeds the {limit}-byte limit")]
    PayloadTooLarge { limit: u64 },
    #[error("{call} failed: {source}")]
    Win32 {
        call: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("unknown injection strategy: {0}")]
    UnknownStrategy(String),
}

impl Error {
    /// Whether a remote load may still be running. Do not retry blindly.
    ///
    /// Checks both branches of a combined operation/cleanup error.
    pub fn is_pending(&self) -> bool {
        match self {
            Self::RemoteTimeout | Self::RemotePending(_) => true,
            Self::Cleanup { operation, cleanup } => operation.is_pending() || cleanup.is_pending(),
            Self::ProtectionRestore(source) => source.is_pending(),
            _ => false,
        }
    }

    /// Whether failed rollback or protection restoration forbids resume.
    ///
    /// A `false` result is not permission to resume or repeat injection.
    pub fn must_not_resume(&self) -> bool {
        match self {
            Self::IatRollbackFailed | Self::ProtectionRestore(_) => true,
            Self::Cleanup { operation, cleanup } => {
                operation.must_not_resume() || cleanup.must_not_resume()
            }
            _ => false,
        }
    }

    /// Preserve a second error while keeping this operation as the source.
    pub(crate) fn with_cleanup(self, cleanup: Error) -> Self {
        Self::Cleanup {
            operation: Box::new(self),
            cleanup: Box::new(cleanup),
        }
    }
}

/// The result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Keep the successful value only when cleanup also succeeds.
pub(crate) fn combine<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(operation.with_cleanup(cleanup)),
    }
}

/// Capture last-error immediately, before another Windows call can overwrite it.
pub(crate) fn win32(call: &'static str) -> Error {
    Error::Win32 {
        call,
        source: std::io::Error::last_os_error(),
    }
}

/// Wrap a previously captured Windows error without reading last-error again.
pub(crate) fn from_win32(call: &'static str, source: std::io::Error) -> Error {
    Error::Win32 { call, source }
}

pub(crate) fn file_io(
    operation: &'static str,
    path: &std::path::Path,
    source: std::io::Error,
) -> Error {
    Error::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

pub(crate) fn pe(message: &str) -> Error {
    Error::Pe(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn cleanup_keeps_both_errors_and_the_primary_source() {
        let error =
            combine::<()>(Err(pe("initial write")), Err(pe("free allocation"))).unwrap_err();
        assert!(error.to_string().contains("initial write"));
        assert!(error.to_string().contains("free allocation"));
        assert_eq!(
            error.source().unwrap().to_string(),
            "PE parse error: initial write"
        );
        assert!(!error.is_pending());
        assert!(!error.must_not_resume());
    }

    #[test]
    fn cleanup_preserves_values_and_single_failures() {
        assert_eq!(combine(Ok(42), Ok(())).unwrap(), 42);
        assert!(matches!(
            combine::<()>(Err(Error::RemoteTimeout), Ok(())),
            Err(Error::RemoteTimeout)
        ));
        assert!(matches!(
            combine(Ok(42), Err(Error::IatRollbackFailed)),
            Err(Error::IatRollbackFailed)
        ));
    }

    #[test]
    fn recovery_checks_follow_both_cleanup_branches() {
        for error in [
            Error::RemoteTimeout.with_cleanup(Error::IatRollbackFailed),
            pe("initial error")
                .with_cleanup(Error::IatRollbackFailed.with_cleanup(Error::RemoteTimeout)),
            Error::ProtectionRestore(Box::new(Error::RemotePending(
                std::io::Error::from_raw_os_error(6),
            ))),
        ] {
            assert!(error.is_pending());
            assert!(error.must_not_resume());
        }
    }

    #[test]
    fn file_error_keeps_path_operation_and_os_source() {
        let path = std::path::Path::new(r"C:\payloads\layer.dll");
        let error = file_io("open DLL", path, std::io::Error::from_raw_os_error(5));
        assert!(error.to_string().contains("open DLL"));
        assert!(error.to_string().contains(&path.display().to_string()));
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(5)
        );
    }
}
