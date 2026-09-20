//! Explicit injection strategies and their string representations.

mod import_table;
mod load_library;
mod queue_apc;
pub(crate) use import_table::inject as import_table;
pub(crate) use load_library::inject as load_library;
pub(crate) use queue_apc::inject as queue_apc;
/// The injection mechanism. No strategy resumes the primary thread.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Strategy {
    /// Start a remote LoadLibrary thread and wait up to 30 seconds.
    #[default]
    LoadLibraryRemoteThread,
    /// Queue LoadLibrary on the caller-attested never-run primary thread.
    QueueUserApc,
    /// Rewrite imports in a caller-attested never-run image.
    ImportTableHijack,
}

impl Strategy {
    /// Return the canonical strategy name: `loadlibrary`, `apc`, or `iat`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LoadLibraryRemoteThread => "loadlibrary",
            Self::QueueUserApc => "apc",
            Self::ImportTableHijack => "iat",
        }
    }
}

impl std::str::FromStr for Strategy {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "loadlibrary" | "load-library" | "remote-thread" | "crt" => {
                Ok(Self::LoadLibraryRemoteThread)
            }
            "apc" | "queue-user-apc" | "early-bird" => Ok(Self::QueueUserApc),
            "iat" | "import-table" | "detours" => Ok(Self::ImportTableHijack),
            _ => Err(crate::Error::UnknownStrategy(s.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_and_default() {
        for s in ["loadlibrary", "load-library", "remote-thread", "crt", "CRT"] {
            assert_eq!(s.parse::<Strategy>().unwrap(), Strategy::default());
        }
        for s in ["apc", "queue-user-apc", "early-bird"] {
            assert_eq!(s.parse::<Strategy>().unwrap(), Strategy::QueueUserApc);
        }
        for s in ["iat", "import-table", "detours"] {
            assert_eq!(s.parse::<Strategy>().unwrap(), Strategy::ImportTableHijack);
        }
        assert!("unknown".parse::<Strategy>().is_err());
        for s in [
            Strategy::default(),
            Strategy::QueueUserApc,
            Strategy::ImportTableHijack,
        ] {
            assert_eq!(s.as_str().parse::<Strategy>().unwrap(), s);
        }
    }
}
