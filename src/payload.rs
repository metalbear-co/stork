//! Validated native payloads. The bytes and their decoded headers share one owner.

use crate::{Error, Result, Strategy, paths, pe::Headers};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

const MAX_PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// A native AMD64 DLL validated before any strategy can mutate a target.
///
/// Private fields prevent callers from pairing headers with unrelated bytes.
/// The path must still remain stable until the remote loader finishes with it.
pub(crate) struct Payload {
    path: PathBuf,
    bytes: Vec<u8>,
    headers: Headers,
}

impl Payload {
    pub(crate) fn load(path: &Path, strategy: Strategy) -> Result<Self> {
        let path = paths::canonical(path)?;
        let bytes = read_payload(&path)?;
        let headers = Headers::parse(&bytes)?;
        headers.validate_file(&bytes)?;
        if headers.directories[14].rva != 0 || headers.directories[14].size != 0 {
            return Err(Error::StrategyUnavailable {
                strategy,
                reason: "managed payloads are unsupported",
            });
        }
        Ok(Self {
            path,
            bytes,
            headers,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Apply IAT's additional export requirement to the same validated bytes.
    pub(crate) fn import_ordinal(&self) -> Result<u16> {
        self.headers
            .import_ordinal(&self.bytes)
            .map_err(|_| Error::StrategyUnavailable {
                strategy: Strategy::ImportTableHijack,
                reason: "payload must export ordinal 1 (Detours import-table requirement)",
            })
    }
}

fn read_payload(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .map_err(|error| crate::error::file_io("open DLL", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| crate::error::file_io("DLL metadata", path, error))?;
    if metadata.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::PayloadTooLarge {
            limit: MAX_PAYLOAD_BYTES,
        });
    }
    read_limited(file, path, MAX_PAYLOAD_BYTES)
}

/// Read at most one extra byte to detect growth after the metadata check.
fn read_limited(reader: impl Read, path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| crate::error::file_io("read DLL", path, error))?;
    if bytes.len() as u64 > limit {
        return Err(Error::PayloadTooLarge { limit });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_limit_accepts_boundary_and_stops_after_one_extra_byte() {
        let path = Path::new("payload.dll");
        assert_eq!(read_limited(&b"1234"[..], path, 4).unwrap(), b"1234");
        assert!(read_limited(&b""[..], path, 0).unwrap().is_empty());
        let mut reader = std::io::Cursor::new(b"123456789");
        assert!(matches!(
            read_limited(&mut reader, path, 4),
            Err(Error::PayloadTooLarge { limit: 4 })
        ));
        assert_eq!(reader.position(), 5);
    }

    #[test]
    fn payload_read_failure_keeps_context_after_partial_data() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(5))
            }
        }
        let reader = (&b"header"[..]).chain(FailingReader);
        let error = read_limited(reader, Path::new("broken.dll"), 32).unwrap_err();
        assert!(
            matches!(error, Error::Io { operation: "read DLL", ref path, ref source }
            if path == Path::new("broken.dll") && source.raw_os_error() == Some(5))
        );
    }
}
