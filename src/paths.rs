//! Local filesystem identity and Windows path encoding policies.
//!
//! This module never accesses or mutates a remote process.

use crate::{Error, Result};
use std::{
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use wincorda::{NullTerminated, WCHAR};

/// Encode Windows paths losslessly before wrapping their NUL-terminated units.
/// Wincorda's string conversion casts characters rather than encoding UTF-16.
pub(crate) fn wide(path: &Path) -> Result<NullTerminated<'static, WCHAR>> {
    let mut v: Vec<_> = path.as_os_str().encode_wide().collect();
    if v.contains(&0) {
        return Err(Error::UnsupportedPath("embedded NUL"));
    }
    v.push(0);
    NullTerminated::try_from(v).map_err(|_| Error::UnsupportedPath("missing NUL terminator"))
}

pub(crate) fn canonical(path: &Path) -> Result<PathBuf> {
    wide(path)?;
    let p = path.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::DllNotFound(path.to_owned())
        } else {
            crate::error::file_io("canonicalize DLL", path, e)
        }
    })?;
    if !p.is_file() {
        return Err(Error::UnsupportedPath("payload is not a file"));
    }
    Ok(p)
}

pub(crate) fn normalized(path: &Path) -> Vec<u16> {
    // Compare canonical full paths. Windows case-sensitive directories retain their spelling.
    let p = path.canonicalize().unwrap_or_else(|_| path.to_owned());
    p.as_os_str().encode_wide().collect()
}

/// IAT uses ASCII paths only. This is lossless for the supported PE import-name policy.
pub(crate) fn import_path(path: &Path) -> Result<Vec<u8>> {
    let mut w: Vec<_> = path.as_os_str().encode_wide().collect();
    if w.starts_with(&[92, 92, 63, 92]) {
        w.drain(..4);
        if w.starts_with(&[85, 78, 67, 92]) {
            return Err(Error::UnsupportedPath("IAT UNC paths are unsupported"));
        }
    }
    if w.len() >= 260 {
        return Err(Error::UnsupportedPath("IAT paths must fit MAX_PATH"));
    }
    if w.iter().any(|c| *c == 0 || *c > 127) {
        return Err(Error::UnsupportedPath(
            "IAT supports ASCII paths only; use LoadLibrary for Unicode",
        ));
    }
    if w.len() < 3
        || !(w[0] as u8).is_ascii_alphabetic()
        || w[1] != b':' as u16
        || ![b'\\' as u16, b'/' as u16].contains(&w[2])
    {
        return Err(Error::UnsupportedPath(
            "IAT requires an absolute local drive path",
        ));
    }
    Ok(w.into_iter().map(|c| c as u8).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};

    fn wide_path(s: &str) -> PathBuf {
        PathBuf::from(OsString::from_wide(&s.encode_utf16().collect::<Vec<_>>()))
    }

    #[test]
    fn import_path_policy() {
        // ASCII local paths pass, with the verbatim prefix stripped.
        let p = Path::new(r"D:\mirrord-stork\target\debug\test_payload.dll");
        assert_eq!(
            import_path(p).unwrap(),
            b"D:\\mirrord-stork\\target\\debug\\test_payload.dll".to_vec()
        );
        let verbatim = wide_path(r"\\?\D:\mirrord-stork\x.dll");
        assert_eq!(
            import_path(&verbatim).unwrap(),
            b"D:\\mirrord-stork\\x.dll".to_vec()
        );
        // Spaces round-trip losslessly.
        assert_eq!(
            import_path(Path::new(r"C:\dir with spaces\a.dll")).unwrap(),
            b"C:\\dir with spaces\\a.dll".to_vec()
        );
        // Non-ASCII characters are rejected.
        let unicode = wide_path(r"D:\ünïcode\x.dll");
        assert!(matches!(
            import_path(&unicode),
            Err(Error::UnsupportedPath(_))
        ));
        // UNC paths are rejected.
        let unc = wide_path(r"\\?\UNC\server\share\x.dll");
        assert!(matches!(import_path(&unc), Err(Error::UnsupportedPath(_))));
        // MAX_PATH-sized and longer paths are rejected.
        let mut long = String::from(r"D:\");
        for _ in 0..12 {
            long.push_str("abcdefghijklmnopqrstuvwxyz0123456789\\");
        }
        assert!(long.len() > 260);
        assert!(matches!(
            import_path(Path::new(&long)),
            Err(Error::UnsupportedPath(_))
        ));
        // Embedded NUL is rejected.
        let nul = wide_path("D:\\a\0b.dll");
        assert!(matches!(import_path(&nul), Err(Error::UnsupportedPath(_))));
        // An exactly short boundary passes.
        let mut short = String::from("C:\\");
        while short.len() < 259 {
            short.push('a');
        }
        assert!(import_path(Path::new(&short)).is_ok());
    }

    #[test]
    fn wide_rejects_nul_and_appends_terminator() {
        assert_eq!(
            wide(Path::new("abc")).unwrap().as_bytes_with_nul(),
            vec![b'a' as u16, b'b' as u16, b'c' as u16, 0]
        );
        let nul = wide_path("x\0y");
        assert!(matches!(wide(&nul), Err(Error::UnsupportedPath(_))));
    }

    #[test]
    fn wide_preserves_surrogates_and_remote_terminator_bytes() {
        // One surrogate pair followed by an unpaired surrogate: both are valid
        // Windows path units and must survive without lossy Unicode conversion.
        let units = [0x0061, 0xd83e, 0xdd80, 0xd800];
        let path = PathBuf::from(OsString::from_wide(&units));
        let encoded = wide(&path).unwrap();
        assert_eq!(
            encoded.as_bytes_with_nul(),
            &[0x0061, 0xd83e, 0xdd80, 0xd800, 0]
        );
        assert_eq!(
            dataview::bytes(encoded.as_bytes_with_nul()),
            &[0x61, 0, 0x3e, 0xd8, 0x80, 0xdd, 0, 0xd8, 0, 0]
        );
        assert_eq!(wide(Path::new("")).unwrap().as_bytes_with_nul(), &[0]);
    }

    #[test]
    fn import_path_rejects_relative_unc_and_device_paths() {
        for path in [
            r"payload.dll",
            r"C:payload.dll",
            r"\payload.dll",
            r"\\server\share\payload.dll",
            r"\\.\C:\payload.dll",
            "",
        ] {
            assert!(
                matches!(import_path(Path::new(path)), Err(Error::UnsupportedPath(_))),
                "{path}"
            );
        }
    }
}
