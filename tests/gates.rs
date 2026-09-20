//! Gate and payload-validation negatives. Every process-level case asserts
//! the target is left untouched: the fixture still runs normally on resume.
#![cfg(windows)]
mod common;

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use common::profile;
use common::*;
use serial_test::serial;
use stork::{Error, Injector, LoaderState, Strategy, Target};

fn payload_copy(name: &str) -> PathBuf {
    let fixtures = fixtures();
    let dir = fixtures
        .workspace
        .join("target")
        .join(profile())
        .join("neg");
    std::fs::create_dir_all(&dir).expect("neg dir");
    let copy = dir.join(name);
    std::fs::copy(&fixtures.payload, &copy).expect("payload copy");
    copy
}

fn patch_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn nt_optional_headers(bytes: &[u8]) -> (usize, usize) {
    assert_eq!(&bytes[..2], b"MZ", "bad DOS magic");
    let nt = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    assert_eq!(&bytes[nt..nt + 4], b"PE\0\0", "bad NT magic");
    (nt, nt + 24)
}

fn x86_payload() -> PathBuf {
    let path = payload_copy("x86.dll");
    let mut bytes = std::fs::read(&path).unwrap();
    let (nt, _) = nt_optional_headers(&bytes);
    patch_u16(&mut bytes, nt + 4, 0x014c); // IMAGE_FILE_MACHINE_I386
    std::fs::write(&path, bytes).unwrap();
    path
}

fn arm64_payload() -> PathBuf {
    let path = payload_copy("arm64.dll");
    let mut bytes = std::fs::read(&path).unwrap();
    let (nt, _) = nt_optional_headers(&bytes);
    patch_u16(&mut bytes, nt + 4, 0xaa64); // IMAGE_FILE_MACHINE_ARM64
    std::fs::write(&path, bytes).unwrap();
    path
}

fn com_descriptor_payload() -> PathBuf {
    let path = payload_copy("managed.dll");
    let mut bytes = std::fs::read(&path).unwrap();
    let (_, optional) = nt_optional_headers(&bytes);
    // DataDirectory[14] (CLR) virtual address, entry 14 of 16.
    patch_u32(&mut bytes, optional + 112 + 14 * 8, 1);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn exportless_payload() -> PathBuf {
    let path = payload_copy("exportless.dll");
    let mut bytes = std::fs::read(&path).unwrap();
    let (_, optional) = nt_optional_headers(&bytes);
    // DataDirectory[0] (export): zeroed => no export directory at all.
    patch_u32(&mut bytes, optional + 112, 0);
    patch_u32(&mut bytes, optional + 116, 0);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn suspended_entry() -> (Child, Events) {
    let child = Child::spawn(&fixtures().entry);
    let events = Events::create_all(child.pid);
    (child, events)
}

fn target_of(child: &Child) -> Target {
    Target::not_started(
        child.process as *mut c_void,
        Some(child.thread as *mut c_void),
        child.pid,
    )
}

/// The failed injection must leave the never-run target resumable.
fn assert_untouched_and_runs(child: &Child, events: &Events) {
    events.entry.assert_clear("entry before the failed inject");
    child.resume("after failed inject");
    events
        .entry
        .wait_object(10_000, "target entry after a failed inject");
}

/// Strategy and loader-state gates. These fail before any handle use.
#[test]
fn dispatch_gates_do_not_touch_handles() {
    let target = Target::new(std::ptr::null_mut(), None, 1, LoaderState::NotStarted);
    let injector = Injector::with_strategy(Strategy::QueueUserApc);
    assert!(
        matches!(
            unsafe { injector.inject(target, "x.dll") },
            Err(Error::MissingThreadHandle)
        ),
        "APC without a thread must fail the gate"
    );
    let target = Target::new(
        std::ptr::null_mut(),
        Some(std::ptr::null_mut()),
        1,
        LoaderState::Unknown,
    );
    assert!(
        matches!(
            unsafe { injector.inject(target, "x.dll") },
            Err(Error::StrategyUnavailable { .. })
        ),
        "APC on Unknown loader state must fail"
    );
    let iat = Injector::with_strategy(Strategy::ImportTableHijack);
    for state in [
        LoaderState::Unknown,
        LoaderState::LoaderComplete,
        LoaderState::EarlyApc,
    ] {
        let target = Target::new(std::ptr::null_mut(), None, 1, state);
        assert!(
            matches!(
                unsafe { iat.inject(target, "x.dll") },
                Err(Error::StrategyUnavailable { .. })
            ),
            "IAT on {state:?} must fail the gate"
        );
    }
    // The default remote-thread strategy accepts an unknown loader state.
    let target = Target::new(std::ptr::null_mut(), None, 1, LoaderState::Unknown);
    assert!(
        matches!(
            unsafe { Injector::new().inject(target, "x.dll") },
            Err(Error::InvalidTarget(_))
        ),
        "CRT passes the gate and fails later on the null handle"
    );
}

#[test]
#[serial]
fn invalid_handle_and_identity_combinations() {
    // Process/thread mismatch: the thread belongs to another process.
    let first = Child::spawn(&fixtures().entry);
    let second = Child::spawn(&fixtures().entry);
    let mismatched = Target::not_started(
        first.process as *mut c_void,
        Some(second.thread as *mut c_void),
        first.pid,
    );
    assert!(
        matches!(
            unsafe { Injector::new().inject(mismatched, &fixtures().payload) },
            Err(Error::InvalidTarget(_))
        ),
        "a thread of another process must be rejected"
    );
    // The stated pid disagrees with the process handle.
    let wrong_pid = Target::not_started(
        first.process as *mut c_void,
        Some(first.thread as *mut c_void),
        first.pid.wrapping_add(1),
    );
    assert!(
        matches!(
            unsafe { Injector::new().inject(wrong_pid, &fixtures().payload) },
            Err(Error::InvalidTarget(_))
        ),
        "a pid that disagrees with the handle must be rejected"
    );
    // Null thread handle.
    let null_thread = Target::not_started(
        first.process as *mut c_void,
        Some(std::ptr::null_mut()),
        first.pid,
    );
    assert!(
        matches!(
            unsafe { Injector::new().inject(null_thread, &fixtures().payload) },
            Err(Error::InvalidTarget(_))
        ),
        "a null thread handle must be rejected"
    );
    // Self-injection is refused.
    let self_target = Target::not_started(
        unsafe { winapi::um::processthreadsapi::GetCurrentProcess() } as *mut c_void,
        None,
        std::process::id(),
    );
    assert!(
        matches!(
            unsafe { Injector::new().inject(self_target, &fixtures().payload) },
            Err(Error::InvalidTarget(_))
        ),
        "self-injection must be refused"
    );
}

#[test]
#[serial]
fn payload_file_errors() {
    let (child, events) = suspended_entry();
    let target = target_of(&child);
    // Missing file.
    let missing = fixtures().workspace.join("no-such-payload.dll");
    assert!(
        matches!(
            unsafe { Injector::new().inject(target, &missing) },
            Err(Error::DllNotFound(_))
        ),
        "a missing DLL must report DllNotFound"
    );
    // A directory is not a payload.
    assert!(
        matches!(
            unsafe { Injector::new().inject(target, fixtures().workspace.join("src")) },
            Err(Error::UnsupportedPath(_))
        ),
        "a directory must be rejected"
    );
    // An embedded NUL cannot name a real file.
    let nul_path = PathBuf::from(std::ffi::OsString::from_wide(&[
        b'D' as u16,
        b':' as u16,
        b'\\' as u16,
        b'a' as u16,
        0,
        b'b' as u16,
    ]));
    assert!(
        matches!(
            unsafe { Injector::new().inject(target, &nul_path) },
            Err(Error::UnsupportedPath(_))
        ),
        "an embedded NUL must be rejected"
    );
    assert_untouched_and_runs(&child, &events);
}

#[test]
#[serial]
fn unsupported_payload_machines() {
    let (child, events) = suspended_entry();
    let target = target_of(&child);
    assert!(
        matches!(
            unsafe { Injector::new().inject(target, x86_payload()) },
            Err(Error::BitnessMismatch { .. })
        ),
        "an x86 payload must be rejected"
    );
    assert_untouched_and_runs(&child, &events);
    drop(events);

    let (child, events) = suspended_entry();
    let target = target_of(&child);
    assert!(
        matches!(
            unsafe { Injector::new().inject(target, arm64_payload()) },
            Err(Error::UnsupportedMachine(_))
        ),
        "an ARM64 payload must be reported as unsupported"
    );
    assert_untouched_and_runs(&child, &events);
}

#[test]
#[serial]
fn iat_rejects_managed_and_exportless_payloads() {
    let (child, events) = suspended_entry();
    let target = target_of(&child);
    let iat = Injector::with_strategy(Strategy::ImportTableHijack);
    let managed = com_descriptor_payload();
    let result = unsafe { iat.inject(target, &managed) };
    assert!(
        matches!(result, Err(Error::StrategyUnavailable { .. })),
        "a managed image must be refused before mutation, got {result:?}"
    );
    let exportless = exportless_payload();
    let result = unsafe { iat.inject(target, &exportless) };
    assert!(
        matches!(result, Err(Error::StrategyUnavailable { .. })),
        "a payload without exports must be refused, got {result:?}"
    );
    assert_untouched_and_runs(&child, &events);
}

#[test]
#[serial]
fn every_strategy_rejects_managed_payloads_before_loading() {
    let managed = com_descriptor_payload();
    for strategy in [
        Strategy::LoadLibraryRemoteThread,
        Strategy::QueueUserApc,
        Strategy::ImportTableHijack,
    ] {
        let (child, events) = suspended_entry();
        let target = target_of(&child);
        assert!(matches!(
            unsafe { Injector::with_strategy(strategy).inject(target, &managed) },
            Err(Error::StrategyUnavailable { .. })
        ));
        assert_untouched_and_runs(&child, &events);
        events.test.assert_clear("managed payload was refused");
    }
}

#[test]
#[serial]
fn iat_rejects_non_ascii_and_oversized_paths() {
    let fixtures = fixtures();
    let (child, events) = suspended_entry();
    let target = target_of(&child);
    let iat = Injector::with_strategy(Strategy::ImportTableHijack);

    // Non-ASCII directory: PE import names are byte strings.
    let unicode_dir = fixtures
        .workspace
        .join("target")
        .join(profile())
        .join("neg")
        .join("ünïcode");
    std::fs::create_dir_all(&unicode_dir).unwrap();
    let unicode_payload = unicode_dir.join("test_payload.dll");
    std::fs::copy(&fixtures.payload, &unicode_payload).unwrap();
    assert!(
        matches!(
            unsafe { iat.inject(target, &unicode_payload) },
            Err(Error::UnsupportedPath(_))
        ),
        "a non-ASCII IAT path must be rejected"
    );

    // A path longer than MAX_PATH must be rejected up front.
    let long_dir = fixtures
        .workspace
        .join("target")
        .join(profile())
        .join("neg");
    let mut deep = long_dir;
    for _ in 0..14 {
        deep = deep.join("very-long-directory-name-for-the-iat-path-limit");
    }
    std::fs::create_dir_all(&deep).unwrap();
    let long_payload = deep.join("test_payload.dll");
    std::fs::copy(&fixtures.payload, &long_payload).unwrap();
    assert!(
        long_payload.as_os_str().encode_wide().count() > 260,
        "the fixture path must exceed MAX_PATH for this test"
    );
    assert!(
        matches!(
            unsafe { iat.inject(target, &long_payload) },
            Err(Error::UnsupportedPath(_))
        ),
        "an overlong IAT path must be rejected"
    );

    assert_untouched_and_runs(&child, &events);
}
