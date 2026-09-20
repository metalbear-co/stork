//! Import-table strategy integration tests.
#![cfg(windows)]
mod common;

use std::ffi::c_void;

use common::*;
use serial_test::serial;
use stork::{Injector, LoadTiming, Strategy, Target};

/// Rewrite the imports of a never-run target, resume once, and observe that
/// the loader mapped the payload and ran its DllMain before the real PE entry.
/// The entry fixture calls Kernel32 functions, so this also proves the
/// original imports still resolve after the rewrite.
#[test]
#[serial]
fn iat_not_started_rewrites_and_loads_before_entry() {
    let fixtures = fixtures();
    let child = Child::spawn(&fixtures.entry);
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut c_void,
        Some(child.thread as *mut c_void),
        child.pid,
    );
    let injected = unsafe {
        Injector::with_strategy(Strategy::ImportTableHijack).inject(target, &fixtures.payload)
    }
    .expect("IAT injection");
    assert_eq!(injected.timing, LoadTiming::OnResume);
    assert!(injected.module.is_none(), "IAT cannot know a module yet");

    events.test.assert_clear("payload before resume");
    events.ready.assert_clear("readiness before resume");
    events.entry.assert_clear("entry before resume");

    child.resume("iat not-started");
    events
        .test
        .wait_object(10_000, "payload DllMain after resume");
    events.entry.wait_object(10_000, "entry after resume");
    events
        .pass
        .wait_object(10_000, "entry observed the payload before its own code");
    events
        .ready_at_entry
        .wait_object(10_000, "readiness preceded entry");
    assert!(module_loaded(child.process, &fixtures.payload));
}

/// The no-import fixture has no import directory and no IAT directory. The
/// injection must still append the payload descriptor and the loader must map
/// the payload during process initialization.
#[test]
#[serial]
fn iat_target_without_imports() {
    let fixtures = fixtures();
    let child = Child::spawn(&fixtures.noimport);
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut c_void,
        Some(child.thread as *mut c_void),
        child.pid,
    );
    let injected = unsafe {
        Injector::with_strategy(Strategy::ImportTableHijack).inject(target, &fixtures.payload)
    }
    .expect("IAT injection into an import-free image");
    assert_eq!(injected.timing, LoadTiming::OnResume);

    events.test.assert_clear("payload before resume");
    child.resume("iat no-imports");
    events
        .test
        .wait_object(10_000, "payload DllMain after resume");
    events
        .ready
        .wait_object(10_000, "synchronous payload readiness");
    assert!(module_loaded(child.process, &fixtures.payload));
}
