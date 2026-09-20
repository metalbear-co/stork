//! QueueUserAPC strategy integration tests.
#![cfg(windows)]
mod common;

use std::ffi::c_void;

use common::*;
use serial_test::serial;
use stork::{
    Injector, LoadTiming, LoaderState, OwnedTarget, Strategy, Target, find_primary_thread_id,
};

#[test]
#[serial]
fn apc_not_started_queues_and_fires_before_entry() {
    let fixtures = fixtures();
    let child = Child::spawn(&fixtures.entry);
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut c_void,
        Some(child.thread as *mut c_void),
        child.pid,
    );
    let injected = unsafe {
        Injector::with_strategy(Strategy::QueueUserApc).inject(target, &fixtures.payload)
    }
    .expect("APC queue");
    assert_eq!(injected.timing, LoadTiming::OnResume);
    assert!(injected.module.is_none(), "APC cannot know a module yet");

    // Nothing loaded before the resume: the APC fires on first thread run.
    events.test.assert_clear("payload before resume");
    events.ready.assert_clear("readiness before resume");
    events.entry.assert_clear("entry before resume");

    child.resume("apc not-started");
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

/// The attach flow: only a pid. Resolve the process and the primary thread,
/// attest the never-run handoff, queue the APC, then resume.
#[test]
#[serial]
fn attach_style_pid_resolution_and_apc() {
    let fixtures = fixtures();
    let child = Child::spawn(&fixtures.entry);
    let events = Events::create_all(child.pid);

    let resolved = find_primary_thread_id(child.pid).expect("primary thread id");
    assert_eq!(
        resolved,
        child.thread_id(),
        "timestamp selection picked another thread"
    );

    let owned = OwnedTarget::open_with_main_thread(child.pid).expect("open primary thread");
    // The pid cannot certify the loader state. The caller attests the trusted
    // never-run handoff on the borrowed view.
    let target = owned.target().with_loader_state(LoaderState::NotStarted);
    let injected = unsafe {
        Injector::with_strategy(Strategy::QueueUserApc).inject(target, &fixtures.payload)
    }
    .expect("attach-style APC queue");
    assert_eq!(injected.timing, LoadTiming::OnResume);
    events.test.assert_clear("payload before resume");

    // Dropping OwnedTarget closes only its own handles: the queued APC stays,
    // the process is neither resumed nor terminated.
    drop(owned);
    assert!(
        child.alive(),
        "OwnedTarget drop must not terminate the process"
    );
    events
        .entry
        .assert_clear("OwnedTarget drop must not resume the process");

    // The IDE-side resume uses the caller's own thread handle.
    child.resume("attach-style resume");
    events
        .test
        .wait_object(10_000, "payload DllMain after resume");
    events
        .pass
        .wait_object(10_000, "entry observed the payload");
    events.entry.wait_object(10_000, "entry after resume");
    assert!(module_loaded(child.process, &fixtures.payload));
}
