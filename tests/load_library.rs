//! LoadLibrary remote-thread strategy integration tests.
#![cfg(windows)]
mod common;

use std::ffi::c_void;

use common::*;
use serial_test::serial;
use stork::{Injector, LoadTiming, Target};

#[test]
#[serial]
fn crt_not_started_loads_before_entry() {
    let fixtures = fixtures();
    let child = Child::spawn(&fixtures.entry);
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut c_void,
        Some(child.thread as *mut c_void),
        child.pid,
    );
    let injected = unsafe { Injector::new().inject(target, &fixtures.payload) }
        .expect("remote-thread injection");
    assert_eq!(injected.timing, LoadTiming::Immediate);
    let module = injected.module.expect("immediate module") as usize;
    assert_ne!(module, 0, "module address must be non-null");

    // DllMain ran on the remote thread while the primary stayed suspended.
    events
        .test
        .wait_object(10_000, "payload DllMain before resume");
    events
        .ready
        .wait_object(10_000, "synchronous payload readiness");
    events.entry.assert_clear("entry before resume");
    // Full-width remote address: the payload base from module enumeration.
    assert_eq!(
        module_base(child.process, &fixtures.payload),
        Some(module),
        "reported module does not match the enumerated payload base"
    );

    child.resume("crt not-started");
    events.entry.wait_object(10_000, "entry after resume");
    events
        .pass
        .wait_object(10_000, "entry observed the loaded payload");
    events
        .ready_at_entry
        .wait_object(10_000, "readiness preceded entry");
}

#[test]
#[serial]
fn crt_after_loader_completion() {
    let fixtures = fixtures();
    let child = Child::spawn(&fixtures.rust_target);
    let events = Events::create_all(child.pid);

    // Deterministic checkpoint: the Rust target signals main once the loader
    // has run. No arbitrary sleep.
    child.resume("loader-complete checkpoint");
    events.main.wait_object(10_000, "main checkpoint");

    let count = child.suspend("loader-complete inject");
    assert_eq!(count, 0, "the primary thread must not be nested-suspended");
    let target = Target::loader_complete(
        child.process as *mut c_void,
        Some(child.thread as *mut c_void),
        child.pid,
    );
    let injected = unsafe { Injector::new().inject(target, &fixtures.payload) }
        .expect("remote-thread injection into a running target");
    assert_eq!(injected.timing, LoadTiming::Immediate);
    assert!(injected.module.is_some());
    events
        .test
        .wait_object(10_000, "payload DllMain while suspended");
    assert!(module_loaded(child.process, &fixtures.payload));

    assert_eq!(child.resume("loader-complete release"), 1);
    // The payload stays loaded and the target keeps running.
    assert!(child.alive());
}

/// The delayed-worker payload models mirrord's layer: DllMain completes and
/// returns before the worker reports readiness. The events expose the race:
/// readiness must follow the entry point, not precede it.
#[test]
#[serial]
fn crt_delayed_worker_readiness_follows_entry() {
    let fixtures = fixtures();
    let child = Child::spawn(&fixtures.entry);
    let events = Events::create_all(child.pid);
    // Arm the payload's delayed-worker model before injection.
    let _delay = create_event(child.pid, "Local\\stork_delay_");
    let worker_go = create_event(child.pid, "Local\\stork_worker_go_");

    let target = Target::not_started(
        child.process as *mut c_void,
        Some(child.thread as *mut c_void),
        child.pid,
    );
    let injected = unsafe { Injector::new().inject(target, &fixtures.payload) }
        .expect("remote-thread injection");
    assert_eq!(injected.timing, LoadTiming::Immediate);

    // DllMain completed synchronously on the remote thread...
    events
        .test
        .wait_object(10_000, "payload DllMain before resume");
    events
        .ready
        .assert_clear("readiness before the worker release");
    events.entry.assert_clear("entry before resume");

    child.resume("delayed-worker resume");
    events.entry.wait_object(10_000, "entry after resume");
    // ...while the worker still waits. Entry ran before readiness.
    events
        .ready
        .assert_clear("readiness raced ahead of the worker");
    events
        .ready_at_entry
        .assert_clear("entry must not observe readiness");

    worker_go.signal();
    events
        .ready
        .wait_object(10_000, "readiness after the worker release");
    assert!(module_loaded(child.process, &fixtures.payload));
}
