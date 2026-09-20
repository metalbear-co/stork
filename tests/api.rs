//! End-to-end examples of the common public API flows.
#![cfg(windows)]
mod common;

use common::*;
use std::os::windows::io::AsHandle;
use stork::{BorrowedTarget, Error, Injector, LoadTiming, LoaderState, OwnedTarget};

#[test]
fn default_injection_accepts_standard_borrowed_handles() {
    let child = Child::spawn(&fixtures().rust_target);
    let events = Events::create_all(child.pid);
    child.resume("run loader");
    events.main.wait_object(10_000, "main checkpoint");
    assert_eq!(child.suspend("inject"), 0);

    let target = BorrowedTarget::new(child.as_handle()).unwrap();
    assert_eq!(target.pid(), child.pid);
    let result = unsafe { stork::inject(&target, &fixtures().payload) }.unwrap();
    assert_eq!(result.timing, LoadTiming::Immediate);
    assert_eq!(
        result.module.map(|module| module as usize),
        module_base(child.process, &fixtures().payload)
    );
    events.test.wait_object(10_000, "payload attached");
    assert!(child.alive());
    assert_eq!(child.resume("caller resumes"), 1);
}

#[test]
fn default_injection_accepts_owned_target_directly() {
    let child = Child::spawn(&fixtures().rust_target);
    let events = Events::create_all(child.pid);
    child.resume("run loader");
    events.main.wait_object(10_000, "main checkpoint");
    assert_eq!(child.suspend("inject"), 0);

    let target = OwnedTarget::open_process(child.pid).unwrap();
    assert_eq!(target.pid(), child.pid);
    let result = unsafe { stork::inject(&target, &fixtures().payload) }.unwrap();
    assert_eq!(result.timing, LoadTiming::Immediate);
    drop(target);
    assert!(child.alive());
    assert_eq!(child.resume("caller resumes"), 1);
}

#[test]
fn apc_uses_a_borrowed_primary_thread_and_explicit_handoff() {
    let child = Child::spawn(&fixtures().entry);
    let events = Events::create_all(child.pid);
    let target = BorrowedTarget::new(child.as_handle())
        .unwrap()
        .with_main_thread(child.main_thread_handle());
    // A thread handle alone must not imply a never-run assertion.
    assert!(matches!(
        unsafe { Injector::queue_apc().inject(&target, "unused.dll") },
        Err(Error::StrategyUnavailable { .. })
    ));
    let target = target.with_loader_state(LoaderState::NotStarted);
    let result = unsafe { Injector::queue_apc().inject(&target, &fixtures().payload) }.unwrap();
    assert_eq!(result.timing, LoadTiming::OnResume);
    assert!(result.module.is_none());
    events
        .entry
        .assert_clear("primary thread remains suspended");
    child.resume("caller resumes APC");
    events.pass.wait_object(10_000, "entry observed payload");
}

#[test]
fn iat_uses_a_lifetime_bound_owned_view() {
    let child = Child::spawn(&fixtures().entry);
    let events = Events::create_all(child.pid);
    let owned = OwnedTarget::open_process(child.pid).unwrap();
    let target = owned.borrowed().with_loader_state(LoaderState::NotStarted);
    let result = unsafe { Injector::import_table().inject(&target, &fixtures().payload) }.unwrap();
    assert_eq!(result.timing, LoadTiming::OnResume);
    assert!(result.module.is_none());
    // Non-lexical lifetimes release the borrow after the last use of target.
    drop(owned);
    events.entry.assert_clear("owner drop must not resume");
    assert!(child.alive());
    child.resume("caller resumes IAT");
    events.pass.wait_object(10_000, "entry observed payload");
}

#[test]
fn borrowed_thread_ownership_is_validated_before_loading() {
    let first = Child::spawn(&fixtures().entry);
    let second = Child::spawn(&fixtures().entry);
    let target = BorrowedTarget::new(first.as_handle())
        .unwrap()
        .with_main_thread(second.main_thread_handle())
        .with_loader_state(LoaderState::NotStarted);
    assert!(matches!(
        unsafe { Injector::queue_apc().inject(&target, "unused.dll") },
        Err(Error::InvalidTarget(_))
    ));
    assert!(first.alive() && second.alive());
}

#[test]
fn borrowed_constructor_reports_a_non_process_handle() {
    let event = create_event(std::process::id(), "Local\\stork_api_non_process_");
    let handle = unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(event.handle.cast()) };
    assert!(matches!(
        BorrowedTarget::new(handle),
        Err(Error::Win32 {
            call: "GetProcessId",
            ..
        })
    ));
}
