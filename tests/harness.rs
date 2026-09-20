//! Regression tests for the process harness itself.
#![cfg(windows)]
mod common;

use common::*;

#[test]
fn tool_supervisor_terminates_descendants_on_timeout_and_success() {
    use std::{process::Command, time::Duration};
    for mode in ["wait", "exit"] {
        let pid_file = real_target_dir().join(format!("descendant_{mode}.txt"));
        let result = command_output(
            Command::new(&fixtures().rust_target).args([
                "--stork-tool-descendant",
                pid_file.to_str().unwrap(),
                mode,
            ]),
            Duration::from_secs(2),
        );
        if mode == "exit" {
            assert!(result.unwrap().status.success());
        } else {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        }
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap()
            .parse::<u32>()
            .unwrap();
        // A terminated child may already have lost its last handle and disappeared.
        unsafe {
            let process =
                winapi::um::processthreadsapi::OpenProcess(winapi::um::winnt::SYNCHRONIZE, 0, pid);
            if !process.is_null() {
                // Job accounting can reach zero before the process handle is signaled.
                let wait = winapi::um::synchapi::WaitForSingleObject(process, 5_000);
                winapi::um::handleapi::CloseHandle(process);
                assert_eq!(wait, 0, "descendant {pid} survived supervisor cleanup");
            } else {
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(87));
            }
        }
    }
}

#[test]
fn child_drop_confirms_process_termination() {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    let child = Child::spawn(&fixtures().rust_target);
    let observer = unsafe { OwnedHandle::from_raw_handle(open_process(child.pid).cast()) };
    drop(child);
    assert_eq!(
        unsafe { winapi::um::synchapi::WaitForSingleObject(observer.as_raw_handle().cast(), 0) },
        0,
        "child must be signaled after teardown"
    );
}

#[test]
fn tool_supervisor_captures_nonzero_exit_and_times_out() {
    use std::{
        process::Command,
        time::{Duration, Instant},
    };
    let output = command_output(
        Command::new(&fixtures().rust_target).arg("--stork-tool-output"),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(output.status.code(), Some(17));
    assert!(String::from_utf8_lossy(&output.stdout).contains("captured stdout"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("captured stderr"));
    let start = Instant::now();
    let error = command_output(
        &mut Command::new(&fixtures().rust_target),
        Duration::from_millis(100),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(!error.to_string().contains("cleanup failed"), "{error}");
    assert!(start.elapsed() < Duration::from_secs(7));
}

#[test]
fn suspended_child_receives_quoted_arguments_exactly() {
    let child = Child::spawn_with_args(
        &fixtures().rust_target,
        &[
            "--stork-check-args",
            "",
            "space value",
            "embedded\"quote",
            "trailing\\",
            "\\\\\"mixed",
            "日本語",
            "\u{1f980}",
        ],
    );
    let events = Events::create_all(child.pid);
    events.main.assert_clear("main before resume");
    child.resume("argument round trip");
    events
        .main
        .wait_object(10_000, "target validated every argument");
}

#[test]
#[should_panic(expected = "event wait failed")]
fn invalid_event_is_not_reported_as_unsignaled() {
    let event = NamedEvent {
        handle: std::ptr::null_mut(),
    };
    event.assert_clear("invalid event");
}

#[test]
fn event_names_preserve_non_bmp_characters() {
    let pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
    let prefix = "Local\\stork_unicode_\u{1f980}_";
    let event = create_event(pid, prefix);
    // Encode independently to verify that the named Windows object matches.
    let expected: Vec<u16> = format!("{prefix}{pid}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let opened = unsafe {
        winapi::um::synchapi::OpenEventW(
            winapi::um::winnt::EVENT_MODIFY_STATE,
            0,
            expected.as_ptr(),
        )
    };
    assert!(!opened.is_null(), "Unicode event could not be reopened");
    let observer = NamedEvent { handle: opened };
    observer.signal();
    assert!(event.is_set());
}
