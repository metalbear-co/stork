#![cfg(windows)]
include!("../../test-support/fixture_events.rs");

/// The IAT fixture imports this named export by ordinal.
#[unsafe(no_mangle)]
pub extern "system" fn stork_payload_marker() -> u32 {
    0x5354_4f52
}

/// Delayed-worker model: waits for the release event, then reports readiness.
unsafe extern "system" fn worker(_: *mut winapi::ctypes::c_void) -> u32 {
    let gate = open(b"Local\\stork_worker_go_");
    if !gate.is_null() {
        unsafe {
            WaitForSingleObject(gate, winapi::um::winbase::INFINITE);
            CloseHandle(gate);
        }
    }
    signal(b"Local\\stork_ready_");
    0
}

/// Signal payload attachment and optionally start a delayed readiness worker.
///
/// DllMain never waits on the worker. The test-only block event models a slow
/// load for pending-outcome tests; the parent releases the event or terminates
/// the process. Other loader notifications leave the payload state untouched.
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _module: *mut winapi::ctypes::c_void,
    reason: u32,
    _reserved: *mut winapi::ctypes::c_void,
) -> i32 {
    if reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        signal(b"Local\\stork_test_");
        let delay = open(b"Local\\stork_delay_");
        if !delay.is_null() {
            unsafe {
                CloseHandle(delay);
                let thread = winapi::um::processthreadsapi::CreateThread(
                    std::ptr::null_mut(),
                    0,
                    Some(worker),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                );
                if !thread.is_null() {
                    CloseHandle(thread);
                }
            }
        } else {
            signal(b"Local\\stork_ready_");
        }
        let block = open(b"Local\\stork_block_");
        if !block.is_null() {
            signal(b"Local\\stork_waiting_");
            unsafe {
                WaitForSingleObject(block, winapi::um::winbase::INFINITE);
                CloseHandle(block);
            }
            signal(b"Local\\stork_unblocked_");
        }
        signal(b"Local\\stork_done_");
    }
    1
}
