//! The locked comment below cites a bare URL; the text is frozen verbatim,
//! so the bare-URL lint is disabled for this module only.
#![allow(rustdoc::bare_urls)]
//! # Why QueueUserAPC is reliable here
//!
//! A user-mode APC normally runs only when the target thread enters an alertable wait
//! (SleepEx, WaitForSingleObjectEx, WaitForMultipleObjectsEx, MsgWaitForMultipleObjectsEx,
//! SignalObjectAndWait). A thread that never waits alertably never runs the APC. That is why
//! naive APC injection into a live, already-running thread is unreliable.
//!
//! mirrord's targets are ALWAYS suspended before their first instruction of user code
//! (CREATE_SUSPENDED for exec/pitm; IDE-suspended-before-run for attach). We queue the APC
//! while the thread is still suspended, i.e. before it begins running. Per the documented
//! behavior, such a thread STARTS by calling the queued APC when it first begins running -- no
//! alertable wait is required. The caller's ResumeThread is the trigger.
//!
//! "If an application queues an APC before the thread begins running, the thread begins by
//!  calling the APC function."
//!   -- https://dennisbabkin.com/blog/?t=windows-apc-deep-dive-into-user-mode-asynchronous-procedure-calls
//!
//! Failure mode that does NOT apply here: a thread already running normal code that never
//! enters an alertable wait will not run the APC. mirrord avoids this by always queuing the
//! APC before the thread's first run.

//!
//! Microsoft reference: <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc>.
//! The never-run handoff is a caller-attested precondition, not a crate-verified fact.
//! The queued path stays allocated until process exit. The caller must retain the DLL and
//! readiness resources until loading completes. Do not retry or queue a fallback after success.
use crate::{
    Error, InjectedModule, LoadTiming, Result, Strategy, Target,
    error::{combine, win32},
    paths,
    payload::Payload,
    remote::{self, RemoteAlloc},
};
use winapi::um::processthreadsapi::QueueUserAPC;
// The frozen module explanation describes NotStarted. EarlyApc is a separate
// caller attestation of pre-application delivery, covered by the debugger test.
pub(crate) fn inject(target: &Target, payload: &Payload) -> Result<InjectedModule> {
    let thread = target.main_thread.ok_or(Error::MissingThreadHandle)?;
    let address = remote::load_library_address(target, Strategy::QueueUserApc)?;
    let wide = paths::wide(payload.path())?;
    let bytes = dataview::bytes(wide.as_bytes_with_nul());
    let mut allocation = RemoteAlloc::with_bytes(target.process.cast(), bytes)?;
    if unsafe {
        QueueUserAPC(
            Some(std::mem::transmute::<usize, unsafe extern "system" fn(usize)>(address)),
            thread.cast(),
            allocation.address,
        )
    } == 0
    {
        let error = win32("QueueUserAPC");
        return combine(Err(error), allocation.release());
    }
    allocation.retain();
    Ok(InjectedModule {
        module: None,
        timing: LoadTiming::OnResume,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    mod support {
        #![allow(dead_code)]
        include!("../../test-support/harness.rs");
    }
    use support::*;
    use winapi::um::{debugapi::*, minwinbase::*, winbase::DEBUG_ONLY_THIS_PROCESS};

    struct Debugged {
        child: Child,
        pending: Option<DEBUG_EVENT>,
    }

    impl Debugged {
        fn next(&mut self) -> Option<u32> {
            self.continue_event();
            let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEvent(&mut event, 100) } == 0 {
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(121));
                return None;
            }
            unsafe {
                let file = match event.dwDebugEventCode {
                    CREATE_PROCESS_DEBUG_EVENT => event.u.CreateProcessInfo().hFile,
                    LOAD_DLL_DEBUG_EVENT => event.u.LoadDll().hFile,
                    _ => std::ptr::null_mut(),
                };
                if !file.is_null() {
                    winapi::um::handleapi::CloseHandle(file);
                }
            }
            let code = event.dwDebugEventCode;
            self.pending = Some(event);
            Some(code)
        }

        fn continue_event(&mut self) {
            if let Some(event) = self.pending.take() {
                assert_ne!(
                    unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, 0x0001_0002) },
                    0
                );
            }
        }
    }

    impl Drop for Debugged {
        fn drop(&mut self) {
            // Detach before Child terminates, so debug-event suspension cannot block reaping.
            if let Some(event) = self.pending.take() {
                unsafe {
                    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, 0x0001_0002);
                }
            }
            unsafe {
                DebugActiveProcessStop(self.child.pid);
            }
        }
    }

    #[test]
    fn apc_at_initial_debugger_breakpoint_runs_before_entry() {
        let child = spawn_suspended_with_flags(&fixtures().entry, &[], DEBUG_ONLY_THIS_PROCESS);
        let events = Events::create_all(child.pid);
        let mut debugger = Debugged {
            child,
            pending: None,
        };
        debugger
            .child
            .resume("reach native initial debugger breakpoint");
        let start = std::time::Instant::now();
        loop {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "no initial debugger breakpoint"
            );
            if debugger.next() == Some(EXCEPTION_DEBUG_EVENT) {
                let event = debugger.pending.as_ref().unwrap();
                assert_eq!(
                    unsafe { event.u.Exception().ExceptionRecord.ExceptionCode },
                    0x8000_0003
                );
                assert_eq!(event.dwThreadId, debugger.child.thread_id());
                break;
            }
        }
        events
            .entry
            .assert_clear("no application entry before the native breakpoint");
        let target = Target::early_apc(
            debugger.child.process.cast(),
            debugger.child.thread.cast(),
            debugger.child.pid,
        );
        assert!(matches!(
            unsafe { crate::Injector::import_table().inject(target, &fixtures().payload) },
            Err(Error::StrategyUnavailable { .. })
        ));
        let _queued =
            unsafe { crate::Injector::queue_apc().inject(target, &fixtures().payload) }.unwrap();
        let start = std::time::Instant::now();
        debugger.continue_event();
        while !events.entry.wait(0) {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "entry did not run"
            );
            debugger.next();
        }
        events.test.wait_object(0, "APC loaded the payload");
        events
            .pass
            .wait_object(0, "PE entry observed the payload already loaded");
    }
}
