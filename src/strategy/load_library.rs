use crate::{
    Error, InjectedModule, LoadTiming, Result, Strategy, Target,
    error::{combine, win32},
    paths,
    payload::Payload,
    remote::{self, RemoteAlloc},
    target::Handle,
};

use std::{path::Path, ptr::null_mut};
use winapi::{
    shared::winerror::WAIT_TIMEOUT,
    um::{
        processthreadsapi::CreateRemoteThread, synchapi::WaitForSingleObject,
        winbase::WAIT_OBJECT_0,
    },
};
pub(crate) fn inject(target: &Target, payload: &Payload) -> Result<InjectedModule> {
    inject_timeout(target, payload.path(), 30_000)
}
fn inject_timeout(target: &Target, path: &Path, timeout: u32) -> Result<InjectedModule> {
    inject_with_wait(target, path, |thread, _| {
        match unsafe { WaitForSingleObject(thread, timeout) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(Error::RemoteTimeout),
            winapi::um::winbase::WAIT_FAILED => {
                Err(Error::RemotePending(std::io::Error::last_os_error()))
            }
            result => Err(Error::RemotePending(std::io::Error::other(format!(
                "unexpected thread wait result: {result:#x}"
            )))),
        }
    })
}

fn inject_with_wait(
    target: &Target,
    path: &Path,
    wait: impl FnOnce(winapi::um::winnt::HANDLE, usize) -> Result<()>,
) -> Result<InjectedModule> {
    let address = remote::load_library_address(target, Strategy::LoadLibraryRemoteThread)?;
    let wide = paths::wide(path)?;
    let bytes = dataview::bytes(wide.as_bytes_with_nul());
    let mut allocation = RemoteAlloc::with_bytes(target.process.cast(), bytes)?;
    let thread = unsafe {
        CreateRemoteThread(
            target.process.cast(),
            null_mut(),
            0,
            Some(std::mem::transmute::<
                usize,
                unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> u32,
            >(address)),
            allocation.address as _,
            0,
            null_mut(),
        )
    };
    if thread.is_null() {
        let error = win32("CreateRemoteThread");
        return combine(Err(error), allocation.release());
    }
    allocation.retain(); // The thread can still read this buffer on timeout or wait failure.
    let thread = Handle(thread);
    wait(thread.0, allocation.address)?;
    let result = remote::find_module(target.process.cast(), path);
    let cleanup = allocation.release();
    combine(result, cleanup).map(|module| InjectedModule {
        module: Some(module as _),
        timing: LoadTiming::Immediate,
    })
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]
    use super::*;
    use crate::target::Handle;

    include!("../../test-support/harness.rs");

    fn spawn_suspended_cmd() -> Child {
        Child::spawn(std::path::Path::new(r"C:\Windows\System32\cmd.exe"))
    }

    #[test]
    fn timeout_retains_argument_and_eventually_completes() {
        let payload = &fixtures().payload;
        let child = spawn_suspended_cmd();
        let test_event = create_event(child.pid, "Local\\stork_test_");
        let ready_event = create_event(child.pid, "Local\\stork_ready_");
        let block_event = create_event(child.pid, "Local\\stork_block_");
        let done_event = create_event(child.pid, "Local\\stork_done_");
        let unblocked_event = create_event(child.pid, "Local\\stork_unblocked_");
        let process = Handle(open_process(child.pid));
        let target = Target::not_started(process.0.cast(), None, child.pid);

        let result =
            inject_timeout(&target, payload, 2_000).expect_err("the blocked load must time out");
        assert!(
            matches!(result, Error::RemoteTimeout),
            "unexpected error: {result:?}"
        );

        // The remote thread reached DllMain and is blocked inside it. The
        // timed-out load has not finished: no completion event yet.
        assert!(
            test_event.wait(5_000),
            "DllMain must run on the remote thread"
        );
        assert!(
            ready_event.wait(1_000),
            "DllMain must signal readiness before blocking"
        );
        assert!(
            !done_event.wait(0),
            "the timed-out load must not have completed"
        );

        // Release the fixture: the original remote thread resumes inside
        // DllMain, returns, and LoadLibraryW completes. No second injection
        // happened between the timeout and this release.
        block_event.signal();
        assert!(
            unblocked_event.wait(10_000),
            "the DllMain block wait must return after the release"
        );
        assert!(
            done_event.wait(15_000),
            "the original load must complete after release"
        );
        let deadline = std::time::Instant::now();
        loop {
            if module_loaded(process.0, payload) {
                break;
            }
            assert!(
                deadline.elapsed().as_secs() < 15,
                "the payload module must be listed"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[test]
    fn wait_failure_keeps_the_original_load_pending() {
        let child = spawn_suspended_cmd();
        let payload = &fixtures().payload;
        let block = create_event(child.pid, "Local\\stork_block_");
        let waiting = create_event(child.pid, "Local\\stork_waiting_");
        let done = create_event(child.pid, "Local\\stork_done_");
        let target = Target::not_started(child.process.cast(), None, child.pid);
        let mut retained_address = 0;
        let error = inject_with_wait(&target, payload, |_, address| {
            retained_address = address;
            waiting.wait_object(10_000, "blocked DllMain");
            Err(Error::RemotePending(std::io::Error::from_raw_os_error(6)))
        })
        .unwrap_err();
        assert!(
            matches!(error, Error::RemotePending(ref source) if source.raw_os_error() == Some(6))
        );
        done.assert_clear("load completion after failed wait");
        assert_eq!(
            remote::query(child.process, retained_address)
                .unwrap()
                .State,
            winapi::um::winnt::MEM_COMMIT
        );
        let expected: Vec<_> = paths::wide(payload)
            .unwrap()
            .as_bytes_with_nul()
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(
            remote::read(child.process, retained_address, expected.len()).unwrap(),
            expected
        );
        block.signal();
        done.wait_object(10_000, "original load completion");
        assert!(module_loaded(child.process, payload));
    }
}
