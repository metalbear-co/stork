//! Borrowed target views and optional ownership of newly opened handles.

use crate::{Error, Result, error::win32};
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, BorrowedHandle},
};

use winapi::{
    shared::{
        minwindef::FILETIME,
        winerror::{ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES},
    },
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        processthreadsapi::*,
        tlhelp32::*,
        winnt::*,
    },
};

/// The caller's current loader-state assertion. A pid cannot establish this state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderState {
    /// The loader and primary thread have never run. No other injection has advanced them.
    NotStarted,
    /// The primary thread is stopped at a verified early APC delivery point.
    ///
    /// The loader may already have run. The caller must establish that a queued
    /// APC will execute before application logic when this thread continues.
    /// Only APC injection accepts this assertion; an arbitrary debugger entry
    /// stop or suspend count does not establish it.
    EarlyApc,
    /// The loader has completed. The primary thread has already run.
    LoaderComplete,
    /// No loader-state assertion. Only the remote-thread strategy accepts this state.
    Unknown,
}

/// Raw borrowed handles. This type does not enforce a Rust lifetime.
///
/// Keep the owner alive through injection. All strategies need process query, VM read,
/// VM write, and VM operation rights. Remote-thread injection also needs create-thread
/// rights. A supplied thread needs query rights; APC also needs set-context rights.
/// The crate never closes these handles. See [`crate::Injector::inject`] for safety.
#[derive(Debug, Clone, Copy)]
pub struct Target {
    /// Borrowed process handle with the required access rights.
    pub process: *mut c_void,
    /// Borrowed primary-thread handle; required for APC injection.
    pub main_thread: Option<*mut c_void>,
    /// Process identifier, checked against `process` during injection.
    pub pid: u32,
    /// Caller assertion about loader progress, never inferred from a pid.
    pub loader_state: LoaderState,
}

impl Target {
    /// Change the caller's loader-state assertion without changing the handles.
    ///
    /// This does not verify the assertion. The safety contract of injection
    /// still applies, and a never-run assertion must not be reused after an attempt.
    #[must_use]
    pub fn with_loader_state(mut self, loader_state: LoaderState) -> Self {
        self.loader_state = loader_state;
        self
    }

    /// Borrow handles with a caller-attested never-run loader and primary thread.
    pub fn not_started(process: *mut c_void, main_thread: Option<*mut c_void>, pid: u32) -> Self {
        Self::new(process, main_thread, pid, LoaderState::NotStarted)
    }
    /// Borrow a primary thread at a caller-verified early APC delivery point.
    pub fn early_apc(process: *mut c_void, main_thread: *mut c_void, pid: u32) -> Self {
        Self::new(process, Some(main_thread), pid, LoaderState::EarlyApc)
    }
    /// Borrow handles with a caller-attested completed loader state.
    pub fn loader_complete(
        process: *mut c_void,
        main_thread: Option<*mut c_void>,
        pid: u32,
    ) -> Self {
        Self::new(process, main_thread, pid, LoaderState::LoaderComplete)
    }
    /// Create a raw view with an explicit loader-state assertion.
    ///
    /// This constructor neither validates nor takes ownership of the handles.
    pub fn new(
        process: *mut c_void,
        main_thread: Option<*mut c_void>,
        pid: u32,
        loader_state: LoaderState,
    ) -> Self {
        Self {
            process,
            main_thread,
            pid,
            loader_state,
        }
    }
}

impl From<&Target> for Target {
    fn from(target: &Target) -> Self {
        *target
    }
}

/// A target view that keeps standard Rust handle owners borrowed.
///
/// The process id is derived from the process handle. The initial loader state
/// is [`LoaderState::Unknown`]; attaching a thread does not change that assertion.
/// Pass `&BorrowedTarget` directly to [`crate::inject`] or [`crate::Injector::inject`].
/// Injection remains unsafe: lifetimes cannot establish loader state or exclude
/// concurrent resume and loader mutation.
///
/// A borrowed view cannot outlive its handle owner:
///
/// ```compile_fail
/// use std::os::windows::io::{AsHandle, OwnedHandle};
/// use stork::BorrowedTarget;
///
/// fn invalid(process: OwnedHandle) -> stork::Result<()> {
///     let target = BorrowedTarget::new(process.as_handle())?;
///     drop(process);
///     unsafe { stork::inject(&target, "payload.dll") }?;
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct BorrowedTarget<'a> {
    process: BorrowedHandle<'a>,
    main_thread: Option<BorrowedHandle<'a>>,
    pid: u32,
    loader_state: LoaderState,
}

impl<'a> BorrowedTarget<'a> {
    /// Borrow a process handle and query its process id.
    ///
    /// # Errors
    ///
    /// Returns a Windows error if the handle does not support `GetProcessId`.
    /// Full target and architecture validation happens during injection.
    pub fn new(process: BorrowedHandle<'a>) -> Result<Self> {
        let pid = unsafe { GetProcessId(process.as_raw_handle().cast()) };
        if pid == 0 {
            return Err(win32("GetProcessId"));
        }
        Ok(Self {
            process,
            main_thread: None,
            pid,
            loader_state: LoaderState::Unknown,
        })
    }

    /// Borrow the primary-thread handle, required for APC injection.
    ///
    /// Its process ownership is checked during injection.
    #[must_use]
    pub fn with_main_thread(mut self, main_thread: BorrowedHandle<'a>) -> Self {
        self.main_thread = Some(main_thread);
        self
    }

    /// Set a caller-provided loader-state assertion. This does not verify it.
    #[must_use]
    pub fn with_loader_state(mut self, loader_state: LoaderState) -> Self {
        self.loader_state = loader_state;
        self
    }

    /// Return the process id queried from the borrowed handle.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

/// Conversion creates a raw view; it does not extend the handle owners' lifetime.
/// Keep the owners alive if retaining this raw value for a later unsafe call.
impl From<&BorrowedTarget<'_>> for Target {
    fn from(target: &BorrowedTarget<'_>) -> Self {
        Self::new(
            target.process.as_raw_handle(),
            target.main_thread.map(|thread| thread.as_raw_handle()),
            target.pid,
            target.loader_state,
        )
    }
}

pub(crate) struct Handle(pub HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Owns only the handles opened by [`Self::open`]. Drop closes them without resume or termination.
pub struct OwnedTarget {
    process: Handle,
    thread: Option<Handle>,
    pid: u32,
}

impl OwnedTarget {
    /// Open a process for remote-thread or IAT injection without thread discovery.
    ///
    /// The loader state remains unknown. Returns a Windows error if opening fails.
    pub fn open_process(pid: u32) -> Result<Self> {
        Self::open(pid, false)
    }

    /// Open a process and retain its selected primary thread, as needed for APC.
    ///
    /// The loader state remains unknown. See [`Self::open`] for selection errors.
    pub fn open_with_main_thread(pid: u32) -> Result<Self> {
        Self::open(pid, true)
    }

    /// Return the id of the process whose handles this value owns.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Open non-inheritable handles with the union of all strategy access rights.
    ///
    /// `with_main_thread` requests timestamp-based selection of the primary
    /// thread. The process must be stable and its primary thread must still exist.
    ///
    /// # Errors
    ///
    /// Returns a Windows API error or [`Error::AmbiguousPrimaryThread`] when
    /// selection cannot be established. Already opened handles close on failure.
    pub fn open(pid: u32, with_main_thread: bool) -> Result<Self> {
        let process = open_process(pid)?;
        let thread = if with_main_thread {
            Some(
                primary(
                    pid,
                    THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT | SYNCHRONIZE,
                )?
                .0,
            )
        } else {
            None
        };
        Ok(Self {
            process,
            thread,
            pid,
        })
    }
    /// Borrow a view with [`LoaderState::Unknown`].
    ///
    /// Set the loader state only from a trusted handoff, and keep this owner
    /// alive until injection returns.
    pub fn target(&self) -> Target {
        Target::new(
            self.process.0.cast(),
            self.thread.as_ref().map(|h| h.0.cast()),
            self.pid,
            LoaderState::Unknown,
        )
    }

    /// Borrow a lifetime-bound view with [`LoaderState::Unknown`].
    ///
    /// Use `.with_loader_state(...)` on this view for a trusted loader handoff.
    /// Unlike [`Self::target`], this view keeps `self` borrowed while in use.
    ///
    /// ```compile_fail
    /// use stork::{InjectedModule, OwnedTarget, Result};
    ///
    /// fn invalid(owned: OwnedTarget) -> Result<InjectedModule> {
    ///     let view = owned.borrowed();
    ///     drop(owned);
    ///     unsafe { stork::inject(&view, "payload.dll") }
    /// }
    /// ```
    pub fn borrowed(&self) -> BorrowedTarget<'_> {
        BorrowedTarget {
            // These handles are owned by self and remain valid for this borrow.
            process: unsafe { BorrowedHandle::borrow_raw(self.process.0.cast()) },
            main_thread: self
                .thread
                .as_ref()
                .map(|thread| unsafe { BorrowedHandle::borrow_raw(thread.0.cast()) }),
            pid: self.pid,
            loader_state: LoaderState::Unknown,
        }
    }
}

impl From<&OwnedTarget> for Target {
    fn from(target: &OwnedTarget) -> Self {
        target.target()
    }
}

fn open_process(pid: u32) -> Result<Handle> {
    let h = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | SYNCHRONIZE,
            0,
            pid,
        )
    };
    if h.is_null() {
        return Err(win32("OpenProcess"));
    }
    Ok(Handle(h))
}

/// Find the unique lowest-creation-time thread of a stable process.
///
/// The primary thread must still be alive. The returned id can expire or be
/// reused; use [`OwnedTarget`] to retain the selected handle.
///
/// # Errors
///
/// Equal minima, incomplete snapshots, and terminated candidates fail selection.
/// Windows API failures retain their call name and underlying OS error.
pub fn find_primary_thread_id(pid: u32) -> Result<u32> {
    let _process = open_process(pid)?;
    Ok(primary(pid, THREAD_QUERY_INFORMATION | SYNCHRONIZE)?.1)
}

fn earliest(times: &[u64]) -> Result<usize> {
    let min = times.iter().min().ok_or(Error::AmbiguousPrimaryThread)?;
    let mut matches = times.iter().enumerate().filter(|(_, v)| *v == min);
    let index = matches.next().unwrap().0;
    if matches.next().is_some() {
        return Err(Error::AmbiguousPrimaryThread);
    }
    Ok(index)
}

fn primary(pid: u32, rights: u32) -> Result<(Handle, u32)> {
    for attempt in 0..3 {
        match primary_once(pid, rights) {
            Err(Error::Win32 { source, .. })
                if source.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) && attempt < 2 =>
            {
                continue;
            }
            result => return result,
        }
    }
    Err(Error::AmbiguousPrimaryThread)
}

fn primary_once(pid: u32, rights: u32) -> Result<(Handle, u32)> {
    unsafe {
        let raw = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if raw == INVALID_HANDLE_VALUE {
            return Err(win32("CreateToolhelp32Snapshot"));
        }
        let snapshot = Handle(raw);
        let mut entry: THREADENTRY32 = zeroed();
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        if Thread32First(snapshot.0, &mut entry) == 0 {
            return Err(win32("Thread32First"));
        }
        let mut candidates = Vec::new();
        let mut times = Vec::new();
        loop {
            if entry.th32OwnerProcessID == pid {
                let raw = OpenThread(rights, 0, entry.th32ThreadID);
                if raw.is_null() {
                    return Err(win32("OpenThread"));
                }
                let h = Handle(raw);
                let owner = GetProcessIdOfThread(h.0);
                if owner == 0 {
                    return Err(win32("GetProcessIdOfThread"));
                }
                if owner != pid {
                    return Err(Error::AmbiguousPrimaryThread);
                }
                let mut created: FILETIME = zeroed();
                let mut exit: FILETIME = zeroed();
                let mut kernel: FILETIME = zeroed();
                let mut user: FILETIME = zeroed();
                if GetThreadTimes(h.0, &mut created, &mut exit, &mut kernel, &mut user) == 0 {
                    return Err(win32("GetThreadTimes"));
                }
                if exit.dwHighDateTime != 0 || exit.dwLowDateTime != 0 {
                    return Err(Error::AmbiguousPrimaryThread);
                }
                times.push(
                    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
                );
                candidates.push((h, entry.th32ThreadID));
            }
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            if Thread32Next(snapshot.0, &mut entry) == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                    return Err(crate::error::from_win32("Thread32Next", error));
                }
                break;
            }
        }
        let index = earliest(&times)?;
        // Revalidate all retained candidates. Never select an accessible survivor silently.
        for (h, _) in &candidates {
            match winapi::um::synchapi::WaitForSingleObject(h.0, 0) {
                winapi::shared::winerror::WAIT_TIMEOUT => {}
                winapi::um::winbase::WAIT_FAILED => {
                    return Err(win32("WaitForSingleObject primary thread"));
                }
                _ => return Err(Error::AmbiguousPrimaryThread),
            }
        }
        Ok(candidates.swap_remove(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timestamp_selection() {
        assert_eq!(earliest(&[8, 2, 5]).unwrap(), 1);
        assert!(earliest(&[2, 2]).is_err());
        assert!(earliest(&[]).is_err());
    }
}
