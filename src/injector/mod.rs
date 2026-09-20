//! Validate a payload and dispatch one explicit injection strategy.

use crate::{Error, LoaderState, Result, Strategy, Target, payload::Payload, remote};
use std::{ffi::c_void, path::Path};

/// The point at which loading is confirmed or prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadTiming {
    /// The DLL is present and the LoadLibrary thread has terminated.
    Immediate,
    /// Loading is prepared. Resume and confirm success through a caller-owned protocol.
    OnResume,
}

/// A non-owning remote module address and load timing.
///
/// [`LoadTiming::Immediate`] carries a module address; [`LoadTiming::OnResume`]
/// does not. Dropping this value does not unload the DLL. DLL load does not prove
/// that an asynchronous payload worker is ready.
#[derive(Debug, Clone, Copy)]
#[must_use = "inspect load timing before deciding when to resume and wait for readiness"]
pub struct InjectedModule {
    /// Non-owning remote address. Never pass it to local `CloseHandle` or `FreeLibrary`.
    pub module: Option<*mut c_void>,
    /// Whether loading completed during injection or was prepared for resume.
    pub timing: LoadTiming,
}

/// An explicit injection strategy. The default uses a remote LoadLibrary thread.
#[derive(Debug, Default)]
#[must_use]
pub struct Injector {
    strategy: Strategy,
}

impl Injector {
    /// Create an injector using [`Strategy::LoadLibraryRemoteThread`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an injector that queues loading before application execution.
    ///
    /// Successful injection returns [`LoadTiming::OnResume`]. The caller must
    /// provide the primary-thread handle and attest [`LoaderState::NotStarted`]
    /// or a verified [`LoaderState::EarlyApc`] handoff.
    pub fn queue_apc() -> Self {
        Self::with_strategy(Strategy::QueueUserApc)
    }

    /// Create an injector that rewrites imports in a never-run target.
    ///
    /// Successful injection returns [`LoadTiming::OnResume`]. The caller must
    /// attest [`LoaderState::NotStarted`]; the payload must export ordinal 1.
    pub fn import_table() -> Self {
        Self::with_strategy(Strategy::ImportTableHijack)
    }

    /// Create an injector using `strategy`, without automatic fallback.
    pub fn with_strategy(strategy: Strategy) -> Self {
        Self { strategy }
    }

    /// Return the selected strategy.
    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// Inject or prepare a DLL load. The caller owns process creation and resume.
    ///
    /// # Arguments
    ///
    /// `target` accepts a raw [`Target`] or a reference to [`Target`],
    /// [`crate::BorrowedTarget`], or [`crate::OwnedTarget`]. It carries the handles
    /// and current loader-state assertion. An owned target passed directly has
    /// [`LoaderState::Unknown`]; use its borrowed view to attest another state.
    /// `dll_path` names a native AMD64 DLL. IAT requires an ASCII absolute path and export ordinal 1.
    ///
    /// # Returns
    ///
    /// A confirmed remote module or an armed load. `OnResume` is not proof of load or readiness.
    ///
    /// # Errors
    ///
    /// Returns validation, file I/O, Windows API, or cleanup errors. Payload reads
    /// are bounded to 512 MiB. [`Error::is_pending`] identifies loads that must
    /// not be retried blindly; [`Error::must_not_resume`] identifies failed
    /// rollback or protection restoration, including nested cleanup failures.
    ///
    /// # Safety
    ///
    /// Keep all handles valid and their owners alive through this call. Recycled handles
    /// cannot be detected reliably. The handles must identify the stated process and primary
    /// thread, with the rights documented on `Target`. Exclude concurrent injection, loader
    /// mutation, resume, handle close, and image unmapping. For `NotStarted`, attest that the
    /// primary thread and loader have never run and no other injection has advanced them.
    /// For `EarlyApc`, attest that continuing the stopped primary thread will
    /// dispatch this APC before application logic. A debugger's generic
    /// stop-on-entry setting alone does not establish that delivery ordering.
    /// Do not reuse that assertion after an injection attempt. The payload must be trusted
    /// executable code that is compatible with the target. Self-injection is refused.
    ///
    /// For the fresh-child startup exception, use Windows 11 build 26200 native AMD64 with
    /// standard system DLL loading. Other absent-module cases return `StrategyUnavailable`.
    pub unsafe fn inject(
        &self,
        target: impl Into<Target>,
        dll_path: impl AsRef<Path>,
    ) -> Result<InjectedModule> {
        let target = target.into();
        gate(self.strategy, &target)?;
        remote::validate(&target)?;
        let payload = Payload::load(dll_path.as_ref(), self.strategy)?;
        match self.strategy {
            Strategy::LoadLibraryRemoteThread => crate::strategy::load_library(&target, &payload),
            Strategy::QueueUserApc => crate::strategy::queue_apc(&target, &payload),
            Strategy::ImportTableHijack => crate::strategy::import_table(&target, &payload),
        }
    }
}

/// Inject with the default remote-thread strategy.
///
/// Equivalent to `Injector::new().inject(target, dll_path)`. Accepts the same
/// target views, returns [`LoadTiming::Immediate`] on success, and never resumes
/// the primary thread. Use [`Injector::queue_apc`] or [`Injector::import_table`]
/// when loading should be prepared for the caller's resume.
///
/// # Errors
///
/// See [`Injector::inject`], [`Error::is_pending`], and [`Error::must_not_resume`].
///
/// # Safety
///
/// The full [`Injector::inject`] safety contract applies: valid handles, a stable
/// target and trusted payload, exclusive loader access, and truthful loader-state
/// assertions. A never-run assertion must not be reused after an injection attempt.
pub unsafe fn inject(
    target: impl Into<Target>,
    dll_path: impl AsRef<Path>,
) -> Result<InjectedModule> {
    unsafe { Injector::new().inject(target, dll_path) }
}

fn gate(strategy: Strategy, target: &Target) -> Result<()> {
    if strategy == Strategy::QueueUserApc && target.main_thread.is_none() {
        return Err(Error::MissingThreadHandle);
    }
    let allowed = match strategy {
        Strategy::LoadLibraryRemoteThread => target.loader_state != LoaderState::EarlyApc,
        Strategy::QueueUserApc => matches!(
            target.loader_state,
            LoaderState::NotStarted | LoaderState::EarlyApc
        ),
        Strategy::ImportTableHijack => target.loader_state == LoaderState::NotStarted,
    };
    if !allowed {
        return Err(Error::StrategyUnavailable {
            strategy,
            reason: match strategy {
                Strategy::LoadLibraryRemoteThread => {
                    "an early-APC handoff permits only APC injection"
                }
                Strategy::QueueUserApc => {
                    "a never-run thread or verified early-APC handoff is required"
                }
                Strategy::ImportTableHijack => "a never-run primary thread and loader are required",
            },
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_gates() {
        let mut t = Target::new(std::ptr::null_mut(), None, 0, LoaderState::Unknown);
        assert!(matches!(
            gate(Strategy::QueueUserApc, &t),
            Err(Error::MissingThreadHandle)
        ));
        assert!(gate(Strategy::ImportTableHijack, &t).is_err());
        assert!(gate(Strategy::default(), &t).is_ok());
        t.main_thread = Some(std::ptr::null_mut());
        assert!(gate(Strategy::QueueUserApc, &t).is_err());
        t.loader_state = LoaderState::LoaderComplete;
        assert!(gate(Strategy::QueueUserApc, &t).is_err());
        t.loader_state = LoaderState::NotStarted;
        assert!(gate(Strategy::QueueUserApc, &t).is_ok());
        t.loader_state = LoaderState::EarlyApc;
        assert!(gate(Strategy::QueueUserApc, &t).is_ok());
        assert!(gate(Strategy::ImportTableHijack, &t).is_err());
        assert!(gate(Strategy::LoadLibraryRemoteThread, &t).is_err());
    }
}
