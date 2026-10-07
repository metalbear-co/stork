# stork

> the bird that makes the delivery

A **Rust** library for **Windows x64** DLL injection, built for [mirrord](https://github.com/metalbear-co/mirrord).

stork injects a native DLL into a Windows AMD64 process through **borrowed handles**. It offers three strategies, with no RPC and no generated remote code stubs. The caller always owns process creation, synchronization, and resume.

## Examples

Default **remote-thread** injection from a pid. Pass an owned target directly, without extracting raw handles:
```rust,no_run
use stork::{InjectedModule, OwnedTarget, Result};

/// # Safety
/// The caller must satisfy stork::inject's handle, payload, and exclusive
/// loader-access contract. Opening a pid does not establish loader state.
unsafe fn inject_pid(pid: u32) -> Result<InjectedModule> {
    let target = OwnedTarget::open_process(pid)?;
    unsafe { stork::inject(&target, r"C:\path\to\payload.dll") }
}
```
> An owned target passed directly uses `LoaderState::Unknown`, for which only the remote-thread strategy is valid.

---

Injecting through **borrowed** process and thread handles that Rust already owns. The compiler keeps both owners borrowed, and the pid is read from the process handle:
```rust,no_run
use std::os::windows::io::BorrowedHandle;
use stork::{BorrowedTarget, InjectedModule, Injector, LoaderState, Result};

/// # Safety
/// The handles identify a never-run child and its primary thread. The caller
/// must satisfy Injector::inject's payload and exclusive loader-access contract.
unsafe fn queue_before_start(
    process: BorrowedHandle<'_>,
    thread: BorrowedHandle<'_>,
) -> Result<InjectedModule> {
    let target = BorrowedTarget::new(process)?
        .with_main_thread(thread)
        .with_loader_state(LoaderState::NotStarted);
    unsafe { Injector::queue_apc().inject(&target, r"C:\path\to\payload.dll") }
}
```
> `BorrowedTarget` checks handle lifetimes at compile time but cannot verify loader state, payload trust, or exclusive access — those remain caller attestations.

---

Injecting into an existing **suspended child** through raw FFI handles. This is the original API, kept for integrations such as mirrord:
```rust,no_run
use std::ffi::c_void;
use stork::{InjectedModule, Result, Target};

/// # Safety
/// The handles must identify a never-run child and remain valid throughout
/// injection. Exclude concurrent resume, injection, and loader mutation.
unsafe fn inject_suspended_child(
    process_handle: *mut c_void,
    main_thread_handle: *mut c_void,
    process_id: u32,
) -> Result<InjectedModule> {
    let target = Target::not_started(
        process_handle,
        Some(main_thread_handle),
        process_id,
    );
    unsafe { stork::inject(target, r"C:\path\to\payload.dll") }
}
```
> **WARNING**: stork never resumes, terminates, or closes anything. After a successful injection the caller owns the single resume, and must keep every handle valid and its owner alive through the call.

---

Choosing a strategy explicitly.

The `Injector::import_table()` strategy is inspired by the awesome method developed by Microsoft in Detours, respectively [`DetourCreateProcessWithDllEx`](https://github.com/microsoft/detours/wiki/DetourCreateProcessWithDllEx), which hijacks part of the PE header — the imports table, specifically — so that the Windows PE loader does the DLL injection for us.

This comes with some trade-offs that we had to work around for .NET/C# targets, just like Detours had to. For example, a neutral (AnyCPU) pure-IL executable runs as AMD64 with PE32 headers, so stork widens those headers to PE32+ in memory and clears the CLR `ILONLY` flag before the loader will honor the added native import.

`Injector::with_strategy` takes a strategy from configuration:
```rust,no_run
use stork::{Injector, Strategy};

let from_config: Strategy = "iat".parse().unwrap(); // also "apc", "loadlibrary"
let injector = Injector::with_strategy(from_config);
assert_eq!(injector.strategy(), Strategy::ImportTableHijack);
```
> The IAT strategy encodes the payload path as a PE import name, so it accepts only ASCII, absolute, local-drive paths shorter than `MAX_PATH`, and the payload must export **ordinal 1**. Use the remote-thread strategy for Unicode and UNC paths.

---

Reading the returned **load timing** before resuming:
```rust,no_run
use stork::{InjectedModule, LoadTiming};

fn after_inject(result: InjectedModule) {
    match result.timing {
        // The DLL is mapped and its DllMain has returned; result.module is set.
        LoadTiming::Immediate => { /* confirm the payload worker's own readiness */ }
        // The load is queued or armed. Resume the thread, then confirm load
        // and readiness through a caller-owned protocol.
        LoadTiming::OnResume => { /* resume, then wait on your own protocol */ }
    }
}
```
> `result.module` is a **non-owning** remote address. Never pass it to `CloseHandle` or `FreeLibrary`. A returned `Immediate` means the DLL loaded and `DllMain` completed — not that an asynchronous payload worker is ready.

---

Inspecting an **injection error** for recovery conditions before deciding what to do with the process:
```rust
use stork::Error;

fn report_injection_error(error: &Error) {
    if error.must_not_resume() {
        // Header rollback or protection restore failed; keep the target stopped.
        eprintln!("Keep the target stopped: {error}");
    } else if error.is_pending() {
        // The remote-thread wait timed out or failed; do not retry blindly.
        eprintln!("Load outcome is pending; do not retry: {error}");
    } else {
        eprintln!("Injection failed: {error}");
    }
}
```
> The remote-thread wait defaults to 30 seconds (`stork::DEFAULT_REMOTE_WAIT`). `Injector::with_remote_wait` changes it, and `None` waits until the thread ends.

## Strategies

| Strategy | When it loads | Requirements |
| --- | --- | --- |
| `LoadLibraryRemoteThread` (default) | During `inject` | Process handle with create-thread and VM rights |
| `QueueUserApc` | On the caller's resume | Main-thread handle; `NotStarted` or verified `EarlyApc` handoff |
| `ImportTableHijack` | On the caller's resume | `NotStarted` target, ASCII path, payload exporting ordinal 1 |

> Every strategy is `unsafe`. stork cannot verify a loader-state attestation from a pid — it is the caller's statement. See the safety contract on `Target` and `Injector::inject`.

## Support

- **Three injection strategies** — remote `LoadLibrary` thread, Early Bird `QueueUserAPC`, and Detours-style import-table hijack
- **Borrowed-handle targets** — `OwnedTarget`, lifetime-checked `BorrowedTarget`, and raw `Target` for FFI
- **Loader-state model** — `NotStarted`, `EarlyApc`, `LoaderComplete`, and `Unknown` gate which strategies are valid
- **Managed (.NET) targets** — AnyCPU and x64 pure-IL and mixed-mode images, following Detours parity
- **Reported load timing** — distinguishes a completed load from one armed for the caller's resume
- Native **AMD64** only; x86 and ARM64 targets are refused, and a 32-bit injector is not supported

## Building

The crate builds with the Rust MSVC toolchain on x64 Windows:
```text
cargo build
cargo test
```
Run the complete local checks (formatting, build, strict Clippy and rustdoc, serialized tests):
```powershell
powershell -NoProfile -File test-support/check.ps1
```
> The tests spawn real suspended processes and compile native PE fixtures, so a Visual Studio Build Tools installation must be present. Optional C# tests skip only when the .NET Framework compiler is absent.

## License

BSD-2-Clause
