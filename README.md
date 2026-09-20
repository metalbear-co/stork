# stork

stork injects a native DLL into a Windows AMD64 process through borrowed
handles. It provides three strategies without RPC or generated remote code
stubs. The caller owns process creation, synchronization, and resume.

## Quick start

For the default remote-thread strategy, call `stork::inject`. Pass an owned
target directly, without extracting raw handles:

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

When Rust already owns the process and thread handles, use `AsHandle::as_handle`
and a `BorrowedTarget`. The compiler keeps both owners borrowed, and the PID is
queried from the process handle. For a trusted never-run handoff:

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

Use `Injector::import_table()` for IAT injection. It also requires an explicit
never-run assertion, but no thread handle. `Injector::with_strategy(strategy)`
remains available when the strategy comes from configuration.

### Existing raw handles

The original raw-handle API remains available for integrations such as mirrord:

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

Inspect the returned timing before ordering readiness and resume. stork does
not resume or terminate the target or close borrowed handles. The caller owns
the single resume after a successful injection.

## Strategies

| Strategy | When it loads | Requirements |
| --- | --- | --- |
| `LoadLibraryRemoteThread` (default) | During `inject` | Process handle with create-thread and VM rights |
| `QueueUserApc` | On the caller's continuation | Main-thread handle, never-run or verified early-APC handoff |
| `ImportTableHijack` | On the caller's resume | Never-run target, ASCII path, exporting payload |

`ImportTableHijack` requires `LoaderState::NotStarted`. APC also accepts
`LoaderState::EarlyApc`: a caller-verified stop from which the queued APC runs
before application logic. That handoff is reserved for APC; other strategies
are refused. Remote-thread injection accepts the other loader states.

## Load timing

The result reports when the DLL loads.

`LoadTiming::Immediate` means the DLL is mapped and its `DllMain` has returned.
The result carries the remote module address. The address is a non-owning
value. Do not pass it to `CloseHandle` or `FreeLibrary`. It does not unload
anything.

`LoadTiming::OnResume` means the load is queued or armed. The module address
is not known yet. Resume the thread, then confirm load and readiness through a
caller-owned protocol.

Three facts are different guarantees:

1. The DLL is loaded.
2. `DllMain` completed.
3. An asynchronous payload worker is ready.

A payload worker can still initialize after `DllMain` returns. `Immediate`
does not mean the layer is ready. The caller orders its readiness wait by the
reported timing.

## Safety contract

`stork::inject` and `Injector::inject` are `unsafe`. `BorrowedTarget` checks
handle lifetimes, but cannot verify loader state, payload trust, or exclusive
access. Prefer it when Rust owns the handles; use raw `Target` for FFI handoffs.

Keep every handle valid and its owner alive through the call. The handles must
identify the stated process and its primary thread. The handles must carry the
rights documented on `Target`. Recycled handles cannot be detected reliably.

Exclude concurrent injection, loader mutation, resume, handle close, and image
unmapping during the call. For `NotStarted`, attest that the primary thread
and the loader have never run and no other injection advanced them. Do not
reuse that attestation after an injection attempt.

For `EarlyApc`, establish that continuing the stopped primary thread dispatches
the queued APC before application logic. Do not reuse this handoff after an
attempt or infer it from a generic debugger stop or thread suspend count.

Self-injection is refused. The payload must be a native AMD64 DLL.

A `LoaderState::NotStarted` attestation is a caller statement. The crate
cannot verify it from a pid.

## APC handoffs

For `NotStarted`, resume is the thread's first run and the queued APC fires
before entry. `EarlyApc` covers a distinct, verified pre-application delivery
point even when loader initialization has begun. A plain resume of an arbitrary
already-running thread does not guarantee APC delivery.

A native-debugger regression verifies the initial Windows breakpoint on this
host: the queued payload loads before the executable's entry point. VS Code
adapter handoffs remain to be tested; this result does not validate their
language-level stop-on-entry behavior.

## IAT limits

The IAT strategy encodes the payload path as a PE import name. Import names
are byte strings.

The crate accepts ASCII, absolute, local drive paths shorter than `MAX_PATH`
(at most 259 characters, plus a NUL terminator). Use the remote-thread strategy
for Unicode and UNC paths. Every strategy rejects embedded NULs.

The payload must export **ordinal 1**, as required by Detours' import-table
injection. A valid forwarder at that ordinal is accepted; the Windows loader
resolves it. An export at another ordinal does not satisfy this requirement.
The payload must be a native DLL. The crate refuses managed payloads.

Managed targets follow the Detours behavior:

- A neutral (AnyCPU) pure-IL managed executable runs as an AMD64 process with
  PE32 headers. The crate widens those headers to PE32+ in memory, drops the
  32-bit-era import table, and installs the payload import.
- An AMD64 managed executable (x64 pure-IL or mixed-mode) keeps its imports;
  the payload descriptor is placed before them.
- Pure-IL images get the CLR `ILONLY` flag cleared in memory so the CLR honors
  the added native import.
- Mixed-mode 32-bit MSIL and `32BITREQUIRED` managed images are refused before
  any mutation.
- PE32 widening supports at most 32 sections. Header padding is preserved;
  directory data overlapping the replacement headers is refused, not relocated.

Existing import names and thunks are resolved by the Windows loader. Stork
copies their descriptors with a bounded walk; successful preparation does not
guarantee that the loader will accept malformed original imports. See the
[Detours parity table](docs/DETOURS_PARITY.md) for exact scope and differences.

The machine and CLR-header mutations happen only while the target is
never-run. The native AMD64 process gate still applies; a WOW64 (x86) process
is refused before the IAT strategy runs.

Managed loader tests cover .NET Framework 4.8 AnyCPU/x64, a real native/managed
C++/CLI x64 executable, and the .NET 10 runtime through its native `dotnet.exe`
host on Windows 11 build 26200. All three strategies and post-start remote-thread
injection are exercised. Self-contained apphosts and other Windows builds still
need their own runtime validation.

The intended IDE safe-point handoff is APC-only and uses `EarlyApc` once its
delivery ordering is validated for that adapter. It does not establish IAT's
untouched-loader requirement. See the [reviewed IDE handoff](docs/IDE_HANDOFF.md).

## Error handling

An injection error can describe a pending load or a partially modified target.
Check recovery conditions before deciding what to do with the process.

| Condition | Meaning | Caller action |
| --- | --- | --- |
| `error.must_not_resume()` | Header rollback or protection restoration failed | Keep the target stopped; its state is not confirmed safe |
| `error.is_pending()` | The remote-thread wait timed out or failed | Do not retry blindly; confirm eventual load through your own protocol |
| Neither condition | Validation, file access, another API call, or ordinary cleanup failed | Inspect the error and the caller's state contract; this does not authorize retry or resume |

Both methods inspect nested cleanup errors. For example:

```rust
use stork::Error;

fn report_injection_error(error: &Error) {
    if error.must_not_resume() {
        eprintln!("Keep the target stopped: {error}");
    } else if error.is_pending() {
        eprintln!("Load outcome is pending; do not retry: {error}");
    } else {
        eprintln!("Injection failed: {error}");
    }
}
```

The remote-thread wait has a 30-second limit. `RemoteTimeout` and
`RemotePending` retain the path allocation and leave the remote thread running;
neither cancels the load. APC success also retains its path until process exit.

`Error::Cleanup` preserves both the operation and cleanup errors. Its display
includes both, while `std::error::Error::source()` follows the operation branch.
Inspect the `cleanup` field when traversing both branches programmatically.
Rollback errors retain the failed write and the rollback cause.

`Error::Io` includes the file operation, path, and underlying I/O error.
`Error::Win32` includes the API name and captured OS error. Payload reads use
one open file handle and a 512 MiB limit; `PayloadTooLarge` reports that limit.
The caller must still keep the payload available until the remote load finishes.

## Loader-state model

The Windows loader maps and initializes a process in stages:

- `NotStarted`: `CREATE_SUSPENDED` handoff. The loader and the primary thread
  have never run. All three strategies are valid.
- `EarlyApc`: a verified stop before application logic with guaranteed early
  APC delivery on continuation. Only the APC strategy is valid.
- `LoaderComplete`: the process is suspended after the loader ran. The
  remote-thread strategy is valid. APC and IAT are refused.
- `Unknown`: no attestation. Only the remote-thread strategy is valid.

`OwnedTarget::open_process(pid)` opens only the process;
`OwnedTarget::open_with_main_thread(pid)` also selects and retains its primary
thread. The original `open(pid, bool)` constructor remains available.

Passing `&OwnedTarget` directly uses `Unknown`. For a trusted handoff, use
`owned.borrowed().with_loader_state(LoaderState::NotStarted)`. This view keeps
the owner borrowed. `owned.target()` still returns the original raw view for
FFI compatibility; the caller must keep its owner alive independently.

The primary thread is the thread with the lowest creation time. Tied minima,
incomplete snapshots, and vanished threads are reported as ambiguous.

## Compatibility scope

The crate is built and tested on Windows 11 build 26200, native AMD64. The
startup exception is also permitted on Windows Server 2025 build 26100, where
the mirrord Windows layer test suite exercises it in continuous integration.

A fresh `CREATE_SUSPENDED` child maps only the executable and `ntdll.dll`.
Remote-thread injection into such a child is an empirically tested startup
case on those builds. The crate resolves `LoadLibraryW` inside the target
whenever its module is mapped. For a never-run child on a tested build, the
crate uses the documented startup exception, and it still requires the module
at that address to be `%SystemRoot%\System32\kernel32.dll` and its remote
region to be free and large enough for the image. Other hosts return
`StrategyUnavailable` instead of an unverified address.

Architecture checks use `IsWow64Process2` (Windows 10 and later). x86 and
ARM64 targets are refused. A 32-bit injector is not supported.

## Building

The crate builds with the Rust MSVC toolchain on x64 Windows:

```text
cargo build
cargo test
```

Run the complete local checks:

```powershell
powershell -NoProfile -File test-support/check.ps1
```

This checks formatting (including shared `include!` files), builds the workspace,
runs strict Clippy and rustdoc checks, and executes serialized tests. README
Rust examples are included in the crate documentation and compiled as doctests.

The harness asks Cargo to refresh fixture artifacts even when files already
exist. Optional C# tests skip only when the .NET Framework compiler is absent;
fixture compilation failures fail the tests.

The `test-target` build script compiles the native PE-entry fixtures. It
discovers `cl.exe` and `link.exe` through the `cc` crate. A Visual Studio
Build Tools installation must be present. The tests spawn real suspended
processes. Their lifetime guards attempt termination and bounded reaping on
every path, including assertion failures.

## Layout

- `src/injector` - loader-state gates, target validation, and strategy dispatch.
- `src/payload.rs` - one validated payload, owning its path, bytes, and headers.
- `src/paths.rs` - local path identity and Windows path encoding policies.
- `src/target` - loader state, lifetime-bound `BorrowedTarget`, raw `Target`, and `OwnedTarget`.
- `src/strategy/load_library` - remote LoadLibrary thread.
- `src/strategy/queue_apc` - Early Bird APC.
- `src/strategy/import_table` - Detours-style import rewrite.
- `src/strategy/import_table/patch.rs` - verified IAT byte/protection transaction.
- `src/remote` - remote memory, modules, and image helpers.
- `src/pe` - pelite-backed PE32/PE32+ decode, validations, import-blob builder.
- `test-payload`, `test-target` - fixture workspace members.
- `tests` - serialized process-level integration tests: fixture targets and
  real targets (python.exe, node.exe, a managed C# program).

See [Architecture](docs/ARCHITECTURE.md) for module responsibilities, ownership
rules, and guidance for future changes.