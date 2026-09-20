// Shared test harness: fixture artifacts, suspended children, named events,
// module enumeration, checkpoints, and real-target discovery.
//
// This file is `include!`d verbatim into `tests/common/mod.rs` and into the
// `#[cfg(test)]` modules of the crate. It therefore declares no `use`
// statements at module scope and no inner attributes. Imports inside functions
// remain local, so inclusion cannot collide with the host module.

pub const ARTIFACTS: &[(&str, &str)] = &[
    ("test_payload.dll", "test-payload"),
    ("test_target.exe", "test-target"),
    ("test_target_entry.exe", "test-target"),
    ("test_target_noimport.exe", "test-target"),
];

pub struct Fixtures {
    pub payload: std::path::PathBuf,
    pub rust_target: std::path::PathBuf,
    pub entry: std::path::PathBuf,
    pub noimport: std::path::PathBuf,
    pub workspace: std::path::PathBuf,
}

pub fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// Ask Cargo to check fixture freshness once per test executable, including
/// when old artifacts already exist. Locate artifacts next to this test's deps
/// directory to support custom target directories, triples, and profiles.
fn build_fixtures() -> Fixtures {
    let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let executable = std::env::current_exe().expect("test executable path");
    let target_dir = executable
        .parent()
        .and_then(std::path::Path::parent)
        .expect("test profile directory")
        .to_path_buf();
    {
        let mut command = std::process::Command::new(env!("CARGO"));
        command.current_dir(&workspace).args([
            "build",
            "--locked",
            "-p",
            "test-payload",
            "-p",
            "test-target",
        ]);
        let profile_name = target_dir.file_name().expect("profile name");
        command.arg("--profile").arg(if profile_name == "debug" {
            std::ffi::OsStr::new("dev")
        } else {
            profile_name
        });
        let parent = target_dir.parent().expect("target directory");
        if parent
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("x86_64-"))
        {
            command.arg("--target").arg(parent.file_name().unwrap());
            command
                .arg("--target-dir")
                .arg(parent.parent().expect("target root"));
        } else {
            command.arg("--target-dir").arg(parent);
        }
        let output = command_output(&mut command, std::time::Duration::from_secs(180))
            .expect("build test fixtures");
        assert!(
            output.status.success(),
            "fixture build failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for (file, _) in ARTIFACTS {
        assert!(
            target_dir.join(file).is_file(),
            "fixture artifact is missing after build: {file}"
        );
    }
    Fixtures {
        payload: target_dir.join("test_payload.dll"),
        rust_target: target_dir.join("test_target.exe"),
        entry: target_dir.join("test_target_entry.exe"),
        noimport: target_dir.join("test_target_noimport.exe"),
        workspace,
    }
}

pub fn fixtures() -> &'static Fixtures {
    static FIXTURES: std::sync::OnceLock<Fixtures> = std::sync::OnceLock::new();
    FIXTURES.get_or_init(build_fixtures)
}

pub type WideString = wincorda::NullTerminated<'static, wincorda::WCHAR>;

pub fn path_output_buffer() -> WideString {
    WideString::zeroed(std::num::NonZeroUsize::new(32 * 1024).unwrap())
}

pub fn finish_path_output(mut buffer: WideString, count: usize) -> WideString {
    assert!(count < buffer.len_with_nul(), "path output was truncated");
    assert_eq!(buffer.len(), count, "path length disagrees with terminator");
    buffer.shrink_to_null();
    buffer
}

pub fn event_name(pid: u32, prefix: &str) -> WideString {
    assert!(!prefix.contains('\0'), "event prefix contains NUL");
    let mut name: Vec<u16> = prefix.encode_utf16().collect();
    let digits = pid.to_string();
    name.extend(digits.encode_utf16());
    name.push(0);
    WideString::try_from(name).expect("terminated event name")
}

pub struct NamedEvent {
    pub handle: winapi::um::winnt::HANDLE,
}

impl Drop for NamedEvent {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle);
        }
    }
}

impl NamedEvent {
    /// Returns true when the event is signaled now.
    pub fn is_set(&self) -> bool {
        self.wait(0)
    }
    /// Bounded wait. Returns true when the event became signaled.
    pub fn wait(&self, timeout_ms: u32) -> bool {
        match self.wait_raw(timeout_ms) {
            winapi::um::winbase::WAIT_OBJECT_0 => true,
            winapi::shared::winerror::WAIT_TIMEOUT => false,
            result => panic!(
                "event wait failed: {result:#x}, {}",
                std::io::Error::last_os_error()
            ),
        }
    }
    /// Bounded wait with the raw Win32 wait result.
    pub fn wait_raw(&self, timeout_ms: u32) -> u32 {
        unsafe { winapi::um::synchapi::WaitForSingleObject(self.handle, timeout_ms) }
    }
    pub fn wait_object(&self, timeout_ms: u32, what: &str) {
        let result = self.wait_raw(timeout_ms);
        assert!(
            result == winapi::um::winbase::WAIT_OBJECT_0,
            "{what} was not signaled within {timeout_ms} ms (wait result {result})"
        );
    }
    pub fn assert_clear(&self, what: &str) {
        assert!(!self.is_set(), "{what} is unexpectedly signaled");
    }
    pub fn signal(&self) {
        unsafe {
            assert!(
                winapi::um::synchapi::SetEvent(self.handle) != 0,
                "SetEvent failed"
            );
        }
    }
}

/// Create one pid-named event (test_, ready_, delay_, worker_go_, block_, ...).
pub fn create_event(pid: u32, prefix: &str) -> NamedEvent {
    let name = event_name(pid, prefix);
    let handle =
        unsafe { winapi::um::synchapi::CreateEventW(std::ptr::null_mut(), 1, 0, name.as_ptr()) };
    assert!(
        !handle.is_null(),
        "CreateEventW({prefix}) failed with error {}",
        unsafe { winapi::um::errhandlingapi::GetLastError() }
    );
    NamedEvent { handle }
}

/// The standard pid-named events. Manual-reset, initially clear.
///
/// `delay`, `worker_go`, and `block` change the payload's DllMain behavior
/// and are created separately only by the tests that need them.
pub struct Events {
    pub test: NamedEvent,
    pub ready: NamedEvent,
    pub entry: NamedEvent,
    pub pass: NamedEvent,
    pub ready_at_entry: NamedEvent,
    pub main: NamedEvent,
}

impl Events {
    pub fn create_all(pid: u32) -> Self {
        let make = |prefix: &str| -> NamedEvent { create_event(pid, prefix) };
        Events {
            test: make("Local\\stork_test_"),
            ready: make("Local\\stork_ready_"),
            entry: make("Local\\stork_entry_"),
            pass: make("Local\\stork_pass_"),
            ready_at_entry: make("Local\\stork_ready_at_entry_"),
            main: make("Local\\stork_main_"),
        }
    }
}

/// A suspended child. Drop terminates and reaps it on every path.
pub struct Child {
    pub process: winapi::um::winnt::HANDLE,
    pub thread: winapi::um::winnt::HANDLE,
    pub pid: u32,
}

impl std::os::windows::io::AsHandle for Child {
    fn as_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        // Child owns this handle until drop; the return value borrows Child.
        unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(self.process.cast()) }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let mut failures = Vec::new();
        unsafe {
            if winapi::um::synchapi::WaitForSingleObject(self.process, 0) != 0 {
                if winapi::um::processthreadsapi::TerminateProcess(self.process, 1) == 0 {
                    let error = std::io::Error::last_os_error();
                    if winapi::um::synchapi::WaitForSingleObject(self.process, 0) != 0 {
                        failures.push(format!("terminate child: {error}"));
                    }
                }
                let wait = winapi::um::synchapi::WaitForSingleObject(self.process, 5_000);
                if wait != 0 {
                    failures.push(if wait == u32::MAX {
                        format!("reap child: {}", std::io::Error::last_os_error())
                    } else {
                        format!("reap child: unexpected wait result {wait:#x}")
                    });
                }
            }
            for handle in [self.process, self.thread] {
                if winapi::um::handleapi::CloseHandle(handle) == 0 {
                    failures.push(format!(
                        "close child handle: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
        }
        if !failures.is_empty() {
            let message = format!("child {} cleanup failed: {}", self.pid, failures.join("; "));
            if std::thread::panicking() {
                eprintln!("{message}");
            } else {
                panic!("{message}");
            }
        }
    }
}

mod supervised_process {
    include!("process.rs");
}
pub use supervised_process::command_output;

fn wide_command_line(exe: &std::path::Path, args: &[&str]) -> WideString {
    use std::os::windows::ffi::OsStrExt as _;
    let mut command: Vec<u16> = vec![b'"' as u16];
    command.extend(exe.as_os_str().encode_wide());
    command.push(b'"' as u16);
    for arg in args {
        assert!(!arg.contains('\0'), "argument contains NUL");
        command.push(b' ' as u16);
        command.push(b'"' as u16);
        let mut slashes = 0;
        for unit in arg.encode_utf16() {
            if unit == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            let count = if unit == b'"' as u16 {
                slashes * 2 + 1
            } else {
                slashes
            };
            command.extend(std::iter::repeat_n(b'\\' as u16, count));
            command.push(unit);
            slashes = 0;
        }
        command.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        command.push(b'"' as u16);
    }
    assert!(!command.contains(&0), "command line contains NUL");
    command.push(0);
    WideString::try_from(command).expect("terminated command line")
}

fn spawn_suspended(exe: &std::path::Path, args: &[&str]) -> Child {
    spawn_suspended_with_flags(exe, args, 0)
}

pub fn spawn_suspended_with_flags(exe: &std::path::Path, args: &[&str], flags: u32) -> Child {
    let mut command = wide_command_line(exe, args);
    let mut startup: winapi::um::processthreadsapi::STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<winapi::um::processthreadsapi::STARTUPINFOW>() as u32;
    let mut info: winapi::um::processthreadsapi::PROCESS_INFORMATION =
        unsafe { std::mem::zeroed() };
    let ok = unsafe {
        winapi::um::processthreadsapi::CreateProcessW(
            std::ptr::null(),
            command.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            winapi::um::winbase::CREATE_SUSPENDED | flags,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut startup,
            &mut info,
        )
    };
    assert!(ok != 0, "CreateProcessW failed with error {}", unsafe {
        winapi::um::errhandlingapi::GetLastError()
    });
    let child = Child {
        process: info.hProcess,
        thread: info.hThread,
        pid: info.dwProcessId,
    };
    // Install the process guard before any assertion or filesystem operation.
    let checkpoint = checkpoint_path(child.pid);
    match std::fs::remove_file(&checkpoint) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "cannot remove stale checkpoint {}: {error}",
            checkpoint.display()
        ),
    }
    assert_eq!(
        unsafe { winapi::um::processthreadsapi::GetProcessId(info.hProcess) },
        info.dwProcessId,
        "spawned pid mismatch"
    );
    child
}

impl Child {
    pub fn main_thread_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        // Child owns the primary thread handle for the duration of this borrow.
        unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(self.thread.cast()) }
    }

    /// Spawn `exe` with CREATE_SUSPENDED and no arguments.
    pub fn spawn(exe: &std::path::Path) -> Child {
        spawn_suspended(exe, &[])
    }
    /// Spawn `exe` with CREATE_SUSPENDED and quoted arguments.
    pub fn spawn_with_args(exe: &std::path::Path, args: &[&str]) -> Child {
        spawn_suspended(exe, args)
    }
    pub fn resume(&self, what: &str) -> u32 {
        let count = unsafe { winapi::um::processthreadsapi::ResumeThread(self.thread) };
        assert!(
            count != u32::MAX,
            "ResumeThread({what}) failed with error {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
        count
    }
    pub fn suspend(&self, what: &str) -> u32 {
        let count = unsafe { winapi::um::processthreadsapi::SuspendThread(self.thread) };
        assert!(
            count != u32::MAX,
            "SuspendThread({what}) failed with error {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
        count
    }
    pub fn thread_id(&self) -> u32 {
        unsafe { winapi::um::processthreadsapi::GetThreadId(self.thread) }
    }
    pub fn alive(&self) -> bool {
        let result = unsafe { winapi::um::synchapi::WaitForSingleObject(self.process, 0) };
        result == winapi::shared::winerror::WAIT_TIMEOUT
    }
}

/// Enumerate the committed image modules of a process by full path.
pub fn module_paths(process: winapi::um::winnt::HANDLE) -> Vec<std::path::PathBuf> {
    module_entries(process)
        .into_iter()
        .map(|(_, path)| path)
        .collect()
}

fn module_entries(process: winapi::um::winnt::HANDLE) -> Vec<(usize, std::path::PathBuf)> {
    use std::os::windows::ffi::OsStringExt as _;
    let mut list: Vec<winapi::shared::minwindef::HMODULE> = vec![std::ptr::null_mut(); 256];
    loop {
        let mut needed: winapi::shared::minwindef::DWORD = 0;
        let bytes = (list.len() * std::mem::size_of::<winapi::shared::minwindef::HMODULE>()) as u32;
        let ok = unsafe {
            winapi::um::psapi::EnumProcessModulesEx(
                process,
                list.as_mut_ptr(),
                bytes,
                &mut needed,
                3,
            )
        };
        assert!(
            ok != 0,
            "EnumProcessModulesEx failed with error {}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
        if (needed as usize)
            <= list.len() * std::mem::size_of::<winapi::shared::minwindef::HMODULE>()
        {
            list.truncate(
                needed as usize / std::mem::size_of::<winapi::shared::minwindef::HMODULE>(),
            );
            break;
        }
        list.resize(
            needed as usize / std::mem::size_of::<winapi::shared::minwindef::HMODULE>() + 16,
            std::ptr::null_mut(),
        );
    }
    let mut result = Vec::new();
    for &module in &list {
        let mut buffer = path_output_buffer();
        let n = unsafe {
            winapi::um::psapi::GetModuleFileNameExW(
                process,
                module,
                buffer.as_mut_ptr(),
                buffer.len_with_nul() as u32,
            )
        };
        assert!(n != 0, "GetModuleFileNameExW failed");
        let buffer = finish_path_output(buffer, n as usize);
        result.push((
            module as usize,
            std::path::PathBuf::from(std::ffi::OsString::from_wide(buffer.as_bytes())),
        ));
    }
    result
}

/// Exact full-path presence check for a module.
pub fn module_loaded(process: winapi::um::winnt::HANDLE, expected: &std::path::Path) -> bool {
    let expected = expected
        .canonicalize()
        .unwrap_or_else(|_| expected.to_path_buf());
    module_paths(process)
        .iter()
        .any(|path| path.canonicalize().map(|p| p == expected).unwrap_or(false))
}

/// The remote base of a module whose full path matches `expected`.
pub fn module_base(
    process: winapi::um::winnt::HANDLE,
    expected: &std::path::Path,
) -> Option<usize> {
    let expected = expected
        .canonicalize()
        .unwrap_or_else(|_| expected.to_path_buf());
    module_entries(process)
        .into_iter()
        .find(|(_, path)| path.canonicalize().map(|p| p == expected).unwrap_or(false))
        .map(|(base, _)| base)
}
/// Open a process handle with the rights stork's strategies need.
pub fn open_process(pid: u32) -> winapi::um::winnt::HANDLE {
    let handle = unsafe {
        winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_QUERY_INFORMATION
                | winapi::um::winnt::PROCESS_VM_OPERATION
                | winapi::um::winnt::PROCESS_VM_READ
                | winapi::um::winnt::PROCESS_VM_WRITE
                | winapi::um::winnt::PROCESS_TERMINATE
                | winapi::um::winnt::SYNCHRONIZE,
            0,
            pid,
        )
    };
    assert!(
        !handle.is_null(),
        "OpenProcess({pid}) failed with error {}",
        unsafe { winapi::um::errhandlingapi::GetLastError() }
    );
    handle
}

/// One region query result, for remote-allocation checks.
pub fn query_region(
    process: winapi::um::winnt::HANDLE,
    address: usize,
) -> winapi::um::winnt::MEMORY_BASIC_INFORMATION {
    let mut info: winapi::um::winnt::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let size = unsafe {
        winapi::um::memoryapi::VirtualQueryEx(
            process,
            address as *const winapi::ctypes::c_void,
            &mut info,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert!(size != 0, "VirtualQueryEx failed");
    info
}

// ---------------------------------------------------------------------------
// Real-target support: checkpoints, python/node discovery, C# fixture build.
// ---------------------------------------------------------------------------

/// Directory for per-pid checkpoint files of real-target tests.
pub fn real_target_dir() -> std::path::PathBuf {
    let executable = std::env::current_exe().expect("test executable path");
    let dir = executable
        .parent()
        .and_then(std::path::Path::parent)
        .expect("test profile directory")
        .join("real_targets")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(&dir).expect("real_targets dir");
    dir
}

/// The file a real target writes once its main code runs.
pub fn checkpoint_path(pid: u32) -> std::path::PathBuf {
    real_target_dir().join(format!("ckpt_{pid}.txt"))
}

/// Poll for a file with a bounded wait.
pub fn wait_for_file(path: &std::path::Path, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now();
    loop {
        if path.is_file() {
            return true;
        }
        if deadline.elapsed().as_millis() >= timeout_ms as u128 {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Python code run as `python -c`: touch the pid checkpoint, then sleep.
pub fn python_code(dir: &std::path::Path) -> String {
    format!(
        "import os,time; d='{}'; open(os.path.join(d,'ckpt_%d.txt'%os.getpid()),'w').close(); time.sleep(60)",
        dir.to_string_lossy()
            .replace('\\', "/")
            .replace('\'', "\\'")
    )
}

/// Node code run as `node -e`: touch the pid checkpoint, then idle.
pub fn node_code(dir: &std::path::Path) -> String {
    format!(
        "require('fs').writeFileSync(require('path').join('{}','ckpt_'+process.pid+'.txt'),'');setTimeout(function(){{}},60000)",
        dir.to_string_lossy()
            .replace('\\', "/")
            .replace('\'', "\\'")
    )
}

/// Resolve the real python.exe: probes PATH, then runs it to learn its true
/// executable. A present but failing interpreter is a test failure.
pub fn probe_python() -> Option<std::path::PathBuf> {
    probe_executable(
        std::process::Command::new("python.exe").args(["-c", "import sys; print(sys.executable)"]),
    )
}

/// Resolve the real node.exe the same way.
pub fn probe_node() -> Option<std::path::PathBuf> {
    probe_executable(
        std::process::Command::new("node.exe")
            .args(["-e", "process.stdout.write(process.execPath)"]),
    )
}

fn probe_executable(command: &mut std::process::Command) -> Option<std::path::PathBuf> {
    match command_output(command, std::time::Duration::from_secs(15)) {
        Ok(output) => {
            assert!(
                output.status.success(),
                "optional-tool probe failed: {}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let path =
                std::path::PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned());
            path.is_file().then_some(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("optional-tool probe failed: {error}"),
    }
}

/// Build an AnyCPU fixture. Only a missing compiler permits a skip.
pub fn csharp_target() -> Option<std::path::PathBuf> {
    static TARGET: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    TARGET.get_or_init(|| build_csharp_target("anycpu")).clone()
}

/// Build the AMD64 managed fixture without PE32 conversion.
pub fn csharp_target_x64() -> Option<std::path::PathBuf> {
    static TARGET: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    TARGET.get_or_init(|| build_csharp_target("x64")).clone()
}

pub fn mixed_target() -> Option<std::path::PathBuf> {
    let path = fixtures()
        .rust_target
        .with_file_name("test_target_mixed.exe");
    path.is_file().then_some(path)
}

/// Run the same managed checkpoint under the installed modern .NET runtime.
pub fn dotnet_target() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    static TARGET: std::sync::OnceLock<Option<(std::path::PathBuf, std::path::PathBuf)>> =
        std::sync::OnceLock::new();
    TARGET.get_or_init(|| {
        let host = std::path::PathBuf::from(std::env::var_os("ProgramFiles")?).join("dotnet/dotnet.exe");
        if !host.is_file() { return None; }
        let output = command_output(std::process::Command::new(&host).arg("--list-runtimes"),
            std::time::Duration::from_secs(15)).expect("query installed .NET runtimes");
        assert!(output.status.success(), ".NET runtime query failed: {}", String::from_utf8_lossy(&output.stderr));
        let text = String::from_utf8(output.stdout).expect(".NET runtime output");
        let version = text.lines().filter_map(|line| {
            let mut words = line.split_whitespace();
            if words.next()? != "Microsoft.NETCore.App" { return None; }
            let version = words.next()?;
            let parts = version.split('.').map(str::parse::<u32>).collect::<std::result::Result<Vec<_>, _>>().ok()?;
            (parts.len() == 3).then_some((parts, version))
        }).max_by(|a, b| a.0.cmp(&b.0))?;
        let managed = csharp_target_x64()?;
        std::fs::write(managed.with_extension("runtimeconfig.json"), format!(
            "{{\"runtimeOptions\":{{\"framework\":{{\"name\":\"Microsoft.NETCore.App\",\"version\":\"{}\"}}}}}}", version.1
        )).expect("write .NET runtime configuration");
        Some((host, managed))
    }).clone()
}

fn build_csharp_target(platform: &str) -> Option<std::path::PathBuf> {
    let system = std::env::var_os("SystemRoot")?;
    let compiler =
        std::path::PathBuf::from(system).join(r"Microsoft.NET\Framework64\v4.0.30319\csc.exe");
    if !compiler.is_file() {
        return None;
    }
    let dir = real_target_dir();
    let source = dir.join(format!("stork_csharp_{platform}.cs"));
    let exe = dir.join(format!("stork_csharp_{platform}.exe"));
    let code = format!(
        "using System;using System.IO;using System.Threading;\n\
         class StorkCSharpTarget {{ static void Main() {{\n\
         var d=@\"{}\";\n\
         File.WriteAllText(Path.Combine(d,\"ckpt_\"+System.Diagnostics.Process.GetCurrentProcess().Id+\".txt\"),\"\");\n\
         Thread.Sleep(60000); }}}}\n",
        dir.to_string_lossy().replace('"', "\"\"")
    );
    std::fs::write(&source, code).expect("write managed fixture source");
    let output = command_output(
        std::process::Command::new(&compiler)
            .args(["/nologo", "/target:exe", "/optimize+"])
            .arg(format!("/platform:{platform}"))
            .arg(format!("/out:{}", exe.display()))
            .arg(&source),
        std::time::Duration::from_secs(30),
    )
    .expect("start managed fixture compiler");
    assert!(
        output.status.success(),
        "managed fixture compilation failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(exe.is_file(), "compiler produced no managed fixture");
    Some(exe)
}
/// Skip note for optional real-target tools.
pub fn note_skipped(tool: &str) {
    assert!(
        std::env::var_os("STORK_REQUIRE_TOOLS").is_none(),
        "required coverage tool is missing: {tool}"
    );
    eprintln!("skipping: {tool} is not available on this host");
}
