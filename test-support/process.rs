use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    time::{Duration, Instant},
};
use winapi::um::{jobapi2::*, winnt::*};

struct Job(OwnedHandle);

impl Job {
    fn new() -> io::Result<Self> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle.cast()) });
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle().cast(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn assign(&self, process: HANDLE) -> io::Result<()> {
        if unsafe { AssignProcessToJobObject(self.0.as_raw_handle().cast(), process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn stop(&self) -> io::Result<()> {
        if unsafe { TerminateJobObject(self.0.as_raw_handle().cast(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let start = Instant::now();
        loop {
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe {
                QueryInformationJobObject(
                    self.0.as_raw_handle().cast(),
                    JobObjectBasicAccountingInformation,
                    (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&info) as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if info.ActiveProcesses == 0 {
                return Ok(());
            }
            if start.elapsed() >= Duration::from_secs(5) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "job processes did not terminate",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

// Command does not expose the primary-thread handle. The child is still
// suspended, so its initial thread can be found before any tool code runs.
fn resume_tool(pid: u32) -> io::Result<()> {
    use winapi::um::{
        handleapi::INVALID_HANDLE_VALUE,
        processthreadsapi::{OpenThread, ResumeThread},
        tlhelp32::*,
    };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.cast()) };
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    if unsafe { Thread32First(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }
    loop {
        if entry.th32OwnerProcessID == pid {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                return Err(io::Error::last_os_error());
            }
            let thread = unsafe { OwnedHandle::from_raw_handle(thread.cast()) };
            if unsafe { ResumeThread(thread.as_raw_handle().cast()) } == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            return Ok(());
        }
        if unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
}

/// Bound tool execution and terminate its job, including descendants, on every exit.
/// Descendants cannot keep a pipe open and prevent the supervisor from returning.
pub fn command_output(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    use std::{
        fs::File,
        io::{Read, Seek},
        process::Stdio,
        time::{Duration, Instant},
    };
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Capture {
        file: Option<File>,
        path: std::path::PathBuf,
    }
    impl Capture {
        fn new(label: &str) -> std::io::Result<Self> {
            // `command_output` is `include!`d into several test modules, so every
            // copy owns a distinct `SEQUENCE` that starts at zero while sharing one
            // process id. Concurrent copies therefore propose identical names, and a
            // crashed prior run with a recycled pid can leave one behind. Skip past
            // any name a peer or an earlier run already claimed instead of failing.
            let temp_dir = std::env::temp_dir();
            let mut last = None;
            for _ in 0..1024 {
                let id = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = temp_dir.join(format!(
                    "stork_tool_{}_{id}_{label}.log",
                    std::process::id()
                ));
                match File::options()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(file) => {
                        return Ok(Self {
                            file: Some(file),
                            path,
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        last = Some(error);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(last.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "exhausted tool capture name attempts",
                )
            }))
        }
        fn read(&mut self) -> std::io::Result<Vec<u8>> {
            let file = self.file.as_mut().unwrap();
            file.rewind()?;
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err(std::io::Error::other("tool output exceeds 1 MiB"));
            }
            Ok(bytes)
        }
    }
    impl Drop for Capture {
        fn drop(&mut self) {
            self.file.take();
            if let Err(error) = std::fs::remove_file(&self.path) {
                eprintln!("remove tool capture {}: {error}", self.path.display());
            }
        }
    }
    use std::os::windows::{io::AsRawHandle, process::CommandExt};
    let job = Job::new()?;
    let mut stdout = Capture::new("stdout")?;
    let mut stderr = Capture::new("stderr")?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.file.as_ref().unwrap().try_clone()?)
        .stderr(stderr.file.as_ref().unwrap().try_clone()?);
    command.creation_flags(0x0800_0004); // CREATE_NO_WINDOW | CREATE_SUSPENDED
    let spawned = command.spawn();
    command.creation_flags(0);
    // Release the command's copies before Capture attempts Windows deletion.
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = spawned?;
    let start = Instant::now();
    let setup = job
        .assign(child.as_raw_handle().cast())
        .and_then(|()| resume_tool(child.id()));
    let result = setup.and_then(|()| {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Err(error) => break Err(error),
                Ok(None) if start.elapsed() >= timeout => {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("tool process {} exceeded {timeout:?}", child.id()),
                    ));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    let result = match (result, job.stop()) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(std::io::Error::new(
            error.kind(),
            format!("{error}; job cleanup failed: {cleanup}"),
        )),
    };
    let status = match result {
        Ok(status) => status,
        Err(error) => {
            let killed = child.kill();
            let cleanup_start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return Err(error),
                    Ok(None) if cleanup_start.elapsed() < Duration::from_secs(5) => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    outcome => {
                        return Err(std::io::Error::new(
                            error.kind(),
                            format!("{error}; cleanup failed: kill={killed:?}, wait={outcome:?}"),
                        ));
                    }
                }
            }
        }
    };
    Ok(std::process::Output {
        status,
        stdout: stdout.read()?,
        stderr: stderr.read()?,
    })
}
