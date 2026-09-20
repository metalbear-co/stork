//! Injection into real-world targets: a managed C# program, python.exe, and
//! node.exe. These complement the fixture targets with production loader
//! graphs and a genuine .NET main image.
//!
//! The tools are optional. When a tool is missing on the host, its tests
//! print a skip note and pass. The payload assertions stay identical to the
//! fixture suites: pid-named events, exact full-path module enumeration,
//! and a checkpoint file that the target's own main code writes.
#![cfg(windows)]
mod common;

use common::*;
use serial_test::serial;
use stork::{Error, Injector, LoadTiming, Strategy, Target};

fn crt_not_started(exe: &std::path::Path, args: &[&str], label: &str) {
    let fixtures = fixtures();
    let child = Child::spawn_with_args(exe, args);
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut std::ffi::c_void,
        Some(child.thread as *mut std::ffi::c_void),
        child.pid,
    );
    let injected = unsafe { Injector::new().inject(target, &fixtures.payload) }
        .unwrap_or_else(|e| panic!("{label} CRT injection: {e}"));
    assert_eq!(injected.timing, LoadTiming::Immediate);
    assert!(injected.module.is_some(), "{label}: module must be present");

    // The payload loaded on the remote thread while the target main code
    // never ran.
    events
        .test
        .wait_object(10_000, "payload DllMain before resume");
    events
        .ready
        .wait_object(10_000, "payload readiness before resume");
    assert!(
        module_loaded(child.process, &fixtures.payload),
        "{label}: payload must be enumerated"
    );

    child.resume("real target");
    let checkpoint = checkpoint_path(child.pid);
    assert!(
        wait_for_file(&checkpoint, 15_000),
        "{label}: target main code must run after resume"
    );
    let _ = std::fs::remove_file(&checkpoint);
}

fn apc_not_started(exe: &std::path::Path, args: &[&str], label: &str) {
    let fixtures = fixtures();
    let child = Child::spawn_with_args(exe, args);
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut std::ffi::c_void,
        Some(child.thread as *mut std::ffi::c_void),
        child.pid,
    );
    let injected = unsafe {
        Injector::with_strategy(Strategy::QueueUserApc).inject(target, &fixtures.payload)
    }
    .unwrap_or_else(|e| panic!("{label} APC queue: {e}"));
    assert_eq!(injected.timing, LoadTiming::OnResume);
    assert!(injected.module.is_none());
    events.test.assert_clear("payload before resume");

    child.resume("real target apc");
    events
        .test
        .wait_object(10_000, "payload DllMain after resume");
    assert!(
        module_loaded(child.process, &fixtures.payload),
        "{label}: payload must be enumerated"
    );
    let checkpoint = checkpoint_path(child.pid);
    assert!(
        wait_for_file(&checkpoint, 15_000),
        "{label}: target main code must run after resume"
    );
    let _ = std::fs::remove_file(&checkpoint);
}

fn iat_not_started(exe: &std::path::Path, args: &[&str], label: &str) {
    let fixtures = fixtures();
    let child = Child::spawn_with_args(exe, args);
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut std::ffi::c_void,
        Some(child.thread as *mut std::ffi::c_void),
        child.pid,
    );
    let injected = unsafe {
        Injector::with_strategy(Strategy::ImportTableHijack).inject(target, &fixtures.payload)
    }
    .unwrap_or_else(|e| panic!("{label} IAT rewrite: {e}"));
    assert_eq!(injected.timing, LoadTiming::OnResume);
    events.test.assert_clear("payload before resume");

    child.resume("real target iat");
    events
        .test
        .wait_object(10_000, "payload DllMain after resume");
    events
        .ready
        .wait_object(10_000, "payload readiness after resume");
    assert!(
        module_loaded(child.process, &fixtures.payload),
        "{label}: payload must be enumerated"
    );
    let checkpoint = checkpoint_path(child.pid);
    assert!(
        wait_for_file(&checkpoint, 15_000),
        "{label}: target main code must run after the loader init"
    );
    let _ = std::fs::remove_file(&checkpoint);
}

/// LoaderComplete path: run the target until its main code checkpoint, then
/// suspend the primary thread and inject with the remote-thread strategy.
fn crt_after_start(exe: &std::path::Path, args: &[&str], label: &str) {
    let fixtures = fixtures();
    let child = Child::spawn_with_args(exe, args);
    let events = Events::create_all(child.pid);
    let checkpoint = checkpoint_path(child.pid);
    child.resume("real target checkpoint");
    assert!(
        wait_for_file(&checkpoint, 15_000),
        "{label}: main checkpoint before suspend"
    );
    let _ = std::fs::remove_file(&checkpoint);

    assert_eq!(child.suspend("real target inject"), 0);
    let target = Target::loader_complete(
        child.process as *mut std::ffi::c_void,
        Some(child.thread as *mut std::ffi::c_void),
        child.pid,
    );
    let injected = unsafe { Injector::new().inject(target, &fixtures.payload) }
        .unwrap_or_else(|e| panic!("{label} CRT into running target: {e}"));
    assert_eq!(injected.timing, LoadTiming::Immediate);
    events
        .test
        .wait_object(10_000, "payload DllMain while suspended");
    assert!(
        module_loaded(child.process, &fixtures.payload),
        "{label}: payload must be enumerated"
    );
    assert_eq!(child.resume("real target release"), 1);
    assert!(child.alive(), "{label}: target must stay alive");
}

// ---------------------------------------------------------------------------
// python.exe
// ---------------------------------------------------------------------------

fn python() -> Option<std::path::PathBuf> {
    probe_python()
}

#[test]
#[serial]
fn python_crt_before_entry() {
    let Some(exe) = python() else {
        note_skipped("python");
        return;
    };
    let code = python_code(&real_target_dir());
    let args = ["-c", code.as_str()];
    crt_not_started(&exe, &args, "python");
}

#[test]
#[serial]
fn python_apc_before_entry() {
    let Some(exe) = python() else {
        note_skipped("python");
        return;
    };
    let code = python_code(&real_target_dir());
    let args = ["-c", code.as_str()];
    apc_not_started(&exe, &args, "python");
}

#[test]
#[serial]
fn python_iat_before_entry() {
    let Some(exe) = python() else {
        note_skipped("python");
        return;
    };
    let code = python_code(&real_target_dir());
    let args = ["-c", code.as_str()];
    iat_not_started(&exe, &args, "python");
}

#[test]
#[serial]
fn python_crt_after_start() {
    let Some(exe) = python() else {
        note_skipped("python");
        return;
    };
    let code = python_code(&real_target_dir());
    let args = ["-c", code.as_str()];
    crt_after_start(&exe, &args, "python");
}

// ---------------------------------------------------------------------------
// node.exe
// ---------------------------------------------------------------------------

fn node() -> Option<std::path::PathBuf> {
    probe_node()
}

#[test]
#[serial]
fn node_crt_before_entry() {
    let Some(exe) = node() else {
        note_skipped("node");
        return;
    };
    let code = node_code(&real_target_dir());
    let args = ["-e", code.as_str()];
    crt_not_started(&exe, &args, "node");
}

#[test]
#[serial]
fn node_apc_before_entry() {
    let Some(exe) = node() else {
        note_skipped("node");
        return;
    };
    let code = node_code(&real_target_dir());
    let args = ["-e", code.as_str()];
    apc_not_started(&exe, &args, "node");
}

#[test]
#[serial]
fn node_iat_before_entry() {
    let Some(exe) = node() else {
        note_skipped("node");
        return;
    };
    let code = node_code(&real_target_dir());
    let args = ["-e", code.as_str()];
    iat_not_started(&exe, &args, "node");
}

#[test]
#[serial]
fn node_crt_after_start() {
    let Some(exe) = node() else {
        note_skipped("node");
        return;
    };
    let code = node_code(&real_target_dir());
    let args = ["-e", code.as_str()];
    crt_after_start(&exe, &args, "node");
}

// ---------------------------------------------------------------------------
// Managed C# program
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn csharp_crt_before_entry() {
    let Some(exe) = csharp_target() else {
        note_skipped("csharp (csc)");
        return;
    };
    crt_not_started(&exe, &[], "csharp");
}

#[test]
#[serial]
fn csharp_apc_before_entry() {
    let Some(exe) = csharp_target() else {
        note_skipped("csharp (csc)");
        return;
    };
    apc_not_started(&exe, &[], "csharp");
}

#[test]
#[serial]
fn csharp_crt_after_start() {
    let Some(exe) = csharp_target() else {
        note_skipped("csharp (csc)");
        return;
    };
    crt_after_start(&exe, &[], "csharp");
}

/// Detours-parity IAT: a neutral (AnyCPU) managed exe is widened to PE32+
/// in memory and the payload is appended to its import table before the
/// loader runs. The managed main code must still run afterwards.
#[test]
#[serial]
fn csharp_anycpu_iat_loads_before_entry() {
    let Some(exe) = csharp_target() else {
        note_skipped("csharp (csc)");
        return;
    };
    managed_iat_loads(&exe, "csharp anycpu");
}

/// An x64-targeted managed image needs no conversion; the payload descriptor
/// is appended to the existing (mscoree) imports and ILONLY is cleared.
#[test]
#[serial]
fn csharp_x64_iat_loads_before_entry() {
    let Some(exe) = csharp_target_x64() else {
        note_skipped("csharp x64 (csc)");
        return;
    };
    managed_iat_loads(&exe, "csharp x64");
}

fn managed_iat_loads(exe: &std::path::Path, label: &str) {
    let fixtures = fixtures();
    let child = Child::spawn_with_args(exe, &[]);
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut std::ffi::c_void,
        Some(child.thread as *mut std::ffi::c_void),
        child.pid,
    );
    let injected = unsafe {
        Injector::with_strategy(Strategy::ImportTableHijack).inject(target, &fixtures.payload)
    }
    .unwrap_or_else(|e| panic!("{label}: IAT into managed target failed: {e}"));
    assert_eq!(injected.timing, LoadTiming::OnResume);
    events.test.assert_clear("payload before resume");

    // Read the mutation back from the never-run target: the image must be
    // AMD64 PE32+ with a repointed import directory and a cleared ILONLY
    // flag in the CLR header.
    verify_managed_mutation(child.process, exe, label);

    child.resume("managed iat");
    events
        .test
        .wait_object(10_000, "payload DllMain after resume");
    events
        .ready
        .wait_object(10_000, "payload readiness after resume");
    assert!(
        module_loaded(child.process, &fixtures.payload),
        "{label}: payload must be enumerated"
    );
    let checkpoint = checkpoint_path(child.pid);
    assert!(
        wait_for_file(&checkpoint, 20_000),
        "{label}: the managed main code must run after injection"
    );
    let _ = std::fs::remove_file(&checkpoint);
    // The managed app keeps running after the mutation and the CLR boot.
    assert!(child.alive(), "{label}: the target must stay alive");
}

#[test]
#[serial]
fn mixed_mode_x64_remote_thread_and_apc() {
    let Some(exe) = mixed_target() else {
        note_skipped("C++/CLI");
        return;
    };
    let dir = real_target_dir();
    let args = [dir.to_str().unwrap()];
    // Establish this is an actual mixed image, not a pure-IL fixture with flags patched.
    let bytes = std::fs::read(&exe).unwrap();
    use pelite::pe64::Pe;
    let file = pelite::pe64::PeFile::from_bytes(&bytes).unwrap();
    let directory = file.data_directory()[14];
    let offset = file.rva_to_file_offset(directory.VirtualAddress).unwrap() as usize;
    let flags = u32::from_le_bytes(bytes[offset + 16..offset + 20].try_into().unwrap());
    assert_eq!(flags & 1, 0, "fixture must contain native code");
    assert_ne!(directory.VirtualAddress, 0);
    crt_not_started(&exe, &args, "C++/CLI mixed-mode");
    apc_not_started(&exe, &args, "C++/CLI mixed-mode");
    crt_after_start(&exe, &args, "C++/CLI mixed-mode");
}

#[test]
#[serial]
fn mixed_mode_iat_before_entry() {
    let Some(exe) = mixed_target() else {
        note_skipped("C++/CLI");
        return;
    };
    let dir = real_target_dir();
    iat_not_started(&exe, &[dir.to_str().unwrap()], "C++/CLI mixed-mode");
}

#[test]
#[serial]
fn dotnet_iat_before_entry() {
    let Some((host, managed)) = dotnet_target() else {
        note_skipped("modern .NET runtime and C# compiler");
        return;
    };
    iat_not_started(&host, &[managed.to_str().unwrap()], "modern .NET host");
}

#[test]
#[serial]
fn dotnet_host_remote_thread_and_apc() {
    let Some((host, managed)) = dotnet_target() else {
        note_skipped("modern .NET runtime and C# compiler");
        return;
    };
    let args = [managed.to_str().unwrap()];
    crt_not_started(&host, &args, "modern .NET host");
    apc_not_started(&host, &args, "modern .NET host");
    crt_after_start(&host, &args, "modern .NET host");
}

/// Read the target's main image and assert the persisted mutation state:
/// AMD64 PE32+ headers, a nonzero import directory, and a CLR header whose
/// ILONLY flag is cleared. The base is located without the loader module
/// list, which does not exist for a never-run process.
fn verify_managed_mutation(
    process: winapi::um::winnt::HANDLE,
    _exe: &std::path::Path,
    label: &str,
) {
    let base = main_image_base(process, label);
    let read = |offset: usize, size: usize| -> Vec<u8> {
        let mut out = vec![0u8; size];
        let mut read_count = 0;
        let ok = unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                process,
                (base + offset) as *const winapi::ctypes::c_void,
                out.as_mut_ptr() as *mut winapi::ctypes::c_void,
                size,
                &mut read_count,
            )
        };
        assert!(
            ok != 0 && read_count == size,
            "{label}: ReadProcessMemory failed"
        );
        out
    };
    let header = read(0, 0x400);
    let e_lfanew = u32::from_le_bytes(header[60..64].try_into().unwrap()) as usize;
    let machine = u16::from_le_bytes(header[e_lfanew + 4..e_lfanew + 6].try_into().unwrap());
    let magic = u16::from_le_bytes(header[e_lfanew + 24..e_lfanew + 26].try_into().unwrap());
    assert_eq!(
        (machine, magic),
        (0x8664, 0x20b),
        "{label}: the mutated image must be AMD64 PE32+"
    );
    let dir1_rva = u32::from_le_bytes(
        header[e_lfanew + 24 + 112 + 8..e_lfanew + 24 + 112 + 12]
            .try_into()
            .unwrap(),
    );
    assert_ne!(dir1_rva, 0, "{label}: import directory must be repointed");
    let dir14_rva = u32::from_le_bytes(
        header[e_lfanew + 24 + 112 + 14 * 8..e_lfanew + 24 + 112 + 14 * 8 + 4]
            .try_into()
            .unwrap(),
    );
    assert_ne!(dir14_rva, 0, "{label}: CLR directory must be intact");
    // IMAGE_COR20_HEADER: Flags at byte 16; ILONLY must be cleared.
    let clr = read(dir14_rva as usize, 20);
    let flags = u32::from_le_bytes(clr[16..20].try_into().unwrap());
    assert_eq!(
        flags & 0x1,
        0,
        "{label}: ILONLY must be cleared in the CLR header (flags {flags:#x})"
    );
}

/// A managed image marked 32BITREQUIRED is refused before any mutation
/// (Detours parity). The flag is set in the CLR header of the fixture copy.
#[test]
#[serial]
fn csharp_32bitrequired_refused_before_mutation() {
    let Some(base) = csharp_target_x64() else {
        note_skipped("csharp x64 (csc)");
        return;
    };
    let dir = real_target_dir();
    let copy = dir.join("stork_csharp_32bitrequired.exe");
    std::fs::copy(&base, &copy).expect("copy managed fixture");
    assert!(set_cor_32bit_required(&copy), "patch managed fixture");
    let fixtures = fixtures();
    let child = Child::spawn_with_args(&copy, &[]);
    let image_base = main_image_base(child.process, "32BITREQUIRED");
    // Compare both regions that managed injection could mutate, without resuming.
    let snapshot = || {
        let mut bytes = vec![0u8; 0x200];
        let mut count = 0;
        let read = |offset: usize, bytes: &mut Vec<u8>, count: &mut usize| {
            assert_ne!(
                unsafe {
                    winapi::um::memoryapi::ReadProcessMemory(
                        child.process,
                        (image_base + offset) as _,
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        count,
                    )
                },
                0
            );
            assert_eq!(*count, bytes.len());
        };
        read(0, &mut bytes, &mut count);
        let nt = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(bytes[nt + 84..nt + 88].try_into().unwrap()) as usize;
        assert!(size <= 1024 * 1024, "fixture image unexpectedly large");
        bytes.resize(size, 0);
        read(0, &mut bytes, &mut count);
        let directory = nt + 24 + 112 + 14 * 8;
        let clr_rva =
            u32::from_le_bytes(bytes[directory..directory + 4].try_into().unwrap()) as usize;
        let mut clr = vec![0; 72];
        read(clr_rva, &mut clr, &mut count);
        (bytes, clr)
    };
    let before = snapshot();
    let events = Events::create_all(child.pid);
    let target = Target::not_started(
        child.process as *mut std::ffi::c_void,
        Some(child.thread as *mut std::ffi::c_void),
        child.pid,
    );
    let result = unsafe {
        Injector::with_strategy(Strategy::ImportTableHijack).inject(target, &fixtures.payload)
    };
    assert!(
        matches!(result, Err(Error::StrategyUnavailable { .. })),
        "32BITREQUIRED managed target must be refused, got {result:?}"
    );
    events.test.assert_clear("nothing may load before resume");
    assert_eq!(snapshot(), before, "refusal changed the never-run image");
}

/// Set the 32BITREQUIRED flag in the CLR header of a managed PE file on disk.
/// Locates the CLR directory through the section table of the image.
fn set_cor_32bit_required(path: &std::path::Path) -> bool {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut header = [0u8; 1024];
    let read_ok = file.read_exact(&mut header).is_ok();
    if !read_ok || &header[..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes(header[60..64].try_into().unwrap()) as usize;
    let nt = e_lfanew;
    if header[nt..nt + 4] != *b"PE\0\0" {
        return false;
    }
    let count = u16::from_le_bytes(header[nt + 6..nt + 8].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(header[nt + 20..nt + 22].try_into().unwrap()) as usize;
    let opt = nt + 24;
    let dir_rva = u32::from_le_bytes(
        header[opt + 112 + 14 * 8..opt + 112 + 14 * 8 + 4]
            .try_into()
            .unwrap(),
    );
    if dir_rva == 0 {
        return false;
    }
    let mut section_offset = opt + opt_size;
    let mut found = None;
    for _ in 0..count {
        let name_ok = header.len() >= section_offset + 40;
        if !name_ok {
            return false;
        }
        let va = u32::from_le_bytes(
            header[section_offset + 12..section_offset + 16]
                .try_into()
                .unwrap(),
        );
        let raw_size = u32::from_le_bytes(
            header[section_offset + 16..section_offset + 20]
                .try_into()
                .unwrap(),
        );
        let raw_off = u32::from_le_bytes(
            header[section_offset + 20..section_offset + 24]
                .try_into()
                .unwrap(),
        );
        let end = va as u64 + raw_size as u64;
        if (dir_rva as u64) >= va as u64 && (dir_rva as u64) < end {
            found = Some(raw_off as u64 + (dir_rva as u64 - va as u64));
            break;
        }
        section_offset += 40;
    }
    let Some(flags_offset) = found else {
        return false;
    };
    // IMAGE_COR20_HEADER: Flags at byte 16.
    let mut buffer = [0u8; 8];
    if file.seek(SeekFrom::Start(flags_offset + 16)).is_err()
        || file.read_exact(&mut buffer).is_err()
    {
        return false;
    }
    let flags = u32::from_le_bytes(buffer[..4].try_into().unwrap());
    let patched = flags | 0x2;
    file.seek(SeekFrom::Start(flags_offset + 16)).is_ok()
        && file.write_all(&patched.to_le_bytes()).is_ok()
}

fn main_image_base(process: winapi::um::winnt::HANDLE, label: &str) -> usize {
    let mut image_name = path_output_buffer();
    let mut count = image_name.len_with_nul() as u32;
    let ok = unsafe {
        winapi::um::winbase::QueryFullProcessImageNameW(
            process,
            1,
            image_name.as_mut_ptr(),
            &mut count,
        )
    };
    assert!(ok != 0, "{label}: QueryFullProcessImageNameW failed");
    let image_name = finish_path_output(image_name, count as usize);
    let mut base = None;
    let mut address = 0usize;
    while address < usize::MAX - 0x1_0000 {
        let mut info: winapi::um::winnt::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let size = unsafe {
            winapi::um::memoryapi::VirtualQueryEx(
                process,
                address as *const winapi::ctypes::c_void,
                &mut info,
                std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
            )
        };
        if size == 0 {
            break;
        }
        let next = (info.BaseAddress as usize).saturating_add(info.RegionSize);
        if next <= address {
            break;
        }
        if info.State == winapi::um::winnt::MEM_COMMIT
            && info.Type == winapi::um::winnt::MEM_IMAGE
            && info.BaseAddress == info.AllocationBase
            && info.Protect & (winapi::um::winnt::PAGE_GUARD | winapi::um::winnt::PAGE_NOACCESS)
                == 0
        {
            let mut mapped = path_output_buffer();
            let n = unsafe {
                winapi::um::psapi::GetMappedFileNameW(
                    process,
                    info.BaseAddress,
                    mapped.as_mut_ptr(),
                    mapped.len_with_nul() as u32,
                )
            };
            if n > 0 {
                let mapped = finish_path_output(mapped, n as usize);
                if mapped == image_name {
                    base = Some(info.AllocationBase as usize);
                    break;
                }
            }
        }
        address = next;
    }
    base.unwrap_or_else(|| panic!("{label}: main image base not found"))
}
