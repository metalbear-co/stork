//! Remote process validation, memory ownership, and image discovery.

use crate::paths::normalized;
use crate::{
    Error, LoaderState, Result, Strategy, Target,
    error::{combine, pe, win32},
    pe::Headers,
};
use wincorda::{NullTerminated, WCHAR};

use std::{
    ffi::OsString,
    mem::{size_of, zeroed},
    num::NonZeroUsize,
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr::null_mut,
};

use winapi::{
    shared::minwindef::{DWORD, HMODULE},
    um::{
        fileapi::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, GetFileInformationByHandle, OPEN_EXISTING,
        },
        handleapi::INVALID_HANDLE_VALUE,
        libloaderapi::*,
        memoryapi::*,
        processthreadsapi::*,
        psapi::*,
        sysinfoapi::*,
        winbase::QueryFullProcessImageNameW,
        winnt::*,
        wow64apiset::IsWow64Process2,
    },
};
// WinBase.h constant omitted by winapi 0.3.9; request a native device path.
const PROCESS_NAME_NATIVE: DWORD = 0x00000001;

// Resource and retry policies, independent of Windows structure layouts.
const MAX_TRANSFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_REGION_QUERIES: usize = 1_000_000;
const PATH_BUFFER_UNITS: NonZeroUsize = NonZeroUsize::new(32 * 1024).unwrap();
const MODULE_ENUMERATION_ATTEMPTS: usize = 5;
const INITIAL_MODULE_CAPACITY: usize = 256;
const MAX_MODULE_LIST_BYTES: usize = 1024 * 1024;
const LOAD_LIBRARY_PROBE_BYTES: usize = 32;
const TESTED_STARTUP_MAJOR_VERSION: u32 = 10;
const TESTED_STARTUP_BUILDS: [u32; 2] = [26200, 26100];
const EXECUTABLE_PROTECTION: DWORD =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

fn system_info() -> SYSTEM_INFO {
    let mut info = unsafe { zeroed() };
    unsafe { GetSystemInfo(&mut info) };
    info
}

/// Every address-space walk must advance without wrapping or skipping a gap.
fn region_end(region: &MEMORY_BASIC_INFORMATION, address: usize) -> Result<usize> {
    let start = region.BaseAddress as usize;
    let end = start
        .checked_add(region.RegionSize)
        .ok_or_else(|| pe("memory region overflow"))?;
    if start > address || end <= address {
        return Err(pe("memory region does not contain scan address"));
    }
    Ok(end)
}

/// Windows path APIs return UTF-16 units, excluding the terminator.
fn finish_path(
    mut buffer: NullTerminated<'static, WCHAR>,
    length: usize,
) -> Result<NullTerminated<'static, WCHAR>> {
    if length >= buffer.len_with_nul() {
        return Err(pe("remote path too long"));
    }
    if buffer.len() != length {
        return Err(pe("remote path length does not match terminator"));
    }
    buffer.shrink_to_null();
    Ok(buffer)
}

pub(crate) fn read(process: HANDLE, address: usize, size: usize) -> Result<Vec<u8>> {
    if size > MAX_TRANSFER_BYTES || address.checked_add(size).is_none() {
        return Err(pe("remote read exceeds bounds"));
    }
    let mut b = vec![0; size];
    let mut count = 0;
    if unsafe {
        ReadProcessMemory(
            process,
            address as _,
            b.as_mut_ptr().cast(),
            size,
            &mut count,
        )
    } == 0
    {
        return Err(win32("ReadProcessMemory"));
    }
    if count != size {
        return Err(pe("short remote read"));
    }
    Ok(b)
}
pub(crate) fn write(process: HANDLE, address: usize, b: &[u8]) -> Result<()> {
    if b.len() > MAX_TRANSFER_BYTES || address.checked_add(b.len()).is_none() {
        return Err(pe("remote write exceeds bounds"));
    }
    let mut count = 0;
    if unsafe {
        WriteProcessMemory(
            process,
            address as _,
            b.as_ptr().cast(),
            b.len(),
            &mut count,
        )
    } == 0
    {
        return Err(win32("WriteProcessMemory"));
    }
    if count != b.len() {
        return Err(pe("short remote write"));
    }
    Ok(())
}
pub(crate) struct RemoteAlloc {
    pub process: HANDLE,
    pub address: usize,
    armed: bool,
}

impl RemoteAlloc {
    pub fn new(process: HANDLE, size: usize) -> Result<Self> {
        Self::at(process, 0, size)
    }

    /// Initialize an allocation, reporting both write and cleanup errors on failure.
    pub fn with_bytes(process: HANDLE, bytes: &[u8]) -> Result<Self> {
        let mut allocation = Self::new(process, bytes.len())?;
        if let Err(error) = write(process, allocation.address, bytes) {
            return combine(Err(error), allocation.release());
        }
        Ok(allocation)
    }
    fn at(process: HANDLE, address: usize, size: usize) -> Result<Self> {
        let p = unsafe {
            VirtualAllocEx(
                process,
                address as _,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if p.is_null() {
            return Err(win32("VirtualAllocEx"));
        }
        Ok(Self {
            process,
            address: p as usize,
            armed: true,
        })
    }
    pub fn retain(&mut self) {
        self.armed = false;
    }
    pub fn release(&mut self) -> Result<()> {
        if unsafe { VirtualFreeEx(self.process, self.address as _, 0, MEM_RELEASE) } == 0 {
            return Err(win32("VirtualFreeEx"));
        }
        self.armed = false;
        Ok(())
    }
    pub fn near(process: HANDLE, base: usize, size: usize) -> Result<Self> {
        let sys = system_info();
        let gran = sys.dwAllocationGranularity as usize;
        if gran == 0 {
            return Err(pe("invalid allocation granularity"));
        }
        let limit = base
            .checked_add(u32::MAX as usize)
            .ok_or_else(|| pe("address overflow"))?;
        let mut address = base;
        let mut attempts = 0;
        while address < limit && attempts < MAX_REGION_QUERIES {
            attempts += 1;
            let m = query(process, address)?;
            let end = region_end(&m, address)?;
            if m.State == MEM_FREE {
                let candidate = address
                    .checked_next_multiple_of(gran)
                    .ok_or_else(|| pe("alignment overflow"))?;
                let fits = candidate
                    .checked_add(size)
                    .is_some_and(|v| v <= end && v <= limit);
                if fits && let Ok(mut allocation) = Self::at(process, candidate, size) {
                    if allocation.address >= base
                        && allocation
                            .address
                            .checked_add(size)
                            .is_some_and(|v| v <= limit)
                    {
                        return Ok(allocation);
                    }
                    allocation.release()?;
                }
            }
            address = end;
        }
        Err(Error::StrategyUnavailable {
            strategy: Strategy::ImportTableHijack,
            reason: "no allocation fits the 32-bit RVA range",
        })
    }
}

impl Drop for RemoteAlloc {
    fn drop(&mut self) {
        if self.armed {
            unsafe {
                VirtualFreeEx(self.process, self.address as _, 0, MEM_RELEASE);
            }
        }
    }
}
pub(crate) fn query(process: HANDLE, address: usize) -> Result<MEMORY_BASIC_INFORMATION> {
    let mut m = unsafe { zeroed() };
    let count = unsafe {
        VirtualQueryEx(
            process,
            address as _,
            &mut m,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if count == 0 {
        return Err(win32("VirtualQueryEx"));
    }
    if count != size_of::<MEMORY_BASIC_INFORMATION>() {
        return Err(pe("short memory information query"));
    }
    Ok(m)
}
pub(crate) fn headers(process: HANDLE, base: usize) -> Result<(Headers, Vec<u8>)> {
    let dos = read(process, base, crate::pe::DOS_HEADER_SIZE)?;
    let nt = crate::pe::nt_offset(&dos)?;
    let prefix = read(process, base, nt + crate::pe::HEADER_PREFIX_SIZE)?;
    let size = crate::pe::header_read_size(&prefix)?;
    let b = read(process, base, size)?;
    let h = Headers::parse_remote(&b)?;
    Ok((h, b))
}

#[derive(Debug)]
pub(crate) struct Mapping {
    pub base: usize,
    pub path: NullTerminated<'static, WCHAR>,
}
pub(crate) fn mapped_name(
    process: HANDLE,
    address: usize,
) -> Result<NullTerminated<'static, WCHAR>> {
    let mut b = NullTerminated::<WCHAR>::zeroed(PATH_BUFFER_UNITS);
    let n = unsafe {
        GetMappedFileNameW(
            process,
            address as _,
            b.as_mut_ptr(),
            b.len_with_nul() as u32,
        )
    };
    if n == 0 {
        return Err(win32("GetMappedFileNameW"));
    }
    finish_path(b, n as usize)
}
pub(crate) fn images(process: HANDLE) -> Result<Vec<Mapping>> {
    let mut result = Vec::new();
    let mut address = 0;
    let sys = system_info();
    let limit = sys.lpMaximumApplicationAddress as usize;
    let mut count = 0;
    while address < limit {
        count += 1;
        if count > MAX_REGION_QUERIES {
            return Err(pe("image scan limit"));
        }
        let m = query(process, address)?;
        let next = region_end(&m, address)?;
        if m.Type == MEM_IMAGE
            && m.State == MEM_COMMIT
            && m.BaseAddress == m.AllocationBase
            && m.Protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
        {
            result.push(Mapping {
                base: m.BaseAddress as usize,
                path: mapped_name(process, m.BaseAddress as usize)?,
            });
        }
        address = next;
    }
    Ok(result)
}
/// On-disk identity (volume + file index) of the file behind an NT device path
/// such as `\Device\HarddiskVolumeN\...`. Reaching the object namespace from
/// Win32 requires the `\\?\GLOBALROOT` prefix. Comparing identity rather than
/// path text tolerates 8.3 short names, casing, and links naming one file.
fn file_identity(device_path: &[u16]) -> Result<(u32, u32, u32)> {
    let mut wide: Vec<u16> = r"\\?\GLOBALROOT".encode_utf16().collect();
    wide.extend_from_slice(device_path);
    wide.push(0);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(win32("CreateFileW"));
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(win32("GetFileInformationByHandle"));
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}
pub(crate) fn main_image(process: HANDLE) -> Result<(usize, Headers, Vec<u8>)> {
    let mut expected = NullTerminated::<WCHAR>::zeroed(PATH_BUFFER_UNITS);
    let mut count = expected.len_with_nul() as u32;
    if unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_NATIVE,
            expected.as_mut_ptr(),
            &mut count,
        )
    } == 0
    {
        return Err(win32("QueryFullProcessImageNameW"));
    }
    let expected = finish_path(expected, count as usize)?;
    // The kernel names the same on-disk file inconsistently across APIs:
    // `GetMappedFileNameW` (behind `images`) can report an 8.3 short component
    // (`PROGRA~1`) where `QueryFullProcessImageNameW` reports the long one
    // (`Program Files`). Match by on-disk identity, which ignores spelling.
    let expected = file_identity(expected.as_bytes())?;
    let mut candidates = Vec::new();
    for m in images(process)? {
        let (h, b) = headers(process, m.base)?;
        if h.characteristics & IMAGE_FILE_DLL != 0 {
            continue;
        }
        if file_identity(m.path.as_bytes())? != expected {
            continue;
        }
        let mut address = m.base;
        let end = m
            .base
            .checked_add(h.image_size as usize)
            .ok_or_else(|| pe("image extent overflow"))?;
        while address < end {
            let region = query(process, address)?;
            if region.AllocationBase as usize != m.base || region.Type != MEM_IMAGE {
                return Err(pe("image extends beyond mapping"));
            }
            let next = region_end(&region, address)?;
            address = next;
        }
        candidates.push((m.base, h, b));
    }
    if candidates.len() != 1 {
        return Err(pe("main executable mapping is missing or ambiguous"));
    }
    Ok(candidates.pop().unwrap())
}
/// Convert the API byte count to handles without silently dropping a tail.
fn module_count(bytes: usize) -> Result<usize> {
    if bytes > MAX_MODULE_LIST_BYTES || !bytes.is_multiple_of(size_of::<HMODULE>()) {
        return Err(pe("invalid module enumeration size"));
    }
    Ok(bytes / size_of::<HMODULE>())
}

pub(crate) fn module_list(process: HANDLE) -> Result<Vec<(usize, PathBuf)>> {
    let mut last_error = None;
    let mut list: Vec<HMODULE> = vec![null_mut(); INITIAL_MODULE_CAPACITY];
    for _ in 0..MODULE_ENUMERATION_ATTEMPTS {
        let mut needed = 0;
        if unsafe {
            EnumProcessModulesEx(
                process,
                list.as_mut_ptr(),
                std::mem::size_of_val(list.as_slice()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        } == 0
        {
            return Err(win32("EnumProcessModulesEx"));
        }
        let count = module_count(needed as usize)?;
        if count > list.len() {
            list.resize(count, null_mut());
            continue;
        }
        let mut result = Vec::new();
        let mut retry = false;
        for &h in &list[..count] {
            let mut b = NullTerminated::<WCHAR>::zeroed(PATH_BUFFER_UNITS);
            let n = unsafe {
                GetModuleFileNameExW(process, h, b.as_mut_ptr(), b.len_with_nul() as u32)
            } as usize;
            if n == 0 {
                last_error = Some(win32("GetModuleFileNameExW"));
                retry = true;
                break;
            }
            let b = finish_path(b, n)?;
            result.push((h as usize, PathBuf::from(OsString::from_wide(b.as_bytes()))));
        }
        if !retry {
            return Ok(result);
        }
    }
    Err(last_error.unwrap_or(Error::ModuleNotFound))
}
pub(crate) fn find_module(process: HANDLE, path: &Path) -> Result<usize> {
    let expected = normalized(path);
    module_list(process)?
        .into_iter()
        .find(|(_, p)| normalized(p) == expected)
        .map(|(h, _)| h)
        .ok_or(Error::ModuleNotFound)
}
pub(crate) fn validate(target: &Target) -> Result<()> {
    unsafe {
        if target.process.is_null()
            || target.process.cast() == INVALID_HANDLE_VALUE
            || target.pid == 0
        {
            return Err(Error::InvalidTarget("invalid process handle or pid"));
        }
        let pid = GetProcessId(target.process.cast());
        if pid == 0 {
            return Err(win32("GetProcessId"));
        }
        if pid != target.pid || pid == GetCurrentProcessId() {
            return Err(Error::InvalidTarget(
                "process/pid mismatch or self-injection",
            ));
        }
        if let Some(h) = target.main_thread {
            if h.is_null() {
                return Err(Error::InvalidTarget("null thread handle"));
            }
            let owner = GetProcessIdOfThread(h.cast());
            if owner == 0 {
                return Err(win32("GetProcessIdOfThread"));
            }
            if owner != pid {
                return Err(Error::InvalidTarget(
                    "thread belongs to a different process",
                ));
            }
        }
        for process in [GetCurrentProcess(), target.process.cast()] {
            let mut machine = 0;
            let mut native = 0;
            if IsWow64Process2(process, &mut machine, &mut native) == 0 {
                return Err(win32("IsWow64Process2"));
            }
            crate::pe::machine_gate(if machine == IMAGE_FILE_MACHINE_UNKNOWN {
                native
            } else {
                machine
            })?;
        }
    }
    if !cfg!(target_arch = "x86_64") {
        return Err(Error::UnsupportedMachine(0));
    }
    Ok(())
}
pub(crate) fn load_library_address(target: &Target, strategy: Strategy) -> Result<usize> {
    let name: NullTerminated<WCHAR> = "kernel32.dll".into();
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        return Err(win32("GetModuleHandleW"));
    }
    let local = unsafe { GetProcAddress(module, c"LoadLibraryW".as_ptr()) } as usize;
    if local == 0 {
        return Err(win32("GetProcAddress"));
    }
    let process = unsafe { GetCurrentProcess() };
    let local_region = query(process, local)?;
    let base = local_region.AllocationBase as usize;
    let name = mapped_name(process, local)?;
    let (local_headers, _) = headers(process, base)?;
    let offset = local
        .checked_sub(base)
        .ok_or_else(|| pe("function precedes module"))?;
    for image in images(target.process.cast())? {
        if image.path == name {
            let (remote_headers, _) = headers(target.process.cast(), image.base)?;
            if remote_headers.image_size != local_headers.image_size
                || remote_headers.machine != local_headers.machine
            {
                return Err(pe("LoadLibrary module differs"));
            }
            let address = image
                .base
                .checked_add(offset)
                .ok_or_else(|| pe("function address overflow"))?;
            let region = query(target.process.cast(), address)?;
            if region.AllocationBase as usize != image.base
                || region.State != MEM_COMMIT
                || region.Protect & EXECUTABLE_PROTECTION == 0
                || region.Protect & (PAGE_GUARD | PAGE_NOACCESS) != 0
            {
                return Err(pe("remote LoadLibrary address is not executable"));
            }
            if read(process, local, LOAD_LIBRARY_PROBE_BYTES)?
                != read(target.process.cast(), address, LOAD_LIBRARY_PROBE_BYTES)?
            {
                return Err(pe("remote LoadLibrary code differs"));
            }
            return Ok(address);
        }
    }
    // Tested startup exception: Windows 11 build 26200 and Windows Server 2025 build
    // 26100, native AMD64, never-run child. The startup loader maps the system image
    // before dispatch. This is an empirical compatibility scope, not a Windows API
    // guarantee. Refuse other builds and collisions.
    if target.loader_state == LoaderState::NotStarted && tested_startup_build() {
        let system =
            std::env::var_os("SystemRoot").ok_or(Error::InvalidTarget("SystemRoot is missing"))?;
        let expected = PathBuf::from(system).join("System32").join("kernel32.dll");
        let actual = module_list(process)?
            .into_iter()
            .find(|(h, _)| *h == base)
            .map(|(_, p)| p)
            .ok_or(Error::ModuleNotFound)?;
        if normalized(&actual) != normalized(&expected) {
            return Err(Error::StrategyUnavailable {
                strategy,
                reason: "fresh-child forwarded LoadLibrary module is outside the tested scope",
            });
        }
        let region = query(target.process.cast(), base)?;
        let image_end = base
            .checked_add(local_headers.image_size as usize)
            .ok_or_else(|| pe("image extent overflow"))?;
        if region.State == MEM_FREE && region_end(&region, base)? >= image_end {
            return Ok(local);
        }
    }
    Err(Error::StrategyUnavailable {
        strategy,
        reason: "LoadLibrary implementation is absent in the target; startup address is not validated on this OS",
    })
}

fn tested_startup_build() -> bool {
    unsafe {
        let name: NullTerminated<WCHAR> = "ntdll.dll".into();
        let ntdll = GetModuleHandleW(name.as_ptr());
        if ntdll.is_null() {
            return false;
        }
        let address = GetProcAddress(ntdll, c"RtlGetVersion".as_ptr());
        if address.is_null() {
            return false;
        }
        let f: unsafe extern "system" fn(PRTL_OSVERSIONINFOW) -> winapi::shared::ntdef::NTSTATUS =
            std::mem::transmute(address);
        let mut v: RTL_OSVERSIONINFOW = zeroed();
        v.dwOSVersionInfoSize = size_of::<RTL_OSVERSIONINFOW>() as u32;
        f(&mut v) == 0
            && v.dwMajorVersion == TESTED_STARTUP_MAJOR_VERSION
            && TESTED_STARTUP_BUILDS.contains(&v.dwBuildNumber)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfers_reject_bounds_before_using_the_handle() {
        assert!(matches!(read(null_mut(), usize::MAX, 1), Err(Error::Pe(_))));
        assert!(matches!(
            read(null_mut(), 0, MAX_TRANSFER_BYTES + 1),
            Err(Error::Pe(_))
        ));
        assert!(matches!(
            write(std::ptr::null_mut(), usize::MAX, &[1]),
            Err(Error::Pe(_))
        ));
    }
    #[test]
    fn region_walk_rejects_gaps_stalls_and_overflow() {
        let mut region: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        region.BaseAddress = 0x1000usize as _;
        region.RegionSize = 0x1000;
        assert_eq!(region_end(&region, 0x1000).unwrap(), 0x2000);
        assert_eq!(region_end(&region, 0x1800).unwrap(), 0x2000);
        for address in [0, 0x2000, 0x3000] {
            assert!(region_end(&region, address).is_err());
        }
        region.RegionSize = 0;
        assert!(region_end(&region, 0x1000).is_err());
        region.RegionSize = usize::MAX;
        assert!(region_end(&region, 0x1000).is_err());
    }
    #[test]
    fn module_counts_require_complete_handles_within_the_limit() {
        assert_eq!(module_count(0).unwrap(), 0);
        assert_eq!(module_count(size_of::<HMODULE>()).unwrap(), 1);
        assert_eq!(
            module_count(MAX_MODULE_LIST_BYTES).unwrap(),
            MAX_MODULE_LIST_BYTES / size_of::<HMODULE>()
        );
        for bytes in [
            1,
            size_of::<HMODULE>() + 1,
            MAX_MODULE_LIST_BYTES + size_of::<HMODULE>(),
            usize::MAX,
        ] {
            assert!(module_count(bytes).is_err());
        }
    }
    #[test]
    fn path_results_reject_truncation_and_preserve_utf16() {
        let path: Vec<u16> = "module-\u{1f980}".encode_utf16().collect();
        let mut units = path.clone();
        units.push(0);
        let buffer = NullTerminated::try_from(units).unwrap();
        let finished = finish_path(buffer.clone(), path.len()).unwrap();
        assert_eq!(finished.as_bytes(), path);
        assert_eq!(finished.len_with_nul(), path.len() + 1);
        assert!(finish_path(buffer.clone(), buffer.len_with_nul()).is_err());
        assert!(finish_path(buffer, usize::MAX).is_err());
    }

    #[test]
    fn path_output_checks_reported_length_before_shrinking() {
        let mut buffer = NullTerminated::<WCHAR>::zeroed(PATH_BUFFER_UNITS);
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.len_with_nul(), PATH_BUFFER_UNITS.get());
        buffer.as_mut_slice()[..4].copy_from_slice(&[b'a' as u16, b'b' as u16, b'c' as u16, 0]);
        let finished = finish_path(buffer.clone(), 3).unwrap();
        assert_eq!(finished.as_bytes_with_nul(), &[97, 98, 99, 0]);
        // An early NUL or an understated count must not silently change the path.
        assert!(finish_path(buffer.clone(), 4).is_err());
        assert!(finish_path(buffer.clone(), 2).is_err());
        buffer.as_mut_slice().fill(b'x' as u16);
        assert!(finish_path(buffer, PATH_BUFFER_UNITS.get() - 1).is_err());
    }
}
