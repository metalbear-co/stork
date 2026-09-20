//! Verified IAT header writes with byte rollback and per-page protection restore.
//!
//! This module owns the low-level transaction, but not the import allocation.
//! Its parent decides whether that allocation must survive the outcome.
use crate::{
    Error, Result,
    error::{combine, pe as bad, win32},
    remote,
};
use winapi::um::{memoryapi::VirtualProtectEx, sysinfoapi::GetSystemInfo, winnt::*};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    None,
    #[cfg(test)]
    PartialWrite,
    #[cfg(test)]
    Rollback,
    #[cfg(test)]
    Restore,
}

struct Protection {
    address: usize,
    size: usize,
    old: u32,
}

fn restore(process: HANDLE, ranges: &[Protection], fault: Fault) -> Result<()> {
    let mut result = Ok(());
    for range in ranges.iter().rev() {
        let mut unused = 0;
        if unsafe {
            VirtualProtectEx(
                process,
                range.address as _,
                range.size,
                range.old,
                &mut unused,
            )
        } == 0
        {
            let error = win32("VirtualProtectEx restore");
            result = combine(result, Err(error));
        }
    }
    #[cfg(test)]
    if fault == Fault::Restore {
        result = combine(result, Err(bad("test restoration failure")));
    }
    let _ = fault;
    result.map_err(|error| Error::ProtectionRestore(Box::new(error)))
}

pub(super) fn patch_headers(
    process: HANDLE,
    base: usize,
    original: &[u8],
    patched: &[u8],
    fault: Fault,
) -> Result<()> {
    if original.len() != patched.len() {
        return Err(bad("patch and rollback sizes differ"));
    }
    let mut system = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut system) };
    let page = system.dwPageSize as usize;
    let start = base / page * page;
    let end = base
        .checked_add(original.len())
        .and_then(|v| v.checked_add(page - 1))
        .ok_or_else(|| bad("header protection overflow"))?
        / page
        * page;
    let mut ranges = Vec::new();
    for address in (start..end).step_by(page) {
        let result = (|| {
            let region = remote::query(process, address)?;
            let executable = region.Protect
                & (PAGE_EXECUTE
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY)
                != 0;
            let protection = if executable {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_READWRITE
            };
            let mut old = 0;
            if unsafe { VirtualProtectEx(process, address as _, page, protection, &mut old) } == 0 {
                return Err(win32("VirtualProtectEx writable"));
            }
            ranges.push(Protection {
                address,
                size: page,
                old,
            });
            Ok(())
        })();
        if result.is_err() {
            return combine(result, restore(process, &ranges, Fault::None));
        }
    }
    let operation = (|| {
        #[cfg(test)]
        if matches!(fault, Fault::PartialWrite | Fault::Rollback) {
            remote::write(process, base, &patched[..patched.len() / 2])?;
            return Err(bad("test partial write"));
        }
        remote::write(process, base, patched)?;
        if remote::read(process, base, patched.len())? != patched {
            return Err(bad("header verification failed"));
        }
        Ok(())
    })();
    if operation.is_err() {
        let rollback = (|| {
            #[cfg(test)]
            if fault == Fault::Rollback {
                return Err(bad("test rollback write failure"));
            }
            remote::write(process, base, original)?;
            if remote::read(process, base, original.len())? != original {
                return Err(bad("rollback verification failed"));
            }
            Ok(())
        })();
        let failure = combine(
            operation,
            rollback.map_err(|error| Error::IatRollbackFailed.with_cleanup(error)),
        );
        return combine(failure, restore(process, &ranges, fault));
    }
    restore(process, &ranges, fault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::RemoteAlloc;
    use winapi::um::processthreadsapi::GetCurrentProcess;

    #[test]
    fn mismatched_patch_lengths_fail_before_touching_memory() {
        assert!(patch_headers(std::ptr::null_mut(), 0, &[1], &[2, 3], Fault::None).is_err());
    }

    #[test]
    fn partial_write_restores_bytes_and_each_page() {
        unsafe {
            let process = GetCurrentProcess();
            let mut a = RemoteAlloc::new(process, 8192).unwrap();
            let old = vec![1; 8192];
            remote::write(process, a.address, &old).unwrap();
            let mut unused = 0;
            assert_ne!(
                VirtualProtectEx(process, a.address as _, 4096, PAGE_READONLY, &mut unused),
                0
            );
            assert_ne!(
                VirtualProtectEx(
                    process,
                    (a.address + 4096) as _,
                    4096,
                    PAGE_EXECUTE_READ,
                    &mut unused
                ),
                0
            );
            assert!(
                patch_headers(
                    process,
                    a.address,
                    &old,
                    &vec![2; 8192],
                    Fault::PartialWrite
                )
                .is_err()
            );
            assert_eq!(remote::read(process, a.address, 8192).unwrap(), old);
            assert_eq!(
                remote::query(process, a.address).unwrap().Protect,
                PAGE_READONLY
            );
            assert_eq!(
                remote::query(process, a.address + 4096).unwrap().Protect,
                PAGE_EXECUTE_READ
            );
            let error = patch_headers(process, a.address, &old, &vec![3; 8192], Fault::Rollback)
                .unwrap_err();
            assert!(error.must_not_resume());
            let message = error.to_string();
            assert!(message.contains("test partial write"));
            assert!(message.contains("test rollback write failure"));
            assert!(matches!(
                patch_headers(process, a.address, &old, &vec![4; 8192], Fault::Restore),
                Err(Error::ProtectionRestore(_))
            ));
            a.release().unwrap();
        }
    }
}
