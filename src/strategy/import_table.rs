//! Prepare IAT imports, commit PE/CLR changes, and retain allocations by outcome.
//!
//! The private patch module owns page protection and verified byte rollback.
//! This module owns managed-image policy and the lifetime of the import blob.
//! No Detours source is copied.
use crate::{
    Error, InjectedModule, LoadTiming, Result, Strategy, Target,
    error::{combine, pe as bad},
    paths,
    payload::Payload,
    pe::{self, DataDirectory, Headers, ImportDescriptor},
    remote::{self, RemoteAlloc},
};

mod patch;
use patch::{Fault, patch_headers};
use winapi::um::winnt::HANDLE;
#[cfg(test)]
use winapi::um::{memoryapi::VirtualProtectEx, winnt::*};
pub(crate) fn inject(target: &Target, payload: &Payload) -> Result<InjectedModule> {
    let process = target.process.cast();
    let ordinal = payload.import_ordinal()?;
    let (base, headers, original) = remote::main_image(process)?;
    let clr = clr_header(process, base, &headers)?;

    // Detours parity: a neutral (AnyCPU) PE32 main image inside an AMD64
    // process is widened to PE32+ in memory when it is pure-IL managed and
    // does not require 32 bits. Everything else must already be native
    // AMD64; mixed-mode 32-bit MSIL and 32BITREQUIRED managed images are
    // refused before any mutation.
    let (model, mut patched) = if headers.magic == 0x10b {
        let clr = clr.ok_or(Error::StrategyUnavailable {
            strategy: Strategy::ImportTableHijack,
            reason: "PE32 targets need a CLR header (managed AnyCPU)",
        })?;
        if clr.flags & COR_FLAG_ILONLY == 0 {
            return Err(Error::StrategyUnavailable {
                strategy: Strategy::ImportTableHijack,
                reason: "mixed-mode 32-bit managed targets are unsupported",
            });
        }
        if clr.flags & COR_FLAG_32BIT_REQUIRED != 0 {
            return Err(Error::StrategyUnavailable {
                strategy: Strategy::ImportTableHijack,
                reason: "32BITREQUIRED managed targets are unsupported",
            });
        }
        if headers.machine != 0x14c {
            return Err(Error::UnsupportedMachine(headers.machine));
        }
        let widened = pe::convert_pe32_to_pe64(&original)?;
        let mut model = Headers::parse_remote(&widened)?;
        // The PE32-era import table carries 32-bit thunks; the widened
        // image must not expose it to the 64-bit loader. Detours zeroes
        // the import directory for converted ILONLY images as well. The
        // commit stage overwrites the directory anyway.
        model.directories[1] = DataDirectory::default();
        (model, widened)
    } else {
        if headers.machine != 0x8664 {
            return Err(Error::UnsupportedMachine(headers.machine));
        }
        if let Some(clr) = clr
            && clr.flags & COR_FLAG_32BIT_REQUIRED != 0
        {
            return Err(Error::StrategyUnavailable {
                strategy: Strategy::ImportTableHijack,
                reason: "32BITREQUIRED managed targets are unsupported",
            });
        }
        (headers, original.clone())
    };

    let path = paths::import_path(payload.path())?;
    let old = read_imports(process, base, &model)?;
    let provisional = pe::build_imports(&old, &path, ordinal, 0)?;
    let allocation = RemoteAlloc::near(process, base, provisional.len())?;
    let result = (|| {
        let rva = u32::try_from(
            allocation
                .address
                .checked_sub(base)
                .ok_or_else(|| bad("allocation below image"))?,
        )
        .map_err(|_| bad("allocation RVA overflow"))?;
        let blob = pe::build_imports(&old, &path, ordinal, rva)?;
        remote::write(process, allocation.address, &blob)?;
        model.set_directory(
            &mut patched,
            1,
            DataDirectory {
                rva,
                size: blob.len() as u32,
            },
        )?;
        model.set_directory(&mut patched, 11, DataDirectory::default())?;
        if model.directories[12].rva == 0 {
            if model.directories[12].size != 0 {
                return Err(bad("IAT size without RVA"));
            }
            let old_import = model.directories[1];
            let fallback = model
                .sections
                .iter()
                .find(|section| {
                    old_import.rva != 0
                        && old_import.rva >= section.rva
                        && u64::from(old_import.rva)
                            < u64::from(section.rva) + u64::from(section.raw_size)
                })
                .map(|section| DataDirectory {
                    rva: section.rva,
                    size: section.raw_size,
                })
                .unwrap_or(DataDirectory {
                    rva,
                    size: blob.len() as u32,
                });
            model.set_directory(&mut patched, 12, fallback)?;
        } else {
            model.image_range(
                model.directories[12].rva,
                model.directories[12].size as usize,
            )?;
        }
        model.clear_checksum(&mut patched)?; // The image checksum is invalidated.
        commit_headers(
            process,
            base,
            &original,
            &patched,
            clr,
            Fault::None,
            Fault::None,
        )
    })();
    finish_injection(allocation, result)
}

fn finish_injection(mut allocation: RemoteAlloc, result: Result<()>) -> Result<InjectedModule> {
    match result {
        Ok(()) => {
            allocation.retain();
            Ok(InjectedModule {
                module: None,
                timing: LoadTiming::OnResume,
            })
        }
        Err(error) => {
            if error.must_not_resume() {
                allocation.retain();
                Err(error)
            } else {
                combine(Err(error), allocation.release())
            }
        }
    }
}

const COR_FLAG_ILONLY: u32 = 0x0000_0001;
const COR_FLAG_32BIT_REQUIRED: u32 = 0x0000_0002;

/// Commit both header regions before allowing the caller to release the import blob.
fn commit_headers(
    process: HANDLE,
    base: usize,
    original: &[u8],
    patched: &[u8],
    clr: Option<ClrHeader>,
    clr_fault: Fault,
    rollback_fault: Fault,
) -> Result<()> {
    patch_headers(process, base, original, patched, Fault::None)?;
    if let Some(clr) = clr
        && clr.flags & COR_FLAG_ILONLY != 0
        && let Err(update) = clear_ilonly(process, clr.va, clr_fault)
    {
        let rollback = patch_headers(process, base, patched, original, rollback_fault)
            .map_err(|error| Error::IatRollbackFailed.with_cleanup(error));
        return combine(Err(update), rollback);
    }
    Ok(())
}

/// The CLR directory state of a main image: remote address of the CLR header
/// and its flags. `None` for native images.
fn clr_header(process: HANDLE, base: usize, headers: &Headers) -> Result<Option<ClrHeader>> {
    let d = headers.directories[14];
    if d.rva == 0 {
        if d.size != 0 {
            return Err(bad("CLR size without RVA"));
        }
        return Ok(None);
    }
    if d.size < 72 {
        return Err(bad("truncated CLR directory"));
    }
    headers.image_range(d.rva, d.size as usize)?;
    headers.image_range(d.rva, 20)?;
    let va = base
        .checked_add(d.rva as usize)
        .ok_or_else(|| bad("CLR address overflow"))?;
    let bytes = remote::read(process, va, 20)?;
    let size = pe::u32_at(&bytes, 0)?;
    if size < 72 || size > d.size {
        return Err(bad("invalid CLR header size"));
    }
    let flags = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    Ok(Some(ClrHeader { va, flags }))
}

#[derive(Clone, Copy)]
struct ClrHeader {
    va: usize,
    flags: u32,
}

/// Clear the ILONLY flag of a remote CLR header. The header usually lives in
/// an executable page; the page keeps its execute permission while writable.
fn clear_ilonly(process: HANDLE, clr_va: usize, fault: Fault) -> Result<()> {
    let flags_va = clr_va
        .checked_add(16)
        .ok_or_else(|| bad("CLR flags address overflow"))?;
    let current = remote::read(process, flags_va, 4)?;
    let next = u32::from_le_bytes(current[..].try_into().unwrap()) & !COR_FLAG_ILONLY;
    patch_headers(process, flags_va, &current, &next.to_le_bytes(), fault)
}

fn read_imports(process: HANDLE, base: usize, h: &Headers) -> Result<Vec<ImportDescriptor>> {
    let d = h.directories[1];
    if d.rva == 0 {
        return if d.size == 0 {
            Ok(Vec::new())
        } else {
            Err(bad("import size without RVA"))
        };
    }
    if d.size != 0 {
        h.image_range(d.rva, d.size as usize)?;
    }
    let available = (h.image_size - d.rva.min(h.image_size)) as usize;
    let bound = if d.size == 0 {
        available
    } else {
        (d.size as usize).min(available)
    };
    let mut result = Vec::new();
    for i in 0..=pe::MAX_IMPORTS {
        let offset = i * ImportDescriptor::SIZE;
        if offset + ImportDescriptor::SIZE > bound {
            return Err(bad("unterminated or truncated import table"));
        }
        let address = base
            .checked_add(d.rva as usize)
            .and_then(|address| address.checked_add(offset))
            .ok_or_else(|| bad("import address overflow"))?;
        let descriptor =
            ImportDescriptor::parse(&remote::read(process, address, ImportDescriptor::SIZE)?)?;
        if descriptor.name == 0 {
            return Ok(result);
        }
        // Like Detours, copy descriptors and let the loader resolve names and
        // thunks. The bounded descriptor walk avoids nested remote-read costs.
        result.push(descriptor);
    }
    Err(bad("too many imports"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use winapi::um::processthreadsapi::GetCurrentProcess;

    #[test]
    fn import_walk_is_bounded_and_does_not_dereference_thunks() {
        let process = unsafe { GetCurrentProcess() };
        let size = (pe::MAX_IMPORTS + 1) * 20;
        let allocation = RemoteAlloc::new(process, size).unwrap();
        let descriptor = ImportDescriptor {
            name: u32::MAX,
            first_thunk: u32::MAX,
            original_first_thunk: u32::MAX,
            ..Default::default()
        };
        let mut bytes = vec![0; size];
        for chunk in bytes.as_chunks_mut::<20>().0 {
            descriptor.write(chunk);
        }
        remote::write(process, allocation.address, &bytes).unwrap();
        let mut headers = Headers {
            machine: 0x8664,
            magic: 0x20b,
            characteristics: 0,
            image_size: (size + 1) as u32,
            header_size: 1,
            directories: [DataDirectory::default(); 16],
            sections: vec![],
        };
        headers.directories[1] = DataDirectory {
            rva: 1,
            size: size as u32,
        };
        let base = allocation.address - 1;
        assert!(read_imports(process, base, &headers).is_err());
        remote::write(process, allocation.address + size - 20, &[0; 20]).unwrap();
        let imports = read_imports(process, base, &headers).unwrap();
        assert_eq!(imports.len(), pe::MAX_IMPORTS);
        assert!(imports.iter().all(|item| *item == descriptor));
        headers.directories[1].size = 20;
        assert!(read_imports(process, base, &headers).is_err());
        headers.directories[1].size = 0;
        assert_eq!(
            read_imports(process, base, &headers).unwrap().len(),
            pe::MAX_IMPORTS
        );
    }

    #[test]
    fn clr_patch_restores_bytes_and_protections_across_pages() {
        let process = unsafe { GetCurrentProcess() };
        let allocation = RemoteAlloc::new(process, 8192).unwrap();
        // Put the four-byte flags field across two differently protected pages.
        let flags_va = allocation.address + 4094;
        let original = 0x0002_0001u32.to_le_bytes();
        for fault in [Fault::PartialWrite, Fault::None] {
            remote::write(process, flags_va, &original).unwrap();
            let mut old = 0;
            for (offset, protection) in [(0, PAGE_READONLY), (4096, PAGE_EXECUTE_READ)] {
                assert_ne!(
                    unsafe {
                        VirtualProtectEx(
                            process,
                            (allocation.address + offset) as _,
                            4096,
                            protection,
                            &mut old,
                        )
                    },
                    0
                );
            }
            let result = clear_ilonly(process, flags_va - 16, fault);
            let expected = if fault == Fault::None {
                result.unwrap();
                0x0002_0000u32.to_le_bytes()
            } else {
                assert!(!result.unwrap_err().must_not_resume());
                original
            };
            assert_eq!(remote::read(process, flags_va, 4).unwrap(), expected);
            assert_eq!(
                remote::query(process, allocation.address).unwrap().Protect,
                PAGE_READONLY
            );
            assert_eq!(
                remote::query(process, allocation.address + 4096)
                    .unwrap()
                    .Protect,
                PAGE_EXECUTE_READ
            );
            assert_ne!(
                unsafe {
                    VirtualProtectEx(
                        process,
                        allocation.address as _,
                        8192,
                        PAGE_READWRITE,
                        &mut old,
                    )
                },
                0
            );
        }
    }

    #[test]
    fn managed_commit_failure_preserves_must_not_resume_errors() {
        let process = unsafe { GetCurrentProcess() };
        let allocation = RemoteAlloc::new(process, 8192).unwrap();
        let original = vec![1; 64];
        let patched = vec![2; 64];
        let clr = ClrHeader {
            va: allocation.address + 4096,
            flags: COR_FLAG_ILONLY,
        };
        for (clr_fault, rollback_fault, dangerous) in [
            (Fault::PartialWrite, Fault::None, false),
            (Fault::PartialWrite, Fault::Rollback, true),
            (Fault::Restore, Fault::None, true),
            (Fault::Rollback, Fault::None, true),
        ] {
            remote::write(process, allocation.address, &original).unwrap();
            remote::write(process, clr.va + 16, &clr.flags.to_le_bytes()).unwrap();
            let error = commit_headers(
                process,
                allocation.address,
                &original,
                &patched,
                Some(clr),
                clr_fault,
                rollback_fault,
            )
            .unwrap_err();
            assert_eq!(error.must_not_resume(), dangerous, "{error:?}");
            if rollback_fault == Fault::None {
                assert_eq!(
                    remote::read(process, allocation.address, original.len()).unwrap(),
                    original
                );
            } else {
                assert!(matches!(error, Error::Cleanup { .. }));
            }
            let blob = RemoteAlloc::new(process, 64).unwrap();
            let address = blob.address;
            assert!(finish_injection(blob, Err(error)).is_err());
            assert_eq!(
                remote::query(process, address).unwrap().State,
                if dangerous { MEM_COMMIT } else { MEM_FREE }
            );
            if dangerous {
                assert_ne!(
                    unsafe {
                        winapi::um::memoryapi::VirtualFreeEx(process, address as _, 0, MEM_RELEASE)
                    },
                    0
                );
            }
        }
    }

    #[test]
    fn failed_allocation_cleanup_keeps_the_operation_error() {
        let process = unsafe { GetCurrentProcess() };
        let allocation = RemoteAlloc::new(process, 64).unwrap();
        // Force the subsequent release to fail without leaving a live allocation.
        assert_ne!(
            unsafe {
                winapi::um::memoryapi::VirtualFreeEx(
                    process,
                    allocation.address as _,
                    0,
                    MEM_RELEASE,
                )
            },
            0
        );
        let error = finish_injection(allocation, Err(bad("original operation"))).unwrap_err();
        let Error::Cleanup { operation, cleanup } = error else {
            panic!("both errors must be retained")
        };
        assert!(operation.to_string().contains("original operation"));
        assert!(matches!(
            *cleanup,
            Error::Win32 {
                call: "VirtualFreeEx",
                ..
            }
        ));
    }

    #[test]
    fn clr_directory_and_declared_header_must_fit() {
        let process = unsafe { GetCurrentProcess() };
        let allocation = RemoteAlloc::new(process, 4096).unwrap();
        let mut headers = Headers {
            machine: 0x8664,
            magic: 0x20b,
            characteristics: 0,
            image_size: 4096,
            header_size: 512,
            directories: [DataDirectory::default(); 16],
            sections: Vec::new(),
        };
        for (rva, size, declared) in [
            (0, 72, 72u32),
            (512, 19, 72),
            (4090, 72, 72),
            (512, 72, 20),
            (512, 72, 80),
        ] {
            headers.directories[14] = DataDirectory { rva, size };
            remote::write(process, allocation.address + 512, &declared.to_le_bytes()).unwrap();
            assert!(clr_header(process, allocation.address, &headers).is_err());
        }
        headers.directories[14] = DataDirectory { rva: 512, size: 72 };
        remote::write(process, allocation.address + 512, &72u32.to_le_bytes()).unwrap();
        remote::write(
            process,
            allocation.address + 528,
            &COR_FLAG_ILONLY.to_le_bytes(),
        )
        .unwrap();
        assert_eq!(
            clr_header(process, allocation.address, &headers)
                .unwrap()
                .unwrap()
                .flags,
            COR_FLAG_ILONLY
        );
    }
    // --- Live suspended-child edge tests ---------------------------------
    mod live {
        #![allow(dead_code)]
        use super::*;
        use crate::target::Handle;

        include!("../../test-support/harness.rs");

        /// Temporarily write arbitrary bytes at a remote address, restoring
        /// each page's original protection right after its write.
        fn mem_patch(process: HANDLE, address: usize, bytes: &[u8]) {
            unsafe {
                let mut offset = 0;
                while offset < bytes.len() {
                    let va = address + offset;
                    let region = remote::query(process, va).unwrap();
                    assert_eq!(
                        region.State, MEM_COMMIT,
                        "mem_patch touched an uncommitted page at {va:#x}"
                    );
                    let region_start = region.BaseAddress as usize;
                    let region_end = region_start + region.RegionSize;
                    let page_start = va & !0xfff;
                    let page_end = (page_start + 0x1000).min(region_end);
                    let chunk = (bytes.len() - offset).min(page_end - va);
                    assert!(page_start >= region_start && page_end <= region_end);
                    let mut old = 0;
                    assert_ne!(
                        VirtualProtectEx(
                            process,
                            page_start as _,
                            page_end - page_start,
                            PAGE_READWRITE,
                            &mut old
                        ),
                        0,
                        "VirtualProtectEx {}",
                        winapi::um::errhandlingapi::GetLastError()
                    );
                    remote::write(process, va, &bytes[offset..offset + chunk]).unwrap();
                    assert_ne!(
                        VirtualProtectEx(
                            process,
                            page_start as _,
                            page_end - page_start,
                            old,
                            &mut old
                        ),
                        0,
                        "protection restore {}",
                        winapi::um::errhandlingapi::GetLastError()
                    );
                    offset += chunk;
                }
            }
        }
        #[test]
        fn no_imports_use_the_whole_allocation_for_iat() {
            let child = Child::spawn(&fixtures().noimport);
            let process = Handle(open_process(child.pid));
            let (base, headers, _) = remote::main_image(process.0).unwrap();
            assert_eq!(headers.directories[1], DataDirectory::default());
            assert_eq!(headers.directories[12], DataDirectory::default());
            let target = Target::not_started(process.0.cast(), Some(child.thread as _), child.pid);
            let payload = Payload::load(&fixtures().payload, Strategy::ImportTableHijack).unwrap();
            let _injected = inject(&target, &payload).unwrap();
            let (after, _) = remote::headers(process.0, base).unwrap();
            assert_ne!(after.directories[1].rva, 0);
            assert!(after.directories[1].size > 32);
            assert_eq!(after.directories[12], after.directories[1]);
        }
        #[test]
        fn size_zero_import_directory_walks_and_loads() {
            let payload = &fixtures().payload;
            let child = Child::spawn(&fixtures().entry);
            let process = Handle(open_process(child.pid));
            let (base, headers, original) = remote::main_image(process.0).unwrap();
            let mut zeroed_size = original.clone();
            // DataDirectory[1] size -> 0, VA kept: the walk must find the null
            // descriptor and still succeed.
            headers
                .set_directory(
                    &mut zeroed_size,
                    1,
                    DataDirectory {
                        rva: headers.directories[1].rva,
                        size: 0,
                    },
                )
                .unwrap();
            patch_headers(process.0, base, &original, &zeroed_size, Fault::None).unwrap();
            let (h2, _) = remote::headers(process.0, base).unwrap();
            assert_eq!(h2.directories[1].size, 0);

            let events = [
                create_event(child.pid, "Local\\stork_test_"),
                create_event(child.pid, "Local\\stork_ready_"),
                create_event(child.pid, "Local\\stork_pass_"),
            ];
            let target = Target::not_started(process.0.cast(), Some(child.thread as _), child.pid);
            let validated = Payload::load(payload, Strategy::ImportTableHijack).unwrap();
            let injected = inject(&target, &validated).unwrap();
            assert_eq!(injected.timing, LoadTiming::OnResume);
            assert!(!events[0].wait(0), "payload must not load before resume");
            assert_ne!(
                unsafe { winapi::um::processthreadsapi::ResumeThread(child.thread) },
                u32::MAX,
                "ResumeThread"
            );
            assert!(events[0].wait(10_000), "payload DllMain after resume");
            assert!(events[1].wait(1_000), "payload readiness");
            assert!(
                events[2].wait(10_000),
                "entry observed the payload (imports intact)"
            );
        }
        #[test]
        fn missing_iat_directory_falls_back_to_import_section() {
            let payload = &fixtures().payload;
            let child = Child::spawn(&fixtures().entry);
            let process = Handle(open_process(child.pid));
            let (base, headers, original) = remote::main_image(process.0).unwrap();
            assert_ne!(
                headers.directories[1].rva, 0,
                "fixture must import something"
            );
            let old_import = headers.directories[1];
            let section = headers
                .sections
                .iter()
                .find(|s| {
                    old_import.rva >= s.rva
                        && u64::from(old_import.rva)
                            < u64::from(s.rva) + u64::from(s.virtual_size.max(s.raw_size))
                })
                .expect("import section");
            let mut seeded = original.clone();
            // Absent IAT directory: rva and size both zero.
            headers
                .set_directory(&mut seeded, 12, DataDirectory::default())
                .unwrap();
            patch_headers(process.0, base, &original, &seeded, Fault::None).unwrap();

            let events = [
                create_event(child.pid, "Local\\stork_test_"),
                create_event(child.pid, "Local\\stork_pass_"),
            ];
            let target = Target::not_started(process.0.cast(), Some(child.thread as _), child.pid);
            let validated = Payload::load(payload, Strategy::ImportTableHijack).unwrap();
            assert_eq!(
                inject(&target, &validated).unwrap().timing,
                LoadTiming::OnResume
            );
            let (after, _) = remote::headers(process.0, base).unwrap();
            assert_eq!(
                after.directories[12].rva, section.rva,
                "IAT fallback must name the import section"
            );
            assert_eq!(after.directories[12].size, section.raw_size);
            assert_ne!(
                unsafe { winapi::um::processthreadsapi::ResumeThread(child.thread) },
                u32::MAX
            );
            assert!(events[0].wait(10_000), "payload DllMain after resume");
            assert!(
                events[1].wait(10_000),
                "entry ran with original imports intact"
            );
        }
        #[test]
        fn bound_import_directory_is_cleared() {
            let payload = &fixtures().payload;
            let child = Child::spawn(&fixtures().entry);
            let process = Handle(open_process(child.pid));
            let (base, headers, original) = remote::main_image(process.0).unwrap();
            let mut seeded = original.clone();
            headers
                .set_directory(
                    &mut seeded,
                    11,
                    DataDirectory {
                        rva: 0x2c0,
                        size: 0x40,
                    },
                )
                .unwrap();
            patch_headers(process.0, base, &original, &seeded, Fault::None).unwrap();

            let target = Target::not_started(process.0.cast(), Some(child.thread as _), child.pid);
            let validated = Payload::load(payload, Strategy::ImportTableHijack).unwrap();
            assert_eq!(
                inject(&target, &validated).unwrap().timing,
                LoadTiming::OnResume
            );
            let (after, _) = remote::headers(process.0, base).unwrap();
            assert_eq!(
                after.directories[11].rva, 0,
                "bound-import directory must be cleared"
            );
            assert_eq!(after.directories[11].size, 0);
            assert_ne!(
                after.directories[1].rva, 0,
                "import directory must be repointed"
            );
        }
        #[test]
        fn import_descriptor_bounds_and_loader_owned_names() {
            let child = Child::spawn(&fixtures().entry);
            let process = Handle(open_process(child.pid));
            let (base, headers, original) = remote::main_image(process.0).unwrap();
            let original_dir1 = headers.directories[1];
            // Descriptor bytes live in a data section; read them to locate the name.
            let first = ImportDescriptor::parse(
                &remote::read(process.0, base + original_dir1.rva as usize, 20).unwrap(),
            )
            .unwrap();
            let name_va = base + first.name as usize;
            // 1. Size without an RVA is inconsistent.
            let mut patch1 = original.clone();
            headers
                .set_directory(
                    &mut patch1,
                    1,
                    DataDirectory {
                        rva: 0,
                        size: headers.directories[1].size,
                    },
                )
                .unwrap();
            patch_headers(process.0, base, &original, &patch1, Fault::None).unwrap();
            let (h1, _) = remote::headers(process.0, base).unwrap();
            assert!(read_imports(process.0, base, &h1).is_err());
            // Restore.
            patch_headers(process.0, base, &patch1, &original, Fault::None).unwrap();
            // 2. Name validity belongs to the loader. Flood the image so
            // no NUL exists before the walk reaches the image boundary.
            let image = headers.image_size as usize;
            let flood = image.saturating_sub(first.name as usize).min(16 * 1024);
            assert!(flood > 64, "name must live inside the image");
            let original_names = remote::read(process.0, name_va, flood).unwrap();
            mem_patch(process.0, name_va, &vec![b'A'; flood]);
            let (h2, _) = remote::headers(process.0, base).unwrap();
            assert_eq!(read_imports(process.0, base, &h2).unwrap()[0], first);
            assert!(remote::read(process.0, name_va, 16).is_ok());
            // Restore the flooded bytes so the next case cannot fail for the old reason.
            mem_patch(process.0, name_va, &original_names);
            assert!(read_imports(process.0, base, &headers).is_ok());
            // 3. Name == 0 terminates the table, even with other fields set.
            mem_patch(process.0, base + original_dir1.rva as usize + 12, &[0u8; 4]);
            let (h3, _) = remote::headers(process.0, base).unwrap();
            assert!(read_imports(process.0, base, &h3).unwrap().is_empty());
        }
    }
}
