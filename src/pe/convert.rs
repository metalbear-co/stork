//! Detours-compatible PE32 widening without relocating header-resident data.

use super::{Headers, layout::*};
use crate::{Result, error::pe};
use pelite::image::*;

const MAX_CONVERSION_SECTIONS: usize = 32;

/// Copy a PE32 header region into a widened PE32+ layout (Detours `UpdateFrom32To64`).
///
/// Only the header bytes change: the optional header grows from 224 to 240
/// bytes, the image base moves to a 64-bit slot, the stack/heap fields widen,
/// and the section table shifts by 16 bytes. Section contents, RVAs, image
/// size, and header size are preserved. The input is validated before conversion;
/// its section table must leave room for the widened layout.
pub(crate) fn convert_pe32_to_pe64(b: &[u8]) -> Result<Vec<u8>> {
    let headers = Headers::parse_remote(b)?;
    if headers.magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC
        || headers.sections.len() > MAX_CONVERSION_SECTIONS
    {
        return Err(pe(
            "PE32 widening requires a PE32 image with at most 32 sections",
        ));
    }
    let nt = nt_offset(b)?;
    let opt = nt + NT_PREFIX_SIZE;
    let mut coff: IMAGE_FILE_HEADER = read(b, nt + FILE_HEADER_OFFSET)?;
    let opt_size = usize::from(coff.SizeOfOptionalHeader);
    let header_size = headers.header_size as usize;
    let count = headers.sections.len();
    let new_sections = opt + OPTIONAL_HEADER64_SIZE;
    let section_bytes = count * SECTION_HEADER_SIZE;
    let changed_end = new_sections + section_bytes;
    if changed_end > header_size {
        return Err(pe("no room to widen the PE32 optional header"));
    }
    for (index, directory) in headers.directories.iter().enumerate() {
        // The certificate directory uses file offsets, not mapped RVAs.
        if index != IMAGE_DIRECTORY_ENTRY_SECURITY
            && directory.rva != 0
            && directory.size != 0
            && (directory.rva as usize) < changed_end
            && u64::from(directory.rva) + u64::from(directory.size) > nt as u64
        {
            return Err(pe("header-resident directory overlaps PE32 widening"));
        }
    }
    let mut out = b[..header_size].to_vec();
    let source: IMAGE_OPTIONAL_HEADER32 = read(b, opt)?;
    let widened = IMAGE_OPTIONAL_HEADER64 {
        Magic: IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        LinkerVersion: source.LinkerVersion,
        SizeOfCode: source.SizeOfCode,
        SizeOfInitializedData: source.SizeOfInitializedData,
        SizeOfUninitializedData: source.SizeOfUninitializedData,
        AddressOfEntryPoint: source.AddressOfEntryPoint,
        BaseOfCode: source.BaseOfCode,
        ImageBase: u64::from(source.ImageBase),
        SectionAlignment: source.SectionAlignment,
        FileAlignment: source.FileAlignment,
        OperatingSystemVersion: source.OperatingSystemVersion,
        ImageVersion: source.ImageVersion,
        SubsystemVersion: source.SubsystemVersion,
        Win32VersionValue: source.Win32VersionValue,
        SizeOfImage: source.SizeOfImage,
        SizeOfHeaders: source.SizeOfHeaders,
        CheckSum: source.CheckSum,
        Subsystem: source.Subsystem,
        DllCharacteristics: source.DllCharacteristics,
        SizeOfStackReserve: u64::from(source.SizeOfStackReserve),
        SizeOfStackCommit: u64::from(source.SizeOfStackCommit),
        SizeOfHeapReserve: u64::from(source.SizeOfHeapReserve),
        SizeOfHeapCommit: u64::from(source.SizeOfHeapCommit),
        LoaderFlags: source.LoaderFlags,
        NumberOfRvaAndSizes: source.NumberOfRvaAndSizes,
        DataDirectory: [],
    };
    coff.Machine = IMAGE_FILE_MACHINE_AMD64;
    coff.SizeOfOptionalHeader = OPTIONAL_HEADER64_SIZE as u16;
    write(&mut out, nt + FILE_HEADER_OFFSET, &coff)?;
    write(&mut out, opt, &widened)?;
    let directories: Directories = read(b, opt + size_of::<IMAGE_OPTIONAL_HEADER32>())?;
    write(
        &mut out,
        opt + size_of::<IMAGE_OPTIONAL_HEADER64>(),
        &directories,
    )?;
    // The section table follows the complete optional header, including directories.
    let old_sections = opt + opt_size;
    out[new_sections..changed_end].copy_from_slice(&b[old_sections..old_sections + section_bytes]);
    Ok(out)
}
