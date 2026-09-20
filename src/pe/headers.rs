//! PE header decoding, payload validation, and bounded header mutation.
//!
//! Both PE32 and PE32+ use pelite's checked views; the decoded model retains
//! only fields stork uses.

use super::layout::*;
use crate::{Result, error::pe};
use pelite::{
    image::*,
    pe64::{Pe, PeFile},
};
use std::mem::{offset_of, size_of};

const MAX_SECTIONS: usize = 96;
const MAX_OPTIONAL_HEADER_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct Section {
    pub virtual_size: u32,
    pub rva: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct Headers {
    pub machine: u16,
    pub magic: u16,
    pub characteristics: u16,
    pub image_size: u32,
    pub header_size: u32,
    pub directories: [DataDirectory; DIRECTORY_COUNT],
    pub sections: Vec<Section>,
}
/// Validate one section against image bounds and its predecessors.
fn check_section(
    sections: &[Section],
    s: &Section,
    header_size: u32,
    image_size: u32,
) -> Result<()> {
    let end = s
        .rva
        .checked_add(s.virtual_size.max(s.raw_size))
        .ok_or_else(|| pe("section overflow"))?;
    if s.rva < header_size || end > image_size {
        return Err(pe("section outside image"));
    }
    for old in sections {
        if s.rva < old.rva + old.virtual_size.max(old.raw_size) && old.rva < end {
            return Err(pe("overlapping sections"));
        }
    }
    Ok(())
}

impl Headers {
    /// Parse a native AMD64 payload; remote managed images use `parse_remote`.
    pub(crate) fn parse(b: &[u8]) -> Result<Self> {
        let nt = nt_offset(b)?;
        let file: IMAGE_FILE_HEADER = read(b, nt + FILE_HEADER_OFFSET)?;
        machine_gate(file.Machine)?;
        let headers = Self::parse_remote(b)?;
        if headers.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(pe("expected PE32+"));
        }
        Ok(headers)
    }

    /// Decode either format. Process bitness and managed-image conversion policy
    /// belong to the caller, independently of the on-disk header format.
    pub(crate) fn parse_remote(b: &[u8]) -> Result<Self> {
        let nt = nt_offset(b)?;
        let file =
            pelite::PeFile::from_bytes(b).map_err(|e| pe(&format!("invalid PE layout: {e:?}")))?;
        let coff = file.file_header();
        let count = usize::from(coff.NumberOfSections);
        if count == 0 || count > MAX_SECTIONS {
            return Err(pe("invalid section count"));
        }
        let (magic, image_size, header_size, dirs, fixed_size) = match file.optional_header() {
            pelite::Wrap::T32(h) => (
                h.Magic,
                h.SizeOfImage,
                h.SizeOfHeaders,
                h.NumberOfRvaAndSizes,
                size_of::<IMAGE_OPTIONAL_HEADER32>(),
            ),
            pelite::Wrap::T64(h) => (
                h.Magic,
                h.SizeOfImage,
                h.SizeOfHeaders,
                h.NumberOfRvaAndSizes,
                size_of::<IMAGE_OPTIONAL_HEADER64>(),
            ),
        };
        let opt_size = usize::from(coff.SizeOfOptionalHeader);
        if !(fixed_size + size_of::<Directories>()..=MAX_OPTIONAL_HEADER_SIZE).contains(&opt_size) {
            return Err(pe("invalid optional-header size"));
        }
        bytes(b, nt + NT_PREFIX_SIZE, opt_size)?;
        if (dirs as usize) < DIRECTORY_COUNT
            || dirs as usize > (opt_size - fixed_size) / size_of::<IMAGE_DATA_DIRECTORY>()
        {
            return Err(pe("invalid data-directory count"));
        }
        if header_size as usize > MAX_HEADERS || header_size == 0 || header_size > image_size {
            return Err(pe("invalid image/header size"));
        }
        bytes(b, 0, header_size as usize)?;
        if nt + NT_PREFIX_SIZE + opt_size + count * SECTION_HEADER_SIZE > header_size as usize {
            return Err(pe("sections exceed headers"));
        }
        let mut directories = [DataDirectory::default(); DIRECTORY_COUNT];
        for (dst, src) in directories.iter_mut().zip(file.data_directory()) {
            dst.rva = src.VirtualAddress;
            dst.size = src.Size;
        }
        let mut sections = Vec::with_capacity(count);
        for header in file.section_headers().iter() {
            let section = Section {
                virtual_size: header.VirtualSize,
                rva: header.VirtualAddress,
                raw_size: header.SizeOfRawData,
                raw_offset: header.PointerToRawData,
            };
            check_section(&sections, &section, header_size, image_size)?;
            sections.push(section);
        }
        Ok(Self {
            machine: coff.Machine,
            magic,
            characteristics: coff.Characteristics,
            image_size,
            header_size,
            directories,
            sections,
        })
    }
    pub(crate) fn image_range(&self, rva: u32, size: usize) -> Result<()> {
        if (rva as usize)
            .checked_add(size)
            .is_none_or(|end| end > self.image_size as usize)
        {
            return Err(pe("RVA outside image"));
        }
        Ok(())
    }
    /// RVA-to-file translation over a byte buffer. Production paths validate
    /// against remote memory directly; this helper backs the parser tests.
    #[cfg(test)]
    pub(crate) fn file_range<'a>(&self, b: &'a [u8], rva: u32, n: usize) -> Result<&'a [u8]> {
        self.image_range(rva, n)?;
        let file = PeFile::from_bytes(b).map_err(|e| pe(&format!("invalid PE layout: {e:?}")))?;
        let offset = file
            .rva_to_file_offset(rva)
            .map_err(|e| pe(&format!("RVA has no file data: {e:?}")))?;
        bytes(b, offset, n)
    }
    pub(crate) fn validate_file(&self, b: &[u8]) -> Result<()> {
        bytes(b, 0, self.header_size as usize)?;
        for s in &self.sections {
            if s.raw_size > 0 {
                if s.raw_offset < self.header_size {
                    return Err(pe("section overlaps file headers"));
                }
                bytes(b, s.raw_offset as usize, s.raw_size as usize)?;
            }
        }
        if self.characteristics & IMAGE_FILE_DLL == 0 {
            return Err(pe("payload is not a DLL"));
        }
        Ok(())
    }
    /// Detours imports ordinal 1; do not silently choose another export.
    pub(crate) fn import_ordinal(&self, b: &[u8]) -> Result<u16> {
        let d = self.directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if d.rva == 0 || (d.size as usize) < size_of::<IMAGE_EXPORT_DIRECTORY>() {
            return Err(pe("payload has no export directory"));
        }
        self.image_range(d.rva, d.size as usize)?;
        let file = PeFile::from_bytes(b).map_err(|e| pe(&format!("invalid PE layout: {e:?}")))?;
        let exports = file
            .exports()
            .map_err(|e| pe(&format!("invalid export directory: {e:?}")))?;
        if exports.image().Base > 1 {
            return Err(pe("payload must export ordinal 1"));
        }
        let by = exports
            .by()
            .map_err(|e| pe(&format!("invalid export tables: {e:?}")))?;
        match by
            .ordinal(1)
            .map_err(|_| pe("payload must export ordinal 1"))?
        {
            pelite::pe64::exports::Export::Symbol(rva) => {
                file.rva_to_file_offset(*rva)
                    .map_err(|_| pe("payload export is not backed by file data"))?;
            }
            pelite::pe64::exports::Export::Forward(_) => {}
        }
        Ok(1)
    }
    /// Patch a standard PE32+ directory in a validated local header buffer.
    pub(crate) fn set_directory(&self, b: &mut [u8], index: usize, d: DataDirectory) -> Result<()> {
        if self.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || index >= DIRECTORY_COUNT {
            return Err(pe("invalid PE32+ directory mutation"));
        }
        let offset = nt_offset(b)?
            + NT_PREFIX_SIZE
            + size_of::<IMAGE_OPTIONAL_HEADER64>()
            + index * size_of::<IMAGE_DATA_DIRECTORY>();
        write(
            b,
            offset,
            &IMAGE_DATA_DIRECTORY {
                VirtualAddress: d.rva,
                Size: d.size,
            },
        )
    }
    /// The IAT rewrite invalidates the original image checksum.
    pub(crate) fn clear_checksum(&self, b: &mut [u8]) -> Result<()> {
        if self.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(pe("expected PE32+"));
        }
        let offset = nt_offset(b)? + NT_PREFIX_SIZE + offset_of!(IMAGE_OPTIONAL_HEADER64, CheckSum);
        write(b, offset, &0u32)
    }
}
