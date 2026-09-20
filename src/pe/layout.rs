//! Checked POD access and layout derived from the PE definitions.
//!
//! PE data is little-endian; stork only builds for native Windows AMD64.

use crate::{Error, Result, error::pe};
use pelite::image::*;
use std::mem::{offset_of, size_of};

pub(crate) const MAX_HEADERS: usize = 1024 * 1024;
pub(crate) const DOS_HEADER_SIZE: usize = size_of::<IMAGE_DOS_HEADER>();
pub(super) const FILE_HEADER_OFFSET: usize = offset_of!(IMAGE_NT_HEADERS64, FileHeader);
pub(super) const NT_PREFIX_SIZE: usize = offset_of!(IMAGE_NT_HEADERS64, OptionalHeader);
pub(super) const DIRECTORY_COUNT: usize = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
pub(super) type Directories = [IMAGE_DATA_DIRECTORY; DIRECTORY_COUNT];
// Pelite's optional-header types end in a zero-length directory array.
pub(super) const OPTIONAL_HEADER64_SIZE: usize =
    size_of::<IMAGE_OPTIONAL_HEADER64>() + size_of::<Directories>();
pub(super) const SECTION_HEADER_SIZE: usize = size_of::<IMAGE_SECTION_HEADER>();
// The fields through SizeOfHeaders have the same offsets in PE32 and PE32+.
pub(crate) const HEADER_PREFIX_SIZE: usize =
    NT_PREFIX_SIZE + offset_of!(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders) + size_of::<u32>();
const _: () = assert!(
    offset_of!(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders)
        == offset_of!(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders)
);

pub(crate) fn bytes(b: &[u8], o: usize, n: usize) -> Result<&[u8]> {
    b.get(o..o.checked_add(n).ok_or_else(|| pe("offset overflow"))?)
        .ok_or_else(|| pe("truncated data"))
}
pub(super) fn read<T: dataview::Pod>(b: &[u8], offset: usize) -> Result<T> {
    Ok(dataview::DataView::from(bytes(b, offset, size_of::<T>())?).read(0))
}
pub(super) fn write<T: dataview::Pod>(b: &mut [u8], offset: usize, value: &T) -> Result<()> {
    let end = offset
        .checked_add(size_of::<T>())
        .ok_or_else(|| pe("offset overflow"))?;
    let dst = b.get_mut(offset..end).ok_or_else(|| pe("truncated data"))?;
    dst.copy_from_slice(dataview::bytes(value));
    Ok(())
}
#[cfg(test)]
pub(crate) fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    read(b, o)
}
pub(crate) fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    read(b, o)
}
#[cfg(test)]
pub(crate) fn put16(b: &mut [u8], o: usize, v: u16) {
    write(b, o, &v).unwrap();
}
#[cfg(test)]
pub(crate) fn put32(b: &mut [u8], o: usize, v: u32) {
    write(b, o, &v).unwrap();
}
pub(crate) fn nt_offset(b: &[u8]) -> Result<usize> {
    let dos: IMAGE_DOS_HEADER = read(b, 0)?;
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(pe("bad DOS signature"));
    }
    let n = dos.e_lfanew as usize;
    if !(DOS_HEADER_SIZE..=MAX_HEADERS - NT_PREFIX_SIZE - OPTIONAL_HEADER64_SIZE).contains(&n) {
        return Err(pe("invalid e_lfanew"));
    }
    Ok(n)
}
/// Determine the bounded full read after fetching the shared header prefix.
pub(crate) fn header_read_size(b: &[u8]) -> Result<usize> {
    let nt = nt_offset(b)?;
    let file: IMAGE_FILE_HEADER = read(b, nt + FILE_HEADER_OFFSET)?;
    let header_size = u32_at(
        b,
        nt + NT_PREFIX_SIZE + offset_of!(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders),
    )? as usize;
    let size = (nt
        + NT_PREFIX_SIZE
        + usize::from(file.SizeOfOptionalHeader)
        + usize::from(file.NumberOfSections) * SECTION_HEADER_SIZE)
        .max(header_size);
    if size > MAX_HEADERS {
        return Err(pe("headers too large"));
    }
    Ok(size)
}
pub(crate) fn machine_gate(machine: u16) -> Result<()> {
    match machine {
        IMAGE_FILE_MACHINE_AMD64 => Ok(()),
        IMAGE_FILE_MACHINE_I386 => Err(Error::BitnessMismatch {
            injector_64: true,
            target_64: false,
        }),
        m => Err(Error::UnsupportedMachine(m)),
    }
}
