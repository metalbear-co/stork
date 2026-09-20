//! Serialize existing import descriptors and prepend one ordinal import.

use super::layout::read;
use crate::{Result, error::pe};
use pelite::image::{IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG64};

pub(crate) const MAX_IMPORTS: usize = 4096;
const THUNK_SIZE: usize = size_of::<u64>();
const THUNK_TABLE_SIZE: usize = 2 * THUNK_SIZE; // ordinal followed by a null

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ImportDescriptor {
    pub original_first_thunk: u32,
    pub timestamp: u32,
    pub forwarder: u32,
    pub name: u32,
    pub first_thunk: u32,
}

impl ImportDescriptor {
    pub(crate) const SIZE: usize = size_of::<IMAGE_IMPORT_DESCRIPTOR>();

    pub(crate) fn parse(b: &[u8]) -> Result<Self> {
        let raw: IMAGE_IMPORT_DESCRIPTOR = read(b, 0)?;
        Ok(Self {
            original_first_thunk: raw.OriginalFirstThunk,
            timestamp: raw.TimeDateStamp,
            forwarder: raw.ForwarderChain,
            name: raw.Name,
            first_thunk: raw.FirstThunk,
        })
    }
    pub(crate) fn write(&self, b: &mut [u8]) {
        let raw = IMAGE_IMPORT_DESCRIPTOR {
            OriginalFirstThunk: self.original_first_thunk,
            TimeDateStamp: self.timestamp,
            ForwarderChain: self.forwarder,
            Name: self.name,
            FirstThunk: self.first_thunk,
        };
        b[..Self::SIZE].copy_from_slice(dataview::bytes(&raw));
    }
}
pub(crate) fn build_imports(
    old: &[ImportDescriptor],
    path: &[u8],
    ordinal: u16,
    rva: u32,
) -> Result<Vec<u8>> {
    if old.len() > MAX_IMPORTS || path.is_empty() || path.len() > 32767 || path.contains(&0) {
        return Err(pe("invalid import builder input"));
    }
    // New descriptor, existing descriptors, terminator, then aligned INT/IAT.
    let descriptor_bytes = (old.len() + 2) * ImportDescriptor::SIZE;
    let int = descriptor_bytes.next_multiple_of(THUNK_SIZE);
    let iat = int + THUNK_TABLE_SIZE;
    let name = iat + THUNK_TABLE_SIZE;
    let size = name + path.len() + 1;
    if u64::from(rva) + size as u64 > u32::MAX as u64 {
        return Err(pe("import allocation exceeds RVA range"));
    }
    let mut out = vec![0; size];
    ImportDescriptor {
        original_first_thunk: rva + int as u32,
        name: rva + name as u32,
        first_thunk: rva + iat as u32,
        ..Default::default()
    }
    .write(&mut out[..ImportDescriptor::SIZE]);
    for (i, d) in old.iter().enumerate() {
        d.write(&mut out[(i + 1) * ImportDescriptor::SIZE..(i + 2) * ImportDescriptor::SIZE]);
    }
    let ordinal = IMAGE_ORDINAL_FLAG64 | u64::from(ordinal);
    out[int..int + THUNK_SIZE].copy_from_slice(&ordinal.to_le_bytes());
    out[iat..iat + THUNK_SIZE].copy_from_slice(&ordinal.to_le_bytes());
    out[name..name + path.len()].copy_from_slice(path);
    Ok(out)
}
