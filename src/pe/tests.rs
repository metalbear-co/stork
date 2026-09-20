use super::layout::{MAX_HEADERS, put16, put32};
use super::*;
use crate::Error;

#[test]
fn image_ranges_reject_overflow_and_preserve_end_boundaries() {
    let b = export_pe(&[0x1300], 1, 0x200, false);
    let headers = Headers::parse(&b).unwrap();
    assert!(headers.image_range(1, usize::MAX).is_err());
    assert!(headers.image_range(u32::MAX, usize::MAX).is_err());
    assert!(headers.image_range(headers.image_size, 0).is_ok());
    assert!(headers.image_range(headers.image_size, 1).is_err());
    assert!(headers.image_range(headers.image_size - 1, 1).is_ok());
}
/// A minimal PE32+ AMD64 DLL whose single .edata section lives at
/// file offset 0x800 but virtual RVA 0x1000, so RVA translation is
/// exercised. `eat` are the raw AddressOfFunctions entries.
fn export_pe(eat: &[u32], base: u32, dir_size: u32, with_file_marker: bool) -> Vec<u8> {
    let mut b = vec![0; 0x1800];
    put16(&mut b, 0, 0x5a4d);
    put32(&mut b, 60, 0x100);
    b[0x100..0x104].copy_from_slice(b"PE\0\0");
    put16(&mut b, 0x104, 0x8664);
    put16(&mut b, 0x106, 1);
    put16(&mut b, 0x114, 240);
    put16(&mut b, 0x116, 0x2000); // size of optional header, DLL
    put16(&mut b, 0x118, 0x20b);
    put32(&mut b, 0x150, 0x2000);
    put32(&mut b, 0x154, 0x400);
    put32(&mut b, 0x184, 16);
    let export_rva = 0x1000u32;
    let funcs_rva = export_rva + 0x100;
    put32(&mut b, 0x188, export_rva);
    put32(&mut b, 0x18c, dir_size);
    let section = 0x208;
    b[section..section + 8].copy_from_slice(b".edata\0\0");
    put32(&mut b, section + 8, 0x1000);
    put32(&mut b, section + 12, 0x1000);
    put32(&mut b, section + 16, 0x1000);
    put32(&mut b, section + 20, 0x800);
    // Export directory at RVA 0x1000 (file offset 0x800).
    put32(&mut b, 0x800 + 16, base);
    put32(&mut b, 0x800 + 20, eat.len() as u32);
    put32(&mut b, 0x800 + 28, funcs_rva);
    for (i, e) in eat.iter().enumerate() {
        put32(&mut b, 0x800 + 0x100 + i * 4, *e);
    }
    if with_file_marker {
        b[0x1200..0x1208].copy_from_slice(b"RVA-MARK");
    }
    b
}
#[test]
fn file_range_translates_through_sections() {
    let b = export_pe(&[], 1, 0x40, true);
    let h = Headers::parse(&b).unwrap();
    h.validate_file(&b).unwrap();
    // RVA 0x1A00 lives at raw offset 0x1200, not 0x1A00.
    assert_eq!(h.file_range(&b, 0x1a00, 8).unwrap(), b"RVA-MARK");
    assert!(h.file_range(&b, 0x1a08, 8).is_ok());
    // Beyond the raw section data the file RVA has no bytes.
    assert!(h.file_range(&b, 0x1f00, 0x200).is_err());
    // Header RVAs map directly.
    assert_eq!(h.file_range(&b, 0x200, 4).unwrap(), &b[0x200..0x204]);
}
#[test]
fn import_requires_ordinal_one() {
    for (exports, base, size, accepted) in [
        (&[0x1300][..], 1, 0x200, true),
        (&[0, 0x1300][..], 0, 0x200, true),
        (&[0x10f0][..], 1, 0x200, true),
        (&[0, 0x1300][..], 1, 0x200, false),
        (&[0x1300][..], 7, 0x200, false),
        (&[0x1300][..], 0x10001, 0x200, false),
        (&[0x1300][..], 1, 39, false),
    ] {
        let b = export_pe(exports, base, size, false);
        let result = Headers::parse(&b).unwrap().import_ordinal(&b);
        assert_eq!(result.is_ok(), accepted, "base {base}, exports {exports:?}");
        if accepted {
            assert_eq!(result.unwrap(), 1);
        }
    }
}
#[test]
fn builder_offsets_and_nulls() {
    let old = ImportDescriptor {
        name: 50,
        first_thunk: 60,
        ..Default::default()
    };
    let b = build_imports(&[old], b"C:\\space path\\a.dll", 37, 0x10000).unwrap();
    assert_eq!(ImportDescriptor::parse(&b[20..]).unwrap(), old);
    assert_eq!(
        ImportDescriptor::parse(&b[40..]).unwrap(),
        ImportDescriptor::default()
    );
    let d = ImportDescriptor::parse(&b).unwrap();
    let i = (d.original_first_thunk - 0x10000) as usize;
    assert_eq!(i % 8, 0);
    assert_eq!(&b[i..i + 8], &((1u64 << 63) | 37).to_le_bytes());
    assert_eq!(&b[i + 8..i + 16], &[0; 8]);
    assert!(build_imports(&[], b"a", 1, u32::MAX).is_err());
    assert!(build_imports(&[], b"", 1, 0).is_err());
}
#[test]
fn known_dll_exports() {
    let b = std::fs::read("C:\\Windows\\System32\\kernel32.dll").unwrap();
    let h = Headers::parse(&b).unwrap();
    h.validate_file(&b).unwrap();
    assert!(h.import_ordinal(&b).is_ok());
}
#[test]
fn truncated_headers() {
    for n in 0..512 {
        assert!(Headers::parse(&vec![0; n]).is_err());
    }
}
#[test]
fn structural_boundaries() {
    // e_lfanew inside the file but beyond MAX_HEADERS range.
    let mut b = vec![0; 0x400];
    put16(&mut b, 0, 0x5a4d);
    put32(&mut b, 60, MAX_HEADERS as u32 - 100);
    assert!(Headers::parse(&b).is_err());
    // Data-directory count that does not fit the optional header.
    let mut b = export_pe(&[0x1300], 1, 0x200, false);
    put32(&mut b, 0x184, 17);
    assert!(Headers::parse(&b).is_err());
    // A section that ends past the image size.
    let mut b = export_pe(&[0x1300], 1, 0x200, false);
    put32(&mut b, 0x208 + 12, 0xff00);
    assert!(Headers::parse(&b).is_err());
    // Machine types: x86 is a bitness mismatch, ARM64 is unsupported.
    let mut b = export_pe(&[0x1300], 1, 0x200, false);
    put16(&mut b, 0x104, 0x14c);
    assert!(matches!(
        Headers::parse(&b),
        Err(Error::BitnessMismatch { .. })
    ));
    let mut b = export_pe(&[0x1300], 1, 0x200, false);
    put16(&mut b, 0x104, 0xaa64);
    assert!(matches!(
        Headers::parse(&b),
        Err(Error::UnsupportedMachine(0xaa64))
    ));
}
fn pe32_fixture(header_size: u32) -> Vec<u8> {
    let mut b = vec![0; header_size as usize];
    put16(&mut b, 0, 0x5a4d);
    put32(&mut b, 60, 0x100);
    b[0x100..0x104].copy_from_slice(b"PE\0\0");
    put16(&mut b, 0x104, 0x14c);
    put16(&mut b, 0x106, 1);
    put16(&mut b, 0x114, 224);
    put16(&mut b, 0x116, 0x2000); // DLL characteristic
    put16(&mut b, 0x118, 0x10b); // PE32 magic
    put32(&mut b, 0x150, 0x2000); // SizeOfImage
    put32(&mut b, 0x154, header_size); // SizeOfHeaders
    put32(&mut b, 0x174, 16); // NumberOfRvaAndSizes (PE32 at +92)
    put32(&mut b, 0x178, 0x1234); // directory 0 rva
    let section = 0x1f8; // optional + 224
    b[section..section + 8].copy_from_slice(b".text\0\0\0");
    put32(&mut b, section + 8, 0x200);
    put32(&mut b, section + 12, 0x1000);
    put32(&mut b, section + 16, 0x200);
    put32(&mut b, section + 20, 0x800);
    put32(&mut b, section + 36, 0x60000020);
    b
}
#[test]
fn pe32_to_pe64_conversion() {
    let b32 = pe32_fixture(0x400);
    // The PE32 parses leniently and fails the strict payload gate.
    let h32 = Headers::parse_remote(&b32).unwrap();
    assert_eq!(h32.magic, 0x10b);
    assert!(matches!(
        Headers::parse(&b32),
        Err(Error::BitnessMismatch { .. })
    ));
    let c = convert_pe32_to_pe64(&b32).unwrap();
    assert_eq!(u16_at(&c, 0x104).unwrap(), 0x8664);
    assert_eq!(u16_at(&c, 0x114).unwrap(), 240);
    assert_eq!(u16_at(&c, 0x118).unwrap(), 0x20b);
    assert_eq!(u32_at(&c, 0x150).unwrap(), 0x2000);
    assert_eq!(u32_at(&c, 0x154).unwrap(), 0x400);
    // Directory 0 moved from PE32 +96 to PE32+ +112; count at +108.
    assert_eq!(u32_at(&c, 0x118 + 112).unwrap(), 0x1234);
    assert_eq!(u32_at(&c, 0x118 + 108).unwrap(), 16);
    let h = Headers::parse_remote(&c).unwrap();
    assert_eq!((h.machine, h.magic), (0x8664, 0x20b));
    assert_eq!(h.image_size, 0x2000);
    assert_eq!(h.header_size, 0x400);
    assert_eq!(h.directories[0].rva, 0x1234);
    assert_eq!(h.sections.len(), 1);
    assert_eq!(h.sections[0].rva, 0x1000);
    assert_eq!(h.sections[0].raw_offset, 0x800);
    assert_eq!(&c[0x208..0x210], b".text\0\0\0");
    assert_eq!(&c[0x208..0x230], &b32[0x1f8..0x220]);
    // The strict gate accepts the widened buffer.
    assert!(Headers::parse(&c).is_ok());
    // Refusals: undersized optional header, no room for the section table.
    let mut small = pe32_fixture(0x400);
    put16(&mut small, 0x114, 200);
    assert!(convert_pe32_to_pe64(&small).is_err());
    let tight = pe32_fixture(0x228);
    assert!(convert_pe32_to_pe64(&tight).is_err());
}
#[test]
fn remote_headers_require_the_full_declared_region() {
    let pe32 = pe32_fixture(0x400);
    let pe64 = convert_pe32_to_pe64(&pe32).unwrap();
    for image in [&pe32, &pe64] {
        for length in 0..image.len() {
            assert!(
                Headers::parse_remote(&image[..length]).is_err(),
                "accepted {length} bytes"
            );
        }
        assert!(Headers::parse_remote(image).is_ok());
    }
}
#[test]
fn widening_preserves_padding_and_refuses_overlapping_directories() {
    let mut b = pe32_fixture(0x400);
    b[0x300..].fill(0xa5);
    put32(&mut b, 0x178, 0x300);
    put32(&mut b, 0x17c, 0x100);
    let widened = convert_pe32_to_pe64(&b).unwrap();
    assert_eq!(&widened[0x230..], &b[0x230..]);
    put32(&mut b, 0x178, 0x220);
    assert!(convert_pe32_to_pe64(&b).is_err());
}
#[test]
fn widening_has_detours_section_limit() {
    for count in [32u16, 33] {
        let mut b = pe32_fixture(0x1000);
        put16(&mut b, 0x106, count);
        put32(&mut b, 0x150, (u32::from(count) + 1) * 0x1000);
        for index in 0..usize::from(count) {
            let section = 0x1f8 + index * 40;
            put32(&mut b, section + 8, 0x200);
            put32(&mut b, section + 12, (index as u32 + 1) * 0x1000);
        }
        assert_eq!(convert_pe32_to_pe64(&b).is_ok(), count == 32);
    }
}
#[test]
fn architecture_gates() {
    assert!(machine_gate(0x8664).is_ok());
    assert!(matches!(
        machine_gate(0x14c),
        Err(Error::BitnessMismatch { .. })
    ));
    assert!(matches!(
        machine_gate(0xaa64),
        Err(Error::UnsupportedMachine(0xaa64))
    ));
}

// Literal wire offsets here are independent of the production Rust layouts.
#[test]
fn widening_preserves_optional_fields_and_zero_extends_addresses() {
    let mut b = pe32_fixture(0x400);
    let opt = 0x118;
    for (i, byte) in b[opt + 2..opt + 92].iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(13).wrapping_add(128);
    }
    put32(&mut b, opt + 56, 0x2000);
    put32(&mut b, opt + 60, 0x400);
    let widened = convert_pe32_to_pe64(&b).unwrap();
    assert_eq!(&widened[opt + 2..opt + 24], &b[opt + 2..opt + 24]);
    assert_eq!(&widened[opt + 32..opt + 72], &b[opt + 32..opt + 72]);
    for (src, dst) in [(28, 24), (72, 72), (76, 80), (80, 88), (84, 96)] {
        let value = u64::from(u32_at(&b, opt + src).unwrap());
        assert_eq!(&widened[opt + dst..opt + dst + 8], &value.to_le_bytes());
    }
    assert_eq!(&widened[opt + 104..opt + 112], &b[opt + 88..opt + 96]);
    assert_eq!(&widened[opt + 112..opt + 240], &b[opt + 96..opt + 224]);
}

#[test]
fn typed_access_rejects_overflow_and_truncation_without_writes() {
    use super::layout::{read, write};
    let original = [0xa5; 8];
    let mut b = original;
    for offset in [5, usize::MAX] {
        assert!(read::<u32>(&b, offset).is_err());
        assert!(write(&mut b, offset, &0u32).is_err());
        assert_eq!(b, original);
    }
    // POD reads and writes also support unaligned input.
    write(&mut b, 1, &0x12345678u32).unwrap();
    assert_eq!(read::<u32>(&b, 1).unwrap(), 0x12345678);
    for len in 0..ImportDescriptor::SIZE {
        assert!(ImportDescriptor::parse(&vec![0; len]).is_err());
    }
    let mut image = export_pe(&[0x1300], 1, 0x200, false);
    let headers = Headers::parse(&image).unwrap();
    let before = image.clone();
    assert!(
        headers
            .set_directory(&mut image, usize::MAX, DataDirectory::default())
            .is_err()
    );
    assert_eq!(image, before);
    assert!(
        headers
            .set_directory(&mut image[..64], 1, DataDirectory::default())
            .is_err()
    );
    assert!(headers.clear_checksum(&mut image[..64]).is_err());
    assert_eq!(image, before);
}

#[test]
fn staged_header_reads_are_bounded_for_both_formats() {
    for mut image in [pe32_fixture(0x400), export_pe(&[0x1300], 1, 0x200, false)] {
        let prefix_end = nt_offset(&image).unwrap() + HEADER_PREFIX_SIZE;
        for len in 0..prefix_end {
            assert!(header_read_size(&image[..len]).is_err());
        }
        assert_eq!(header_read_size(&image[..prefix_end]).unwrap(), 0x400);
        put32(&mut image, 0x154, MAX_HEADERS as u32 + 1);
        assert!(header_read_size(&image[..prefix_end]).is_err());
    }
}
