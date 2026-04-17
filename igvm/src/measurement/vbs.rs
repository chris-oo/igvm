// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Microsoft VBS launch measurement (boot digest) calculation.
//!
//! Computes the VBS boot measurement digest by iterating IGVM directive
//! headers and hashing page chunks and VP register state using SHA-256,
//! matching the VBS measurement protocol.

use super::{MeasurementError, SHA_256_OUTPUT_SIZE};
use crate::IgvmDirectiveHeader;
use igvm_defs::PAGE_SIZE_4K;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zerocopy::{Immutable, IntoBytes, KnownLayout};

const PAGE_SIZE_4K_USIZE: usize = PAGE_SIZE_4K as usize;

// VBS measurement chunk types.

/// Boot measurement chunk type: VP register.
const CHUNK_TYPE_VP_REGISTER: u32 = 0;
/// Boot measurement chunk type: GPA page.
const CHUNK_TYPE_VP_GPA_PAGE: u32 = 2;

/// VBS chunk header (16 bytes).
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout)]
struct VbsChunkHeader {
    byte_count: u32,
    chunk_type: u32,
    reserved: u64,
}

/// Structure describing a page to be measured.
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout)]
struct VpGpaPageChunk {
    header: VbsChunkHeader,
    metadata: u64,
    page_number: u64,
}

/// Full chunk size for VBS measurement (chunk header + page data).
const VBS_VP_CHUNK_SIZE_BYTES: usize = PAGE_SIZE_4K_USIZE + size_of::<VpGpaPageChunk>();

/// Structure describing a register being measured.
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout)]
struct VbsRegisterChunk {
    header: VbsChunkHeader,
    reserved: u32,
    vtl: u8,
    reserved2: u8,
    reserved3: u16,
    reserved4: u32,
    name: u32,
    value: [u8; 16],
}

const _: () = assert!(size_of::<VbsRegisterChunk>() <= VBS_VP_CHUNK_SIZE_BYTES);

/// Page boot metadata bitfield.
///
/// Bits [0:1] = acceptance, bit [2] = data_unmeasured.
fn page_metadata(acceptance: u64, data_unmeasured: bool) -> u64 {
    (acceptance & 0x3) | (if data_unmeasured { 1 << 2 } else { 0 })
}

/// Compute the VBS boot measurement digest from IGVM directive headers.
///
/// Iterates all directive headers for the given compatibility mask, computing
/// the chained SHA-256 measurement that VBS firmware would produce.
pub fn generate_vbs_measurement(
    directive_headers: &[IgvmDirectiveHeader],
    compatibility_mask: u32,
    enable_debug: bool,
) -> Result<[u8; SHA_256_OUTPUT_SIZE], MeasurementError> {
    let mut digest = [0u8; SHA_256_OUTPUT_SIZE];
    let mut parameter_area_table = HashMap::new();
    let mut bsp_regs: Vec<Vec<(u8, u32, [u8; 16])>> = Vec::new();

    for header in directive_headers {
        if header
            .compatibility_mask()
            .map(|mask| mask & compatibility_mask != compatibility_mask)
            .unwrap_or(false)
        {
            continue;
        }

        match header {
            IgvmDirectiveHeader::PageData {
                gpa, flags, data, ..
            } => {
                if flags.shared() {
                    continue;
                }

                let metadata = page_metadata(0, flags.unmeasured());
                record_gpa_page(
                    &mut digest,
                    gpa / PAGE_SIZE_4K,
                    1,
                    metadata,
                    data,
                    flags.unmeasured(),
                );
            }
            IgvmDirectiveHeader::ParameterInsert(param) => {
                let parameter_area_size = parameter_area_table
                    .get(&param.parameter_area_index)
                    .ok_or(MeasurementError::InvalidParameterAreaIndex(
                        param.parameter_area_index,
                    ))?;
                let metadata = page_metadata(0, true);
                record_gpa_page(
                    &mut digest,
                    param.gpa / PAGE_SIZE_4K,
                    parameter_area_size / PAGE_SIZE_4K,
                    metadata,
                    &[],
                    true,
                );
            }
            IgvmDirectiveHeader::X64VbsVpContext {
                vtl,
                registers,
                ..
            } => {
                let vtl_registers: Vec<(u8, u32, [u8; 16])> = registers
                    .iter()
                    .map(|r| {
                        let vbs_reg = r.into_vbs_vp_context_reg(*vtl);
                        (
                            vbs_reg.vtl,
                            u32::from(vbs_reg.register_name),
                            vbs_reg.register_value,
                        )
                    })
                    .collect();
                bsp_regs.push(vtl_registers);
            }
            IgvmDirectiveHeader::AArch64VbsVpContext {
                vtl,
                registers,
                ..
            } => {
                let vtl_registers: Vec<(u8, u32, [u8; 16])> = registers
                    .iter()
                    .map(|r| {
                        let vbs_reg = r.into_vbs_vp_context_reg(*vtl);
                        (
                            vbs_reg.vtl,
                            u32::from(vbs_reg.register_name),
                            vbs_reg.register_value,
                        )
                    })
                    .collect();
                bsp_regs.push(vtl_registers);
            }
            IgvmDirectiveHeader::ErrorRange {
                gpa, size_bytes, ..
            } => {
                // Readable + Writable acceptance, unmeasured
                let metadata = page_metadata(0x3, true); // VM_GPA_PAGE_READABLE | VM_GPA_PAGE_WRITABLE
                let page_count = (*size_bytes as u64).div_ceil(PAGE_SIZE_4K);
                record_gpa_page(
                    &mut digest,
                    *gpa / PAGE_SIZE_4K,
                    page_count,
                    metadata,
                    &[],
                    true,
                );
            }
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                ..
            } => {
                parameter_area_table.insert(*parameter_area_index, *number_of_bytes);
            }
            _ => {}
        }
    }

    // Measure all VP registers last (VBS protocol requirement)
    for set in bsp_regs {
        for (vtl, name, value) in set {
            record_vp_register(&mut digest, vtl, name, value);
        }
    }

    // The boot_measurement_digest field is the final digest value.
    // Note: We return just the raw digest here, not the full
    // VBS_VM_BOOT_MEASUREMENT_SIGNED_DATA structure, since the CoRIM
    // endorsement only needs the boot measurement digest.
    let _ = enable_debug; // Used by the signed data structure but not by the digest itself

    Ok(digest)
}

fn record_gpa_page(
    digest: &mut [u8; SHA_256_OUTPUT_SIZE],
    gpa_page_base: u64,
    page_count: u64,
    metadata: u64,
    mut data: &[u8],
    data_unmeasured: bool,
) {
    for page in 0..page_count {
        let import_data_len = if data_unmeasured {
            0
        } else {
            std::cmp::min(PAGE_SIZE_4K_USIZE, data.len())
        };
        let (import_data, data_remaining) = data.split_at(import_data_len);
        data = data_remaining;

        let padding = vec![0u8; PAGE_SIZE_4K_USIZE - import_data.len()];
        let page_number = gpa_page_base + page;
        let chunk = VpGpaPageChunk {
            header: VbsChunkHeader {
                byte_count: VBS_VP_CHUNK_SIZE_BYTES as u32,
                chunk_type: CHUNK_TYPE_VP_GPA_PAGE,
                reserved: 0,
            },
            metadata,
            page_number,
        };

        let mut hasher = Sha256::new();
        hasher.update(digest.as_slice());
        hasher.update(chunk.as_bytes());
        hasher.update(import_data);
        hasher.update(&padding);
        *digest = hasher.finalize().into();
    }
}

fn record_vp_register(digest: &mut [u8; SHA_256_OUTPUT_SIZE], vtl: u8, name: u32, value: [u8; 16]) {
    let chunk = VbsRegisterChunk {
        header: VbsChunkHeader {
            byte_count: size_of::<VbsRegisterChunk>() as u32,
            chunk_type: CHUNK_TYPE_VP_REGISTER,
            reserved: 0,
        },
        reserved: 0,
        vtl,
        reserved2: 0,
        reserved3: 0,
        reserved4: 0,
        name,
        value,
    };

    let mut hasher = Sha256::new();
    hasher.update(digest.as_slice());
    hasher.update(chunk.as_bytes());
    *digest = hasher.finalize().into();
}
