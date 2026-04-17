// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! IGVM file serializer with support for computing launch measurements
//! and attaching CoRIM endorsements before writing to binary format.
//!
//! [`IgvmSerializer`] borrows an immutable [`IgvmFile`] and provides a
//! builder-style API for enriching the output with per-platform launch
//! measurements and CoRIM documents, without mutating the original file.
//!
//! # Example
//!
//! ```rust,no_run
//! use igvm::{IgvmFile, IgvmSerializer, CorimTemplate};
//! use igvm_defs::IgvmPlatformType;
//!
//! # fn example(file: &IgvmFile) -> Result<(), igvm::Error> {
//! let mut serializer = IgvmSerializer::new(file);
//!
//! // Compute and inspect the SNP measurement
//! let measurement = serializer.compute_measurement(IgvmPlatformType::SEV_SNP)?;
//! println!("SNP digest: {}", hex::encode(&measurement.digest));
//!
//! // Attach a CoRIM endorsement using the computed measurement
//! serializer.add_corim(IgvmPlatformType::SEV_SNP, CorimTemplate::LaunchEndorsement { svn: 1 })?;
//!
//! // Serialize to binary
//! let mut output = Vec::new();
//! serializer.serialize(&mut output)?;
//! # Ok(())
//! # }
//! ```

use crate::{
    CorimTemplate, Error, FileDataSerializer, FixedHeader, IgvmFile, IgvmInitializationHeader,
    IgvmPlatformHeader,
};
use igvm_defs::*;
use std::mem::size_of;
use zerocopy::IntoBytes;

/// A per-platform launch measurement computed from an IGVM file's headers.
#[derive(Debug, Clone)]
pub struct IgvmPlatformMeasurement {
    /// The platform type this measurement was computed for.
    pub platform: IgvmPlatformType,
    /// The compatibility mask associated with this platform.
    pub compatibility_mask: u32,
    /// The raw launch measurement digest bytes.
    ///
    /// Length depends on the platform:
    /// - SEV-SNP: 48 bytes (SHA-384)
    /// - TDX: 48 bytes (SHA-384)
    /// - VBS: 32 bytes (SHA-256)
    pub digest: Vec<u8>,
}

/// Serializer that borrows an [`IgvmFile`] and enriches the output with
/// computed measurements and CoRIM endorsement documents.
///
/// The underlying [`IgvmFile`] is never mutated. Additional initialization
/// headers (CoRIM documents) are accumulated in the serializer and merged
/// into the output during [`serialize`](IgvmSerializer::serialize).
pub struct IgvmSerializer<'a> {
    file: &'a IgvmFile,
    measurements: Vec<IgvmPlatformMeasurement>,
    extra_init_headers: Vec<IgvmInitializationHeader>,
}

impl<'a> IgvmSerializer<'a> {
    /// Create a new serializer for the given IGVM file.
    pub fn new(file: &'a IgvmFile) -> Self {
        Self {
            file,
            measurements: Vec::new(),
            extra_init_headers: Vec::new(),
        }
    }

    /// Get a reference to the underlying IGVM file.
    pub fn file(&self) -> &IgvmFile {
        self.file
    }

    /// Get all measurements that have been computed so far.
    pub fn measurements(&self) -> &[IgvmPlatformMeasurement] {
        &self.measurements
    }

    /// Look up the compatibility mask for a platform type from the file's
    /// platform headers.
    fn lookup_compatibility_mask(
        &self,
        platform: IgvmPlatformType,
    ) -> Result<u32, Error> {
        self.file
            .platforms()
            .iter()
            .find_map(|h| match h {
                IgvmPlatformHeader::SupportedPlatform(info)
                    if info.platform_type == platform =>
                {
                    Some(info.compatibility_mask)
                }
                _ => None,
            })
            .ok_or_else(|| {
                Error::CorimGeneration(format!("no platform header found for {platform:?}"))
            })
    }

    /// Compute the launch measurement for a specific platform and cache it.
    ///
    /// Returns a reference to the computed measurement so the caller can
    /// inspect the digest (e.g., for logging or external signing).
    ///
    /// If the measurement for this platform has already been computed, the
    /// cached value is returned without recomputation.
    ///
    /// # Supported platforms
    ///
    /// - [`IgvmPlatformType::SEV_SNP`] — SHA-384 launch digest
    /// - [`IgvmPlatformType::TDX`] — SHA-384 MRTD
    /// - [`IgvmPlatformType::VSM_ISOLATION`] — SHA-256 VBS boot digest
    #[cfg(feature = "corim")]
    #[cfg_attr(docsrs, doc(cfg(feature = "corim")))]
    pub fn compute_measurement(
        &mut self,
        platform: IgvmPlatformType,
    ) -> Result<&IgvmPlatformMeasurement, Error> {
        // Return cached measurement if already computed for this platform.
        if let Some(idx) = self
            .measurements
            .iter()
            .position(|m| m.platform == platform)
        {
            return Ok(&self.measurements[idx]);
        }

        let compatibility_mask = self.lookup_compatibility_mask(platform)?;

        let digest = match platform {
            IgvmPlatformType::SEV_SNP => {
                crate::measurement::generate_snp_measurement(
                    self.file.initializations(),
                    self.file.directives(),
                    compatibility_mask,
                )
                .map_err(|e| Error::CorimGeneration(e.to_string()))?
                .to_vec()
            }
            IgvmPlatformType::TDX => {
                crate::measurement::generate_tdx_measurement(
                    self.file.directives(),
                    compatibility_mask,
                )
                .map_err(|e| Error::CorimGeneration(e.to_string()))?
                .to_vec()
            }
            IgvmPlatformType::VSM_ISOLATION => {
                crate::measurement::generate_vbs_measurement(
                    self.file.directives(),
                    compatibility_mask,
                    false, // enable_debug
                )
                .map_err(|e| Error::CorimGeneration(e.to_string()))?
                .to_vec()
            }
            _ => {
                return Err(Error::CorimGeneration(format!(
                    "unsupported platform type for measurement: {platform:?}"
                )))
            }
        };

        self.measurements.push(IgvmPlatformMeasurement {
            platform,
            compatibility_mask,
            digest,
        });

        Ok(self.measurements.last().unwrap())
    }

    /// Get the measurement for a specific platform, if already computed.
    pub fn measurement_for(
        &self,
        platform: IgvmPlatformType,
    ) -> Option<&IgvmPlatformMeasurement> {
        self.measurements.iter().find(|m| m.platform == platform)
    }

    /// Attach a CoRIM endorsement for the given platform.
    ///
    /// If the measurement for this platform has not yet been computed, it is
    /// computed automatically. The generated CoRIM document will be included
    /// as an [`IgvmInitializationHeader::CorimDocument`] in the serialized
    /// output.
    ///
    /// # Arguments
    ///
    /// * `platform` — The target platform type. Must match a platform header
    ///   in the file.
    /// * `template` — The CoRIM template to instantiate. Currently only
    ///   [`CorimTemplate::LaunchEndorsement`] is supported.
    #[cfg(feature = "corim")]
    #[cfg_attr(docsrs, doc(cfg(feature = "corim")))]
    pub fn add_corim(
        &mut self,
        platform: IgvmPlatformType,
        template: CorimTemplate,
    ) -> Result<(), Error> {
        // Ensure the measurement is computed (uses cache if already done).
        self.compute_measurement(platform)?;

        let measurement = self
            .measurement_for(platform)
            .expect("just computed above");

        let corim_bytes = match template {
            CorimTemplate::LaunchEndorsement { svn } => {
                crate::corim::launch_endorsement::generate(
                    platform,
                    &measurement.digest,
                    svn,
                )
                .map_err(|e| Error::CorimGeneration(e.to_string()))?
            }
            CorimTemplate::Architectural | CorimTemplate::Custom(_) => {
                todo!("Architectural and Custom CoRIM templates not yet implemented")
            }
        };

        self.extra_init_headers
            .push(IgvmInitializationHeader::CorimDocument {
                compatibility_mask: measurement.compatibility_mask,
                document: corim_bytes,
            });

        Ok(())
    }

    /// Serialize the IGVM file to binary format, including any CoRIM
    /// documents that were added via [`add_corim`](Self::add_corim).
    ///
    /// This produces the same binary format as [`IgvmFile::serialize`],
    /// but with additional initialization headers appended.
    pub fn serialize(&self, output: &mut Vec<u8>) -> Result<(), Error> {
        let file = self.file;

        // The IgvmFile was validated at construction time, so platform headers
        // are already known to be valid.

        // Combine the file's init headers with any extra ones from the builder.
        let all_init_headers: Vec<&IgvmInitializationHeader> = file
            .initialization_headers
            .iter()
            .chain(self.extra_init_headers.iter())
            .collect();

        // Calculate variable header section size.
        let mut variable_header_section_size = 0;
        for header in file.platform_headers.iter() {
            variable_header_section_size += header.header_size();
        }
        for header in &all_init_headers {
            variable_header_section_size += header.header_size();
        }
        for header in file.directive_headers.iter() {
            variable_header_section_size += header.header_size();
        }

        assert_eq!(variable_header_section_size % 8, 0);

        let file_data_section_start =
            file.revision.fixed_header_size() + variable_header_section_size;

        let mut variable_header_binary = Vec::new();

        // Add platform headers
        for header in &file.platform_headers {
            match header {
                IgvmPlatformHeader::SupportedPlatform(platform) => {
                    let header = IGVM_VHS_VARIABLE_HEADER {
                        typ: IgvmVariableHeaderType::IGVM_VHT_SUPPORTED_PLATFORM,
                        length: platform.as_bytes().len() as u32,
                    };
                    variable_header_binary.extend_from_slice(header.as_bytes());
                    variable_header_binary.extend_from_slice(platform.as_bytes());
                }
            }
        }

        let mut file_data = FileDataSerializer::new(file_data_section_start);

        // Add initialization headers (original + extra)
        for header in &all_init_headers {
            header
                .write_binary_header(&mut variable_header_binary, &mut file_data)
                .map_err(Error::InvalidBinaryInitializationHeader)?;
            assert_eq!(variable_header_binary.len() % 8, 0);
        }

        // Add directive headers
        for header in &file.directive_headers {
            header
                .write_binary_header(&mut variable_header_binary, &mut file_data)
                .map_err(Error::InvalidBinaryDirectiveHeader)?;
            assert_eq!(variable_header_binary.len() % 8, 0);
        }

        assert_eq!(variable_header_section_size, variable_header_binary.len());

        let mut fixed_header = match file.revision {
            crate::IgvmRevision::V1 => FixedHeader::V1(IGVM_FIXED_HEADER {
                magic: IGVM_MAGIC_VALUE,
                format_version: IGVM_FORMAT_VERSION_1,
                variable_header_offset: size_of::<IGVM_FIXED_HEADER>() as u32,
                variable_header_size: variable_header_binary
                    .len()
                    .try_into()
                    .map_err(|_| Error::VariableHeaderSectionTooLarge)?,
                total_file_size: 0,
                checksum: 0,
            }),
            crate::IgvmRevision::V2 { arch, page_size } => {
                FixedHeader::V2(IGVM_FIXED_HEADER_V2 {
                    magic: IGVM_MAGIC_VALUE,
                    format_version: IGVM_FORMAT_VERSION_2,
                    variable_header_offset: size_of::<IGVM_FIXED_HEADER_V2>() as u32,
                    variable_header_size: variable_header_binary
                        .len()
                        .try_into()
                        .map_err(|_| Error::VariableHeaderSectionTooLarge)?,
                    total_file_size: 0,
                    checksum: 0,
                    architecture: arch.into(),
                    page_size,
                })
            }
        };

        let mut file_data = file_data.take();
        let total_file_size =
            fixed_header.as_bytes().len() + variable_header_binary.len() + file_data.len();

        fixed_header.set_total_file_size(
            total_file_size
                .try_into()
                .map_err(|_| Error::TotalFileSizeTooLarge)?,
        );

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(fixed_header.as_bytes());
        hasher.update(&variable_header_binary);
        let checksum = hasher.finalize();
        fixed_header.set_checksum(checksum);

        output.extend_from_slice(fixed_header.as_bytes());
        output.append(&mut variable_header_binary);
        output.append(&mut file_data);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv_defs::Vtl;
    use crate::registers::X86Register;
    use crate::{
        Arch, CorimTemplate, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
    };
    use igvm_defs::{
        IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SUPPORTED_PLATFORM,
        PAGE_SIZE_4K,
    };

    fn new_platform(mask: u32, platform_type: IgvmPlatformType) -> IgvmPlatformHeader {
        IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask: mask,
            highest_vtl: 0,
            platform_type,
            platform_version: 1,
            shared_gpa_boundary: 0,
        })
    }

    fn new_page_data(page: u64, mask: u32, data: &[u8]) -> crate::IgvmDirectiveHeader {
        crate::IgvmDirectiveHeader::PageData {
            gpa: page * PAGE_SIZE_4K,
            compatibility_mask: mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: data.to_vec(),
        }
    }

    /// Build a minimal VBS IgvmFile with some page data and VP context.
    fn make_vbs_file() -> IgvmFile {
        IgvmFile::new(
            IgvmRevision::V2 {
                arch: Arch::X64,
                page_size: PAGE_SIZE_4K as u32,
            },
            vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
            vec![],
            vec![
                new_page_data(0, 1, &[0xAA; PAGE_SIZE_4K as usize]),
                new_page_data(1, 1, &[0xBB; PAGE_SIZE_4K as usize]),
                crate::IgvmDirectiveHeader::X64VbsVpContext {
                    vtl: Vtl::Vtl0,
                    registers: vec![X86Register::Rip(0x1000)],
                    compatibility_mask: 0x1,
                },
            ],
        )
        .unwrap()
    }

    /// Build a minimal SNP IgvmFile with a guest policy and page data.
    fn make_snp_file() -> IgvmFile {
        IgvmFile::new(
            IgvmRevision::V1,
            vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
            vec![IgvmInitializationHeader::GuestPolicy {
                policy: 0x30000,
                compatibility_mask: 0x1,
            }],
            vec![
                new_page_data(0, 1, &[0xCC; PAGE_SIZE_4K as usize]),
                new_page_data(1, 1, &[0xDD; PAGE_SIZE_4K as usize]),
            ],
        )
        .unwrap()
    }

    /// Build a minimal TDX IgvmFile with page data.
    fn make_tdx_file() -> IgvmFile {
        IgvmFile::new(
            IgvmRevision::V1,
            vec![new_platform(0x1, IgvmPlatformType::TDX)],
            vec![],
            vec![
                new_page_data(0, 1, &[0xEE; PAGE_SIZE_4K as usize]),
                new_page_data(1, 1, &[0xFF; PAGE_SIZE_4K as usize]),
            ],
        )
        .unwrap()
    }

    // ── Basic serializer tests ──────────────────────────────────────

    #[test]
    fn serialize_without_corim_matches_file_serialize() {
        let file = make_vbs_file();

        // Serialize via IgvmFile::serialize
        let mut direct = Vec::new();
        file.serialize(&mut direct).unwrap();

        // Serialize via IgvmSerializer (no CoRIM added)
        let serializer = IgvmSerializer::new(&file);
        let mut via_builder = Vec::new();
        serializer.serialize(&mut via_builder).unwrap();

        assert_eq!(direct, via_builder);
    }

    #[test]
    fn serialize_without_corim_roundtrips() {
        let file = make_snp_file();

        let serializer = IgvmSerializer::new(&file);
        let mut output = Vec::new();
        serializer.serialize(&mut output).unwrap();

        let deserialized = IgvmFile::new_from_binary(&output, None).unwrap();
        assert_eq!(file.platforms(), deserialized.platforms());
        assert_eq!(file.directives().len(), deserialized.directives().len());
    }

    // ── Measurement tests ───────────────────────────────────────────

    #[test]
    fn compute_vbs_measurement() {
        let file = make_vbs_file();
        let mut serializer = IgvmSerializer::new(&file);

        let m = serializer
            .compute_measurement(IgvmPlatformType::VSM_ISOLATION)
            .unwrap();
        assert_eq!(m.platform, IgvmPlatformType::VSM_ISOLATION);
        assert_eq!(m.compatibility_mask, 0x1);
        assert_eq!(m.digest.len(), 32); // SHA-256
    }

    #[test]
    fn compute_snp_measurement() {
        let file = make_snp_file();
        let mut serializer = IgvmSerializer::new(&file);

        let m = serializer
            .compute_measurement(IgvmPlatformType::SEV_SNP)
            .unwrap();
        assert_eq!(m.platform, IgvmPlatformType::SEV_SNP);
        assert_eq!(m.digest.len(), 48); // SHA-384
    }

    #[test]
    fn compute_tdx_measurement() {
        let file = make_tdx_file();
        let mut serializer = IgvmSerializer::new(&file);

        let m = serializer
            .compute_measurement(IgvmPlatformType::TDX)
            .unwrap();
        assert_eq!(m.platform, IgvmPlatformType::TDX);
        assert_eq!(m.digest.len(), 48); // SHA-384
    }

    #[test]
    fn measurement_is_cached() {
        let file = make_snp_file();
        let mut serializer = IgvmSerializer::new(&file);

        let m1 = serializer
            .compute_measurement(IgvmPlatformType::SEV_SNP)
            .unwrap()
            .digest
            .clone();
        let m2 = serializer
            .compute_measurement(IgvmPlatformType::SEV_SNP)
            .unwrap()
            .digest
            .clone();

        assert_eq!(m1, m2);
        assert_eq!(serializer.measurements().len(), 1);
    }

    #[test]
    fn measurement_for_returns_none_if_not_computed() {
        let file = make_snp_file();
        let serializer = IgvmSerializer::new(&file);
        assert!(serializer.measurement_for(IgvmPlatformType::SEV_SNP).is_none());
    }

    #[test]
    fn unsupported_platform_returns_error() {
        // Build a file with NATIVE platform (measurement not supported for it)
        let file = IgvmFile::new(
            IgvmRevision::V1,
            vec![new_platform(0x1, IgvmPlatformType::NATIVE)],
            vec![],
            vec![new_page_data(0, 1, &[0xAA; PAGE_SIZE_4K as usize])],
        )
        .unwrap();
        let mut serializer = IgvmSerializer::new(&file);

        let err = serializer
            .compute_measurement(IgvmPlatformType::NATIVE)
            .unwrap_err();
        assert!(err.to_string().contains("unsupported platform"));
    }

    #[test]
    fn wrong_platform_returns_error() {
        // File has SNP but we ask for TDX
        let file = make_snp_file();
        let mut serializer = IgvmSerializer::new(&file);

        let err = serializer
            .compute_measurement(IgvmPlatformType::TDX)
            .unwrap_err();
        assert!(err.to_string().contains("no platform header"));
    }

    // ── CoRIM integration tests ─────────────────────────────────────

    #[test]
    fn add_corim_produces_larger_output() {
        let file = make_snp_file();

        // Serialize without CoRIM
        let mut without = Vec::new();
        file.serialize(&mut without).unwrap();

        // Serialize with CoRIM
        let mut serializer = IgvmSerializer::new(&file);
        serializer
            .add_corim(
                IgvmPlatformType::SEV_SNP,
                CorimTemplate::LaunchEndorsement { svn: 1 },
            )
            .unwrap();
        let mut with = Vec::new();
        serializer.serialize(&mut with).unwrap();

        // Output with CoRIM should be larger (has the CorimDocument init header)
        assert!(with.len() > without.len());
    }

    #[test]
    fn add_corim_auto_computes_measurement() {
        let file = make_tdx_file();
        let mut serializer = IgvmSerializer::new(&file);

        // Measurement not computed yet
        assert!(serializer.measurement_for(IgvmPlatformType::TDX).is_none());

        // add_corim should auto-compute it
        serializer
            .add_corim(
                IgvmPlatformType::TDX,
                CorimTemplate::LaunchEndorsement { svn: 5 },
            )
            .unwrap();

        assert!(serializer.measurement_for(IgvmPlatformType::TDX).is_some());
        assert_eq!(serializer.measurements().len(), 1);
    }

    #[test]
    fn add_corim_output_roundtrips() {
        let file = make_snp_file();
        let mut serializer = IgvmSerializer::new(&file);
        serializer
            .add_corim(
                IgvmPlatformType::SEV_SNP,
                CorimTemplate::LaunchEndorsement { svn: 42 },
            )
            .unwrap();

        let mut output = Vec::new();
        serializer.serialize(&mut output).unwrap();

        // Should parse back successfully and contain a CorimDocument
        let deserialized = IgvmFile::new_from_binary(&output, None).unwrap();
        let has_corim = deserialized.initializations().iter().any(|h| {
            matches!(h, IgvmInitializationHeader::CorimDocument { .. })
        });
        assert!(has_corim);
    }

    #[test]
    fn file_not_mutated_after_add_corim() {
        let file = make_snp_file();
        let init_count_before = file.initializations().len();

        let mut serializer = IgvmSerializer::new(&file);
        serializer
            .add_corim(
                IgvmPlatformType::SEV_SNP,
                CorimTemplate::LaunchEndorsement { svn: 1 },
            )
            .unwrap();

        // The original file should not have been mutated
        assert_eq!(file.initializations().len(), init_count_before);
    }

    #[test]
    fn measurement_deterministic() {
        let file = make_vbs_file();

        let mut s1 = IgvmSerializer::new(&file);
        let m1 = s1
            .compute_measurement(IgvmPlatformType::VSM_ISOLATION)
            .unwrap()
            .digest
            .clone();

        let mut s2 = IgvmSerializer::new(&file);
        let m2 = s2
            .compute_measurement(IgvmPlatformType::VSM_ISOLATION)
            .unwrap()
            .digest
            .clone();

        assert_eq!(m1, m2);
    }
}
