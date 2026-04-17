// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Launch endorsement CoRIM profile.
//!
//! This module implements the IGVM launch endorsement CoRIM profile
//! (`tag:microsoft.com,2026:igvm-launch-endorsement/v1`), which produces
//! and validates CoRIM documents containing a launch measurement reference
//! value and an SVN endorsement for supported CVM platforms.

pub(crate) mod builder;
pub mod profile;

pub use igvm_defs::IgvmPlatformType;

/// Fixed namespace UUID for deterministic CoMID tag-id derivation.
///
/// `tag-id = UUIDv5(TAG_ID_NAMESPACE, "{vendor}/{model}")`
pub const TAG_ID_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    0x85, 0xf3, 0xf1, 0xc2, 0x22, 0xa8, 0x44, 0x1e, 0xa1, 0xb9, 0xbc, 0xcf, 0xb6, 0x3e, 0xd5,
    0xf7,
]);

// Platform properties

/// Platform properties for CoRIM generation and validation.
pub(crate) struct PlatformInfo {
    pub vendor: &'static str,
    pub model: &'static str,
    pub mkey: &'static str,
    pub digest_alg: i64,
    pub digest_len: usize,
}

/// Named Information Hash Algorithm ID for SHA-256 (RFC 6920).
const NI_SHA256: i64 = 1;
/// Named Information Hash Algorithm ID for SHA-384 (RFC 6920).
const NI_SHA384: i64 = 7;

/// Canonical list of supported platforms.
pub(crate) fn known_platforms() -> &'static [PlatformInfo] {
    &[
        PlatformInfo {
            vendor: "Intel",
            model: "TDX",
            mkey: "MRTD",
            digest_alg: NI_SHA384,
            digest_len: 48,
        },
        PlatformInfo {
            vendor: "AMD",
            model: "SEV-SNP",
            mkey: "MEASUREMENT",
            digest_alg: NI_SHA384,
            digest_len: 48,
        },
        PlatformInfo {
            vendor: "Microsoft",
            model: "VBS",
            mkey: "MEASUREMENT",
            digest_alg: NI_SHA256,
            digest_len: 32,
        },
    ]
}

fn platform_info(platform: IgvmPlatformType) -> Option<&'static PlatformInfo> {
    let (vendor, model) = match platform {
        IgvmPlatformType::TDX => ("Intel", "TDX"),
        IgvmPlatformType::SEV_SNP => ("AMD", "SEV-SNP"),
        IgvmPlatformType::VSM_ISOLATION => ("Microsoft", "VBS"),
        _ => return None,
    };
    known_platforms()
        .iter()
        .find(|p| p.vendor == vendor && p.model == model)
}

// Errors

/// Errors from launch endorsement generation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The platform type is not supported for CoRIM launch endorsements.
    #[error(
        "unsupported platform type {0:?}: only SEV_SNP, TDX, and \
         VSM_ISOLATION are supported for CoRIM launch endorsements"
    )]
    UnsupportedPlatform(IgvmPlatformType),
    /// Digest length does not match the platform's expected size.
    #[error("digest length mismatch: expected {expected}, got {actual}")]
    DigestLength { expected: usize, actual: usize },
    /// CoRIM building or encoding failed.
    #[error("CoRIM build failed")]
    Build(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// Public API

/// Generate a CoRIM launch endorsement for the given platform.
///
/// See the [`profile`] module for the full specification.
pub fn generate(
    platform: IgvmPlatformType,
    launch_digest: &[u8],
    svn: u64,
) -> Result<Vec<u8>, Error> {
    let info = platform_info(platform).ok_or(Error::UnsupportedPlatform(platform))?;

    if launch_digest.len() != info.digest_len {
        return Err(Error::DigestLength {
            expected: info.digest_len,
            actual: launch_digest.len(),
        });
    }

    builder::build_corim_bytes(info, launch_digest, svn)
}
