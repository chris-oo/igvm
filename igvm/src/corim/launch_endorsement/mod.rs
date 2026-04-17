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
mod validate;

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

/// Errors from launch endorsement validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// CoRIM structural validation failed (from the corim crate).
    #[error("CoRIM validation failed: {0}")]
    CorimValidation(#[from] corim::ValidationError),
    /// Multiple CoMID tags found; profile requires exactly one.
    #[error("multiple CoMID tags found; profile requires exactly one")]
    MultipleComids,
    /// The CoRIM is missing the required profile URI.
    #[error("missing required profile URI")]
    MissingProfile,
    /// The CoRIM profile URI does not match the expected profile.
    #[error("profile mismatch: expected {expected:?}, got {actual:?}")]
    ProfileMismatch { expected: String, actual: String },
    /// The tag-id does not match the expected UUIDv5 derivation.
    #[error("tag-id mismatch: expected {expected:?}, got {actual:?}")]
    TagIdMismatch { expected: String, actual: String },
    /// The vendor/model does not match any supported platform.
    #[error("unknown platform: vendor={vendor:?}, model={model:?}")]
    UnknownPlatform { vendor: String, model: String },
    /// Digest algorithm or length doesn't match the platform.
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
    /// SVN field is missing or malformed.
    #[error("invalid SVN: {0}")]
    InvalidSvn(String),
    /// The triples map is missing reference-triples.
    #[error("triples map has no reference triples")]
    EmptyTriples,
    /// The conditional-endorsement-series triple is required but missing.
    #[error("conditional-endorsement-series triple is required by profile")]
    MissingCes,
    /// Structural issue in the decoded CoMID.
    #[error("{0}")]
    Structure(String),
    /// COSE_Sign1 envelope is structurally invalid.
    #[error("invalid COSE_Sign1 envelope")]
    CoseSign1(#[from] crate::corim::CoseSign1Error),
}

/// A parsed launch endorsement extracted from a CoRIM document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchEndorsement {
    /// Platform vendor (e.g. `"AMD"`, `"Intel"`, `"Microsoft"`).
    pub vendor: String,
    /// Platform model (e.g. `"SEV-SNP"`, `"TDX"`, `"VBS"`).
    pub model: String,
    /// The CoMID tag-id (UUIDv5-derived string).
    pub tag_id: String,
    /// The measurement key (e.g. `"MEASUREMENT"`, `"MRTD"`).
    pub mkey: String,
    /// Digest algorithm ID (e.g. 7 = SHA-384, 1 = SHA-256).
    pub digest_alg: i64,
    /// The raw digest bytes from the reference-values triple.
    pub digest: Vec<u8>,
    /// The endorsed exact SVN value.
    pub svn: u64,
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

/// Validate and decode a CoRIM launch endorsement document.
///
/// Enforces strict profile conformance. See the [`profile`] module for
/// the full list of constraints checked.
pub fn validate(bytes: &[u8]) -> Result<LaunchEndorsement, ValidationError> {
    validate::validate(bytes)
}
