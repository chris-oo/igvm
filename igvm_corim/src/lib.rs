// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Minimal CoRIM launch-endorsement generator and validator for IGVM.
//!
//! This crate provides a single-function API to produce and validate CoRIM
//! documents containing a launch measurement reference value and an SVN
//! endorsement for supported platforms.
//!
//! # Example
//!
//! ```rust
//! use igvm_defs::IgvmPlatformType;
//! use igvm_corim::generate_launch_endorsement;
//! use igvm_corim::validate_launch_endorsement;
//!
//! let digest = vec![0xAA; 48]; // SHA-384 launch measurement
//! let corim_bytes = generate_launch_endorsement(
//!     IgvmPlatformType::SEV_SNP,
//!     &digest,
//!     1, // ISV SVN
//! ).unwrap();
//!
//! let endorsement = validate_launch_endorsement(&corim_bytes).unwrap();
//! assert_eq!(endorsement.vendor, "AMD");
//! assert_eq!(endorsement.svn, 1);
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod builder;
mod cbor;
pub(crate) mod constants;
pub mod profile;
mod signed;
mod validate;

pub use igvm_defs::IgvmPlatformType;

// Platform properties

/// Platform properties for CoRIM generation and validation.
pub(crate) struct PlatformInfo {
    pub vendor: &'static str,
    pub model: &'static str,
    pub mkey: &'static str,
    pub digest_alg: i64,
    pub digest_len: usize,
}

/// Canonical list of supported platforms. Used by both builder and validator
/// to avoid duplication.
pub(crate) fn known_platforms() -> &'static [PlatformInfo] {
    use constants::NI_SHA256;
    use constants::NI_SHA384;

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
    /// CBOR encoding failed.
    #[error("CBOR encode failed")]
    Encode(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors from launch endorsement validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// CBOR decoding failed.
    #[error("CBOR decode failed")]
    Decode(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Expected CBOR tag not found.
    #[error("missing CBOR tag {expected}")]
    MissingTag { expected: u64 },
    /// Required map key not found.
    #[error("missing key {key} in {context}")]
    MissingKey { key: i64, context: &'static str },
    /// A value had an unexpected CBOR type.
    #[error("expected {expected} in {context}")]
    UnexpectedType {
        expected: &'static str,
        context: &'static str,
    },
    /// No CoMID tag (tag 506) found in the tags array.
    #[error("no CoMID tag (506) found in tags array")]
    NoComid,
    /// Multiple CoMID tags found; profile requires exactly one.
    #[error("multiple CoMID tags found; profile requires exactly one")]
    MultipleComids,
    /// The CoRIM is missing the required profile URI.
    #[error("missing required profile URI")]
    MissingProfile,
    /// The triples map is missing both reference-triples and CES triples.
    #[error("triples map has no reference or CES triples")]
    EmptyTriples,
    /// The conditional-endorsement-series triple is required but missing.
    #[error("conditional-endorsement-series triple is required by profile")]
    MissingCes,
    /// The CoRIM profile URI does not match the expected IGVM launch endorsement profile.
    #[error("profile mismatch: expected {expected:?}, got {actual:?}")]
    ProfileMismatch { expected: String, actual: String },
    /// The tag-id does not match the expected UUIDv5 derivation from vendor/model.
    #[error("tag-id mismatch: expected {expected:?}, got {actual:?}")]
    TagIdMismatch { expected: String, actual: String },
    /// The vendor/model in the CoRIM does not match any supported platform.
    #[error("unknown platform: vendor={vendor:?}, model={model:?}")]
    UnknownPlatform { vendor: String, model: String },
    /// Digest algorithm or length doesn't match the platform.
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
    /// SVN field is missing or malformed.
    #[error("invalid SVN: {0}")]
    InvalidSvn(String),
    /// COSE_Sign1 envelope is structurally invalid.
    #[error("invalid COSE_Sign1 envelope")]
    CoseSign1(#[from] CoseSign1Error),
}

/// Errors from COSE_Sign1 structural validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoseSign1Error {
    /// CBOR decoding of the COSE_Sign1 envelope failed.
    #[error("CBOR decode failed")]
    Decode(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The outer value is not a COSE_Sign1 array or Tag(18).
    #[error("expected COSE_Sign1 array or Tag(18)")]
    NotCoseSign1,
    /// The COSE_Sign1 array does not have exactly 4 elements.
    #[error("COSE_Sign1 must have 4 elements, got {actual}")]
    WrongArrayLength { actual: usize },
    /// Element [0] (protected headers) is not a bstr.
    #[error("element [0] (protected) must be a bstr")]
    InvalidProtected,
    /// Element [1] (unprotected headers) is not a map.
    #[error("element [1] (unprotected) must be a map")]
    InvalidUnprotected,
    /// Element [2] (payload) is nil — this is a detached signature.
    #[error("payload is nil (detached); use validate_launch_endorsement on the document directly")]
    DetachedPayload,
    /// Element [2] (payload) is not a bstr.
    #[error("element [2] (payload) must be a bstr")]
    InvalidPayload,
    /// Element [3] (signature) is not a bstr.
    #[error("element [3] (signature) must be a bstr")]
    InvalidSignature,
}

// Shared public types

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
    /// Digest algorithm ID (IANA COSE, e.g. 7 = SHA-384, 1 = SHA-256).
    pub digest_alg: i64,
    /// The raw digest bytes from the reference-values triple.
    pub digest: Vec<u8>,
    /// The endorsed exact SVN value from the conditional-endorsement-series triple.
    pub svn: u64,
}

// Public API — re-exported from submodules

/// Generate a CoRIM launch endorsement for the given platform.
///
/// Produces a CBOR-encoded, tag-501-wrapped CoRIM containing:
/// - A **reference-values** triple with the launch measurement digest
///   (Phase 3 — corroborate against hardware evidence).
/// - A **conditional-endorsement-series** triple mapping that digest to
///   the given SVN (Phase 4 — endorse metadata not in evidence).
///
/// The CoMID `tag-id` is derived deterministically via UUIDv5 from the
/// platform's vendor/model strings.
///
/// # Arguments
///
/// * `platform` — The IGVM platform type. Only [`IgvmPlatformType::SEV_SNP`],
///   [`IgvmPlatformType::TDX`], and [`IgvmPlatformType::VSM_ISOLATION`] are
///   supported. Other variants return [`Error::UnsupportedPlatform`].
/// * `launch_digest` — The raw digest bytes. Must match the platform's
///   expected length (48 for SHA-384, 32 for SHA-256).
/// * `svn` — The ISV SVN to endorse for this digest.
///
/// # Returns
///
/// CBOR bytes (`#6.501(corim-map)`) ready for embedding or transmission.
pub fn generate_launch_endorsement(
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

    let comid_bytes = builder::build_comid(info, launch_digest, svn)?;
    builder::build_corim(info, comid_bytes)
}

/// Validate and decode a CoRIM launch endorsement.
///
/// Enforces strict profile conformance. See the [`profile`] module for the
/// full list of constraints checked.
pub fn validate_launch_endorsement(bytes: &[u8]) -> Result<LaunchEndorsement, ValidationError> {
    validate::validate_launch_endorsement(bytes)
}

/// Validate a signed CoRIM (COSE_Sign1) and extract the launch endorsement.
///
/// Parses the COSE_Sign1 envelope, extracts the embedded payload, and
/// validates it as a launch endorsement. Cryptographic signature
/// verification is **not** performed.
///
/// See [`signed::validate_signed_corim`] for details.
pub fn validate_signed_corim(bytes: &[u8]) -> Result<LaunchEndorsement, ValidationError> {
    signed::validate_signed_corim(bytes)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::TAG_COMID;
    use crate::constants::TAG_CORIM;
    use ciborium::Value;

    /// Encode a `Value` to CBOR bytes (test helper).
    fn encode(value: &Value) -> Vec<u8> {
        cbor::encode(value).unwrap()
    }

    /// Shorthand: integer key.
    fn k(key: i64) -> Value {
        cbor::int_key(key)
    }

    /// Shorthand: build a CBOR map.
    fn cbor_map(entries: Vec<(Value, Value)>) -> Value {
        Value::Map(entries)
    }

    /// Decode the tag-501 wrapper and return the inner corim-map.
    fn unwrap_corim(bytes: &[u8]) -> Value {
        let val: Value = ciborium::from_reader(bytes).expect("valid CBOR");
        match val {
            Value::Tag(501, inner) => *inner,
            other => panic!("expected tag 501, got: {other:?}"),
        }
    }

    /// Get a map entry by integer key.
    fn map_get(map: &Value, key: i64) -> &Value {
        match map {
            Value::Map(entries) => {
                for (k, v) in entries {
                    if let Value::Integer(i) = k {
                        if i128::from(*i) == key as i128 {
                            return v;
                        }
                    }
                }
                panic!("key {key} not found in map");
            }
            other => panic!("expected map, got: {other:?}"),
        }
    }

    /// Extract text from a Value.
    fn as_text(v: &Value) -> &str {
        match v {
            Value::Text(t) => t,
            other => panic!("expected text, got: {other:?}"),
        }
    }

    // Builder tests

    #[test]
    fn amd_sev_snp_round_trip() {
        let digest = vec![0xAA; 48];
        let bytes = generate_launch_endorsement(IgvmPlatformType::SEV_SNP, &digest, 1).unwrap();

        let corim = unwrap_corim(&bytes);
        assert_eq!(
            as_text(map_get(&corim, 0)),
            "AMD/SEV-SNP/launch-endorsement"
        );

        let tags = match map_get(&corim, 1) {
            Value::Array(a) => a,
            other => panic!("expected array, got: {other:?}"),
        };
        assert_eq!(tags.len(), 1);

        let comid_bytes = match &tags[0] {
            Value::Tag(506, inner) => match inner.as_ref() {
                Value::Bytes(b) => b,
                other => panic!("expected bytes, got: {other:?}"),
            },
            other => panic!("expected tag 506, got: {other:?}"),
        };
        let comid: Value = ciborium::from_reader(comid_bytes.as_slice()).unwrap();

        let tag_identity = map_get(&comid, 1);
        assert_eq!(
            as_text(map_get(tag_identity, 0)),
            "77e8061e-4634-5e53-a848-d1d09e996843"
        );

        let triples = map_get(&comid, 4);
        let ref_triples = match map_get(triples, 0) {
            Value::Array(a) => a,
            other => panic!("expected array, got: {other:?}"),
        };
        assert_eq!(ref_triples.len(), 1);

        let ces_triples = match map_get(triples, 8) {
            Value::Array(a) => a,
            other => panic!("expected array, got: {other:?}"),
        };
        assert_eq!(ces_triples.len(), 1);
    }

    #[test]
    fn intel_tdx_round_trip() {
        let digest = vec![0xBB; 48];
        let bytes = generate_launch_endorsement(IgvmPlatformType::TDX, &digest, 5).unwrap();

        let corim = unwrap_corim(&bytes);
        assert_eq!(as_text(map_get(&corim, 0)), "Intel/TDX/launch-endorsement");

        let tags = match map_get(&corim, 1) {
            Value::Array(a) => a,
            other => panic!("expected array: {other:?}"),
        };
        let comid_bytes = match &tags[0] {
            Value::Tag(506, inner) => match inner.as_ref() {
                Value::Bytes(b) => b,
                other => panic!("expected bytes: {other:?}"),
            },
            other => panic!("expected tag 506: {other:?}"),
        };
        let comid: Value = ciborium::from_reader(comid_bytes.as_slice()).unwrap();
        let tag_identity = map_get(&comid, 1);
        assert_eq!(
            as_text(map_get(tag_identity, 0)),
            "e0510081-7b78-5b2a-97a6-d73d890e07b6"
        );
    }

    #[test]
    fn microsoft_vbs_round_trip() {
        let digest = vec![0xCC; 32];
        let bytes =
            generate_launch_endorsement(IgvmPlatformType::VSM_ISOLATION, &digest, 2).unwrap();

        let corim = unwrap_corim(&bytes);
        assert_eq!(
            as_text(map_get(&corim, 0)),
            "Microsoft/VBS/launch-endorsement"
        );

        let tags = match map_get(&corim, 1) {
            Value::Array(a) => a,
            other => panic!("expected array: {other:?}"),
        };
        let comid_bytes = match &tags[0] {
            Value::Tag(506, inner) => match inner.as_ref() {
                Value::Bytes(b) => b,
                other => panic!("expected bytes: {other:?}"),
            },
            other => panic!("expected tag 506: {other:?}"),
        };
        let comid: Value = ciborium::from_reader(comid_bytes.as_slice()).unwrap();
        let tag_identity = map_get(&comid, 1);
        assert_eq!(
            as_text(map_get(tag_identity, 0)),
            "2e29068e-e0fa-59e6-b0ff-3bfe09132e13"
        );
    }

    #[test]
    fn wrong_digest_length_rejected() {
        let err =
            generate_launch_endorsement(IgvmPlatformType::SEV_SNP, &[0xAA; 32], 1).unwrap_err();
        assert!(err.to_string().contains("digest length mismatch"));
    }

    #[test]
    fn vbs_wrong_digest_length_rejected() {
        let err = generate_launch_endorsement(IgvmPlatformType::VSM_ISOLATION, &[0xCC; 48], 1)
            .unwrap_err();
        assert!(err.to_string().contains("expected 32, got 48"));
    }

    #[test]
    fn output_has_tag_501() {
        let bytes = generate_launch_endorsement(IgvmPlatformType::SEV_SNP, &[0xAA; 48], 1).unwrap();
        let val: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        match val {
            Value::Tag(501, _) => {}
            other => panic!("expected tag 501, got: {other:?}"),
        }
    }

    #[test]
    fn verify_cbor_structure_detail() {
        let digest = vec![0xDD; 48];
        let bytes = generate_launch_endorsement(IgvmPlatformType::SEV_SNP, &digest, 42).unwrap();

        let corim = unwrap_corim(&bytes);
        let tags = match map_get(&corim, 1) {
            Value::Array(a) => a,
            _ => panic!(),
        };
        let comid_bytes = match &tags[0] {
            Value::Tag(506, inner) => match inner.as_ref() {
                Value::Bytes(b) => b,
                _ => panic!(),
            },
            _ => panic!(),
        };
        let comid: Value = ciborium::from_reader(comid_bytes.as_slice()).unwrap();
        let triples = map_get(&comid, 4);

        let ref_triple = match map_get(triples, 0) {
            Value::Array(a) => match &a[0] {
                Value::Array(inner) => inner,
                _ => panic!(),
            },
            _ => panic!(),
        };
        let env = &ref_triple[0];
        let class = map_get(env, 0);
        assert_eq!(as_text(map_get(class, 1)), "AMD");
        assert_eq!(as_text(map_get(class, 2)), "SEV-SNP");

        let measurements = match &ref_triple[1] {
            Value::Array(a) => a,
            _ => panic!(),
        };
        let meas = &measurements[0];
        assert_eq!(as_text(map_get(meas, 0)), "MEASUREMENT");

        let mval = map_get(meas, 1);
        let digests = match map_get(mval, 2) {
            Value::Array(a) => a,
            _ => panic!(),
        };
        let d = match &digests[0] {
            Value::Array(a) => a,
            _ => panic!(),
        };
        assert_eq!(d[0], Value::Integer(7.into()));
        assert_eq!(d[1], Value::Bytes(vec![0xDD; 48]));

        let ces_triple = match map_get(triples, 8) {
            Value::Array(a) => match &a[0] {
                Value::Array(inner) => inner,
                _ => panic!(),
            },
            _ => panic!(),
        };
        let series = match &ces_triple[1] {
            Value::Array(a) => a,
            _ => panic!(),
        };
        let series_entry = match &series[0] {
            Value::Array(a) => a,
            _ => panic!(),
        };
        let addition = match &series_entry[1] {
            Value::Array(a) => &a[0],
            _ => panic!(),
        };
        let svn_val = map_get(map_get(addition, 1), 1);
        match svn_val {
            Value::Tag(552, inner) => {
                assert_eq!(**inner, Value::Integer(42.into()));
            }
            other => panic!("expected tag 552, got: {other:?}"),
        }
    }

    // Validation tests

    #[test]
    fn validate_snp_round_trip() {
        let digest = vec![0xAA; 48];
        let bytes = generate_launch_endorsement(IgvmPlatformType::SEV_SNP, &digest, 7).unwrap();

        let e = validate_launch_endorsement(&bytes).unwrap();
        assert_eq!(e.vendor, "AMD");
        assert_eq!(e.model, "SEV-SNP");
        assert_eq!(e.mkey, "MEASUREMENT");
        assert_eq!(e.digest_alg, 7);
        assert_eq!(e.digest, digest);
        assert_eq!(e.svn, 7);
        assert_eq!(e.tag_id, "77e8061e-4634-5e53-a848-d1d09e996843");
    }

    #[test]
    fn validate_tdx_round_trip() {
        let digest = vec![0xBB; 48];
        let bytes = generate_launch_endorsement(IgvmPlatformType::TDX, &digest, 3).unwrap();

        let e = validate_launch_endorsement(&bytes).unwrap();
        assert_eq!(e.vendor, "Intel");
        assert_eq!(e.model, "TDX");
        assert_eq!(e.mkey, "MRTD");
        assert_eq!(e.digest_alg, 7);
        assert_eq!(e.digest, digest);
        assert_eq!(e.svn, 3);
        assert_eq!(e.tag_id, "e0510081-7b78-5b2a-97a6-d73d890e07b6");
    }

    #[test]
    fn validate_vbs_round_trip() {
        let digest = vec![0xCC; 32];
        let bytes =
            generate_launch_endorsement(IgvmPlatformType::VSM_ISOLATION, &digest, 99).unwrap();

        let e = validate_launch_endorsement(&bytes).unwrap();
        assert_eq!(e.vendor, "Microsoft");
        assert_eq!(e.model, "VBS");
        assert_eq!(e.mkey, "MEASUREMENT");
        assert_eq!(e.digest_alg, 1);
        assert_eq!(e.digest, digest);
        assert_eq!(e.svn, 99);
    }

    #[test]
    fn validate_rejects_garbage() {
        let err = validate_launch_endorsement(&[0xFF, 0x00]).unwrap_err();
        assert!(err.to_string().contains("CBOR decode"));
    }

    #[test]
    fn validate_rejects_missing_tag_501() {
        let plain = cbor_map(vec![(k(0), Value::Text("hello".into()))]);
        let bytes = encode(&plain);
        let err = validate_launch_endorsement(&bytes).unwrap_err();
        assert!(err.to_string().contains("missing CBOR tag 501"));
    }

    #[test]
    fn validate_rejects_no_comid() {
        use crate::profile::PROFILE_URI;

        let corim_map = cbor_map(vec![
            (k(0), Value::Text("test".into())),
            (k(1), Value::Array(vec![])),
            (k(3), Value::Text(PROFILE_URI.into())),
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);
        let err = validate_launch_endorsement(&bytes).unwrap_err();
        assert!(err.to_string().contains("no CoMID tag"));
    }

    #[test]
    fn validate_rejects_unknown_platform() {
        use crate::constants::TAG_ID_NAMESPACE;
        use crate::profile::PROFILE_URI;
        use uuid::Uuid;

        // Compute correct tag-id for the unknown vendor/model
        let fake_tag_id = Uuid::new_v5(&TAG_ID_NAMESPACE, b"FooVendor/BarModel").to_string();

        let env = cbor_map(vec![(
            k(0),
            cbor_map(vec![
                (k(1), Value::Text("FooVendor".into())),
                (k(2), Value::Text("BarModel".into())),
            ]),
        )]);
        let mval = cbor_map(vec![(
            k(2),
            Value::Array(vec![Value::Array(vec![
                Value::Integer(7.into()),
                Value::Bytes(vec![0; 48]),
            ])]),
        )]);
        let measurement = cbor_map(vec![
            (k(0), Value::Text("MEASUREMENT".into())),
            (k(1), mval),
        ]);
        let ref_triple = Value::Array(vec![env, Value::Array(vec![measurement])]);
        let triples = cbor_map(vec![(k(0), Value::Array(vec![ref_triple]))]);
        let tag_identity = cbor_map(vec![(k(0), Value::Text(fake_tag_id))]);
        let comid = cbor_map(vec![(k(1), tag_identity), (k(4), triples)]);
        let comid_bytes = encode(&comid);

        let tagged_comid = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_bytes)));
        let corim_map = cbor_map(vec![
            (k(0), Value::Text("test".into())),
            (k(1), Value::Array(vec![tagged_comid])),
            (k(3), Value::Text(PROFILE_URI.into())),
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);

        let err = validate_launch_endorsement(&bytes).unwrap_err();
        assert!(err.to_string().contains("unknown platform"));
        assert!(err.to_string().contains("FooVendor"));
    }

    #[test]
    fn validate_rejects_wrong_digest_length() {
        let info = PlatformInfo {
            vendor: "AMD",
            model: "SEV-SNP",
            mkey: "MEASUREMENT",
            digest_alg: 7,
            digest_len: 48,
        };
        let comid_bytes = builder::build_comid(&info, &[0xAA; 32], 1).unwrap();
        let corim_bytes = builder::build_corim(&info, comid_bytes).unwrap();

        let err = validate_launch_endorsement(&corim_bytes).unwrap_err();
        assert!(err.to_string().contains("expected 48 bytes, got 32"));
    }

    #[test]
    fn validate_rejects_wrong_digest_alg() {
        // Build a structurally valid CoRIM for AMD/SEV-SNP but with wrong
        // digest algorithm (SHA-256 = 1 instead of SHA-384 = 7).
        let info = PlatformInfo {
            vendor: "AMD",
            model: "SEV-SNP",
            mkey: "MEASUREMENT",
            digest_alg: 1, // wrong: should be 7 for SEV-SNP
            digest_len: 48,
        };
        let comid_bytes = builder::build_comid(&info, &[0xAA; 48], 1).unwrap();
        let corim_bytes = builder::build_corim(&info, comid_bytes).unwrap();

        let err = validate_launch_endorsement(&corim_bytes).unwrap_err();
        assert!(err.to_string().contains("expected algorithm 7, got 1"));
    }

    #[test]
    fn validate_rejects_wrong_profile() {
        // Build a valid CoRIM, then re-encode with a wrong profile URI.
        let digest = vec![0xAA; 48];
        let info = platform_info(IgvmPlatformType::SEV_SNP).unwrap();
        let comid_bytes = builder::build_comid(info, &digest, 1).unwrap();

        // Manually build corim-map with wrong profile
        use crate::constants::CORIM_ID;
        use crate::constants::CORIM_PROFILE;
        use crate::constants::CORIM_TAGS;
        use crate::constants::TAG_COMID;
        use crate::constants::TAG_CORIM;

        let tagged_comid = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_bytes)));
        let corim_map = cbor_map(vec![
            (k(CORIM_ID), Value::Text("test".into())),
            (k(CORIM_TAGS), Value::Array(vec![tagged_comid])),
            (k(CORIM_PROFILE), Value::Text("tag:evil.com,2025:wrong-profile".into())),
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);

        let err = validate_launch_endorsement(&bytes).unwrap_err();
        assert!(err.to_string().contains("profile mismatch"));
    }

    #[test]
    fn validate_rejects_missing_profile() {
        // Build a CoRIM without the profile key
        let digest = vec![0xAA; 48];
        let info = platform_info(IgvmPlatformType::SEV_SNP).unwrap();
        let comid_bytes = builder::build_comid(info, &digest, 1).unwrap();

        let tagged_comid = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_bytes)));
        let corim_map = cbor_map(vec![
            (k(0), Value::Text("test".into())),
            (k(1), Value::Array(vec![tagged_comid])),
            // no key 3 (profile) — should be rejected
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);

        let err = validate_launch_endorsement(&bytes).unwrap_err();
        assert!(err.to_string().contains("missing required profile"));
    }

    #[test]
    fn validate_rejects_multiple_comids() {
        // Build a CoRIM with two CoMID tags
        let digest = vec![0xAA; 48];
        let info = platform_info(IgvmPlatformType::SEV_SNP).unwrap();
        let comid_bytes = builder::build_comid(info, &digest, 1).unwrap();

        use crate::constants::CORIM_ID;
        use crate::constants::CORIM_PROFILE;
        use crate::constants::CORIM_TAGS;
        use crate::constants::TAG_COMID;
        use crate::constants::TAG_CORIM;
        use crate::profile::PROFILE_URI;

        let tagged1 = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_bytes.clone())));
        let tagged2 = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_bytes)));
        let corim_map = cbor_map(vec![
            (k(CORIM_ID), Value::Text("test".into())),
            (k(CORIM_TAGS), Value::Array(vec![tagged1, tagged2])),
            (k(CORIM_PROFILE), Value::Text(PROFILE_URI.into())),
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);

        let err = validate_launch_endorsement(&bytes).unwrap_err();
        assert!(err.to_string().contains("multiple CoMID"));
    }

    #[test]
    fn validate_rejects_tag_id_mismatch() {
        // Build a CoRIM where the tag-id doesn't match UUIDv5(vendor/model)
        use crate::constants::COMID_TAG_IDENTITY;
        use crate::constants::COMID_TRIPLES;
        use crate::constants::CORIM_ID;
        use crate::constants::CORIM_PROFILE;
        use crate::constants::CORIM_TAGS;
        use crate::constants::TAG_COMID;
        use crate::constants::TAG_CORIM;
        use crate::constants::TAG_IDENTITY_TAG_ID;
        use crate::profile::PROFILE_URI;

        // Use AMD/SEV-SNP environment but a fake tag-id
        let info = platform_info(IgvmPlatformType::SEV_SNP).unwrap();
        let digest = vec![0xAA; 48];

        // Build triples normally via the builder internals
        // but override the tag-identity with a wrong UUID
        let comid_with_bad_tag = {
            let triples_val = {
                // We need a valid triples structure — easiest to just encode a
                // full comid and swap the tag-id
                let good_comid_bytes = builder::build_comid(info, &digest, 1).unwrap();
                let good_comid: Value =
                    ciborium::from_reader(good_comid_bytes.as_slice()).unwrap();
                // Extract triples from the good comid
                match &good_comid {
                    Value::Map(entries) => {
                        entries
                            .iter()
                            .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == 4))
                            .unwrap()
                            .1
                            .clone()
                    }
                    _ => panic!("expected map"),
                }
            };
            let bad_identity = cbor_map(vec![(
                k(TAG_IDENTITY_TAG_ID),
                Value::Text("00000000-0000-0000-0000-000000000000".into()),
            )]);
            let comid = cbor_map(vec![
                (k(COMID_TAG_IDENTITY), bad_identity),
                (k(COMID_TRIPLES), triples_val),
            ]);
            encode(&comid)
        };

        let tagged_comid = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_with_bad_tag)));
        let corim_map = cbor_map(vec![
            (k(CORIM_ID), Value::Text("test".into())),
            (k(CORIM_TAGS), Value::Array(vec![tagged_comid])),
            (k(CORIM_PROFILE), Value::Text(PROFILE_URI.into())),
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);

        let err = validate_launch_endorsement(&bytes).unwrap_err();
        assert!(err.to_string().contains("tag-id mismatch"));
    }
}
