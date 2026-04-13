// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CoRIM (Concise Reference Integrity Manifest) support for IGVM.
//!
//! This crate provides generation, validation, and COSE_Sign1 envelope
//! checking for CoRIM documents used in IGVM attestation.
//!
//! # Modules
//!
//! - [`launch_endorsement`] — The launch endorsement profile
//!   (`tag:microsoft.com,2026:igvm-launch-endorsement/v1`)
//! - [`cose`] — General COSE_Sign1 envelope validation for CoRIM payloads
//!
//! # Example
//!
//! ```rust
//! use igvm_defs::IgvmPlatformType;
//! use igvm_corim::launch_endorsement;
//!
//! let digest = vec![0xAA; 48]; // SHA-384 launch measurement
//! let corim_bytes = launch_endorsement::generate(
//!     IgvmPlatformType::SEV_SNP,
//!     &digest,
//!     1, // ISV SVN
//! ).unwrap();
//!
//! let endorsement = launch_endorsement::validate(&corim_bytes).unwrap();
//! assert_eq!(endorsement.vendor, "AMD");
//! assert_eq!(endorsement.svn, 1);
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

pub(crate) mod cbor;
pub(crate) mod constants;
pub mod cose;
pub mod launch_endorsement;

// Re-export launch_endorsement types at crate root for ergonomics.
pub use launch_endorsement::Error;
pub use launch_endorsement::LaunchEndorsement;
pub use launch_endorsement::ValidationError;

// Crate-level error type for COSE_Sign1 validation (shared across profiles).

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
    /// Element [2] (payload) must be nil for a detached signature.
    #[error("payload must be nil for detached COSE_Sign1, got embedded bstr")]
    PayloadNotNil,
    /// Element [2] (payload) is not nil or bstr.
    #[error("element [2] (payload) has unexpected type")]
    InvalidPayload,
    /// Element [3] (signature) is not a bstr.
    #[error("element [3] (signature) must be a bstr")]
    InvalidSignature,
    /// Protected header content-type does not match expected value.
    #[error("protected header content-type mismatch: expected {expected:?}, got {actual:?}")]
    ContentTypeMismatch { expected: String, actual: String },
}

#[cfg(test)]
mod tests {
    use crate::launch_endorsement;
    use crate::CoseSign1Error;
    use ciborium::Value;
    use igvm_defs::IgvmPlatformType;

    /// Encode a `Value` to CBOR bytes (test helper).
    fn encode(value: &Value) -> Vec<u8> {
        crate::cbor::encode(value).unwrap()
    }

    /// Shorthand: integer key.
    fn k(key: i64) -> Value {
        crate::cbor::int_key(key)
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
        let bytes = launch_endorsement::generate(IgvmPlatformType::SEV_SNP, &digest, 1).unwrap();

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
    }

    #[test]
    fn intel_tdx_round_trip() {
        let digest = vec![0xBB; 48];
        let bytes = launch_endorsement::generate(IgvmPlatformType::TDX, &digest, 5).unwrap();

        let corim = unwrap_corim(&bytes);
        assert_eq!(as_text(map_get(&corim, 0)), "Intel/TDX/launch-endorsement");
    }

    #[test]
    fn microsoft_vbs_round_trip() {
        let digest = vec![0xCC; 32];
        let bytes =
            launch_endorsement::generate(IgvmPlatformType::VSM_ISOLATION, &digest, 2).unwrap();

        let corim = unwrap_corim(&bytes);
        assert_eq!(
            as_text(map_get(&corim, 0)),
            "Microsoft/VBS/launch-endorsement"
        );
    }

    #[test]
    fn wrong_digest_length_rejected() {
        let err =
            launch_endorsement::generate(IgvmPlatformType::SEV_SNP, &[0xAA; 32], 1).unwrap_err();
        assert!(err.to_string().contains("digest length mismatch"));
    }

    #[test]
    fn vbs_wrong_digest_length_rejected() {
        let err =
            launch_endorsement::generate(IgvmPlatformType::VSM_ISOLATION, &[0xCC; 48], 1)
                .unwrap_err();
        assert!(err.to_string().contains("expected 32, got 48"));
    }

    #[test]
    fn output_has_tag_501() {
        let bytes =
            launch_endorsement::generate(IgvmPlatformType::SEV_SNP, &[0xAA; 48], 1).unwrap();
        let val: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        match val {
            Value::Tag(501, _) => {}
            other => panic!("expected tag 501, got: {other:?}"),
        }
    }

    // Validation tests

    #[test]
    fn validate_snp_round_trip() {
        let digest = vec![0xAA; 48];
        let bytes = launch_endorsement::generate(IgvmPlatformType::SEV_SNP, &digest, 7).unwrap();

        let e = launch_endorsement::validate(&bytes).unwrap();
        assert_eq!(e.vendor, "AMD");
        assert_eq!(e.model, "SEV-SNP");
        assert_eq!(e.svn, 7);
        assert_eq!(e.digest, digest);
        assert_eq!(e.tag_id, "77e8061e-4634-5e53-a848-d1d09e996843");
    }

    #[test]
    fn validate_tdx_round_trip() {
        let digest = vec![0xBB; 48];
        let bytes = launch_endorsement::generate(IgvmPlatformType::TDX, &digest, 3).unwrap();

        let e = launch_endorsement::validate(&bytes).unwrap();
        assert_eq!(e.vendor, "Intel");
        assert_eq!(e.model, "TDX");
        assert_eq!(e.mkey, "MRTD");
        assert_eq!(e.svn, 3);
    }

    #[test]
    fn validate_vbs_round_trip() {
        let digest = vec![0xCC; 32];
        let bytes =
            launch_endorsement::generate(IgvmPlatformType::VSM_ISOLATION, &digest, 99).unwrap();

        let e = launch_endorsement::validate(&bytes).unwrap();
        assert_eq!(e.vendor, "Microsoft");
        assert_eq!(e.model, "VBS");
        assert_eq!(e.digest_alg, 1);
        assert_eq!(e.svn, 99);
    }

    #[test]
    fn validate_rejects_garbage() {
        let err = launch_endorsement::validate(&[0xFF, 0x00]).unwrap_err();
        assert!(err.to_string().contains("CBOR decode"));
    }

    #[test]
    fn validate_rejects_missing_tag_501() {
        let plain = cbor_map(vec![(k(0), Value::Text("hello".into()))]);
        let bytes = encode(&plain);
        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(err.to_string().contains("missing CBOR tag 501"));
    }

    #[test]
    fn validate_rejects_no_comid() {
        use crate::constants::TAG_CORIM;
        use crate::launch_endorsement::profile::PROFILE_URI;

        let corim_map = cbor_map(vec![
            (k(0), Value::Text("test".into())),
            (k(1), Value::Array(vec![])),
            (k(3), Value::Text(PROFILE_URI.into())),
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);
        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(err.to_string().contains("no CoMID tag"));
    }

    #[test]
    fn validate_rejects_wrong_profile() {
        let digest = vec![0xAA; 48];
        let info = launch_endorsement::known_platforms()
            .iter()
            .find(|p| p.vendor == "AMD")
            .unwrap();
        let comid_bytes =
            crate::launch_endorsement::builder::build_comid(info, &digest, 1).unwrap();

        use crate::constants::CORIM_ID;
        use crate::constants::CORIM_PROFILE;
        use crate::constants::CORIM_TAGS;
        use crate::constants::TAG_COMID;
        use crate::constants::TAG_CORIM;

        let tagged_comid = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_bytes)));
        let corim_map = cbor_map(vec![
            (k(CORIM_ID), Value::Text("test".into())),
            (k(CORIM_TAGS), Value::Array(vec![tagged_comid])),
            (k(CORIM_PROFILE), Value::Text("tag:evil.com,2025:wrong".into())),
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);

        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(err.to_string().contains("profile mismatch"));
    }

    #[test]
    fn validate_rejects_missing_profile() {
        let digest = vec![0xAA; 48];
        let info = launch_endorsement::known_platforms()
            .iter()
            .find(|p| p.vendor == "AMD")
            .unwrap();
        let comid_bytes =
            crate::launch_endorsement::builder::build_comid(info, &digest, 1).unwrap();

        use crate::constants::TAG_COMID;
        use crate::constants::TAG_CORIM;

        let tagged_comid = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_bytes)));
        let corim_map = cbor_map(vec![
            (k(0), Value::Text("test".into())),
            (k(1), Value::Array(vec![tagged_comid])),
        ]);
        let tagged = Value::Tag(TAG_CORIM, Box::new(corim_map));
        let bytes = encode(&tagged);

        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(err.to_string().contains("missing required profile"));
    }

    #[test]
    fn validate_rejects_wrong_digest_length() {
        let info = launch_endorsement::known_platforms()
            .iter()
            .find(|p| p.vendor == "AMD")
            .unwrap();
        let comid_bytes =
            crate::launch_endorsement::builder::build_comid(info, &[0xAA; 32], 1).unwrap();
        let corim_bytes =
            crate::launch_endorsement::builder::build_corim(info, comid_bytes).unwrap();

        let err = launch_endorsement::validate(&corim_bytes).unwrap_err();
        assert!(err.to_string().contains("expected 48 bytes, got 32"));
    }

    #[test]
    fn validate_rejects_wrong_digest_alg() {
        let info = launch_endorsement::PlatformInfo {
            vendor: "AMD",
            model: "SEV-SNP",
            mkey: "MEASUREMENT",
            digest_alg: 1, // wrong
            digest_len: 48,
        };
        let comid_bytes =
            crate::launch_endorsement::builder::build_comid(&info, &[0xAA; 48], 1).unwrap();
        let corim_bytes =
            crate::launch_endorsement::builder::build_corim(&info, comid_bytes).unwrap();

        let err = launch_endorsement::validate(&corim_bytes).unwrap_err();
        assert!(err.to_string().contains("expected algorithm 7, got 1"));
    }

    // COSE envelope tests

    fn build_detached_cose_sign1(protected: &[u8]) -> Vec<u8> {
        use crate::constants::TAG_COSE_SIGN1;

        let cose = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::Bytes(protected.to_vec()),
                Value::Map(vec![]),
                Value::Null,
                Value::Bytes(vec![0xDE; 32]),
            ])),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        buf
    }

    fn encode_protected_header(entries: Vec<(Value, Value)>) -> Vec<u8> {
        let map = Value::Map(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        buf
    }

    #[test]
    fn envelope_validates_empty_protected() {
        let sig = build_detached_cose_sign1(&[]);
        crate::cose::validate_corim_envelope(&sig).unwrap();
    }

    #[test]
    fn envelope_validates_correct_content_type() {
        use crate::constants::COSE_HEADER_CONTENT_TYPE;
        use crate::constants::CORIM_CONTENT_TYPE;

        let protected = encode_protected_header(vec![(
            Value::Integer(COSE_HEADER_CONTENT_TYPE.into()),
            Value::Text(CORIM_CONTENT_TYPE.into()),
        )]);
        let sig = build_detached_cose_sign1(&protected);
        crate::cose::validate_corim_envelope(&sig).unwrap();
    }

    #[test]
    fn envelope_rejects_wrong_content_type() {
        use crate::constants::COSE_HEADER_CONTENT_TYPE;

        let protected = encode_protected_header(vec![(
            Value::Integer(COSE_HEADER_CONTENT_TYPE.into()),
            Value::Text("application/json".into()),
        )]);
        let sig = build_detached_cose_sign1(&protected);
        let err = crate::cose::validate_corim_envelope(&sig).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::ContentTypeMismatch { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn envelope_rejects_embedded_payload() {
        use crate::constants::TAG_COSE_SIGN1;

        let cose = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![]),
                Value::Map(vec![]),
                Value::Bytes(vec![0x01, 0x02]),
                Value::Bytes(vec![0xDE; 32]),
            ])),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();

        let err = crate::cose::validate_corim_envelope(&buf).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::PayloadNotNil),
            "got: {err:?}"
        );
    }

    #[test]
    fn envelope_rejects_wrong_array_length() {
        use crate::constants::TAG_COSE_SIGN1;

        let cose = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![]),
                Value::Map(vec![]),
                Value::Null,
            ])),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();

        let err = crate::cose::validate_corim_envelope(&buf).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::WrongArrayLength { actual: 3 }),
            "got: {err:?}"
        );
    }

    #[test]
    fn envelope_rejects_empty_input() {
        let err = crate::cose::validate_corim_envelope(&[]).unwrap_err();
        assert!(matches!(err, CoseSign1Error::Decode(_)), "got: {err:?}");
    }

    #[test]
    fn envelope_accepts_no_tag() {
        let cose = Value::Array(vec![
            Value::Bytes(vec![]),
            Value::Map(vec![]),
            Value::Null,
            Value::Bytes(vec![0xFF; 32]),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();

        crate::cose::validate_corim_envelope(&buf).unwrap();
    }
}
