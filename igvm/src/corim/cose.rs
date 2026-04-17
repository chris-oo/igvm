// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! COSE_Sign1 envelope validation for CoRIM payloads.
//!
//! Validates the structural envelope of a detached COSE_Sign1 signature
//! per RFC 9052 §4.2, delegating parsing to the [`corim`] crate's
//! [`decode_signed_corim`](corim::types::signed::decode_signed_corim).
//!
//! **Note:** Cryptographic signature verification is NOT performed.

/// Errors from COSE_Sign1 structural validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoseSign1Error {
    /// CBOR decoding of the COSE_Sign1 envelope failed.
    #[error("CBOR decode failed")]
    Decode(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Element [2] (payload) must be nil for a detached signature.
    #[error("payload must be nil for detached COSE_Sign1, got embedded bstr")]
    PayloadNotNil,
    /// Element [3] (signature) is an empty bstr.
    #[error("signature must not be empty")]
    SignatureEmpty,
    /// Protected header content-type does not match expected value.
    #[error("protected header content-type mismatch: expected {expected:?}, got {actual:?}")]
    ContentTypeMismatch { expected: String, actual: String },
}

/// Validate that a COSE_Sign1 envelope is well-formed with a detached
/// (nil) payload.
///
/// Checks:
/// 1. Valid COSE_Sign1 structure (Tag(18) wrapper, 4-element array)
/// 2. Protected and unprotected headers are well-formed
/// 3. Payload is nil (detached)
/// 4. Signature is non-empty
/// 5. If protected header contains `content-type`, it must be
///    `"application/rim+cbor"`
///
/// This function does NOT perform any cryptographic signature verification,
/// leaving the responsibility of signature validation to the relying party
/// during attestation.
pub fn validate_corim_envelope(data: &[u8]) -> Result<(), CoseSign1Error> {
    let signed = corim::types::signed::decode_signed_corim(data)
        .map_err(|e| CoseSign1Error::Decode(Box::new(e)))?;

    // Must be detached (nil payload)
    if signed.payload.is_some() {
        return Err(CoseSign1Error::PayloadNotNil);
    }

    // Signature must not be empty
    if signed.signature.is_empty() {
        return Err(CoseSign1Error::SignatureEmpty);
    }

    // Check content-type if present
    if let Some(ref ct) = signed.protected.content_type {
        const EXPECTED: &str = "application/rim+cbor";
        if ct != EXPECTED {
            return Err(CoseSign1Error::ContentTypeMismatch {
                expected: EXPECTED.to_string(),
                actual: ct.clone(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::types::common::{MeasuredElement, TagIdChoice};
    use corim::types::corim::CorimId;
    use corim::types::environment::{ClassMap, EnvironmentMap};
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
    use corim::types::signed::{CwtClaims, SignedCorimBuilder};
    use corim::types::triples::ReferenceTriple;

    use super::CoseSign1Error;

    /// Build a minimal unsigned CoRIM payload for test signing.
    fn build_test_corim_bytes() -> Vec<u8> {
        let env = EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("Test".into()),
                model: Some("Model".into()),
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        };
        let meas = MeasurementMap {
            mkey: Some(MeasuredElement::Text("fw".into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };
        let comid = ComidBuilder::new(TagIdChoice::Text("test-comid".into()))
            .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
            .build()
            .unwrap();
        CorimBuilder::new(CorimId::Text("test-corim".into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap()
    }

    /// Build a detached COSE_Sign1 envelope with a dummy signature.
    fn build_detached_envelope() -> Vec<u8> {
        let corim_bytes = build_test_corim_bytes();
        let mut builder = SignedCorimBuilder::new(-7, corim_bytes)
            .set_cwt_claims(CwtClaims::new("Test Signer"));
        let _tbs = builder.to_be_signed(&[]).unwrap();
        let signature = vec![0xDE; 64]; // dummy ES256 signature
        builder.build_detached_with_signature(signature).unwrap()
    }

    #[test]
    fn validates_detached_envelope() {
        let sig = build_detached_envelope();
        super::validate_corim_envelope(&sig).unwrap();
    }

    #[test]
    fn rejects_embedded_payload() {
        let corim_bytes = build_test_corim_bytes();
        let mut builder = SignedCorimBuilder::new(-7, corim_bytes)
            .set_cwt_claims(CwtClaims::new("Test Signer"));
        let _tbs = builder.to_be_signed(&[]).unwrap();
        let signature = vec![0xDE; 64];
        let sig = builder.build_with_signature(signature).unwrap();

        let err = super::validate_corim_envelope(&sig).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::PayloadNotNil),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_empty_signature() {
        let corim_bytes = build_test_corim_bytes();
        let mut builder = SignedCorimBuilder::new(-7, corim_bytes)
            .set_cwt_claims(CwtClaims::new("Test Signer"));
        let _tbs = builder.to_be_signed(&[]).unwrap();
        let signature = vec![];
        let sig = builder.build_detached_with_signature(signature).unwrap();

        let err = super::validate_corim_envelope(&sig).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::SignatureEmpty),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_empty_input() {
        let err = super::validate_corim_envelope(&[]).unwrap_err();
        assert!(matches!(err, CoseSign1Error::Decode(_)), "got: {err:?}");
    }
}
