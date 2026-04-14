// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! COSE_Sign1 envelope validation for CoRIM payloads.
//!
//! Validates the structural envelope of a detached COSE_Sign1 signature
//! per RFC 9052 §4.2. This is a general CoRIM operation, not specific to
//! any particular CoRIM profile.
//!
//! **Note:** Cryptographic signature verification is NOT performed.

use ciborium::Value;

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
/// 1. Optional CBOR Tag(18) wrapper
/// 2. 4-element CBOR array
/// 3. Element \[0\] is a bstr (protected headers)
/// 4. Element \[1\] is a map (unprotected headers)
/// 5. Element \[2\] is nil (detached payload)
/// 6. Element \[3\] is a bstr (signature)
/// 7. If protected header contains `content-type` (key 3), it must be
///    `"application/rim+cbor"`
///
/// This function does NOT perform any cryptographic signature verification, leaving
/// the responsibility of signature validation to the relaying party during attestation.
pub fn validate_corim_envelope(data: &[u8]) -> Result<(), CoseSign1Error> {
    use crate::corim::constants::COSE_HEADER_CONTENT_TYPE;
    use crate::corim::constants::COSE_SIGN1_ARRAY_LEN;
    use crate::corim::constants::CORIM_CONTENT_TYPE;
    use crate::corim::constants::TAG_COSE_SIGN1;

    let val: Value =
        ciborium::from_reader(data).map_err(|e| CoseSign1Error::Decode(Box::new(e)))?;

    // Unwrap optional Tag(18)
    let inner = match val {
        Value::Tag(TAG_COSE_SIGN1, inner) => *inner,
        Value::Array(_) => val,
        _ => return Err(CoseSign1Error::NotCoseSign1),
    };

    // Must be a 4-element array
    let elements = match &inner {
        Value::Array(arr) if arr.len() == COSE_SIGN1_ARRAY_LEN => arr,
        Value::Array(arr) => {
            return Err(CoseSign1Error::WrongArrayLength { actual: arr.len() })
        }
        _ => return Err(CoseSign1Error::NotCoseSign1),
    };

    // [0] protected — must be bstr
    let protected_bytes = match &elements[0] {
        Value::Bytes(b) => b.as_slice(),
        _ => return Err(CoseSign1Error::InvalidProtected),
    };

    // [1] unprotected — must be map
    if !matches!(&elements[1], Value::Map(_)) {
        return Err(CoseSign1Error::InvalidUnprotected);
    }

    // [2] payload — must be nil (detached)
    match &elements[2] {
        Value::Null => {}
        Value::Bytes(_) => return Err(CoseSign1Error::PayloadNotNil),
        _ => return Err(CoseSign1Error::InvalidPayload),
    }

    // [3] signature — must be non-empty bstr
    match &elements[3] {
        Value::Bytes(b) if b.is_empty() => return Err(CoseSign1Error::SignatureEmpty),
        Value::Bytes(_) => {}
        _ => return Err(CoseSign1Error::InvalidSignature),
    }

    // Validate protected header content-type if present
    if !protected_bytes.is_empty() {
        let protected_map: Value = ciborium::from_reader(protected_bytes)
            .map_err(|e| CoseSign1Error::Decode(Box::new(e)))?;

        if let Value::Map(entries) = &protected_map {
            for (key, value) in entries {
                if let Value::Integer(i) = key {
                    if i128::from(*i) == COSE_HEADER_CONTENT_TYPE as i128 {
                        match value {
                            Value::Text(ct) if ct == CORIM_CONTENT_TYPE => {}
                            Value::Text(ct) => {
                                return Err(CoseSign1Error::ContentTypeMismatch {
                                    expected: CORIM_CONTENT_TYPE.to_string(),
                                    actual: ct.clone(),
                                })
                            }
                            _ => {
                                return Err(CoseSign1Error::ContentTypeMismatch {
                                    expected: CORIM_CONTENT_TYPE.to_string(),
                                    actual: format!("{value:?}"),
                                })
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::CoseSign1Error;

    fn build_detached_cose_sign1(protected: &[u8]) -> Vec<u8> {
        use crate::corim::constants::TAG_COSE_SIGN1;

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
    fn validates_empty_protected() {
        let sig = build_detached_cose_sign1(&[]);
        super::validate_corim_envelope(&sig).unwrap();
    }

    #[test]
    fn validates_correct_content_type() {
        use crate::corim::constants::COSE_HEADER_CONTENT_TYPE;
        use crate::corim::constants::CORIM_CONTENT_TYPE;

        let protected = encode_protected_header(vec![(
            Value::Integer(COSE_HEADER_CONTENT_TYPE.into()),
            Value::Text(CORIM_CONTENT_TYPE.into()),
        )]);
        let sig = build_detached_cose_sign1(&protected);
        super::validate_corim_envelope(&sig).unwrap();
    }

    #[test]
    fn rejects_wrong_content_type() {
        use crate::corim::constants::COSE_HEADER_CONTENT_TYPE;

        let protected = encode_protected_header(vec![(
            Value::Integer(COSE_HEADER_CONTENT_TYPE.into()),
            Value::Text("application/json".into()),
        )]);
        let sig = build_detached_cose_sign1(&protected);
        let err = super::validate_corim_envelope(&sig).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::ContentTypeMismatch { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_embedded_payload() {
        use crate::corim::constants::TAG_COSE_SIGN1;

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

        let err = super::validate_corim_envelope(&buf).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::PayloadNotNil),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_array_length() {
        use crate::corim::constants::TAG_COSE_SIGN1;

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

        let err = super::validate_corim_envelope(&buf).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::WrongArrayLength { actual: 3 }),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_empty_input() {
        let err = super::validate_corim_envelope(&[]).unwrap_err();
        assert!(matches!(err, CoseSign1Error::Decode(_)), "got: {err:?}");
    }

    #[test]
    fn rejects_empty_signature() {
        use crate::corim::constants::TAG_COSE_SIGN1;

        let cose = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![]),
                Value::Map(vec![]),
                Value::Null,
                Value::Bytes(vec![]),
            ])),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();

        let err = super::validate_corim_envelope(&buf).unwrap_err();
        assert!(
            matches!(err, CoseSign1Error::SignatureEmpty),
            "got: {err:?}"
        );
    }

    #[test]
    fn accepts_no_tag() {
        let cose = Value::Array(vec![
            Value::Bytes(vec![]),
            Value::Map(vec![]),
            Value::Null,
            Value::Bytes(vec![0xFF; 32]),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();

        super::validate_corim_envelope(&buf).unwrap();
    }
}
