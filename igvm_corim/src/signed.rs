// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Signed CoRIM (COSE_Sign1) validation.
//!
//! A signed CoRIM is a COSE_Sign1 structure (RFC 9052 §4.2, optionally
//! wrapped in CBOR Tag 18) whose payload is a `bstr` containing a
//! tag-501-wrapped CoRIM document.
//!
//! This module validates the COSE_Sign1 structural envelope and then
//! delegates to [`crate::validate_launch_endorsement`] for the inner
//! CoRIM payload.
//!
//! **Note:** Cryptographic signature verification is NOT performed.
//! This module only validates the CBOR/COSE structure and the CoRIM
//! payload semantics. Signature verification requires access to trust
//! anchors and is out of scope for this crate.

use ciborium::Value;

use crate::CoseSign1Error;
use crate::LaunchEndorsement;
use crate::ValidationError;

/// CBOR Tag(18) for COSE_Sign1 per RFC 9052 §4.2.
const TAG_COSE_SIGN1: u64 = 18;

/// Expected number of elements in a COSE_Sign1 array.
const COSE_SIGN1_ARRAY_LEN: usize = 4;

/// Validate a signed CoRIM (COSE_Sign1) and extract the launch endorsement
/// from its payload.
///
/// Accepts a **bundled** COSE_Sign1 where the payload is an embedded `bstr`
/// containing the tag-501-wrapped CoRIM document. For detached payloads
/// (nil), use [`crate::validate_launch_endorsement`] directly.
///
/// # Structural validation performed
///
/// 1. Optional CBOR Tag(18) wrapper
/// 2. 4-element CBOR array
/// 3. Element \[0\] is a bstr (protected headers)
/// 4. Element \[1\] is a map (unprotected headers)
/// 5. Element \[2\] is a bstr (embedded payload) — not nil
/// 6. Element \[3\] is a bstr (signature)
/// 7. The payload bytes are validated via [`crate::validate_launch_endorsement`]
///
/// # Cryptographic verification
///
/// **Not performed.** Signature verification against trust anchors requires
/// a crypto backend and is out of scope for this crate.
pub fn validate_signed_corim(data: &[u8]) -> Result<LaunchEndorsement, ValidationError> {
    let payload_bytes = extract_cose_sign1_payload(data)?;
    crate::validate_launch_endorsement(&payload_bytes)
}

/// Parse a COSE_Sign1 envelope and return the embedded payload bytes.
///
/// Returns [`CoseSign1Error`] for any structural issue with the envelope.
fn extract_cose_sign1_payload(data: &[u8]) -> Result<Vec<u8>, CoseSign1Error> {
    let val: Value =
        ciborium::from_reader(data).map_err(|e| CoseSign1Error::Decode(Box::new(e)))?;

    // Unwrap optional Tag(18)
    let inner = match val {
        Value::Tag(TAG_COSE_SIGN1, inner) => *inner,
        Value::Array(_) => val,
        _ => return Err(CoseSign1Error::NotCoseSign1),
    };

    // Must be a 4-element array
    let mut elements = match inner {
        Value::Array(arr) if arr.len() == COSE_SIGN1_ARRAY_LEN => arr,
        Value::Array(arr) => {
            return Err(CoseSign1Error::WrongArrayLength { actual: arr.len() })
        }
        _ => return Err(CoseSign1Error::NotCoseSign1),
    };

    // [0] protected — must be bstr
    if !matches!(&elements[0], Value::Bytes(_)) {
        return Err(CoseSign1Error::InvalidProtected);
    }

    // [1] unprotected — must be map
    if !matches!(&elements[1], Value::Map(_)) {
        return Err(CoseSign1Error::InvalidUnprotected);
    }

    // [3] signature — must be bstr (check before we move [2])
    if !matches!(&elements[3], Value::Bytes(_)) {
        return Err(CoseSign1Error::InvalidSignature);
    }

    // [2] payload — must be embedded bstr, not nil
    match std::mem::replace(&mut elements[2], Value::Null) {
        Value::Bytes(b) => Ok(b),
        Value::Null => Err(CoseSign1Error::DetachedPayload),
        _ => Err(CoseSign1Error::InvalidPayload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_launch_endorsement;
    use igvm_defs::IgvmPlatformType;

    /// Build a COSE_Sign1 with an embedded payload using ciborium.
    fn wrap_in_cose_sign1(payload: &[u8]) -> Vec<u8> {
        let cose = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![]),        // empty protected headers
                Value::Map(vec![]),          // empty unprotected headers
                Value::Bytes(payload.into()), // embedded payload
                Value::Bytes(vec![0xDE; 32]), // fake 32-byte signature
            ])),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        buf
    }

    #[test]
    fn signed_corim_round_trip() {
        let digest = vec![0xAA; 48];
        let corim = generate_launch_endorsement(IgvmPlatformType::SEV_SNP, &digest, 5).unwrap();
        let signed = wrap_in_cose_sign1(&corim);

        let e = validate_signed_corim(&signed).unwrap();
        assert_eq!(e.vendor, "AMD");
        assert_eq!(e.model, "SEV-SNP");
        assert_eq!(e.svn, 5);
        assert_eq!(e.digest, digest);
    }

    #[test]
    fn signed_corim_tdx() {
        let digest = vec![0xBB; 48];
        let corim = generate_launch_endorsement(IgvmPlatformType::TDX, &digest, 3).unwrap();
        let signed = wrap_in_cose_sign1(&corim);

        let e = validate_signed_corim(&signed).unwrap();
        assert_eq!(e.vendor, "Intel");
        assert_eq!(e.model, "TDX");
        assert_eq!(e.mkey, "MRTD");
        assert_eq!(e.svn, 3);
    }

    #[test]
    fn signed_corim_no_tag() {
        // COSE_Sign1 without Tag(18) — tag is optional per RFC 9052 §4.2
        let digest = vec![0xCC; 32];
        let corim =
            generate_launch_endorsement(IgvmPlatformType::VSM_ISOLATION, &digest, 1).unwrap();

        let cose = Value::Array(vec![
            Value::Bytes(vec![]),
            Value::Map(vec![]),
            Value::Bytes(corim),
            Value::Bytes(vec![0xFF; 32]),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();

        let e = validate_signed_corim(&buf).unwrap();
        assert_eq!(e.vendor, "Microsoft");
        assert_eq!(e.model, "VBS");
    }

    #[test]
    fn rejects_empty() {
        let err = validate_signed_corim(&[]).unwrap_err();
        assert!(
            matches!(err, ValidationError::CoseSign1(CoseSign1Error::Decode(_))),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_nil_payload() {
        let cose = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![]),
                Value::Map(vec![]),
                Value::Null, // detached
                Value::Bytes(vec![]),
            ])),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();

        let err = validate_signed_corim(&buf).unwrap_err();
        assert!(
            matches!(err, ValidationError::CoseSign1(CoseSign1Error::DetachedPayload)),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_array_length() {
        let cose = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![]),
                Value::Map(vec![]),
                Value::Null,
            ])), // only 3 elements
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();

        let err = validate_signed_corim(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                ValidationError::CoseSign1(CoseSign1Error::WrongArrayLength { actual: 3 })
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn rejects_invalid_inner_corim() {
        let garbage_payload = vec![0x01, 0x02, 0x03];
        let signed = wrap_in_cose_sign1(&garbage_payload);
        let err = validate_signed_corim(&signed).unwrap_err();
        // Should fail on inner CoRIM validation (not a CoseSign1 error)
        assert!(
            !matches!(err, ValidationError::CoseSign1(_)),
            "should be a CoRIM validation error, got: {err:?}"
        );
    }
}
