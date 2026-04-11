// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CoRIM launch-endorsement validation.
//!
//! Decodes a tag-501-wrapped CoRIM from CBOR bytes, verifies the structure,
//! and extracts the platform identity, launch measurement digest, and SVN.
//!
//! This validator enforces **strict profile conformance** per `profile.rs`:
//! - Profile URI is required and must match.
//! - Exactly one CoMID tag (tag 506).
//! - Both reference-triples and CES triples are required.
//! - Only exact SVN (`#6.552`) is accepted; plain uint and min-SVN are rejected.
//! - Tag-id must match UUIDv5 derivation from vendor/model.

use ciborium::Value;

use crate::cbor::map_require_key;
use crate::cbor::val_as_array;
use crate::cbor::val_as_bytes;
use crate::cbor::val_as_i64;
use crate::cbor::val_as_map;
use crate::cbor::val_as_text;
use crate::cbor::val_as_u64;
use crate::LaunchEndorsement;
use crate::ValidationError;

// Field extractors (private)

/// Extract (vendor, model) from an environment-map → class-map.
fn extract_vendor_model(env: &Value) -> Result<(String, String), ValidationError> {
    use crate::constants::CLASS_MODEL;
    use crate::constants::CLASS_VENDOR;
    use crate::constants::ENV_CLASS;

    let env_entries = val_as_map(env, "environment-map")?;
    let class = map_require_key(env_entries, ENV_CLASS, "environment-map.class")?;
    let class_entries = val_as_map(class, "class-map")?;
    let vendor = val_as_text(
        map_require_key(class_entries, CLASS_VENDOR, "class-map.vendor")?,
        "class-map.vendor",
    )?
    .to_string();
    let model = val_as_text(
        map_require_key(class_entries, CLASS_MODEL, "class-map.model")?,
        "class-map.model",
    )?
    .to_string();
    Ok((vendor, model))
}

/// Extract (mkey, digest_alg, digest_bytes) from a measurement-map.
fn extract_measurement_digest(meas: &Value) -> Result<(String, i64, Vec<u8>), ValidationError> {
    use crate::constants::MEAS_KEY;
    use crate::constants::MEAS_VAL;
    use crate::constants::MVAL_DIGESTS;

    let meas_entries = val_as_map(meas, "measurement-map")?;
    let mkey_val = map_require_key(meas_entries, MEAS_KEY, "measurement-map.mkey")?;
    let mkey = val_as_text(mkey_val, "measurement-map.mkey")?.to_string();

    let mval = map_require_key(meas_entries, MEAS_VAL, "measurement-map.mval")?;
    let mval_entries = val_as_map(mval, "measurement-values-map")?;
    let digests = val_as_array(
        map_require_key(mval_entries, MVAL_DIGESTS, "measurement-values-map.digests")?,
        "digests",
    )?;

    if digests.is_empty() {
        return Err(ValidationError::InvalidDigest(
            "digests array is empty".into(),
        ));
    }

    let digest_pair = val_as_array(&digests[0], "digest[0]")?;
    if digest_pair.len() != 2 {
        return Err(ValidationError::InvalidDigest(
            "digest must be [alg, bytes]".into(),
        ));
    }

    let alg = val_as_i64(&digest_pair[0], "digest.alg")?;
    let hash = val_as_bytes(&digest_pair[1], "digest.value")?.to_vec();

    Ok((mkey, alg, hash))
}

/// Extract SVN from a CES triple's first series entry's addition.
///
/// Strict mode: only `#6.552(uint)` is accepted. Plain uint and `#6.553`
/// are rejected per the profile.
fn extract_ces_svn(ces_triple: &Value) -> Result<u64, ValidationError> {
    use crate::constants::MEAS_VAL;
    use crate::constants::MVAL_SVN;
    use crate::constants::TAG_MIN_SVN;
    use crate::constants::TAG_SVN;

    let top = val_as_array(ces_triple, "ces-triple")?;
    if top.len() < 2 {
        return Err(ValidationError::InvalidSvn(
            "CES triple missing series array".into(),
        ));
    }

    let series = val_as_array(&top[1], "ces-triple.series")?;
    if series.is_empty() {
        return Err(ValidationError::InvalidSvn(
            "CES series array is empty".into(),
        ));
    }

    let series_entry = val_as_array(&series[0], "series-entry")?;
    if series_entry.len() < 2 {
        return Err(ValidationError::InvalidSvn(
            "series entry missing addition".into(),
        ));
    }

    let additions = val_as_array(&series_entry[1], "series-entry.addition")?;
    if additions.is_empty() {
        return Err(ValidationError::InvalidSvn(
            "addition array is empty".into(),
        ));
    }

    // addition[0] is a measurement-map; mval → svn
    let addition_entries = val_as_map(&additions[0], "addition measurement-map")?;
    let addition_mval = map_require_key(addition_entries, MEAS_VAL, "addition.mval")?;
    let mval_entries = val_as_map(addition_mval, "addition measurement-values-map")?;
    let svn_val = map_require_key(mval_entries, MVAL_SVN, "addition.mval.svn")?;

    // Strict: only #6.552(uint) is accepted per profile.
    match svn_val {
        Value::Tag(TAG_SVN, inner) => val_as_u64(inner, "svn.value"),
        Value::Tag(TAG_MIN_SVN, _) => Err(ValidationError::InvalidSvn(
            "minimum SVN (#6.553) is not supported; only exact SVN (#6.552) is accepted".into(),
        )),
        _ => Err(ValidationError::InvalidSvn(
            "SVN must be tagged with #6.552 per profile".into(),
        )),
    }
}

// Public validation entry point

/// Validate and decode a CoRIM launch endorsement.
///
/// Enforces strict profile conformance:
///
/// - Outer wrapper is `#6.501(corim-map)`
/// - Profile URI (key 3) is required and must match the IGVM launch
///   endorsement profile
/// - `tags` array (key 1) must contain exactly one `#6.506(comid-bytes)` entry
/// - CoMID has `tag-identity` (key 1) with `tag-id` (key 0)
/// - Tag-id must match UUIDv5 derivation from vendor/model
/// - CoMID has `triples` (key 4) with both `reference-triples` (key 0)
///   and `conditional-endorsement-series-triples` (key 8)
/// - Reference triple has a valid environment with vendor/model
/// - Reference triple has at least one measurement with digest
/// - CES triple contains an SVN tagged with `#6.552` (exact only)
/// - Vendor/model maps to a known platform
/// - Digest algorithm and length match the platform expectations
pub fn validate_launch_endorsement(bytes: &[u8]) -> Result<LaunchEndorsement, ValidationError> {
    use crate::constants::COMID_TAG_IDENTITY;
    use crate::constants::COMID_TRIPLES;
    use crate::constants::CORIM_PROFILE;
    use crate::constants::CORIM_TAGS;
    use crate::constants::TAG_COMID;
    use crate::constants::TAG_CORIM;
    use crate::constants::TAG_IDENTITY_TAG_ID;
    use crate::constants::TAG_ID_NAMESPACE;
    use crate::constants::TRIPLES_COND_ENDORSEMENT_SERIES;
    use crate::constants::TRIPLES_REFERENCE;
    use crate::known_platforms;
    use crate::profile::PROFILE_URI;
    use uuid::Uuid;

    // Decode and unwrap tag 501
    let val: Value =
        ciborium::from_reader(bytes).map_err(|e| ValidationError::Decode(Box::new(e)))?;
    let corim_map = match val {
        Value::Tag(TAG_CORIM, inner) => *inner,
        _ => {
            return Err(ValidationError::MissingTag {
                expected: TAG_CORIM,
            })
        }
    };
    let corim_entries = val_as_map(&corim_map, "corim-map")?;

    // Require and validate profile URI
    let profile_val = map_require_key(corim_entries, CORIM_PROFILE, "corim-map.profile")
        .map_err(|_| ValidationError::MissingProfile)?;
    let profile_str = val_as_text(profile_val, "corim-map.profile")?;
    if profile_str != PROFILE_URI {
        return Err(ValidationError::ProfileMismatch {
            expected: PROFILE_URI.to_string(),
            actual: profile_str.to_string(),
        });
    }

    // Extract tags array and require exactly one CoMID
    let tags = val_as_array(
        map_require_key(corim_entries, CORIM_TAGS, "corim-map.tags")?,
        "corim-map.tags",
    )?;

    let comid_entries: Vec<&[u8]> = tags
        .iter()
        .filter_map(|t| match t {
            Value::Tag(TAG_COMID, inner) => match inner.as_ref() {
                Value::Bytes(b) => Some(b.as_slice()),
                _ => None,
            },
            _ => None,
        })
        .collect();

    if comid_entries.is_empty() {
        return Err(ValidationError::NoComid);
    }
    if comid_entries.len() > 1 {
        return Err(ValidationError::MultipleComids);
    }

    let comid: Value = ciborium::from_reader(comid_entries[0])
        .map_err(|e| ValidationError::Decode(Box::new(e)))?;
    let comid_entries_map = val_as_map(&comid, "concise-mid-tag")?;

    // Extract tag-identity → tag-id
    let tag_identity =
        map_require_key(comid_entries_map, COMID_TAG_IDENTITY, "comid.tag-identity")?;
    let tag_identity_entries = val_as_map(tag_identity, "tag-identity-map")?;
    let tag_id = val_as_text(
        map_require_key(
            tag_identity_entries,
            TAG_IDENTITY_TAG_ID,
            "tag-identity.tag-id",
        )?,
        "tag-identity.tag-id",
    )?
    .to_string();

    // Extract triples
    let triples = map_require_key(comid_entries_map, COMID_TRIPLES, "comid.triples")?;
    let triples_entries = val_as_map(triples, "triples-map")?;

    // Extract reference-triples — required
    let ref_triples = val_as_array(
        map_require_key(
            triples_entries,
            TRIPLES_REFERENCE,
            "triples.reference-triples",
        )?,
        "reference-triples",
    )?;
    if ref_triples.is_empty() {
        return Err(ValidationError::EmptyTriples);
    }

    // Parse the first reference triple: [environment, [measurements]]
    let first_ref = val_as_array(&ref_triples[0], "reference-triple[0]")?;
    if first_ref.len() < 2 {
        return Err(ValidationError::UnexpectedType {
            expected: "[env, [measurements]]",
            context: "reference-triple",
        });
    }

    // Extract vendor/model from environment
    let (vendor, model) = extract_vendor_model(&first_ref[0])?;

    // Verify tag-id matches UUIDv5 derivation (case-insensitive per RFC 9562)
    let expected_tag_id =
        Uuid::new_v5(&TAG_ID_NAMESPACE, format!("{vendor}/{model}").as_bytes()).to_string();
    if !tag_id.eq_ignore_ascii_case(&expected_tag_id) {
        return Err(ValidationError::TagIdMismatch {
            expected: expected_tag_id,
            actual: tag_id,
        });
    }

    // Extract digest from measurements[0]
    let measurements = val_as_array(&first_ref[1], "reference-triple.measurements")?;
    if measurements.is_empty() {
        return Err(ValidationError::InvalidDigest(
            "no measurements in reference triple".into(),
        ));
    }
    let (mkey, digest_alg, digest) = extract_measurement_digest(&measurements[0])?;

    // Validate against known platforms (before CES, so unknown
    // platforms are rejected with a clear error)
    let platform = known_platforms()
        .iter()
        .find(|p| p.vendor == vendor && p.model == model)
        .ok_or_else(|| ValidationError::UnknownPlatform {
            vendor: vendor.clone(),
            model: model.clone(),
        })?;

    if digest_alg != platform.digest_alg {
        return Err(ValidationError::InvalidDigest(format!(
            "expected algorithm {}, got {}",
            platform.digest_alg, digest_alg
        )));
    }

    if digest.len() != platform.digest_len {
        return Err(ValidationError::InvalidDigest(format!(
            "expected {} bytes, got {}",
            platform.digest_len,
            digest.len()
        )));
    }

    // Require CES triples and extract SVN
    let ces_val = map_require_key(
        triples_entries,
        TRIPLES_COND_ENDORSEMENT_SERIES,
        "triples.conditional-endorsement-series",
    )
    .map_err(|_| ValidationError::MissingCes)?;
    let ces_arr = val_as_array(ces_val, "ces-triples")?;
    if ces_arr.is_empty() {
        return Err(ValidationError::MissingCes);
    }
    let svn = extract_ces_svn(&ces_arr[0])?;

    Ok(LaunchEndorsement {
        vendor,
        model,
        tag_id,
        mkey,
        digest_alg,
        digest,
        svn,
    })
}
