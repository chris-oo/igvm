// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CoRIM launch-endorsement validation.
//!
//! Decodes a tag-501-wrapped CoRIM using the [`corim`] crate's
//! [`decode_and_validate`](corim::validate::decode_and_validate), then
//! enforces the IGVM launch endorsement profile constraints on the typed
//! [`CorimMap`](corim::types::corim::CorimMap) and
//! [`ComidTag`](corim::types::comid::ComidTag) structures.
//!
//! This validator enforces **strict profile conformance** per `profile.rs`:
//! - Profile URI is required and must match.
//! - Exactly one CoMID tag (tag 506).
//! - Both reference-triples and CES triples are required.
//! - Only exact SVN is accepted; minimum SVN is rejected.
//! - Tag-id must match UUIDv5 derivation from vendor/model.

use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::ProfileChoice;
use corim::types::measurement::SvnChoice;
use uuid::Uuid;

use super::profile::PROFILE_URI;
use super::{known_platforms, LaunchEndorsement, ValidationError, TAG_ID_NAMESPACE};

/// Validate and decode a CoRIM launch endorsement.
///
/// Enforces strict profile conformance:
///
/// - Outer wrapper is `#6.501(corim-map)` (checked by corim crate)
/// - Profile URI (key 3) is required and must match the IGVM launch
///   endorsement profile
/// - `tags` array (key 1) must contain exactly one `#6.506(comid-bytes)` entry
/// - CoMID has `tag-identity` (key 1) with `tag-id` (key 0)
/// - Tag-id must match UUIDv5 derivation from vendor/model
/// - CoMID has `triples` (key 4) with both `reference-triples` (key 0)
///   and `conditional-endorsement-series-triples` (key 8)
/// - Reference triple has a valid environment with vendor/model
/// - Reference triple has at least one measurement with digest
/// - CES triple contains an exact SVN value
/// - Vendor/model maps to a known platform
/// - Digest algorithm and length match the platform expectations
pub fn validate(bytes: &[u8]) -> Result<LaunchEndorsement, ValidationError> {
    // Phase 1: Structural CoRIM/CoMID validation (tag 501, non-empty triples, etc.)
    let (corim, comids) = corim::validate::decode_and_validate(bytes)?;

    // Require and validate profile URI
    match &corim.profile {
        Some(ProfileChoice::Uri(uri)) if uri == PROFILE_URI => {}
        Some(ProfileChoice::Uri(uri)) => {
            return Err(ValidationError::ProfileMismatch {
                expected: PROFILE_URI.to_string(),
                actual: uri.clone(),
            })
        }
        Some(ProfileChoice::Oid(_)) => {
            return Err(ValidationError::ProfileMismatch {
                expected: PROFILE_URI.to_string(),
                actual: "(OID)".to_string(),
            })
        }
        None => return Err(ValidationError::MissingProfile),
        _ => {
            return Err(ValidationError::ProfileMismatch {
                expected: PROFILE_URI.to_string(),
                actual: "(unknown profile type)".to_string(),
            })
        }
    }

    // Require exactly one CoMID
    if comids.len() > 1 {
        return Err(ValidationError::MultipleComids);
    }
    let comid = &comids[0]; // decode_and_validate guarantees >= 1

    // Extract tag-id as text
    let tag_id = match &comid.tag_identity.tag_id {
        TagIdChoice::Text(s) => s.clone(),
        TagIdChoice::Uuid(u) => {
            // Format UUID bytes as hyphenated lowercase
            let u = uuid::Uuid::from_bytes(*u);
            u.to_string()
        }
        _ => {
            return Err(ValidationError::Structure(
                "tag-id must be text or UUID".into(),
            ))
        }
    };

    // Extract reference-triples — required
    let triples = &comid.triples;
    let ref_triples = triples
        .reference_triples
        .as_ref()
        .ok_or(ValidationError::EmptyTriples)?;
    if ref_triples.is_empty() {
        return Err(ValidationError::EmptyTriples);
    }

    // Parse the first reference triple
    let first_ref = &ref_triples[0];
    let env = first_ref.environment();
    let class = env.class.as_ref().ok_or_else(|| {
        ValidationError::Structure("reference triple environment missing class".into())
    })?;
    let vendor = class.vendor.as_ref().ok_or_else(|| {
        ValidationError::Structure("class-map missing vendor".into())
    })?;
    let model = class.model.as_ref().ok_or_else(|| {
        ValidationError::Structure("class-map missing model".into())
    })?;

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
    let measurements = first_ref.measurements();
    if measurements.is_empty() {
        return Err(ValidationError::InvalidDigest(
            "no measurements in reference triple".into(),
        ));
    }
    let meas = &measurements[0];
    let mkey = match &meas.mkey {
        Some(MeasuredElement::Text(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => {
            return Err(ValidationError::Structure(
                "measurement missing mkey".into(),
            ))
        }
    };
    let digests = meas
        .mval
        .digests
        .as_ref()
        .ok_or_else(|| ValidationError::InvalidDigest("measurement missing digests".into()))?;
    if digests.is_empty() {
        return Err(ValidationError::InvalidDigest(
            "digests array is empty".into(),
        ));
    }
    let digest = &digests[0];
    let digest_alg = digest.alg();
    let digest_bytes = digest.value().to_vec();

    // Validate against known platforms
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

    if digest_bytes.len() != platform.digest_len {
        return Err(ValidationError::InvalidDigest(format!(
            "expected {} bytes, got {}",
            platform.digest_len,
            digest_bytes.len()
        )));
    }

    // Require CES triples and extract SVN
    let ces = triples
        .conditional_endorsement_series
        .as_ref()
        .ok_or(ValidationError::MissingCes)?;
    if ces.is_empty() {
        return Err(ValidationError::MissingCes);
    }
    let ces_triple = &ces[0];
    let series = ces_triple.series();
    if series.is_empty() {
        return Err(ValidationError::InvalidSvn(
            "CES series array is empty".into(),
        ));
    }
    let addition = series[0].addition();
    if addition.is_empty() {
        return Err(ValidationError::InvalidSvn(
            "addition array is empty".into(),
        ));
    }
    let svn = match &addition[0].mval.svn {
        Some(SvnChoice::ExactValue(n)) => *n,
        Some(SvnChoice::MinValue(_)) => {
            return Err(ValidationError::InvalidSvn(
                "minimum SVN is not supported; only exact SVN is accepted".into(),
            ))
        }
        _ => {
            return Err(ValidationError::InvalidSvn(
                "SVN field missing in CES addition".into(),
            ))
        }
    };

    Ok(LaunchEndorsement {
        vendor: vendor.clone(),
        model: model.clone(),
        tag_id,
        mkey,
        digest_alg,
        digest: digest_bytes,
        svn,
    })
}

#[cfg(test)]
mod tests {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::types::common::{MeasuredElement, TagIdChoice};
    use corim::types::corim::{CorimId, ProfileChoice};
    use corim::types::environment::{ClassMap, EnvironmentMap};
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};
    use corim::types::triples::{
        CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord,
        ReferenceTriple,
    };
    use igvm_defs::IgvmPlatformType;
    use uuid::Uuid;

    use crate::corim::launch_endorsement;
    use crate::corim::launch_endorsement::profile::PROFILE_URI;
    use crate::corim::launch_endorsement::TAG_ID_NAMESPACE;

    /// Build a CoRIM with custom parameters for negative testing.
    fn build_custom_corim(
        vendor: &str,
        model: &str,
        mkey: &str,
        digest_alg: i64,
        digest: &[u8],
        svn: u64,
        profile: Option<&str>,
    ) -> Vec<u8> {
        let env = EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some(vendor.into()),
                model: Some(model.into()),
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        };
        let tag_id =
            Uuid::new_v5(&TAG_ID_NAMESPACE, format!("{vendor}/{model}").as_bytes()).to_string();
        let ref_meas = MeasurementMap {
            mkey: Some(MeasuredElement::Text(mkey.into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(digest_alg, digest.to_vec())]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };
        let ces_sel = MeasurementMap {
            mkey: Some(MeasuredElement::Text(mkey.into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(digest_alg, digest.to_vec())]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };
        let ces_add = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(svn)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };
        let ces = ConditionalEndorsementSeriesTriple::new(
            CesCondition {
                environment: env.clone(),
                claims_list: Vec::new(),
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord::new(vec![ces_sel], vec![ces_add])],
        );
        let comid = ComidBuilder::new(TagIdChoice::Text(tag_id))
            .add_reference_triple(ReferenceTriple::new(env, vec![ref_meas]))
            .add_conditional_endorsement_series(ces)
            .build()
            .unwrap();

        let corim_id = format!("{vendor}/{model}/launch-endorsement");
        let mut builder = CorimBuilder::new(CorimId::Text(corim_id));
        if let Some(p) = profile {
            builder = builder.set_profile(ProfileChoice::Uri(p.into()));
        }
        builder
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap()
    }

    #[test]
    fn snp_round_trip() {
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
    fn tdx_round_trip() {
        let digest = vec![0xBB; 48];
        let bytes = launch_endorsement::generate(IgvmPlatformType::TDX, &digest, 3).unwrap();

        let e = launch_endorsement::validate(&bytes).unwrap();
        assert_eq!(e.vendor, "Intel");
        assert_eq!(e.model, "TDX");
        assert_eq!(e.mkey, "MRTD");
        assert_eq!(e.svn, 3);
    }

    #[test]
    fn vbs_round_trip() {
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
    fn rejects_garbage() {
        let err = launch_endorsement::validate(&[0xFF, 0x00]).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("decode") ||
                err.to_string().to_lowercase().contains("valid"));
    }

    #[test]
    fn rejects_wrong_profile() {
        let bytes = build_custom_corim(
            "AMD",
            "SEV-SNP",
            "MEASUREMENT",
            7,
            &[0xAA; 48],
            1,
            Some("tag:evil.com,2025:wrong"),
        );
        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(err.to_string().contains("profile mismatch"));
    }

    #[test]
    fn rejects_missing_profile() {
        let bytes =
            build_custom_corim("AMD", "SEV-SNP", "MEASUREMENT", 7, &[0xAA; 48], 1, None);
        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(err.to_string().contains("missing required profile"));
    }

    #[test]
    fn rejects_wrong_digest_length() {
        // Build CoRIM with AMD/SEV-SNP but only 32-byte digest (should be 48)
        let bytes = build_custom_corim(
            "AMD",
            "SEV-SNP",
            "MEASUREMENT",
            7,
            &[0xAA; 32],
            1,
            Some(PROFILE_URI),
        );
        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(err.to_string().contains("expected 48 bytes, got 32"));
    }

    #[test]
    fn rejects_wrong_digest_alg() {
        // Build CoRIM with AMD/SEV-SNP but SHA-256 alg (should be SHA-384 = 7)
        let bytes = build_custom_corim(
            "AMD",
            "SEV-SNP",
            "MEASUREMENT",
            1, // SHA-256 instead of SHA-384
            &[0xAA; 48],
            1,
            Some(PROFILE_URI),
        );
        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(err.to_string().contains("expected algorithm 7, got 1"));
    }

    #[test]
    fn rejects_unknown_platform() {
        let bytes = build_custom_corim(
            "Acme",
            "FakeCPU",
            "MEASUREMENT",
            7,
            &[0xAA; 48],
            1,
            Some(PROFILE_URI),
        );
        let err = launch_endorsement::validate(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("unknown platform"),
            "got: {err}"
        );
    }
}

