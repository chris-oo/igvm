// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CoRIM launch-endorsement builder.
//!
//! Uses the [`corim`] crate's typed builder API instead of manual CBOR
//! tree construction.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, ProfileChoice};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::triples::{
    CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord, ReferenceTriple,
};
use uuid::Uuid;

use super::profile::PROFILE_URI;
use super::{Error, PlatformInfo, TAG_ID_NAMESPACE};

/// Build a complete CoRIM launch endorsement as tag-501-wrapped CBOR bytes.
pub(crate) fn build_corim_bytes(
    info: &PlatformInfo,
    hash: &[u8],
    svn: u64,
) -> Result<Vec<u8>, Error> {
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some(info.vendor.into()),
            model: Some(info.model.into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };

    let tag_id =
        Uuid::new_v5(&TAG_ID_NAMESPACE, format!("{}/{}", info.vendor, info.model).as_bytes())
            .to_string();

    // Reference triple: digest measurement
    let ref_meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text(info.mkey.into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(info.digest_alg, hash.to_vec())]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };

    // CES triple: digest selection → SVN addition
    let ces_selection = MeasurementMap {
        mkey: Some(MeasuredElement::Text(info.mkey.into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(info.digest_alg, hash.to_vec())]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let ces_addition = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(svn)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let ces_triple = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env.clone(),
            claims_list: Vec::new(),
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![ces_selection],
            vec![ces_addition],
        )],
    );

    // Build CoMID
    let comid = ComidBuilder::new(TagIdChoice::Text(tag_id))
        .add_reference_triple(ReferenceTriple::new(env, vec![ref_meas]))
        .add_conditional_endorsement_series(ces_triple)
        .build()
        .map_err(|e| Error::Build(Box::new(e)))?;

    // Build CoRIM with profile URI
    let corim_id = format!("{}/{}/launch-endorsement", info.vendor, info.model);
    CorimBuilder::new(CorimId::Text(corim_id))
        .set_profile(ProfileChoice::Uri(PROFILE_URI.into()))
        .add_comid_tag(comid)
        .map_err(|e| Error::Build(Box::new(e)))?
        .build_bytes()
        .map_err(|e| Error::Build(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use igvm_defs::IgvmPlatformType;

    use crate::corim::launch_endorsement::generate;

    #[test]
    fn amd_sev_snp_round_trip() {
        let digest = vec![0xAA; 48];
        let bytes = generate(IgvmPlatformType::SEV_SNP, &digest, 1).unwrap();

        let (corim, comids) = corim::validate::decode_and_validate(&bytes).unwrap();
        assert_eq!(corim.id.to_string(), "AMD/SEV-SNP/launch-endorsement");
        assert_eq!(comids.len(), 1);

        let tag_id = comids[0].tag_identity.tag_id.to_string();
        assert_eq!(tag_id, "77e8061e-4634-5e53-a848-d1d09e996843");
    }

    #[test]
    fn intel_tdx_round_trip() {
        let digest = vec![0xBB; 48];
        let bytes = generate(IgvmPlatformType::TDX, &digest, 5).unwrap();

        let (corim, _) = corim::validate::decode_and_validate(&bytes).unwrap();
        assert_eq!(corim.id.to_string(), "Intel/TDX/launch-endorsement");
    }

    #[test]
    fn microsoft_vbs_round_trip() {
        let digest = vec![0xCC; 32];
        let bytes = generate(IgvmPlatformType::VSM_ISOLATION, &digest, 2).unwrap();

        let (corim, _) = corim::validate::decode_and_validate(&bytes).unwrap();
        assert_eq!(
            corim.id.to_string(),
            "Microsoft/VBS/launch-endorsement"
        );
    }

    #[test]
    fn wrong_digest_length_rejected() {
        let err = generate(IgvmPlatformType::SEV_SNP, &[0xAA; 32], 1).unwrap_err();
        assert!(err.to_string().contains("digest length mismatch"));
    }

    #[test]
    fn vbs_wrong_digest_length_rejected() {
        let err = generate(IgvmPlatformType::VSM_ISOLATION, &[0xCC; 48], 1).unwrap_err();
        assert!(err.to_string().contains("expected 32, got 48"));
    }

    #[test]
    fn output_has_tag_501() {
        let bytes = generate(IgvmPlatformType::SEV_SNP, &[0xAA; 48], 1).unwrap();
        // decode_and_validate checks for tag 501 internally
        corim::validate::decode_and_validate(&bytes).unwrap();
    }

    #[test]
    fn unsupported_platform_rejected() {
        use crate::corim::launch_endorsement::Error;

        let err = generate(IgvmPlatformType::NATIVE, &[0xAA; 48], 1).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedPlatform(IgvmPlatformType::NATIVE)),
            "got: {err:?}"
        );
    }
}
