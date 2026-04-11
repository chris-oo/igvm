// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CoRIM launch-endorsement builder.

use ciborium::Value;

use crate::cbor::cbor_map;
use crate::cbor::encode;
use crate::cbor::int_key;
use crate::Error;
use crate::PlatformInfo;

// CBOR structure builders

/// `class-map` = `{ 1: vendor, 2: model }`
fn build_class_map(info: &PlatformInfo) -> Value {
    use crate::constants::CLASS_MODEL;
    use crate::constants::CLASS_VENDOR;

    cbor_map([
        (int_key(CLASS_VENDOR), Value::Text(info.vendor.into())),
        (int_key(CLASS_MODEL), Value::Text(info.model.into())),
    ])
}

/// `environment-map` = `{ 0: class-map }`
fn build_environment(info: &PlatformInfo) -> Value {
    use crate::constants::ENV_CLASS;

    cbor_map([(int_key(ENV_CLASS), build_class_map(info))])
}

/// `eatmc.digest` = `[alg-id, hash-bytes]`
fn build_digest(alg: i64, hash: &[u8]) -> Value {
    Value::Array(vec![
        Value::Integer(alg.into()),
        Value::Bytes(hash.to_vec()),
    ])
}

/// `measurement-values-map` with only `digests` (key 2).
fn build_mval_digests(alg: i64, hash: &[u8]) -> Value {
    use crate::constants::MVAL_DIGESTS;

    cbor_map([(
        int_key(MVAL_DIGESTS),
        Value::Array(vec![build_digest(alg, hash)]),
    )])
}

/// `measurement-values-map` with only `svn` (key 1) as `#6.552(uint)`.
fn build_mval_svn(svn: u64) -> Value {
    use crate::constants::MVAL_SVN;
    use crate::constants::TAG_SVN;

    cbor_map([(
        int_key(MVAL_SVN),
        Value::Tag(TAG_SVN, Box::new(Value::Integer(svn.into()))),
    )])
}

/// `measurement-map` = `{ 0: mkey, 1: mval }`
fn build_measurement(mkey: &str, mval: Value) -> Value {
    use crate::constants::MEAS_KEY;
    use crate::constants::MEAS_VAL;

    cbor_map([
        (int_key(MEAS_KEY), Value::Text(mkey.into())),
        (int_key(MEAS_VAL), mval),
    ])
}

/// `measurement-map` with only `mval` (no mkey) — used in CES addition.
fn build_measurement_no_key(mval: Value) -> Value {
    use crate::constants::MEAS_VAL;

    cbor_map([(int_key(MEAS_VAL), mval)])
}

/// `reference-triple-record` = `[ environment-map, [+ measurement-map] ]`
fn build_reference_triple(info: &PlatformInfo, hash: &[u8]) -> Value {
    Value::Array(vec![
        build_environment(info),
        Value::Array(vec![build_measurement(
            info.mkey,
            build_mval_digests(info.digest_alg, hash),
        )]),
    ])
}

/// `conditional-endorsement-series-triple-record` = `[ condition, [+ series] ]`
fn build_ces_triple(info: &PlatformInfo, hash: &[u8], svn: u64) -> Value {
    let condition = Value::Array(vec![
        build_environment(info),
        Value::Array(vec![]), // empty claims-list
    ]);

    let selection_meas = build_measurement(info.mkey, build_mval_digests(info.digest_alg, hash));
    let addition_meas = build_measurement_no_key(build_mval_svn(svn));
    let series_entry = Value::Array(vec![
        Value::Array(vec![selection_meas]),
        Value::Array(vec![addition_meas]),
    ]);

    Value::Array(vec![condition, Value::Array(vec![series_entry])])
}

/// `tag-identity-map` = `{ 0: tag-id }`
fn build_tag_identity(vendor: &str, model: &str) -> Value {
    use crate::constants::TAG_IDENTITY_TAG_ID;
    use crate::constants::TAG_ID_NAMESPACE;
    use uuid::Uuid;

    let tag_uuid = Uuid::new_v5(&TAG_ID_NAMESPACE, format!("{vendor}/{model}").as_bytes());
    cbor_map([(
        int_key(TAG_IDENTITY_TAG_ID),
        Value::Text(tag_uuid.to_string()),
    )])
}

/// `triples-map` = `{ 0: [ref-triples], 8: [ces-triples] }`
fn build_triples(info: &PlatformInfo, hash: &[u8], svn: u64) -> Value {
    use crate::constants::TRIPLES_COND_ENDORSEMENT_SERIES;
    use crate::constants::TRIPLES_REFERENCE;

    cbor_map([
        (
            int_key(TRIPLES_REFERENCE),
            Value::Array(vec![build_reference_triple(info, hash)]),
        ),
        (
            int_key(TRIPLES_COND_ENDORSEMENT_SERIES),
            Value::Array(vec![build_ces_triple(info, hash, svn)]),
        ),
    ])
}

/// `concise-mid-tag` (CoMID) = `{ 1: tag-identity, 4: triples }`
pub(crate) fn build_comid(info: &PlatformInfo, hash: &[u8], svn: u64) -> Result<Vec<u8>, Error> {
    use crate::constants::COMID_TAG_IDENTITY;
    use crate::constants::COMID_TRIPLES;

    let comid = cbor_map([
        (
            int_key(COMID_TAG_IDENTITY),
            build_tag_identity(info.vendor, info.model),
        ),
        (int_key(COMID_TRIPLES), build_triples(info, hash, svn)),
    ]);
    encode(&comid)
}

/// `corim-map` = `{ 0: id, 1: [tags], 3: profile }`, wrapped in `#6.501(...)`.
pub(crate) fn build_corim(info: &PlatformInfo, comid_bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    use crate::constants::CORIM_ID;
    use crate::constants::CORIM_PROFILE;
    use crate::constants::CORIM_TAGS;
    use crate::constants::TAG_COMID;
    use crate::constants::TAG_CORIM;
    use crate::profile::PROFILE_URI;

    let corim_id = format!("{}/{}/launch-endorsement", info.vendor, info.model);

    let tagged_comid = Value::Tag(TAG_COMID, Box::new(Value::Bytes(comid_bytes)));

    let corim_map = cbor_map([
        (int_key(CORIM_ID), Value::Text(corim_id)),
        (int_key(CORIM_TAGS), Value::Array(vec![tagged_comid])),
        (int_key(CORIM_PROFILE), Value::Text(PROFILE_URI.into())),
    ]);

    let tagged_corim = Value::Tag(TAG_CORIM, Box::new(corim_map));
    encode(&tagged_corim)
}
