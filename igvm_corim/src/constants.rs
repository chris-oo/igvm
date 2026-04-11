// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Constants used by the IGVM launch endorsement CoRIM profile.
//!
//! CBOR tag numbers are from the IANA "CBOR Tags" registry as defined in
//! draft-ietf-rats-corim-10 §12.2. CDDL map key numbers are from the
//! corresponding IANA registries (§12.3–§12.9). Hash algorithm identifiers
//! are from the IANA "Named Information Hash Algorithm Registry" (RFC 6920).

// CBOR Semantic Tags — draft-ietf-rats-corim-10 §12.2
// https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html#section-12.2

/// `#6.501(unsigned-corim-map)` — Tagged unsigned CoRIM map (§4.1).
pub const TAG_CORIM: u64 = 501;

/// `#6.506(bytes .cbor concise-mid-tag)` — Tagged CoMID (§4.1.2).
pub const TAG_COMID: u64 = 506;

/// `#6.552(svn)` — Tagged exact SVN value (§5.1.4.5.4).
pub const TAG_SVN: u64 = 552;

/// `#6.553(min-svn)` — Tagged minimum SVN value (§5.1.4.5.4).
pub const TAG_MIN_SVN: u64 = 553;

// corim-map keys — draft-ietf-rats-corim-10 §12.3
// https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html#section-12.3

/// `corim-map` key 0: CoRIM identifier.
pub const CORIM_ID: i64 = 0;
/// `corim-map` key 1: Array of concise tags (CoMID, CoSWID, CoTL).
pub const CORIM_TAGS: i64 = 1;
/// `corim-map` key 3: Profile identifier.
pub const CORIM_PROFILE: i64 = 3;

// concise-mid-tag (CoMID) keys — draft-ietf-rats-corim-10 §12.6
// https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html#section-12.6

/// `concise-mid-tag` key 1: Tag identity.
pub const COMID_TAG_IDENTITY: i64 = 1;
/// `concise-mid-tag` key 4: Triples map.
pub const COMID_TRIPLES: i64 = 4;

// tag-identity-map keys — draft-ietf-rats-corim-10 §5.1.1

/// `tag-identity-map` key 0: Tag identifier (text or UUID).
pub const TAG_IDENTITY_TAG_ID: i64 = 0;

// triples-map keys — draft-ietf-rats-corim-10 §12.8
// https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html#section-12.8

/// `triples-map` key 0: Reference Values triples (§5.1.5).
pub const TRIPLES_REFERENCE: i64 = 0;
/// `triples-map` key 8: Conditional endorsement series triples (§5.1.8).
pub const TRIPLES_COND_ENDORSEMENT_SERIES: i64 = 8;

// environment-map keys — draft-ietf-rats-corim-10 §5.1.4.1

/// `environment-map` key 0: Class (§5.1.4.2).
pub const ENV_CLASS: i64 = 0;

// class-map keys — draft-ietf-rats-corim-10 §5.1.4.2

/// `class-map` key 1: Vendor name.
pub const CLASS_VENDOR: i64 = 1;
/// `class-map` key 2: Model name.
pub const CLASS_MODEL: i64 = 2;

// measurement-map keys — draft-ietf-rats-corim-10 §5.1.4.5

/// `measurement-map` key 0: Measurement key (`mkey`).
pub const MEAS_KEY: i64 = 0;
/// `measurement-map` key 1: Measurement values (`mval`).
pub const MEAS_VAL: i64 = 1;

// measurement-values-map keys — draft-ietf-rats-corim-10 §12.9
// https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html#section-12.9

/// `measurement-values-map` key 1: Security version number (§5.1.4.5.4).
pub const MVAL_SVN: i64 = 1;
/// `measurement-values-map` key 2: Digests (§7.7).
pub const MVAL_DIGESTS: i64 = 2;

// Named Information Hash Algorithm IDs — RFC 6920
// https://www.iana.org/assignments/named-information/named-information.xhtml

/// SHA-256 — Named Information hash algorithm ID (RFC 6920).
pub const NI_SHA256: i64 = 1;
/// SHA-384 — Named Information hash algorithm ID (RFC 6920).
pub const NI_SHA384: i64 = 7;

// UUIDv5 namespace for tag-id derivation

/// Fixed namespace UUID for deterministic CoMID tag-id derivation.
///
/// `tag-id = UUIDv5(TAG_ID_NAMESPACE, "{vendor}/{model}")`
pub const TAG_ID_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    0x85, 0xf3, 0xf1, 0xc2, 0x22, 0xa8, 0x44, 0x1e, 0xa1, 0xb9, 0xbc, 0xcf, 0xb6, 0x3e, 0xd5, 0xf7,
]);
