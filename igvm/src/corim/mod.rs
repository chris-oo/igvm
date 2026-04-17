// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CoRIM (Concise Reference Integrity Manifest) support for IGVM.
//!
//! This module provides generation, validation, and COSE_Sign1 envelope
//! checking for CoRIM documents used in IGVM attestation.
//!
//! Built on top of the [`corim`](https://github.com/Azure/corim) crate
//! for typed CoRIM/CoMID structures, CBOR encoding, and structural
//! validation per draft-ietf-rats-corim-10.
//!
//! # Modules
//!
//! - [`launch_endorsement`] — The launch endorsement profile
//! - [`cose`] — COSE_Sign1 envelope validation for CoRIM payloads

pub mod cose;
pub mod launch_endorsement;

// Re-export launch_endorsement types for convenience.
pub use cose::CoseSign1Error;
pub use launch_endorsement::Error;
pub use launch_endorsement::LaunchEndorsement;
pub use launch_endorsement::ValidationError;
