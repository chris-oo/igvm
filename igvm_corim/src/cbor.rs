// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CBOR helper functions shared by the builder and validator.
//!
//! Provides ergonomic wrappers around [`ciborium::Value`] for constructing
//! and inspecting CBOR maps with integer keys.

use ciborium::Value;

use crate::Error;
use crate::ValidationError;

// Encoding helpers

/// Create a CBOR integer value for use as a map key.
pub(crate) fn int_key(key: i64) -> Value {
    Value::Integer(key.into())
}

/// Build a CBOR map from an iterator of `(key, value)` pairs.
///
/// In debug builds, asserts that integer keys are in strictly ascending order
/// to ensure CBOR Core Deterministic Encoding (RFC 8949 §4.2.1).
pub(crate) fn cbor_map(entries: impl IntoIterator<Item = (Value, Value)>) -> Value {
    let entries: Vec<(Value, Value)> = entries.into_iter().collect();

    debug_assert!(
        {
            let int_keys: Vec<i128> = entries
                .iter()
                .filter_map(|(k, _)| match k {
                    Value::Integer(i) => Some((*i).into()),
                    _ => None,
                })
                .collect();
            int_keys.windows(2).all(|w| w[0] < w[1])
        },
        "CBOR map integer keys must be in strictly ascending order"
    );

    Value::Map(entries)
}

/// Encode a `Value` to CBOR bytes.
pub(crate) fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| Error::Encode(Box::new(e)))?;
    Ok(buf)
}

// Decoding helpers

/// Require a Value to be a Map, returning the entries.
pub(crate) fn val_as_map<'a>(
    v: &'a Value,
    context: &'static str,
) -> Result<&'a Vec<(Value, Value)>, ValidationError> {
    match v {
        Value::Map(entries) => Ok(entries),
        _ => Err(ValidationError::UnexpectedType {
            expected: "map",
            context,
        }),
    }
}

/// Look up integer key in a CBOR map entries list.
pub(crate) fn map_get_key(entries: &[(Value, Value)], key: i64) -> Option<&Value> {
    for (k, v) in entries {
        if let Value::Integer(i) = k {
            if i128::from(*i) == key as i128 {
                return Some(v);
            }
        }
    }
    None
}

/// Require an integer key in a CBOR map entries list.
pub(crate) fn map_require_key<'a>(
    entries: &'a [(Value, Value)],
    key: i64,
    context: &'static str,
) -> Result<&'a Value, ValidationError> {
    map_get_key(entries, key).ok_or(ValidationError::MissingKey { key, context })
}

/// Require a Value to be Text.
pub(crate) fn val_as_text<'a>(
    v: &'a Value,
    context: &'static str,
) -> Result<&'a str, ValidationError> {
    match v {
        Value::Text(t) => Ok(t.as_str()),
        _ => Err(ValidationError::UnexpectedType {
            expected: "text",
            context,
        }),
    }
}

/// Require a Value to be Array.
pub(crate) fn val_as_array<'a>(
    v: &'a Value,
    context: &'static str,
) -> Result<&'a Vec<Value>, ValidationError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(ValidationError::UnexpectedType {
            expected: "array",
            context,
        }),
    }
}

/// Require a Value to be Bytes.
pub(crate) fn val_as_bytes<'a>(
    v: &'a Value,
    context: &'static str,
) -> Result<&'a [u8], ValidationError> {
    match v {
        Value::Bytes(b) => Ok(b.as_slice()),
        _ => Err(ValidationError::UnexpectedType {
            expected: "bytes",
            context,
        }),
    }
}

/// Extract a u64 from a Value::Integer.
pub(crate) fn val_as_u64(v: &Value, context: &'static str) -> Result<u64, ValidationError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            u64::try_from(n).map_err(|_| ValidationError::UnexpectedType {
                expected: "unsigned integer",
                context,
            })
        }
        _ => Err(ValidationError::UnexpectedType {
            expected: "integer",
            context,
        }),
    }
}

/// Extract an i64 from a Value::Integer.
pub(crate) fn val_as_i64(v: &Value, context: &'static str) -> Result<i64, ValidationError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            i64::try_from(n).map_err(|_| ValidationError::UnexpectedType {
                expected: "signed integer",
                context,
            })
        }
        _ => Err(ValidationError::UnexpectedType {
            expected: "integer",
            context,
        }),
    }
}
