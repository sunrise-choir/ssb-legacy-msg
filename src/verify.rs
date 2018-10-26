//! Ssb legacy message verification.

use serde::Serialize;

use ssb_multiformats::{
    multihash::Multihash,
    // multikey::Multisig,
};
use ssb_legacy_msg_data::{to_weird_encoding, legacy_length};

use super::{
    Message,
    json::{
        to_legacy_string,
        EncodeJsonError,
    },
};

fn check_sequence<T>(msg: &Message<T>, prev_seq: u64) -> bool {
    msg.sequence == prev_seq + 1
}

fn check_previous<T>(msg: &Message<T>, prev_hash: Multihash) -> bool {
    msg.previous.as_ref().map_or(true, |prev| *prev == prev_hash)
}

fn check_length(len: usize) -> bool {
    len < 16385
}

/// Returns the signing encoding of the message, its hash, and its length
fn compute_expensive_stuff<T>(msg: &Message<T>) -> Result<(Vec<u8>, Multihash, usize), EncodeJsonError> where T: Serialize {
    let signing_encoding = to_legacy_string(msg, false)?;
    let mut len = 0;
    for b in to_weird_encoding(&signing_encoding) {
        len += 1;
        unimplemented!()
    }

    unimplemented!()
    // Ok((signing_encoding.into_bytes(), TODO, len))
}

/// Check whether the given string is a valid `type` value of a content object.
fn check_type_value(s: &str) -> bool{
    let len = legacy_length(s);

    if len < 3 || len > 53 {
        false
    } else {
        true
    }
}

// fn verify_signature<T>
