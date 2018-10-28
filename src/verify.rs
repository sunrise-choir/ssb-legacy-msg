//! Ssb legacy message verification.
use std::io::Write;

use serde::Serialize;
use crypto_hash::{Algorithm, Hasher};

use ssb_multiformats::{
    multihash::{Multihash, Target},
    multikey::{Multikey, Multisig},
};
use ssb_legacy_msg_data::to_weird_encoding;

use super::{
    Message,
    json::{
        to_legacy_string,
        EncodeJsonError,
    },
};

pub fn check_sequence<T>(msg: &Message<T>, prev_seq: u64) -> bool {
    msg.sequence == prev_seq + 1
}

pub fn check_previous<T>(msg: &Message<T>, prev_hash: &Option<Multihash>) -> bool {
    msg.previous == *prev_hash
}

pub fn check_length(len: usize) -> bool {
    len < 16385
}

pub fn check_signature(signing_encoding: &str, author: &Multikey, signature: &Multisig) -> bool {
    let raw = signing_encoding.as_bytes();
    let raw_len = raw.len();
    let mut enc_without_sig = Vec::with_capacity(raw_len - 120); // signature entry + whitespace take up 120 bytes
    enc_without_sig.extend_from_slice(&raw[..raw_len - 121]); // one more bytes for the closing brace
    enc_without_sig.extend_from_slice(b"\n}");
    author.is_signature_correct(&enc_without_sig, signature)
}

pub fn hash_and_length(signing_encoding: &str) -> (Multihash, usize) {
    let mut len = 0;

    let mut hasher = Hasher::new(Algorithm::SHA256);
    for b in to_weird_encoding(&signing_encoding) {
        len += 1;
        hasher.write_all(&[b]).unwrap();
    }

    let digest = hasher.finish();
    debug_assert!(digest.len() == 32);
    let mut data = [0; 32];
    for i in 0..32 {
        data[i] = digest[i];
    }

    (Multihash::from_sha256(data, Target::Message), len)
}
