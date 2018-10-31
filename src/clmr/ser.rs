use std::io::{self, Write};

use serde::Serialize;
use ssb_legacy_msg_data::cbor;
use varu64;

use super::super::{Message, Content};

/// Everything that can go wrong when encoding a `Message` to clmr.
#[derive(Debug)]
pub enum EncodeClmrError {
    /// An io error occured on the underlying writer.
    Io(io::Error),
    /// Serializing the plaintext content errored.
    Content(cbor::EncodeCborError),
}

impl From<io::Error> for EncodeClmrError {
    fn from(e: io::Error) -> EncodeClmrError {
        EncodeClmrError::Io(e)
    }
}

impl From<cbor::EncodeCborError> for EncodeClmrError {
    fn from(e: cbor::EncodeCborError) -> EncodeClmrError {
        EncodeClmrError::Content(e)
    }
}

/// Serialize a `Message` into a writer, using the
/// [clmr](https://spec.scuttlebutt.nz/messages.html#compact-legacy-message-representation).
pub fn to_clmr<W, T>(msg: &Message<T>, w: &mut W) -> Result<(), EncodeClmrError>
    where W: Write,
          T: Serialize
{
    let mut flags = 0u8;
    if msg.previous.is_some() {
        flags |= 0b0000_0100;
    }
    if msg.swapped {
        flags |= 0b0000_0010;
    }
    if msg.is_encrypted() {
        flags |= 0b0000_0001;
    }

    w.write_all(&[flags])?;

    msg.author.to_compact(&mut *w)?;

    varu64::encode_write(msg.sequence, &mut *w)?;

    if let Some(ref mh) = msg.previous {
        let _ = mh.to_compact(&mut *w)?;
    }

    match msg.content {
        Content::Encrypted(ref mb) => mb.to_compact(w)?,
        Content::Plain(ref t) => cbor::to_writer(&mut *w, t)?,
    }

    msg.signature.to_compact(w)?;

    Ok(())
}

/// Serialize a `Message` into an owned byte vector, using the
/// [clmr](https://spec.scuttlebutt.nz/messages.html#compact-legacy-message-representation).
pub fn to_clmr_vec<T: Serialize>(msg: &Message<T>) -> Result<Vec<u8>, EncodeClmrError> {
    let mut out = Vec::with_capacity(256);
    to_clmr(msg, &mut out)?;
    Ok(out)
}

/// Serialize a `Message` into an owned string, using the
/// [clmr](https://spec.scuttlebutt.nz/messages.html#compact-legacy-message-representation).
pub fn to_clmr_string<T: Serialize>(msg: &Message<T>) -> Result<String, EncodeClmrError> {
    Ok(unsafe { String::from_utf8_unchecked(to_clmr_vec(msg)?) })
}
