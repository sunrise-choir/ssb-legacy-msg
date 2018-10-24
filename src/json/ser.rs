use std::io::{self, Write};

use serde::Serialize;
use ssb_legacy_msg_data::json;

use super::super::{Message, Content};

/// Everything that can go wrong when encoding a `Message` to legacy json.
#[derive(Debug)]
pub enum EncodeJsonError {
    /// An io error occured on the underlying writer.
    Io(io::Error),
    /// Serializing the plaintext content errored.
    Content(json::EncodeJsonError),
}

impl From<io::Error> for EncodeJsonError {
    fn from(e: io::Error) -> EncodeJsonError {
        EncodeJsonError::Io(e)
    }
}

impl From<json::EncodeJsonError> for EncodeJsonError {
    fn from(e: json::EncodeJsonError) -> EncodeJsonError {
        EncodeJsonError::Content(e)
    }
}

/// Serialize a `Message` into a writer, using the
/// [legacy encoding](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
///
/// If `compact`, this omits all whitespace. Else, this produces the signing encoding.
pub fn to_legacy<W, T>(msg: &Message<T>, w: &mut W, compact: bool) -> Result<(), EncodeJsonError>
    where W: Write,
          T: Serialize
{
    w.write_all(b"{")?;
    ws(w, compact)?;

    write_key("previous", w, compact)?;
    match msg.previous {
        None => w.write_all(b"null")?,
        Some(ref mh) => mh.to_legacy(w)?,
    }
    end_entry(w, compact)?;

    if msg.swapped {
        write_key("sequence", w, compact)?;
        json::to_writer(w, &msg.sequence, compact)?;

        entry("author", w, compact)?;
        msg.author.to_legacy(w)?;
    } else {
        write_key("author", w, compact)?;
        msg.author.to_legacy(w)?;

        entry("sequence", w, compact)?;
        json::to_writer(w, &msg.sequence, compact)?;
    }

    entry("timestamp", w, compact)?;
    json::to_writer(w, &msg.timestamp, compact)?;

    entry("hash", w, compact)?;
    w.write_all(b"\"sha256\"")?;

    entry("content", w, compact)?;
    match msg.content {
        Content::Encrypted(ref mb) => mb.to_legacy(w)?,
        Content::Plain(ref t) => json::to_writer(w, t, compact)?,
    }

    entry("signature", w, compact)?;
    msg.author.sig_to_legacy(&msg.signature, w)?;

    w.write_all(b"\n}")?;
    Ok(())
}

/// Serialize a `Message` into an owned byte vector, using the
/// [legacy encoding](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
///
/// If `compact`, this omits all whitespace. Else, this produces the signing encoding.
pub fn to_legacy_vec<T: Serialize>(msg: &Message<T>, compact: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    to_legacy(msg, &mut out, compact).unwrap();
    out
}

/// Serialize a `Message` into an owned string, using the
/// [legacy encoding](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
///
/// If `compact`, this omits all whitespace. Else, this produces the signing encoding.
pub fn to_legacy_string<T: Serialize>(msg: &Message<T>, compact: bool) -> String {
    unsafe { String::from_utf8_unchecked(to_legacy_vec(msg, compact)) }
}

fn ws<W: Write>(w: &mut W, compact: bool) -> Result<(), io::Error> {
    if !compact {
        w.write_all(b"\n  ")?;
    }
    Ok(())
}

fn write_key<W: Write>(key: &str, w: &mut W, compact: bool) -> Result<(), io::Error> {
    w.write_all(b"\"")?;
    w.write_all(key.as_bytes())?;
    w.write_all(b"\":")?;
    if !compact {
        w.write_all(b" ")?;
    }
    Ok(())
}

fn end_entry<W: Write>(w: &mut W, compact: bool) -> Result<(), io::Error> {
    w.write_all(b",")?;
    ws(w, compact)
}

fn entry<W: Write>(key: &str, w: &mut W, compact: bool) -> Result<(), io::Error> {
    end_entry(w, compact)?;
    write_key(key, w, compact)
}
