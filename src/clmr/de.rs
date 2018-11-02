use serde::de::DeserializeOwned;

use ssb_legacy_msg_data::{
    LegacyF64,
};
use ssb_multiformats::{
    multihash::{Multihash, self},
    multikey::{Multikey, self, DecodeCompactSigError, Multisig},
    multibox::{Multibox, self}
};
use ssb_legacy_msg_data::cbor;
use varu64;

use super::super::{Message, Content};

/// Everything that can go wrong when decoding a `Message` from clmr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeClmrError {
    /// Needed more data but got EOF instead.
    UnexpectedEndOfInput,
    InvalidFlags,
    InvalidAuthor(multikey::DecodeCompactError),
    InvalidSequenceEnc(varu64::DecodeError),
    OutOfBoundsSequence(u64),
    InvalidTimestamp,
    InvalidPrevious(multihash::DecodeCompactError),
    PreviousNotMessage,
    InvalidPrivateContent(multibox::DecodeCompactError),
    InvalidSignature(DecodeCompactSigError),
    Content(cbor::DecodeCborError),
}

impl From<cbor::DecodeCborError> for DecodeClmrError {
    fn from(e: cbor::DecodeCborError) -> DecodeClmrError {
        DecodeClmrError::Content(e)
    }
}

impl From<multihash::DecodeCompactError> for DecodeClmrError {
    fn from(e: multihash::DecodeCompactError) -> DecodeClmrError {
        DecodeClmrError::InvalidPrevious(e)
    }
}

impl From<multikey::DecodeCompactError> for DecodeClmrError {
    fn from(e: multikey::DecodeCompactError) -> DecodeClmrError {
        DecodeClmrError::InvalidAuthor(e)
    }
}

impl From<multibox::DecodeCompactError> for DecodeClmrError {
    fn from(e: multibox::DecodeCompactError) -> DecodeClmrError {
        DecodeClmrError::InvalidPrivateContent(e)
    }
}

impl From<DecodeCompactSigError> for DecodeClmrError {
    fn from(e: DecodeCompactSigError) -> DecodeClmrError {
        DecodeClmrError::InvalidSignature(e)
    }
}

/// Try to parse data from the input, returning the remaining input when done.
pub fn from_clmr<'de, T>(input: &'de [u8]) -> Result<(Message<T>, &'de [u8]), DecodeClmrError>
    where T: DeserializeOwned
{
    let mut dec = ClmrDes::from_slice(input);

    let not_first: bool;
    let swapped: bool;
    let encrypted: bool;

    let flags = dec.next()?;
    not_first = flags & 0b0000_0100 != 0;
    swapped = flags & 0b0000_0010 != 0;
    encrypted = flags & 0b0000_0001 != 0;

    let author = dec.multikey()?;
    let sequence = dec.sequence()?;
    let timestamp = dec.timestamp()?;

    let previous: Option<Multihash>;
    if not_first {
        previous = Some(dec.message_hash()?);
    } else {
        previous = None;
    }

    let content: Content<T>;
    if encrypted {
        content = Content::Encrypted(dec.multibox()?);
    } else {
        content = Content::Plain(dec.cbor::<T>()?);
    }

    let signature = dec.signature(&author)?;

    Ok((Message {
            previous,
            author,
            sequence,
            timestamp,
            content,
            swapped,
            signature,
        },
        dec.input))
}

// A structure that deserializes cbor encoded compact messages.
struct ClmrDes<'de> {
    input: &'de [u8],
}

impl<'de> ClmrDes<'de> {
    // Creates a `ClmrDes` from a `&[u8]`.
    fn from_slice(input: &'de [u8]) -> Self {
        ClmrDes { input }
    }

    // Consumes the next byte and returns it.
    fn next(&mut self) -> Result<u8, DecodeClmrError> {
        match self.input.split_first() {
            Some((head, tail)) => {
                self.input = tail;
                Ok(*head)
            }
            None => Err(DecodeClmrError::UnexpectedEndOfInput),
        }
    }

    fn multikey(&mut self) -> Result<Multikey, DecodeClmrError> {
        let (mk, tail) = Multikey::from_compact(self.input)?;
        self.input = tail;
        Ok(mk)
    }

    fn sequence(&mut self) -> Result<u64, DecodeClmrError> {
        match varu64::decode(self.input) {
            Ok((seq, tail)) => {
                if seq > 9007199254740992 {
                    return Err(DecodeClmrError::OutOfBoundsSequence(seq));
                } else {
                    self.input = tail;
                    Ok(seq)
                }
            }

            Err((e, _)) => Err(DecodeClmrError::InvalidSequenceEnc(e)),
        }
    }

    fn timestamp(&mut self) -> Result<LegacyF64, DecodeClmrError> {
        let mut raw_bits: u64 = 0;
        for _ in 0..8 {
            raw_bits <<= 8;
            let byte = self.next()?;
            raw_bits |= byte as u64;
        }

        let parsed = f64::from_bits(raw_bits);

        match LegacyF64::from_f64(parsed) {
            Some(f) => Ok(f),
            None => Err(DecodeClmrError::InvalidTimestamp)
        }
    }

    fn message_hash(&mut self) -> Result<Multihash, DecodeClmrError> {
        let (mh, tail) = Multihash::from_compact(self.input)?;
        self.input = tail;
        if mh.0 != multihash::Target::Message {
            return Err(DecodeClmrError::PreviousNotMessage);
        }

        Ok(mh)
    }

    fn multibox(&mut self) -> Result<Multibox, DecodeClmrError> {
        let (mb, tail) = Multibox::from_compact(self.input)?;
        self.input = tail;
        Ok(mb)
    }

    fn cbor<T>(&mut self) -> Result<T, DecodeClmrError> where T: DeserializeOwned {
        let (content, tail) = cbor::from_slice_partial::<T>(self.input)?;
        self.input = tail;
        Ok(content)
    }

    fn signature(&mut self, author: &Multikey) -> Result<Multisig, DecodeClmrError> {
        let (sig, tail) = author.sig_from_compact(self.input)?;
        self.input = tail;
        Ok(sig)
    }
}
