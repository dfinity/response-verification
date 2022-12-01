use std::fmt::Write;
use thiserror::Error;
use crate::base32::{base32_decode, base32_encode};

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum PrincipalError {
    #[error("Bytes is longer than 29 bytes.")]
    BytesTooLong(),

    #[error("Text must be in valid Base32 encoding.")]
    InvalidBase32(),

    #[error("Text is too short.")]
    TextTooShort(),

    #[error("Text is too long.")]
    TextTooLong(),

    #[error("CRC32 check sequence doesn't match with calculated from Principal bytes.")]
    CheckSequenceNotMatch(),

    #[error(r#"Text should be separated by - (dash) every 5 characters: expected "{0}""#)]
    AbnormalGrouped(Principal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal {
    len: u8,
    bytes: [u8; Self::MAX_LENGTH_IN_BYTES],
}

impl Principal {
    const MAX_LENGTH_IN_BYTES: usize = 29;
    const CRC_LENGTH_IN_BYTES: usize = 4;

    pub const fn try_from_slice(slice: &[u8]) -> Result<Self, PrincipalError> {
        const MAX_LENGTH_IN_BYTES: usize = Principal::MAX_LENGTH_IN_BYTES;
        match slice.len() {
            len @ 0..=MAX_LENGTH_IN_BYTES => {
                let mut bytes = [0; MAX_LENGTH_IN_BYTES];
                let mut i = 0;
                while i < len {
                    bytes[i] = slice[i];
                    i += 1;
                }
                Ok(Self {
                    len: len as u8,
                    bytes,
                })
            }
            _ => Err(PrincipalError::BytesTooLong()),
        }
    }

    pub fn from_text<S: AsRef<str>>(text: S) -> Result<Self, PrincipalError> {
        let mut s = text.as_ref().to_string();
        s.make_ascii_uppercase();
        s.retain(|c| c != '-');
        
        match base32_decode(&s) {
            Some(bytes) => {
                if bytes.len() < Self::CRC_LENGTH_IN_BYTES {
                    return Err(PrincipalError::TextTooShort());
                }

                let crc_bytes = &bytes[..Self::CRC_LENGTH_IN_BYTES];
                let data_bytes = &bytes[Self::CRC_LENGTH_IN_BYTES..];
                if data_bytes.len() > Self::MAX_LENGTH_IN_BYTES {
                    return Err(PrincipalError::TextTooLong());
                }

                if crc32fast::hash(data_bytes).to_be_bytes() != crc_bytes {
                    return Err(PrincipalError::CheckSequenceNotMatch());
                }

                let result = Self::try_from_slice(data_bytes).unwrap();
                let expected = format!("{}", result);

                if text.as_ref().to_ascii_lowercase() != expected {
                    return Err(PrincipalError::AbnormalGrouped(result));
                }
                Ok(result)
            }
            _ => Err(PrincipalError::InvalidBase32()),
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let blob: &[u8] = self.as_slice();

        let checksum = crc32fast::hash(blob);

        let mut bytes = vec![];
        bytes.extend_from_slice(&checksum.to_be_bytes());
        bytes.extend_from_slice(blob);

        let mut s = base32_encode(&bytes);
        s.make_ascii_lowercase();

        let mut s = s.as_str();
        while s.len() > 5 {
            f.write_str(&s[..5])?;
            f.write_char('-')?;
            s = &s[5..];
        }
        f.write_str(s)
    }
}

impl AsRef<[u8]> for Principal {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

