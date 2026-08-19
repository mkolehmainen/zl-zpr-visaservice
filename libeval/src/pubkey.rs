use base64::{Engine as _, engine::general_purpose};
use thiserror::Error;
use zpr::vsapi_types::{KeyFormat, PublicKey};

const ZPRKF01_FMT: &str = "ZprKF01";

/// Failures parsing a stored `FMT:BASE64` public key value.
#[derive(Debug, Error)]
pub enum PubKeyError {
    #[error("public key value is not FMT:KEY")]
    Malformed,

    #[error("unknown public key format: '{0}'")]
    UnknownFormat(String),

    #[error("public key base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// Render pubkeys as FMT:BASE64 for storage in an attribute value.
pub fn encode_public_key(key: &PublicKey) -> String {
    let fmt = match key.format {
        KeyFormat::ZprKF01 => ZPRKF01_FMT,
    };
    format!(
        "{fmt}:{}",
        general_purpose::STANDARD.encode(&key.public_key)
    )
}

/// Parse an attribute value written by encode_public_key().
pub fn decode_public_key(s: &str) -> Result<PublicKey, PubKeyError> {
    let (fmt, b64) = s.split_once(':').ok_or(PubKeyError::Malformed)?;
    let format = match fmt {
        ZPRKF01_FMT => KeyFormat::ZprKF01,
        _ => return Err(PubKeyError::UnknownFormat(fmt.to_string())),
    };
    Ok(PublicKey {
        format,
        public_key: general_purpose::STANDARD.decode(b64)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key encodes to its format tag plus standard base64, and decodes back
    /// unchanged.
    #[test]
    fn test_public_key_round_trip() {
        let key_bytes: Vec<u8> = (0..32u8).collect();
        let encoded = encode_public_key(&PublicKey::new(&key_bytes));
        assert_eq!(
            encoded,
            "ZprKF01:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        );

        let decoded = decode_public_key(&encoded).expect("should decode");
        assert!(matches!(decoded.format, KeyFormat::ZprKF01));
        assert_eq!(decoded.public_key, key_bytes);
    }

    /// An unrecognized format tag is rejected, which is what keeps a key written
    /// by a newer VS from being read as a ZprKF01 key.
    #[test]
    fn test_decode_public_key_rejects_unknown_format() {
        let err = decode_public_key("ZprKF99:AAEC").expect_err("should not decode");
        match err {
            PubKeyError::UnknownFormat(fmt) => assert_eq!(fmt, "ZprKF99"),
            other => panic!("expected UnknownFormat, got {other}"),
        }
    }
}
