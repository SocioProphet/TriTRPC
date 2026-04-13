/// Handle243: the canonical v4 route-handle codec.
///
/// Encoding prefix byte:
///   0..=242  – direct integer handle (the value itself)
///   243      – extended handle  (S243-encoded extension id follows)
///   244      – inline UTF-8     (S243 length, then UTF-8 bytes)
///   245      – hash handle      (32 raw bytes follow)
///   246      – tombstone        (no further bytes)
///   247..255 – reserved / invalid
use super::error::V4Error;
use super::s243::{decode_s243, encode_s243};

/// All canonical forms a route handle may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleValue {
    /// An integer in 0..=242 encoded directly as a single byte.
    Direct(u8),
    /// An extended handle identified by a non-negative integer id.
    Extended(u64),
    /// An inline UTF-8 route handle (e.g. a service path string).
    Utf8(String),
    /// A 32-byte hash-based handle.
    Hash([u8; 32]),
    /// Tombstone – signals absence / revocation.
    Tombstone,
}

/// Encode a [`HandleValue`] into its canonical wire bytes.
pub fn encode_handle243(value: &HandleValue) -> Result<Vec<u8>, V4Error> {
    match value {
        HandleValue::Direct(v) => {
            if *v > 242 {
                return Err(V4Error::new(format!(
                    "direct Handle243 values must be in 0..=242, got {v}"
                )));
            }
            Ok(vec![*v])
        }
        HandleValue::Extended(id) => {
            let mut out = vec![243u8];
            out.extend(encode_s243(*id));
            Ok(out)
        }
        HandleValue::Utf8(s) => {
            let raw = s.as_bytes();
            let mut out = vec![244u8];
            out.extend(encode_s243(raw.len() as u64));
            out.extend_from_slice(raw);
            Ok(out)
        }
        HandleValue::Hash(digest) => {
            let mut out = vec![245u8];
            out.extend_from_slice(digest);
            Ok(out)
        }
        HandleValue::Tombstone => Ok(vec![246u8]),
    }
}

/// Decode a [`HandleValue`] from `data` starting at `offset`.
///
/// Returns `(value, new_offset)` on success.
pub fn decode_handle243(data: &[u8], offset: usize) -> Result<(HandleValue, usize), V4Error> {
    if offset >= data.len() {
        return Err(V4Error::new("EOF in Handle243"));
    }
    let prefix = data[offset];
    match prefix {
        0..=242 => Ok((HandleValue::Direct(prefix), offset + 1)),
        243 => {
            let (id, new_offset) = decode_s243(data, offset + 1)?;
            Ok((HandleValue::Extended(id), new_offset))
        }
        244 => {
            let (length, new_offset) = decode_s243(data, offset + 1)?;
            let end = new_offset + length as usize;
            if end > data.len() {
                return Err(V4Error::new("truncated inline UTF-8 handle"));
            }
            let s = std::str::from_utf8(&data[new_offset..end])
                .map_err(|e| V4Error::new(format!("invalid UTF-8 in handle: {e}")))?
                .to_string();
            Ok((HandleValue::Utf8(s), end))
        }
        245 => {
            let end = offset + 1 + 32;
            if end > data.len() {
                return Err(V4Error::new("truncated hash handle"));
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&data[offset + 1..end]);
            Ok((HandleValue::Hash(digest), end))
        }
        246 => Ok((HandleValue::Tombstone, offset + 1)),
        other => Err(V4Error::new(format!(
            "invalid leading byte for Handle243: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_direct() {
        for v in [0u8, 1, 100, 242] {
            let enc = encode_handle243(&HandleValue::Direct(v)).unwrap();
            let (dec, _) = decode_handle243(&enc, 0).unwrap();
            assert_eq!(dec, HandleValue::Direct(v));
        }
    }

    #[test]
    fn roundtrip_utf8() {
        for s in ["", "a", "hello", "service/method"] {
            let enc = encode_handle243(&HandleValue::Utf8(s.to_string())).unwrap();
            let (dec, _) = decode_handle243(&enc, 0).unwrap();
            assert_eq!(dec, HandleValue::Utf8(s.to_string()));
        }
    }

    #[test]
    fn roundtrip_tombstone() {
        let enc = encode_handle243(&HandleValue::Tombstone).unwrap();
        let (dec, _) = decode_handle243(&enc, 0).unwrap();
        assert_eq!(dec, HandleValue::Tombstone);
    }

    #[test]
    fn direct_out_of_range_is_error() {
        assert!(encode_handle243(&HandleValue::Direct(243)).is_err());
    }
}
