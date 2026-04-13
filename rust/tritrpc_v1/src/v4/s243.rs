/// S243: a compact single-byte codec for small non-negative integers.
///
/// Values 0..=242 are encoded directly as one byte.
/// Values ≥ 243 are encoded as the marker byte 0xF3 (243) followed by a
/// TLEB3-encoded representation of (value − 243).
///
/// This is the canonical length/count codec used throughout v4 frames.
use super::error::V4Error;
use crate::tleb3;

/// Encode a non-negative integer using S243.
pub fn encode_s243(value: u64) -> Vec<u8> {
    if value <= 242 {
        vec![value as u8]
    } else {
        let mut out = vec![243u8];
        out.extend(tleb3::encode_len(value - 243));
        out
    }
}

/// Decode an S243 value from `data` starting at `offset`.
///
/// Returns `(decoded_value, new_offset)` on success.
pub fn decode_s243(data: &[u8], offset: usize) -> Result<(u64, usize), V4Error> {
    if offset >= data.len() {
        return Err(V4Error::new("EOF in S243"));
    }
    let prefix = data[offset];
    if prefix <= 242 {
        return Ok((prefix as u64, offset + 1));
    }
    if prefix != 243 {
        return Err(V4Error::new(format!(
            "invalid leading byte for canonical S243: {prefix}"
        )));
    }
    let (inner, new_offset) =
        tleb3::decode_len(data, offset + 1).map_err(|e| V4Error::new(e))?;
    Ok((243 + inner, new_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small_values() {
        for v in [0u64, 1, 100, 242] {
            let enc = encode_s243(v);
            let (dec, _) = decode_s243(&enc, 0).unwrap();
            assert_eq!(dec, v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn roundtrip_large_values() {
        for v in [243u64, 244, 500, 65535] {
            let enc = encode_s243(v);
            let (dec, _) = decode_s243(&enc, 0).unwrap();
            assert_eq!(dec, v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn small_values_are_one_byte() {
        assert_eq!(encode_s243(0), vec![0]);
        assert_eq!(encode_s243(1), vec![1]);
        assert_eq!(encode_s243(242), vec![242]);
    }

    #[test]
    fn extended_values_start_with_marker() {
        let enc = encode_s243(243);
        assert_eq!(enc[0], 243);
        assert!(enc.len() > 1);
    }
}
