/// v4 primitive unit tests (S243, Handle243, Kind243, Control243).
///
/// These tests exercise the low-level codec primitives used by v4 frames.
/// They are designed to match the oracle behaviour described in:
///   reference/experimental/tritrpc_requirements_impl_v4/src/tritrpc_requirements_impl/codec.py
use tritrpc_v1::v4::{
    frames::Control243,
    handle243::{decode_handle243, encode_handle243, HandleValue},
    kind243::FrameKind,
    s243::{decode_s243, encode_s243},
};

// ────────────────────────────────────────────────
// S243 primitives
// ────────────────────────────────────────────────

#[test]
fn v4_primitives_s243_zero_is_single_zero_byte() {
    assert_eq!(encode_s243(0), vec![0x00]);
}

#[test]
fn v4_primitives_s243_small_values_are_single_bytes() {
    for v in [1u64, 10, 100, 242] {
        let enc = encode_s243(v);
        assert_eq!(enc.len(), 1, "expected 1-byte encoding for {v}");
        assert_eq!(enc[0], v as u8);
    }
}

#[test]
fn v4_primitives_s243_boundary_243_starts_with_marker() {
    let enc = encode_s243(243);
    assert_eq!(enc[0], 0xf3, "S243(243) must start with marker byte 0xf3");
    assert!(enc.len() > 1, "S243(243) must have at least 2 bytes");
}

#[test]
fn v4_primitives_s243_roundtrip_wide_range() {
    for v in [0u64, 1, 100, 242, 243, 244, 300, 1000, 65535] {
        let enc = encode_s243(v);
        let (dec, consumed) = decode_s243(&enc, 0).unwrap();
        assert_eq!(dec, v, "S243 roundtrip failed for {v}");
        assert_eq!(consumed, enc.len(), "consumed all bytes for {v}");
    }
}

#[test]
fn v4_primitives_s243_decode_with_offset() {
    let mut buf = vec![0xAB, 0xCD];
    buf.extend(encode_s243(42));
    let (val, offset) = decode_s243(&buf, 2).unwrap();
    assert_eq!(val, 42);
    assert_eq!(offset, 3);
}

#[test]
fn v4_primitives_s243_eof_returns_error() {
    assert!(decode_s243(&[], 0).is_err());
    assert!(decode_s243(&[0x01], 1).is_err());
}

// ────────────────────────────────────────────────
// Handle243 primitives
// ────────────────────────────────────────────────

#[test]
fn v4_primitives_handle243_direct_zero() {
    let enc = encode_handle243(&HandleValue::Direct(0)).unwrap();
    assert_eq!(enc, vec![0x00]);
    let (dec, _) = decode_handle243(&enc, 0).unwrap();
    assert_eq!(dec, HandleValue::Direct(0));
}

#[test]
fn v4_primitives_handle243_direct_max() {
    let enc = encode_handle243(&HandleValue::Direct(242)).unwrap();
    assert_eq!(enc, vec![242]);
    let (dec, _) = decode_handle243(&enc, 0).unwrap();
    assert_eq!(dec, HandleValue::Direct(242));
}

#[test]
fn v4_primitives_handle243_direct_out_of_range_is_error() {
    assert!(encode_handle243(&HandleValue::Direct(243)).is_err());
}

#[test]
fn v4_primitives_handle243_utf8_empty_string() {
    let enc = encode_handle243(&HandleValue::Utf8("".to_string())).unwrap();
    assert_eq!(enc[0], 244, "utf8 handle must start with 0xf4=244");
    let (dec, _) = decode_handle243(&enc, 0).unwrap();
    assert_eq!(dec, HandleValue::Utf8("".to_string()));
}

#[test]
fn v4_primitives_handle243_utf8_single_char() {
    // Oracle: encode_handle243("a") = [0xf4, 0x01, 0x61]
    let enc = encode_handle243(&HandleValue::Utf8("a".to_string())).unwrap();
    assert_eq!(enc, vec![0xf4, 0x01, 0x61]);
    let (dec, _) = decode_handle243(&enc, 0).unwrap();
    assert_eq!(dec, HandleValue::Utf8("a".to_string()));
}

#[test]
fn v4_primitives_handle243_tombstone() {
    let enc = encode_handle243(&HandleValue::Tombstone).unwrap();
    assert_eq!(enc, vec![246]);
    let (dec, _) = decode_handle243(&enc, 0).unwrap();
    assert_eq!(dec, HandleValue::Tombstone);
}

#[test]
fn v4_primitives_handle243_eof_returns_error() {
    assert!(decode_handle243(&[], 0).is_err());
}

// ────────────────────────────────────────────────
// FrameKind243 primitives
// ────────────────────────────────────────────────

#[test]
fn v4_primitives_framekind_roundtrip_all() {
    for b in 0u8..=8 {
        let kind = FrameKind::from_byte(b).unwrap();
        assert_eq!(kind.as_byte(), b);
    }
}

#[test]
fn v4_primitives_framekind_invalid_returns_error() {
    assert!(FrameKind::from_byte(9).is_err());
    assert!(FrameKind::from_byte(255).is_err());
}

#[test]
fn v4_primitives_framekind_hot_unary_set() {
    assert!(FrameKind::UnaryReq.is_hot_unary());
    assert!(FrameKind::UnaryRsp.is_hot_unary());
    assert!(FrameKind::Error.is_hot_unary());
    assert!(!FrameKind::StreamOpen.is_hot_unary());
    assert!(!FrameKind::StreamData.is_hot_unary());
    assert!(!FrameKind::StreamClose.is_hot_unary());
}

// ────────────────────────────────────────────────
// Control243 primitives
// ────────────────────────────────────────────────

#[test]
fn v4_primitives_ctrl243_all_zeros_is_zero_byte() {
    let ctrl = Control243::default();
    assert_eq!(ctrl.encode().unwrap(), 0x00);
}

#[test]
fn v4_primitives_ctrl243_routefmt1_is_byte_1() {
    // routefmt=1 (direct handle), all others 0
    // Encoding: ((((0*3+0)*3+0)*3+0)*3+1) = 1 = 0x01
    let ctrl = Control243 {
        routefmt: 1,
        ..Default::default()
    };
    assert_eq!(ctrl.encode().unwrap(), 0x01);
}

#[test]
fn v4_primitives_ctrl243_roundtrip() {
    for profile in 0u8..=2 {
        for routefmt in 0u8..=2 {
            let ctrl = Control243 {
                profile,
                routefmt,
                ..Default::default()
            };
            let byte = ctrl.encode().unwrap();
            let decoded = Control243::decode(byte).unwrap();
            assert_eq!(decoded, ctrl);
        }
    }
}

#[test]
fn v4_primitives_ctrl243_invalid_field_returns_error() {
    let ctrl = Control243 {
        profile: 3,
        ..Default::default()
    };
    assert!(ctrl.encode().is_err());
}

#[test]
fn v4_primitives_ctrl243_byte_243_is_invalid() {
    assert!(Control243::decode(243).is_err());
    assert!(Control243::decode(255).is_err());
}
