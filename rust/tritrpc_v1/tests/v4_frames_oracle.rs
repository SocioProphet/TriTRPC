//! Oracle-driven parity for the v4 Beacon / StreamData / StreamClose frames.
//!
//! Reads the shared Python-generated vectors (sample_vectors_v4.json), supplies each vector's real
//! AES-GCM tag (its last 16 bytes), rebuilds the frame from the known field values, and asserts the
//! Rust serializer produces the exact oracle bytes — verifying the Rust prefix layout matches Python.

use std::fs;

use tritrpc_v1::v4::frames::{
    BeaconFrame, Control243, CryptoSuite, StreamCloseFrame, StreamDataFrame,
};
use tritrpc_v1::v4::handle243::HandleValue;
use tritrpc_v1::v4::kind243::FrameKind;

fn oracle() -> serde_json::Value {
    let path = format!(
        "{}/../../reference/experimental/tritrpc_requirements_impl_v4/generated/sample_vectors_v4.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read oracle {path}: {e}"));
    serde_json::from_str(&raw).expect("parse oracle")
}

fn get(o: &serde_json::Value, k: &str) -> String {
    o[k].as_str()
        .unwrap_or_else(|| panic!("oracle missing {k}"))
        .to_string()
}

fn tag_of(hex_str: &str) -> [u8; 16] {
    let bytes = hex::decode(hex_str).expect("hex");
    let mut t = [0u8; 16];
    t.copy_from_slice(&bytes[bytes.len() - 16..]);
    t
}

fn ctrl_a() -> Control243 {
    Control243 {
        profile: 0,
        lane: 0,
        evidence: 0,
        fallback: 0,
        routefmt: 1,
    }
}

#[test]
fn beacon_commit_matches_oracle() {
    let o = oracle();
    let want = get(&o, "beacon_commit");
    let identity = get(&o, "beacon_identity");
    let mut payload = vec![136u8]; // State243(active/verified/routine/fluid/cohort)
    payload.extend_from_slice(identity.as_bytes());
    let frame = BeaconFrame {
        control: Control243 {
            profile: 2,
            lane: 2,
            evidence: 2,
            fallback: 2,
            routefmt: 2,
        },
        suite: CryptoSuite::Cnsa2Ready,
        kind: FrameKind::BeaconCommit,
        epoch: 18,
        identity_handle: HandleValue::Direct(19),
        phase: 4,
        topic: 21,
        payload,
        tag: tag_of(&want),
    };
    assert_eq!(hex::encode(frame.serialize().unwrap()), want);
}

#[test]
fn stream_data_inherit_matches_oracle() {
    let o = oracle();
    let want = get(&o, "stream_data_inherit");
    let frame = StreamDataFrame {
        control: ctrl_a(),
        suite: CryptoSuite::FipsClassical,
        epoch: 18,
        stream_id: 9,
        payload: b"{\"chunk\":1}".to_vec(),
        override_semantic: None,
        tag: tag_of(&want),
    };
    assert_eq!(hex::encode(frame.serialize().unwrap()), want);
}

#[test]
fn stream_data_override_matches_oracle() {
    let o = oracle();
    let want = get(&o, "stream_data_override");
    let frame = StreamDataFrame {
        control: ctrl_a(),
        suite: CryptoSuite::FipsClassical,
        epoch: 18,
        stream_id: 9,
        payload: b"{\"chunk\":1}".to_vec(),
        override_semantic: Some((101, 136)),
        tag: tag_of(&want),
    };
    assert_eq!(hex::encode(frame.serialize().unwrap()), want);
}

#[test]
fn stream_close_serializes_canonically() {
    // No oracle vector for close; assert the canonical structure round-trips a known prefix.
    let frame = StreamCloseFrame {
        control: ctrl_a(),
        suite: CryptoSuite::FipsClassical,
        epoch: 18,
        stream_id: 9,
        payload: b"{}".to_vec(),
        tag: [0u8; 16],
    };
    let bytes = frame.serialize().unwrap();
    // f32a | ctrl(01) | kind(04) | suite(01) | epoch(12) | stream_id(09) | len(02) | {} | 16B tag
    assert_eq!(
        &bytes[..8],
        &[0xf3, 0x2a, 0x01, 0x04, 0x01, 0x12, 0x09, 0x02]
    );
    assert_eq!(bytes.len(), 8 + 2 + 16);
}
