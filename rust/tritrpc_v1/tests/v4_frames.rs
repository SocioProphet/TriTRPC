/// v4 frame fixture-driven tests.
///
/// Loads conformance fixture JSON files from conformance/fixtures/v4/frames/
/// and validates that the Rust frame serializer and parser match the expected
/// oracle output for every case.
///
/// Known gaps (WIP):
///   - Some seed fixture hex values may need correction after first oracle run.
///   - Not all frame types are exercised yet.
use serde::Deserialize;
use std::fs;
use tritrpc_v1::v4::{
    frames::{Control243, CryptoSuite, HotUnaryFrame, StreamOpenFrame},
    handle243::HandleValue,
    kind243::FrameKind,
};

fn fixture_path(name: &str) -> String {
    format!(
        "{}/../../conformance/fixtures/v4/frames/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

// ────────────────────────────────────────────────
// Fixture JSON schema
// ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FixtureFile {
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    id: String,
    kind: String,
    // Positive case fields
    semantic_input: Option<serde_json::Value>,
    expected_frame_hex: Option<String>,
    // Negative case fields
    operation: Option<String>,
    input_hex: Option<String>,
    expected_error: Option<String>,
    expected_error_contains: Option<String>,
}

// ────────────────────────────────────────────────
// Helper: build HandleValue from fixture JSON
// ────────────────────────────────────────────────

fn handle_from_json(v: &serde_json::Value) -> HandleValue {
    let typ = v["type"].as_str().expect("route_handle.type");
    match typ {
        "direct" => {
            let val = v["value"].as_u64().expect("direct handle value") as u8;
            HandleValue::Direct(val)
        }
        "utf8" => {
            let s = v["value"].as_str().expect("utf8 handle value").to_string();
            HandleValue::Utf8(s)
        }
        other => panic!("unsupported route handle type in fixture: {other}"),
    }
}

fn control_from_json(v: &serde_json::Value) -> Control243 {
    Control243 {
        profile: v["profile"].as_u64().unwrap_or(0) as u8,
        lane: v["lane"].as_u64().unwrap_or(0) as u8,
        evidence: v["evidence"].as_u64().unwrap_or(0) as u8,
        fallback: v["fallback"].as_u64().unwrap_or(0) as u8,
        routefmt: v["routefmt"].as_u64().unwrap_or(0) as u8,
    }
}

// ────────────────────────────────────────────────
// HotUnary fixture tests
// ────────────────────────────────────────────────

#[test]
fn v4_frames_hot_unary_positive_cases_match_fixture() {
    let path = fixture_path("hot_unary.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let file: FixtureFile = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));

    let positive: Vec<&FixtureCase> =
        file.cases.iter().filter(|c| c.kind == "positive").collect();
    assert!(!positive.is_empty(), "no positive cases found in hot_unary.json");

    for case in positive {
        let input = case.semantic_input.as_ref().unwrap_or_else(|| {
            panic!("case {} missing semantic_input", case.id)
        });

        let control = control_from_json(&input["control"]);
        let kind_byte = input["kind"].as_u64().unwrap() as u8;
        let suite_byte = input["suite"].as_u64().unwrap() as u8;
        let epoch = input["epoch"].as_u64().unwrap();
        let route_handle = handle_from_json(&input["route_handle"]);
        let payload_hex = input["payload_hex"].as_str().unwrap_or("");
        let tag_hex = input["tag_hex"].as_str().unwrap();

        let payload = hex::decode(payload_hex)
            .unwrap_or_else(|e| panic!("case {}: bad payload_hex: {e}", case.id));
        let tag_bytes = hex::decode(tag_hex)
            .unwrap_or_else(|e| panic!("case {}: bad tag_hex: {e}", case.id));
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes);

        let kind = FrameKind::from_byte(kind_byte)
            .unwrap_or_else(|e| panic!("case {}: bad kind: {e}", case.id));
        let suite = CryptoSuite::from_byte(suite_byte)
            .unwrap_or_else(|e| panic!("case {}: bad suite: {e}", case.id));

        let frame = HotUnaryFrame { control, kind, suite, epoch, route_handle, payload, tag };

        // Serialize and compare against fixture hex
        let serialized = frame
            .serialize()
            .unwrap_or_else(|e| panic!("case {}: serialize failed: {e}", case.id));

        let expected_hex = case.expected_frame_hex.as_deref().unwrap_or_else(|| {
            panic!("case {} missing expected_frame_hex", case.id)
        });
        let expected_bytes = hex::decode(expected_hex)
            .unwrap_or_else(|e| panic!("case {}: bad expected_frame_hex: {e}", case.id));

        assert_eq!(
            serialized,
            expected_bytes,
            "case {}: serialized frame does not match fixture\n  got:      {}\n  expected: {}",
            case.id,
            hex::encode(&serialized),
            expected_hex,
        );

        // Parse the expected bytes and verify round-trip
        let parsed = HotUnaryFrame::parse(&expected_bytes)
            .unwrap_or_else(|e| panic!("case {}: parse failed: {e}", case.id));
        let re_serialized = parsed
            .serialize()
            .unwrap_or_else(|e| panic!("case {}: re-serialize failed: {e}", case.id));
        assert_eq!(
            re_serialized,
            expected_bytes,
            "case {}: round-trip failed",
            case.id
        );
    }
}

#[test]
fn v4_frames_hot_unary_negative_cases_produce_errors() {
    let path = fixture_path("hot_unary.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let file: FixtureFile = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));

    let negative: Vec<&FixtureCase> =
        file.cases.iter().filter(|c| c.kind == "negative").collect();
    assert!(!negative.is_empty(), "no negative cases found in hot_unary.json");

    for case in negative {
        let op = case.operation.as_deref().unwrap_or("parse");
        assert_eq!(op, "parse", "case {}: only 'parse' operation supported", case.id);

        let input_hex = case.input_hex.as_deref().unwrap_or_else(|| {
            panic!("case {} missing input_hex", case.id)
        });
        let input_bytes = hex::decode(input_hex)
            .unwrap_or_else(|e| panic!("case {}: bad input_hex: {e}", case.id));

        let result = HotUnaryFrame::parse(&input_bytes);
        assert!(
            result.is_err(),
            "case {}: expected parse error but got Ok",
            case.id
        );

        let err_msg = result.unwrap_err().0;

        if let Some(expected) = &case.expected_error {
            assert_eq!(
                &err_msg,
                expected,
                "case {}: error message mismatch",
                case.id
            );
        }
        if let Some(contains) = &case.expected_error_contains {
            assert!(
                err_msg.contains(contains.as_str()),
                "case {}: expected error to contain {:?}, got {:?}",
                case.id,
                contains,
                err_msg
            );
        }
    }
}

// ────────────────────────────────────────────────
// StreamOpen fixture tests
// ────────────────────────────────────────────────

#[test]
fn v4_frames_stream_open_positive_cases_match_fixture() {
    let path = fixture_path("stream_open.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let file: FixtureFile = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));

    let positive: Vec<&FixtureCase> =
        file.cases.iter().filter(|c| c.kind == "positive").collect();
    assert!(!positive.is_empty(), "no positive cases found in stream_open.json");

    for case in positive {
        let input = case.semantic_input.as_ref().unwrap_or_else(|| {
            panic!("case {} missing semantic_input", case.id)
        });

        let control = control_from_json(&input["control"]);
        let suite_byte = input["suite"].as_u64().unwrap() as u8;
        let epoch = input["epoch"].as_u64().unwrap();
        let route_handle = handle_from_json(&input["route_handle"]);
        let stream_id = input["stream_id"].as_u64().unwrap();
        let payload_hex = input["payload_hex"].as_str().unwrap_or("");
        let tag_hex = input["tag_hex"].as_str().unwrap();

        let payload = hex::decode(payload_hex)
            .unwrap_or_else(|e| panic!("case {}: bad payload_hex: {e}", case.id));
        let tag_bytes = hex::decode(tag_hex)
            .unwrap_or_else(|e| panic!("case {}: bad tag_hex: {e}", case.id));
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes);

        let suite = CryptoSuite::from_byte(suite_byte)
            .unwrap_or_else(|e| panic!("case {}: bad suite: {e}", case.id));

        let frame = StreamOpenFrame {
            control,
            suite,
            epoch,
            route_handle,
            stream_id,
            payload,
            default_semantic: None,
            tag,
        };

        let serialized = frame
            .serialize()
            .unwrap_or_else(|e| panic!("case {}: serialize failed: {e}", case.id));

        let expected_hex = case.expected_frame_hex.as_deref().unwrap_or_else(|| {
            panic!("case {} missing expected_frame_hex", case.id)
        });
        let expected_bytes = hex::decode(expected_hex)
            .unwrap_or_else(|e| panic!("case {}: bad expected_frame_hex: {e}", case.id));

        assert_eq!(
            serialized,
            expected_bytes,
            "case {}: serialized frame does not match fixture\n  got:      {}\n  expected: {}",
            case.id,
            hex::encode(&serialized),
            expected_hex,
        );

        let parsed = StreamOpenFrame::parse(&expected_bytes)
            .unwrap_or_else(|e| panic!("case {}: parse failed: {e}", case.id));
        let re_serialized = parsed
            .serialize()
            .unwrap_or_else(|e| panic!("case {}: re-serialize failed: {e}", case.id));
        assert_eq!(
            re_serialized,
            expected_bytes,
            "case {}: round-trip failed",
            case.id
        );
    }
}

#[test]
fn v4_frames_stream_open_negative_cases_produce_errors() {
    let path = fixture_path("stream_open.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let file: FixtureFile = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));

    let negative: Vec<&FixtureCase> =
        file.cases.iter().filter(|c| c.kind == "negative").collect();
    assert!(!negative.is_empty(), "no negative cases found in stream_open.json");

    for case in negative {
        let input_hex = case.input_hex.as_deref().unwrap_or_else(|| {
            panic!("case {} missing input_hex", case.id)
        });
        let input_bytes = hex::decode(input_hex)
            .unwrap_or_else(|e| panic!("case {}: bad input_hex: {e}", case.id));

        let result = StreamOpenFrame::parse(&input_bytes);
        assert!(
            result.is_err(),
            "case {}: expected parse error but got Ok",
            case.id
        );

        let err_msg = result.unwrap_err().0;

        if let Some(expected) = &case.expected_error {
            assert_eq!(
                &err_msg,
                expected,
                "case {}: error message mismatch",
                case.id
            );
        }
        if let Some(contains) = &case.expected_error_contains {
            assert!(
                err_msg.contains(contains.as_str()),
                "case {}: expected error to contain {:?}, got {:?}",
                case.id,
                contains,
                err_msg
            );
        }
    }
}
