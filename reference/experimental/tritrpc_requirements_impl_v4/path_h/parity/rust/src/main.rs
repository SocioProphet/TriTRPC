use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Number, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

const MAGIC_B2: [u8; 2] = [0xF3, 0x2A];
const TEST_TAG_KEY: &[u8] = b"TRITRPC_PATH_H_DRAFT_TEST_KEY_32";

#[derive(Debug, Deserialize)]
struct FixtureFile {
    meta: Meta,
    fixtures: HashMap<String, Fixture>,
}

#[derive(Debug, Deserialize)]
struct Meta {
    epoch: i64,
    kind: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    event: String,
    epoch: i64,
    kind: String,
    route_h: i64,
    frame_hex: String,
    object: HashMap<String, Value>,
}

fn tritpack243(trits: &[i64]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 5 <= trits.len() {
        let mut val = 0i64;
        for &t in &trits[i..i + 5] {
            if !(0..=2).contains(&t) {
                return Err(format!("invalid trit {}", t));
            }
            val = val * 3 + t;
        }
        out.push(val as u8);
        i += 5;
    }
    let k = trits.len() - i;
    if k > 0 {
        out.push((243 + (k - 1)) as u8);
        let mut val = 0i64;
        for &t in &trits[i..] {
            if !(0..=2).contains(&t) {
                return Err(format!("invalid trit {}", t));
            }
            val = val * 3 + t;
        }
        out.push(val as u8);
    }
    Ok(out)
}

fn tleb3_encode_len(mut n: i64) -> Result<Vec<u8>, String> {
    if n < 0 {
        return Err("negative length".into());
    }
    let mut digits = Vec::new();
    if n == 0 {
        digits.push(0);
    } else {
        while n > 0 {
            digits.push(n % 9);
            n /= 9;
        }
    }
    let mut trits = Vec::new();
    for (i, d) in digits.iter().enumerate() {
        let c = if i < digits.len() - 1 { 2 } else { 0 };
        let p1 = d / 3;
        let p0 = d % 3;
        trits.extend([c, p1, p0]);
    }
    tritpack243(&trits)
}

fn s243(n: i64) -> Result<Vec<u8>, String> {
    if n < 0 {
        return Err("negative integer".into());
    }
    if n <= 242 {
        return Ok(vec![n as u8]);
    }
    let mut out = vec![243u8];
    out.extend(tleb3_encode_len(n - 243)?);
    Ok(out)
}

fn h243(n: i64) -> Result<Vec<u8>, String> {
    if !(0..=242).contains(&n) {
        return Err(format!("handle out of range: {}", n));
    }
    Ok(vec![n as u8])
}

fn u8b(n: i64) -> Result<Vec<u8>, String> {
    if !(0..=255).contains(&n) {
        return Err(format!("u8 out of range: {}", n));
    }
    Ok(vec![n as u8])
}

fn u16be(n: i64) -> Result<Vec<u8>, String> {
    if !(0..=65535).contains(&n) {
        return Err(format!("u16 out of range: {}", n));
    }
    Ok(vec![(n >> 8) as u8, n as u8])
}

fn u64be(n: u64) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

fn bool8(v: bool) -> Vec<u8> {
    vec![if v { 1 } else { 0 }]
}

fn ctrl243(profile: i64, lane: i64, evidence: i64, fallback: i64, routefmt: i64) -> Result<Vec<u8>, String> {
    tritpack243(&[profile, lane, evidence, fallback, routefmt])
}

fn bsm3_u8(code: &str) -> Result<Vec<u8>, String> {
    let b = code.as_bytes();
    if b.len() != 2 || !(b'0'..=b'2').contains(&b[0]) || !(b'0'..=b'2').contains(&b[1]) {
        return Err(format!("invalid bsm3_code: {}", code));
    }
    Ok(vec![((b[0] - b'0') * 3 + (b[1] - b'0')) as u8])
}

fn test_tag(aad: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(TEST_TAG_KEY).expect("HMAC key");
    mac.update(aad);
    let tag = mac.finalize().into_bytes();
    tag[..16].to_vec()
}

fn append_all(parts: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn kind243(kind: &str) -> Result<i64, String> {
    match kind {
        "unary_req" => Ok(0),
        "unary_rsp" => Ok(1),
        "stream_open" => Ok(2),
        "stream_data" => Ok(3),
        "stream_close" => Ok(4),
        "beacon_cap" => Ok(5),
        "beacon_intent" => Ok(6),
        "beacon_commit" => Ok(7),
        "error" => Ok(8),
        _ => Err(format!("unknown kind: {}", kind)),
    }
}

fn route_h(event: &str) -> Result<i64, String> {
    match event {
        "PAIR.OPEN" => Ok(11),
        "PAIR.HERALD" => Ok(12),
        "TELEPORT.BSM3" => Ok(13),
        "FRAME.DEFER" => Ok(14),
        "WITNESS.REPORT" => Ok(15),
        _ => Err(format!("unknown route event: {}", event)),
    }
}

fn ctrl_map(event: &str) -> Result<[i64; 5], String> {
    match event {
        "PAIR.OPEN" => Ok([2, 2, 0, 1, 1]),
        "PAIR.HERALD" => Ok([2, 1, 1, 0, 1]),
        "TELEPORT.BSM3" => Ok([2, 2, 0, 0, 1]),
        "FRAME.DEFER" => Ok([2, 2, 0, 1, 1]),
        "WITNESS.REPORT" => Ok([2, 2, 2, 0, 1]),
        _ => Err(format!("missing control map for {}", event)),
    }
}

fn pair_kind(v: &str) -> Result<i64, String> {
    match v {
        "qubit" => Ok(0),
        "qutrit" => Ok(1),
        _ => Err(format!("unknown pair_kind: {}", v)),
    }
}

fn encoding_kind(v: &str) -> Result<i64, String> {
    match v {
        "unknown" => Ok(0),
        "time-bin" => Ok(1),
        "frequency-bin" => Ok(2),
        "path" => Ok(3),
        "memory-backed" => Ok(4),
        _ => Err(format!("unknown encoding_kind: {}", v)),
    }
}

fn subject_kind(v: &str) -> Result<i64, String> {
    match v {
        "link" => Ok(0),
        "pair" => Ok(1),
        "path" => Ok(2),
        "memory" => Ok(3),
        "swap" => Ok(4),
        _ => Err(format!("unknown subject_kind: {}", v)),
    }
}

fn clock_quality(v: &str) -> Result<i64, String> {
    match v {
        "ok" => Ok(0),
        "degraded" => Ok(1),
        "holdover" => Ok(2),
        _ => Err(format!("unknown clock_quality_code: {}", v)),
    }
}

fn as_i64(v: &Value) -> Result<i64, String> {
    match v {
        Value::Number(n) => number_to_i64(n),
        _ => Err(format!("expected number, got {}", v)),
    }
}

fn number_to_i64(n: &Number) -> Result<i64, String> {
    n.as_i64().ok_or_else(|| format!("number not representable as i64: {}", n))
}

fn as_u64(v: &Value) -> Result<u64, String> {
    match v {
        Value::Number(n) => n.as_u64().ok_or_else(|| format!("number not representable as u64: {}", n)),
        _ => Err(format!("expected number, got {}", v)),
    }
}

fn as_bool(v: &Value) -> Result<bool, String> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(format!("expected bool, got {}", v)),
    }
}

fn as_str<'a>(v: &'a Value) -> Result<&'a str, String> {
    match v {
        Value::String(s) => Ok(s),
        _ => Err(format!("expected string, got {}", v)),
    }
}

fn get<'a>(obj: &'a HashMap<String, Value>, key: &str) -> Result<&'a Value, String> {
    obj.get(key).ok_or_else(|| format!("missing key: {}", key))
}

fn encode_pair_open(obj: &HashMap<String, Value>) -> Result<Vec<u8>, String> {
    let mut flags = 0;
    if as_bool(get(obj, "need_memory")?)? { flags |= 1; }
    if as_bool(get(obj, "need_teleport_ready")?)? { flags |= 1 << 1; }
    Ok(append_all(&[
        s243(as_i64(get(obj, "seq")?)?)?,
        h243(as_i64(get(obj, "src_site")?)?)?,
        h243(as_i64(get(obj, "dst_site")?)?)?,
        u8b(pair_kind(as_str(get(obj, "pair_kind")?)?)?)?,
        u8b(encoding_kind(as_str(get(obj, "encoding_kind")?)?)?)?,
        u16be(as_i64(get(obj, "target_fidelity_milli")?)?)?,
        s243(as_i64(get(obj, "ttl_ms")?)?)?,
        u8b(flags)?,
    ]))
}

fn encode_pair_herald(obj: &HashMap<String, Value>) -> Result<Vec<u8>, String> {
    Ok(append_all(&[
        s243(as_i64(get(obj, "seq")?)?)?,
        h243(as_i64(get(obj, "pair_id")?)?)?,
        h243(as_i64(get(obj, "src_site")?)?)?,
        h243(as_i64(get(obj, "dst_site")?)?)?,
        u8b(encoding_kind(as_str(get(obj, "encoding_kind")?)?)?)?,
        bool8(as_bool(get(obj, "herald_success")?)?),
        u64be(as_u64(get(obj, "ts_ns")?)?),
        u16be(as_i64(get(obj, "fidelity_milli")?)?)?,
        u16be(as_i64(get(obj, "visibility_milli")?)?)?,
        s243(as_i64(get(obj, "ttl_ms")?)?)?,
    ]))
}

fn encode_teleport_bsm3(obj: &HashMap<String, Value>) -> Result<Vec<u8>, String> {
    let mut flags = 0;
    if as_bool(get(obj, "defer_ok")?)? { flags |= 1; }
    if obj.get("mem_id").is_some() { flags |= 1 << 1; }
    let mut out = append_all(&[
        s243(as_i64(get(obj, "seq")?)?)?,
        h243(as_i64(get(obj, "pair_id")?)?)?,
        u8b(as_i64(get(obj, "basis_id")?)?)?,
        bsm3_u8(as_str(get(obj, "bsm3_code")?)?)?,
        u64be(as_u64(get(obj, "ts_ns")?)?),
        u8b(flags)?,
    ]);
    if let Some(v) = obj.get("mem_id") {
        out.extend(h243(as_i64(v)?)?);
    }
    Ok(out)
}

fn encode_frame_defer(obj: &HashMap<String, Value>) -> Result<Vec<u8>, String> {
    Ok(append_all(&[
        s243(as_i64(get(obj, "seq")?)?)?,
        h243(as_i64(get(obj, "pair_id")?)?)?,
        u8b(as_i64(get(obj, "frame_shift_x")?)?)?,
        u8b(as_i64(get(obj, "frame_shift_z")?)?)?,
        s243(as_i64(get(obj, "frame_epoch")?)?)?,
        u64be(as_u64(get(obj, "ts_ns")?)?),
    ]))
}

fn encode_witness_report(obj: &HashMap<String, Value>) -> Result<Vec<u8>, String> {
    Ok(append_all(&[
        s243(as_i64(get(obj, "seq")?)?)?,
        u8b(subject_kind(as_str(get(obj, "subject_kind")?)?)?)?,
        h243(as_i64(get(obj, "subject_id")?)?)?,
        u64be(as_u64(get(obj, "delay_ns")?)?),
        u16be(as_i64(get(obj, "fidelity_milli")?)?)?,
        u16be(as_i64(get(obj, "visibility_milli")?)?)?,
        u16be(as_i64(get(obj, "snr_milli")?)?)?,
        u8b(clock_quality(as_str(get(obj, "clock_quality_code")?)?)?)?,
        h243(as_i64(get(obj, "env_ref")?)?)?,
        u64be(as_u64(get(obj, "ts_ns")?)?),
    ]))
}

fn encode_payload(event: &str, obj: &HashMap<String, Value>) -> Result<Vec<u8>, String> {
    match event {
        "PAIR.OPEN" => encode_pair_open(obj),
        "PAIR.HERALD" => encode_pair_herald(obj),
        "TELEPORT.BSM3" => encode_teleport_bsm3(obj),
        "FRAME.DEFER" => encode_frame_defer(obj),
        "WITNESS.REPORT" => encode_witness_report(obj),
        _ => Err(format!("unknown event {}", event)),
    }
}

fn encode_frame(event: &str, obj: &HashMap<String, Value>, epoch: i64, kind: &str) -> Result<Vec<u8>, String> {
    let ctrl_cfg = ctrl_map(event)?;
    let ctrl = ctrl243(ctrl_cfg[0], ctrl_cfg[1], ctrl_cfg[2], ctrl_cfg[3], ctrl_cfg[4])?;
    let payload = encode_payload(event, obj)?;
    let front = append_all(&[
        MAGIC_B2.to_vec(),
        ctrl,
        u8b(kind243(kind)?)?,
        s243(epoch)?,
        h243(route_h(event)?)?,
        s243(payload.len() as i64)?,
        payload,
    ]);
    let mut out = front.clone();
    out.extend(test_tag(&front));
    Ok(out)
}

fn default_fixture_path() -> PathBuf {
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent().unwrap_or_else(|| std::path::Path::new(".")).join("tritrpc_path_h_fixtures.json")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture_path = env::args().nth(1).map(PathBuf::from).unwrap_or_else(default_fixture_path);
    let raw = fs::read_to_string(&fixture_path)?;
    let ff: FixtureFile = serde_json::from_str(&raw)?;

    let mut failures = 0usize;
    for (name, fx) in ff.fixtures.iter() {
        match encode_frame(&fx.event, &fx.object, fx.epoch, &fx.kind) {
            Ok(bytes) => {
                let got = hex::encode(bytes);
                if got == fx.frame_hex {
                    println!("PASS {}", name);
                } else {
                    println!("FAIL {}\n  want: {}\n  got:  {}", name, fx.frame_hex, got);
                    failures += 1;
                }
            }
            Err(e) => {
                eprintln!("{}: encode error: {}", name, e);
                failures += 1;
            }
        }
    }

    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}
