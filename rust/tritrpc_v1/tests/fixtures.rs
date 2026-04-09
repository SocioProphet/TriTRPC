use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use std::collections::HashMap;
use std::fs;
use subtle::ConstantTimeEq;
use tritrpc_v1::{avrodec, avroenc, envelope, tleb3, tritpack243};

fn read_pairs(path: &str) -> Vec<(String, Vec<u8>)> {
    let txt = fs::read_to_string(path).expect("read fixtures");
    txt.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut it = l.splitn(2, ' ');
            let name = it.next().unwrap().to_string();
            let hexs = it.next().unwrap();
            let bytes = hex::decode(hexs).unwrap();
            (name, bytes)
        })
        .collect()
}

fn read_nonces(path: &str) -> HashMap<String, Vec<u8>> {
    let txt = fs::read_to_string(path).expect("read nonces");
    txt.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut it = l.splitn(2, ' ');
            let name = it.next().unwrap().to_string();
            let hexs = it.next().unwrap();
            (name, hex::decode(hexs).unwrap())
        })
        .collect()
}

fn split_fields(mut buf: &[u8]) -> Vec<Vec<u8>> {
    let mut off = 0usize;
    let mut fields: Vec<Vec<u8>> = Vec::new();
    while off < buf.len() {
        let (len, new_off) = tleb3::decode_len(buf, off).unwrap();
        let l = len as usize;
        let val_off = new_off;
        let val_end = val_off + l;
        fields.push(buf[val_off..val_end].to_vec());
        off = val_end;
    }
    fields
}

fn aead_bit(flags_bytes: &[u8]) -> bool {
    let trits = tritpack243::unpack(flags_bytes).unwrap();
    trits.get(0) == Some(&2u8)
}

#[test]
fn verify_all_frames_and_payloads() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures");
    let sets = vec![
        (
            format!("{}/vectors_hex.txt", root),
            format!("{}/vectors_hex.txt.nonces", root),
        ),
        (
            format!("{}/vectors_hex_stream_avrochunk.txt", root),
            format!("{}/vectors_hex_stream_avrochunk.txt.nonces", root),
        ),
        (
            format!("{}/vectors_hex_unary_rich.txt", root),
            format!("{}/vectors_hex_unary_rich.txt.nonces", root),
        ),
        (
            format!("{}/vectors_hex_stream_avronested.txt", root),
            format!("{}/vectors_hex_stream_avronested.txt.nonces", root),
        ),
        (
            format!("{}/vectors_hex_pathB.txt", root),
            format!("{}/vectors_hex_pathB.txt.nonces", root),
        ),
    ];
    let key = [0u8; 32];
    for (fx, nx) in sets {
        let pairs = read_pairs(&fx);
        let nonces = read_nonces(&nx);
        for (name, frame) in pairs {
            let fields = split_fields(&frame);
            assert!(fields.len() >= 9, "{}", name);
            let decoded = envelope::decode(&frame).expect("decode envelope");
            assert_eq!(
                decoded.schema.as_slice(),
                envelope::SCHEMA_ID_32.as_slice(),
                "schema id mismatch {}",
                name
            );
            assert_eq!(
                decoded.context.as_slice(),
                envelope::CONTEXT_ID_32.as_slice(),
                "context id mismatch {}",
                name
            );

            let repacked = envelope::build(
                &decoded.service,
                &decoded.method,
                &decoded.payload,
                decoded.aux.as_deref(),
                decoded.tag.as_deref(),
                decoded.aead_on,
                decoded.compress,
            );
            assert_eq!(repacked, frame, "repack mismatch {}", name);

            let flags = &fields[3];
            let has_aead = aead_bit(flags);
            if has_aead {
                let tag = decoded.tag.as_ref().expect("missing tag");
                assert_eq!(tag.len(), 16, "tag size mismatch {}", name);
                let nonce = nonces.get(&name).expect("nonce missing");
                assert_eq!(nonce.len(), 24, "nonce size mismatch {}", name);
                let aad_start = decoded.tag_start.expect("tag start missing");
                let aad = &frame[..aad_start];
                let strict = std::env::var("STRICT_AEAD").ok().as_deref() == Some("1");
                let aead = XChaCha20Poly1305::new(&key.into());
                let ct = aead
                    .encrypt(
                        nonce.as_slice().into(),
                        chacha20poly1305::aead::Payload { msg: b"", aad },
                    )
                    .unwrap();
                let computed = &ct[ct.len() - 16..];
                let matches: bool = bool::from(computed.ct_eq(tag.as_slice()));
                assert!(matches, "tag mismatch for {}", name);
                if strict {
                    assert!(matches, "strict tag mismatch for {}", name);
                }
            }

            if decoded.method.ends_with(".REQ") {
                let parsed = avrodec::dec_hg_request(&decoded.payload).expect("decode HGRequest");
                let recoded = avrodec::enc_hg_request(&parsed).expect("re-encode HGRequest");
                assert_eq!(
                    recoded, decoded.payload,
                    "HGRequest round-trip mismatch {}",
                    name
                );
            }
            if decoded.method.ends_with(".RSP") {
                let parsed = avrodec::dec_hg_response(&decoded.payload).expect("decode HGResponse");
                let recoded = avrodec::enc_hg_response(&parsed).expect("re-encode HGResponse");
                assert_eq!(
                    recoded, decoded.payload,
                    "HGResponse round-trip mismatch {}",
                    name
                );
            }
        }
    }
}

#[test]
fn debug_aead_single() {
    let frame_hex = "f502f32af502f301f502f300f502f512d0f300b2ab814588f99c875d37bb7546d0df4369c28bc5f60ce38a6607dac468034352d0f300e6572c0e618f18d572d4c2969db4909659f09eaef32ec66fbb804bad9d89aacdf50868797065722e7631eaf301476574537562677261706853747265616da2f3010a0000020261000202b4f30108742d303108732d303100e1f301b4f58a932b3da2f25489ed7e6a023155";
    let nonce_hex = "020202020202020202020202020202020202020200000000";
    let frame = hex::decode(frame_hex).unwrap();
    let nonce_bytes = hex::decode(nonce_hex).unwrap();
    let decoded = envelope::decode(&frame).expect("decode");
    let tag_start = decoded.tag_start.expect("tag_start");
    let aad = &frame[..tag_start];
    // also rebuild to verify
    let rebuilt = envelope::build(
        &decoded.service, &decoded.method, &decoded.payload,
        decoded.aux.as_deref(), None, decoded.aead_on, decoded.compress,
    );
    eprintln!("tag_start={} frame_len={} aad_len={} rebuilt_len={}", tag_start, frame.len(), aad.len(), rebuilt.len());
    eprintln!("aad==rebuilt: {}", aad == rebuilt.as_slice());
    eprintln!("stored tag: {}", hex::encode(decoded.tag.as_ref().unwrap()));
    let key = [0u8; 32];
    let aead = XChaCha20Poly1305::new(&key.into());
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let ct = aead.encrypt(nonce.as_slice().into(), chacha20poly1305::aead::Payload { msg: b"", aad }).unwrap();
    let computed_tag = &ct[ct.len()-16..];
    eprintln!("computed tag: {}", hex::encode(computed_tag));
}
