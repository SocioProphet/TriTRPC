
use std::fs;
use std::collections::HashMap;
use tritrpc_v1::{tleb3, tritpack243, envelope, avroenc};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;

fn read_pairs(path:&str)->Vec<(String, Vec<u8>)>{
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

fn read_nonces(path:&str)->HashMap<String, Vec<u8>>{
    let txt = fs::read_to_string(path).expect("read nonces");
    txt.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut it = l.splitn(2, ' ');
            let name = it.next().unwrap().to_string();
            let hexs = it.next().unwrap();
            (name, hex::decode(hexs).unwrap())
        }).collect()
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
    let sets = vec![
        ("fixtures/vectors_hex.txt","fixtures/vectors_hex.txt.nonces"),
        ("fixtures/vectors_hex_stream_avrochunk.txt","fixtures/vectors_hex_stream_avrochunk.txt.nonces"),
        ("fixtures/vectors_hex_unary_rich.txt","fixtures/vectors_hex_unary_rich.txt.nonces"),
        ("fixtures/vectors_hex_stream_avronested.txt","fixtures/vectors_hex_stream_avronested.txt.nonces"),
    ];
    let key = [0u8;32];
    for (fx, nx) in sets {
        let pairs = read_pairs(fx);
        let nonces = read_nonces(nx);
        for (name, frame) in pairs {
            let fields = split_fields(&frame);
            assert!(fields.len() >= 9, "{}", name);
            let flags = &fields[3];
            let has_aead = aead_bit(flags);
            if has_aead {
                // last field is tag
                let tag = fields.last().unwrap();
                // AAD is everything before the last field; reconstruct by slicing
                // We reconstruct by walking lengths: easier approach is to compute tag by encrypting empty with aad=the AAD bytes.
                // AAD bytes are frame[.. frame.len() - (lenprefix(tag)+tag.len())], but we don't have lenprefix length.
                // Instead, recompute by removing the final length+value pair using TLEB3 decode traversal.
                // We'll rebuild the traversal to find the starting index of last field.
                // Implementation: walk again until we reach the final field, computing offsets.
                let mut off = 0usize;
                let mut last_start = 0usize;
                let mut idx = 0usize;
                while off < frame.len() {
                    let (len, new_off) = tleb3::decode_len(&frame, off).unwrap();
                    last_start = off;
                    off = new_off + len as usize;
                    idx += 1;
                }
                // now AAD is frame[..last_start]
                let aad = &frame[..last_start];
                let nonce = nonces.get(&name).expect("nonce missing");
                let strict = std::env::var("STRICT_AEAD").ok().as_deref()==Some("1");
                let aead = XChaCha20Poly1305::new(&key.into());
                let ct = aead.encrypt(nonce.as_slice().into(), chacha20poly1305::aead::Payload{ msg: b"", aad }).unwrap();
                assert_eq!(&ct[ct.len()-16..], tag.as_slice(), "tag mismatch for {}", name);

                // Payload check for a few known names
                if name.ends_with("hyper.v1.AddVertex_a.REQ") || name.ends_with("hyper.v1.AddVertex_a") {
                    let payload = &fields[8];
                    let want = avroenc::enc_HGRequest_AddVertex("a", Some("A"));
                    assert_eq!(payload, &want, "payload mismatch {}", name);
                }
                if name.ends_with("hyper.v1.AddHyperedge_e1_ab.REQ") || name.ends_with("hyper.v1.AddHyperedge_e1_ab") {
                    let payload = &fields[8];
                    let want = avroenc::enc_HGRequest_AddHyperedge("e1", &["a","b"], Some(1));
                    assert_eq!(payload, &want, "payload mismatch {}", name);
                }
                if name.ends_with("hyper.v1.QueryNeighbors_a_k1.REQ") || name.ends_with("hyper.v1.QueryNeighbors_a_k1") {
                    let payload = &fields[8];
                    let want = avroenc::enc_HGRequest_QueryNeighbors("a", 1);
                    assert_eq!(payload, &want, "payload mismatch {}", name);
                }
            }
        }
    }
}
