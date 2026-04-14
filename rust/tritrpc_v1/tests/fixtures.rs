use blake2::{
    digest::{consts::U16, KeyInit, Mac},
    Blake2bMac,
};
use std::fs;
use tritrpc_v1::{avrodec, envelope, tleb3, tritpack243};

type Blake2bMac128 = Blake2bMac<U16>;

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

fn split_fields(buf: &[u8]) -> Vec<Vec<u8>> {
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
        format!("{}/vectors_hex.txt", root),
        format!("{}/vectors_hex_stream_avrochunk.txt", root),
        format!("{}/vectors_hex_unary_rich.txt", root),
        format!("{}/vectors_hex_stream_avronested.txt", root),
        format!("{}/vectors_hex_pathB.txt", root),
    ];
    let key = [0u8; 32];
    for fx in sets {
        let pairs = read_pairs(&fx);
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

            let mode_trit = tritpack243::unpack(&decoded.mode)
                .ok()
                .and_then(|t| t.into_iter().next())
                .unwrap_or(0);
            let repacked = envelope::build_with_mode(
                &decoded.service,
                &decoded.method,
                &decoded.payload,
                decoded.aux.as_deref(),
                decoded.tag.as_deref(),
                decoded.aead_on,
                decoded.compress,
                mode_trit,
            );
            assert_eq!(repacked, frame, "repack mismatch {}", name);

            let flags = &fields[3];
            let has_aead = aead_bit(flags);
            if has_aead {
                let tag = decoded.tag.as_ref().expect("missing tag");
                assert_eq!(tag.len(), 16, "tag size mismatch {}", name);
                let aad_start = decoded.tag_start.expect("tag start missing");
                let aad = &frame[..aad_start];
                let mut mac = <Blake2bMac128 as KeyInit>::new_from_slice(&key).expect("valid key");
                mac.update(aad);
                let computed = mac.finalize().into_bytes();
                assert_eq!(
                    computed.as_slice(),
                    tag.as_slice(),
                    "tag mismatch for {}",
                    name
                );
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
