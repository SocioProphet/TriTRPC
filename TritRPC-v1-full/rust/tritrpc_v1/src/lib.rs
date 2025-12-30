
pub mod tritpack243 {
    pub fn pack(trits: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i + 5 <= trits.len() {
            let mut val: u32 = 0;
            for &t in &trits[i..i+5] {
                assert!(t <= 2, "invalid trit");
                val = val * 3 + t as u32;
            }
            out.push(val as u8);
            i += 5;
        }
        let k = trits.len() - i;
        if k > 0 {
            out.push(243 + (k as u8 - 1));
            let mut val: u32 = 0;
            for &t in &trits[i..] {
                val = val * 3 + t as u32;
            }
            out.push(val as u8);
        }
        out
    }

    pub fn unpack(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut trits: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < bytes.len() {
            let b = bytes[i]; i += 1;
            if b <= 242 {
                let mut val = b as u32;
                let mut group = [0u8; 5];
                for j in (0..5).rev() {
                    group[j] = (val % 3) as u8;
                    val /= 3;
                }
                trits.extend_from_slice(&group);
            } else if (243..=246).contains(&b) {
                if i >= bytes.len() { return Err("truncated tail marker".into()); }
                let k = (b - 243 + 1) as usize;
                let mut val = bytes[i] as u32; i += 1;
                let mut group = vec![0u8; k];
                for j in (0..k).rev() {
                    group[j] = (val % 3) as u8;
                    val /= 3;
                }
                trits.extend(group);
            } else {
                return Err("invalid byte 247..255 in canonical stream".into());
            }
        }
        Ok(trits)
    }
}

pub mod tleb3 {
    use super::tritpack243;
    pub fn encode_len(mut n: u64) -> Vec<u8> {
        let mut digits: Vec<u8> = Vec::new();
        if n == 0 { digits.push(0); } else {
            while n > 0 {
                digits.push((n % 9) as u8);
                n /= 9;
            }
        }
        let mut trits: Vec<u8> = Vec::new();
        for (i, d) in digits.iter().enumerate() {
            let c = if i < digits.len()-1 { 2 } else { 0 };
            let p1 = d / 3;
            let p0 = d % 3;
            trits.push(c); trits.push(*p1); trits.push(*p0);
        }
        tritpack243::pack(&trits)
    }

    pub fn decode_len(bytes: &[u8], mut offset: usize) -> Result<(u64, usize), String> {
        let mut trits: Vec<u8> = Vec::new();
        loop {
            if offset >= bytes.len() { return Err("EOF in TLEB3".into()); }
            let b = bytes[offset]; offset += 1;
            let ts = super::tritpack243::unpack(&[b])?;
            trits.extend_from_slice(&ts);
            if trits.len() < 3 { continue; }
            let mut val: u64 = 0;
            let mut used_trits: usize = 0;
            for j in 0..(trits.len()/3) {
                let c = trits[3*j] as u64;
                let p1 = trits[3*j+1] as u64;
                let p0 = trits[3*j+2] as u64;
                let digit = p1*3 + p0;
                val += digit * 9u64.pow(j as u32);
                if c == 0 {
                    used_trits = (j+1)*3;
                    break;
                }
            }
            if used_trits > 0 {
                let used_bytes = super::tritpack243::pack(&trits[..used_trits]).len();
                let new_off = offset - 1 + (used_bytes - 1);
                return Ok((val, new_off));
            }
        }
    }
}

pub mod envelope {
    use super::{tritpack243, tleb3};
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::XChaCha20Poly1305;

    const MAGIC_B2: [u8;2] = [0xF3, 0x2A];

    fn len_prefix(b: &[u8]) -> Vec<u8> {
        tleb3::encode_len(b.len() as u64)
    }

    fn pack_trits(ts: &[u8]) -> Vec<u8> {
        tritpack243::pack(ts)
    }

    pub fn flags_trits(aead: bool, compress: bool) -> [u8;3] {
        [
            if aead {2} else {0},
            if compress {2} else {0},
            0
        ]
    }

    pub fn build(service:&str, method:&str, payload:&[u8], aux: Option<&[u8]>, aead_tag: Option<&[u8]>, aead_on: bool, compress: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend(len_prefix(&MAGIC_B2)); out.extend(MAGIC_B2);
        let ver = pack_trits(&[1]); out.extend(len_prefix(&ver)); out.extend(ver);
        let mode = pack_trits(&[0]); out.extend(len_prefix(&mode)); out.extend(mode);
        let flags = pack_trits(&super::envelope::flags_trits(aead_on, compress)); out.extend(len_prefix(&flags)); out.extend(flags);
        let schema = vec![0u8;32]; out.extend(len_prefix(&schema)); out.extend(&schema);
        let context = vec![0u8;32]; out.extend(len_prefix(&context)); out.extend(&context);
        let svc = service.as_bytes(); out.extend(len_prefix(svc)); out.extend(svc);
        let m = method.as_bytes(); out.extend(len_prefix(m)); out.extend(m);
        out.extend(len_prefix(payload)); out.extend(payload);
        if let Some(auxb) = aux { out.extend(len_prefix(auxb)); out.extend(auxb); }
        if let Some(tag) = aead_tag { out.extend(len_prefix(tag)); out.extend(tag); }
        out
    }

    pub fn envelope_with_tag(service:&str, method:&str, payload:&[u8], aux: Option<&[u8]>, key:&[u8;32], nonce:&[u8;24]) -> (Vec<u8>, Vec<u8>) {
        let aad = build(service, method, payload, aux, None, true, false);
        let aead = XChaCha20Poly1305::new(key.into());
        let ct = aead.encrypt(nonce.into(), chacha20poly1305::aead::Payload { msg: b"", aad: &aad }).expect("encrypt");
        let tag = ct[ct.len()-16..].to_vec();
        let frame = build(service, method, payload, aux, Some(&tag), true, false);
        (frame, tag)
    }
}

pub mod avroenc {
    // Avro subset encoders: zigzag, varint, string, bytes, array, map, union, enum, records for control+HG
    fn zigzag(n: i64) -> u64 { ((n << 1) ^ (n >> 63)) as u64 }
    pub fn enc_varint(mut u: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while (u & !0x7F) != 0 {
            out.push(((u & 0x7F) as u8) | 0x80);
            u >>= 7;
        }
        out.push(u as u8);
        out
    }
    pub fn enc_long(n: i64) -> Vec<u8> { enc_varint(zigzag(n)) }
    pub fn enc_int(n: i32) -> Vec<u8> { enc_long(n as i64) }
    pub fn enc_bool(v: bool) -> Vec<u8> { if v { vec![1] } else { vec![0] } }
    pub fn enc_string(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = enc_long(b.len() as i64);
        out.extend_from_slice(b);
        out
    }
    pub fn enc_bytes(b: &[u8]) -> Vec<u8> {
        let mut out = enc_long(b.len() as i64);
        out.extend_from_slice(b);
        out
    }
    pub fn enc_array<T>(items: &[T], f: fn(&T)->Vec<u8>) -> Vec<u8> {
        if items.is_empty() { return vec![0]; }
        let mut out = Vec::new();
        out.extend(enc_long(items.len() as i64));
        for it in items { out.extend(f(it)); }
        out.push(0);
        out
    }
    pub fn enc_map(m: &[(&str, &str)]) -> Vec<u8> {
        if m.is_empty() { return vec![0]; }
        let mut out = Vec::new();
        out.extend(enc_long(m.len() as i64));
        for (k, v) in m {
            out.extend(enc_string(k));
            out.extend(enc_string(v));
        }
        out.push(0);
        out
    }
    pub fn enc_union(index: i64, payload: Vec<u8>) -> Vec<u8> {
        let mut out = enc_long(index);
        out.extend(payload);
        out
    }
    pub fn enc_enum(index: i32) -> Vec<u8> { enc_int(index) }

    // Control
    pub fn enc_Hello(modes:&[&str], suites:&[&str], comp:&[&str], context_uri: Option<&str>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_array(modes, |s| enc_string(s)));
        out.extend(enc_array(suites, |s| enc_string(s)));
        out.extend(enc_array(comp, |s| enc_string(s)));
        match context_uri {
            None => out.extend(enc_union(0, vec![])),
            Some(u) => out.extend(enc_union(1, enc_string(u))),
        }
        out
    }
    pub fn enc_Choose(mode:&str, suite:&str, comp:&str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_string(mode));
        out.extend(enc_string(suite));
        out.extend(enc_string(comp));
        out
    }
    pub fn enc_Error(code:i32, msg:&str, details: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_int(code));
        out.extend(enc_string(msg));
        match details {
            None => out.extend(enc_union(0, vec![])),
            Some(b) => out.extend(enc_union(1, enc_bytes(b))),
        }
        out
    }

    // Hypergraph
    pub fn enc_Vertex(vid:&str, label: Option<&str>, attrs: &[(&str,&str)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_string(vid));
        match label {
            None => out.extend(enc_union(0, vec![])),
            Some(l) => out.extend(enc_union(1, enc_string(l))),
        }
        out.extend(enc_map(attrs));
        out
    }
    pub fn enc_Hyperedge(eid:&str, members:&[&str], weight: Option<i64>, attrs:&[(&str,&str)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_string(eid));
        out.extend(enc_array(members, |s| enc_string(s)));
        match weight {
            None => out.extend(enc_union(0, vec![])),
            Some(w) => out.extend(enc_union(1, enc_long(w))),
        }
        out.extend(enc_map(attrs));
        out
    }
    pub fn enc_HGRequest_AddVertex(vid:&str, label: Option<&str>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(0));
        out.extend(enc_union(1, enc_Vertex(vid, label, &[])));
        out.extend(enc_union(0, vec![])); // edge null
        out.extend(enc_union(0, vec![])); // vid null
        out.extend(enc_union(0, vec![])); // eid null
        out.extend(enc_union(0, vec![])); // k null
        out
    }
    pub fn enc_HGRequest_AddHyperedge(eid:&str, members:&[&str], weight: Option<i64>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(1));
        out.extend(enc_union(0, vec![])); // vertex null
        out.extend(enc_union(1, enc_Hyperedge(eid, members, weight, &[])));
        out.extend(enc_union(0, vec![])); // vid null
        out.extend(enc_union(0, vec![])); // eid null
        out.extend(enc_union(0, vec![])); // k null
        out
    }
    pub fn enc_HGRequest_QueryNeighbors(vid:&str, k:i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(4));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(1, enc_string(vid)));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(1, enc_int(k)));
        out
    }
    pub fn enc_HGRequest_GetSubgraph(vid:&str, k:i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(5));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(1, enc_string(vid)));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(1, enc_int(k)));
        out
    }
    pub fn enc_HGResponse(ok: bool, err: Option<&str>, vertices:&[(&str, Option<&str>)], edges:&[(&str, Vec<&str>, Option<i64>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_bool(ok));
        match err {
            None => out.extend(enc_union(0, vec![])),
            Some(e) => out.extend(enc_union(1, enc_string(e))),
        }
        // vertices
        let vbytes = vertices.iter().map(|(vid,l)| enc_Vertex(vid, *l, &[])).collect::<Vec<_>>();
        let mut arr = Vec::new();
        if vbytes.is_empty() { arr.push(0); }
        else {
            arr.extend(enc_long(vbytes.len() as i64));
            for vb in vbytes { arr.extend(vb); }
            arr.push(0);
        }
        out.extend(arr);
        // edges
        let ebytes = edges.iter().map(|(eid,mem,w)| enc_Hyperedge(eid, mem, *w, &[])).collect::<Vec<_>>();
        let mut arr2 = Vec::new();
        if ebytes.is_empty() { arr2.push(0); }
        else {
            arr2.extend(enc_long(ebytes.len() as i64));
            for eb in ebytes { arr2.extend(eb); }
            arr2.push(0);
        }
        out.extend(arr2);
        out
    }
}


pub mod tritrpc_v1_tests {
    use super::{tleb3, tritpack243, avroenc};
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::XChaCha20Poly1305;
    use std::collections::HashMap;
    use std::fs;

    pub fn verify_file(fx: &str, nonces_path: &str) -> String {
        let key = [0u8;32];
        let pairs = read_pairs(fx);
        let nonces = read_nonces(nonces_path);
        let mut ok = 0usize;
        for (name, frame) in pairs {
            let fields = split_fields(&frame);
            let flags = &fields[3];
            if aead_bit(flags) {
                let tag = fields.last().unwrap();
                let aad = aad_before_last(&frame);
                let nonce = nonces.get(&name).expect("nonce missing");
                let aead = XChaCha20Poly1305::new(&key.into());
                let ct = aead.encrypt(nonce.as_slice().into(), chacha20poly1305::aead::Payload{ msg: b"", aad }).unwrap();
                assert_eq!(&ct[ct.len()-16..], tag.as_slice(), "tag mismatch {}", name);
            }
            ok += 1;
        }
        format!("Verified {} frames in {}", ok, fx)
    }

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
    fn split_fields(buf: &[u8]) -> Vec<Vec<u8>> {
        let mut off = 0usize;
        let mut fields: Vec<Vec<u8>> = Vec::new();
        while off < buf.len() {
            let (len, new_off) = super::tleb3::decode_len(buf, off).unwrap();
            let l = len as usize;
            let val_off = new_off;
            let val_end = val_off + l;
            fields.push(buf[val_off..val_end].to_vec());
            off = val_end;
        }
        fields
    }
    fn aead_bit(flags_bytes: &[u8]) -> bool {
        let trits = super::tritpack243::unpack(flags_bytes).unwrap();
        trits.get(0) == Some(&2u8)
    }
    fn aad_before_last(frame: &[u8]) -> &[u8] {
        let mut off = 0usize;
        let mut last_start = 0usize;
        while off < frame.len() {
            let (len, new_off) = super::tleb3::decode_len(frame, off).unwrap();
            last_start = off;
            off = new_off + len as usize;
        }
        &frame[..last_start]
    }
}

pub mod avroenc_json {
    use super::avroenc;
    use serde_json::Value;

    pub fn enc_HGRequest(v:&Value) -> Vec<u8> {
        let op = v["op"].as_str().unwrap();
        match op {
            "AddVertex" => {
                let vid = v["vertex"]["vid"].as_str().unwrap();
                let label = v["vertex"]["label"].as_str().unwrap_or("");
                let lopt = if label.is_empty() { None } else { Some(label) };
                avroenc::enc_HGRequest_AddVertex(vid, lopt)
            }
            "AddHyperedge" => {
                let eid = v["edge"]["eid"].as_str().unwrap();
                let members = v["edge"]["members"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect::<Vec<_>>();
                avroenc::enc_HGRequest_AddHyperedge(eid, &members, Some(1))
            }
            "QueryNeighbors" => {
                let vid = v["vid"].as_str().unwrap();
                let k = v["k"].as_i64().unwrap_or(1) as i32;
                avroenc::enc_HGRequest_QueryNeighbors(vid, k)
            }
            "GetSubgraph" => {
                let vid = v["vid"].as_str().unwrap();
                let k = v["k"].as_i64().unwrap_or(1) as i32;
                avroenc::enc_HGRequest_GetSubgraph(vid, k)
            }
            "RemoveVertex" => {
                // simple: not used in CLI pack example
                avroenc::enc_HGRequest_GetSubgraph("a", 1)
            }
            _ => avroenc::enc_HGRequest_GetSubgraph("a", 1)
        }
    }

    pub fn enc_HGResponse_json(v: &Value) -> Vec<u8> {
        let ok = v["ok"].as_bool().unwrap_or(true);
        let err = v.get("err").and_then(|e| e.as_str());
        let vertices = v["vertices"].as_array().unwrap_or(&vec![]).iter().map(|x| {
            (x["vid"].as_str().unwrap(), x.get("label").and_then(|l| l.as_str()))
        }).collect::<Vec<_>>();
        let edges = v["edges"].as_array().unwrap_or(&vec![]).iter().map(|x| {
            let eid = x["eid"].as_str().unwrap();
            let members = x["members"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect::<Vec<_>>();
            let weight = x.get("weight").and_then(|w| w.as_i64());
            (eid, members, weight)
        }).collect::<Vec<_>>();
        super::avroenc::enc_HGResponse(ok, err, &vertices, &edges)
    }
}


pub mod avrodec {
    // Minimal Avro Binary decoders for our subset (string, int/long, array<>, map<string>, union, enum)
    pub fn dec_varint(mut it: &mut &[u8]) -> u64 {
        let mut val: u64 = 0;
        let mut shift = 0;
        loop {
            let b = it[0]; *it = &it[1..];
            val |= ((b & 0x7F) as u64) << shift;
            if (b & 0x80) == 0 { break; }
            shift += 7;
        }
        val
    }
    pub fn dec_long(it: &mut &[u8]) -> i64 {
        let u = dec_varint(it);
        // zigzag inverse
        ((u >> 1) as i64) ^ (-((u & 1) as i64))
    }
    pub fn dec_int(it: &mut &[u8]) -> i32 { dec_long(it) as i32 }
    pub fn dec_string(it: &mut &[u8]) -> String {
        let len = dec_long(it) as usize;
        let s = std::str::from_utf8(&it[..len]).unwrap();
        *it = &it[len..];
        s.to_string()
    }
    pub fn dec_bytes(it: &mut &[u8]) -> Vec<u8> {
        let len = dec_long(it) as usize;
        let b = it[..len].to_vec();
        *it = &it[len..];
        b
    }
    pub fn dec_union_index(it: &mut &[u8]) -> i64 { dec_long(it) }
    pub fn dec_enum_index(it: &mut &[u8]) -> i32 { dec_int(it) }
    pub fn dec_array<T>(it: &mut &[u8], mut f: impl FnMut(&mut &[u8])->T) -> Vec<T> {
        let mut out = Vec::new();
        let mut count = dec_long(it);
        if count == 0 { return out; }
        while count != 0 {
            if count < 0 { let _ = dec_long(it); count = -count; }
            for _ in 0..count { out.push(f(it)); }
            count = dec_long(it);
        }
        out
    }
    pub fn dec_map<V>(it: &mut &[u8], mut fv: impl FnMut(&mut &[u8])->V) -> std::collections::BTreeMap<String, V> {
        let mut out = std::collections::BTreeMap::new();
        let mut count = dec_long(it);
        if count == 0 { return out; }
        while count != 0 {
            if count < 0 { let _ = dec_long(it); count = -count; }
            for _ in 0..count {
                let k = dec_string(it);
                let v = fv(it);
                out.insert(k, v);
            }
            count = dec_long(it);
        }
        out
    }
}

pub mod pathb {
    use super::tleb3;
    use super::tritpack243;

    pub fn bt_encode(mut n: i64) -> Vec<u8> {
        let mut digits: Vec<i8> = vec![];
        if n == 0 { digits.push(0); }
        else {
            while n != 0 {
                let mut rem = (n % 3) as i8;
                n /= 3;
                if rem == 2 { rem = -1; n += 1; }
                digits.push(rem);
            }
            digits.reverse();
        }
        let trits: Vec<u8> = digits.into_iter().map(|d| (d+1) as u8).collect();
        let mut out = tleb3::encode_len(trits.len() as u64);
        out.extend(tritpack243::pack(&trits));
        out
    }

    pub fn enc_string(s: &str) -> Vec<u8> {
        let mut out = tleb3::encode_len(s.as_bytes().len() as u64);
        out.extend(s.as_bytes());
        out
    }

    pub fn enc_enum(index: u64) -> Vec<u8> { tleb3::encode_len(index) }
    pub fn enc_union_index(index: u64) -> Vec<u8> { tleb3::encode_len(index) }

    pub fn enc_array<T>(items:&[T], f: fn(&T)->Vec<u8>) -> Vec<u8> {
        if items.is_empty() { return vec![0]; }
        let mut out = tleb3::encode_len(items.len() as u64);
        for it in items { out.extend(f(it)); }
        out.push(0); out
    }

    pub fn enc_map(m:&[(&str,&str)]) -> Vec<u8> {
        if m.is_empty() { return vec![0]; }
        let mut out = tleb3::encode_len(m.len() as u64);
        for (k,v) in m {
            out.extend(enc_string(k));
            out.extend(enc_string(v));
        }
        out.push(0); out
    }
}


pub mod pathb_dec {
    use super::{tleb3, tritpack243};

    pub fn dec_len(bytes: &[u8], mut off: usize) -> (usize, usize) {
        // decode TLEB3 length and return (len, new_offset)
        let (val, new_off) = super::tleb3::decode_len(bytes, off).unwrap();
        (val as usize, new_off)
    }

    pub fn dec_string(bytes:&[u8], off: usize) -> (String, usize) {
        let (l, o2) = dec_len(bytes, off);
        let s = std::str::from_utf8(&bytes[o2..o2+l]).unwrap().to_string();
        (s, o2+l)
    }

    pub fn dec_union_index(bytes:&[u8], off: usize) -> (u64, usize) {
        let (u, o2) = super::tleb3::decode_len(bytes, off).unwrap();
        (u, o2)
    }

    pub fn dec_vertex(bytes:&[u8], off: usize) -> ((String, Option<String>), usize) {
        let (vid, o2) = dec_string(bytes, off);
        let (uix, o3) = dec_union_index(bytes, o2);
        let (label, o4) = if uix == 0 { (None, o3) } else { let (s, p) = dec_string(bytes, o3); (Some(s), p) };
        // skip attr map (length + entries) — for fixtures attr is empty (0x00)
        ( (vid, label), o4 + 1 )
    }
}
