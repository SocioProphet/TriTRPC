/// v4 frame parsing and serialization.
///
/// Wire layout for every frame:
///   [0..1]  magic        = 0xf3 0x2a
///   [2]     ctrl         = Control243 byte (ternary-encoded profile/lane/evidence/fallback/routefmt)
///   [3]     kind         = FrameKind byte
///   [4]     suite        = CryptoSuite byte (0..=3)
///   [5..]   epoch        = S243-encoded u64
///   [..]    frame-type-specific fields (see each variant)
///   [last 16] tag        = 16-byte authentication tag
///
/// HotUnaryFrame-specific fields (after epoch):
///   route_handle    = Handle243
///   payload_len     = S243
///   payload         = payload_len bytes
///
/// StreamOpenFrame-specific fields (after epoch):
///   route_handle    = Handle243
///   stream_id       = S243
///   payload_len     = S243
///   payload         = payload_len bytes
///   [optional 2-byte semantic tail: braid243 byte + state243 byte]
use super::error::V4Error;
use super::handle243::{decode_handle243, encode_handle243, HandleValue};
use super::kind243::FrameKind;
use super::s243::{decode_s243, encode_s243};

/// Magic bytes that open every v4 frame.
pub const MAGIC: [u8; 2] = [0xf3, 0x2a];

/// CryptoSuite: identifies the cryptographic posture for the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CryptoSuite {
    ResearchNonapproved = 0,
    FipsClassical = 1,
    Cnsa2Ready = 2,
    Reserved = 3,
}

impl CryptoSuite {
    pub fn from_byte(b: u8) -> Result<Self, V4Error> {
        match b {
            0 => Ok(CryptoSuite::ResearchNonapproved),
            1 => Ok(CryptoSuite::FipsClassical),
            2 => Ok(CryptoSuite::Cnsa2Ready),
            3 => Ok(CryptoSuite::Reserved),
            other => Err(V4Error::new(format!("invalid suite byte {other}"))),
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Control243: five ternary fields packed into a single byte (0..=242).
///
/// Encoding: ((((profile*3 + lane)*3 + evidence)*3 + fallback)*3 + routefmt)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Control243 {
    pub profile: u8,
    pub lane: u8,
    pub evidence: u8,
    pub fallback: u8,
    pub routefmt: u8,
}

impl Control243 {
    pub fn encode(self) -> Result<u8, V4Error> {
        for (name, v) in [
            ("profile", self.profile),
            ("lane", self.lane),
            ("evidence", self.evidence),
            ("fallback", self.fallback),
            ("routefmt", self.routefmt),
        ] {
            if v > 2 {
                return Err(V4Error::new(format!(
                    "Control243 field {name} must be a trit (0..=2), got {v}"
                )));
            }
        }
        let v = ((((self.profile as u32 * 3 + self.lane as u32) * 3 + self.evidence as u32) * 3
            + self.fallback as u32)
            * 3
            + self.routefmt as u32) as u8;
        Ok(v)
    }

    pub fn decode(b: u8) -> Result<Self, V4Error> {
        if b > 242 {
            return Err(V4Error::new(format!(
                "Control243 byte must be in 0..=242, got {b}"
            )));
        }
        let mut w = b as u32;
        let routefmt = (w % 3) as u8;
        w /= 3;
        let fallback = (w % 3) as u8;
        w /= 3;
        let evidence = (w % 3) as u8;
        w /= 3;
        let lane = (w % 3) as u8;
        w /= 3;
        let profile = (w % 3) as u8;
        Ok(Control243 { profile, lane, evidence, fallback, routefmt })
    }
}

/// A parsed v4 HotUnary frame (kinds: UnaryReq, UnaryRsp, Error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotUnaryFrame {
    pub control: Control243,
    pub kind: FrameKind,
    pub suite: CryptoSuite,
    pub epoch: u64,
    pub route_handle: HandleValue,
    pub payload: Vec<u8>,
    pub tag: [u8; 16],
}

/// A parsed v4 StreamOpen frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenFrame {
    pub control: Control243,
    pub suite: CryptoSuite,
    pub epoch: u64,
    pub route_handle: HandleValue,
    pub stream_id: u64,
    pub payload: Vec<u8>,
    /// Optional 2-byte semantic tail: (braid243, state243).
    pub default_semantic: Option<(u8, u8)>,
    pub tag: [u8; 16],
}

impl HotUnaryFrame {
    /// Serialize this frame to canonical wire bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, V4Error> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(self.control.encode()?);
        out.push(self.kind.as_byte());
        out.push(self.suite.as_byte());
        out.extend(encode_s243(self.epoch));
        out.extend(encode_handle243(&self.route_handle)?);
        out.extend(encode_s243(self.payload.len() as u64));
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.tag);
        Ok(out)
    }

    /// Parse a HotUnary frame from raw bytes.
    ///
    /// Validates magic, kind (must be UnaryReq/UnaryRsp/Error), suite, and frame length.
    pub fn parse(data: &[u8]) -> Result<Self, V4Error> {
        if data.len() < 2 + 1 + 1 + 1 + 16 {
            return Err(V4Error::new("frame is too short to be canonical"));
        }
        if data[..2] != MAGIC {
            return Err(V4Error::new("invalid magic"));
        }

        let mut offset = 2;
        let control = Control243::decode(data[offset])?;
        offset += 1;
        let kind = FrameKind::from_byte(data[offset])?;
        offset += 1;
        if !kind.is_hot_unary() {
            return Err(V4Error::new(format!(
                "hot unary frame received invalid kind: {}",
                kind.as_byte()
            )));
        }
        let suite = CryptoSuite::from_byte(data[offset])?;
        offset += 1;
        let (epoch, new_offset) = decode_s243(data, offset)?;
        offset = new_offset;
        let (route_handle, new_offset) = decode_handle243(data, offset)?;
        offset = new_offset;
        let (payload_len, new_offset) = decode_s243(data, offset)?;
        offset = new_offset;
        let payload_end = offset + payload_len as usize;
        if payload_end + 16 != data.len() {
            return Err(V4Error::new("truncated or overlong unary frame"));
        }
        let payload = data[offset..payload_end].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[payload_end..]);

        Ok(HotUnaryFrame { control, kind, suite, epoch, route_handle, payload, tag })
    }
}

impl StreamOpenFrame {
    /// Serialize this frame to canonical wire bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, V4Error> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(self.control.encode()?);
        out.push(FrameKind::StreamOpen.as_byte());
        out.push(self.suite.as_byte());
        out.extend(encode_s243(self.epoch));
        out.extend(encode_handle243(&self.route_handle)?);
        out.extend(encode_s243(self.stream_id));
        out.extend(encode_s243(self.payload.len() as u64));
        out.extend_from_slice(&self.payload);
        if let Some((braid, state)) = self.default_semantic {
            out.push(braid);
            out.push(state);
        }
        out.extend_from_slice(&self.tag);
        Ok(out)
    }

    /// Parse a StreamOpen frame from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, V4Error> {
        if data.len() < 2 + 1 + 1 + 1 + 16 {
            return Err(V4Error::new("frame is too short to be canonical"));
        }
        if data[..2] != MAGIC {
            return Err(V4Error::new("invalid magic"));
        }

        let mut offset = 2;
        let control = Control243::decode(data[offset])?;
        offset += 1;
        let kind = FrameKind::from_byte(data[offset])?;
        offset += 1;
        if kind != FrameKind::StreamOpen {
            return Err(V4Error::new(format!(
                "expected stream-open kind (2), got {}",
                kind.as_byte()
            )));
        }
        let suite = CryptoSuite::from_byte(data[offset])?;
        offset += 1;
        let (epoch, new_offset) = decode_s243(data, offset)?;
        offset = new_offset;
        let (route_handle, new_offset) = decode_handle243(data, offset)?;
        offset = new_offset;
        let (stream_id, new_offset) = decode_s243(data, offset)?;
        offset = new_offset;
        let (payload_len, new_offset) = decode_s243(data, offset)?;
        offset = new_offset;
        let payload_end = offset + payload_len as usize;

        if payload_end + 16 > data.len() {
            return Err(V4Error::new("truncated stream-open frame"));
        }

        let extra_len = data.len() - payload_end - 16;
        let default_semantic = match extra_len {
            0 => None,
            2 => Some((data[payload_end], data[payload_end + 1])),
            _ => {
                return Err(V4Error::new(
                    "canonical semantic tails must be either absent or exactly 2 bytes",
                ))
            }
        };

        let payload = data[offset..payload_end].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[data.len() - 16..]);

        Ok(StreamOpenFrame {
            control,
            suite,
            epoch,
            route_handle,
            stream_id,
            payload,
            default_semantic,
            tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_tag() -> [u8; 16] {
        [0u8; 16]
    }

    fn default_ctrl() -> Control243 {
        Control243 { profile: 0, lane: 0, evidence: 0, fallback: 0, routefmt: 1 }
    }

    #[test]
    fn hot_unary_roundtrip_direct_handle() {
        let frame = HotUnaryFrame {
            control: default_ctrl(),
            kind: FrameKind::UnaryReq,
            suite: CryptoSuite::ResearchNonapproved,
            epoch: 1,
            route_handle: HandleValue::Direct(18),
            payload: b"hello".to_vec(),
            tag: zero_tag(),
        };
        let serialized = frame.serialize().unwrap();
        let parsed = HotUnaryFrame::parse(&serialized).unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn hot_unary_roundtrip_utf8_handle() {
        let frame = HotUnaryFrame {
            control: Control243 { routefmt: 0, ..Default::default() },
            kind: FrameKind::Error,
            suite: CryptoSuite::Cnsa2Ready,
            epoch: 0,
            route_handle: HandleValue::Utf8("svc/op".to_string()),
            payload: vec![],
            tag: zero_tag(),
        };
        let serialized = frame.serialize().unwrap();
        let parsed = HotUnaryFrame::parse(&serialized).unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn hot_unary_rejects_stream_kind() {
        let frame = HotUnaryFrame {
            control: default_ctrl(),
            kind: FrameKind::UnaryReq,
            suite: CryptoSuite::ResearchNonapproved,
            epoch: 0,
            route_handle: HandleValue::Direct(0),
            payload: vec![],
            tag: zero_tag(),
        };
        let mut raw = frame.serialize().unwrap();
        raw[3] = FrameKind::StreamOpen.as_byte();
        let result = HotUnaryFrame::parse(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("hot unary frame received invalid kind"));
    }

    #[test]
    fn hot_unary_rejects_invalid_magic() {
        let frame = HotUnaryFrame {
            control: default_ctrl(),
            kind: FrameKind::UnaryReq,
            suite: CryptoSuite::ResearchNonapproved,
            epoch: 0,
            route_handle: HandleValue::Direct(0),
            payload: vec![],
            tag: zero_tag(),
        };
        let mut raw = frame.serialize().unwrap();
        raw[0] = 0x00;
        let result = HotUnaryFrame::parse(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("invalid magic"));
    }

    #[test]
    fn stream_open_roundtrip() {
        let frame = StreamOpenFrame {
            control: default_ctrl(),
            suite: CryptoSuite::ResearchNonapproved,
            epoch: 0,
            route_handle: HandleValue::Direct(5),
            stream_id: 1,
            payload: vec![],
            default_semantic: None,
            tag: zero_tag(),
        };
        let serialized = frame.serialize().unwrap();
        let parsed = StreamOpenFrame::parse(&serialized).unwrap();
        assert_eq!(parsed, frame);
    }
}
