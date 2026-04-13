/// Frame kind discriminant for v4 frames (one byte in the frame header).
use super::error::V4Error;

/// All recognised v4 frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    UnaryReq = 0,
    UnaryRsp = 1,
    StreamOpen = 2,
    StreamData = 3,
    StreamClose = 4,
    BeaconCap = 5,
    BeaconIntent = 6,
    BeaconCommit = 7,
    Error = 8,
}

impl FrameKind {
    /// Decode a raw byte into a [`FrameKind`].
    pub fn from_byte(b: u8) -> Result<Self, V4Error> {
        match b {
            0 => Ok(FrameKind::UnaryReq),
            1 => Ok(FrameKind::UnaryRsp),
            2 => Ok(FrameKind::StreamOpen),
            3 => Ok(FrameKind::StreamData),
            4 => Ok(FrameKind::StreamClose),
            5 => Ok(FrameKind::BeaconCap),
            6 => Ok(FrameKind::BeaconIntent),
            7 => Ok(FrameKind::BeaconCommit),
            8 => Ok(FrameKind::Error),
            other => Err(V4Error::new(format!("invalid frame kind {other}"))),
        }
    }

    /// Encode this kind as a raw byte.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Returns `true` for kinds that may appear in a `HotUnaryFrame`.
    pub fn is_hot_unary(self) -> bool {
        matches!(self, FrameKind::UnaryReq | FrameKind::UnaryRsp | FrameKind::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_kinds() {
        for b in 0u8..=8 {
            let kind = FrameKind::from_byte(b).unwrap();
            assert_eq!(kind.as_byte(), b);
        }
    }

    #[test]
    fn invalid_kind_returns_error() {
        assert!(FrameKind::from_byte(9).is_err());
        assert!(FrameKind::from_byte(255).is_err());
    }

    #[test]
    fn hot_unary_kinds() {
        assert!(FrameKind::UnaryReq.is_hot_unary());
        assert!(FrameKind::UnaryRsp.is_hot_unary());
        assert!(FrameKind::Error.is_hot_unary());
        assert!(!FrameKind::StreamOpen.is_hot_unary());
    }
}
