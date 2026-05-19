#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcLevel {
    L,
    M,
    Q,
    H,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QrSpec {
    pub version: u8,
    pub size: u8,
    pub ecc: EcLevel,
    pub mask: u8,
}

impl QrSpec {
    pub const fn v1(ecc: EcLevel, mask: u8) -> Self {
        Self { version: 1, size: 21, ecc, mask: mask & 0x07 }
    }
}
