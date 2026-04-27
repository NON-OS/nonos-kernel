extern crate alloc;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

impl FrameType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x0 => Some(Self::Data),
            0x1 => Some(Self::Headers),
            0x2 => Some(Self::Priority),
            0x3 => Some(Self::RstStream),
            0x4 => Some(Self::Settings),
            0x5 => Some(Self::PushPromise),
            0x6 => Some(Self::Ping),
            0x7 => Some(Self::GoAway),
            0x8 => Some(Self::WindowUpdate),
            0x9 => Some(Self::Continuation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FrameFlags(pub u8);

impl FrameFlags {
    pub fn end_stream(&self) -> bool {
        self.0 & 0x1 != 0
    }
    pub fn end_headers(&self) -> bool {
        self.0 & 0x4 != 0
    }
    pub fn padded(&self) -> bool {
        self.0 & 0x8 != 0
    }
    pub fn priority(&self) -> bool {
        self.0 & 0x20 != 0
    }
    pub fn ack(&self) -> bool {
        self.0 & 0x1 != 0
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(frame_type: FrameType, stream_id: u32, payload: Vec<u8>) -> Self {
        Self { frame_type, flags: FrameFlags(0), stream_id, payload }
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = FrameFlags(flags);
        self
    }
}
