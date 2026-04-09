extern crate alloc;
use alloc::vec::Vec;
use super::frame_types::{Frame, FrameType, FrameFlags};

pub fn decode_frame(data: &[u8]) -> Option<(Frame, usize)> {
    if data.len() < 9 { return None; }
    let len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);
    if data.len() < 9 + len { return None; }
    let frame_type = FrameType::from_u8(data[3])?;
    let flags = FrameFlags(data[4]);
    let stream_id = ((data[5] as u32 & 0x7F) << 24) | ((data[6] as u32) << 16)
        | ((data[7] as u32) << 8) | (data[8] as u32);
    let payload = data[9..9 + len].to_vec();
    Some((Frame { frame_type, flags, stream_id, payload }, 9 + len))
}

pub fn decode_settings_payload(payload: &[u8]) -> Vec<(u16, u32)> {
    let mut settings = Vec::new();
    let mut i = 0;
    while i + 6 <= payload.len() {
        let id = ((payload[i] as u16) << 8) | (payload[i + 1] as u16);
        let val = ((payload[i + 2] as u32) << 24) | ((payload[i + 3] as u32) << 16)
            | ((payload[i + 4] as u32) << 8) | (payload[i + 5] as u32);
        settings.push((id, val));
        i += 6;
    }
    settings
}

pub fn decode_window_update_payload(payload: &[u8]) -> Option<u32> {
    if payload.len() < 4 { return None; }
    Some(((payload[0] as u32 & 0x7F) << 24) | ((payload[1] as u32) << 16)
        | ((payload[2] as u32) << 8) | (payload[3] as u32))
}
