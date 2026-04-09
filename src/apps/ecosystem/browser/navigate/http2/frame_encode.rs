extern crate alloc;
use alloc::vec::Vec;
use super::frame_types::Frame;

pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let len = frame.payload.len();
    let mut buf = Vec::with_capacity(9 + len);
    buf.push((len >> 16) as u8);
    buf.push((len >> 8) as u8);
    buf.push(len as u8);
    buf.push(frame.frame_type as u8);
    buf.push(frame.flags.0);
    let sid = frame.stream_id & 0x7FFF_FFFF;
    buf.push((sid >> 24) as u8);
    buf.push((sid >> 16) as u8);
    buf.push((sid >> 8) as u8);
    buf.push(sid as u8);
    buf.extend_from_slice(&frame.payload);
    buf
}

pub fn encode_settings_frame(settings: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(settings.len() * 6);
    for &(id, val) in settings {
        payload.push((id >> 8) as u8);
        payload.push(id as u8);
        payload.push((val >> 24) as u8);
        payload.push((val >> 16) as u8);
        payload.push((val >> 8) as u8);
        payload.push(val as u8);
    }
    let frame = Frame::new(super::frame_types::FrameType::Settings, 0, payload);
    encode_frame(&frame)
}

pub fn encode_window_update(stream_id: u32, increment: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4);
    let inc = increment & 0x7FFF_FFFF;
    payload.push((inc >> 24) as u8);
    payload.push((inc >> 16) as u8);
    payload.push((inc >> 8) as u8);
    payload.push(inc as u8);
    let frame = Frame::new(super::frame_types::FrameType::WindowUpdate, stream_id, payload);
    encode_frame(&frame)
}

pub fn encode_ping(data: &[u8; 8], ack: bool) -> Vec<u8> {
    let flags = if ack { 0x1 } else { 0 };
    let frame = Frame::new(super::frame_types::FrameType::Ping, 0, data.to_vec()).with_flags(flags);
    encode_frame(&frame)
}
