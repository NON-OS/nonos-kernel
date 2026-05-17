use crate::protocol::header::{Request, HDR_LEN, MAGIC, VERSION};

pub fn parse(buf: &[u8]) -> Option<(Request, &[u8])> {
    if buf.len() < HDR_LEN {
        return None;
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    let version = u16::from_le_bytes(buf[4..6].try_into().ok()?);
    if magic != MAGIC || version != VERSION {
        return None;
    }
    let op = u16::from_le_bytes(buf[6..8].try_into().ok()?);
    let request_id = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    let len = u32::from_le_bytes(buf[16..20].try_into().ok()?) as usize;
    if HDR_LEN + len > buf.len() {
        return None;
    }
    Some((Request { op, request_id }, &buf[HDR_LEN..HDR_LEN + len]))
}
