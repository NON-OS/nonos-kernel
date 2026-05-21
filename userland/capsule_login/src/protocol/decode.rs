use super::{Request, E_BAD_LEN, E_BAD_MAGIC, E_BAD_VERSION, HDR_LEN, MAGIC, VERSION};

pub fn parse(buf: &[u8]) -> Result<(Request, &[u8]), (Request, i32)> {
    if buf.len() < HDR_LEN {
        return Err((empty_req(), E_BAD_LEN));
    }
    let op = match u16_at(buf, 6) {
        Some(v) => v,
        None => return Err((empty_req(), E_BAD_LEN)),
    };
    let flags = match u16_at(buf, 8) {
        Some(v) => v,
        None => return Err((empty_req(), E_BAD_LEN)),
    };
    let request_id = match u32_at(buf, 12) {
        Some(v) => v,
        None => return Err((empty_req(), E_BAD_LEN)),
    };
    let req = Request { op, flags, request_id };
    let Some(magic) = u32_at(buf, 0) else {
        return Err((req, E_BAD_LEN));
    };
    if magic != MAGIC {
        return Err((req, E_BAD_MAGIC));
    }
    let Some(version) = u16_at(buf, 4) else {
        return Err((req, E_BAD_LEN));
    };
    if version != VERSION {
        return Err((req, E_BAD_VERSION));
    }
    let Some(payload_len) = u32_at(buf, 16) else {
        return Err((req, E_BAD_LEN));
    };
    let payload_len = payload_len as usize;
    if HDR_LEN + payload_len != buf.len() {
        return Err((req, E_BAD_LEN));
    }
    Ok((req, &buf[HDR_LEN..]))
}

fn empty_req() -> Request {
    Request { op: 0, flags: 0, request_id: 0 }
}

fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}
