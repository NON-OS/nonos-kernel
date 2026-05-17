use super::{Request, E_BAD_LEN, E_BAD_MAGIC, E_BAD_VERSION, HDR_LEN, MAGIC, VERSION};

pub fn parse(buf: &[u8]) -> Result<(Request, &[u8]), (Request, i32)> {
    if buf.len() < HDR_LEN {
        return Err((empty_req(), E_BAD_LEN));
    }
    let req = Request {
        op: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
        flags: u16::from_le_bytes(buf[8..10].try_into().unwrap()),
        request_id: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
    };
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err((req, E_BAD_MAGIC));
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if version != VERSION {
        return Err((req, E_BAD_VERSION));
    }
    let payload_len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    if HDR_LEN + payload_len != buf.len() {
        return Err((req, E_BAD_LEN));
    }
    Ok((req, &buf[HDR_LEN..]))
}

fn empty_req() -> Request {
    Request { op: 0, flags: 0, request_id: 0 }
}
