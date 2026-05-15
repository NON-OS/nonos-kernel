use super::{Request, HDR_LEN, MAGIC, VERSION};

pub fn response_header(out: &mut [u8], req: &Request, payload_len: u32) {
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&req.op.to_le_bytes());
    out[8..10].copy_from_slice(&req.flags.to_le_bytes());
    out[10..12].fill(0);
    out[12..16].copy_from_slice(&req.request_id.to_le_bytes());
    out[16..20].copy_from_slice(&payload_len.to_le_bytes());
}

pub fn write_status(out: &mut [u8], status: i32) {
    out[HDR_LEN..HDR_LEN + 4].copy_from_slice(&status.to_le_bytes());
}
