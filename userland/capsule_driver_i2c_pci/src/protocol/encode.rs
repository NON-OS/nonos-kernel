use crate::protocol::header::{HDR_LEN, MAGIC, VERSION};

pub fn response(op: u16, request_id: u64, errno: i32, body: &[u8], out: &mut [u8]) -> usize {
    let total = HDR_LEN + 4 + body.len();
    if out.len() < total {
        return 0;
    }
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&op.to_le_bytes());
    out[8..16].copy_from_slice(&request_id.to_le_bytes());
    out[16..20].copy_from_slice(&(4u32 + body.len() as u32).to_le_bytes());
    out[20..24].copy_from_slice(&errno.to_le_bytes());
    out[24..total].copy_from_slice(body);
    total
}
