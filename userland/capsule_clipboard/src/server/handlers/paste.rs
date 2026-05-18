use crate::protocol::{Request, E_INVAL, HDR_LEN, STATUS_LEN};
use crate::server::respond;
use crate::state::Clipboard;

pub fn handle(state: &Clipboard, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() != 4 {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let content_type = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let off = HDR_LEN + STATUS_LEN;
    if let Some(e) = state.latest_of_type(content_type) {
        tx[off..off + 4].copy_from_slice(&e.content_type.to_le_bytes());
        tx[off + 4..off + 8].copy_from_slice(&(e.len() as u32).to_le_bytes());
        tx[off + 8..off + 8 + e.len()].copy_from_slice(&e.data);
        let _ = respond::payload(sender_pid, req, 8 + e.len(), tx);
    } else {
        tx[off..off + 4].copy_from_slice(&content_type.to_le_bytes());
        tx[off + 4..off + 8].fill(0);
        let _ = respond::payload(sender_pid, req, 8, tx);
    }
}
