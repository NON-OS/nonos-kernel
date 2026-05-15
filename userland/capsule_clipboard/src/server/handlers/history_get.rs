use crate::protocol::{Request, E_INVAL, E_RANGE, HDR_LEN, STATUS_LEN};
use crate::server::respond;
use crate::state::Clipboard;

pub fn handle(state: &Clipboard, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() != 4 {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let idx = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    let Some(e) = state.get_by_index(idx) else {
        let _ = respond::status(sender_pid, req, E_RANGE, tx);
        return;
    };
    let off = HDR_LEN + STATUS_LEN;
    tx[off..off + 4].copy_from_slice(&e.content_type.to_le_bytes());
    tx[off + 4..off + 8].copy_from_slice(&(e.len() as u32).to_le_bytes());
    tx[off + 8..off + 8 + e.len()].copy_from_slice(&e.data);
    let _ = respond::payload(sender_pid, req, 8 + e.len(), tx);
}
