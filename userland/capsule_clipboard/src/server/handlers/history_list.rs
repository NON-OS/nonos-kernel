use crate::protocol::{Request, E_INVAL, HDR_LEN, MAX_DEPTH, STATUS_LEN};
use crate::server::respond;
use crate::state::Clipboard;

pub fn handle(state: &Clipboard, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if !body.is_empty() {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let off = HDR_LEN + STATUS_LEN;
    let mut count = 0u32;
    let mut cursor = off + 4;
    for e in state.iter().take(MAX_DEPTH) {
        tx[cursor..cursor + 4].copy_from_slice(&e.content_type.to_le_bytes());
        tx[cursor + 4..cursor + 8].copy_from_slice(&(e.len() as u32).to_le_bytes());
        cursor += 8;
        count += 1;
    }
    tx[off..off + 4].copy_from_slice(&count.to_le_bytes());
    let _ = respond::payload(sender_pid, req, 4 + count as usize * 8, tx);
}
