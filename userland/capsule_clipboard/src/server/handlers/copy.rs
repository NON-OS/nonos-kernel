use crate::protocol::{Request, E_INVAL, MAX_ENTRY_BYTES};
use crate::server::respond;
use crate::state::Clipboard;

pub fn handle(state: &mut Clipboard, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() < 8 {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let content_type = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let n = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
    if n > MAX_ENTRY_BYTES || body.len() != 8 + n {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    state.copy(content_type, &body[8..]);
    let _ = respond::status(sender_pid, req, 0, tx);
}
