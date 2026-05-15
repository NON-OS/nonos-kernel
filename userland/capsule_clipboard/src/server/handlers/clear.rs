use crate::protocol::{Request, E_INVAL};
use crate::server::respond;
use crate::state::Clipboard;

pub fn handle(state: &mut Clipboard, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if !body.is_empty() {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    state.clear();
    let _ = respond::status(sender_pid, req, 0, tx);
}
