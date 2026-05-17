use crate::protocol::{Request, E_NOT_FOUND, E_OK};
use crate::server::respond;
use crate::state::State;

pub fn handle(state: &State, sender_pid: u32, req: &Request, out: &mut [u8]) {
    if !state.found() {
        let _ = respond::send(sender_pid, req, E_NOT_FOUND, &[], out);
        return;
    }
    let mut body = [0u8; 34];
    body[0] = state.addr;
    body[2..4].copy_from_slice(&(state.descriptor_len as u16).to_le_bytes());
    body[4..4 + state.descriptor_len].copy_from_slice(&state.descriptor[..state.descriptor_len]);
    let _ = respond::send(sender_pid, req, E_OK, &body[..4 + state.descriptor_len], out);
}
