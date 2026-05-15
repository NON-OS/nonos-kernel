use crate::protocol::{E_OK, Request};
use crate::server::respond;
use crate::state::State;

pub fn handle(state: &State, sender_pid: u32, req: &Request, out: &mut [u8]) {
    let mut body = [0u8; 24];
    body[0] = state.found() as u8;
    body[1] = state.addr;
    body[4..8].copy_from_slice(&state.i2c_port.to_le_bytes());
    body[8..12].copy_from_slice(&state.i2c_pid.to_le_bytes());
    body[16..24].copy_from_slice(&state.probes.to_le_bytes());
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}

