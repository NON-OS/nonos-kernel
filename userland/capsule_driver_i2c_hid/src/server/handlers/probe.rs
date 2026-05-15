use crate::protocol::{E_OK, Request};
use crate::server::respond;
use crate::setup::reprobe;
use crate::state::State;

pub fn handle(state: &mut State, sender_pid: u32, req: &Request, out: &mut [u8]) {
    reprobe(state);
    let body = [state.found() as u8, state.addr];
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}

