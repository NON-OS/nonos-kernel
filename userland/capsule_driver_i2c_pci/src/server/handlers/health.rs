use crate::protocol::{E_OK, Request};
use crate::server::respond;

pub fn handle(sender_pid: u32, req: &Request, out: &mut [u8]) {
    let body = [1u8];
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}

