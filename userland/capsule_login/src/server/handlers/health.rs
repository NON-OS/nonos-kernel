use crate::protocol::Request;
use crate::server::respond;

pub fn handle(sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let _ = respond::status(sender_pid, req, 0, tx);
}
