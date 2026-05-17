use crate::driver::Driver;
use crate::protocol::{Request, E_BUSY, E_INVAL, E_NACK, E_OK, E_TIMEOUT};
use crate::server::respond;
use crate::transaction::{probe, TransferError};

pub fn handle(driver: &Driver, sender_pid: u32, req: &Request, body: &[u8], out: &mut [u8]) {
    if body.len() != 1 || body[0] > 0x7F {
        let _ = respond::send(sender_pid, req, E_INVAL, &[], out);
        return;
    }
    match probe(driver, body[0]) {
        Ok(found) => {
            let payload = [found as u8];
            let _ = respond::send(sender_pid, req, E_OK, &payload, out);
        }
        Err(e) => {
            let _ = respond::send(sender_pid, req, errno(e), &[], out);
        }
    }
}

fn errno(err: TransferError) -> i32 {
    match err {
        TransferError::Busy => E_BUSY,
        TransferError::Timeout => E_TIMEOUT,
        TransferError::Nack => E_NACK,
        TransferError::Invalid => E_INVAL,
    }
}
