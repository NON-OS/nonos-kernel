use crate::driver::Driver;
use crate::firmware::alive::wait_for_alive;
use crate::protocol::{E_OK, E_TIMEOUT, Request};
use crate::server::respond;

pub fn handle(driver: &mut Driver, sender_pid: u32, req: &Request, out: &mut [u8]) {
    let (seen, last_int) = wait_for_alive(driver.regs);
    driver.firmware_stage.alive_seen = seen;
    driver.firmware_stage.last_int = last_int;
    let mut body = [0u8; 8];
    body[0] = seen as u8;
    body[4..8].copy_from_slice(&last_int.to_le_bytes());
    let errno = if seen { E_OK } else { E_TIMEOUT };
    let _ = respond::send(sender_pid, req, errno, &body, out);
}

