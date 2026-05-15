use crate::driver::Driver;
use crate::protocol::{E_OK, Request};
use crate::server::respond;

pub fn handle(driver: &Driver, sender_pid: u32, req: &Request, out: &mut [u8]) {
    let mut body = [0u8; 64];
    body[0..8].copy_from_slice(&driver.device_id.to_le_bytes());
    body[8..10].copy_from_slice(&driver.pci_device.to_le_bytes());
    body[10..14].copy_from_slice(&driver.clock_hz.to_le_bytes());
    body[14..22].copy_from_slice(&driver.claim_epoch.to_le_bytes());
    body[22..30].copy_from_slice(&driver.mmio_grant.to_le_bytes());
    body[30..38].copy_from_slice(&driver.irq_grant.to_le_bytes());
    body[38..42].copy_from_slice(&driver.irq_vector.to_le_bytes());
    let name = driver.family.as_bytes();
    let n = core::cmp::min(name.len(), 22);
    body[42..42 + n].copy_from_slice(&name[..n]);
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}

