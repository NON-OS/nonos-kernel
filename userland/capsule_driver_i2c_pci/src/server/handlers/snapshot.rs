use crate::constants::*;
use crate::driver::Driver;
use crate::protocol::{Request, E_OK};
use crate::server::respond;

pub fn handle(driver: &Driver, sender_pid: u32, req: &Request, out: &mut [u8]) {
    let values = [
        driver.comp_type,
        driver.comp_param,
        driver.enabled,
        driver.status,
        driver.regs.read32(IC_CON),
        driver.regs.read32(IC_INTR_MASK),
        driver.regs.read32(IC_RAW_INTR_STAT),
        driver.regs.read32(IC_TXFLR),
        driver.regs.read32(IC_RXFLR),
        driver.regs.read32(IC_ENABLE),
    ];
    let mut body = [0u8; 40];
    for (i, value) in values.iter().enumerate() {
        body[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}
