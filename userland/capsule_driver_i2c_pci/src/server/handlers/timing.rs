use crate::constants::*;
use crate::driver::Driver;
use crate::protocol::{E_OK, Request};
use crate::server::respond;

pub fn handle(driver: &Driver, sender_pid: u32, req: &Request, out: &mut [u8]) {
    let values = [
        driver.clock_hz, driver.regs.read32(IC_SS_SCL_HCNT),
        driver.regs.read32(IC_SS_SCL_LCNT), driver.regs.read32(IC_FS_SCL_HCNT),
        driver.regs.read32(IC_FS_SCL_LCNT), driver.regs.read32(IC_RX_TL),
        driver.regs.read32(IC_TX_TL),
    ];
    let mut body = [0u8; 28];
    for (i, value) in values.iter().enumerate() {
        body[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}

