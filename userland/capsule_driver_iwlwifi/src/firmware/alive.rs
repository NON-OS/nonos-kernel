use crate::constants::{ALIVE_POLL_ITERS, CSR_INT, INT_BIT_ALIVE};
use crate::regs::Regs;

pub fn wait_for_alive(regs: Regs) -> (bool, u32) {
    let mut last = 0u32;
    for _ in 0..ALIVE_POLL_ITERS {
        last = regs.read32(CSR_INT);
        if last & INT_BIT_ALIVE != 0 {
            regs.write32(CSR_INT, last);
            return (true, last);
        }
        core::hint::spin_loop();
    }
    (false, last)
}

