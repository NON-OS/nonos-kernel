use crate::constants::*;
use crate::regs::Regs;
use crate::transaction::TransferError;

pub fn enable(regs: Regs) -> Result<(), TransferError> {
    regs.write32(IC_ENABLE, IC_ENABLE_ENABLE);
    wait_enable_state(regs, true)
}

pub fn disable(regs: Regs) -> Result<(), TransferError> {
    regs.write32(IC_ENABLE, 0);
    wait_enable_state(regs, false)
}

pub fn set_target(regs: Regs, addr: u8) -> Result<(), TransferError> {
    let was_enabled = regs.read32(IC_ENABLE) & IC_ENABLE_ENABLE != 0;
    if was_enabled {
        disable(regs)?;
    }
    regs.write32(IC_TAR, (addr & 0x7F) as u32);
    if was_enabled {
        enable(regs)?;
    }
    Ok(())
}

pub fn wait_idle(regs: Regs) -> Result<(), TransferError> {
    for _ in 0..TIMEOUT_ITERS {
        if regs.read32(IC_STATUS) & IC_STATUS_MST_ACTIVITY == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(TransferError::Busy)
}

fn wait_enable_state(regs: Regs, enabled: bool) -> Result<(), TransferError> {
    let want = if enabled { 1 } else { 0 };
    for _ in 0..TIMEOUT_ITERS {
        if regs.read32(IC_ENABLE_STATUS) & 1 == want {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(TransferError::Timeout)
}
