use crate::constants::*;
use crate::regs::Regs;

#[derive(Clone, Copy)]
pub struct InitState {
    pub comp_type: u32,
    pub comp_param: u32,
    pub enabled: u32,
    pub status: u32,
}

pub fn bring_up(regs: Regs) -> Result<InitState, &'static str> {
    disable(regs)?;
    regs.write32(
        IC_CON,
        IC_CON_MASTER_MODE | IC_CON_SPEED_FAST | IC_CON_RESTART_EN | IC_CON_SLAVE_DISABLE,
    );
    regs.write32(IC_RX_TL, 0);
    regs.write32(IC_TX_TL, 0);
    regs.write32(IC_INTR_MASK, 0);
    let _ = regs.read32(IC_CLR_INTR);
    let comp_type = regs.read32(IC_COMP_TYPE);
    let comp_param = regs.read32(IC_COMP_PARAM_1);
    let enabled = regs.read32(IC_ENABLE_STATUS);
    let status = regs.read32(IC_STATUS);
    Ok(InitState { comp_type, comp_param, enabled, status })
}

fn disable(regs: Regs) -> Result<(), &'static str> {
    regs.write32(IC_ENABLE, 0);
    for _ in 0..TIMEOUT_ITERS {
        if regs.read32(IC_ENABLE_STATUS) & IC_ENABLE_ENABLE == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err("i2c-pci: controller disable timeout")
}
