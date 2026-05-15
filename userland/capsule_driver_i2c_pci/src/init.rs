use crate::constants::*;
use crate::regs::Regs;

#[derive(Clone, Copy)]
pub struct InitState {
    pub comp_type: u32,
    pub comp_param: u32,
    pub enabled: u32,
    pub status: u32,
}

pub fn bring_up(regs: Regs) -> InitState {
    regs.write32(IC_INTR_MASK, 0);
    let _ = regs.read32(IC_CLR_INTR);
    let comp_type = regs.read32(IC_COMP_TYPE);
    let comp_param = regs.read32(IC_COMP_PARAM_1);
    let enabled = regs.read32(IC_ENABLE_STATUS);
    let status = regs.read32(IC_STATUS);
    InitState { comp_type, comp_param, enabled, status }
}

