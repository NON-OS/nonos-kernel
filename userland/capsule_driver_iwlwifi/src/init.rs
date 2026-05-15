// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use crate::constants::{
    ALL_INTS_MASK, APM_POLL_ITERS, CSR_FH_INT_STATUS, CSR_GP_CNTRL, CSR_HW_REV, CSR_INT,
    CSR_INT_COALESCING, CSR_INT_MASK, GP_CNTRL_INIT_DONE, GP_CNTRL_MAC_ACCESS_REQ,
    GP_CNTRL_MAC_CLOCK_READY, GP_CNTRL_XTAL_ON, INT_COALESCING_TIMEOUT, INT_MASK_DISABLED,
};
use crate::regs::Regs;

#[derive(Clone, Copy)]
pub struct InitState {
    pub hw_rev: u32,
    pub gp_cntrl: u32,
    pub rf_kill: bool,
}

pub fn bring_up(regs: Regs) -> Result<InitState, &'static str> {
    regs.set_bits(CSR_GP_CNTRL, GP_CNTRL_XTAL_ON);
    regs.set_bits(CSR_GP_CNTRL, GP_CNTRL_MAC_ACCESS_REQ | GP_CNTRL_INIT_DONE);
    if !regs.poll_set(CSR_GP_CNTRL, GP_CNTRL_MAC_CLOCK_READY, APM_POLL_ITERS) {
        return Err("iwlwifi: mac clock not ready");
    }
    regs.write32(CSR_INT_COALESCING, INT_COALESCING_TIMEOUT);
    regs.write32(CSR_INT, ALL_INTS_MASK);
    regs.write32(CSR_INT_MASK, INT_MASK_DISABLED);
    regs.write32(CSR_FH_INT_STATUS, ALL_INTS_MASK);
    let gp_cntrl = regs.read32(CSR_GP_CNTRL);
    Ok(InitState {
        hw_rev: regs.read32(CSR_HW_REV),
        gp_cntrl,
        rf_kill: gp_cntrl & GP_CNTRL_INIT_DONE == 0,
    })
}
