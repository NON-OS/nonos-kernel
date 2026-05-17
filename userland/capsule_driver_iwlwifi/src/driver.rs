// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use crate::firmware::{blob_for_family, stage_firmware, Family, FirmwareBlob, FirmwareStageState};
use crate::regs::Regs;

#[derive(Clone, Copy)]
pub struct Driver {
    pub device_id: u64,
    pub pci_device: u16,
    pub claim_epoch: u64,
    pub mmio_grant: u64,
    pub irq_grant: u64,
    pub dma_grant: u64,
    pub dma_user_va: u64,
    pub dma_device_addr: u64,
    pub dma_len: u64,
    pub hw_rev: u32,
    pub gp_cntrl: u32,
    pub rf_kill: bool,
    pub family: Family,
    pub regs: Regs,
    pub firmware_stage: FirmwareStageState,
}

impl Driver {
    pub fn firmware(&self) -> FirmwareBlob {
        blob_for_family(self.family)
    }

    pub fn stage_firmware(&mut self) -> Option<FirmwareStageState> {
        let fw = self.firmware();
        let state = stage_firmware(fw.bytes, self.dma_user_va, self.dma_len)?;
        self.firmware_stage = state;
        Some(state)
    }
}
