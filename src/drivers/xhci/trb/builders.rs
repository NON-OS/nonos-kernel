// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::constants::*;
use super::base::Trb;

pub struct NormalTrbBuilder {
    trb: Trb,
}

impl NormalTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_NORMAL);
        Self { trb }
    }

    pub fn data_buffer(mut self, phys_addr: u64, length: u32) -> Self {
        self.trb.set_pointer(phys_addr);
        self.trb.set_transfer_length(length);
        self
    }

    pub fn ioc(mut self, ioc: bool) -> Self {
        self.trb.set_ioc(ioc);
        self
    }

    pub fn chain(mut self, chain: bool) -> Self {
        self.trb.set_chain(chain);
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for NormalTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SetupStageTrbBuilder {
    trb: Trb,
}

impl SetupStageTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_SETUP_STAGE);
        Self { trb }
    }

    pub fn setup_packet(
        mut self,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        w_length: u16,
    ) -> Self {
        self.trb.d0 =
            (bm_request_type as u32) | ((b_request as u32) << 8) | ((w_value as u32) << 16);
        self.trb.d1 = (w_index as u32) | ((w_length as u32) << 16);
        self
    }

    pub fn transfer_type(mut self, has_data: bool, is_in: bool) -> Self {
        let trt = if !has_data {
            TRT_NO_DATA
        } else if is_in {
            TRT_IN_DATA
        } else {
            TRT_OUT_DATA
        };
        self.trb.d2 = (self.trb.d2 & !0x30000) | trt;
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for SetupStageTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DataStageTrbBuilder {
    trb: Trb,
}

impl DataStageTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_DATA_STAGE);
        Self { trb }
    }

    pub fn data_buffer(mut self, phys_addr: u64, length: u32) -> Self {
        self.trb.set_pointer(phys_addr);
        self.trb.set_transfer_length(length);
        self
    }

    pub fn direction_in(mut self, is_in: bool) -> Self {
        if is_in {
            self.trb.d3 |= TRB_DIR_IN;
        } else {
            self.trb.d3 &= !TRB_DIR_IN;
        }
        self
    }

    pub fn ioc(mut self, ioc: bool) -> Self {
        self.trb.set_ioc(ioc);
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for DataStageTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StatusStageTrbBuilder {
    trb: Trb,
}

impl StatusStageTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_STATUS_STAGE);
        Self { trb }
    }

    pub fn direction_in(mut self, is_in: bool) -> Self {
        if is_in {
            self.trb.d3 |= TRB_DIR_IN;
        } else {
            self.trb.d3 &= !TRB_DIR_IN;
        }
        self
    }

    pub fn ioc(mut self, ioc: bool) -> Self {
        self.trb.set_ioc(ioc);
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for StatusStageTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LinkTrbBuilder {
    trb: Trb,
}

impl LinkTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_LINK);
        Self { trb }
    }

    pub fn target(mut self, phys_addr: u64) -> Self {
        self.trb.set_pointer(phys_addr);
        self
    }

    pub fn toggle_cycle(mut self, toggle: bool) -> Self {
        if toggle {
            self.trb.d3 |= LINK_TC;
        } else {
            self.trb.d3 &= !LINK_TC;
        }
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for LinkTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}
