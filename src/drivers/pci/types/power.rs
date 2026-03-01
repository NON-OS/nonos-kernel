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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerManagementInfo {
    pub offset: u8,
    pub version: u8,
    pub pme_clock: bool,
    pub dsi: bool,
    pub aux_current: u8,
    pub d1_support: bool,
    pub d2_support: bool,
    pub pme_support: u8,
    pub current_state: u8,
    pub no_soft_reset: bool,
    pub pme_enabled: bool,
    pub pme_status: bool,
}

impl PowerManagementInfo {
    pub fn supports_d1(&self) -> bool {
        self.d1_support
    }

    pub fn supports_d2(&self) -> bool {
        self.d2_support
    }

    pub fn supports_pme_from_d0(&self) -> bool {
        (self.pme_support & (1 << 0)) != 0
    }

    pub fn supports_pme_from_d1(&self) -> bool {
        (self.pme_support & (1 << 1)) != 0
    }

    pub fn supports_pme_from_d2(&self) -> bool {
        (self.pme_support & (1 << 2)) != 0
    }

    pub fn supports_pme_from_d3_hot(&self) -> bool {
        (self.pme_support & (1 << 3)) != 0
    }

    pub fn supports_pme_from_d3_cold(&self) -> bool {
        (self.pme_support & (1 << 4)) != 0
    }

    pub fn state_name(&self) -> &'static str {
        match self.current_state {
            0 => "D0",
            1 => "D1",
            2 => "D2",
            3 => "D3hot",
            _ => "Unknown",
        }
    }
}
