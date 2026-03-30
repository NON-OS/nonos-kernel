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

#[derive(Debug, Clone, Copy)]
pub struct PageFaultInfo {
    pub address: u64,
    pub error_code: u64,
    pub is_write: bool,
    pub is_user: bool,
    pub is_instruction_fetch: bool,
    pub page_was_present: bool,
}

impl PageFaultInfo {
    pub const fn from_fault(address: u64, error_code: u64) -> Self {
        Self {
            address,
            error_code,
            is_write: error_code & 0x02 != 0,
            is_user: error_code & 0x04 != 0,
            is_instruction_fetch: error_code & 0x10 != 0,
            page_was_present: error_code & 0x01 != 0,
        }
    }

    pub const fn is_cow_fault(&self) -> bool {
        self.page_was_present && self.is_write
    }

    pub const fn is_demand_fault(&self) -> bool {
        !self.page_was_present
    }
}
