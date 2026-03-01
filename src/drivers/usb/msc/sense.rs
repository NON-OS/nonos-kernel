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
pub struct SenseData {
    pub sense_key: u8,
    pub asc: u8,
    pub ascq: u8,
}

impl SenseData {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        Some(Self {
            sense_key: data[2] & 0x0F,
            asc: data[12],
            ascq: data[13],
        })
    }

    pub fn is_no_sense(&self) -> bool {
        self.sense_key == 0
    }

    pub fn is_recovered(&self) -> bool {
        self.sense_key == 1
    }

    pub fn is_not_ready(&self) -> bool {
        self.sense_key == 2
    }

    pub fn is_medium_error(&self) -> bool {
        self.sense_key == 3
    }

    pub fn is_hardware_error(&self) -> bool {
        self.sense_key == 4
    }

    pub fn is_unit_attention(&self) -> bool {
        self.sense_key == 6
    }
}
