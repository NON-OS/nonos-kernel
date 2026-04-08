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
pub struct InterruptOverride {
    pub source_irq: u8,
    pub gsi: u32,
    pub polarity: u8,
    pub trigger_mode: u8,
}

impl InterruptOverride {
    pub fn is_active_low(&self) -> bool {
        self.polarity == 3
    }

    pub fn is_level_triggered(&self) -> bool {
        self.trigger_mode == 3
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NmiConfig {
    pub processor_uid: u32,
    pub lint: u8,
    pub flags: u16,
}

impl NmiConfig {
    pub fn applies_to_all(&self) -> bool {
        self.processor_uid == u32::MAX
    }
}
