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

#[derive(Debug, Clone)]
pub struct ProcessorInfo {
    pub apic_id: u32,
    pub processor_uid: u32,
    pub proximity_domain: u32,
    pub is_x2apic: bool,
    pub enabled: bool,
}

impl ProcessorInfo {
    pub fn new(apic_id: u32, processor_uid: u32, is_x2apic: bool, enabled: bool) -> Self {
        Self {
            apic_id,
            processor_uid,
            proximity_domain: 0,
            is_x2apic,
            enabled,
        }
    }
}
