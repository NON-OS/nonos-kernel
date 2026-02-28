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

#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiStats {
    pub tables_found: u32,
    pub processors_found: u32,
    pub ioapics_found: u32,
    pub overrides_found: u32,
    pub numa_nodes: u32,
    pub pcie_segments: u32,
    pub parse_errors: u32,
}

impl AcpiStats {
    pub const fn new() -> Self {
        Self {
            tables_found: 0,
            processors_found: 0,
            ioapics_found: 0,
            overrides_found: 0,
            numa_nodes: 0,
            pcie_segments: 0,
            parse_errors: 0,
        }
    }
}
