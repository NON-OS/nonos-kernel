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

use super::error::PortError;
use super::manager_core::PortManager;
use super::types::PortRange;

pub static PORT_MANAGER: PortManager = PortManager::new();

pub fn init() -> Result<(), PortError> {
    PORT_MANAGER.initialize()
}

pub fn is_initialized() -> bool {
    PORT_MANAGER.is_initialized()
}

pub fn reserve_range(start: u16, count: u16) -> Result<(), PortError> {
    PORT_MANAGER.reserve_range(PortRange::new(start, count))
}

pub fn release_range(start: u16, count: u16) {
    PORT_MANAGER.release_range(PortRange::new(start, count));
}

pub fn is_reserved(port: u16) -> bool {
    PORT_MANAGER.is_reserved(port)
}
