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


use crate::network::onion::OnionError;
use crate::network::onion::cell::Cell;

pub struct NetworkSecurity;

impl NetworkSecurity {
    pub fn validate_cell_structure(cell: &Cell) -> Result<(), OnionError> {
        if cell.payload.len() > 509 {
            return Err(OnionError::InvalidCell);
        }

        if cell.circuit_id == 0 {
            return Err(OnionError::InvalidCell);
        }

        match cell.command {
            0..=15 | 128..=132 => Ok(()),
            _ => Err(OnionError::InvalidCell),
        }
    }

    pub fn check_connection_limits(active_connections: u32) -> Result<(), OnionError> {
        const MAX_CONNECTIONS: u32 = 10000;

        if active_connections > MAX_CONNECTIONS {
            return Err(OnionError::NetworkError);
        }

        Ok(())
    }

    pub fn validate_handshake_timing(start_time: u64, end_time: u64) -> Result<(), OnionError> {
        let duration = end_time - start_time;

        if duration < 100 || duration > 30000 {
            return Err(OnionError::SecurityViolation);
        }

        Ok(())
    }
}
