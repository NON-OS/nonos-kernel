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


use crate::network::onion::cell::Cell;
use crate::network::onion::OnionError;

pub(super) fn current_time_ms() -> u64 {
    crate::time::timestamp_millis()
}

pub(super) fn send_cell(cell: Cell) -> Result<(), OnionError> {
    let guard = crate::network::onion::get_onion_router().lock();
    let router = guard.as_ref().ok_or(OnionError::NetworkError)?;
    router.circuit_manager.transmit_cell(cell.circuit_id, cell)
}
