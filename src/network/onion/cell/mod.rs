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

mod cell_core;
mod cell_relay;
mod processor;
mod types;

pub use cell_core::Cell;
pub use cell_relay::{RelayCell, RelayHeader};
pub use processor::{CellProcessor, CellStatistics};
pub use types::{
    CellType, RelayCommand, CELL_HEADER_SIZE, CELL_PAYLOAD_SIZE, CELL_SIZE,
    MAX_VAR_CELL_PAYLOAD_SIZE, RELAY_HEADER_SIZE, RELAY_PAYLOAD_SIZE, VAR_CELL_HEADER_SIZE,
};
