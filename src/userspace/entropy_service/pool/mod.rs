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

mod extract;
mod hardware;
mod mix;
mod state;
mod stats;

pub(super) use extract::{get_random_bytes, get_random_bytes_blocking};
pub(super) use hardware::{add_hardware_entropy, add_interrupt_entropy};
pub(super) use state::{add_entropy, get_entropy_available, init_pool};
pub(super) use stats::get_stats;
