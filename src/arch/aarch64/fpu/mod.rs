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

mod context;
mod current;
mod enable;
mod lazy;
mod pcb_slot;
mod restore;
mod save;
mod slot;
mod switch;

pub use context::FpSimdContext;
pub use enable::{disable, enable};
pub use lazy::try_enable_for_current_task;
pub use pcb_slot::PcbArchFpu;
pub use restore::restore;
pub use save::save;
pub use slot::FpSimdSlot;
pub use switch::{prepare_incoming, save_outgoing};
