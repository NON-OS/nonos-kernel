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

mod bind;
pub mod dispatch;
mod poll;
mod records;
mod release;
mod slots;
mod types;

pub use bind::bind;
pub use poll::poll;
pub use release::{ack_grant, release_all_for_pid, release_for_device, unmap_grant};
pub use types::{IrqBindError, IrqBindRequest, IrqBindResult, IrqError, IrqGrant, IrqPollResult};
