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

mod error;
mod validate;
mod copy;
mod fault;

pub use error::UsercopyError;
pub use validate::{validate_user_read, validate_user_write};
pub use copy::{copy_from_user, copy_to_user, read_user_value, write_user_value};
pub use fault::{set_fault_handler, clear_fault_handler, try_recover_fault, did_fault, FaultRecovery};
