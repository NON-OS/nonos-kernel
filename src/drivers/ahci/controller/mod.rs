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

mod accessors;
mod commands;
mod constructor;
mod encryption;
mod erase_methods;
mod helpers;
mod init;
mod init_ctrl;
mod io;
mod io_methods;
mod ncq;
mod ncq_fis;
mod ncq_read;
mod ncq_wait;
mod ncq_write;
mod secure_erase;
mod structure;
mod validation;

pub use helpers::{hdr_flags_for, RegisterAccess};
pub use structure::AhciController;
