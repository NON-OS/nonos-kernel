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

mod master;
mod slave;
mod pair;
mod unix98;

pub use master::{master_read, master_write, master_ioctl, master_poll};
pub use slave::{slave_open, slave_close, slave_read, slave_write, slave_ioctl, slave_poll};
pub use pair::{create_pair, destroy_pair, get_pair, PtyPair};
pub use unix98::{unlock, get_pty_name, grantpt, ptsname};
