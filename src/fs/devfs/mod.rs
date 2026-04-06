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

mod types;
mod inode;
mod mount;
mod registry;
mod major_minor;
pub mod char;
pub mod block;
pub mod pts;

pub use types::{DeviceNode, DeviceType, DeviceOps};
pub use inode::{devfs_lookup, devfs_readdir, devfs_mknod};
pub use mount::{devfs_mount, devfs_unmount, is_devfs_mounted};
pub use registry::{register_device, unregister_device, get_device};
pub use major_minor::{make_dev, major, minor};
