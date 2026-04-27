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

pub mod api;
pub mod constants;
pub mod device;
pub mod queue;
pub mod types;

#[cfg(test)]
#[cfg(test)]
pub mod tests;

pub use api::{
    capacity, discard, flush, get_device_id, init, is_initialized, is_read_only, read, write,
    write_zeroes,
};
pub use constants::{
    SECTOR_SIZE, VIRTIO_BLK_DEVICE_ID_MODERN, VIRTIO_BLK_DEVICE_ID_TRANSITIONAL,
    VIRTIO_BLK_VENDOR_ID,
};
pub use types::BlkError;
