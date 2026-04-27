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

mod api;
mod capacity;
mod cbw;
mod commands;
mod constants;
mod csw;
mod driver;
mod inquiry;
mod registry;
mod scsi;
mod sense;
mod state;

pub use api::{
    flush_device, get_device_info, init_msc_driver, query_all_capacities, query_capacity,
    read_sector, write_sector,
};
pub use capacity::StorageCapacity;
pub use cbw::CommandBlockWrapper;
pub use commands::{
    eject_media, get_capacity, inquiry, is_write_protected, lock_media, read_blocks,
    read_blocks_16, read_blocks_auto, read_capacity_10, read_capacity_16, request_sense,
    sync_cache, test_unit_ready, write_blocks, write_blocks_16, write_blocks_auto,
};
pub use csw::CommandStatusWrapper;
pub use driver::MscClassDriver;
pub use inquiry::InquiryResponse;
pub use registry::{get_msc_device, get_msc_devices};
pub use sense::SenseData;
pub use state::MscDeviceState;
