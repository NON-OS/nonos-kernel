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

mod constants;
mod cbw;
mod csw;
mod inquiry;
mod capacity;
mod sense;
mod state;
mod registry;
mod scsi;
mod commands;
mod driver;
mod api;

pub use cbw::CommandBlockWrapper;
pub use csw::CommandStatusWrapper;
pub use inquiry::InquiryResponse;
pub use capacity::StorageCapacity;
pub use sense::SenseData;
pub use state::MscDeviceState;
pub use registry::{get_msc_device, get_msc_devices};
pub use commands::{
    test_unit_ready, request_sense, inquiry, read_capacity_10, read_capacity_16,
    get_capacity, read_blocks, write_blocks, read_blocks_16, write_blocks_16,
    sync_cache, is_write_protected, eject_media, lock_media,
    read_blocks_auto, write_blocks_auto,
};
pub use driver::MscClassDriver;
pub use api::{
    query_capacity, query_all_capacities, read_sector, write_sector,
    flush_device, get_device_info, init_msc_driver,
};
