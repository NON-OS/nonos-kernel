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

pub mod constants;
pub mod driver;
pub mod operations;
pub mod scsi;
pub mod state;
pub mod types;

pub use constants::{CBW_SIGNATURE, CSW_SIGNATURE, CBW_SIZE, CSW_SIZE, MAX_MSC_DEVICES};
pub use driver::{init, register_device};
pub use operations::{read_blocks, write_blocks, test_unit_ready};
pub use state::{device_count, is_init, get_device_info};
pub use types::{CommandBlockWrapper, MscDevice};
