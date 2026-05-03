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

use super::types::NvmeController;
use crate::mem::allocator::allocate_pages;

pub fn nvme_identify_controller(controller: &mut NvmeController) -> Result<(), &'static str> {
    let data_pages = allocate_pages(1)?;
    let command =
        super::nvme_command_identify_controller::nvme_command_identify_controller(data_pages);

    super::nvme_submit_admin_command::nvme_submit_admin_command(controller, command)?;
    super::nvme_wait_for_completion::nvme_wait_for_completion(controller)?;

    let id_data = unsafe { core::slice::from_raw_parts(data_pages as *const u32, 1024) };
    controller.namespace_count = id_data[516];

    Ok(())
}
