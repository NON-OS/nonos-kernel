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

pub fn nvme_controller_initialize(controller: &mut NvmeController) -> Result<(), &'static str> {
    super::nvme_reset_controller::nvme_reset_controller(controller)?;
    super::nvme_setup_admin_queues::nvme_setup_admin_queues(controller)?;
    super::nvme_enable_controller::nvme_enable_controller(controller)?;
    super::nvme_identify_controller::nvme_identify_controller(controller)?;
    super::nvme_setup_io_queues::nvme_setup_io_queues(controller)?;
    Ok(())
}
