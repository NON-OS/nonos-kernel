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

pub fn nvme_read_blocks(controller: &mut NvmeController, namespace: u32, lba: u64, blocks: u16, buffer: u64) -> Result<(), &'static str> {
    let queue_id = (lba % controller.io_queues.len() as u64) as usize;
    let command = super::nvme_command_read::nvme_command_read(namespace, lba, blocks, buffer);

    super::nvme_submit_io_command::nvme_submit_io_command(controller, queue_id, command)?;
    super::nvme_wait_for_io_completion::nvme_wait_for_io_completion(controller, queue_id)?;
    Ok(())
}