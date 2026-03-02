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

mod commands;
mod eoi;
mod init;
mod mask;
mod ports;

pub use commands::{
    EOI, ICW1_ICW4, ICW1_INIT, ICW4_8086, MASTER_CASCADE_LINE, MASTER_VECTOR_OFFSET,
    SLAVE_CASCADE_ID, SLAVE_VECTOR_OFFSET,
};
pub use eoi::send_eoi;
pub use init::init;
pub use mask::{get_mask, mask_all, mask_irq, set_mask, unmask_all, unmask_irq};
pub use ports::{MASTER_COMMAND, MASTER_DATA, SLAVE_COMMAND, SLAVE_DATA};
