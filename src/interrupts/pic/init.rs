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

use x86_64::instructions::port::Port;

use super::commands::{
    ICW1_ICW4, ICW1_INIT, ICW4_8086, MASTER_CASCADE_LINE, MASTER_VECTOR_OFFSET, SLAVE_CASCADE_ID,
    SLAVE_VECTOR_OFFSET,
};
use super::ports::{MASTER_COMMAND, MASTER_DATA, SLAVE_COMMAND, SLAVE_DATA};

pub fn init() {
    // SAFETY: Direct hardware access to 8259 PIC ports for initialization.
    // This sequence follows the Intel 8259A initialization protocol.
    unsafe {
        let mut master_cmd = Port::<u8>::new(MASTER_COMMAND);
        let mut master_data = Port::<u8>::new(MASTER_DATA);
        let mut slave_cmd = Port::<u8>::new(SLAVE_COMMAND);
        let mut slave_data = Port::<u8>::new(SLAVE_DATA);

        let saved_master_mask = master_data.read();
        let saved_slave_mask = slave_data.read();

        master_cmd.write(ICW1_INIT | ICW1_ICW4);
        slave_cmd.write(ICW1_INIT | ICW1_ICW4);

        master_data.write(MASTER_VECTOR_OFFSET);
        slave_data.write(SLAVE_VECTOR_OFFSET);

        master_data.write(MASTER_CASCADE_LINE);
        slave_data.write(SLAVE_CASCADE_ID);

        master_data.write(ICW4_8086);
        slave_data.write(ICW4_8086);

        master_data.write(saved_master_mask);
        slave_data.write(saved_slave_mask);
    }
}
