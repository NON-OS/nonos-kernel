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

use super::ports::{MASTER_DATA, SLAVE_DATA};

pub fn mask_irq(irq: u8) {
    // SAFETY: Direct hardware access to mask a specific IRQ line.
    unsafe {
        if irq < 8 {
            let mut data = Port::<u8>::new(MASTER_DATA);
            let current = data.read();
            data.write(current | (1 << irq));
        } else {
            let mut data = Port::<u8>::new(SLAVE_DATA);
            let current = data.read();
            data.write(current | (1 << (irq - 8)));
        }
    }
}

pub fn unmask_irq(irq: u8) {
    // SAFETY: Direct hardware access to unmask a specific IRQ line.
    unsafe {
        if irq < 8 {
            let mut data = Port::<u8>::new(MASTER_DATA);
            let current = data.read();
            data.write(current & !(1 << irq));
        } else {
            let mut data = Port::<u8>::new(SLAVE_DATA);
            let current = data.read();
            data.write(current & !(1 << (irq - 8)));
        }
    }
}

pub fn mask_all() {
    // SAFETY: Direct hardware access to mask all IRQ lines.
    unsafe {
        Port::<u8>::new(MASTER_DATA).write(0xFF);
        Port::<u8>::new(SLAVE_DATA).write(0xFF);
    }
}

pub fn unmask_all() {
    // SAFETY: Direct hardware access to unmask all IRQ lines.
    unsafe {
        Port::<u8>::new(MASTER_DATA).write(0x00);
        Port::<u8>::new(SLAVE_DATA).write(0x00);
    }
}

pub fn get_mask() -> (u8, u8) {
    // SAFETY: Direct hardware access to read current IRQ masks.
    unsafe {
        let master = Port::<u8>::new(MASTER_DATA).read();
        let slave = Port::<u8>::new(SLAVE_DATA).read();
        (master, slave)
    }
}

pub fn set_mask(master: u8, slave: u8) {
    // SAFETY: Direct hardware access to set IRQ masks.
    unsafe {
        Port::<u8>::new(MASTER_DATA).write(master);
        Port::<u8>::new(SLAVE_DATA).write(slave);
    }
}
