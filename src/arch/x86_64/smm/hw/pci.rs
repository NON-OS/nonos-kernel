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

pub fn read_pci_byte(bus: u8, device: u8, function: u8, offset: u16) -> u8 {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        x86_64::instructions::port::Port::<u32>::new(0xCF8).write(address);
        let data = x86_64::instructions::port::Port::<u32>::new(0xCFC).read();
        ((data >> ((offset & 3) * 8)) & 0xFF) as u8
    }
}

pub fn write_pci_byte(bus: u8, device: u8, function: u8, offset: u16, value: u8) {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        x86_64::instructions::port::Port::<u32>::new(0xCF8).write(address);
        let mut data = x86_64::instructions::port::Port::<u32>::new(0xCFC).read();
        let shift = (offset & 3) * 8;
        data &= !(0xFF << shift);
        data |= (value as u32) << shift;
        x86_64::instructions::port::Port::<u32>::new(0xCFC).write(data);
    }
}

pub fn read_pci_dword(bus: u8, device: u8, function: u8, offset: u16) -> u32 {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        x86_64::instructions::port::Port::<u32>::new(0xCF8).write(address);
        x86_64::instructions::port::Port::<u32>::new(0xCFC).read()
    }
}

pub fn get_acpi_pm_base() -> Option<u16> {
    let pm_base = read_pci_dword(0, 31, 0, 0x40);
    let base = (pm_base & 0xFF80) as u16;
    if base != 0 { Some(base) } else { None }
}
