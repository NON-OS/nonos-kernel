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

use alloc::vec::Vec;

#[inline]
pub unsafe fn read_msr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
pub unsafe fn write_msr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
}

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
    if base != 0 {
        Some(base)
    } else {
        None
    }
}

#[inline]
pub unsafe fn read_cr4() -> u64 {
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
    }
    cr4
}

#[inline]
pub unsafe fn write_cr4(value: u64) {
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) value);
    }
}

pub fn read_smram(base: u64, size: usize) -> Vec<u8> {
    let mut data = alloc::vec![0u8; size];
    for i in 0..size {
        let ptr = (base + i as u64) as *const u8;
        data[i] = unsafe { core::ptr::read_volatile(ptr) };
    }
    data
}
