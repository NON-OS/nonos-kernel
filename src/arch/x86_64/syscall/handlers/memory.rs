// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub fn syscall_mmap(addr: u64, length: u64, prot: u64, flags: u64, _fd: u64, _offset: u64) -> u64 {
    let result = crate::syscall::dispatch::file_io::handle_mmap(addr, length, prot, flags);
    result.value as u64
}

pub fn syscall_mprotect(addr: u64, len: u64, prot: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::memory::handle_mprotect(addr, len, prot);
    result.value as u64
}

pub fn syscall_munmap(addr: u64, length: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if addr == 0 || length == 0 {
        return (-22i64) as u64;
    }

    let proc = match crate::process::current_process() {
        Some(p) => p,
        None => return (-1i64) as u64,
    };

    let num_pages = (length + 4095) / 4096;
    for i in 0..num_pages {
        let page_addr = x86_64::VirtAddr::new(addr + i * 4096);
        let _ = crate::memory::paging::unmap_page(page_addr);
    }

    {
        let mut mem = proc.memory.lock();
        mem.vmas.retain(|vma| {
            let unmap_start = x86_64::VirtAddr::new(addr);
            let unmap_end = x86_64::VirtAddr::new(addr + length);
            !(vma.start >= unmap_start && vma.end <= unmap_end)
        });
    }

    0
}

pub fn syscall_brk(addr: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::memory::handle_brk(addr);
    result.value as u64
}
