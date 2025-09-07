//! Memory layout constants and utilities

pub const PAGE_SIZE: usize = 4096;
pub const HUGE_2M: usize = 2 * 1024 * 1024;
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

pub fn align_down(addr: u64, alignment: u64) -> u64 {
    addr & !(alignment - 1)
}

pub fn align_up(addr: u64, alignment: u64) -> u64 {
    (addr + alignment - 1) & !(alignment - 1)
}

#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub kind: RegionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    Usable,
    Reserved,
    Bootloader,
}
