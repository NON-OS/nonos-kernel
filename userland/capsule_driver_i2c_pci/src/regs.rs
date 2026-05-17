#[derive(Clone, Copy)]
pub struct Regs {
    base: *mut u8,
}

impl Regs {
    pub const fn new(base: u64) -> Self {
        Self { base: base as *mut u8 }
    }

    pub fn read32(&self, offset: u64) -> u32 {
        unsafe { core::ptr::read_volatile(self.base.add(offset as usize) as *const u32) }
    }

    pub fn write32(&self, offset: u64, value: u32) {
        unsafe { core::ptr::write_volatile(self.base.add(offset as usize) as *mut u32, value) }
    }
}
