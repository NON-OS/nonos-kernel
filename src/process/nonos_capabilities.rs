#![no_std]

extern crate alloc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilitySet {
    bits: u64,
}

impl CapabilitySet {
    #[inline] pub const fn new() -> Self { Self { bits: 0 } }
    #[inline] pub const fn from_bits(bits: u64) -> Self { Self { bits } }
    #[inline] pub const fn bits(&self) -> u64 { self.bits }
    #[inline] pub fn as_bytes(&self) -> [u8; 8] { self.bits.to_le_bytes() }

    // Base capabilities used by syscall gating
    #[inline] pub fn can_exit(&self) -> bool { (self.bits & (1<<0)) != 0 }
    #[inline] pub fn can_read(&self) -> bool { (self.bits & (1<<1)) != 0 }
    #[inline] pub fn can_write(&self) -> bool { (self.bits & (1<<2)) != 0 }
    #[inline] pub fn can_open_files(&self) -> bool { (self.bits & (1<<3)) != 0 }
    #[inline] pub fn can_close_files(&self) -> bool { (self.bits & (1<<4)) != 0 }
    #[inline] pub fn can_allocate_memory(&self) -> bool { (self.bits & (1<<5)) != 0 }
    #[inline] pub fn can_deallocate_memory(&self) -> bool { (self.bits & (1<<6)) != 0 }
    #[inline] pub fn can_load_modules(&self) -> bool { (self.bits & (1<<7)) != 0 }
    #[inline] pub fn can_use_crypto(&self) -> bool { (self.bits & (1<<8)) != 0 }
    #[inline] pub fn can_send_ipc(&self) -> bool { (self.bits & (1<<9)) != 0 }
    #[inline] pub fn can_receive_ipc(&self) -> bool { (self.bits & (1<<10)) != 0 }

    // Derived convenience bits (used by syscall gate)
    #[inline] pub fn can_stat(&self) -> bool { (self.bits & (1<<11)) != 0 || self.can_read() || self.can_open_files() }
    #[inline] pub fn can_seek(&self) -> bool { (self.bits & (1<<12)) != 0 || self.can_read() || self.can_write() }
    #[inline] pub fn can_modify_dirs(&self) -> bool { (self.bits & (1<<13)) != 0 || (self.can_open_files() && self.can_write()) }
    #[inline] pub fn can_unlink(&self) -> bool { (self.bits & (1<<14)) != 0 || self.can_write() }

    #[inline] pub fn add(&mut self, bit: u8) { self.bits |= 1u64 << bit; }
    #[inline] pub fn remove(&mut self, bit: u8) { self.bits &= !(1u64 << bit); }

    // Decentralized model follows with tokens can be verified via detached provenance later
    #[inline] pub fn verify_tokens(&self) -> Result<bool, &'static str> { Ok(true) }
    #[inline] pub fn requires_isolation(&self) -> bool { false }

    #[inline] pub fn has_capability(&self, cap: Capability) -> bool {
        match cap {
            Capability::FileAccess => self.can_read() || self.can_write() || self.can_open_files() || self.can_close_files(),
            Capability::MemoryManagement => self.can_allocate_memory() || self.can_deallocate_memory(),
            Capability::InterProcessComm => self.can_send_ipc() || self.can_receive_ipc(),
            Capability::CryptographicOps => self.can_use_crypto(),
            Capability::ModuleLoading => self.can_load_modules(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    FileAccess,
    MemoryManagement,
    InterProcessComm,
    CryptographicOps,
    ModuleLoading,
}
