/// Nonos process capability bitset 

#![no_std]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilitySet {
    bits: u64,
}

impl CapabilitySet {
    #[inline]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    #[inline]
    pub const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    #[inline]
    pub const fn bits(&self) -> u64 {
        self.bits
    }

    // Mutators 
    #[inline]
    pub fn insert(&mut self, bit: u8) {
        self.bits |= 1u64 << bit;
    }

    #[inline]
    pub fn remove(&mut self, bit: u8) {
        self.bits &= !(1u64 << bit);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.bits = 0;
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    #[inline]
    pub fn is_superset_of(&self, other: &CapabilitySet) -> bool {
        (self.bits & other.bits) == other.bits
    }

    // Base capabilities used by syscall gating
    #[inline] pub fn can_exit(&self) -> bool { (self.bits & (1 << 0)) != 0 }
    #[inline] pub fn can_read(&self) -> bool { (self.bits & (1 << 1)) != 0 }
    #[inline] pub fn can_write(&self) -> bool { (self.bits & (1 << 2)) != 0 }
    #[inline] pub fn can_open_files(&self) -> bool { (self.bits & (1 << 3)) != 0 }
    #[inline] pub fn can_close_files(&self) -> bool { (self.bits & (1 << 4)) != 0 }
    #[inline] pub fn can_allocate_memory(&self) -> bool { (self.bits & (1 << 5)) != 0 }
    #[inline] pub fn can_deallocate_memory(&self) -> bool { (self.bits & (1 << 6)) != 0 }
    #[inline] pub fn can_load_modules(&self) -> bool { (self.bits & (1 << 7)) != 0 }
    #[inline] pub fn can_use_crypto(&self) -> bool { (self.bits & (1 << 8)) != 0 }
    #[inline] pub fn can_send_ipc(&self) -> bool { (self.bits & (1 << 9)) != 0 }
    #[inline] pub fn can_receive_ipc(&self) -> bool { (self.bits & (1 << 10)) != 0 }

    // Derived convenience bits for syscall gating
    #[inline]
    pub fn can_stat(&self) -> bool {
        (self.bits & (1 << 11)) != 0 || self.can_read() || self.can_open_files()
    }

    #[inline]
    pub fn can_seek(&self) -> bool {
        (self.bits & (1 << 12)) != 0 || self.can_read() || self.can_write()
    }

    #[inline]
    pub fn can_modify_dirs(&self) -> bool {
        (self.bits & (1 << 13)) != 0 || (self.can_open_files() && self.can_write())
    }

    #[inline]
    pub fn can_unlink(&self) -> bool {
        (self.bits & (1 << 14)) != 0 || self.can_write()
    }
}

/// Optional semantic grouping (helper) for policy code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Exit,              // bit 0
    Read,              // bit 1
    Write,             // bit 2
    OpenFiles,         // bit 3
    CloseFiles,        // bit 4
    AllocateMemory,    // bit 5
    DeallocateMemory,  // bit 6
    LoadModules,       // bit 7
    UseCrypto,         // bit 8
    SendIpc,           // bit 9
    ReceiveIpc,        // bit 10
    Stat,              // bit 11 (derived OR direct)
    Seek,              // bit 12 (derived OR direct)
    ModifyDirs,        // bit 13 (derived OR direct)
    Unlink,            // bit 14 (derived OR direct)
}

impl Capability {
    #[inline]
    pub const fn bit(self) -> u8 {
        match self {
            Capability::Exit => 0,
            Capability::Read => 1,
            Capability::Write => 2,
            Capability::OpenFiles => 3,
            Capability::CloseFiles => 4,
            Capability::AllocateMemory => 5,
            Capability::DeallocateMemory => 6,
            Capability::LoadModules => 7,
            Capability::UseCrypto => 8,
            Capability::SendIpc => 9,
            Capability::ReceiveIpc => 10,
            Capability::Stat => 11,
            Capability::Seek => 12,
            Capability::ModifyDirs => 13,
            Capability::Unlink => 14,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let c = CapabilitySet::new();
        assert!(c.is_empty());
        assert_eq!(c.bits(), 0);
    }

    #[test]
    fn insert_and_remove_bits() {
        let mut c = CapabilitySet::new();
        c.insert(Capability::Read.bit());
        c.insert(Capability::Write.bit());
        assert!(c.can_read());
        assert!(c.can_write());
        assert!(!c.can_open_files());

        c.remove(Capability::Write.bit());
        assert!(c.can_read());
        assert!(!c.can_write());
    }

    #[test]
    fn derived_permissions() {
        let mut c = CapabilitySet::new();
        // Without direct stat, read or open_files should grant stat
        c.insert(Capability::Read.bit());
        assert!(c.can_stat());
        assert!(c.can_seek()); // read implies seek

        c.remove(Capability::Read.bit());
        assert!(!c.can_stat());
        assert!(!c.can_seek());

        c.insert(Capability::OpenFiles.bit());
        assert!(c.can_stat());
        c.insert(Capability::Write.bit());
        assert!(c.can_seek());
        assert!(c.can_unlink());
        assert!(c.can_modify_dirs());
    }

    #[test]
    fn superset_logic() {
        let a = CapabilitySet::from_bits(0b1011);
        let b = CapabilitySet::from_bits(0b0011);
        assert!(a.is_superset_of(&b));
        assert!(!b.is_superset_of(&a));
    }
}
