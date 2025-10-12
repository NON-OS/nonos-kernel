/// Syscall capability token used by the syscall gate. 

#![no_std]

#[derive(Clone, Copy)]
pub struct CapabilityToken {
    bits: u64,
}

impl CapabilityToken {
    pub const fn new(bits: u64) -> Self {
        Self { bits }
    }

    /// Enable a capability bit.
    #[inline]
    pub const fn with(mut self, bit: u8) -> Self {
        self.bits |= 1u64 << bit;
        self
    }

    /// Check a capability bit.
    #[inline]
    pub const fn has(self, bit: u8) -> bool {
        (self.bits & (1u64 << bit)) != 0
    }
}

/// Map the current process capability view into a syscall token.
/// Falls back to a safe, permissive ZeroState baseline if unavailable

#[inline]
pub fn current_caps() -> CapabilityToken {
    let pcaps = crate::process::get_current_process_capabilities();

    // Bit layout 
    let mut tok = CapabilityToken::new(0);

    if pcaps.can_exit()             { tok = tok.with(0); }
    if pcaps.can_read()             { tok = tok.with(1); }
    if pcaps.can_write()            { tok = tok.with(2); }
    if pcaps.can_open_files()       { tok = tok.with(3); }
    if pcaps.can_close_files()      { tok = tok.with(4); }
    // The process layer doesn't expose a dedicated "stat" bit; allow when open/read is allowed.
    if pcaps.can_open_files() || pcaps.can_read() { tok = tok.with(5); }
    // Seek allowed if read or write is allowed 
    if pcaps.can_read() || pcaps.can_write() { tok = tok.with(6); }
    if pcaps.can_allocate_memory()  { tok = tok.with(7); }
    if pcaps.can_deallocate_memory(){ tok = tok.with(8); }
    // Directory modifications: re-use open_files + write as a proxy
    if pcaps.can_open_files() && pcaps.can_write() { tok = tok.with(9); }
    // Unlink requires write permission.
    if pcaps.can_write()            { tok = tok.with(10); }

    tok
}

impl CapabilityToken {
    // Accessors 

    #[inline] pub fn can_exit(self) -> bool { self.has(0) }
    #[inline] pub fn can_read(self) -> bool { self.has(1) }
    #[inline] pub fn can_write(self) -> bool { self.has(2) }
    #[inline] pub fn can_open_files(self) -> bool { self.has(3) }
    #[inline] pub fn can_close_files(self) -> bool { self.has(4) }
    #[inline] pub fn can_stat(self) -> bool { self.has(5) }
    #[inline] pub fn can_seek(self) -> bool { self.has(6) }

    #[inline] pub fn can_allocate_memory(self) -> bool { self.has(7) }
    #[inline] pub fn can_deallocate_memory(self) -> bool { self.has(8) }

    #[inline] pub fn can_modify_dirs(self) -> bool { self.has(9) }
    #[inline] pub fn can_unlink(self) -> bool { self.has(10) }
}
