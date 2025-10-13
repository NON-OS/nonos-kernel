/// IPC policy for ZeroState RAM-only profile

#![no_std]

use crate::syscall::capabilities::CapabilityToken;
use super::nonos_message::{IpcEnvelope, SecurityLevel};

pub struct IpcPolicy {
    max_message_bytes: usize,
    allow_unsigned: bool,
}

impl IpcPolicy {
    pub const fn new() -> Self {
        Self {
            max_message_bytes: 1 << 20, // 1 MiB cap per message
            allow_unsigned: true,
        }
    }

    #[inline]
    pub fn allow_message(&self, env: &IpcEnvelope, _token: &CapabilityToken) -> bool {
        if env.data.len() > self.max_message_bytes {
            return false;
        }
        match env.sec_level {
            SecurityLevel::None => self.allow_unsigned,
            SecurityLevel::Signed | SecurityLevel::Encrypted => true,
        }
    }

    #[inline]
    pub fn allow_channel(&self, _from: &str, _to: &str, _token: &CapabilityToken) -> bool {
        // default allow for RAM-only ZeroState.
        true
    }
}

impl Default for IpcPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// Global active policy used in ipc/mod.rs
#[no_mangle]
pub static mut ACTIVE_POLICY: IpcPolicy = IpcPolicy::new();
