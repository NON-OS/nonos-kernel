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

//! IPC capability flags.

/// IPC capability flags (bitfield)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum IpcCapability {
    /// Can send messages
    Send = 1 << 0,
    /// Can receive messages
    Receive = 1 << 1,
    /// Can create new channels
    CreateChannel = 1 << 2,
    /// Can send to kernel modules
    KernelAccess = 1 << 3,
    /// Can send unsigned messages
    AllowUnsigned = 1 << 4,
    /// Can send large messages (>64KB)
    LargeMessages = 1 << 5,
    /// Bypass rate limiting
    UnlimitedRate = 1 << 6,
    /// Can send to network stack
    NetworkAccess = 1 << 7,
    /// Can send to filesystem
    FilesystemAccess = 1 << 8,
    /// Can send to crypto subsystem
    CryptoAccess = 1 << 9,
    /// Can send to security monitor
    SecurityAccess = 1 << 10,
    /// Can broadcast to all modules
    Broadcast = 1 << 11,
}

impl IpcCapability {
    /// Get capability name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Send => "Send",
            Self::Receive => "Receive",
            Self::CreateChannel => "CreateChannel",
            Self::KernelAccess => "KernelAccess",
            Self::AllowUnsigned => "AllowUnsigned",
            Self::LargeMessages => "LargeMessages",
            Self::UnlimitedRate => "UnlimitedRate",
            Self::NetworkAccess => "NetworkAccess",
            Self::FilesystemAccess => "FilesystemAccess",
            Self::CryptoAccess => "CryptoAccess",
            Self::SecurityAccess => "SecurityAccess",
            Self::Broadcast => "Broadcast",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_capability_name() {
        assert_eq!(IpcCapability::Send.name(), "Send");
        assert_eq!(IpcCapability::KernelAccess.name(), "KernelAccess");
        assert_eq!(IpcCapability::Broadcast.name(), "Broadcast");
    }
}
