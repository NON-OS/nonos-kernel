// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//! Capability-Based Security System
//!
//! Fine-grained privilege control with capability inheritance and delegation

use alloc::{collections::BTreeSet, string::String, vec::Vec, format};
use core::fmt;

/// System capabilities for fine-grained access control
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    // Process control capabilities
    SysAdmin,        // CAP_SYS_ADMIN - full system administration
    SysNice,         // CAP_SYS_NICE - modify process priority/scheduling
    SysTime,         // CAP_SYS_TIME - modify system time
    SysResource,     // CAP_SYS_RESOURCE - override resource limits
    SysModule,       // CAP_SYS_MODULE - load/unload kernel modules
    
    // File system capabilities
    DacOverride,     // CAP_DAC_OVERRIDE - bypass file permission checks
    DacReadSearch,   // CAP_DAC_READ_SEARCH - bypass file read permission checks
    FOwner,          // CAP_FOWNER - bypass permission checks for file ownership
    FSetId,          // CAP_FSETID - don't clear set-user-ID and set-group-ID bits
    
    // Network capabilities
    NetAdmin,        // CAP_NET_ADMIN - network administration
    NetBindService,  // CAP_NET_BIND_SERVICE - bind to privileged ports
    NetBroadcast,    // CAP_NET_BROADCAST - make socket broadcasts
    NetRaw,          // CAP_NET_RAW - use raw sockets
    
    // IPC capabilities
    IpcLock,         // CAP_IPC_LOCK - lock memory
    IpcOwner,        // CAP_IPC_OWNER - bypass permission checks for IPC
    
    // Process capabilities
    Kill,            // CAP_KILL - send signals to arbitrary processes
    SetUid,          // CAP_SETUID - set user ID
    SetGid,          // CAP_SETGID - set group ID
    SetPCap,         // CAP_SETPCAP - transfer capabilities
    
    // Security capabilities
    SysChroot,       // CAP_SYS_CHROOT - use chroot()
    SysPtrace,       // CAP_SYS_PTRACE - trace arbitrary processes
    AuditWrite,      // CAP_AUDIT_WRITE - write to audit log
    AuditControl,    // CAP_AUDIT_CONTROL - configure audit subsystem
    
    // Device capabilities
    Mknod,           // CAP_MKNOD - create device files
    SysRawIO,        // CAP_SYS_RAWIO - perform I/O port operations
    SysBoot,         // CAP_SYS_BOOT - reboot system
    
    // Advanced security capabilities
    MacAdmin,        // CAP_MAC_ADMIN - MAC security administration
    MacOverride,     // CAP_MAC_OVERRIDE - override MAC restrictions
    
    // Container capabilities
    SysContainer,    // Custom: container management
    SysNamespace,    // Custom: namespace operations
    
    // Hardware capabilities
    SysHardware,     // Custom: direct hardware access
    SysCrypto,       // Custom: cryptographic operations
    
    // Custom application capabilities
    Custom(String),  // Custom capability by name
}

impl Capability {
    /// Convert capability to u8 for serialization
    pub fn to_u8(&self) -> u8 {
        match self {
            Capability::SysAdmin => 0x01,
            Capability::SysNice => 0x02,
            Capability::SysTime => 0x03,
            Capability::SysResource => 0x04,
            Capability::SysModule => 0x05,
            Capability::DacOverride => 0x06,
            Capability::DacReadSearch => 0x07,
            Capability::FOwner => 0x08,
            Capability::FSetId => 0x09,
            Capability::NetAdmin => 0x0A,
            Capability::NetBindService => 0x0B,
            Capability::NetBroadcast => 0x0C,
            Capability::NetRaw => 0x0D,
            Capability::IpcLock => 0x0E,
            Capability::IpcOwner => 0x0F,
            Capability::Kill => 0x10,
            Capability::SetUid => 0x11,
            Capability::SetGid => 0x12,
            Capability::SetPCap => 0x13,
            Capability::SysChroot => 0x14,
            Capability::SysPtrace => 0x15,
            Capability::AuditWrite => 0x16,
            Capability::AuditControl => 0x17,
            Capability::Mknod => 0x18,
            Capability::SysRawIO => 0x19,
            Capability::SysBoot => 0x1A,
            Capability::MacAdmin => 0x1B,
            Capability::MacOverride => 0x1C,
            Capability::SysContainer => 0x1D,
            Capability::SysNamespace => 0x1E,
            Capability::SysHardware => 0x1F,
            Capability::SysCrypto => 0x20,
            Capability::Custom(_) => 0xFF, // Custom capabilities. We use reserved value
        }
    }
}

impl TryFrom<u8> for Capability {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Capability::SysAdmin),
            0x02 => Ok(Capability::SysNice),
            0x03 => Ok(Capability::SysTime),
            0x04 => Ok(Capability::SysResource),
            0x05 => Ok(Capability::SysModule),
            0x06 => Ok(Capability::DacOverride),
            0x07 => Ok(Capability::DacReadSearch),
            0x08 => Ok(Capability::FOwner),
            0x09 => Ok(Capability::FSetId),
            0x0A => Ok(Capability::NetAdmin),
            0x0B => Ok(Capability::NetBindService),
            0x0C => Ok(Capability::NetBroadcast),
            0x0D => Ok(Capability::NetRaw),
            0x0E => Ok(Capability::IpcLock),
            0x0F => Ok(Capability::IpcOwner),
            0x10 => Ok(Capability::Kill),
            0x11 => Ok(Capability::SetUid),
            0x12 => Ok(Capability::SetGid),
            0x13 => Ok(Capability::SetPCap),
            0x14 => Ok(Capability::SysChroot),
            0x15 => Ok(Capability::SysPtrace),
            0x16 => Ok(Capability::AuditWrite),
            0x17 => Ok(Capability::AuditControl),
            0x18 => Ok(Capability::Mknod),
            0x19 => Ok(Capability::SysRawIO),
            0x1A => Ok(Capability::SysBoot),
            0x1B => Ok(Capability::MacAdmin),
            0x1C => Ok(Capability::MacOverride),
            0x1D => Ok(Capability::SysContainer),
            0x1E => Ok(Capability::SysNamespace),
            0x1F => Ok(Capability::SysHardware),
            0x20 => Ok(Capability::SysCrypto),
            _ => Err("Invalid capability value"),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::SysAdmin => write!(f, "CAP_SYS_ADMIN"),
            Capability::SysNice => write!(f, "CAP_SYS_NICE"),
            Capability::SysTime => write!(f, "CAP_SYS_TIME"),
            Capability::SysResource => write!(f, "CAP_SYS_RESOURCE"),
            Capability::SysModule => write!(f, "CAP_SYS_MODULE"),
            Capability::DacOverride => write!(f, "CAP_DAC_OVERRIDE"),
            Capability::DacReadSearch => write!(f, "CAP_DAC_READ_SEARCH"),
            Capability::FOwner => write!(f, "CAP_FOWNER"),
            Capability::FSetId => write!(f, "CAP_FSETID"),
            Capability::NetAdmin => write!(f, "CAP_NET_ADMIN"),
            Capability::NetBindService => write!(f, "CAP_NET_BIND_SERVICE"),
            Capability::NetBroadcast => write!(f, "CAP_NET_BROADCAST"),
            Capability::NetRaw => write!(f, "CAP_NET_RAW"),
            Capability::IpcLock => write!(f, "CAP_IPC_LOCK"),
            Capability::IpcOwner => write!(f, "CAP_IPC_OWNER"),
            Capability::Kill => write!(f, "CAP_KILL"),
            Capability::SetUid => write!(f, "CAP_SETUID"),
            Capability::SetGid => write!(f, "CAP_SETGID"),
            Capability::SetPCap => write!(f, "CAP_SETPCAP"),
            Capability::SysChroot => write!(f, "CAP_SYS_CHROOT"),
            Capability::SysPtrace => write!(f, "CAP_SYS_PTRACE"),
            Capability::AuditWrite => write!(f, "CAP_AUDIT_WRITE"),
            Capability::AuditControl => write!(f, "CAP_AUDIT_CONTROL"),
            Capability::Mknod => write!(f, "CAP_MKNOD"),
            Capability::SysRawIO => write!(f, "CAP_SYS_RAWIO"),
            Capability::SysBoot => write!(f, "CAP_SYS_BOOT"),
            Capability::MacAdmin => write!(f, "CAP_MAC_ADMIN"),
            Capability::MacOverride => write!(f, "CAP_MAC_OVERRIDE"),
            Capability::SysContainer => write!(f, "CAP_SYS_CONTAINER"),
            Capability::SysNamespace => write!(f, "CAP_SYS_NAMESPACE"),
            Capability::SysHardware => write!(f, "CAP_SYS_HARDWARE"),
            Capability::SysCrypto => write!(f, "CAP_SYS_CRYPTO"),
            Capability::Custom(name) => write!(f, "CAP_{}", name.to_uppercase()),
        }
    }
}

/// Capability set with inheritance and delegation
#[derive(Debug, Clone)]
pub struct CapabilitySet {
    // Effective capabilities (currently active)
    pub effective: BTreeSet<Capability>,
    
    // Permitted capabilities (can be made effective)
    pub permitted: BTreeSet<Capability>,
    
    // Inheritable capabilities (passed to child processes)
    pub inheritable: BTreeSet<Capability>,
    
    // Bounding set (limits what can be gained)
    pub bounding: BTreeSet<Capability>,
    
    // Ambient capabilities (preserved across exec)
    pub ambient: BTreeSet<Capability>,
}

impl CapabilitySet {
    /// Create new capability set for root user
    pub fn new_root() -> Self {
        let all_caps = Self::all_capabilities();
        
        CapabilitySet {
            effective: all_caps.clone(),
            permitted: all_caps.clone(),
            inheritable: all_caps.clone(),
            bounding: all_caps.clone(),
            ambient: BTreeSet::new(), // Ambient starts empty
        }
    }
    
    /// Create new capability set for regular user
    pub fn new_user() -> Self {
        let user_caps = Self::default_user_capabilities();
        
        CapabilitySet {
            effective: user_caps.clone(),
            permitted: user_caps.clone(),
            inheritable: BTreeSet::new(),
            bounding: Self::all_capabilities(),
            ambient: BTreeSet::new(),
        }
    }
    
    /// Create empty capability set
    pub fn new_empty() -> Self {
        CapabilitySet {
            effective: BTreeSet::new(),
            permitted: BTreeSet::new(),
            inheritable: BTreeSet::new(),
            bounding: BTreeSet::new(),
            ambient: BTreeSet::new(),
        }
    }
    
    /// Get all available system capabilities
    pub fn all_capabilities() -> BTreeSet<Capability> {
        let mut caps = BTreeSet::new();
        
        // System administration
        caps.insert(Capability::SysAdmin);
        caps.insert(Capability::SysNice);
        caps.insert(Capability::SysTime);
        caps.insert(Capability::SysResource);
        caps.insert(Capability::SysModule);
        caps.insert(Capability::SysBoot);
        caps.insert(Capability::SysRawIO);
        caps.insert(Capability::SysChroot);
        caps.insert(Capability::SysPtrace);
        
        // File system
        caps.insert(Capability::DacOverride);
        caps.insert(Capability::DacReadSearch);
        caps.insert(Capability::FOwner);
        caps.insert(Capability::FSetId);
        caps.insert(Capability::Mknod);
        
        // Network
        caps.insert(Capability::NetAdmin);
        caps.insert(Capability::NetBindService);
        caps.insert(Capability::NetBroadcast);
        caps.insert(Capability::NetRaw);
        
        // Process control
        caps.insert(Capability::Kill);
        caps.insert(Capability::SetUid);
        caps.insert(Capability::SetGid);
        caps.insert(Capability::SetPCap);
        
        // IPC
        caps.insert(Capability::IpcLock);
        caps.insert(Capability::IpcOwner);
        
        // Security
        caps.insert(Capability::AuditWrite);
        caps.insert(Capability::AuditControl);
        caps.insert(Capability::MacAdmin);
        caps.insert(Capability::MacOverride);
        
        // Advanced features
        caps.insert(Capability::SysContainer);
        caps.insert(Capability::SysNamespace);
        caps.insert(Capability::SysHardware);
        caps.insert(Capability::SysCrypto);
        
        caps
    }
    
    /// Get default capabilities for regular users
    pub fn default_user_capabilities() -> BTreeSet<Capability> {
        let mut caps = BTreeSet::new();
        
        // Basic user capabilities
        caps.insert(Capability::Kill); // Can send signals to own processes
        caps.insert(Capability::AuditWrite); // Can write to audit log
        
        caps
    }
    
    /// Check if capability is in effective set
    pub fn has_capability(&self, cap_name: &str) -> bool {
        // Handle string-based capability lookup
        let capability = match cap_name {
            "CAP_SYS_ADMIN" => Capability::SysAdmin,
            "CAP_SYS_NICE" => Capability::SysNice,
            "CAP_SYS_TIME" => Capability::SysTime,
            "CAP_DAC_OVERRIDE" => Capability::DacOverride,
            "CAP_NET_ADMIN" => Capability::NetAdmin,
            "CAP_NET_BIND_SERVICE" => Capability::NetBindService,
            "CAP_KILL" => Capability::Kill,
            "CAP_SETUID" => Capability::SetUid,
            "CAP_SETGID" => Capability::SetGid,
            _ => return false, // Unknown capability
        };
        
        self.effective.contains(&capability)
    }
    
    /// Check if specific capability is effective
    pub fn has_effective(&self, cap: &Capability) -> bool {
        self.effective.contains(cap)
    }
    
    /// Add capability to effective set
    pub fn add_effective(&mut self, cap: Capability) -> Result<(), &'static str> {
        if !self.permitted.contains(&cap) {
            return Err("Capability not in permitted set");
        }
        
        if !self.bounding.contains(&cap) {
            return Err("Capability not in bounding set");
        }
        
        self.effective.insert(cap);
        Ok(())
    }
    
    /// Remove capability from effective set
    pub fn remove_effective(&mut self, cap: &Capability) {
        self.effective.remove(cap);
    }
    
    /// Drop capability entirely
    pub fn drop_capability(&mut self, cap: &Capability) {
        self.effective.remove(cap);
        self.permitted.remove(cap);
        self.inheritable.remove(cap);
        self.ambient.remove(cap);
    }
    
    /// Grant capability (requires CAP_SETPCAP)
    pub fn grant_capability(&mut self, cap: Capability, source: &CapabilitySet) -> Result<(), &'static str> {
        if !source.has_effective(&Capability::SetPCap) {
            return Err("Source lacks CAP_SETPCAP");
        }
        
        if !source.permitted.contains(&cap) {
            return Err("Source doesn't have capability in permitted set");
        }
        
        if !self.bounding.contains(&cap) {
            return Err("Capability not in target bounding set");
        }
        
        self.permitted.insert(cap.clone());
        self.effective.insert(cap);
        Ok(())
    }
    
    /// Create capability set for child process
    pub fn inherit_to_child(&self, is_setuid: bool) -> CapabilitySet {
        let mut child = CapabilitySet::new_empty();
        
        // Bounding set is intersection with parent
        child.bounding = self.bounding.clone();
        
        // Inheritable capabilities are preserved
        child.inheritable = self.inheritable.clone();
        
        if is_setuid {
            // For setuid programs, clear most capabilities
            child.permitted.clear();
            child.effective.clear();
        } else {
            // Normal inheritance
            child.permitted = self.inheritable.intersection(&self.bounding).cloned().collect();
            child.effective = child.permitted.intersection(&self.ambient).cloned().collect();
        }
        
        child
    }
    
    /// Serialize capabilities for auditing
    pub fn to_audit_string(&self) -> String {
        let effective: Vec<String> = self.effective.iter().map(|c| format!("{}", c)).collect();
        let permitted: Vec<String> = self.permitted.iter().map(|c| format!("{}", c)).collect();
        
        format!(
            "effective=[{}] permitted=[{}] inheritable=[{}]",
            effective.join(","),
            permitted.join(","),
            self.inheritable.len()
        )
    }
    
    /// Check if this capability set is a subset of another (for privilege escalation checks)
    pub fn is_subset_of(&self, other: &CapabilitySet) -> bool {
        self.effective.is_subset(&other.effective) &&
        self.permitted.is_subset(&other.permitted) &&
        self.inheritable.is_subset(&other.inheritable)
    }
    
    /// Get capability count for each set
    pub fn get_stats(&self) -> CapabilityStats {
        CapabilityStats {
            effective_count: self.effective.len(),
            permitted_count: self.permitted.len(),
            inheritable_count: self.inheritable.len(),
            bounding_count: self.bounding.len(),
            ambient_count: self.ambient.len(),
        }
    }
}

/// Capability statistics
#[derive(Debug, Clone)]
pub struct CapabilityStats {
    pub effective_count: usize,
    pub permitted_count: usize,
    pub inheritable_count: usize,
    pub bounding_count: usize,
    pub ambient_count: usize,
}
