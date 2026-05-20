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

use alloc::vec::Vec;

use crate::arch::x86_64::acpi::data::{InterruptOverride, IoApicInfo};
use crate::arch::x86_64::acpi::{interrupt_overrides, ioapics, is_initialized};

#[derive(Debug, Clone)]
pub struct DiscoveredIoApics {
    pub ioapics: Vec<IoApicInfo>,
    pub isos: Vec<InterruptOverride>,
}

pub fn discover_ioapics() -> Option<DiscoveredIoApics> {
    if !is_initialized() {
        return None;
    }
    let ioapics = ioapics();
    if ioapics.is_empty() {
        return None;
    }
    Some(DiscoveredIoApics { ioapics, isos: interrupt_overrides() })
}
