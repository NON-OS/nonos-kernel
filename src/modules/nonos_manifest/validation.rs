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


use crate::security::trusted_keys::get_trusted_keys;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
use core::ptr;
use super::types::ModuleManifest;

impl ModuleManifest {
    pub fn verify_attestation(&self) -> bool {
        let trusted_keys = get_trusted_keys();
        for key in &self.attestation_chain {
            if !trusted_keys.contains(key) {
                return false;
            }
        }
        true
    }

    pub fn secure_erase(&mut self) {
        secure_erase_string(&mut self.name);
        secure_erase_string(&mut self.version);
        secure_erase_string(&mut self.author);
        secure_erase_string(&mut self.description);

        self.capabilities.clear();
        self.attestation_chain.clear();

        for b in self.hash.iter_mut() {
            unsafe { ptr::write_volatile(b, 0) };
        }
        compiler_fence();
        memory_fence();
    }

    pub fn validate(&self) -> bool {
        if self.name.is_empty() {
            return false;
        }

        if self.version.is_empty() {
            return false;
        }

        if !self.memory_requirements.validate() {
            return false;
        }

        if self.hash == [0u8; 32] {
            return false;
        }

        true
    }

    pub fn has_capability(&self, cap: &crate::process::capabilities::Capability) -> bool {
        self.capabilities.contains(cap)
    }
}

fn secure_erase_string(s: &mut alloc::string::String) {
    // SAFETY: We have mutable access and will replace the string afterward
    let bytes = unsafe { s.as_bytes_mut() };
    for b in bytes.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    s.clear();
}
