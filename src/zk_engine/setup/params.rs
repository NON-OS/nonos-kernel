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

//! Setup parameters and key structures.

use crate::zk_engine::groth16::{FieldElement, ProvingKey, VerifyingKey};

/// Complete setup output
#[derive(Debug, Clone)]
pub struct SetupParameters {
    pub proving_key: ProvingKey,
    pub verifying_key: VerifyingKey,
    pub toxic_waste: Option<ToxicWaste>,
}

pub struct ToxicWaste {
    pub tau: FieldElement,
    pub alpha: FieldElement,
    pub beta: FieldElement,
    pub gamma: FieldElement,
    pub delta: FieldElement,
}

impl Drop for ToxicWaste {
    fn drop(&mut self) {
        unsafe {
            let ptr = &mut self.tau.limbs as *mut [u64; 4];
            core::ptr::write_volatile(ptr, [0u64; 4]);
            let ptr = &mut self.alpha.limbs as *mut [u64; 4];
            core::ptr::write_volatile(ptr, [0u64; 4]);
            let ptr = &mut self.beta.limbs as *mut [u64; 4];
            core::ptr::write_volatile(ptr, [0u64; 4]);
            let ptr = &mut self.gamma.limbs as *mut [u64; 4];
            core::ptr::write_volatile(ptr, [0u64; 4]);
            let ptr = &mut self.delta.limbs as *mut [u64; 4];
            core::ptr::write_volatile(ptr, [0u64; 4]);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
