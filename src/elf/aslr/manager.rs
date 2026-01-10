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

use core::arch::x86_64::_rdrand64_step;

pub const EXEC_RANDOMIZATION_RANGE: u64 = 0x40000000;
pub const STACK_RANDOMIZATION_RANGE: u64 = 0x1000000;
pub const HEAP_RANDOMIZATION_RANGE: u64 = 0x2000000;

const LCG_MULTIPLIER: u64 = 6364136223846793005;
const LCG_INCREMENT: u64 = 1;
const FALLBACK_SEED: u64 = 0xDEADBEEFCAFEBABE;

#[derive(Debug)]
pub struct AslrManager {
    entropy_pool: u64,
    stack_randomization: bool,
    heap_randomization: bool,
    executable_randomization: bool,
}

impl AslrManager {
    pub fn new() -> Self {
        let entropy = Self::gather_entropy();
        AslrManager {
            entropy_pool: entropy,
            stack_randomization: true,
            heap_randomization: true,
            executable_randomization: true,
        }
    }

    pub fn with_settings(stack: bool, heap: bool, executable: bool) -> Self {
        let entropy = Self::gather_entropy();
        AslrManager {
            entropy_pool: entropy,
            stack_randomization: stack,
            heap_randomization: heap,
            executable_randomization: executable,
        }
    }

    pub fn disabled() -> Self {
        AslrManager {
            entropy_pool: 0,
            stack_randomization: false,
            heap_randomization: false,
            executable_randomization: false,
        }
    }

    fn gather_entropy() -> u64 {
        // SAFETY: RDRAND is available on modern x86_64 CPUs
        unsafe {
            let mut tmp: u64 = 0;
            if _rdrand64_step(&mut tmp) == 1 {
                tmp
            } else {
                FALLBACK_SEED
            }
        }
    }

    pub fn random_offset(&mut self, max_offset: u64) -> u64 {
        if max_offset == 0 {
            return 0;
        }

        // SAFETY: RDRAND is available on modern x86_64 CPUs
        unsafe {
            let mut rand: u64 = 0;
            if _rdrand64_step(&mut rand) == 1 {
                self.entropy_pool ^= rand;
            } else {
                self.entropy_pool = self
                    .entropy_pool
                    .wrapping_mul(LCG_MULTIPLIER)
                    .wrapping_add(LCG_INCREMENT);
            }
        }

        (self.entropy_pool >> 16) % max_offset
    }

    pub fn randomize_base(&mut self, preferred_base: u64) -> u64 {
        if !self.executable_randomization {
            return preferred_base;
        }
        let offset = self.random_offset(EXEC_RANDOMIZATION_RANGE);
        (preferred_base + offset) & !0xFFF
    }

    pub fn randomize_stack(&mut self, base_stack: u64) -> u64 {
        if !self.stack_randomization {
            return base_stack;
        }
        let offset = self.random_offset(STACK_RANDOMIZATION_RANGE);
        (base_stack - offset) & !0xFFF
    }

    pub fn randomize_heap(&mut self, base_heap: u64) -> u64 {
        if !self.heap_randomization {
            return base_heap;
        }
        let offset = self.random_offset(HEAP_RANDOMIZATION_RANGE);
        (base_heap + offset) & !0xFFF
    }

    pub fn is_executable_randomization_enabled(&self) -> bool {
        self.executable_randomization
    }

    pub fn is_stack_randomization_enabled(&self) -> bool {
        self.stack_randomization
    }

    pub fn is_heap_randomization_enabled(&self) -> bool {
        self.heap_randomization
    }

    pub fn set_executable_randomization(&mut self, enabled: bool) {
        self.executable_randomization = enabled;
    }

    pub fn set_stack_randomization(&mut self, enabled: bool) {
        self.stack_randomization = enabled;
    }

    pub fn set_heap_randomization(&mut self, enabled: bool) {
        self.heap_randomization = enabled;
    }

    pub fn reseed(&mut self) {
        self.entropy_pool ^= Self::gather_entropy();
    }

    pub fn entropy(&self) -> u64 {
        self.entropy_pool
    }
}

impl Default for AslrManager {
    fn default() -> Self {
        Self::new()
    }
}
