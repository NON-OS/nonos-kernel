//! Address Space Layout Randomization Manager for ELF Loader

use core::arch::x86_64::_rdrand64_step;

/// ASLR for kernel ELF loading.

pub struct AslrManager {
    entropy_pool: u64,
    stack_randomization: bool,
    heap_randomization: bool,
    executable_randomization: bool,
}

impl AslrManager {
    /// Create a new ASLR manager with RDRAND entropy and all randomizations enabled.
    pub fn new() -> Self {
        let mut entropy = 0u64;
        unsafe {
            let mut tmp: u64 = 0;
            if _rdrand64_step(&mut tmp) == 1 {
                entropy = tmp;
            } else {
                // LCG fallback if hardware RNG unavailable
                entropy = 0xDEADBEEFCAFEBABE;
            }
        }
        AslrManager {
            entropy_pool: entropy,
            stack_randomization: true,
            heap_randomization: true,
            executable_randomization: true,
        }
    }

    /// Generate a random offset in range [0, max_offset).
    pub fn random_offset(&mut self, max_offset: u64) -> u64 {
        unsafe {
            let mut rand: u64 = 0;
            if _rdrand64_step(&mut rand) == 1 {
                self.entropy_pool ^= rand;
            } else {
                // Fallback: LCG update if hardware RNG failed
                self.entropy_pool = self.entropy_pool.wrapping_mul(6364136223846793005).wrapping_add(1);
            }
        }
        (self.entropy_pool >> 16) % max_offset
    }

    /// Get a randomized base address for an executable.
    pub fn randomize_base(&mut self, preferred_base: u64) -> u64 {
        if !self.executable_randomization {
            return preferred_base;
        }
        let randomization_range = 0x40000000u64; // 1GB range
        let offset = self.random_offset(randomization_range);
        (preferred_base + offset) & !0xFFF
    }

    /// Get a randomized stack address.
    pub fn randomize_stack(&mut self, base_stack: u64) -> u64 {
        if !self.stack_randomization {
            return base_stack;
        }
        let stack_randomization_range = 0x1000000u64; // 16MB range
        let offset = self.random_offset(stack_randomization_range);
        (base_stack - offset) & !0xFFF
    }

    /// Get a randomized heap address.
    pub fn randomize_heap(&mut self, base_heap: u64) -> u64 {
        if !self.heap_randomization {
            return base_heap;
        }
        let heap_randomization_range = 0x2000000u64; // 32MB range
        let offset = self.random_offset(heap_randomization_range);
        (base_heap + offset) & !0xFFF
    }
}
