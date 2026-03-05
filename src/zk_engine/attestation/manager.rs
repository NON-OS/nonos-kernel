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

//! Attestation manager implementation.

use alloc::{vec::Vec, string::String};
use core::ptr::addr_of_mut;
use crate::zk_engine::groth16::Proof;
use crate::zk_engine::circuit::{Circuit, CircuitBuilder, LinearCombination};
use crate::zk_engine::{ZKEngine, ZKError};
use crate::crypto::{hash::blake3_hash, ed25519::{KeyPair, Signature as Ed25519Signature}};
use crate::memory::VirtAddr;

use super::types::*;

/// Kernel attestation manager
pub struct AttestationManager {
    signing_keypair: KeyPair,
    measurement_history: Vec<KernelMeasurement>,
    attestation_circuit: Option<Circuit>,
    zk_engine: Option<&'static ZKEngine>,
}

impl AttestationManager {
    pub fn new() -> Result<Self, ZKError> {
        let signing_keypair = KeyPair::generate();

        Ok(Self {
            signing_keypair,
            measurement_history: Vec::new(),
            attestation_circuit: None,
            zk_engine: None,
        })
    }

    pub fn initialize_with_engine(&mut self, engine: &'static ZKEngine) -> Result<(), ZKError> {
        self.zk_engine = Some(engine);
        self.attestation_circuit = Some(self.build_attestation_circuit()?);
        Ok(())
    }

    /// Generate a complete kernel attestation
    pub fn generate_attestation(&mut self) -> Result<KernelAttestation, ZKError> {
        let measurement = self.measure_kernel_state()?;
        self.measurement_history.push(measurement.clone());

        let signature = self.sign_measurement(&measurement)?;
        let zk_proof = self.generate_integrity_proof(&measurement)?;

        Ok(KernelAttestation {
            measurement,
            signature,
            zk_proof,
            public_key: self.signing_keypair.public,
            timestamp: crate::time::timestamp_millis(),
        })
    }

    /// Verify a kernel attestation
    pub fn verify_attestation(attestation: &KernelAttestation) -> Result<bool, ZKError> {
        // Verify signature
        let message = attestation.measurement.to_bytes();
        if !crate::crypto::ed25519::verify(&attestation.public_key, &message, &attestation.signature) {
            return Ok(false);
        }

        // Verify ZK proof if available
        if let Some(ref proof) = attestation.zk_proof {
            // Get ZK engine and verify
            if let Some(engine) = crate::zk_engine::get_zk_engine_static() {
                // Convert Groth16 Proof to ZKProof
                let zk_proof = crate::zk_engine::ZKProof {
                    circuit_id: proof.circuit_id,
                    proof_data: proof.clone(),
                    public_inputs: vec![],  // Public inputs would be extracted from measurement
                    proof_hash: [0; 32],    // Would compute actual hash
                    created_at: crate::time::timestamp_millis(),
                };
                return engine.verify_proof(&zk_proof);
            }
        }

        Ok(true)
    }

    /// Measure current kernel state
    fn measure_kernel_state(&self) -> Result<KernelMeasurement, ZKError> {
        let mut measurement = KernelMeasurement::new();

        // Measure kernel code sections
        measurement.code_hash = self.hash_kernel_code()?;

        // Measure critical data structures
        measurement.data_hash = self.hash_kernel_data()?;

        // Measure memory layout
        measurement.memory_layout = self.measure_memory_layout()?;

        // Measure loaded modules
        measurement.module_hashes = self.hash_loaded_modules()?;

        // Measure configuration
        measurement.config_hash = self.hash_kernel_config()?;

        // Compute overall integrity hash
        measurement.integrity_hash = measurement.compute_integrity_hash();

        Ok(measurement)
    }

    fn hash_kernel_code(&self) -> Result<[u8; 32], ZKError> {
        // Get actual kernel sections from linker symbols
        let sections = crate::memory::layout::kernel_sections();
        let mut hasher_input = Vec::new();

        // Hash .text section (executable code)
        for section in sections.iter() {
            if section.rx {
                // This is executable code section
                let start = section.start as *const u8;
                let size = section.size() as usize;

                // Hash the code in 4KB chunks to avoid stack overflow
                let mut offset = 0;
                while offset < size {
                    let chunk_size = core::cmp::min(4096, size - offset);
                    let chunk_ptr = unsafe { start.add(offset) };
                    let chunk = unsafe { core::slice::from_raw_parts(chunk_ptr, chunk_size) };
                    let chunk_hash = blake3_hash(chunk);
                    hasher_input.extend_from_slice(&chunk_hash);
                    offset += chunk_size;
                }
            }
        }

        // Include KASLR slide in hash to detect tampering
        let slide = crate::memory::layout::get_slide();
        hasher_input.extend_from_slice(&slide.to_le_bytes());

        Ok(blake3_hash(&hasher_input))
    }

    fn hash_kernel_data(&self) -> Result<[u8; 32], ZKError> {
        // Hash critical kernel data structures
        let mut hasher_input = Vec::new();

        // Get kernel data sections from linker symbols
        let sections = crate::memory::layout::kernel_sections();
        for section in sections.iter() {
            if section.rw && !section.rx {
                // This is a data section (.data or .bss)
                let start = section.start as *const u8;
                let size = section.size() as usize;

                // Hash in 4KB chunks
                let mut offset = 0;
                while offset < size {
                    let chunk_size = core::cmp::min(4096, size - offset);
                    let chunk_ptr = unsafe { start.add(offset) };
                    let chunk = unsafe { core::slice::from_raw_parts(chunk_ptr, chunk_size) };
                    let chunk_hash = blake3_hash(chunk);
                    hasher_input.extend_from_slice(&chunk_hash);
                    offset += chunk_size;
                }
            }
        }

        // Hash process table state - get actual process count and IDs
        let process_table = crate::process::get_process_table();
        let process_list = process_table.get_all_processes();
        hasher_input.extend_from_slice(&(process_list.len() as u64).to_le_bytes());
        for proc in process_list.iter() {
            hasher_input.extend_from_slice(&proc.pid.to_le_bytes());
            let state = *proc.state.lock();
            // Map ProcessState to u32 explicitly
            let state_num: u32 = match state {
                crate::process::nonos_core::ProcessState::New => 0,
                crate::process::nonos_core::ProcessState::Ready => 1,
                crate::process::nonos_core::ProcessState::Running => 2,
                crate::process::nonos_core::ProcessState::Sleeping => 3,
                crate::process::nonos_core::ProcessState::Stopped => 4,
                crate::process::nonos_core::ProcessState::Zombie(_) => 5,
                crate::process::nonos_core::ProcessState::Terminated(_) => 6,
            };
            hasher_input.extend_from_slice(&state_num.to_le_bytes());
        }

        // Hash scheduler stats
        let sched_stats = crate::sched::get_scheduler_stats();
        hasher_input.extend_from_slice(&sched_stats.context_switches.to_le_bytes());
        hasher_input.extend_from_slice(&sched_stats.tick_count.to_le_bytes());
        hasher_input.extend_from_slice(&sched_stats.wakeups.to_le_bytes());

        // Hash memory manager stats
        let mem_stats = crate::memory::get_memory_system_stats();
        hasher_input.extend_from_slice(&mem_stats.total_physical_memory.to_le_bytes());
        hasher_input.extend_from_slice(&mem_stats.total_virtual_memory.to_le_bytes());
        hasher_input.extend_from_slice(&(mem_stats.active_allocations as u64).to_le_bytes());

        Ok(blake3_hash(&hasher_input))
    }

    fn measure_memory_layout(&self) -> Result<MemoryLayout, ZKError> {
        use crate::memory::layout;

        // Get actual kernel sections from linker symbols
        let sections = layout::kernel_sections();
        let kernel_start = sections.iter().map(|s| s.start).min().unwrap_or(layout::KERNEL_BASE);
        let kernel_end = sections.iter().map(|s| s.end).max().unwrap_or(layout::KERNEL_BASE);

        // Get heap window from layout config
        let layout_config = layout::get_layout();
        let heap_base = layout_config.heap_lo;
        let heap_size = layout_config.heap_sz;

        Ok(MemoryLayout {
            kernel_start: VirtAddr::new(kernel_start),
            kernel_end: VirtAddr::new(kernel_end),
            user_start: VirtAddr::new(layout::USER_BASE),
            user_end: VirtAddr::new(layout::USER_TOP),
            heap_start: VirtAddr::new(heap_base),
            heap_end: VirtAddr::new(heap_base + heap_size),
        })
    }

    fn hash_loaded_modules(&self) -> Result<Vec<ModuleHash>, ZKError> {
        let mut modules = Vec::new();

        // Get module regions from layout which tracks loaded kernel modules
        let module_regions = crate::memory::layout::get_module_regions();

        for region in module_regions {
            // Hash the actual module contents
            let start = region.base as *const u8;
            let size = region.size;
            let mut module_hash_input = Vec::new();

            // Hash in 4KB chunks
            let mut offset = 0;
            while offset < size {
                let chunk_size = core::cmp::min(4096, size - offset);
                let chunk_ptr = unsafe { start.add(offset) };
                let chunk = unsafe { core::slice::from_raw_parts(chunk_ptr, chunk_size) };
                let chunk_hash = blake3_hash(chunk);
                module_hash_input.extend_from_slice(&chunk_hash);
                offset += chunk_size;
            }

            modules.push(ModuleHash {
                name: String::from(region.name),
                hash: blake3_hash(&module_hash_input),
                address: VirtAddr::new(region.base),
                size: region.size,
            });
        }

        // Also hash critical driver modules
        let critical_drivers = crate::drivers::get_critical_drivers();
        for driver in critical_drivers {
            modules.push(ModuleHash {
                name: String::from(driver.name),
                hash: driver.hash,
                address: VirtAddr::new(driver.base_address as u64),
                size: driver.size,
            });
        }

        Ok(modules)
    }

    fn hash_kernel_config(&self) -> Result<[u8; 32], ZKError> {
        // Hash kernel configuration and actual runtime settings
        let mut config_input = Vec::new();

        // Compile-time configuration from build
        config_input.extend_from_slice(b"NONOS_VERSION=");
        config_input.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
        config_input.push(b'\n');

        // Target architecture
        config_input.extend_from_slice(b"TARGET=x86_64-unknown-none\n");

        // Security features
        config_input.extend_from_slice(b"CONFIG_ZK_ENGINE=y\n");
        config_input.extend_from_slice(b"CONFIG_KPTI=y\n");
        config_input.extend_from_slice(b"CONFIG_KASLR=y\n");
        config_input.extend_from_slice(b"CONFIG_STACK_PROTECTOR=y\n");
        config_input.extend_from_slice(b"CONFIG_SMAP=y\n");
        config_input.extend_from_slice(b"CONFIG_SMEP=y\n");

        // Runtime security state
        let slide = crate::memory::layout::get_slide();
        let kaslr_enabled = slide != 0;
        if kaslr_enabled {
            config_input.extend_from_slice(b"KASLR_ACTIVE=y\n");
            config_input.extend_from_slice(b"KASLR_SLIDE=");
            config_input.extend_from_slice(&slide.to_le_bytes());
            config_input.push(b'\n');
        }

        // CPU features detected at runtime
        #[cfg(target_arch = "x86_64")]
        {
            // Use compiler intrinsic for CPUID
            let cpuid_result = core::arch::x86_64::__cpuid(1);
            config_input.extend_from_slice(b"CPUID_1_ECX=");
            config_input.extend_from_slice(&cpuid_result.ecx.to_le_bytes());
            config_input.push(b'\n');
            config_input.extend_from_slice(b"CPUID_1_EDX=");
            config_input.extend_from_slice(&cpuid_result.edx.to_le_bytes());
            config_input.push(b'\n');
        }

        Ok(blake3_hash(&config_input))
    }

    fn sign_measurement(&self, measurement: &KernelMeasurement) -> Result<Ed25519Signature, ZKError> {
        let message = measurement.to_bytes();
        Ok(crate::crypto::ed25519::sign(&self.signing_keypair, &message))
    }

    fn generate_integrity_proof(&self, measurement: &KernelMeasurement) -> Result<Option<Proof>, ZKError> {
        let Some(engine) = self.zk_engine else {
            return Ok(None);
        };

        let Some(ref _circuit) = self.attestation_circuit else {
            return Ok(None);
        };

        // Convert measurement to witness
        let witness = measurement.to_witness()?;
        let public_inputs = measurement.to_field_elements()?;

        // Generate proof
        let circuit_id = 1; // Attestation circuit ID
        let public_inputs_bytes: Vec<Vec<u8>> = public_inputs.iter()
            .map(|fe| fe.to_bytes().to_vec())
            .collect();
        let zk_proof = engine.generate_proof(circuit_id, witness, public_inputs_bytes)?;

        // ZKProof already contains the Groth16 Proof
        Ok(Some(zk_proof.proof_data))
    }

    fn build_attestation_circuit(&self) -> Result<Circuit, ZKError> {
        let mut builder = CircuitBuilder::new();

        // Input: integrity hash
        let integrity_hash_var = builder.alloc_input(Some("integrity_hash"));

        // Witness: individual component hashes
        let code_hash_var = builder.alloc_variable(Some("code_hash"));
        let data_hash_var = builder.alloc_variable(Some("data_hash"));
        let config_hash_var = builder.alloc_variable(Some("config_hash"));

        // Intermediate variables for hash computation
        let temp1 = builder.alloc_variable(Some("temp1"));
        let temp2 = builder.alloc_variable(Some("temp2"));

        // Simulate hash computation constraints
        // In practice, this would be a proper hash circuit
        builder.enforce_multiplication(code_hash_var, data_hash_var, temp1);
        builder.enforce_multiplication(temp1, config_hash_var, temp2);

        // Ensure computed hash equals public input
        builder.enforce_equal(
            LinearCombination::from_variable(temp2),
            LinearCombination::from_variable(integrity_hash_var),
        );

        Ok(builder.build(4)?)
    }

    /// Get attestation history
    pub fn get_measurement_history(&self) -> &[KernelMeasurement] {
        &self.measurement_history
    }

    /// Clear attestation history (for security)
    pub fn clear_history(&mut self) {
        self.measurement_history.clear();
    }

    /// Rotate signing key
    pub fn rotate_key(&mut self) -> Result<(), ZKError> {
        self.signing_keypair = KeyPair::generate();
        Ok(())
    }
}

/// Global attestation manager instance
static mut GLOBAL_ATTESTATION_MANAGER: Option<AttestationManager> = None;

pub fn init_attestation_manager() -> Result<(), ZKError> {
    let manager = AttestationManager::new()?;

    // SAFETY: Called once during kernel initialization before any concurrent access
    unsafe {
        *addr_of_mut!(GLOBAL_ATTESTATION_MANAGER) = Some(manager);
    }

    Ok(())
}

pub fn get_attestation_manager() -> Option<&'static mut AttestationManager> {
    // SAFETY: Mutable access to attestation manager, single-threaded kernel context
    unsafe {
        (*addr_of_mut!(GLOBAL_ATTESTATION_MANAGER)).as_mut()
    }
}

/// Generate system attestation (kernel interface)
pub fn generate_system_attestation() -> Result<KernelAttestation, ZKError> {
    let manager = get_attestation_manager().ok_or(ZKError::NotInitialized)?;
    manager.generate_attestation()
}
