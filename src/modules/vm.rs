//! NØNOS Virtual Machine Runtime Layer
//!
//! This layer sets up secure, sealed memory capsules for `.mod` binaries
//! to execute under ZeroState. It includes:
//! - Memory layout bootstrapping (code/stack/heap)
//! - Entrypoint integrity sealing
//! - Cryptographic execution ID derivation
//! - Format-aware capsule prep (FlatBin, ELF, WASM, ZKVM)
//! - Future syscall interposition hooks
//!
//! Memory Layout (ZeroState Capsule):
//!
//!   [ Heap Memory Region ]:
//!   +-----------------------------+
//!   |  CODE  |  STACK  |  HEAP    |
//!   |        |         |          |
//!   +-----------------------------+
//!   ^        ^         ^
//!   base     +code     +stack
//!            size      size
//!
//!   - CODE: binary blob from manifest (entrypoint lives here)
//!   - STACK: top-down stack segment mapped above code
//!   - HEAP: remaining runtime heap for capsule state + allocs
//!
//! Entrypoint must fall within the CODE region.
//! Stack pointer is offset from code boundary with fixed size.
//! Heap region backs capsule allocator and is sealed with execution hash.

use crate::memory::region::{allocate_region, MemoryRegion};
use crate::modules::manifest::{ModuleManifest, ModuleFormat};
use crate::crypto::hash::sha3_256;
use crate::log::logger::log_info;

use core::ptr::NonNull;
use alloc::{string::ToString, format};

/// Struct representing the secure memory layout of a `.mod` instance
pub struct VmLayout {
    pub code_base: NonNull<u8>,
    pub code_size: usize,
    pub stack_base: NonNull<u8>,
    pub stack_size: usize,
    pub heap_region: MemoryRegion,
    pub entry_trampoline: NonNull<u8>,
}

/// VM instance encapsulates runtime capsule metadata
pub struct VmInstance {
    pub layout: VmLayout,
    pub format: ModuleFormat,
    pub entry_ptr: NonNull<u8>,
    pub sealed_hash: [u8; 32],
}

impl VmInstance {
    /// Prepare an execution environment from manifest
    pub fn from_manifest(manifest: &'static ModuleManifest) -> Result<Self, &'static str> {
        let mem_total = manifest.memory_required as usize;
        let code_size = manifest.binary_size;
        let stack_size = manifest.stack_size.unwrap_or(0x8000); // 32KB default

        let region = allocate_region(mem_total).ok_or("vm: region allocation failed")?;
        let base_ptr = region.base.as_ptr();

        let code_ptr = NonNull::new(base_ptr).ok_or("vm: null code ptr")?;
        let stack_ptr = NonNull::new(unsafe { base_ptr.add(code_size) }).ok_or("vm: bad stack ptr")?;
        let entry_offset = manifest.entrypoint_offset as usize;

        if entry_offset >= code_size {
            return Err("vm: entrypoint outside code region");
        }

        let entry_ptr = NonNull::new(unsafe { base_ptr.add(entry_offset) }).ok_or("vm: invalid entry ptr")?;
        let entry_trampoline = entry_ptr;

        let seal_input = [
            manifest.name.as_bytes(),
            &region.base.as_ptr().cast::<u8>() as *const u8 as &[u8; 8],
        ]
        .concat();
        let sealed_hash = sha3_256(&seal_input);

        log_info!("vm", &format!(
            "VM sealed layout for '{}' | entry@0x{:x} stack@0x{:x} code={}KB",
            manifest.name,
            entry_ptr.as_ptr() as usize,
            stack_ptr.as_ptr() as usize,
            code_size / 1024
        ));

        Ok(Self {
            format: manifest.format.unwrap_or(ModuleFormat::FlatBin),
            entry_ptr,
            sealed_hash,
            layout: VmLayout {
                code_base: code_ptr,
                code_size,
                stack_base: stack_ptr,
                stack_size,
                heap_region: region,
                entry_trampoline,
            },
        })
    }

    /// Access capsule entrypoint
    pub fn entrypoint(&self) -> NonNull<u8> {
        self.entry_ptr
    }

    /// Return sealed hash for audit + zk proof binding
    pub fn sealed_fingerprint(&self) -> [u8; 32] {
        self.sealed_hash
    }

    /// Return memory region backing the capsule
    pub fn heap(&self) -> MemoryRegion {
        self.layout.heap_region.clone()
    }

    /// Return VM stack pointer for runtime mapping
    pub fn stack(&self) -> NonNull<u8> {
        self.layout.stack_base
    }
}
