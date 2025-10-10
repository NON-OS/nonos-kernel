//! Interrupt Vector Allocation
//!
//! Management of interrupt vectors for device drivers and system components.
//! Provides allocation and deallocation of interrupt vectors with conflict
//! detection.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use spin::Mutex;

/// Interrupt vector range for device drivers
const DEVICE_INTERRUPT_START: u8 = 32;
const DEVICE_INTERRUPT_END: u8 = 255;

/// Interrupt vector allocation state
struct InterruptAllocator {
    allocated_vectors: BTreeMap<u8, String>,
    next_vector: u8,
}

impl InterruptAllocator {
    const fn new() -> Self {
        Self { allocated_vectors: BTreeMap::new(), next_vector: DEVICE_INTERRUPT_START }
    }

    fn allocate(&mut self, name: &str) -> Result<u8, &'static str> {
        // Find next available vector
        for vector in self.next_vector..=DEVICE_INTERRUPT_END {
            if !self.allocated_vectors.contains_key(&vector) {
                self.allocated_vectors.insert(vector, name.to_string());
                self.next_vector = vector + 1;
                return Ok(vector);
            }
        }

        // Wrap around and check from start
        for vector in DEVICE_INTERRUPT_START..self.next_vector {
            if !self.allocated_vectors.contains_key(&vector) {
                self.allocated_vectors.insert(vector, name.to_string());
                self.next_vector = vector + 1;
                return Ok(vector);
            }
        }

        Err("No interrupt vectors available")
    }

    fn deallocate(&mut self, vector: u8) -> Result<(), &'static str> {
        if self.allocated_vectors.remove(&vector).is_some() {
            Ok(())
        } else {
            Err("Vector not allocated")
        }
    }

    fn is_allocated(&self, vector: u8) -> bool {
        self.allocated_vectors.contains_key(&vector)
    }

    fn get_owner(&self, vector: u8) -> Option<&String> {
        self.allocated_vectors.get(&vector)
    }
}

/// Global interrupt vector allocator
static INTERRUPT_ALLOCATOR: Mutex<Option<InterruptAllocator>> = Mutex::new(None);

/// Allocate an interrupt vector for a device
pub fn allocate_vector() -> Result<u8, &'static str> {
    let mut guard = INTERRUPT_ALLOCATOR.lock();
    if guard.is_none() {
        *guard = Some(InterruptAllocator::new());
    }
    guard.as_mut().unwrap().allocate("device")
}

/// Allocate an interrupt vector with a specific name
pub fn allocate_vector_named(name: &str) -> Result<u8, &'static str> {
    let mut guard = INTERRUPT_ALLOCATOR.lock();
    if guard.is_none() {
        *guard = Some(InterruptAllocator::new());
    }
    guard.as_mut().unwrap().allocate(name)
}

/// Deallocate an interrupt vector
pub fn deallocate_vector(vector: u8) -> Result<(), &'static str> {
    let mut guard = INTERRUPT_ALLOCATOR.lock();
    if let Some(allocator) = guard.as_mut() {
        allocator.deallocate(vector)
    } else {
        Err("Allocator not initialized")
    }
}

/// Check if vector is allocated
pub fn is_vector_allocated(vector: u8) -> bool {
    let guard = INTERRUPT_ALLOCATOR.lock();
    guard.as_ref().map_or(false, |a| a.is_allocated(vector))
}

/// Get owner of an interrupt vector
pub fn get_vector_owner(vector: u8) -> Option<String> {
    let guard = INTERRUPT_ALLOCATOR.lock();
    guard.as_ref()?.get_owner(vector).cloned()
}

/// Get all allocated vectors
pub fn get_allocated_vectors() -> BTreeMap<u8, String> {
    let guard = INTERRUPT_ALLOCATOR.lock();
    guard.as_ref().map_or(BTreeMap::new(), |a| a.allocated_vectors.clone())
}

/// Interrupt handler function type
pub type InterruptHandler = fn();

/// Interrupt handler registration table
static INTERRUPT_HANDLERS: Mutex<BTreeMap<u8, InterruptHandler>> = Mutex::new(BTreeMap::new());

/// Register an interrupt handler for a vector
pub fn register_interrupt_handler(
    vector: u8,
    handler: InterruptHandler,
) -> Result<(), &'static str> {
    let mut handlers = INTERRUPT_HANDLERS.lock();

    if handlers.contains_key(&vector) {
        return Err("Handler already registered for this vector");
    }

    handlers.insert(vector, handler);

    // Enable the interrupt in the interrupt controller
    crate::arch::x86_64::interrupt::apic::enable_interrupt(vector);

    Ok(())
}

/// Unregister an interrupt handler
pub fn unregister_interrupt_handler(vector: u8) -> Result<(), &'static str> {
    let mut handlers = INTERRUPT_HANDLERS.lock();

    if handlers.remove(&vector).is_none() {
        return Err("No handler registered for this vector");
    }

    // Disable the interrupt in the interrupt controller
    crate::arch::x86_64::interrupt::apic::disable_interrupt(vector);

    Ok(())
}

/// Call interrupt handler for a vector
pub fn call_interrupt_handler(vector: u8) {
    let handlers = INTERRUPT_HANDLERS.lock();

    if let Some(&handler) = handlers.get(&vector) {
        // Call the handler
        handler();
    } else {
        crate::log::warning!("Unhandled interrupt vector: {}", vector);
    }
}

/// Initialize interrupt allocation system
pub fn init_interrupt_allocation() {
    crate::log::info!("Interrupt vector allocation system initialized");
    crate::log::info!("Available vectors: {} - {}", DEVICE_INTERRUPT_START, DEVICE_INTERRUPT_END);
}

/// Get interrupt allocation statistics
pub fn get_interrupt_stats() -> InterruptStats {
    let guard = INTERRUPT_ALLOCATOR.lock();
    let handlers = INTERRUPT_HANDLERS.lock();

    let allocated_count = guard.as_ref().map_or(0, |a| a.allocated_vectors.len());

    InterruptStats {
        total_vectors: (DEVICE_INTERRUPT_END - DEVICE_INTERRUPT_START + 1) as usize,
        allocated_vectors: allocated_count,
        registered_handlers: handlers.len(),
        available_vectors: (DEVICE_INTERRUPT_END - DEVICE_INTERRUPT_START + 1) as usize
            - allocated_count,
    }
}

/// Interrupt allocation statistics
#[derive(Debug, Clone, Copy)]
pub struct InterruptStats {
    pub total_vectors: usize,
    pub allocated_vectors: usize,
    pub registered_handlers: usize,
    pub available_vectors: usize,
}
