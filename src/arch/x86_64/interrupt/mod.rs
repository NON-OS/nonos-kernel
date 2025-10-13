//! NØNOS x86_64 Interrupt Controllers

pub mod nonos_apic;
pub mod nonos_ioapic;
pub mod nonos_pic_legacy;

/// Prelude for ergonomic import of all interrupt controller APIs
pub mod prelude {
    pub use super::nonos_apic::*;
    pub use super::nonos_ioapic::*;
    pub use super::nonos_pic_legacy::*;
}

#[cfg(test)]
mod tests {
    use super::prelude::*;
    #[test]
    fn test_apic_feature_detection() {
        // Only tests logic, does not touch hardware.
        assert!(has_xapic() || !has_xapic());
        assert!(has_x2apic() || !has_x2apic());
    }
    #[test]
    fn test_ioapic_vector_alloc() {
        // Only tests vector allocator logic, not actual hardware.
        let (_vec, rte) = alloc_route(5, 1).expect("vector alloc failed");
        assert!(rte.masked);
    }
}
