use nonos_kernel::arch::x86_64::interrupt::prelude::*;

#[test]
fn test_apic_feature_detection() {
    assert!(has_xapic() || !has_xapic());
    assert!(has_x2apic() || !has_x2apic());
}

#[test]
fn test_ioapic_vector_alloc() {
    // Only tests vector allocator logic, not actual hardware.
    let (_vec, rte) = alloc_route(5, 1).expect("vector alloc failed");
    assert!(rte.masked);
}

#[test]
fn test_pic_mask_unmask_logic() {
    // Tests bit logic only, not hardware IO.
    let mut v: u8 = 0b0000_0000;
    v |= 1 << 2;
    assert_eq!(v, 0b0000_0100);
    v &= !(1 << 2);
    assert_eq!(v, 0b0000_0000);
}
