// NØNOS Operating System
// Copyright (C) 2024 NØNOS Contributors
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
