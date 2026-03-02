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

#[cfg(test)]
mod tests {
    use crate::process::capabilities::{
        Capability, CapabilitySet,
        standard_user_capabilities, privileged_capabilities, full_capabilities,
        sandboxed_capabilities,
    };

    #[test]
    fn new_is_empty() {
        let c = CapabilitySet::new();
        assert!(c.is_empty());
        assert_eq!(c.bits(), 0);
    }

    #[test]
    fn insert_and_remove_bits() {
        let mut c = CapabilitySet::new();
        c.grant(Capability::Read);
        c.grant(Capability::Write);
        assert!(c.can_read());
        assert!(c.can_write());
        assert!(!c.can_open_files());

        c.revoke(Capability::Write);
        assert!(c.can_read());
        assert!(!c.can_write());
    }

    #[test]
    fn derived_permissions() {
        let mut c = CapabilitySet::new();
        // Without direct stat, read should grant stat
        c.grant(Capability::Read);
        assert!(c.can_stat());
        assert!(c.can_seek());

        c.revoke(Capability::Read);
        assert!(!c.can_stat());
        assert!(!c.can_seek());

        c.grant(Capability::OpenFiles);
        assert!(c.can_stat());
        c.grant(Capability::Write);
        assert!(c.can_seek());
        assert!(c.can_unlink());
        assert!(c.can_modify_dirs());
    }

    #[test]
    fn superset_logic() {
        let a = CapabilitySet::from_bits(0b1011);
        let b = CapabilitySet::from_bits(0b0011);
        assert!(a.is_superset_of(&b));
        assert!(!b.is_superset_of(&a));
    }

    #[test]
    fn capability_bits_match_enum() {
        assert_eq!(Capability::Exit.bit(), 0);
        assert_eq!(Capability::Read.bit(), 1);
        assert_eq!(Capability::Write.bit(), 2);
        assert_eq!(Capability::Admin.bit(), 17);
        assert_eq!(Capability::Signal.bit(), 23);
    }

    #[test]
    fn has_method_consistency() {
        let mut c = CapabilitySet::new();
        c.grant(Capability::Read);
        assert!(c.has(Capability::Read));
        assert!(c.can_read());
        assert!(!c.has(Capability::Write));
        assert!(!c.can_write());
    }

    #[test]
    fn standard_capabilities_are_reasonable() {
        let caps = standard_user_capabilities();
        assert!(caps.can_exit());
        assert!(caps.can_read());
        assert!(caps.can_write());
        assert!(caps.can_allocate_memory());
        assert!(!caps.can_fork());
        assert!(!caps.is_admin());
        assert!(!caps.can_network());
    }

    #[test]
    fn privileged_capabilities_include_standard() {
        let standard = standard_user_capabilities();
        let privileged = privileged_capabilities();

        assert!(privileged.is_superset_of(&standard));
        assert!(privileged.can_fork());
        assert!(privileged.can_exec());
        assert!(privileged.can_signal());
        assert!(privileged.can_network());
        assert!(!privileged.is_admin());
    }

    #[test]
    fn full_capabilities_has_all() {
        let full = full_capabilities();
        assert!(full.can_exit());
        assert!(full.can_read());
        assert!(full.can_write());
        assert!(full.can_fork());
        assert!(full.can_exec());
        assert!(full.is_admin());
        assert!(full.can_network());
        assert!(full.can_raw_io());
        assert!(full.can_chroot());
        assert!(full.can_signal());
    }

    #[test]
    fn sandboxed_is_minimal() {
        let sandboxed = sandboxed_capabilities();
        assert!(sandboxed.can_exit());
        assert!(sandboxed.can_read());
        assert!(sandboxed.can_write());
        assert!(!sandboxed.can_open_files());
        assert!(!sandboxed.can_fork());
        assert!(!sandboxed.can_network());
    }

    #[test]
    fn admin_implies_privileged_operations() {
        let mut c = CapabilitySet::new();
        c.grant(Capability::Admin);

        // Admin should grant setuid, setgid, chroot
        assert!(c.can_setuid());
        assert!(c.can_setgid());
        assert!(c.can_chroot());
    }

    #[test]
    fn capability_names_are_valid() {
        assert_eq!(Capability::Exit.name(), "exit");
        assert_eq!(Capability::Read.name(), "read");
        assert_eq!(Capability::Admin.name(), "admin");
        assert_eq!(Capability::Signal.name(), "signal");
    }

    #[test]
    fn clear_removes_all() {
        let mut c = full_capabilities();
        assert!(!c.is_empty());
        c.clear();
        assert!(c.is_empty());
        assert_eq!(c.bits(), 0);
    }

    #[test]
    fn default_is_empty() {
        let c = CapabilitySet::default();
        assert!(c.is_empty());
    }
}
