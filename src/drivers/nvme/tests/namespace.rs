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

extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use crate::drivers::nvme::namespace;

    #[test]
    fn test_namespace_lba_validation() {
        let mut ns_data = [0u8; 4096];

        ns_data[0x00..0x08].copy_from_slice(&1000u64.to_le_bytes());
        ns_data[0x08..0x10].copy_from_slice(&1000u64.to_le_bytes());
        ns_data[0x19] = 0;
        ns_data[0x1A] = 0;
        ns_data[0x80..0x84].copy_from_slice(&0x0000_0900u32.to_le_bytes());

        let ns = namespace::Namespace::from_identify_data(1, &ns_data).unwrap();

        assert!(ns.validate_lba_range(0, 100).is_ok());
        assert!(ns.validate_lba_range(900, 100).is_ok());
        assert!(ns.validate_lba_range(900, 101).is_err());
        assert!(ns.validate_lba_range(1000, 1).is_err());
        assert!(ns.validate_lba_range(0, 0).is_err());
    }

    #[test]
    fn test_namespace_manager() {
        let mut manager = namespace::NamespaceManager::new();

        let mut ns_data = [0u8; 4096];
        ns_data[0x00..0x08].copy_from_slice(&1000u64.to_le_bytes());
        ns_data[0x08..0x10].copy_from_slice(&1000u64.to_le_bytes());
        ns_data[0x80..0x84].copy_from_slice(&0x0000_0900u32.to_le_bytes());

        let ns1 = namespace::Namespace::from_identify_data(1, &ns_data).unwrap();
        let ns2 = namespace::Namespace::from_identify_data(2, &ns_data).unwrap();

        manager.add(ns1);
        manager.add(ns2);

        assert_eq!(manager.count(), 2);
        assert!(manager.get(1).is_some());
        assert!(manager.get(2).is_some());
        assert!(manager.get(3).is_none());

        let nsids = manager.nsids();
        assert_eq!(nsids, vec![1, 2]);
    }

    #[test]
    fn test_namespace_list_parsing() {
        let mut data = [0u8; 4096];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&2u32.to_le_bytes());
        data[8..12].copy_from_slice(&5u32.to_le_bytes());

        let nsids = namespace::parse_namespace_list(&data);
        assert_eq!(nsids, vec![1, 2, 5]);
    }
}
