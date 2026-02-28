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
    use super::super::types::{SignatureEntry, SignatureList};
    use super::super::parse::{parse_signature_lists, hash_in_signature_lists, count_signatures, extract_hashes};
    use super::super::build::build_signature_list;
    use crate::arch::x86_64::uefi::types::Guid;

    #[test]
    fn test_signature_entry_creation() {
        let owner = Guid::NONOS_OWNER;
        let data = vec![0xAB; 32];
        let entry = SignatureEntry::new(owner, data.clone());

        assert_eq!(entry.owner, owner);
        assert_eq!(entry.data, data);
        assert_eq!(entry.data_len(), 32);
        assert_eq!(entry.total_size(), 48);
    }

    #[test]
    fn test_signature_list_creation() {
        let list = SignatureList::new(Guid::CERT_SHA256);
        assert!(list.is_empty());
        assert_eq!(list.entry_count(), 0);
    }

    #[test]
    fn test_build_signature_list() {
        let hash = [0xAB; 32];
        let list_data = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &hash);

        assert_eq!(list_data.len(), 76);

        let sig_type = Guid::from_bytes(&list_data[0..16]).unwrap();
        assert_eq!(sig_type, Guid::CERT_SHA256);

        let list_size = u32::from_le_bytes([list_data[16], list_data[17], list_data[18], list_data[19]]);
        assert_eq!(list_size, 76);
    }

    #[test]
    fn test_parse_signature_list() {
        let hash = [0xAB; 32];
        let list_data = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &hash);

        let lists = parse_signature_lists(&list_data).unwrap();
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].signature_type, Guid::CERT_SHA256);
        assert_eq!(lists[0].entries.len(), 1);
        assert_eq!(lists[0].entries[0].owner, Guid::NONOS_OWNER);
        assert_eq!(lists[0].entries[0].data, hash.to_vec());
    }

    #[test]
    fn test_hash_in_signature_lists() {
        let hash = [0xCD; 32];
        let list_data = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &hash);
        let lists = parse_signature_lists(&list_data).unwrap();

        assert!(hash_in_signature_lists(&hash, &lists));
        assert!(!hash_in_signature_lists(&[0xFF; 32], &lists));
    }

    #[test]
    fn test_roundtrip() {
        let mut list = SignatureList::new(Guid::CERT_SHA256);
        list.add_entry(SignatureEntry::new(Guid::NONOS_OWNER, vec![0x11; 32]));
        list.add_entry(SignatureEntry::new(Guid::NONOS_OWNER, vec![0x22; 32]));

        let bytes = list.to_bytes();
        let parsed = parse_signature_lists(&bytes).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].entries.len(), 2);
        assert_eq!(parsed[0].entries[0].data, vec![0x11; 32]);
        assert_eq!(parsed[0].entries[1].data, vec![0x22; 32]);
    }

    #[test]
    fn test_multiple_lists() {
        let list1 = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &[0x11; 32]);
        let list2 = build_signature_list(&Guid::CERT_SHA384, &Guid::NONOS_OWNER, &[0x22; 48]);

        let mut combined = list1;
        combined.extend_from_slice(&list2);

        let parsed = parse_signature_lists(&combined).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].signature_type, Guid::CERT_SHA256);
        assert_eq!(parsed[1].signature_type, Guid::CERT_SHA384);
    }

    #[test]
    fn test_parse_empty() {
        let lists = parse_signature_lists(&[]).unwrap();
        assert!(lists.is_empty());
    }

    #[test]
    fn test_parse_invalid() {
        let result = parse_signature_lists(&[0; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_count_signatures() {
        let list = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &[0x11; 32]);
        assert_eq!(count_signatures(&list).unwrap(), 1);
    }

    #[test]
    fn test_extract_hashes() {
        let list = build_signature_list(&Guid::CERT_SHA256, &Guid::NONOS_OWNER, &[0xAB; 32]);
        let hashes = extract_hashes(&list, &Guid::CERT_SHA256).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], vec![0xAB; 32]);
    }
}
