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
    use crate::drivers::xhci::constants;

    #[test]
    fn test_portsc_change_bits() {
        let change_bits = constants::PORTSC_CHANGE_BITS;
        assert_eq!(change_bits & constants::PORTSC_CSC, constants::PORTSC_CSC);
        assert_eq!(change_bits & constants::PORTSC_PEC, constants::PORTSC_PEC);
        assert_eq!(change_bits & constants::PORTSC_PRC, constants::PORTSC_PRC);
        assert_eq!(change_bits & constants::PORTSC_PED, 0);
    }

    #[test]
    fn test_trb_alignment_constant() {
        assert_eq!(constants::TRB_ALIGNMENT, 16);
        assert!(constants::DMA_MIN_ALIGNMENT >= constants::TRB_ALIGNMENT as usize);
    }

    #[test]
    fn test_ring_size_constants() {
        assert!(constants::MIN_RING_SIZE >= 16);
        assert!(constants::MAX_RING_SIZE >= constants::MIN_RING_SIZE);
        assert!(constants::DEFAULT_CMD_RING_SIZE >= constants::MIN_RING_SIZE);
        assert!(constants::DEFAULT_EVENT_RING_SIZE >= constants::MIN_RING_SIZE);
    }

    #[test]
    fn test_valid_trb_types_lists() {
        assert!(constants::VALID_TRANSFER_TRB_TYPES.contains(&constants::TRB_TYPE_NORMAL));
        assert!(constants::VALID_TRANSFER_TRB_TYPES.contains(&constants::TRB_TYPE_SETUP_STAGE));
        assert!(constants::VALID_TRANSFER_TRB_TYPES.contains(&constants::TRB_TYPE_LINK));

        assert!(constants::VALID_COMMAND_TRB_TYPES.contains(&constants::TRB_TYPE_ENABLE_SLOT_CMD));
        assert!(
            constants::VALID_COMMAND_TRB_TYPES.contains(&constants::TRB_TYPE_ADDRESS_DEVICE_CMD)
        );
    }
}
