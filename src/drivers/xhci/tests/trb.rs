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
    use crate::drivers::xhci::{constants, trb, Trb};
    use core::mem;

    #[test]
    fn test_trb_size_and_alignment() {
        assert_eq!(mem::size_of::<Trb>(), 16);
        assert_eq!(mem::align_of::<Trb>(), 16);
    }

    #[test]
    fn test_trb_type_field() {
        let mut trb = Trb::default();

        trb.set_type(constants::TRB_TYPE_NORMAL);
        assert_eq!(trb.get_type(), constants::TRB_TYPE_NORMAL);

        trb.set_type(constants::TRB_TYPE_LINK);
        assert_eq!(trb.get_type(), constants::TRB_TYPE_LINK);

        trb.set_type(constants::TRB_TYPE_SETUP_STAGE);
        assert_eq!(trb.get_type(), constants::TRB_TYPE_SETUP_STAGE);
    }

    #[test]
    fn test_trb_cycle_bit() {
        let mut trb = Trb::default();

        assert!(!trb.get_cycle());

        trb.set_cycle(true);
        assert!(trb.get_cycle());

        trb.set_cycle(false);
        assert!(!trb.get_cycle());
    }

    #[test]
    fn test_trb_pointer() {
        let mut trb = Trb::default();
        let ptr = 0x1234_5678_9ABC_DEF0u64;

        trb.set_pointer(ptr);
        assert_eq!(trb.get_pointer(), ptr);
    }

    #[test]
    fn test_trb_ioc_bit() {
        let mut trb = Trb::default();

        assert!(!trb.ioc());

        trb.set_ioc(true);
        assert!(trb.ioc());

        trb.set_ioc(false);
        assert!(!trb.ioc());
    }

    #[test]
    fn test_trb_pointer_alignment_validation() {
        assert!(Trb::validate_pointer_alignment(0x1000).is_ok());
        assert!(Trb::validate_pointer_alignment(0x1010).is_ok());
        assert!(Trb::validate_pointer_alignment(0x1001).is_err());
        assert!(Trb::validate_pointer_alignment(0x1008).is_err());
    }

    #[test]
    fn test_setup_stage_builder() {
        let trb = trb::SetupStageTrbBuilder::new()
            .setup_packet(0x80, 0x06, 0x0100, 0x0000, 18)
            .transfer_type(true, true)
            .cycle(true)
            .build();

        assert_eq!(trb.get_type(), constants::TRB_TYPE_SETUP_STAGE);
        assert!(trb.get_cycle());
        assert_eq!(trb.d0 & 0xFF, 0x80);
        assert_eq!((trb.d0 >> 8) & 0xFF, 0x06);
    }

    #[test]
    fn test_data_stage_builder() {
        let trb = trb::DataStageTrbBuilder::new()
            .data_buffer(0x1000, 512)
            .direction_in(true)
            .ioc(true)
            .cycle(true)
            .build();

        assert_eq!(trb.get_type(), constants::TRB_TYPE_DATA_STAGE);
        assert!(trb.get_cycle());
        assert!(trb.ioc());
        assert_eq!(trb.get_pointer(), 0x1000);
        assert_eq!(trb.get_transfer_length(), 512);
    }

    #[test]
    fn test_status_stage_builder() {
        let trb = trb::StatusStageTrbBuilder::new()
            .direction_in(false)
            .cycle(true)
            .build();

        assert_eq!(trb.get_type(), constants::TRB_TYPE_STATUS_STAGE);
        assert!(trb.get_cycle());
    }

    #[test]
    fn test_link_trb_builder() {
        let trb = trb::LinkTrbBuilder::new()
            .target(0x2000)
            .toggle_cycle(true)
            .cycle(true)
            .build();

        assert_eq!(trb.get_type(), constants::TRB_TYPE_LINK);
        assert!(trb.get_cycle());
        assert_eq!(trb.get_pointer(), 0x2000);
    }

    #[test]
    fn test_enable_slot_command() {
        let trb = trb::enable_slot_command(true);
        assert_eq!(trb.get_type(), constants::TRB_TYPE_ENABLE_SLOT_CMD);
        assert!(trb.get_cycle());
    }

    #[test]
    fn test_address_device_command() {
        let trb = trb::address_device_command(0x3000, 5, false, true);
        assert_eq!(trb.get_type(), constants::TRB_TYPE_ADDRESS_DEVICE_CMD);
        assert!(trb.get_cycle());
        assert_eq!(trb.get_pointer(), 0x3000);
        assert_eq!(trb.slot_id(), 5);
    }
}
