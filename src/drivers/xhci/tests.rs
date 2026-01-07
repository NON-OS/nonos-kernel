// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
    use super::super::*;
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

    #[test]
    fn test_slot_context_size() {
        assert_eq!(mem::size_of::<types::SlotContext>(), 32);
    }

    #[test]
    fn test_ep_context_size() {
        assert_eq!(mem::size_of::<types::EpContext>(), 32);
    }

    #[test]
    fn test_device_context_alignment() {
        assert_eq!(mem::align_of::<types::DeviceContext>(), 64);
    }

    #[test]
    fn test_slot_context_fields() {
        let mut slot = types::SlotContext::default();

        slot.set_speed(4);
        assert_eq!(slot.speed(), 4);
        slot.set_root_hub_port(3);
        assert_eq!(slot.root_hub_port(), 3);
        slot.set_context_entries(5);
        assert_eq!(slot.context_entries(), 5);
        slot.set_hub(true);
        assert!(slot.hub());
        slot.set_mtt(true);
        assert!(slot.mtt());
    }

    #[test]
    fn test_ep_context_dequeue_pointer() {
        let mut ep = types::EpContext::default();

        ep.set_tr_dequeue_pointer(0x1000_0010, true);
        assert_eq!(ep.tr_dequeue_pointer(), 0x1000_0010);
        assert!(ep.dcs());
        ep.set_tr_dequeue_pointer(0x2000_0020, false);
        assert_eq!(ep.tr_dequeue_pointer(), 0x2000_0020);
        assert!(!ep.dcs());
    }

    #[test]
    fn test_ep_context_max_packet_size() {
        let mut ep = types::EpContext::default();
        ep.set_max_packet_size(512);
        assert_eq!(ep.max_packet_size(), 512);
        ep.set_max_packet_size(1024);
        assert_eq!(ep.max_packet_size(), 1024);
    }

    #[test]
    fn test_ep_addr_to_dci() {
        assert_eq!(types::DeviceContext::ep_addr_to_dci(0x00), 1);
        assert_eq!(types::DeviceContext::ep_addr_to_dci(0x80), 1);
        assert_eq!(types::DeviceContext::ep_addr_to_dci(0x01), 2);
        assert_eq!(types::DeviceContext::ep_addr_to_dci(0x81), 3);
        assert_eq!(types::DeviceContext::ep_addr_to_dci(0x02), 4);
        assert_eq!(types::DeviceContext::ep_addr_to_dci(0x82), 5);
    }

    #[test]
    fn test_input_control_context() {
        let mut icc = types::InputControlContext::default();

        icc.add_context(0);
        icc.add_context(1);
        assert!(icc.is_adding(0));
        assert!(icc.is_adding(1));
        assert!(!icc.is_adding(2));

        icc.drop_context(3);
        assert!(icc.is_dropping(3));
        assert!(!icc.is_dropping(0));
    }

    #[test]
    fn test_error_display() {
        let err = XhciError::InvalidSlotId(5);
        assert_eq!(err.as_str(), "Invalid slot ID");

        let err = XhciError::Timeout;
        assert_eq!(err.as_str(), "Operation timeout");
    }

    #[test]
    fn test_completion_code_extraction() {
        let err = XhciError::CompletionCodeError(6);
        assert_eq!(err.completion_code(), Some(6));

        let err = XhciError::Timeout;
        assert_eq!(err.completion_code(), None);
    }

    #[test]
    fn test_error_requires_reset() {
        assert!(XhciError::Stall.requires_endpoint_reset());
        assert!(XhciError::BabbleDetected.requires_endpoint_reset());
        assert!(!XhciError::Timeout.requires_endpoint_reset());
    }

    #[test]
    fn test_error_is_recoverable() {
        assert!(XhciError::Timeout.is_recoverable());
        assert!(XhciError::Stall.is_recoverable());
        assert!(!XhciError::HostSystemError.is_fatal());
    }

    #[test]
    fn test_from_completion_code() {
        assert!(XhciError::from_completion_code(1).is_none());
        assert!(matches!(
            XhciError::from_completion_code(6),
            Some(XhciError::Stall)
        ));
        assert!(matches!(
            XhciError::from_completion_code(3),
            Some(XhciError::BabbleDetected)
        ));
    }

    #[test]
    fn test_stats_increment() {
        let stats = stats::XhciStatistics::new();

        stats.inc_interrupts();
        stats.inc_commands();
        stats.inc_transfers();
        stats.add_bytes(1024);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.interrupts, 1);
        assert_eq!(snapshot.commands_completed, 1);
        assert_eq!(snapshot.transfers, 1);
        assert_eq!(snapshot.bytes_transferred, 1024);
    }

    #[test]
    fn test_stats_total_errors() {
        let stats = stats::XhciStatistics::new();

        stats.inc_timeouts();
        stats.inc_stalls();

        assert_eq!(stats.total_errors(), 2);
    }

    #[test]
    fn test_stats_error_rate() {
        let mut snapshot = stats::XhciStats::new();
        snapshot.transfers = 90;
        snapshot.errors = 10;

        let rate = snapshot.error_rate();
        assert!((rate - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_controller_health() {
        let mut snapshot = stats::XhciStats::new();
        snapshot.transfers = 100;
        snapshot.errors = 0;

        assert_eq!(
            stats::ControllerHealth::from_stats(&snapshot),
            stats::ControllerHealth::Healthy
        );

        snapshot.errors = 5;
        assert_eq!(
            stats::ControllerHealth::from_stats(&snapshot),
            stats::ControllerHealth::Warning
        );

        snapshot.errors = 20;
        assert_eq!(
            stats::ControllerHealth::from_stats(&snapshot),
            stats::ControllerHealth::Critical
        );
    }

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

    #[test]
    fn test_usb_device_descriptor_size() {
        assert_eq!(mem::size_of::<types::UsbDeviceDescriptor>(), 18);
    }

    #[test]
    fn test_usb_device_descriptor_validation() {
        let mut desc = types::UsbDeviceDescriptor::default();
        assert!(!desc.validate());

        desc.length = 18;
        desc.descriptor_type = constants::DESC_TYPE_DEVICE;
        assert!(desc.validate());
    }

    #[test]
    fn test_usb_version_parsing() {
        let mut desc = types::UsbDeviceDescriptor::default();
        desc.bcd_usb = 0x0200;

        let (major, minor) = desc.usb_version();
        assert_eq!(major, 2);
        assert_eq!(minor, 0);

        desc.bcd_usb = 0x0310;
        let (major, minor) = desc.usb_version();
        assert_eq!(major, 3);
        assert_eq!(minor, 0x10);
    }
}
