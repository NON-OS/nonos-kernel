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

use crate::drivers::usb::constants::*;

#[test]
fn test_request_get_status() {
    assert_eq!(REQ_GET_STATUS, 0x00);
}

#[test]
fn test_request_clear_feature() {
    assert_eq!(REQ_CLEAR_FEATURE, 0x01);
}

#[test]
fn test_request_set_feature() {
    assert_eq!(REQ_SET_FEATURE, 0x03);
}

#[test]
fn test_request_set_address() {
    assert_eq!(REQ_SET_ADDRESS, 0x05);
}

#[test]
fn test_request_get_descriptor() {
    assert_eq!(REQ_GET_DESCRIPTOR, 0x06);
}

#[test]
fn test_request_set_descriptor() {
    assert_eq!(REQ_SET_DESCRIPTOR, 0x07);
}

#[test]
fn test_request_get_configuration() {
    assert_eq!(REQ_GET_CONFIGURATION, 0x08);
}

#[test]
fn test_request_set_configuration() {
    assert_eq!(REQ_SET_CONFIGURATION, 0x09);
}

#[test]
fn test_request_get_interface() {
    assert_eq!(REQ_GET_INTERFACE, 0x0A);
}

#[test]
fn test_request_set_interface() {
    assert_eq!(REQ_SET_INTERFACE, 0x0B);
}

#[test]
fn test_request_synch_frame() {
    assert_eq!(REQ_SYNCH_FRAME, 0x0C);
}

#[test]
fn test_recipient_device() {
    assert_eq!(RT_DEV, 0x00);
}

#[test]
fn test_recipient_interface() {
    assert_eq!(RT_INTF, 0x01);
}

#[test]
fn test_recipient_endpoint() {
    assert_eq!(RT_EP, 0x02);
}

#[test]
fn test_recipient_other() {
    assert_eq!(RT_OTHER, 0x03);
}

#[test]
fn test_direction_out() {
    assert_eq!(DIR_OUT, 0x00);
}

#[test]
fn test_direction_in() {
    assert_eq!(DIR_IN, 0x80);
}

#[test]
fn test_type_standard() {
    assert_eq!(TYPE_STD, 0x00);
}

#[test]
fn test_type_class() {
    assert_eq!(TYPE_CLASS, 0x20);
}

#[test]
fn test_type_vendor() {
    assert_eq!(TYPE_VENDOR, 0x40);
}

#[test]
fn test_descriptor_type_device() {
    assert_eq!(DT_DEVICE, 1);
}

#[test]
fn test_descriptor_type_config() {
    assert_eq!(DT_CONFIG, 2);
}

#[test]
fn test_descriptor_type_string() {
    assert_eq!(DT_STRING, 3);
}

#[test]
fn test_descriptor_type_interface() {
    assert_eq!(DT_INTERFACE, 4);
}

#[test]
fn test_descriptor_type_endpoint() {
    assert_eq!(DT_ENDPOINT, 5);
}

#[test]
fn test_descriptor_type_device_qualifier() {
    assert_eq!(DT_DEVICE_QUALIFIER, 6);
}

#[test]
fn test_descriptor_type_other_speed_config() {
    assert_eq!(DT_OTHER_SPEED_CONFIG, 7);
}

#[test]
fn test_descriptor_type_interface_power() {
    assert_eq!(DT_INTERFACE_POWER, 8);
}

#[test]
fn test_descriptor_type_otg() {
    assert_eq!(DT_OTG, 9);
}

#[test]
fn test_descriptor_type_debug() {
    assert_eq!(DT_DEBUG, 10);
}

#[test]
fn test_descriptor_type_interface_assoc() {
    assert_eq!(DT_INTERFACE_ASSOC, 11);
}

#[test]
fn test_descriptor_type_bos() {
    assert_eq!(DT_BOS, 15);
}

#[test]
fn test_descriptor_type_device_capability() {
    assert_eq!(DT_DEVICE_CAPABILITY, 16);
}

#[test]
fn test_descriptor_type_ss_ep_companion() {
    assert_eq!(DT_SS_EP_COMPANION, 48);
}

#[test]
fn test_descriptor_type_ssp_isoch_ep_companion() {
    assert_eq!(DT_SSP_ISOCH_EP_COMPANION, 49);
}

#[test]
fn test_endpoint_transfer_type_mask() {
    assert_eq!(EP_TRANSFER_TYPE_MASK, 0x03);
}

#[test]
fn test_endpoint_type_control() {
    assert_eq!(EP_TYPE_CONTROL, 0x00);
}

#[test]
fn test_endpoint_type_isochronous() {
    assert_eq!(EP_TYPE_ISOCHRONOUS, 0x01);
}

#[test]
fn test_endpoint_type_bulk() {
    assert_eq!(EP_TYPE_BULK, 0x02);
}

#[test]
fn test_endpoint_type_interrupt() {
    assert_eq!(EP_TYPE_INTERRUPT, 0x03);
}

#[test]
fn test_endpoint_sync_type_mask() {
    assert_eq!(EP_SYNC_TYPE_MASK, 0x0C);
}

#[test]
fn test_endpoint_sync_none() {
    assert_eq!(EP_SYNC_NONE, 0x00);
}

#[test]
fn test_endpoint_sync_async() {
    assert_eq!(EP_SYNC_ASYNC, 0x04);
}

#[test]
fn test_endpoint_sync_adaptive() {
    assert_eq!(EP_SYNC_ADAPTIVE, 0x08);
}

#[test]
fn test_endpoint_sync_sync() {
    assert_eq!(EP_SYNC_SYNC, 0x0C);
}

#[test]
fn test_endpoint_usage_type_mask() {
    assert_eq!(EP_USAGE_TYPE_MASK, 0x30);
}

#[test]
fn test_endpoint_usage_data() {
    assert_eq!(EP_USAGE_DATA, 0x00);
}

#[test]
fn test_endpoint_usage_feedback() {
    assert_eq!(EP_USAGE_FEEDBACK, 0x10);
}

#[test]
fn test_endpoint_usage_implicit_fb() {
    assert_eq!(EP_USAGE_IMPLICIT_FB, 0x20);
}

#[test]
fn test_class_device() {
    assert_eq!(CLASS_DEVICE, 0x00);
}

#[test]
fn test_class_audio() {
    assert_eq!(CLASS_AUDIO, 0x01);
}

#[test]
fn test_class_cdc() {
    assert_eq!(CLASS_CDC, 0x02);
}

#[test]
fn test_class_hid() {
    assert_eq!(CLASS_HID, 0x03);
}

#[test]
fn test_class_physical() {
    assert_eq!(CLASS_PHYSICAL, 0x05);
}

#[test]
fn test_class_image() {
    assert_eq!(CLASS_IMAGE, 0x06);
}

#[test]
fn test_class_printer() {
    assert_eq!(CLASS_PRINTER, 0x07);
}

#[test]
fn test_class_mass_storage() {
    assert_eq!(CLASS_MASS_STORAGE, 0x08);
}

#[test]
fn test_class_hub() {
    assert_eq!(CLASS_HUB, 0x09);
}

#[test]
fn test_class_cdc_data() {
    assert_eq!(CLASS_CDC_DATA, 0x0A);
}

#[test]
fn test_class_smart_card() {
    assert_eq!(CLASS_SMART_CARD, 0x0B);
}

#[test]
fn test_class_content_security() {
    assert_eq!(CLASS_CONTENT_SECURITY, 0x0D);
}

#[test]
fn test_class_video() {
    assert_eq!(CLASS_VIDEO, 0x0E);
}

#[test]
fn test_class_personal_healthcare() {
    assert_eq!(CLASS_PERSONAL_HEALTHCARE, 0x0F);
}

#[test]
fn test_class_audio_video() {
    assert_eq!(CLASS_AUDIO_VIDEO, 0x10);
}

#[test]
fn test_class_billboard() {
    assert_eq!(CLASS_BILLBOARD, 0x11);
}

#[test]
fn test_class_type_c_bridge() {
    assert_eq!(CLASS_TYPE_C_BRIDGE, 0x12);
}

#[test]
fn test_class_diagnostic() {
    assert_eq!(CLASS_DIAGNOSTIC, 0xDC);
}

#[test]
fn test_class_wireless() {
    assert_eq!(CLASS_WIRELESS, 0xE0);
}

#[test]
fn test_class_misc() {
    assert_eq!(CLASS_MISC, 0xEF);
}

#[test]
fn test_class_application() {
    assert_eq!(CLASS_APPLICATION, 0xFE);
}

#[test]
fn test_class_vendor() {
    assert_eq!(CLASS_VENDOR, 0xFF);
}

#[test]
fn test_feature_endpoint_halt() {
    assert_eq!(FEATURE_ENDPOINT_HALT, 0);
}

#[test]
fn test_feature_device_remote_wakeup() {
    assert_eq!(FEATURE_DEVICE_REMOTE_WAKEUP, 1);
}

#[test]
fn test_feature_test_mode() {
    assert_eq!(FEATURE_TEST_MODE, 2);
}

#[test]
fn test_default_control_timeout() {
    assert_eq!(DEFAULT_CONTROL_TIMEOUT_US, 5_000_000);
}

#[test]
fn test_default_bulk_timeout() {
    assert_eq!(DEFAULT_BULK_TIMEOUT_US, 5_000_000);
}

#[test]
fn test_default_interrupt_timeout() {
    assert_eq!(DEFAULT_INTERRUPT_TIMEOUT_US, 1_000_000);
}

#[test]
fn test_usb2_max_control_packet() {
    assert_eq!(USB2_MAX_CONTROL_PACKET, 64);
}

#[test]
fn test_usb3_max_control_packet() {
    assert_eq!(USB3_MAX_CONTROL_PACKET, 512);
}

#[test]
fn test_default_lang_id() {
    assert_eq!(DEFAULT_LANG_ID, 0x0409);
}

#[test]
fn test_timeout_ordering() {
    assert!(DEFAULT_INTERRUPT_TIMEOUT_US < DEFAULT_CONTROL_TIMEOUT_US);
    assert_eq!(DEFAULT_CONTROL_TIMEOUT_US, DEFAULT_BULK_TIMEOUT_US);
}
