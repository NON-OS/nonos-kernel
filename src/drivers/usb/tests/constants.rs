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
use crate::test::framework::TestResult;

pub(crate) fn test_request_get_status() -> TestResult {
    if REQ_GET_STATUS != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_clear_feature() -> TestResult {
    if REQ_CLEAR_FEATURE != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_set_feature() -> TestResult {
    if REQ_SET_FEATURE != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_set_address() -> TestResult {
    if REQ_SET_ADDRESS != 0x05 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_get_descriptor() -> TestResult {
    if REQ_GET_DESCRIPTOR != 0x06 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_set_descriptor() -> TestResult {
    if REQ_SET_DESCRIPTOR != 0x07 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_get_configuration() -> TestResult {
    if REQ_GET_CONFIGURATION != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_set_configuration() -> TestResult {
    if REQ_SET_CONFIGURATION != 0x09 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_get_interface() -> TestResult {
    if REQ_GET_INTERFACE != 0x0A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_set_interface() -> TestResult {
    if REQ_SET_INTERFACE != 0x0B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_synch_frame() -> TestResult {
    if REQ_SYNCH_FRAME != 0x0C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_recipient_device() -> TestResult {
    if RT_DEV != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_recipient_interface() -> TestResult {
    if RT_INTF != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_recipient_endpoint() -> TestResult {
    if RT_EP != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_recipient_other() -> TestResult {
    if RT_OTHER != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_direction_out() -> TestResult {
    if DIR_OUT != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_direction_in() -> TestResult {
    if DIR_IN != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_standard() -> TestResult {
    if TYPE_STD != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_class() -> TestResult {
    if TYPE_CLASS != 0x20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_vendor() -> TestResult {
    if TYPE_VENDOR != 0x40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_device() -> TestResult {
    if DT_DEVICE != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_config() -> TestResult {
    if DT_CONFIG != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_string() -> TestResult {
    if DT_STRING != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_interface() -> TestResult {
    if DT_INTERFACE != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_endpoint() -> TestResult {
    if DT_ENDPOINT != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_device_qualifier() -> TestResult {
    if DT_DEVICE_QUALIFIER != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_other_speed_config() -> TestResult {
    if DT_OTHER_SPEED_CONFIG != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_interface_power() -> TestResult {
    if DT_INTERFACE_POWER != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_otg() -> TestResult {
    if DT_OTG != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_debug() -> TestResult {
    if DT_DEBUG != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_interface_assoc() -> TestResult {
    if DT_INTERFACE_ASSOC != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_bos() -> TestResult {
    if DT_BOS != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_device_capability() -> TestResult {
    if DT_DEVICE_CAPABILITY != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_ss_ep_companion() -> TestResult {
    if DT_SS_EP_COMPANION != 48 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_descriptor_type_ssp_isoch_ep_companion() -> TestResult {
    if DT_SSP_ISOCH_EP_COMPANION != 49 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_transfer_type_mask() -> TestResult {
    if EP_TRANSFER_TYPE_MASK != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_type_control() -> TestResult {
    if EP_TYPE_CONTROL != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_type_isochronous() -> TestResult {
    if EP_TYPE_ISOCHRONOUS != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_type_bulk() -> TestResult {
    if EP_TYPE_BULK != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_type_interrupt() -> TestResult {
    if EP_TYPE_INTERRUPT != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_sync_type_mask() -> TestResult {
    if EP_SYNC_TYPE_MASK != 0x0C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_sync_none() -> TestResult {
    if EP_SYNC_NONE != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_sync_async() -> TestResult {
    if EP_SYNC_ASYNC != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_sync_adaptive() -> TestResult {
    if EP_SYNC_ADAPTIVE != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_sync_sync() -> TestResult {
    if EP_SYNC_SYNC != 0x0C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_usage_type_mask() -> TestResult {
    if EP_USAGE_TYPE_MASK != 0x30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_usage_data() -> TestResult {
    if EP_USAGE_DATA != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_usage_feedback() -> TestResult {
    if EP_USAGE_FEEDBACK != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_usage_implicit_fb() -> TestResult {
    if EP_USAGE_IMPLICIT_FB != 0x20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_device() -> TestResult {
    if CLASS_DEVICE != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_audio() -> TestResult {
    if CLASS_AUDIO != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_cdc() -> TestResult {
    if CLASS_CDC != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_hid() -> TestResult {
    if CLASS_HID != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_physical() -> TestResult {
    if CLASS_PHYSICAL != 0x05 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_image() -> TestResult {
    if CLASS_IMAGE != 0x06 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_printer() -> TestResult {
    if CLASS_PRINTER != 0x07 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_mass_storage() -> TestResult {
    if CLASS_MASS_STORAGE != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_hub() -> TestResult {
    if CLASS_HUB != 0x09 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_cdc_data() -> TestResult {
    if CLASS_CDC_DATA != 0x0A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_smart_card() -> TestResult {
    if CLASS_SMART_CARD != 0x0B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_content_security() -> TestResult {
    if CLASS_CONTENT_SECURITY != 0x0D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_video() -> TestResult {
    if CLASS_VIDEO != 0x0E {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_personal_healthcare() -> TestResult {
    if CLASS_PERSONAL_HEALTHCARE != 0x0F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_audio_video() -> TestResult {
    if CLASS_AUDIO_VIDEO != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_billboard() -> TestResult {
    if CLASS_BILLBOARD != 0x11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_type_c_bridge() -> TestResult {
    if CLASS_TYPE_C_BRIDGE != 0x12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_diagnostic() -> TestResult {
    if CLASS_DIAGNOSTIC != 0xDC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_wireless() -> TestResult {
    if CLASS_WIRELESS != 0xE0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_misc() -> TestResult {
    if CLASS_MISC != 0xEF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_application() -> TestResult {
    if CLASS_APPLICATION != 0xFE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_vendor() -> TestResult {
    if CLASS_VENDOR != 0xFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_endpoint_halt() -> TestResult {
    if FEATURE_ENDPOINT_HALT != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_device_remote_wakeup() -> TestResult {
    if FEATURE_DEVICE_REMOTE_WAKEUP != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_test_mode() -> TestResult {
    if FEATURE_TEST_MODE != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_control_timeout() -> TestResult {
    if DEFAULT_CONTROL_TIMEOUT_US != 5_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_bulk_timeout() -> TestResult {
    if DEFAULT_BULK_TIMEOUT_US != 5_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_interrupt_timeout() -> TestResult {
    if DEFAULT_INTERRUPT_TIMEOUT_US != 1_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb2_max_control_packet() -> TestResult {
    if USB2_MAX_CONTROL_PACKET != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb3_max_control_packet() -> TestResult {
    if USB3_MAX_CONTROL_PACKET != 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_lang_id() -> TestResult {
    if DEFAULT_LANG_ID != 0x0409 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timeout_ordering() -> TestResult {
    if !(DEFAULT_INTERRUPT_TIMEOUT_US < DEFAULT_CONTROL_TIMEOUT_US) {
        return TestResult::Fail;
    }
    if DEFAULT_CONTROL_TIMEOUT_US != DEFAULT_BULK_TIMEOUT_US {
        return TestResult::Fail;
    }
    TestResult::Pass
}
