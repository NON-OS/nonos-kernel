use crate::input::usb_hid::transfer::{
    EpInfo, TRB_IDT, TRB_IOC, TRB_TYPE_DATA, TRB_TYPE_SETUP, TRB_TYPE_STATUS, USB_CLASS_HID,
    USB_DESC_CONFIGURATION, USB_DESC_DEVICE, USB_DESC_ENDPOINT, USB_DESC_INTERFACE,
    USB_HID_REQ_SET_IDLE, USB_HID_REQ_SET_PROTOCOL, USB_REQ_GET_DESCRIPTOR,
    USB_REQ_SET_CONFIGURATION,
};
use crate::input::usb_hid::{
    hid_to_ascii, KBD_AVAIL, MOUSE_AVAIL, MOUSE_BTN, MOUSE_X, MOUSE_Y, SCR_H, SCR_W, USB_INIT,
};
use crate::test::framework::TestResult;
use core::sync::atomic::Ordering;

fn reset_usb_state() {
    USB_INIT.store(false, Ordering::SeqCst);
    KBD_AVAIL.store(false, Ordering::SeqCst);
    MOUSE_AVAIL.store(false, Ordering::SeqCst);
    MOUSE_X.store(400, Ordering::SeqCst);
    MOUSE_Y.store(300, Ordering::SeqCst);
    MOUSE_BTN.store(0, Ordering::SeqCst);
    SCR_W.store(800, Ordering::SeqCst);
    SCR_H.store(600, Ordering::SeqCst);
}

pub(crate) fn test_hid_to_ascii_letters() -> TestResult {
    if hid_to_ascii(0x04, 0x00) != Some(b'a') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x05, 0x00) != Some(b'b') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x06, 0x00) != Some(b'c') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x07, 0x00) != Some(b'd') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x08, 0x00) != Some(b'e') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x09, 0x00) != Some(b'f') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x1D, 0x00) != Some(b'z') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_shifted_letters() -> TestResult {
    if hid_to_ascii(0x04, 0x02) != Some(b'A') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x05, 0x02) != Some(b'B') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x1D, 0x02) != Some(b'Z') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x04, 0x20) != Some(b'A') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_numbers() -> TestResult {
    if hid_to_ascii(0x1E, 0x00) != Some(b'1') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x1F, 0x00) != Some(b'2') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x20, 0x00) != Some(b'3') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x21, 0x00) != Some(b'4') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x22, 0x00) != Some(b'5') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x23, 0x00) != Some(b'6') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x24, 0x00) != Some(b'7') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x25, 0x00) != Some(b'8') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x26, 0x00) != Some(b'9') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x27, 0x00) != Some(b'0') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_shifted_numbers() -> TestResult {
    if hid_to_ascii(0x1E, 0x02) != Some(b'!') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x1F, 0x02) != Some(b'@') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x20, 0x02) != Some(b'#') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x21, 0x02) != Some(b'$') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x22, 0x02) != Some(b'%') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x23, 0x02) != Some(b'^') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x24, 0x02) != Some(b'&') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x25, 0x02) != Some(b'*') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x26, 0x02) != Some(b'(') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x27, 0x02) != Some(b')') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_special_keys() -> TestResult {
    if hid_to_ascii(0x28, 0x00) != Some(13) {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x29, 0x00) != Some(27) {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x2A, 0x00) != Some(8) {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x2B, 0x00) != Some(9) {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x2C, 0x00) != Some(b' ') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_punctuation() -> TestResult {
    if hid_to_ascii(0x2D, 0x00) != Some(b'-') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x2E, 0x00) != Some(b'=') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x2F, 0x00) != Some(b'[') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x30, 0x00) != Some(b']') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x31, 0x00) != Some(b'\\') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_shifted_punctuation() -> TestResult {
    if hid_to_ascii(0x2D, 0x02) != Some(b'_') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x2E, 0x02) != Some(b'+') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x2F, 0x02) != Some(b'{') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x30, 0x02) != Some(b'}') {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x31, 0x02) != Some(b'|') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_invalid_code() -> TestResult {
    if hid_to_ascii(0x00, 0x00) != None {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x01, 0x00) != None {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x02, 0x00) != None {
        return TestResult::Fail;
    }
    if hid_to_ascii(0x03, 0x00) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_out_of_range() -> TestResult {
    if hid_to_ascii(0x80, 0x00) != None {
        return TestResult::Fail;
    }
    if hid_to_ascii(0xFF, 0x00) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_to_ascii_forward_delete() -> TestResult {
    if hid_to_ascii(0x4C, 0x00) != Some(0x7F) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trb_type_constants() -> TestResult {
    if TRB_TYPE_SETUP != 2 {
        return TestResult::Fail;
    }
    if TRB_TYPE_DATA != 3 {
        return TestResult::Fail;
    }
    if TRB_TYPE_STATUS != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trb_flag_constants() -> TestResult {
    if TRB_IOC != 1 << 5 {
        return TestResult::Fail;
    }
    if TRB_IDT != 1 << 6 {
        return TestResult::Fail;
    }
    if TRB_IOC != 32 {
        return TestResult::Fail;
    }
    if TRB_IDT != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_request_constants() -> TestResult {
    if USB_REQ_GET_DESCRIPTOR != 0x06 {
        return TestResult::Fail;
    }
    if USB_REQ_SET_CONFIGURATION != 0x09 {
        return TestResult::Fail;
    }
    if USB_HID_REQ_SET_PROTOCOL != 0x0B {
        return TestResult::Fail;
    }
    if USB_HID_REQ_SET_IDLE != 0x0A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_descriptor_type_constants() -> TestResult {
    if USB_DESC_DEVICE != 0x01 {
        return TestResult::Fail;
    }
    if USB_DESC_CONFIGURATION != 0x02 {
        return TestResult::Fail;
    }
    if USB_DESC_INTERFACE != 0x04 {
        return TestResult::Fail;
    }
    if USB_DESC_ENDPOINT != 0x05 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_class_hid() -> TestResult {
    if USB_CLASS_HID != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ep_info_is_interrupt() -> TestResult {
    let interrupt_ep = EpInfo { address: 0x81, attributes: 0x03, max_packet: 8, interval: 10 };
    if !interrupt_ep.is_interrupt() {
        return TestResult::Fail;
    }

    let bulk_ep = EpInfo { address: 0x82, attributes: 0x02, max_packet: 512, interval: 0 };
    if bulk_ep.is_interrupt() {
        return TestResult::Fail;
    }

    let control_ep = EpInfo { address: 0x00, attributes: 0x00, max_packet: 64, interval: 0 };
    if control_ep.is_interrupt() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ep_info_structure() -> TestResult {
    let ep = EpInfo { address: 0x81, attributes: 0x03, max_packet: 64, interval: 10 };
    if ep.address != 0x81 {
        return TestResult::Fail;
    }
    if ep.attributes != 0x03 {
        return TestResult::Fail;
    }
    if ep.max_packet != 64 {
        return TestResult::Fail;
    }
    if ep.interval != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_state_defaults() -> TestResult {
    reset_usb_state();
    if USB_INIT.load(Ordering::Relaxed) {
        return TestResult::Fail;
    }
    if KBD_AVAIL.load(Ordering::Relaxed) {
        return TestResult::Fail;
    }
    if MOUSE_AVAIL.load(Ordering::Relaxed) {
        return TestResult::Fail;
    }
    if MOUSE_X.load(Ordering::Relaxed) != 400 {
        return TestResult::Fail;
    }
    if MOUSE_Y.load(Ordering::Relaxed) != 300 {
        return TestResult::Fail;
    }
    if MOUSE_BTN.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if SCR_W.load(Ordering::Relaxed) != 800 {
        return TestResult::Fail;
    }
    if SCR_H.load(Ordering::Relaxed) != 600 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_state_initialization() -> TestResult {
    reset_usb_state();
    USB_INIT.store(true, Ordering::SeqCst);
    KBD_AVAIL.store(true, Ordering::SeqCst);
    MOUSE_AVAIL.store(true, Ordering::SeqCst);

    if !USB_INIT.load(Ordering::Relaxed) {
        return TestResult::Fail;
    }
    if !KBD_AVAIL.load(Ordering::Relaxed) {
        return TestResult::Fail;
    }
    if !MOUSE_AVAIL.load(Ordering::Relaxed) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_mouse_position() -> TestResult {
    reset_usb_state();
    MOUSE_X.store(100, Ordering::SeqCst);
    MOUSE_Y.store(200, Ordering::SeqCst);

    if MOUSE_X.load(Ordering::Relaxed) != 100 {
        return TestResult::Fail;
    }
    if MOUSE_Y.load(Ordering::Relaxed) != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_mouse_buttons() -> TestResult {
    reset_usb_state();
    MOUSE_BTN.store(0x01, Ordering::SeqCst);
    if MOUSE_BTN.load(Ordering::Relaxed) & 0x01 != 0x01 {
        return TestResult::Fail;
    }

    MOUSE_BTN.store(0x02, Ordering::SeqCst);
    if MOUSE_BTN.load(Ordering::Relaxed) & 0x02 != 0x02 {
        return TestResult::Fail;
    }

    MOUSE_BTN.store(0x03, Ordering::SeqCst);
    if MOUSE_BTN.load(Ordering::Relaxed) & 0x01 != 0x01 {
        return TestResult::Fail;
    }
    if MOUSE_BTN.load(Ordering::Relaxed) & 0x02 != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_usb_screen_bounds() -> TestResult {
    reset_usb_state();
    SCR_W.store(1920, Ordering::SeqCst);
    SCR_H.store(1080, Ordering::SeqCst);

    if SCR_W.load(Ordering::Relaxed) != 1920 {
        return TestResult::Fail;
    }
    if SCR_H.load(Ordering::Relaxed) != 1080 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_modifier_left_shift() -> TestResult {
    let mods = 0x02;
    let shift = (mods & 0x22) != 0;
    if !shift {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_modifier_right_shift() -> TestResult {
    let mods = 0x20;
    let shift = (mods & 0x22) != 0;
    if !shift {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_modifier_no_shift() -> TestResult {
    let mods = 0x00;
    let shift = (mods & 0x22) != 0;
    if shift {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_direction() -> TestResult {
    let in_ep = 0x81u8;
    let out_ep = 0x01u8;

    if (in_ep & 0x80) == 0 {
        return TestResult::Fail;
    }
    if (out_ep & 0x80) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_endpoint_number() -> TestResult {
    let ep = 0x83u8;
    let ep_num = ep & 0x0F;
    if ep_num != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
