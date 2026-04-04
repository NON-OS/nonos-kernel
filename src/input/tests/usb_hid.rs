use core::sync::atomic::Ordering;
use crate::input::usb_hid::{
    USB_INIT, KBD_AVAIL, MOUSE_AVAIL, MOUSE_X, MOUSE_Y, MOUSE_BTN, SCR_W, SCR_H,
    hid_to_ascii,
};
use crate::input::usb_hid::transfer::{
    TRB_TYPE_SETUP, TRB_TYPE_DATA, TRB_TYPE_STATUS,
    TRB_IOC, TRB_IDT,
    USB_REQ_GET_DESCRIPTOR, USB_REQ_SET_CONFIGURATION,
    USB_HID_REQ_SET_PROTOCOL, USB_HID_REQ_SET_IDLE,
    USB_DESC_DEVICE, USB_DESC_CONFIGURATION, USB_DESC_INTERFACE, USB_DESC_ENDPOINT,
    USB_CLASS_HID,
    EpInfo,
};

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

#[test]
fn test_hid_to_ascii_letters() {
    assert_eq!(hid_to_ascii(0x04, 0x00), Some(b'a'));
    assert_eq!(hid_to_ascii(0x05, 0x00), Some(b'b'));
    assert_eq!(hid_to_ascii(0x06, 0x00), Some(b'c'));
    assert_eq!(hid_to_ascii(0x07, 0x00), Some(b'd'));
    assert_eq!(hid_to_ascii(0x08, 0x00), Some(b'e'));
    assert_eq!(hid_to_ascii(0x09, 0x00), Some(b'f'));
    assert_eq!(hid_to_ascii(0x1D, 0x00), Some(b'z'));
}

#[test]
fn test_hid_to_ascii_shifted_letters() {
    assert_eq!(hid_to_ascii(0x04, 0x02), Some(b'A'));
    assert_eq!(hid_to_ascii(0x05, 0x02), Some(b'B'));
    assert_eq!(hid_to_ascii(0x1D, 0x02), Some(b'Z'));
    assert_eq!(hid_to_ascii(0x04, 0x20), Some(b'A'));
}

#[test]
fn test_hid_to_ascii_numbers() {
    assert_eq!(hid_to_ascii(0x1E, 0x00), Some(b'1'));
    assert_eq!(hid_to_ascii(0x1F, 0x00), Some(b'2'));
    assert_eq!(hid_to_ascii(0x20, 0x00), Some(b'3'));
    assert_eq!(hid_to_ascii(0x21, 0x00), Some(b'4'));
    assert_eq!(hid_to_ascii(0x22, 0x00), Some(b'5'));
    assert_eq!(hid_to_ascii(0x23, 0x00), Some(b'6'));
    assert_eq!(hid_to_ascii(0x24, 0x00), Some(b'7'));
    assert_eq!(hid_to_ascii(0x25, 0x00), Some(b'8'));
    assert_eq!(hid_to_ascii(0x26, 0x00), Some(b'9'));
    assert_eq!(hid_to_ascii(0x27, 0x00), Some(b'0'));
}

#[test]
fn test_hid_to_ascii_shifted_numbers() {
    assert_eq!(hid_to_ascii(0x1E, 0x02), Some(b'!'));
    assert_eq!(hid_to_ascii(0x1F, 0x02), Some(b'@'));
    assert_eq!(hid_to_ascii(0x20, 0x02), Some(b'#'));
    assert_eq!(hid_to_ascii(0x21, 0x02), Some(b'$'));
    assert_eq!(hid_to_ascii(0x22, 0x02), Some(b'%'));
    assert_eq!(hid_to_ascii(0x23, 0x02), Some(b'^'));
    assert_eq!(hid_to_ascii(0x24, 0x02), Some(b'&'));
    assert_eq!(hid_to_ascii(0x25, 0x02), Some(b'*'));
    assert_eq!(hid_to_ascii(0x26, 0x02), Some(b'('));
    assert_eq!(hid_to_ascii(0x27, 0x02), Some(b')'));
}

#[test]
fn test_hid_to_ascii_special_keys() {
    assert_eq!(hid_to_ascii(0x28, 0x00), Some(13));
    assert_eq!(hid_to_ascii(0x29, 0x00), Some(27));
    assert_eq!(hid_to_ascii(0x2A, 0x00), Some(8));
    assert_eq!(hid_to_ascii(0x2B, 0x00), Some(9));
    assert_eq!(hid_to_ascii(0x2C, 0x00), Some(b' '));
}

#[test]
fn test_hid_to_ascii_punctuation() {
    assert_eq!(hid_to_ascii(0x2D, 0x00), Some(b'-'));
    assert_eq!(hid_to_ascii(0x2E, 0x00), Some(b'='));
    assert_eq!(hid_to_ascii(0x2F, 0x00), Some(b'['));
    assert_eq!(hid_to_ascii(0x30, 0x00), Some(b']'));
    assert_eq!(hid_to_ascii(0x31, 0x00), Some(b'\\'));
}

#[test]
fn test_hid_to_ascii_shifted_punctuation() {
    assert_eq!(hid_to_ascii(0x2D, 0x02), Some(b'_'));
    assert_eq!(hid_to_ascii(0x2E, 0x02), Some(b'+'));
    assert_eq!(hid_to_ascii(0x2F, 0x02), Some(b'{'));
    assert_eq!(hid_to_ascii(0x30, 0x02), Some(b'}'));
    assert_eq!(hid_to_ascii(0x31, 0x02), Some(b'|'));
}

#[test]
fn test_hid_to_ascii_invalid_code() {
    assert_eq!(hid_to_ascii(0x00, 0x00), None);
    assert_eq!(hid_to_ascii(0x01, 0x00), None);
    assert_eq!(hid_to_ascii(0x02, 0x00), None);
    assert_eq!(hid_to_ascii(0x03, 0x00), None);
}

#[test]
fn test_hid_to_ascii_out_of_range() {
    assert_eq!(hid_to_ascii(0x80, 0x00), None);
    assert_eq!(hid_to_ascii(0xFF, 0x00), None);
}

#[test]
fn test_hid_to_ascii_forward_delete() {
    assert_eq!(hid_to_ascii(0x4C, 0x00), Some(0x7F));
}

#[test]
fn test_trb_type_constants() {
    assert_eq!(TRB_TYPE_SETUP, 2);
    assert_eq!(TRB_TYPE_DATA, 3);
    assert_eq!(TRB_TYPE_STATUS, 4);
}

#[test]
fn test_trb_flag_constants() {
    assert_eq!(TRB_IOC, 1 << 5);
    assert_eq!(TRB_IDT, 1 << 6);
    assert_eq!(TRB_IOC, 32);
    assert_eq!(TRB_IDT, 64);
}

#[test]
fn test_usb_request_constants() {
    assert_eq!(USB_REQ_GET_DESCRIPTOR, 0x06);
    assert_eq!(USB_REQ_SET_CONFIGURATION, 0x09);
    assert_eq!(USB_HID_REQ_SET_PROTOCOL, 0x0B);
    assert_eq!(USB_HID_REQ_SET_IDLE, 0x0A);
}

#[test]
fn test_usb_descriptor_type_constants() {
    assert_eq!(USB_DESC_DEVICE, 0x01);
    assert_eq!(USB_DESC_CONFIGURATION, 0x02);
    assert_eq!(USB_DESC_INTERFACE, 0x04);
    assert_eq!(USB_DESC_ENDPOINT, 0x05);
}

#[test]
fn test_usb_class_hid() {
    assert_eq!(USB_CLASS_HID, 0x03);
}

#[test]
fn test_ep_info_is_interrupt() {
    let interrupt_ep = EpInfo {
        address: 0x81,
        attributes: 0x03,
        max_packet: 8,
        interval: 10,
    };
    assert!(interrupt_ep.is_interrupt());

    let bulk_ep = EpInfo {
        address: 0x82,
        attributes: 0x02,
        max_packet: 512,
        interval: 0,
    };
    assert!(!bulk_ep.is_interrupt());

    let control_ep = EpInfo {
        address: 0x00,
        attributes: 0x00,
        max_packet: 64,
        interval: 0,
    };
    assert!(!control_ep.is_interrupt());
}

#[test]
fn test_ep_info_structure() {
    let ep = EpInfo {
        address: 0x81,
        attributes: 0x03,
        max_packet: 64,
        interval: 10,
    };
    assert_eq!(ep.address, 0x81);
    assert_eq!(ep.attributes, 0x03);
    assert_eq!(ep.max_packet, 64);
    assert_eq!(ep.interval, 10);
}

#[test]
fn test_usb_state_defaults() {
    reset_usb_state();
    assert!(!USB_INIT.load(Ordering::Relaxed));
    assert!(!KBD_AVAIL.load(Ordering::Relaxed));
    assert!(!MOUSE_AVAIL.load(Ordering::Relaxed));
    assert_eq!(MOUSE_X.load(Ordering::Relaxed), 400);
    assert_eq!(MOUSE_Y.load(Ordering::Relaxed), 300);
    assert_eq!(MOUSE_BTN.load(Ordering::Relaxed), 0);
    assert_eq!(SCR_W.load(Ordering::Relaxed), 800);
    assert_eq!(SCR_H.load(Ordering::Relaxed), 600);
}

#[test]
fn test_usb_state_initialization() {
    reset_usb_state();
    USB_INIT.store(true, Ordering::SeqCst);
    KBD_AVAIL.store(true, Ordering::SeqCst);
    MOUSE_AVAIL.store(true, Ordering::SeqCst);

    assert!(USB_INIT.load(Ordering::Relaxed));
    assert!(KBD_AVAIL.load(Ordering::Relaxed));
    assert!(MOUSE_AVAIL.load(Ordering::Relaxed));
}

#[test]
fn test_usb_mouse_position() {
    reset_usb_state();
    MOUSE_X.store(100, Ordering::SeqCst);
    MOUSE_Y.store(200, Ordering::SeqCst);

    assert_eq!(MOUSE_X.load(Ordering::Relaxed), 100);
    assert_eq!(MOUSE_Y.load(Ordering::Relaxed), 200);
}

#[test]
fn test_usb_mouse_buttons() {
    reset_usb_state();
    MOUSE_BTN.store(0x01, Ordering::SeqCst);
    assert_eq!(MOUSE_BTN.load(Ordering::Relaxed) & 0x01, 0x01);

    MOUSE_BTN.store(0x02, Ordering::SeqCst);
    assert_eq!(MOUSE_BTN.load(Ordering::Relaxed) & 0x02, 0x02);

    MOUSE_BTN.store(0x03, Ordering::SeqCst);
    assert_eq!(MOUSE_BTN.load(Ordering::Relaxed) & 0x01, 0x01);
    assert_eq!(MOUSE_BTN.load(Ordering::Relaxed) & 0x02, 0x02);
}

#[test]
fn test_usb_screen_bounds() {
    reset_usb_state();
    SCR_W.store(1920, Ordering::SeqCst);
    SCR_H.store(1080, Ordering::SeqCst);

    assert_eq!(SCR_W.load(Ordering::Relaxed), 1920);
    assert_eq!(SCR_H.load(Ordering::Relaxed), 1080);
}

#[test]
fn test_hid_modifier_left_shift() {
    let mods = 0x02;
    let shift = (mods & 0x22) != 0;
    assert!(shift);
}

#[test]
fn test_hid_modifier_right_shift() {
    let mods = 0x20;
    let shift = (mods & 0x22) != 0;
    assert!(shift);
}

#[test]
fn test_hid_modifier_no_shift() {
    let mods = 0x00;
    let shift = (mods & 0x22) != 0;
    assert!(!shift);
}

#[test]
fn test_endpoint_direction() {
    let in_ep = 0x81u8;
    let out_ep = 0x01u8;

    assert!((in_ep & 0x80) != 0);
    assert!((out_ep & 0x80) == 0);
}

#[test]
fn test_endpoint_number() {
    let ep = 0x83u8;
    let ep_num = ep & 0x0F;
    assert_eq!(ep_num, 3);
}
