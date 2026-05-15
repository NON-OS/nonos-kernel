use crate::hid::{valid_descriptor, HID_DESC_LEN};
use crate::i2c_client::write_read;

pub const CANDIDATE_ADDRS: &[u8] = &[0x10, 0x15, 0x2C, 0x38, 0x4B, 0x4C, 0x20, 0x24];

pub fn probe_bus(port: u32, descriptor: &mut [u8; HID_DESC_LEN]) -> Option<(u8, usize)> {
    for &addr in CANDIDATE_ADDRS {
        let mut buf = [0u8; HID_DESC_LEN];
        if write_read(port, addr, &[0x01, 0x00], &mut buf).is_some() && valid_descriptor(&buf) {
            descriptor.copy_from_slice(&buf);
            return Some((addr, HID_DESC_LEN));
        }
    }
    None
}

