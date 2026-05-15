pub const HID_DESC_LEN: usize = 30;

pub fn valid_descriptor(desc: &[u8]) -> bool {
    if desc.len() < HID_DESC_LEN {
        return false;
    }
    let len = u16::from_le_bytes([desc[0], desc[1]]);
    let version = u16::from_le_bytes([desc[2], desc[3]]);
    (28..=256).contains(&len) && (0x0100..=0x0111).contains(&version)
}

