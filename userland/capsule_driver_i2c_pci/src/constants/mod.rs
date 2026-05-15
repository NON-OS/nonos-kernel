pub const INTEL_VENDOR_ID: u16 = 0x8086;
pub const BAR_INDEX: u32 = 0;
pub const BAR_OFFSET: u64 = 0;
pub const PAGE_MASK: u64 = 0xFFF;

pub const IC_CON: u64 = 0x00;
pub const IC_TAR: u64 = 0x04;
pub const IC_DATA_CMD: u64 = 0x10;
pub const IC_SS_SCL_HCNT: u64 = 0x14;
pub const IC_SS_SCL_LCNT: u64 = 0x18;
pub const IC_FS_SCL_HCNT: u64 = 0x1C;
pub const IC_FS_SCL_LCNT: u64 = 0x20;
pub const IC_INTR_MASK: u64 = 0x30;
pub const IC_RAW_INTR_STAT: u64 = 0x34;
pub const IC_RX_TL: u64 = 0x38;
pub const IC_TX_TL: u64 = 0x3C;
pub const IC_CLR_INTR: u64 = 0x40;
pub const IC_ENABLE: u64 = 0x6C;
pub const IC_STATUS: u64 = 0x70;
pub const IC_TXFLR: u64 = 0x74;
pub const IC_RXFLR: u64 = 0x78;
pub const IC_TX_ABRT_SOURCE: u64 = 0x80;
pub const IC_ENABLE_STATUS: u64 = 0x9C;
pub const IC_COMP_PARAM_1: u64 = 0xF4;
pub const IC_COMP_TYPE: u64 = 0xFC;

pub fn device_info(device: u16) -> Option<(&'static str, u32)> {
    match device {
        0x9D60..=0x9D65 => Some(("Sunrise Point-LP", 120_000_000)),
        0xA160..=0xA163 => Some(("Sunrise Point-H", 120_000_000)),
        0x9DE8..=0x9DEB => Some(("Cannon Point-LP", 120_000_000)),
        0xA368..=0xA36B => Some(("Cannon Lake-H", 120_000_000)),
        0x02E8..=0x02EB => Some(("Comet Lake", 120_000_000)),
        0x06E8..=0x06EB => Some(("Comet Lake-H", 120_000_000)),
        0xA0E8..=0xA0EB | 0xA0C5 | 0xA0C6 => Some(("Tiger Lake-LP", 100_000_000)),
        0x43E8..=0x43EB => Some(("Tiger Lake-H", 100_000_000)),
        0x51E8..=0x51EB | 0x51C5 | 0x51C6 => Some(("Alder Lake-P", 100_000_000)),
        0x7AE8..=0x7AEB | 0x7AF8 | 0x7AF9 => Some(("Alder Lake-S", 100_000_000)),
        0xA0D8..=0xA0DD => Some(("Raptor Lake-P", 100_000_000)),
        0x7A4C..=0x7A4F | 0x7A7C | 0x7A7D => Some(("Raptor Lake-S", 100_000_000)),
        0x54E8..=0x54EB => Some(("Alder Lake-N", 100_000_000)),
        0x7E50..=0x7E52 | 0x7E78..=0x7E7A => Some(("Meteor Lake-P", 100_000_000)),
        0x34E8..=0x34EB | 0x34C5 | 0x34C6 => Some(("Ice Lake-LP", 100_000_000)),
        0x4DE8..=0x4DEB | 0x4DC5 | 0x4DC6 => Some(("Jasper Lake", 100_000_000)),
        0x5AC2 | 0x5AC4 | 0x5AC6 | 0x5AEE => Some(("Broxton", 100_000_000)),
        0x1AC2 | 0x1AC4 | 0x1AC6 | 0x1AEE => Some(("Broxton-P", 100_000_000)),
        0x31AC | 0x31AE | 0x31B0 | 0x31B2 => Some(("Gemini Lake", 100_000_000)),
        0x31B4 | 0x31B6 | 0x31B8 | 0x31BA => Some(("Gemini Lake", 100_000_000)),
        _ => None,
    }
}
pub const IC_DATA_CMD_READ: u32 = 1 << 8;
pub const IC_DATA_CMD_STOP: u32 = 1 << 9;
pub const IC_INTR_TX_ABRT: u32 = 1 << 6;
pub const IC_STATUS_TFE: u32 = 1 << 2;
pub const IC_STATUS_RFNE: u32 = 1 << 3;
pub const IC_STATUS_MST_ACTIVITY: u32 = 1 << 5;
pub const IC_ENABLE_ENABLE: u32 = 1;
pub const IC_CLR_TX_ABRT: u64 = 0x54;
pub const TIMEOUT_ITERS: usize = 250_000;
pub const TX_FIFO_DEPTH: u32 = 64;
pub const RX_FIFO_DEPTH: u32 = 64;
