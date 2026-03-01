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

//! Intel HD Audio register constants and bit definitions.

pub const HDA_CLASS: u8 = 0x04;
pub const HDA_SUBCLASS: u8 = 0x03;
pub const HDA_PROG_IF: u8 = 0x00;
pub const HDA_BAR_INDEX: usize = 0;
pub const HDA_BAR_MIN_SIZE: usize = 0x1000;

pub const GCAP: usize = 0x00;
pub const VMIN: usize = 0x02;
pub const VMAJ: usize = 0x03;
pub const OUTPAY: usize = 0x04;
pub const INPAY: usize = 0x06;
pub const GCTL: usize = 0x08;
pub const WAKEEN: usize = 0x0C;
pub const STATESTS: usize = 0x0E;
pub const GSTS: usize = 0x10;
pub const INTCTL: usize = 0x20;
pub const INTSTS: usize = 0x24;
pub const WALCLK: usize = 0x30;
pub const SSYNC: usize = 0x34;

pub const CORBLBASE: usize = 0x40;
pub const CORBUBASE: usize = 0x44;
pub const CORBWP: usize = 0x48;
pub const CORBRP: usize = 0x4A;
pub const CORBCTL: usize = 0x4C;
pub const CORBSTS: usize = 0x4D;
pub const CORBSIZE: usize = 0x4E;

pub const RIRBLBASE: usize = 0x50;
pub const RIRBUBASE: usize = 0x54;
pub const RIRBWP: usize = 0x58;
pub const RINTCNT: usize = 0x5A;
pub const RIRBCTL: usize = 0x5C;
pub const RIRBSTS: usize = 0x5D;
pub const RIRBSIZE: usize = 0x5E;

pub const IC: usize = 0x60;
pub const IR: usize = 0x64;
pub const IRS: usize = 0x68;

pub const STREAM_BASE: usize = 0x80;
pub const STREAM_STRIDE: usize = 0x20;
pub const MAX_STREAMS: usize = 30;

pub const SD_CTL: usize = 0x00;
pub const SD_STS: usize = 0x03;
pub const SD_LPIB: usize = 0x04;
pub const SD_CBL: usize = 0x08;
pub const SD_LVI: usize = 0x0C;
pub const SD_FIFOS: usize = 0x10;
pub const SD_FMT: usize = 0x12;
pub const SD_BDPL: usize = 0x18;
pub const SD_BDPU: usize = 0x1C;

pub const GCTL_CRST: u32 = 1 << 0;
pub const GCTL_FCNTRL: u32 = 1 << 1;
pub const GCTL_UNSOL: u32 = 1 << 8;

pub const GCAP_64OK_BIT: u32 = 0;
pub const GCAP_NSDO_SHIFT: u32 = 1;
pub const GCAP_NSDO_MASK: u32 = 0x3;
pub const GCAP_BSS_SHIFT: u32 = 3;
pub const GCAP_BSS_MASK: u32 = 0x1F;
pub const GCAP_ISS_SHIFT: u32 = 8;
pub const GCAP_ISS_MASK: u32 = 0xF;
pub const GCAP_OSS_SHIFT: u32 = 12;
pub const GCAP_OSS_MASK: u32 = 0xF;

pub const INTCTL_SIE_MASK: u32 = 0x3FFF_FFFF;
pub const INTCTL_CIE: u32 = 1 << 30;
pub const INTCTL_GIE: u32 = 1 << 31;

pub const CORBCTL_CMEIE: u8 = 1 << 0;
pub const CORBCTL_CORBRUN: u8 = 1 << 1;
pub const CORBSTS_CMEI: u8 = 1 << 0;
pub const CORBRP_RST: u16 = 1 << 15;

pub const RIRBCTL_RINTCTL: u8 = 1 << 0;
pub const RIRBCTL_RIRBDMAEN: u8 = 1 << 1;
pub const RIRBCTL_RIRBOIC: u8 = 1 << 2;
pub const RIRBSTS_RINTFL: u8 = 1 << 0;
pub const RIRBSTS_RIRBOIS: u8 = 1 << 2;

pub const IRS_BUSY: u8 = 1 << 0;
pub const IRS_VALID: u8 = 1 << 1;

pub const SD_CTL_SRST: u32 = 1 << 0;
pub const SD_CTL_RUN: u32 = 1 << 1;
pub const SD_CTL_IOCE: u32 = 1 << 2;
pub const SD_CTL_FEIE: u32 = 1 << 3;
pub const SD_CTL_DEIE: u32 = 1 << 4;
pub const SD_CTL_STRM_SHIFT: u32 = 20;
pub const SD_CTL_STRM_MASK: u32 = 0xF;

pub const SD_STS_BCIS: u8 = 1 << 2;
pub const SD_STS_FIFOE: u8 = 1 << 3;
pub const SD_STS_DESE: u8 = 1 << 4;
pub const SD_STS_FIFORDY: u8 = 1 << 5;

pub const SD_FMT_CHAN_SHIFT: u16 = 0;
pub const SD_FMT_CHAN_MASK: u16 = 0xF;
pub const SD_FMT_BITS_SHIFT: u16 = 4;
pub const SD_FMT_BITS_MASK: u16 = 0x7;
pub const SD_FMT_DIV_SHIFT: u16 = 8;
pub const SD_FMT_DIV_MASK: u16 = 0x7;
pub const SD_FMT_MULT_SHIFT: u16 = 11;
pub const SD_FMT_MULT_MASK: u16 = 0x7;
pub const SD_FMT_BASE_44K: u16 = 1 << 14;
pub const SD_FMT_NON_PCM: u16 = 1 << 15;

pub const VERB_GET_PARAMETER: u16 = 0xF00;
pub const VERB_SET_CONVERTER_FORMAT: u16 = 0x200;
pub const VERB_SET_CONV_CHANNEL_COUNT: u16 = 0x70D;
pub const VERB_SET_POWER_STATE: u16 = 0x705;
pub const VERB_GET_POWER_STATE: u16 = 0xF05;
pub const VERB_SET_PIN_WIDGET_CONTROL: u16 = 0x707;
pub const VERB_GET_PIN_WIDGET_CONTROL: u16 = 0xF07;
pub const VERB_SET_EAPD_BTL_ENABLE: u16 = 0x70C;
pub const VERB_GET_EAPD_BTL_ENABLE: u16 = 0xF0C;
pub const VERB_SET_CONNECTION_SELECT: u16 = 0x701;
pub const VERB_SET_CONN_SELECT: u16 = 0x701;
pub const VERB_GET_CONNECTION_SELECT: u16 = 0xF01;
pub const VERB_GET_CONNECTION_LIST_ENTRY: u16 = 0xF02;
pub const VERB_GET_CONN_LIST: u16 = 0xF02;
pub const VERB_GET_CONFIG_DEFAULT: u16 = 0xF1C;
pub const VERB_SET_STREAM_CHANNEL: u16 = 0x706;
pub const VERB_GET_STREAM_CHANNEL: u16 = 0xF06;
pub const VERB_SET_AMP_GAIN_MUTE: u16 = 0x300;
pub const VERB_GET_AMP_GAIN_MUTE: u16 = 0xB00;
pub const VERB_SET_VOLUME_KNOB: u16 = 0x70F;
pub const VERB_GET_VOLUME_KNOB: u16 = 0xF0F;

pub const PARAM_VENDOR_ID: u16 = 0x00;
pub const PARAM_REVISION_ID: u16 = 0x02;
pub const PARAM_SUB_NODE_COUNT: u16 = 0x04;
pub const PARAM_FN_GROUP_TYPE: u16 = 0x05;
pub const PARAM_AFG_CAP: u16 = 0x08;
pub const PARAM_AUDIO_WIDGET_CAP: u16 = 0x09;
pub const PARAM_PCM_SIZE_RATE: u16 = 0x0A;
pub const PARAM_STREAM_FORMATS: u16 = 0x0B;
pub const PARAM_PIN_CAP: u16 = 0x0C;
pub const PARAM_AMP_IN_CAP: u16 = 0x0D;
pub const PARAM_CONN_LIST_LEN: u16 = 0x0E;
pub const PARAM_POWER_STATES: u16 = 0x0F;
pub const PARAM_PROC_CAP: u16 = 0x10;
pub const PARAM_GPIO_COUNT: u16 = 0x11;
pub const PARAM_AMP_OUT_CAP: u16 = 0x12;
pub const PARAM_VOL_KNOB_CAP: u16 = 0x13;

pub const WIDGET_CAP_TYPE_SHIFT: u32 = 20;
pub const WIDGET_CAP_TYPE_MASK: u32 = 0xF;
pub const WIDGET_CAP_CONN_LIST: u32 = 1 << 8;
pub const WIDGET_CAP_IN_AMP: u32 = 1 << 1;
pub const WIDGET_CAP_OUT_AMP: u32 = 1 << 2;
pub const WIDGET_CAP_AMP_OVRD: u32 = 1 << 3;
pub const WIDGET_CAP_FORMAT_OVRD: u32 = 1 << 4;
pub const WIDGET_CAP_STRIPE: u32 = 1 << 5;
pub const WIDGET_CAP_PROC_WIDGET: u32 = 1 << 6;
pub const WIDGET_CAP_UNSOL: u32 = 1 << 7;
pub const WIDGET_CAP_DIGITAL: u32 = 1 << 9;
pub const WIDGET_CAP_POWER: u32 = 1 << 10;
pub const WIDGET_CAP_LR_SWAP: u32 = 1 << 11;
pub const WIDGET_CAP_CP_CAPS: u32 = 1 << 12;
pub const WIDGET_CAP_CHAN_SHIFT: u32 = 13;
pub const WIDGET_CAP_CHAN_MASK: u32 = 0x7;
pub const WIDGET_CAP_DELAY_SHIFT: u32 = 16;
pub const WIDGET_CAP_DELAY_MASK: u32 = 0xF;

pub const SPIN_TIMEOUT_DEFAULT: u32 = 1_000_000;
pub const SPIN_TIMEOUT_SHORT: u32 = 100_000;
pub const SPIN_TIMEOUT_LONG: u32 = 10_000_000;
pub const SPIN_TIMEOUT_INIT: u32 = 5_000_000;
pub const CODEC_STARTUP_DELAY: u32 = 10_000;

pub const CORB_ENTRIES: usize = 256;
pub const RIRB_ENTRIES: usize = 256;
pub const CORB_SIZE: usize = CORB_ENTRIES * 4;
pub const RIRB_SIZE: usize = RIRB_ENTRIES * 8;
pub const BDL_ENTRIES: usize = 16;
pub const BDL_ENTRIES_MAX: usize = 256;
pub const BDL_ENTRY_SIZE: usize = 16;
pub const PCM_BUFFER_SIZE: usize = 64 * 1024;
pub const PCM_BUFFER_SIZE_MIN: usize = 4 * 1024;
pub const PCM_BUFFER_SIZE_MAX: usize = 1024 * 1024;
pub const DMA_ALIGNMENT: usize = 128;
pub const BDL_ENTRY_MAX_LENGTH: u32 = 0xFFFF_FFFF;

pub const DEFAULT_SAMPLE_RATE: u32 = 48_000;
pub const SAMPLE_RATE_44K: u32 = 44_100;
pub const DEFAULT_BITS_PER_SAMPLE: u16 = 16;
pub const DEFAULT_CHANNELS: u16 = 2;
pub const MAX_CHANNELS: u16 = 8;
pub const MIN_BITS_PER_SAMPLE: u16 = 8;
pub const MAX_BITS_PER_SAMPLE: u16 = 32;

pub const MAX_CODEC_ADDRESS: u8 = 15;
pub const MAX_NODE_ID: u8 = 127;
pub const MAX_CODECS: usize = 16;

pub const CORB_RIRB_SIZE_2: u8 = 0x00;
pub const CORB_RIRB_SIZE_16: u8 = 0x01;
pub const CORB_RIRB_SIZE_256: u8 = 0x02;

#[inline]
pub const fn is_valid_codec_address(cad: u8) -> bool {
    cad <= MAX_CODEC_ADDRESS
}

#[inline]
pub const fn is_valid_node_id(nid: u8) -> bool {
    nid <= MAX_NODE_ID
}

#[inline]
pub const fn is_valid_stream_index(index: u8, output_streams: u8, input_streams: u8) -> bool {
    index >= 1 && index <= output_streams + input_streams
}

#[inline]
pub const fn is_valid_global_reg(offset: usize) -> bool {
    matches!(
        offset,
        GCAP | VMIN | VMAJ | OUTPAY | INPAY | GCTL | WAKEEN | STATESTS | GSTS | INTCTL | INTSTS
            | WALCLK | SSYNC | CORBLBASE | CORBUBASE | CORBWP | CORBRP | CORBCTL | CORBSTS
            | CORBSIZE | RIRBLBASE | RIRBUBASE | RIRBWP | RINTCNT | RIRBCTL | RIRBSTS | RIRBSIZE
            | IC | IR | IRS
    )
}

#[inline]
pub const fn is_valid_stream_reg(offset: usize) -> bool {
    matches!(
        offset,
        SD_CTL | SD_STS | SD_LPIB | SD_CBL | SD_LVI | SD_FIFOS | SD_FMT | SD_BDPL | SD_BDPU
    )
}

#[inline]
pub const fn stream_descriptor_base(stream_index: u8) -> usize {
    STREAM_BASE + (stream_index as usize - 1) * STREAM_STRIDE
}

#[inline]
pub const fn is_dma_aligned(addr: u64) -> bool {
    addr % DMA_ALIGNMENT as u64 == 0
}

#[inline]
pub const fn is_valid_buffer_size(size: usize) -> bool {
    size >= PCM_BUFFER_SIZE_MIN && size <= PCM_BUFFER_SIZE_MAX
}

const _: () = assert!(BDL_ENTRY_SIZE == 16);
const _: () = assert!(CORB_SIZE == 1024);
const _: () = assert!(RIRB_SIZE == 2048);
const _: () = assert!(DMA_ALIGNMENT.is_power_of_two());
const _: () = assert!(STREAM_STRIDE == 0x20);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_address_validation() {
        assert!(is_valid_codec_address(0));
        assert!(is_valid_codec_address(15));
        assert!(!is_valid_codec_address(16));
    }

    #[test]
    fn test_node_id_validation() {
        assert!(is_valid_node_id(0));
        assert!(is_valid_node_id(127));
        assert!(!is_valid_node_id(128));
    }

    #[test]
    fn test_dma_alignment_validation() {
        assert!(is_dma_aligned(0));
        assert!(is_dma_aligned(128));
        assert!(is_dma_aligned(256));
        assert!(!is_dma_aligned(64));
        assert!(!is_dma_aligned(100));
    }

    #[test]
    fn test_stream_descriptor_base() {
        assert_eq!(stream_descriptor_base(1), 0x80);
        assert_eq!(stream_descriptor_base(2), 0xA0);
        assert_eq!(stream_descriptor_base(3), 0xC0);
    }

    #[test]
    fn test_buffer_size_validation() {
        assert!(!is_valid_buffer_size(1024));
        assert!(is_valid_buffer_size(4096));
        assert!(is_valid_buffer_size(65536));
        assert!(is_valid_buffer_size(1024 * 1024));
        assert!(!is_valid_buffer_size(2 * 1024 * 1024));
    }
}
