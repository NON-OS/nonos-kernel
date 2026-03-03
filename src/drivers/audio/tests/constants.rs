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

use super::super::constants::*;

#[test]
fn test_global_register_offsets() {
    assert_eq!(GCAP, 0x00);
    assert_eq!(VMIN, 0x02);
    assert_eq!(VMAJ, 0x03);
    assert_eq!(GCTL, 0x08);
    assert_eq!(STATESTS, 0x0E);
    assert_eq!(INTCTL, 0x20);
    assert_eq!(INTSTS, 0x24);
}

#[test]
fn test_corb_rirb_offsets() {
    assert_eq!(CORBLBASE, 0x40);
    assert_eq!(CORBUBASE, 0x44);
    assert_eq!(CORBWP, 0x48);
    assert_eq!(CORBRP, 0x4A);
    assert_eq!(CORBCTL, 0x4C);
    assert_eq!(RIRBLBASE, 0x50);
    assert_eq!(RIRBUBASE, 0x54);
    assert_eq!(RIRBWP, 0x58);
    assert_eq!(RIRBCTL, 0x5C);
}

#[test]
fn test_immediate_command_offsets() {
    assert_eq!(IC, 0x60);
    assert_eq!(IR, 0x64);
    assert_eq!(IRS, 0x68);
}

#[test]
fn test_stream_descriptor_offsets() {
    assert_eq!(STREAM_BASE, 0x80);
    assert_eq!(STREAM_STRIDE, 0x20);
    assert_eq!(SD_CTL, 0x00);
    assert_eq!(SD_LPIB, 0x04);
    assert_eq!(SD_CBL, 0x08);
    assert_eq!(SD_LVI, 0x0C);
    assert_eq!(SD_FMT, 0x12);
    assert_eq!(SD_BDPL, 0x18);
    assert_eq!(SD_BDPU, 0x1C);
}

#[test]
fn test_gctl_bits() {
    assert_eq!(GCTL_CRST, 1 << 0);
    assert_eq!(GCTL_FCNTRL, 1 << 1);
    assert_eq!(GCTL_UNSOL, 1 << 8);
}

#[test]
fn test_stream_ctl_bits() {
    assert_eq!(SD_CTL_SRST, 1 << 0);
    assert_eq!(SD_CTL_RUN, 1 << 1);
    assert_eq!(SD_CTL_IOCE, 1 << 2);
    assert_eq!(SD_CTL_FEIE, 1 << 3);
    assert_eq!(SD_CTL_DEIE, 1 << 4);
}

#[test]
fn test_buffer_sizes() {
    assert_eq!(CORB_ENTRIES, 256);
    assert_eq!(RIRB_ENTRIES, 256);
    assert_eq!(CORB_SIZE, 256 * 4);
    assert_eq!(RIRB_SIZE, 256 * 8);
    assert_eq!(BDL_ENTRIES, 16);
    assert_eq!(PCM_BUFFER_SIZE, 64 * 1024);
}

#[test]
fn test_default_audio_constants() {
    assert_eq!(DEFAULT_SAMPLE_RATE, 48_000);
    assert_eq!(DEFAULT_BITS_PER_SAMPLE, 16);
    assert_eq!(DEFAULT_CHANNELS, 2);
}

#[test]
fn test_spin_timeouts() {
    assert!(SPIN_TIMEOUT_DEFAULT > 0);
    assert!(SPIN_TIMEOUT_SHORT > 0);
    assert!(SPIN_TIMEOUT_LONG > 0);
    assert!(SPIN_TIMEOUT_SHORT < SPIN_TIMEOUT_DEFAULT);
    assert!(SPIN_TIMEOUT_DEFAULT < SPIN_TIMEOUT_LONG);
}

#[test]
fn test_pci_class_codes() {
    assert_eq!(HDA_CLASS, 0x04);
    assert_eq!(HDA_SUBCLASS, 0x03);
}

#[test]
fn test_parameter_constants() {
    assert_eq!(PARAM_AMP_IN_CAP, 0x0D);
    assert_eq!(PARAM_AMP_OUT_CAP, 0x12);
    assert_eq!(VERB_SET_CONN_SELECT, 0x701);
    assert_eq!(VERB_GET_CONN_LIST, 0xF02);
    assert_eq!(VERB_GET_CONFIG_DEFAULT, 0xF1C);
    assert_eq!(VERB_SET_STREAM_CHANNEL, 0x706);
}
