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

use crate::drivers::audio::constants::*;
use crate::test::framework::TestResult;

pub(crate) fn test_global_register_offsets() -> TestResult {
    if GCAP != 0x00 {
        return TestResult::Fail;
    }
    if VMIN != 0x02 {
        return TestResult::Fail;
    }
    if VMAJ != 0x03 {
        return TestResult::Fail;
    }
    if GCTL != 0x08 {
        return TestResult::Fail;
    }
    if STATESTS != 0x0E {
        return TestResult::Fail;
    }
    if INTCTL != 0x20 {
        return TestResult::Fail;
    }
    if INTSTS != 0x24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_corb_rirb_offsets() -> TestResult {
    if CORBLBASE != 0x40 {
        return TestResult::Fail;
    }
    if CORBUBASE != 0x44 {
        return TestResult::Fail;
    }
    if CORBWP != 0x48 {
        return TestResult::Fail;
    }
    if CORBRP != 0x4A {
        return TestResult::Fail;
    }
    if CORBCTL != 0x4C {
        return TestResult::Fail;
    }
    if RIRBLBASE != 0x50 {
        return TestResult::Fail;
    }
    if RIRBUBASE != 0x54 {
        return TestResult::Fail;
    }
    if RIRBWP != 0x58 {
        return TestResult::Fail;
    }
    if RIRBCTL != 0x5C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_immediate_command_offsets() -> TestResult {
    if IC != 0x60 {
        return TestResult::Fail;
    }
    if IR != 0x64 {
        return TestResult::Fail;
    }
    if IRS != 0x68 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stream_descriptor_offsets() -> TestResult {
    if STREAM_BASE != 0x80 {
        return TestResult::Fail;
    }
    if STREAM_STRIDE != 0x20 {
        return TestResult::Fail;
    }
    if SD_CTL != 0x00 {
        return TestResult::Fail;
    }
    if SD_LPIB != 0x04 {
        return TestResult::Fail;
    }
    if SD_CBL != 0x08 {
        return TestResult::Fail;
    }
    if SD_LVI != 0x0C {
        return TestResult::Fail;
    }
    if SD_FMT != 0x12 {
        return TestResult::Fail;
    }
    if SD_BDPL != 0x18 {
        return TestResult::Fail;
    }
    if SD_BDPU != 0x1C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gctl_bits() -> TestResult {
    if GCTL_CRST != 1 << 0 {
        return TestResult::Fail;
    }
    if GCTL_FCNTRL != 1 << 1 {
        return TestResult::Fail;
    }
    if GCTL_UNSOL != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stream_ctl_bits() -> TestResult {
    if SD_CTL_SRST != 1 << 0 {
        return TestResult::Fail;
    }
    if SD_CTL_RUN != 1 << 1 {
        return TestResult::Fail;
    }
    if SD_CTL_IOCE != 1 << 2 {
        return TestResult::Fail;
    }
    if SD_CTL_FEIE != 1 << 3 {
        return TestResult::Fail;
    }
    if SD_CTL_DEIE != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_sizes() -> TestResult {
    if CORB_ENTRIES != 256 {
        return TestResult::Fail;
    }
    if RIRB_ENTRIES != 256 {
        return TestResult::Fail;
    }
    if CORB_SIZE != 256 * 4 {
        return TestResult::Fail;
    }
    if RIRB_SIZE != 256 * 8 {
        return TestResult::Fail;
    }
    if BDL_ENTRIES != 16 {
        return TestResult::Fail;
    }
    if PCM_BUFFER_SIZE != 64 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_audio_constants() -> TestResult {
    if DEFAULT_SAMPLE_RATE != 48_000 {
        return TestResult::Fail;
    }
    if DEFAULT_BITS_PER_SAMPLE != 16 {
        return TestResult::Fail;
    }
    if DEFAULT_CHANNELS != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spin_timeouts() -> TestResult {
    if !(SPIN_TIMEOUT_DEFAULT > 0) {
        return TestResult::Fail;
    }
    if !(SPIN_TIMEOUT_SHORT > 0) {
        return TestResult::Fail;
    }
    if !(SPIN_TIMEOUT_LONG > 0) {
        return TestResult::Fail;
    }
    if !(SPIN_TIMEOUT_SHORT < SPIN_TIMEOUT_DEFAULT) {
        return TestResult::Fail;
    }
    if !(SPIN_TIMEOUT_DEFAULT < SPIN_TIMEOUT_LONG) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_class_codes() -> TestResult {
    if HDA_CLASS != 0x04 {
        return TestResult::Fail;
    }
    if HDA_SUBCLASS != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parameter_constants() -> TestResult {
    if PARAM_AMP_IN_CAP != 0x0D {
        return TestResult::Fail;
    }
    if PARAM_AMP_OUT_CAP != 0x12 {
        return TestResult::Fail;
    }
    if VERB_SET_CONN_SELECT != 0x701 {
        return TestResult::Fail;
    }
    if VERB_GET_CONN_LIST != 0xF02 {
        return TestResult::Fail;
    }
    if VERB_GET_CONFIG_DEFAULT != 0xF1C {
        return TestResult::Fail;
    }
    if VERB_SET_STREAM_CHANNEL != 0x706 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
