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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cSpeed {
    Standard,
    Fast,
    FastPlus,
    High,
}

impl I2cSpeed {
    pub fn frequency_hz(&self) -> u32 {
        match self {
            I2cSpeed::Standard => 100_000,
            I2cSpeed::Fast => 400_000,
            I2cSpeed::FastPlus => 1_000_000,
            I2cSpeed::High => 3_400_000,
        }
    }

    pub fn from_frequency(freq: u32) -> Self {
        if freq >= 3_400_000 {
            I2cSpeed::High
        } else if freq >= 1_000_000 {
            I2cSpeed::FastPlus
        } else if freq >= 400_000 {
            I2cSpeed::Fast
        } else {
            I2cSpeed::Standard
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I2cAddress {
    addr: u8,
    ten_bit: bool,
}

impl I2cAddress {
    pub fn new_7bit(addr: u8) -> Self {
        Self {
            addr: addr & 0x7F,
            ten_bit: false,
        }
    }

    pub fn new_10bit(addr: u16) -> Self {
        Self {
            addr: (addr & 0x3FF) as u8,
            ten_bit: true,
        }
    }

    pub fn value(&self) -> u8 {
        self.addr
    }

    pub fn is_10bit(&self) -> bool {
        self.ten_bit
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cDirection {
    Write,
    Read,
}

#[derive(Debug)]
pub struct I2cMessage<'a> {
    pub addr: I2cAddress,
    pub direction: I2cDirection,
    pub data: &'a [u8],
    pub read_buf: Option<&'a mut [u8]>,
}

#[derive(Debug, Clone, Copy)]
pub struct I2cTransaction {
    pub addr: u8,
    pub write_len: usize,
    pub read_len: usize,
}

pub(crate) const _I2C_SMBUS_BLOCK_MAX: usize = 32;
pub(crate) const _I2C_FIFO_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum I2cAbortSource {
    SevenBitAddrNack,
    TenBitAddr1Nack,
    TenBitAddr2Nack,
    TxDataNack,
    GeneralCallNack,
    GeneralCallRead,
    HighSpeedAckdet,
    StartByteAckdet,
    HighSpeedNoRst,
    StartByteNoRst,
    TenBitReadNoRst,
    MasterDisabled,
    ArbitrationLost,
    SlaveFlushTxFifo,
    SlaveArbitrationLost,
    SlaveReadIntx,
    UserAbort,
}

impl I2cAbortSource {
    pub(crate) fn from_bits(bits: u32) -> Option<Self> {
        if bits & (1 << 0) != 0 {
            Some(I2cAbortSource::SevenBitAddrNack)
        } else if bits & (1 << 1) != 0 {
            Some(I2cAbortSource::TenBitAddr1Nack)
        } else if bits & (1 << 2) != 0 {
            Some(I2cAbortSource::TenBitAddr2Nack)
        } else if bits & (1 << 3) != 0 {
            Some(I2cAbortSource::TxDataNack)
        } else if bits & (1 << 4) != 0 {
            Some(I2cAbortSource::GeneralCallNack)
        } else if bits & (1 << 5) != 0 {
            Some(I2cAbortSource::GeneralCallRead)
        } else if bits & (1 << 6) != 0 {
            Some(I2cAbortSource::HighSpeedAckdet)
        } else if bits & (1 << 7) != 0 {
            Some(I2cAbortSource::StartByteAckdet)
        } else if bits & (1 << 8) != 0 {
            Some(I2cAbortSource::HighSpeedNoRst)
        } else if bits & (1 << 9) != 0 {
            Some(I2cAbortSource::StartByteNoRst)
        } else if bits & (1 << 10) != 0 {
            Some(I2cAbortSource::TenBitReadNoRst)
        } else if bits & (1 << 11) != 0 {
            Some(I2cAbortSource::MasterDisabled)
        } else if bits & (1 << 12) != 0 {
            Some(I2cAbortSource::ArbitrationLost)
        } else if bits & (1 << 13) != 0 {
            Some(I2cAbortSource::SlaveFlushTxFifo)
        } else if bits & (1 << 14) != 0 {
            Some(I2cAbortSource::SlaveArbitrationLost)
        } else if bits & (1 << 15) != 0 {
            Some(I2cAbortSource::SlaveReadIntx)
        } else if bits & (1 << 16) != 0 {
            Some(I2cAbortSource::UserAbort)
        } else {
            None
        }
    }
}
