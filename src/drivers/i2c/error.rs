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
pub enum I2cError {
    NoController,
    InvalidAddress,
    BusBusy,
    Nack,
    ArbitrationLost,
    Timeout,
    TxOverflow,
    RxOverflow,
    TxAbort,
    InvalidParameter,
    NotInitialized,
    TransferFailed,
    DeviceNotFound,
    InvalidData,
}

impl I2cError {
    pub fn as_str(&self) -> &'static str {
        match self {
            I2cError::NoController => "no controller",
            I2cError::InvalidAddress => "invalid address",
            I2cError::BusBusy => "bus busy",
            I2cError::Nack => "nack received",
            I2cError::ArbitrationLost => "arbitration lost",
            I2cError::Timeout => "timeout",
            I2cError::TxOverflow => "tx overflow",
            I2cError::RxOverflow => "rx overflow",
            I2cError::TxAbort => "tx abort",
            I2cError::InvalidParameter => "invalid parameter",
            I2cError::NotInitialized => "not initialized",
            I2cError::TransferFailed => "transfer failed",
            I2cError::DeviceNotFound => "device not found",
            I2cError::InvalidData => "invalid data",
        }
    }
}
