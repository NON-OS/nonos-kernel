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

use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkSyncError {
    NotInitialized,
    InvalidTransaction,
    InvalidSignature,
    InsufficientBalance,
    NonceMismatch,
    GasLimitExceeded,
    InvalidProof,
    BatchNotFound,
    BlockNotFound,
    AccountNotFound,
    StorageError,
    ProvingFailed,
    WitnessGenerationFailed,
    L1CommunicationFailed,
    BridgeError,
    CapabilityDenied,
    InvalidInput,
    OutOfMemory,
    InternalError,
}

impl fmt::Display for ZkSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "zkSync not initialized"),
            Self::InvalidTransaction => write!(f, "invalid transaction"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::InsufficientBalance => write!(f, "insufficient balance"),
            Self::NonceMismatch => write!(f, "nonce mismatch"),
            Self::GasLimitExceeded => write!(f, "gas limit exceeded"),
            Self::InvalidProof => write!(f, "invalid proof"),
            Self::BatchNotFound => write!(f, "batch not found"),
            Self::BlockNotFound => write!(f, "block not found"),
            Self::AccountNotFound => write!(f, "account not found"),
            Self::StorageError => write!(f, "storage error"),
            Self::ProvingFailed => write!(f, "proving failed"),
            Self::WitnessGenerationFailed => write!(f, "witness generation failed"),
            Self::L1CommunicationFailed => write!(f, "L1 communication failed"),
            Self::BridgeError => write!(f, "bridge error"),
            Self::CapabilityDenied => write!(f, "capability denied"),
            Self::InvalidInput => write!(f, "invalid input"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::InternalError => write!(f, "internal error"),
        }
    }
}
