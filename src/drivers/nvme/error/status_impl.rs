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

use super::status_code::NvmeStatusCode;
use core::fmt;

impl fmt::Display for NvmeStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::InvalidOpcode => write!(f, "Invalid Command Opcode"),
            Self::InvalidField => write!(f, "Invalid Field in Command"),
            Self::CommandIdConflict => write!(f, "Command ID Conflict"),
            Self::DataTransferError => write!(f, "Data Transfer Error"),
            Self::CommandAbortedPower => write!(f, "Command Aborted Due to Power Loss"),
            Self::InternalError => write!(f, "Internal Error"),
            Self::CommandAbortedSq => write!(f, "Command Aborted by SQ Deletion"),
            Self::FusedCommandMissing => write!(f, "Fused Command Missing"),
            Self::FusedCommandMismatch => write!(f, "Fused Command Mismatch"),
            Self::InvalidNamespaceFormat => write!(f, "Invalid Namespace or Format"),
            Self::CommandSequenceError => write!(f, "Command Sequence Error"),
            Self::InvalidSglSegmentDescriptor => write!(f, "Invalid SGL Segment Descriptor"),
            Self::InvalidSglCount => write!(f, "Invalid Number of SGL Descriptors"),
            Self::DataSglLengthInvalid => write!(f, "Data SGL Length Invalid"),
            Self::MetadataSglLengthInvalid => write!(f, "Metadata SGL Length Invalid"),
            Self::SglTypeInvalid => write!(f, "SGL Descriptor Type Invalid"),
            Self::InvalidControllerMemory => write!(f, "Invalid Use of Controller Memory Buffer"),
            Self::InvalidPrpOffset => write!(f, "Invalid PRP Offset"),
            Self::AtomicWriteUnitExceeded => write!(f, "Atomic Write Unit Exceeded"),
            Self::OperationDenied => write!(f, "Operation Denied"),
            Self::SglDataBlockInvalid => write!(f, "SGL Data Block Granularity Invalid"),
            Self::NamespaceIdentifierUnavailable => write!(f, "Namespace Identifier Unavailable"),
            Self::ZoneInvalidTransition => write!(f, "Zone Invalid State Transition"),
            Self::ZoneBoundaryError => write!(f, "Zone Boundary Error"),
            Self::ZoneFull => write!(f, "Zone Full"),
            Self::ZoneReadOnly => write!(f, "Zone Read Only"),
            Self::ZoneOffline => write!(f, "Zone Offline"),
            Self::ZoneInvalidWrite => write!(f, "Zone Invalid Write"),
            Self::TooManyActiveZones => write!(f, "Too Many Active Zones"),
            Self::TooManyOpenZones => write!(f, "Too Many Open Zones"),
            Self::InvalidZoneState => write!(f, "Invalid Zone State Transition"),
            Self::LbaOutOfRange => write!(f, "LBA Out of Range"),
            Self::CapacityExceeded => write!(f, "Capacity Exceeded"),
            Self::NamespaceNotReady => write!(f, "Namespace Not Ready"),
            Self::ReservationConflict => write!(f, "Reservation Conflict"),
            Self::FormatInProgress => write!(f, "Format in Progress"),
            Self::ZoneResetPending => write!(f, "Zone Reset Recommended"),
            Self::GenericError => write!(f, "Generic Error"),
            Self::MediaError => write!(f, "Media/Data Integrity Error"),
            Self::Unknown(code) => write!(f, "Unknown Status Code 0x{:04X}", code),
        }
    }
}
