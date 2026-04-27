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
pub enum NvmeStatusCode {
    Success,
    InvalidOpcode,
    InvalidField,
    CommandIdConflict,
    DataTransferError,
    CommandAbortedPower,
    InternalError,
    CommandAbortedSq,
    FusedCommandMissing,
    FusedCommandMismatch,
    InvalidNamespaceFormat,
    CommandSequenceError,
    InvalidSglSegmentDescriptor,
    InvalidSglCount,
    DataSglLengthInvalid,
    MetadataSglLengthInvalid,
    SglTypeInvalid,
    InvalidControllerMemory,
    InvalidPrpOffset,
    AtomicWriteUnitExceeded,
    OperationDenied,
    SglDataBlockInvalid,
    NamespaceIdentifierUnavailable,
    ZoneInvalidTransition,
    ZoneBoundaryError,
    ZoneFull,
    ZoneReadOnly,
    ZoneOffline,
    ZoneInvalidWrite,
    TooManyActiveZones,
    TooManyOpenZones,
    InvalidZoneState,
    LbaOutOfRange,
    CapacityExceeded,
    NamespaceNotReady,
    ReservationConflict,
    FormatInProgress,
    ZoneResetPending,
    GenericError,
    MediaError,
    Unknown(u16),
}

impl NvmeStatusCode {
    pub fn from_status_field(status: u16) -> Self {
        let sc = (status >> 1) & 0xFF;
        let sct = (status >> 9) & 0x7;
        match (sct, sc) {
            (0, 0x00) => Self::Success,
            (0, 0x01) => Self::InvalidOpcode,
            (0, 0x02) => Self::InvalidField,
            (0, 0x03) => Self::CommandIdConflict,
            (0, 0x04) => Self::DataTransferError,
            (0, 0x05) => Self::CommandAbortedPower,
            (0, 0x06) => Self::InternalError,
            (0, 0x07) => Self::CommandAbortedSq,
            (0, 0x08) => Self::FusedCommandMissing,
            (0, 0x09) => Self::FusedCommandMismatch,
            (0, 0x0A) => Self::InvalidNamespaceFormat,
            (0, 0x0B) => Self::CommandSequenceError,
            (0, 0x0C) => Self::InvalidSglSegmentDescriptor,
            (0, 0x0D) => Self::InvalidSglCount,
            (0, 0x0E) => Self::DataSglLengthInvalid,
            (0, 0x0F) => Self::MetadataSglLengthInvalid,
            (0, 0x10) => Self::SglTypeInvalid,
            (0, 0x11) => Self::InvalidControllerMemory,
            (0, 0x12) => Self::InvalidPrpOffset,
            (0, 0x13) => Self::AtomicWriteUnitExceeded,
            (0, 0x14) => Self::OperationDenied,
            (0, 0x15) => Self::SglDataBlockInvalid,
            (0, 0x18) => Self::NamespaceIdentifierUnavailable,
            (0, 0xB8) => Self::ZoneInvalidTransition,
            (0, 0xB9) => Self::ZoneBoundaryError,
            (0, 0xBA) => Self::ZoneFull,
            (0, 0xBB) => Self::ZoneReadOnly,
            (0, 0xBC) => Self::ZoneOffline,
            (0, 0xBD) => Self::ZoneInvalidWrite,
            (0, 0xBE) => Self::TooManyActiveZones,
            (0, 0xBF) => Self::TooManyOpenZones,
            (0, 0xC0) => Self::InvalidZoneState,
            (2, 0x80) => Self::LbaOutOfRange,
            (2, 0x81) => Self::CapacityExceeded,
            (2, 0x82) => Self::NamespaceNotReady,
            (2, 0x83) => Self::ReservationConflict,
            (2, 0x84) => Self::FormatInProgress,
            (2, 0xBD) => Self::ZoneResetPending,
            (3, _) => Self::MediaError,
            _ => Self::Unknown(status),
        }
    }

    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
    pub const fn is_media_error(&self) -> bool {
        matches!(self, Self::MediaError | Self::DataTransferError)
    }
    pub const fn is_namespace_error(&self) -> bool {
        matches!(
            self,
            Self::NamespaceNotReady
                | Self::InvalidNamespaceFormat
                | Self::NamespaceIdentifierUnavailable
        )
    }
}
