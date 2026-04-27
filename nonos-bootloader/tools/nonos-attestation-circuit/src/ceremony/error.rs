// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::MIN_PARTICIPANTS;

#[derive(Debug)]
pub enum CeremonyError {
    InsufficientParticipants,
    InvalidPreviousParams,
    InvalidContribution,
    SerializationError(String),
    VerificationFailed,
    ToxicWasteNotDestroyed,
    InvalidRound,
    HashMismatch,
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientParticipants => write!(f, "need {} participants", MIN_PARTICIPANTS),
            Self::InvalidPreviousParams => write!(f, "invalid previous parameters"),
            Self::InvalidContribution => write!(f, "invalid contribution"),
            Self::SerializationError(s) => write!(f, "serialization: {}", s),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::ToxicWasteNotDestroyed => write!(f, "toxic waste destruction not verified"),
            Self::InvalidRound => write!(f, "invalid round number"),
            Self::HashMismatch => write!(f, "hash mismatch"),
        }
    }
}

impl std::error::Error for CeremonyError {}
