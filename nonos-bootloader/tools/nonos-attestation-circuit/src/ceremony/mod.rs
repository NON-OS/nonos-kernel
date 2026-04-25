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

mod constants;
mod contribute;
mod destruction;
mod error;
mod finalize;
mod hash;
mod init;
mod metadata;
mod params;
mod record;
mod tau;
mod transcript;
mod verify;

pub use constants::{DS_CEREMONY, DS_CONTRIBUTION, DS_TOXIC_WASTE, MIN_PARTICIPANTS};
pub use contribute::contribute_randomness;
pub use destruction::add_destruction_attestation;
pub use error::CeremonyError;
pub use finalize::ceremony_finalize;
pub use hash::hash_params;
pub use init::ceremony_init;
pub use metadata::CeremonyMetadata;
pub use params::CeremonyParams;
pub use record::{ContributionRecord, DestructionAttestation};
pub use transcript::CeremonyTranscript;
pub use verify::verify_contribution;
