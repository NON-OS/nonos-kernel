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

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use ark_bls12_381::Bls12_381;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, Compress, Validate};

pub fn load_proving_key(path: &Path) -> Result<ProvingKey<Bls12_381>> {
    let pk_bytes = fs::read(path)
        .with_context(|| format!("Failed to read proving key: {}", path.display()))?;

    let pk = ProvingKey::deserialize_with_mode(&pk_bytes[..], Compress::Yes, Validate::Yes)
        .with_context(|| "Failed to deserialize proving key")?;

    Ok(pk)
}
