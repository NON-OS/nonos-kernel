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

use crate::error::SignError;

pub struct KeyPair {
    pub pubkey: Vec<u8>,
    pub seed: Vec<u8>,
}

pub trait Signer {
    fn keygen_from_seed(seed: &[u8]) -> Result<KeyPair, SignError>;
    fn keygen_random() -> Result<KeyPair, SignError>;
    fn sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, SignError>;
}

pub trait Verifier {
    fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SignError>;
}
