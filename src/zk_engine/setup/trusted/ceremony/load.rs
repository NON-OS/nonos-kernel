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

use super::setup::TrustedSetup;
use crate::zk_engine::circuit::{Circuit, Constraint, LinearCombination};
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::setup::params::SetupParameters;
use crate::zk_engine::setup::trusted::serialize::{load_from_storage, save_to_storage};
use crate::zk_engine::ZKError;
use alloc::vec;

impl TrustedSetup {
    pub fn load_or_generate(
        config: &crate::zk_engine::ZKConfig,
    ) -> Result<SetupParameters, ZKError> {
        if let Some(ref path) = config.trusted_setup_path {
            if let Ok(params) = load_from_storage(path) {
                return Ok(params);
            }
        }

        let default_paths =
            ["/nonos/zk/trusted_setup.bin", "/etc/nonos/zk_setup.bin", "/boot/zk_params.bin"];

        for path in &default_paths {
            if let Ok(params) = load_from_storage(path) {
                return Ok(params);
            }
        }

        let one = LinearCombination::from_constant(FieldElement::one());
        let identity_constraint = Constraint::new(one.clone(), one.clone(), one);
        let dummy_circuit = Circuit::with_params(vec![identity_constraint], 1, 0);
        let params = TrustedSetup::setup(&dummy_circuit)?;

        if let Some(ref path) = config.trusted_setup_path {
            let _ = save_to_storage(path, &params);
        }

        Ok(params)
    }
}
