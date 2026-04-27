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

use crate::network::nym::error::NymError;
use crate::network::nym::types::{Gateway, MixNode, NymRoute, NYM_MIX_LAYERS};

pub struct RoutePath {
    pub gateway: Gateway,
    pub mixnodes: [MixNode; NYM_MIX_LAYERS],
}

pub fn validate_route(route: &NymRoute) -> Result<(), NymError> {
    if !route.gateway.is_healthy() {
        return Err(NymError::GatewayNotFound);
    }
    for (i, node) in route.mixnodes.iter().enumerate() {
        if !node.is_healthy() {
            return Err(NymError::MixNodeNotFound);
        }
        if node.layer != (i + 1) as u8 {
            return Err(NymError::InvalidRoute);
        }
    }
    let mut seen = [[0u8; 32]; NYM_MIX_LAYERS];
    for (i, node) in route.mixnodes.iter().enumerate() {
        for j in 0..i {
            if seen[j] == node.id.0 {
                return Err(NymError::InvalidRoute);
            }
        }
        seen[i] = node.id.0;
    }
    Ok(())
}

impl RoutePath {
    pub fn from_route(route: &NymRoute) -> Result<Self, NymError> {
        validate_route(route)?;
        Ok(Self { gateway: route.gateway.clone(), mixnodes: route.mixnodes.clone() })
    }

    pub fn hop_count(&self) -> usize {
        NYM_MIX_LAYERS
    }
}
