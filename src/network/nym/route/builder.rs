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

use crate::network::nym::directory::{select_gateway, select_mixnode_by_layer};
use crate::network::nym::error::NymError;
use crate::network::nym::types::{NymAddress, NymRoute};

pub struct RouteBuilder {
    destination: Option<NymAddress>,
}

pub fn build_route(destination: &NymAddress) -> Result<NymRoute, NymError> {
    RouteBuilder::new().destination(destination.clone()).build()
}

impl RouteBuilder {
    pub fn new() -> Self {
        Self { destination: None }
    }

    pub fn destination(mut self, dest: NymAddress) -> Self {
        self.destination = Some(dest);
        self
    }

    pub fn build(self) -> Result<NymRoute, NymError> {
        let destination = self.destination.ok_or(NymError::InvalidAddress)?;
        let gateway = select_gateway()?;
        let layer1 = select_mixnode_by_layer(1)?;
        let layer2 = select_mixnode_by_layer(2)?;
        let layer3 = select_mixnode_by_layer(3)?;
        let layer4 = select_mixnode_by_layer(4)?;
        let layer5 = select_mixnode_by_layer(5)?;
        Ok(NymRoute { gateway, mixnodes: [layer1, layer2, layer3, layer4, layer5], destination })
    }
}

impl Default for RouteBuilder {
    fn default() -> Self {
        Self::new()
    }
}
