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

use alloc::vec::Vec;

use super::path::{family_conflict, subnet16_conflict, weighted_pick};
use super::service_core::DirectoryService;
use super::types::RelayDescriptor;
use crate::network::onion::circuit::PathConstraints;
use crate::network::onion::OnionError;

impl DirectoryService {
    pub fn select_path_with_constraints(&self, constraints: &PathConstraints) -> Result<Vec<RelayDescriptor>, OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        let guards: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_guard && r.flags.is_running && r.flags.is_valid)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        let middles: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_running && r.flags.is_valid && !r.flags.is_authority)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        let exits: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_exit && r.flags.is_running && r.flags.is_valid && !r.flags.is_bad_exit)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        if guards.is_empty() || middles.is_empty() || exits.is_empty() {
            return Err(OnionError::InsufficientRelays);
        }

        let gw = &c.bandwidth_weights;
        let guard = weighted_pick(&guards, gw, "guard", self.secure_random_u64());
        let mut middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
        let mut exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());

        for _ in 0..8 {
            if !family_conflict(guard, middle) && !family_conflict(guard, exit)
                && !subnet16_conflict(guard.address, middle.address)
                && !subnet16_conflict(guard.address, exit.address)
                && !subnet16_conflict(middle.address, exit.address) {
                break;
            }
            middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
            exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());
        }

        let mut path = Vec::new();
        for e in [guard, middle, exit] {
            let rds = self.relay_descriptors.read();
            if let Some(rd) = rds.get(&e.identity_digest) {
                path.push(rd.clone());
            } else {
                drop(rds);
                if let Some(d) = e.microdesc_sha256 {
                    self.fetch_microdesc_for_digest(&d)?;
                    self.materialize_relays_from_microdescs()?;
                    let rds2 = self.relay_descriptors.read();
                    if let Some(rd2) = rds2.get(&e.identity_digest) {
                        path.push(rd2.clone());
                    } else {
                        return Err(OnionError::DirectoryError);
                    }
                } else {
                    return Err(OnionError::DirectoryError);
                }
            }
        }

        Ok(path)
    }

    pub fn select_path(&self) -> Result<Vec<RelayDescriptor>, OnionError> {
        self.select_path_with_constraints(&PathConstraints::default())
    }

    pub fn select_path_with_exit_policy(&self, required_ports: &[u16]) -> Result<Vec<RelayDescriptor>, OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        let rds = self.relay_descriptors.read();

        let guards: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_guard && r.flags.is_running && r.flags.is_valid)
            .collect();

        let middles: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_running && r.flags.is_valid && !r.flags.is_authority)
            .collect();

        let exits: Vec<_> = if required_ports.is_empty() {
            c.relays.iter()
                .filter(|r| r.flags.is_exit && r.flags.is_running && r.flags.is_valid && !r.flags.is_bad_exit)
                .collect()
        } else {
            c.relays.iter()
                .filter(|r| {
                    if !r.flags.is_exit || !r.flags.is_running || !r.flags.is_valid || r.flags.is_bad_exit {
                        return false;
                    }
                    if let Some(rd) = rds.get(&r.identity_digest) {
                        rd.allows_all_ports(required_ports)
                    } else {
                        false
                    }
                })
                .collect()
        };

        drop(rds);

        if guards.is_empty() || middles.is_empty() || exits.is_empty() {
            return Err(OnionError::InsufficientRelays);
        }

        let gw = &c.bandwidth_weights;
        let guard = weighted_pick(&guards, gw, "guard", self.secure_random_u64());
        let mut middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
        let mut exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());

        for _ in 0..8 {
            if !family_conflict(guard, middle) && !family_conflict(guard, exit)
                && !subnet16_conflict(guard.address, middle.address)
                && !subnet16_conflict(guard.address, exit.address)
                && !subnet16_conflict(middle.address, exit.address) {
                break;
            }
            middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
            exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());
        }

        let mut path = Vec::new();
        for e in [guard, middle, exit] {
            let rds = self.relay_descriptors.read();
            if let Some(rd) = rds.get(&e.identity_digest) {
                path.push(rd.clone());
            } else {
                drop(rds);
                if let Some(d) = e.microdesc_sha256 {
                    self.fetch_microdesc_for_digest(&d)?;
                    self.materialize_relays_from_microdescs()?;
                    let rds2 = self.relay_descriptors.read();
                    if let Some(rd2) = rds2.get(&e.identity_digest) {
                        path.push(rd2.clone());
                    } else {
                        return Err(OnionError::DirectoryError);
                    }
                } else {
                    return Err(OnionError::DirectoryError);
                }
            }
        }

        Ok(path)
    }
}
