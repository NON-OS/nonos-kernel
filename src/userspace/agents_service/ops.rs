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

extern crate alloc;

use crate::agents::{self, AgentConfig};
use crate::services::ServiceResponse;
use alloc::vec::Vec;

const ERR_AGENTS: i32 = -104;

pub(super) fn agent_create(seq: u32, data: &[u8]) -> ServiceResponse {
    let mut config = AgentConfig::default();
    let len = core::cmp::min(data.len(), 32);
    config.name[..len].copy_from_slice(&data[..len]);
    let id = agents::create_agent(config);
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&id.to_le_bytes());
    ServiceResponse::ok(seq, out)
}

pub(super) fn agent_run(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 4 {
        return ServiceResponse::err(seq, ERR_AGENTS);
    }
    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let input = &data[4..];
    if agents::run_agent(id, input) {
        ServiceResponse::ok(seq, Vec::new())
    } else {
        ServiceResponse::err(seq, ERR_AGENTS)
    }
}

pub(super) fn agent_stop(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 4 {
        return ServiceResponse::err(seq, ERR_AGENTS);
    }
    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    agents::stop_agent(id);
    ServiceResponse::ok(seq, Vec::new())
}

pub(super) fn agent_list(seq: u32) -> ServiceResponse {
    let list = agents::list_agents();
    let mut out = Vec::new();
    for (id, name) in list {
        out.extend_from_slice(&id.to_le_bytes());
        let len = name.iter().position(|&c| c == 0).unwrap_or(32);
        out.extend_from_slice(&name[..len]);
        out.push(0);
    }
    ServiceResponse::ok(seq, out)
}

pub(super) fn agent_output(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 4 {
        return ServiceResponse::err(seq, ERR_AGENTS);
    }
    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let output = agents::agent_output(id);
    ServiceResponse::ok(seq, output)
}
