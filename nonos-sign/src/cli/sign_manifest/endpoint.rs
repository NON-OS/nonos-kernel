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

use nonos_capsule_sign::error::SignError;

pub(super) fn parse_endpoint(s: &str) -> Result<(u8, u32, String), SignError> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(SignError::EndpointSpec(s.into()));
    }
    let kind: u8 = match parts[0] {
        "service" => 1,
        "reply" => 2,
        _ => return Err(SignError::EndpointSpec(s.into())),
    };
    let port: u32 = parts[1].parse().map_err(|_| SignError::EndpointSpec(s.into()))?;
    Ok((kind, port, parts[2].to_string()))
}
