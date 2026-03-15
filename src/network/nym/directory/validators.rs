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

pub struct Validator {
    pub name: &'static str,
    pub api_url: &'static str,
    pub nyxd_url: &'static str,
}

pub static VALIDATORS: &[Validator] = &[
    Validator {
        name: "nym-api-1",
        api_url: "https://validator.nymtech.net/api",
        nyxd_url: "https://rpc.nymtech.net",
    },
    Validator {
        name: "nym-api-2",
        api_url: "https://validator2.nymtech.net/api",
        nyxd_url: "https://rpc2.nymtech.net",
    },
    Validator {
        name: "nym-api-3",
        api_url: "https://validator3.nymtech.net/api",
        nyxd_url: "https://rpc3.nymtech.net",
    },
];

impl Validator {
    pub fn mixnodes_url(&self) -> alloc::string::String {
        alloc::format!("{}/v1/mixnodes/active", self.api_url)
    }

    pub fn gateways_url(&self) -> alloc::string::String {
        alloc::format!("{}/v1/gateways", self.api_url)
    }

    pub fn topology_url(&self) -> alloc::string::String {
        alloc::format!("{}/v1/topology", self.api_url)
    }
}

extern crate alloc;
