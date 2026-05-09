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

use crate::algs::AlgId;

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum EndpointKind {
    Service = 1,
    Reply = 2,
}

pub struct EndpointInput {
    pub kind: EndpointKind,
    pub port: u32,
    pub name: String,
}

#[derive(Clone, Copy)]
pub struct VersionInput {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

pub struct PublisherSignatureInput {
    pub alg: AlgId,
    pub key_id: [u8; 16],
    pub sig: Vec<u8>,
}

pub struct CapsuleManifestInputs {
    pub nonos_id_cert_id: [u8; 32],
    pub namespace: String,
    pub version: VersionInput,
    pub target_triple: String,
    pub payload_hash: [u8; 32],
    pub required_caps: u64,
    pub optional_caps: u64,
    pub endpoints: Vec<EndpointInput>,
}
