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

pub(super) const TLS_1_2: u16 = 0x0303;
pub(super) const TLS_1_3: u16 = 0x0304;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum HSType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsChacha20Poly1305Sha256 = 0x1303,
}

#[derive(Debug, Clone)]
pub struct TlsSessionInfo {
    pub cipher_suite: u16,
    pub client_app_traffic_secret: Vec<u8>,
    pub server_app_traffic_secret: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TLSState {
    Start,
    Connected,
    Closed,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PublicKeyKind {
    Rsa,
    Ed25519,
    EcdsaP256,
    X25519,
}
