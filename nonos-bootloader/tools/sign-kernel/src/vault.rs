// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const VAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug)]
pub enum VaultError {
    ConnectionFailed(String),
    AuthenticationFailed,
    KeyNotFound,
    InvalidKeyFormat,
    SigningFailed(String),
    InvalidResponse(String),
    PermissionDenied,
    HttpError(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(s) => write!(f, "connection failed: {}", s),
            Self::AuthenticationFailed => write!(f, "authentication failed"),
            Self::KeyNotFound => write!(f, "key not found"),
            Self::InvalidKeyFormat => write!(f, "invalid key format"),
            Self::SigningFailed(s) => write!(f, "signing failed: {}", s),
            Self::InvalidResponse(s) => write!(f, "invalid response: {}", s),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::HttpError(s) => write!(f, "HTTP error: {}", s),
        }
    }
}

impl std::error::Error for VaultError {}

#[derive(Serialize)]
struct SignRequest {
    input: String,
    hash_algorithm: String,
    signature_algorithm: String,
    prehashed: bool,
}

#[derive(Deserialize)]
struct VaultResponse<T> {
    data: T,
}

#[derive(Deserialize)]
struct SecretData {
    data: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
struct SignData {
    signature: String,
}

#[derive(Deserialize)]
struct KeyData {
    keys: std::collections::HashMap<String, KeyInfo>,
}

#[derive(Deserialize)]
struct KeyInfo {
    public_key: Option<String>,
}

pub struct VaultClient {
    addr: String,
    token: String,
    client: Client,
    namespace: Option<String>,
}

impl VaultClient {
    pub fn new(addr: String, token: String, namespace: Option<String>) -> Result<Self, VaultError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(VAULT_TIMEOUT_SECS))
            .build()
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            addr: addr.trim_end_matches('/').to_string(),
            token,
            client,
            namespace,
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}/v1/{}", self.addr, path);
        let mut req = self.client.request(method, &url)
            .header("X-Vault-Token", &self.token);

        if let Some(ref ns) = self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        req
    }

    pub fn get_signing_key(&self, key_path: &str) -> Result<[u8; 32], VaultError> {
        let response = self.request(reqwest::Method::GET, &format!("secret/data/{}", key_path))
            .send()
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(VaultError::PermissionDenied);
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(VaultError::KeyNotFound);
        }

        if !response.status().is_success() {
            return Err(VaultError::HttpError(response.status().to_string()));
        }

        let vault_resp: VaultResponse<SecretData> = response
            .json()
            .map_err(|e| VaultError::InvalidResponse(e.to_string()))?;

        let key_hex = vault_resp.data.data.get("key")
            .ok_or(VaultError::KeyNotFound)?;

        let key_bytes = hex::decode(key_hex)
            .map_err(|_| VaultError::InvalidKeyFormat)?;

        if key_bytes.len() != 32 {
            return Err(VaultError::InvalidKeyFormat);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    pub fn sign_with_transit(
        &self,
        key_name: &str,
        message_hash: &[u8; 32],
    ) -> Result<[u8; 64], VaultError> {
        let request = SignRequest {
            input: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, message_hash),
            hash_algorithm: "sha2-256".to_string(),
            signature_algorithm: "ed25519".to_string(),
            prehashed: true,
        };

        let response = self.request(reqwest::Method::POST, &format!("transit/sign/{}", key_name))
            .json(&request)
            .send()
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(VaultError::PermissionDenied);
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(VaultError::KeyNotFound);
        }

        if !response.status().is_success() {
            return Err(VaultError::HttpError(format!(
                "{}: {}",
                response.status(),
                response.text().unwrap_or_default()
            )));
        }

        let vault_resp: VaultResponse<SignData> = response
            .json()
            .map_err(|e| VaultError::InvalidResponse(e.to_string()))?;

        let sig_str = vault_resp.data.signature
            .strip_prefix("vault:v1:")
            .ok_or(VaultError::InvalidResponse("missing vault prefix".into()))?;

        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_str)
            .map_err(|e| VaultError::InvalidResponse(e.to_string()))?;

        if sig_bytes.len() != 64 {
            return Err(VaultError::InvalidResponse(format!(
                "signature length {} != 64",
                sig_bytes.len()
            )));
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        Ok(sig)
    }

    pub fn get_transit_public_key(&self, key_name: &str) -> Result<[u8; 32], VaultError> {
        let response = self.request(reqwest::Method::GET, &format!("transit/keys/{}", key_name))
            .send()
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(VaultError::PermissionDenied);
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(VaultError::KeyNotFound);
        }

        if !response.status().is_success() {
            return Err(VaultError::HttpError(response.status().to_string()));
        }

        let vault_resp: VaultResponse<KeyData> = response
            .json()
            .map_err(|e| VaultError::InvalidResponse(e.to_string()))?;

        let latest_version = vault_resp.data.keys.keys()
            .filter_map(|k| k.parse::<u64>().ok())
            .max()
            .ok_or(VaultError::KeyNotFound)?;

        let key_info = vault_resp.data.keys.get(&latest_version.to_string())
            .ok_or(VaultError::KeyNotFound)?;

        let pubkey_b64 = key_info.public_key.as_ref()
            .ok_or(VaultError::KeyNotFound)?;

        let pubkey_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pubkey_b64)
            .map_err(|e| VaultError::InvalidResponse(e.to_string()))?;

        if pubkey_bytes.len() != 32 {
            return Err(VaultError::InvalidKeyFormat);
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_bytes);
        Ok(pubkey)
    }

    pub fn health_check(&self) -> Result<bool, VaultError> {
        let response = self.client
            .get(format!("{}/v1/sys/health", self.addr))
            .timeout(Duration::from_secs(5))
            .send()
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        Ok(response.status().is_success() || response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE)
    }
}

pub fn sign_kernel_with_vault(
    vault_addr: &str,
    vault_token: &str,
    key_name: &str,
    kernel_data: &[u8],
) -> Result<[u8; 64], VaultError> {
    let client = VaultClient::new(
        vault_addr.to_string(),
        vault_token.to_string(),
        None,
    )?;

    let kernel_hash = blake3::hash(kernel_data);
    let hash_bytes: [u8; 32] = *kernel_hash.as_bytes();

    client.sign_with_transit(key_name, &hash_bytes)
}
