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

pub const SENSITIVE_EXTENSIONS: &[&str] = &[
    "key", "pem", "p12", "pfx", "gpg", "asc", "pgp",
    "crt", "cer", "der", "p7b", "p7c",
    "env", "htpasswd", "netrc", "npmrc",
    "keystore", "jks", "kdbx",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
];

pub const SENSITIVE_FILENAMES: &[&str] = &[
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys", "known_hosts",
    "shadow", "passwd", "master.passwd",
    "secrets", "credentials", "password", "passwords",
    "token", "access_token", "refresh_token", "api_key",
    "config.json", "secrets.yaml", "secrets.yml",
    "credentials.json", "service_account.json",
    ".env", ".env.local", ".env.production",
    ".htpasswd", ".netrc", ".npmrc", ".pypirc",
    "kubeconfig", "kube.config",
    "private.key", "server.key", "client.key",
    "keyfile", "keyring",
    "wallet.dat", "seed.txt",
];

pub const SENSITIVE_PATTERNS: &[&str] = &[
    "secret", "private", "credential", "password", "passwd",
    "apikey", "api_key", "api-key",
    "authtoken", "auth_token", "auth-token",
    "accesskey", "access_key", "access-key",
    "privatekey", "private_key", "private-key",
    "encryption", "decrypt",
];

pub const CRYPTO_EXTENSIONS: &[&str] = &[
    "key", "pem", "p12", "pfx", "gpg", "asc", "pgp",
    "crt", "cer", "der", "p7b", "p7c", "p7s",
    "keystore", "jks", "kdbx", "kdb",
    "aes", "enc", "encrypted",
];

pub const CERTIFICATE_EXTENSIONS: &[&str] = &[
    "crt", "cer", "der", "pem", "p7b", "p7c", "p7s", "pfx", "p12",
];

pub const CONFIG_EXTENSIONS: &[&str] = &[
    "json", "yaml", "yml", "toml", "ini", "cfg", "conf", "config",
    "properties", "xml",
];

pub const DATABASE_EXTENSIONS: &[&str] = &[
    "db", "sqlite", "sqlite3", "mdb", "accdb", "dbf", "sql",
];

pub const ARCHIVE_EXTENSIONS: &[&str] = &[
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "tgz", "tbz2",
];

pub const BACKUP_EXTENSIONS: &[&str] = &[
    "bak", "backup", "old", "orig", "save", "swp", "tmp",
];

pub const LOG_EXTENSIONS: &[&str] = &[
    "log", "logs", "out", "err", "trace",
];

pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "so", "dylib", "bin", "elf", "com", "bat", "sh", "ps1",
];
