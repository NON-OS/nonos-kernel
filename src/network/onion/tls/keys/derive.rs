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

use super::super::crypto_provider::crypto;
use super::expand::{expand_label_256, expand_label_384, expand_label_into_384, expand_label_len};
use super::schedule::KeySchedule;
use super::secret::Secret;
use crate::network::onion::OnionError;

impl KeySchedule {
    pub(crate) fn derive_after_sh(
        &mut self,
        shared: &[u8],
        th_sh: &[u8],
    ) -> Result<(), OnionError> {
        let c = crypto();
        let hl = self.hash_len;
        let zeros = [0u8; 48];
        if hl == 48 {
            let mut eh = [0u8; 48];
            c.sha384(&[], &mut eh);
            let mut ep = [0u8; 48];
            c.hkdf_extract_384(&zeros[..hl], &zeros[..hl], &mut ep);
            self.early_prk = ep;
            let derived = expand_label_384(&self.early_prk[..hl], b"derived", &eh[..hl], hl);
            let mut hp = [0u8; 48];
            c.hkdf_extract_384(&derived[..hl], shared, &mut hp);
            self.handshake_prk = hp;
            expand_label_into_384(
                &self.handshake_prk[..hl],
                b"c hs traffic",
                th_sh,
                &mut self.client_hs.secret[..hl],
            );
            expand_label_into_384(
                &self.handshake_prk[..hl],
                b"s hs traffic",
                th_sh,
                &mut self.server_hs.secret[..hl],
            );
        } else {
            let mut eh32 = [0u8; 32];
            c.sha256(&[], &mut eh32);
            let z32 = [0u8; 32];
            let mut ep32 = [0u8; 32];
            c.hkdf_extract(&z32, &z32, &mut ep32);
            self.early_prk[..32].copy_from_slice(&ep32);
            let derived32 = expand_label_256(&ep32, b"derived", &eh32);
            let mut shared32 = [0u8; 32];
            shared32[..shared.len().min(32)].copy_from_slice(&shared[..shared.len().min(32)]);
            let mut hp32 = [0u8; 32];
            c.hkdf_extract(&derived32, &shared32, &mut hp32);
            self.handshake_prk[..32].copy_from_slice(&hp32);
            let mut th32 = [0u8; 32];
            th32[..th_sh.len().min(32)].copy_from_slice(&th_sh[..th_sh.len().min(32)]);
            self.client_hs.secret[..32].copy_from_slice(&expand_label_256(
                &hp32,
                b"c hs traffic",
                &th32,
            ));
            self.server_hs.secret[..32].copy_from_slice(&expand_label_256(
                &hp32,
                b"s hs traffic",
                &th32,
            ));
        }
        Ok(())
    }

    pub(crate) fn derive_application(&mut self, th_finished: &[u8]) -> Result<(), OnionError> {
        let c = crypto();
        let hl = self.hash_len;
        let zeros = [0u8; 48];
        if hl == 48 {
            let mut eh = [0u8; 48];
            c.sha384(&[], &mut eh);
            let derived = expand_label_384(&self.handshake_prk[..hl], b"derived", &eh[..hl], hl);
            let mut mp = [0u8; 48];
            c.hkdf_extract_384(&derived[..hl], &zeros[..hl], &mut mp);
            self.master_prk = mp;
            expand_label_into_384(
                &self.master_prk[..hl],
                b"c ap traffic",
                th_finished,
                &mut self.client_app.secret[..hl],
            );
            expand_label_into_384(
                &self.master_prk[..hl],
                b"s ap traffic",
                th_finished,
                &mut self.server_app.secret[..hl],
            );
        } else {
            let mut eh32 = [0u8; 32];
            c.sha256(&[], &mut eh32);
            let z32 = [0u8; 32];
            let mut hp32 = [0u8; 32];
            hp32.copy_from_slice(&self.handshake_prk[..32]);
            let derived32 = expand_label_256(&hp32, b"derived", &eh32);
            let mut mp32 = [0u8; 32];
            c.hkdf_extract(&derived32, &z32, &mut mp32);
            self.master_prk[..32].copy_from_slice(&mp32);
            let mut tf32 = [0u8; 32];
            tf32[..th_finished.len().min(32)]
                .copy_from_slice(&th_finished[..th_finished.len().min(32)]);
            self.client_app.secret[..32].copy_from_slice(&expand_label_256(
                &mp32,
                b"c ap traffic",
                &tf32,
            ));
            self.server_app.secret[..32].copy_from_slice(&expand_label_256(
                &mp32,
                b"s ap traffic",
                &tf32,
            ));
        }
        Ok(())
    }

    pub(crate) fn derive_resumption_master_secret(&self, th_with_client_finished: &[u8]) -> Secret {
        let hl = self.hash_len;
        let mut secret = Secret::new(hl);
        expand_label_len(
            &self.master_prk[..hl],
            b"res master",
            th_with_client_finished,
            &mut secret.secret[..hl],
            hl,
        );
        secret
    }

    pub(crate) fn derive_after_sh_with_psk(
        &mut self,
        shared: &[u8],
        psk: &[u8],
        th_sh: &[u8],
    ) -> Result<(), OnionError> {
        let c = crypto();
        let hl = self.hash_len;
        if hl == 48 {
            let mut eh = [0u8; 48];
            c.sha384(&[], &mut eh);
            let zeros = [0u8; 48];
            let mut ep = [0u8; 48];
            c.hkdf_extract_384(&zeros[..hl], psk, &mut ep);
            self.early_prk = ep;
            let derived = expand_label_384(&self.early_prk[..hl], b"derived", &eh[..hl], hl);
            let mut hp = [0u8; 48];
            c.hkdf_extract_384(&derived[..hl], shared, &mut hp);
            self.handshake_prk = hp;
            expand_label_into_384(
                &self.handshake_prk[..hl],
                b"c hs traffic",
                th_sh,
                &mut self.client_hs.secret[..hl],
            );
            expand_label_into_384(
                &self.handshake_prk[..hl],
                b"s hs traffic",
                th_sh,
                &mut self.server_hs.secret[..hl],
            );
        } else {
            let mut eh32 = [0u8; 32];
            c.sha256(&[], &mut eh32);
            let z32 = [0u8; 32];
            let mut psk32 = [0u8; 32];
            psk32[..psk.len().min(32)].copy_from_slice(&psk[..psk.len().min(32)]);
            let mut ep32 = [0u8; 32];
            c.hkdf_extract(&z32, &psk32, &mut ep32);
            self.early_prk[..32].copy_from_slice(&ep32);
            let derived32 = expand_label_256(&ep32, b"derived", &eh32);
            let mut shared32 = [0u8; 32];
            shared32[..shared.len().min(32)].copy_from_slice(&shared[..shared.len().min(32)]);
            let mut hp32 = [0u8; 32];
            c.hkdf_extract(&derived32, &shared32, &mut hp32);
            self.handshake_prk[..32].copy_from_slice(&hp32);
            let mut th32 = [0u8; 32];
            th32[..th_sh.len().min(32)].copy_from_slice(&th_sh[..th_sh.len().min(32)]);
            self.client_hs.secret[..32].copy_from_slice(&expand_label_256(
                &hp32,
                b"c hs traffic",
                &th32,
            ));
            self.server_hs.secret[..32].copy_from_slice(&expand_label_256(
                &hp32,
                b"s hs traffic",
                &th32,
            ));
        }
        Ok(())
    }
}
