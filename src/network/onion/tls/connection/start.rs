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
use super::super::io::write_all;
use super::super::protocol::{
    build_client_hello, build_client_hello_with_psk, wrap_record, PskParams,
};
use super::super::session::compute_psk_binder;
use super::super::types::{ContentType, TLS_1_2};
use super::types::{HandshakePhase, TLSConnection};
use crate::network::onion::OnionError;
use crate::network::tcp::TcpSocket;
use alloc::string::ToString;

impl TLSConnection {
    pub fn start_handshake(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        alpn: Option<&[&str]>,
    ) -> Result<(), OnionError> {
        if self.phase != HandshakePhase::Idle {
            return Err(OnionError::CryptoError);
        }
        // Cache SNI and ALPN for potential HRR ClientHello2 rebuild
        self.sni_cache = sni.map(|s| s.to_string());
        self.alpn_cache = alpn.map(|a| a.iter().map(|s| s.to_string()).collect());

        let c = crypto();
        crate::sys::serial::println(b"[TLS-START] random");
        c.random(&mut self.client_random)?;
        crate::sys::serial::println(b"[TLS-START] x25519_keypair");
        let (epk_x25519, esk_x25519) = c.x25519_keypair()?;
        crate::sys::serial::println(b"[TLS-START] p256_keypair");
        let (esk_p256, epk_p256) = c.p256_keypair()?;
        crate::sys::serial::println(b"[TLS-START] keypairs done");
        self.ephemeral_x25519 = esk_x25519;
        self.ephemeral_p256 = esk_p256;
        let key_shares: &[(u16, &[u8])] = &[(0x001d, &epk_x25519), (0x0017, &epk_p256)];

        // Try PSK resumption if we have a cached session ticket
        let ch = if let Some(ticket) = self.try_get_session_ticket(sni) {
            let psk = ticket.derive_psk();
            let hash_len = ticket.hash_len;
            let obfuscated_age = ticket.obfuscated_age(crate::time::timestamp_millis());

            let psk_params =
                PskParams { ticket: &ticket.ticket, obfuscated_age, binder_len: hash_len };

            let (mut ch_msg, binder_offset) = build_client_hello_with_psk(
                &self.client_random,
                sni,
                alpn,
                key_shares,
                &psk_params,
            );

            // Compute the binder over the truncated ClientHello.
            // Use a temporary transcript with the ticket's suite for hashing.
            let truncated = &ch_msg[..binder_offset];
            let mut tmp_transcript = super::super::transcript::Transcript::new();
            tmp_transcript.set_suite(ticket.suite);
            tmp_transcript.add_handshake(truncated);
            let th_truncated = tmp_transcript.hash();

            let binder = compute_psk_binder(&psk, ticket.suite, th_truncated);

            // Patch the binder into the ClientHello
            ch_msg[binder_offset..binder_offset + hash_len].copy_from_slice(&binder);

            self.using_psk = true;
            self.psk_suite = Some(ticket.suite);
            self.psk_value = Some(psk);

            ch_msg
        } else {
            crate::sys::serial::println(b"[TLS-START] build_client_hello");
            build_client_hello(&self.client_random, sni, alpn, key_shares)
        };

        crate::sys::serial::println(b"[TLS-START] add_handshake + wrap_record");
        self.transcript.add_handshake(&ch);
        write_all(sock, &wrap_record(ContentType::Handshake as u8, TLS_1_2, &ch), 10_000)?;
        crate::sys::serial::println(b"[TLS-START] write_all done");
        self.phase = HandshakePhase::SentClientHello;
        Ok(())
    }

    /// Try to retrieve a session ticket from the cache for the given host.
    fn try_get_session_ticket(
        &self,
        sni: Option<&str>,
    ) -> Option<super::super::session::SessionTicket> {
        let cache = self.session_cache?;
        let host = sni?;
        cache.get(host, 443)
    }
}
