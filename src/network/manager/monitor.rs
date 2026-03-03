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

use alloc::string::String;
use alloc::vec::Vec;

use crate::network::firewall;
use crate::network::dns;

pub fn get_suspicious_flows() -> Vec<(String, String)> {
    let mut suspicious = Vec::new();

    let fw = firewall::get_firewall();
    let (allowed, denied, dropped, _logged, _tracked) = fw.get_stats();

    if denied > 100 && denied > allowed / 10 {
        suspicious.push((
            String::from("firewall-high-denial"),
            alloc::format!("High packet denial: {} denied vs {} allowed", denied, allowed),
        ));
    }

    if dropped > 1000 {
        suspicious.push((
            String::from("firewall-high-drops"),
            alloc::format!("Excessive dropped packets: {}", dropped),
        ));
    }

    suspicious
}

pub fn read_flow_bytes(flow_id: &str) -> Result<Vec<u8>, &'static str> {
    if flow_id.is_empty() {
        return Err("Invalid flow ID");
    }

    Err("Flow not found")
}

pub fn get_recent_dns_queries() -> Vec<String> {
    dns::get_recent_queries()
}
