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

use alloc::format;
use alloc::string::String;

use super::network_line::NETWORKS;
use crate::browser::net::mixnet;
use crate::browser::proxy::{parse_socks5, said, Outcome};
use crate::browser::shell::settings_ui::proxy_text;
use crate::browser::shell::Shell;
use crate::browser::tabs::Tabs;
use crate::browser::ui::settings_rows::Field;

const NOT_PROXY: &str = "Not a proxy address: type host:port, such as 127.0.0.1:9050.";

/// Chooses the network the next request leaves through, as the address
/// bar's route does: a page already loading finishes where it started.
pub(super) fn choose(tabs: &mut Tabs, i: u8) {
    let Some(&net) = NETWORKS.get(i as usize) else { return };
    mixnet::choose(net);
    tabs.active_mut().tell(format!("{} from the next request.", net.label()));
}

/// Puts the proxy typed in its field into use for every tab of the window,
/// as the address bar's `proxy socks5://` command does for one; a field
/// that is not `host:port` says so under it.
pub(super) fn set_proxy(tabs: &mut Tabs, shell: &mut Shell) {
    let typed = shell.settings.proxy.text.trim();
    let spec = match typed.starts_with("socks5://") {
        true => String::from(typed),
        false => format!("socks5://{}", typed),
    };
    let Some(cfg) = parse_socks5(&spec) else {
        shell.settings.proxy_err = Some(NOT_PROXY);
        return;
    };
    let line = said(Outcome::Set(&cfg.host, cfg.port), mixnet::chosen());
    shell.settings.refill(Field::Proxy, &proxy_text(&cfg.host, cfg.port));
    for s in tabs.list.iter_mut() {
        s.proxy = Some(cfg.clone());
    }
    tabs.active_mut().tell(line);
}

/// Turns the proxy off for every tab of the window.
pub(super) fn proxy_off(tabs: &mut Tabs, shell: &mut Shell) {
    if tabs.active().proxy.is_none() {
        return;
    }
    for s in tabs.list.iter_mut() {
        s.proxy = None;
    }
    shell.settings.refill(Field::Proxy, "");
    tabs.active_mut().tell(said(Outcome::Off, mixnet::chosen()));
}
