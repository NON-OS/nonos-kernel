// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The History page's route pills: All, Mixnet, Anyone, and Direct, which
//! holds the SOCKS proxy as it rides the direct network.

use crate::browser::shell::route::Route;
use crate::browser::shell::types::Visit;
use crate::browser::shell::visits::filter;

fn on(url: &str, route: Route) -> Visit {
    Visit { url: url.into(), title: String::new(), host: String::new(), at_ms: 0, route }
}

#[test]
fn the_route_pills_filter_newest_first() {
    let v = [
        on("https://a/", Route::Direct),
        on("https://b/", Route::Mixnet),
        on("https://c/", Route::Socks),
        on("https://d/", Route::Anyone),
    ];
    assert_eq!(filter(&v, 0), [3, 2, 1, 0]);
    assert_eq!(filter(&v, 1), [1]);
    assert_eq!(filter(&v, 2), [3]);
    assert_eq!(filter(&v, 3), [2, 0]);
    assert_eq!(filter(&v, 9), [3, 2, 1, 0]);
    assert!(filter(&[], 1).is_empty());
}
