extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::rc::Rc;
use core::cell::RefCell;
use alloc::collections::BTreeMap;
use crate::apps::ecosystem::browser::js::runtime::JsValue;

pub fn create_url_constructor() -> JsValue { JsValue::NativeFunc(construct_url) }

fn construct_url(args: &[JsValue]) -> JsValue {
    let raw = args.first().map(|v| v.to_string()).unwrap_or_default();
    let parts = parse_url(&raw);
    let mut obj = BTreeMap::new();
    obj.insert(String::from("href"), JsValue::String(raw.clone()));
    obj.insert(String::from("origin"), JsValue::String(alloc::format!("{}://{}", parts.protocol, parts.host)));
    obj.insert(String::from("protocol"), JsValue::String(alloc::format!("{}:", parts.protocol)));
    obj.insert(String::from("host"), JsValue::String(parts.host.clone()));
    obj.insert(String::from("hostname"), JsValue::String(parts.hostname.clone()));
    obj.insert(String::from("port"), JsValue::String(parts.port.clone()));
    obj.insert(String::from("pathname"), JsValue::String(parts.pathname.clone()));
    obj.insert(String::from("search"), JsValue::String(parts.search.clone()));
    obj.insert(String::from("hash"), JsValue::String(parts.hash.clone()));
    obj.insert(String::from("searchParams"), create_search_params(&parts.search));
    obj.insert(String::from("toString"), JsValue::NativeFunc(url_to_string));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

struct UrlParts { protocol: String, host: String, hostname: String, port: String, pathname: String, search: String, hash: String }

fn parse_url(raw: &str) -> UrlParts {
    let mut rest = raw;
    let protocol = if let Some(idx) = rest.find("://") { let p = &rest[..idx]; rest = &rest[idx + 3..]; String::from(p) } else { rest = raw; String::from("https") };
    let hash = if let Some(idx) = rest.find('#') { let h = String::from(&rest[idx..]); rest = &rest[..idx]; h } else { String::new() };
    let search = if let Some(idx) = rest.find('?') { let s = String::from(&rest[idx..]); rest = &rest[..idx]; s } else { String::new() };
    let (host_part, pathname) = if let Some(idx) = rest.find('/') { (String::from(&rest[..idx]), String::from(&rest[idx..])) } else { (String::from(rest), String::from("/")) };
    let (hostname, port) = if let Some(idx) = host_part.find(':') { (String::from(&host_part[..idx]), String::from(&host_part[idx + 1..])) } else { (host_part.clone(), String::new()) };
    UrlParts { protocol, host: host_part, hostname, port, pathname, search, hash }
}

fn url_to_string(args: &[JsValue]) -> JsValue {
    if let Some(JsValue::Object(ref obj)) = args.first() {
        obj.borrow().get("href").cloned().unwrap_or(JsValue::Undefined)
    } else { JsValue::Undefined }
}

pub fn create_search_params(query: &str) -> JsValue {
    let mut store = BTreeMap::new();
    let q = if query.starts_with('?') { &query[1..] } else { query };
    for pair in q.split('&') {
        if pair.is_empty() { continue; }
        let (k, v) = if let Some(idx) = pair.find('=') { (String::from(&pair[..idx]), String::from(&pair[idx + 1..])) } else { (String::from(pair), String::new()) };
        store.insert(k, JsValue::String(v));
    }
    let mut obj = BTreeMap::new();
    obj.insert(String::from("_store"), JsValue::Object(Rc::new(RefCell::new(store))));
    obj.insert(String::from("get"), JsValue::NativeFunc(sp_get));
    obj.insert(String::from("set"), JsValue::NativeFunc(sp_set));
    obj.insert(String::from("has"), JsValue::NativeFunc(sp_has));
    obj.insert(String::from("delete"), JsValue::NativeFunc(sp_delete));
    obj.insert(String::from("toString"), JsValue::NativeFunc(sp_to_string));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn sp_store(args: &[JsValue]) -> Option<Rc<RefCell<BTreeMap<String, JsValue>>>> {
    if let Some(JsValue::Object(ref o)) = args.first() {
        if let Some(JsValue::Object(ref s)) = o.borrow().get("_store") { return Some(s.clone()); }
    }
    None
}

fn sp_get(a: &[JsValue]) -> JsValue { let k = a.get(1).map(|v| v.to_string()).unwrap_or_default(); sp_store(a).and_then(|s| s.borrow().get(&k).cloned()).unwrap_or(JsValue::Null) }
fn sp_set(a: &[JsValue]) -> JsValue { let k = a.get(1).map(|v| v.to_string()).unwrap_or_default(); let v = a.get(2).cloned().unwrap_or(JsValue::Undefined); if let Some(s) = sp_store(a) { s.borrow_mut().insert(k, v); } JsValue::Undefined }
fn sp_has(a: &[JsValue]) -> JsValue { let k = a.get(1).map(|v| v.to_string()).unwrap_or_default(); JsValue::Bool(sp_store(a).map(|s| s.borrow().contains_key(&k)).unwrap_or(false)) }
fn sp_delete(a: &[JsValue]) -> JsValue { let k = a.get(1).map(|v| v.to_string()).unwrap_or_default(); if let Some(s) = sp_store(a) { s.borrow_mut().remove(&k); } JsValue::Undefined }

fn sp_to_string(a: &[JsValue]) -> JsValue {
    if let Some(s) = sp_store(a) {
        let pairs: Vec<String> = s.borrow().iter().map(|(k, v)| alloc::format!("{}={}", k, v.to_string())).collect();
        JsValue::String(pairs.join("&"))
    } else { JsValue::String(String::new()) }
}
