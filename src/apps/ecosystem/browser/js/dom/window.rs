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
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

pub struct JsWindow {
    pub inner_width: u32,
    pub inner_height: u32,
    pub location: String,
}

impl JsWindow {
    pub fn new(width: u32, height: u32, url: &str) -> Self {
        Self { inner_width: width, inner_height: height, location: String::from(url) }
    }
    pub fn to_js_value(&self) -> JsValue {
        let mut obj = BTreeMap::new();
        obj.insert(String::from("innerWidth"), JsValue::Number(self.inner_width as f64));
        obj.insert(String::from("innerHeight"), JsValue::Number(self.inner_height as f64));
        obj.insert(String::from("outerWidth"), JsValue::Number(self.inner_width as f64));
        obj.insert(String::from("outerHeight"), JsValue::Number(self.inner_height as f64));
        obj.insert(String::from("screenX"), JsValue::Number(0.0));
        obj.insert(String::from("screenY"), JsValue::Number(0.0));
        obj.insert(String::from("scrollX"), JsValue::Number(0.0));
        obj.insert(String::from("scrollY"), JsValue::Number(0.0));
        obj.insert(String::from("location"), self.create_location());
        obj.insert(String::from("navigator"), self.create_navigator());
        obj.insert(String::from("history"), self.create_history());
        obj.insert(String::from("localStorage"), self.create_storage());
        obj.insert(String::from("sessionStorage"), self.create_storage());
        obj.insert(String::from("setTimeout"), JsValue::NativeFunc(native_set_timeout));
        obj.insert(String::from("setInterval"), JsValue::NativeFunc(native_set_interval));
        obj.insert(String::from("clearTimeout"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("clearInterval"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(
            String::from("requestAnimationFrame"),
            JsValue::NativeFunc(|_| JsValue::Number(0.0)),
        );
        obj.insert(
            String::from("cancelAnimationFrame"),
            JsValue::NativeFunc(|_| JsValue::Undefined),
        );
        obj.insert(String::from("alert"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("confirm"), JsValue::NativeFunc(|_| JsValue::Bool(false)));
        obj.insert(String::from("prompt"), JsValue::NativeFunc(|_| JsValue::Null));
        obj.insert(String::from("open"), JsValue::NativeFunc(|_| JsValue::Null));
        obj.insert(String::from("close"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("scroll"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("scrollTo"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("scrollBy"), JsValue::NativeFunc(|_| JsValue::Undefined));
        obj.insert(String::from("fetch"), JsValue::NativeFunc(native_fetch));
        obj.insert(String::from("atob"), JsValue::NativeFunc(native_atob));
        obj.insert(String::from("btoa"), JsValue::NativeFunc(native_btoa));
        JsValue::Object(Rc::new(RefCell::new(obj)))
    }
    fn create_location(&self) -> JsValue {
        let mut loc = BTreeMap::new();
        loc.insert(String::from("href"), JsValue::String(self.location.clone()));
        loc.insert(String::from("protocol"), JsValue::String(String::from("https:")));
        loc.insert(String::from("host"), JsValue::String(String::new()));
        loc.insert(String::from("hostname"), JsValue::String(String::new()));
        loc.insert(String::from("port"), JsValue::String(String::new()));
        loc.insert(String::from("pathname"), JsValue::String(String::from("/")));
        loc.insert(String::from("search"), JsValue::String(String::new()));
        loc.insert(String::from("hash"), JsValue::String(String::new()));
        loc.insert(String::from("reload"), JsValue::NativeFunc(|_| JsValue::Undefined));
        loc.insert(String::from("assign"), JsValue::NativeFunc(|_| JsValue::Undefined));
        loc.insert(String::from("replace"), JsValue::NativeFunc(|_| JsValue::Undefined));
        JsValue::Object(Rc::new(RefCell::new(loc)))
    }
    fn create_navigator(&self) -> JsValue {
        let mut nav = BTreeMap::new();
        nav.insert(String::from("userAgent"), JsValue::String(String::from("NONOS Browser/1.0")));
        nav.insert(String::from("platform"), JsValue::String(String::from("NONOS")));
        nav.insert(String::from("language"), JsValue::String(String::from("en-US")));
        nav.insert(
            String::from("languages"),
            JsValue::Array(Rc::new(RefCell::new(alloc::vec![JsValue::String(String::from(
                "en-US"
            ))]))),
        );
        nav.insert(String::from("onLine"), JsValue::Bool(true));
        nav.insert(String::from("cookieEnabled"), JsValue::Bool(true));
        JsValue::Object(Rc::new(RefCell::new(nav)))
    }
    fn create_history(&self) -> JsValue {
        let mut hist = BTreeMap::new();
        hist.insert(String::from("length"), JsValue::Number(1.0));
        hist.insert(String::from("back"), JsValue::NativeFunc(|_| JsValue::Undefined));
        hist.insert(String::from("forward"), JsValue::NativeFunc(|_| JsValue::Undefined));
        hist.insert(String::from("go"), JsValue::NativeFunc(|_| JsValue::Undefined));
        hist.insert(String::from("pushState"), JsValue::NativeFunc(|_| JsValue::Undefined));
        hist.insert(String::from("replaceState"), JsValue::NativeFunc(|_| JsValue::Undefined));
        JsValue::Object(Rc::new(RefCell::new(hist)))
    }
    fn create_storage(&self) -> JsValue {
        let mut st = BTreeMap::new();
        st.insert(String::from("length"), JsValue::Number(0.0));
        st.insert(String::from("getItem"), JsValue::NativeFunc(|_| JsValue::Null));
        st.insert(String::from("setItem"), JsValue::NativeFunc(|_| JsValue::Undefined));
        st.insert(String::from("removeItem"), JsValue::NativeFunc(|_| JsValue::Undefined));
        st.insert(String::from("clear"), JsValue::NativeFunc(|_| JsValue::Undefined));
        st.insert(String::from("key"), JsValue::NativeFunc(|_| JsValue::Null));
        JsValue::Object(Rc::new(RefCell::new(st)))
    }
}

fn native_set_timeout(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn native_set_interval(_args: &[JsValue]) -> JsValue {
    JsValue::Number(0.0)
}
fn native_fetch(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn native_atob(args: &[JsValue]) -> JsValue {
    JsValue::String(args.get(0).map(|v| v.to_string()).unwrap_or_default())
}
fn native_btoa(args: &[JsValue]) -> JsValue {
    JsValue::String(args.get(0).map(|v| v.to_string()).unwrap_or_default())
}
