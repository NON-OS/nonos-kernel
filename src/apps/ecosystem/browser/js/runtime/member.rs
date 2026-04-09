extern crate alloc;
use super::value::JsValue;
use super::engine::JsRuntime;
use crate::apps::ecosystem::browser::js::prototype::ProtoChain;

impl JsRuntime {
    pub fn get_member(&self, obj: &JsValue, key: &str) -> JsValue {
        match obj {
            JsValue::Object(o) => {
                if let Some(val) = o.borrow().get(key) { return val.clone(); }
                ProtoChain::get_property(&self.prototypes.object_proto, key)
                    .unwrap_or(JsValue::Undefined)
            }
            JsValue::Array(a) => {
                if key == "length" { return JsValue::Number(a.borrow().len() as f64); }
                if let Ok(i) = key.parse::<usize>() {
                    return a.borrow().get(i).cloned().unwrap_or(JsValue::Undefined);
                }
                ProtoChain::get_property(&self.prototypes.array_proto, key)
                    .unwrap_or(JsValue::Undefined)
            }
            JsValue::String(s) => {
                if key == "length" { return JsValue::Number(s.len() as f64); }
                if let Ok(i) = key.parse::<usize>() {
                    return s.chars().nth(i)
                        .map(|c| JsValue::String(alloc::format!("{}", c)))
                        .unwrap_or(JsValue::Undefined);
                }
                ProtoChain::get_property(&self.prototypes.string_proto, key)
                    .unwrap_or(JsValue::Undefined)
            }
            JsValue::Number(_) => {
                ProtoChain::get_property(&self.prototypes.number_proto, key)
                    .unwrap_or(JsValue::Undefined)
            }
            JsValue::Function(_) | JsValue::NativeFunc(_) => {
                ProtoChain::get_property(&self.prototypes.function_proto, key)
                    .unwrap_or(JsValue::Undefined)
            }
            _ => JsValue::Undefined,
        }
    }
}
