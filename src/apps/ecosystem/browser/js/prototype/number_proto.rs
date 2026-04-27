extern crate alloc;
use super::super::runtime::JsValue;
use super::chain::ProtoObject;
use alloc::string::String;

pub fn populate(proto: &ProtoObject) {
    let p = &proto.properties;
    p.borrow_mut().insert(String::from("toFixed"), JsValue::NativeFunc(to_fixed));
    p.borrow_mut().insert(String::from("toString"), JsValue::NativeFunc(to_string));
    p.borrow_mut().insert(String::from("valueOf"), JsValue::NativeFunc(value_of));
}

fn to_fixed(a: &[JsValue]) -> JsValue {
    let n = a.first().map(|v| v.to_number()).unwrap_or(0.0);
    let digits = a.get(1).map(|v| v.to_number() as usize).unwrap_or(0);
    let factor = libm::pow(10.0, digits as f64);
    let rounded = libm::round(n * factor) / factor;
    JsValue::String(alloc::format!("{:.prec$}", rounded, prec = digits))
}

fn to_string(a: &[JsValue]) -> JsValue {
    JsValue::String(a.first().map(|v| v.to_string()).unwrap_or_default())
}

fn value_of(a: &[JsValue]) -> JsValue {
    a.first().cloned().unwrap_or(JsValue::Undefined)
}
