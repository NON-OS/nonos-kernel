extern crate alloc;
use crate::apps::ecosystem::browser::js::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;

pub fn create_mutation_observer() -> JsValue {
    JsValue::NativeFunc(construct_mutation_observer)
}
pub fn create_intersection_observer() -> JsValue {
    JsValue::NativeFunc(construct_intersection_observer)
}
pub fn create_resize_observer() -> JsValue {
    JsValue::NativeFunc(construct_resize_observer)
}

fn construct_mutation_observer(args: &[JsValue]) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("_callback"), args.first().cloned().unwrap_or(JsValue::Undefined));
    obj.insert(String::from("observe"), JsValue::NativeFunc(observe));
    obj.insert(String::from("disconnect"), JsValue::NativeFunc(disconnect));
    obj.insert(String::from("takeRecords"), JsValue::NativeFunc(take_records));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn construct_intersection_observer(args: &[JsValue]) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("_callback"), args.first().cloned().unwrap_or(JsValue::Undefined));
    obj.insert(String::from("observe"), JsValue::NativeFunc(observe));
    obj.insert(String::from("unobserve"), JsValue::NativeFunc(disconnect));
    obj.insert(String::from("disconnect"), JsValue::NativeFunc(disconnect));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn construct_resize_observer(args: &[JsValue]) -> JsValue {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("_callback"), args.first().cloned().unwrap_or(JsValue::Undefined));
    obj.insert(String::from("observe"), JsValue::NativeFunc(observe));
    obj.insert(String::from("unobserve"), JsValue::NativeFunc(disconnect));
    obj.insert(String::from("disconnect"), JsValue::NativeFunc(disconnect));
    JsValue::Object(Rc::new(RefCell::new(obj)))
}

fn observe(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}
fn disconnect(_args: &[JsValue]) -> JsValue {
    JsValue::Undefined
}

fn take_records(_args: &[JsValue]) -> JsValue {
    JsValue::Array(Rc::new(RefCell::new(alloc::vec::Vec::new())))
}
