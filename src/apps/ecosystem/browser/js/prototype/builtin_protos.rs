extern crate alloc;
use super::super::runtime::JsValue;
use super::array_proto;
use super::chain::ProtoObject;
use super::number_proto;
use super::string_proto;
use alloc::rc::Rc;
use alloc::string::String;

pub struct BuiltinPrototypes {
    pub object_proto: Rc<ProtoObject>,
    pub array_proto: Rc<ProtoObject>,
    pub string_proto: Rc<ProtoObject>,
    pub number_proto: Rc<ProtoObject>,
    pub function_proto: Rc<ProtoObject>,
}

impl BuiltinPrototypes {
    pub fn new() -> Self {
        let object_proto = Rc::new(create_object_proto());
        let array_proto = Rc::new(ProtoObject::with_proto(object_proto.clone()));
        let string_proto = Rc::new(ProtoObject::with_proto(object_proto.clone()));
        let number_proto = Rc::new(ProtoObject::with_proto(object_proto.clone()));
        let function_proto = Rc::new(ProtoObject::with_proto(object_proto.clone()));
        string_proto::populate(&string_proto);
        array_proto::populate(&array_proto);
        number_proto::populate(&number_proto);
        Self { object_proto, array_proto, string_proto, number_proto, function_proto }
    }
}

fn create_object_proto() -> ProtoObject {
    let proto = ProtoObject::new();
    let p = &proto.properties;
    p.borrow_mut().insert(String::from("hasOwnProperty"), JsValue::NativeFunc(has_own_property));
    p.borrow_mut().insert(String::from("toString"), JsValue::NativeFunc(to_string));
    p.borrow_mut().insert(String::from("valueOf"), JsValue::NativeFunc(value_of));
    proto
}

fn has_own_property(_args: &[JsValue]) -> JsValue {
    JsValue::Bool(false)
}
fn to_string(_args: &[JsValue]) -> JsValue {
    JsValue::String(String::from("[object Object]"))
}
fn value_of(args: &[JsValue]) -> JsValue {
    args.first().cloned().unwrap_or(JsValue::Undefined)
}
