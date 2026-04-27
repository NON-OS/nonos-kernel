extern crate alloc;
use super::chain::ProtoObject;
use alloc::rc::Rc;

pub fn create_with_proto(proto: Rc<ProtoObject>) -> ProtoObject {
    ProtoObject::with_proto(proto)
}

pub fn object_create(proto: Option<Rc<ProtoObject>>) -> ProtoObject {
    match proto {
        Some(p) => ProtoObject::with_proto(p),
        None => ProtoObject::new(),
    }
}
