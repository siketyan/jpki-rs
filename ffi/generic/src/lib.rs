#![feature(vec_into_raw_parts)]

use jpki::ap::JpkiAp;
use jpki::nfc::{Command, HandlerInCtx, Response};
use jpki::Card;
use std::rc::Rc;

#[repr(C)]
pub struct ByteArray {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

pub struct NfcCard {
    delegate: extern "C" fn(ByteArray) -> ByteArray,
}

impl HandlerInCtx for NfcCard {
    fn handle_in_ctx(&self, _: (), command: Command) -> Response {
        let bytes = Box::new(Vec::from(command));
        let (ptr, len, cap) = bytes.into_raw_parts();
        let byte_array = ByteArray { ptr, len, cap };

        let ByteArray { ptr, len, cap } = (self.delegate)(byte_array);

        unsafe { Response::from(Vec::from_raw_parts(ptr, len, cap)) }
    }
}

#[no_mangle]
pub extern "C" fn jpki_init() {}

#[no_mangle]
pub extern "C" fn jpki_new_nfc_card(
    delegate: extern "C" fn(ByteArray) -> ByteArray,
) -> *mut NfcCard {
    let card = NfcCard { delegate };

    Box::into_raw(Box::new(card))
}

#[no_mangle]
pub unsafe extern "C" fn jpki_new_card(nfc_card: *mut NfcCard) -> *mut Card<NfcCard, ()> {
    let nfc_card = Box::from_raw(nfc_card);
    let card = Card::new(nfc_card);

    Box::into_raw(Box::new(card))
}

#[no_mangle]
pub unsafe extern "C" fn jpki_new_jpki_ap(
    card: *mut Card<NfcCard, ()>,
) -> *mut JpkiAp<NfcCard, ()> {
    let card = Rc::from_raw(card);
    let ap = JpkiAp::open((), card).unwrap();

    Box::into_raw(Box::new(ap))
}
