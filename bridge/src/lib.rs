use ffi_support::IntoFfi;
use jpki::{ap, nfc, Card};
use std::error::Error;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr::null_mut;

ffi_support::implement_into_ffi_by_pointer! {
    ap::JpkiAp::<'static>,
    Card,
    NfcCard,
}

const CERT_TYPE_AUTH: u32 = 0;
const CERT_TYPE_AUTH_CA: u32 = 1;
const CERT_TYPE_SIGN: u32 = 2;
const CERT_TYPE_SIGN_CA: u32 = 3;

#[repr(C)]
struct ByteArrayRef {
    len: u64,
    ptr: *mut u8,
}

impl ByteArrayRef {
    fn new(vec: Vec<u8>) -> Self {}
}

#[repr(C)]
struct FfiResult<T, E>
where
    T: IntoFfi,
    E: Error,
{
    ptr: *mut T,
    ptr_err: *mut c_char,
}

impl<T, E> FfiResult<T, E>
where
    T: IntoFfi,
    E: Error,
{
    fn new(src: Result<T, E>) -> Self {
        if src.is_ok() {
            Self {
                ptr: src.unwrap().into_ffi_value(),
                ptr_err: null_mut(),
            }
        } else {
            Self {
                ptr: null_mut(),
                ptr_err: CString::new(src.err().unwrap().to_string())
                    .unwrap()
                    .into_raw(),
            }
        }
    }
}

type NfcCardDelegate = unsafe extern "C" fn(req: ByteArrayRef) -> ByteArrayRef;

struct NfcCard {
    delegate: NfcCardDelegate,
}

impl NfcCard {
    fn new(delegate: NfcCardDelegate) -> Self {
        Self { delegate }
    }
}

impl nfc::apdu::Handler for NfcCard {
    fn handle(&self, command: nfc::apdu::Command) -> nfc::apdu::Response {
        nfc::apdu::Response::from(self.delegate(ByteArrayRef::new(command.into_bytes())))
    }
}

impl nfc::Card for NfcCard {}

#[no_mangle]
pub extern "C" fn jpki_nfc_card_new(delegate: NfcCardDelegate) -> *mut NfcCard {
    NfcCard { delegate }.into_ffi_value()
}

#[no_mangle]
pub extern "C" fn jpki_card_new(nfc_card: *mut NfcCard) -> *mut Card {
    Card::new(Box::new(nfc_card)).into_ffi_value()
}

#[no_mangle]
pub extern "C" fn jpki_ap_jpki_open(
    card: *mut Card,
) -> FfiResult<ap::JpkiAp<'static>, nfc::apdu::Error> {
    FfiResult::new(ap::JpkiAp::open(&card))
}

#[no_mangle]
pub extern "C" fn jpki_ap_jpki_read_certificate(ap: *mut ap::JpkiAp, ty: u32) -> ByteArrayRef {
    ByteArrayRef::new(
        ap.read_certificate(match ty {
            CERT_TYPE_AUTH => ap::jpki::CertType::Auth,
            CERT_TYPE_AUTH_CA => ap::jpki::CertType::AuthCA,
            CERT_TYPE_SIGN => ap::jpki::CertType::Sign,
            CERT_TYPE_SIGN_CA => ap::jpki::CertType::SignCA,
            _ => panic!("error"),
        })
        .unwrap_or_else(vec![]),
    )
}
