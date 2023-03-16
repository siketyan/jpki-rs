#![feature(vec_into_raw_parts)]
#![allow(clippy::missing_safety_doc)]

use jpki::ap::crypto::CertType;
use jpki::ap::CryptoAp;
use jpki::nfc::{HandleError, HandlerInCtx, Result as NfcResult};
use jpki::Card;
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;
use std::rc::Rc;

static mut LAST_ERROR: Option<String> = None;

fn unwrap_or<T, E>(result: Result<T, E>, default: T) -> T
where
    E: ToString,
{
    unsafe {
        // If result is an error, sets the message to LAST_ERROR.
        // Clears the last error otherwise.
        LAST_ERROR = result.as_ref().err().map(|e| e.to_string());
    }

    match result {
        Ok(value) => value,
        Err(_) => default,
    }
}

fn unwrap<T, E>(result: Result<T, E>) -> T
where
    T: Default,
    E: ToString,
{
    unwrap_or(result, T::default())
}

/// A struct represents a byte array.
/// Dependents can read it from ptr to ptr+len, and should ignore about cap.
/// ptr can be null pointer, so dependents must check the ptr is not null.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ByteArray {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl Default for ByteArray {
    fn default() -> Self {
        Self {
            ptr: null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(bytes: Vec<u8>) -> Self {
        let bytes = Box::new(bytes);
        let (ptr, len, cap) = bytes.into_raw_parts();
        Self { ptr, len, cap }
    }
}

impl From<ByteArray> for Vec<u8> {
    fn from(ByteArray { ptr, len, cap }: ByteArray) -> Self {
        unsafe { Self::from_raw_parts(ptr, len, cap) }
    }
}

impl ByteArray {
    fn drain(self) {
        let Self { ptr, len, cap } = self;
        let _ = unsafe { Vec::from_raw_parts(ptr, len, cap) };
    }
}

pub struct NfcCard {
    delegate_: extern "C" fn(command: ByteArray) -> ByteArray,
}

impl HandlerInCtx for NfcCard {
    fn handle_in_ctx(&self, _: (), command: &[u8], response: &mut [u8]) -> NfcResult {
        let command = Vec::from(command).into();
        let buf = Vec::from((self.delegate_)(command));
        let len = buf.len();
        if response.len() < len {
            return Err(HandleError::NotEnoughBuffer(len));
        }

        response[..len].copy_from_slice(&buf);
        command.drain();
        Ok(len)
    }
}

/// Initiates the libjpki library.
/// Currently this occur no side effects, but it will be added in the future.
/// So dependents should call this before using other functions.
#[no_mangle]
pub extern "C" fn jpki_init() {}

/// Returns the latest error occurred before calling this function.
/// If no error occurred before or failed to get the error, returns null pointer.
#[no_mangle]
pub extern "C" fn jpki_last_error() -> *mut c_char {
    match unsafe { LAST_ERROR.clone() }.and_then(|e| CString::new(e).ok()) {
        Some(str) => str.into_raw(),
        None => null_mut(),
    }
}

/// Creates a new NFC card delegate from the function pointer.
/// This provided function will be called on transmitting APDU commands into the card.
#[no_mangle]
pub extern "C" fn jpki_new_nfc_card(
    delegate_: extern "C" fn(command: ByteArray) -> ByteArray,
) -> *mut NfcCard {
    let card = NfcCard { delegate_ };

    Box::into_raw(Box::new(card))
}

/// Closes the NFC card.
#[no_mangle]
pub unsafe extern "C" fn jpki_nfc_card_close(card: &mut NfcCard) {
    let _ = Box::from_raw(card);
}

/// Creates a new card from the NFC card.
/// This is an abstraction layer to support other protocols rather than NFC in the future.
#[no_mangle]
pub unsafe extern "C" fn jpki_new_card(nfc_card: *mut NfcCard) -> *mut Card<NfcCard, ()> {
    let nfc_card = Box::from_raw(nfc_card);
    let card = Card::new(nfc_card);

    Box::into_raw(Box::new(card))
}

/// Closes the card.
#[no_mangle]
pub unsafe extern "C" fn jpki_card_close(card: &mut Card<NfcCard, ()>) {
    // HACK: To avoid NfcCard to be deallocated recursively, using Rc instead of Box here.
    let _ = Rc::from_raw(card);
}

/// Opens JPKI application on the card.
#[no_mangle]
pub unsafe extern "C" fn jpki_new_crypto_ap(
    card: *mut Card<NfcCard, ()>,
) -> *mut CryptoAp<NfcCard, ()> {
    let card = Rc::from_raw(card);

    unwrap_or(
        CryptoAp::open((), card).map(|ap| Box::into_raw(Box::new(ap))),
        null_mut(),
    )
}

/// Closes the opened JPKI application.
#[no_mangle]
pub unsafe extern "C" fn jpki_crypto_ap_close(crypto_ap: *mut CryptoAp<NfcCard, ()>) {
    let _ = Box::from_raw(crypto_ap);
}

/// Reads a certificate for signing.
/// PIN is required.
/// If ca is true, reads a CA certificate instead.
#[no_mangle]
pub unsafe extern "C" fn jpki_crypto_ap_read_certificate_sign(
    crypto_ap: *mut CryptoAp<NfcCard, ()>,
    pin: *const c_char,
    ca: bool,
) -> ByteArray {
    let pin = CStr::from_ptr(pin).to_bytes().to_vec();
    let ty = match ca {
        true => CertType::SignCA,
        _ => CertType::Sign,
    };

    unwrap(
        crypto_ap
            .as_ref()
            .unwrap()
            .read_certificate((), ty, pin)
            .map(|v| v.into()),
    )
}

/// Reads a certificate for user authentication.
/// If ca is true, reads a CA certificate instead.
#[no_mangle]
pub unsafe extern "C" fn jpki_crypto_ap_read_certificate_auth(
    crypto_ap: *mut CryptoAp<NfcCard, ()>,
    ca: bool,
) -> ByteArray {
    let ty = match ca {
        true => CertType::AuthCA,
        _ => CertType::Auth,
    };

    unwrap(
        crypto_ap
            .as_ref()
            .unwrap()
            .read_certificate((), ty, vec![])
            .map(|v| v.into()),
    )
}

/// Sign the computed digest using the key-pair for user authentication.
#[no_mangle]
pub unsafe extern "C" fn jpki_crypto_ap_auth(
    crypto_ap: *mut CryptoAp<NfcCard, ()>,
    pin: *const c_char,
    digest: ByteArray,
) -> ByteArray {
    let pin = CStr::from_ptr(pin).to_bytes().to_vec();

    unwrap(
        crypto_ap
            .as_ref()
            .unwrap()
            .auth((), pin, digest.into())
            .map(|v| v.into()),
    )
}

/// Sign the computed digest using the key-pair for signing.
#[no_mangle]
pub unsafe extern "C" fn jpki_crypto_ap_sign(
    crypto_ap: *mut CryptoAp<NfcCard, ()>,
    pin: *const c_char,
    digest: ByteArray,
) -> ByteArray {
    let pin = CStr::from_ptr(pin).to_bytes().to_vec();

    unwrap(
        crypto_ap
            .as_ref()
            .unwrap()
            .sign((), pin, digest.into())
            .map(|v| v.into()),
    )
}
