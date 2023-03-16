#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate log;
extern crate android_log;

use std::rc::Rc;

use jni::objects::{GlobalRef, JByteBuffer, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jlong, jobject, jstring, JNI_TRUE};
use jni::JNIEnv;

use jpki::ap::crypto::CertType;
use jpki::ap::CryptoAp;
use jpki::{card, nfc, Card};

const NULL: jobject = 0 as jobject;

static mut LAST_ERROR: Option<String> = None;

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("Card Error: {0}")]
    Card(#[from] card::Error),

    #[error("JNI Error: {0}")]
    Jni(#[from] jni::errors::Error),
}

struct JniNfcCard {
    delegate: GlobalRef,
}

#[derive(Copy, Clone)]
struct JniContext<'a> {
    env: JNIEnv<'a>,
}

impl nfc::HandlerInCtx<JniContext<'_>> for JniNfcCard {
    fn handle_in_ctx(&self, ctx: JniContext, command: &[u8], response: &mut [u8]) -> nfc::Result {
        let bytes = Vec::from(command).leak();
        let buffer = unsafe {
            ctx.env
                .new_direct_byte_buffer(bytes.as_mut_ptr(), bytes.len())
        }
        .unwrap();

        let obj = self.delegate.as_obj();
        let arg_val = JValue::Object(JObject::from(buffer));
        let res = ctx.env.call_method(
            obj,
            "handleApdu",
            "(Ljava/nio/ByteBuffer;)Ljava/nio/ByteBuffer;",
            &[arg_val],
        );

        if let Err(ref e) = res {
            error!("handleApdu Error: {:?}", e)
        }

        let val = res.unwrap();
        let buf = if let JValue::Object(obj) = val {
            let buffer = JByteBuffer::from(obj);
            let ptr = match ctx.env.get_direct_buffer_address(buffer) {
                Ok(ptr) => ptr,
                Err(e) => {
                    error!("getDirectBufferAddress Error: {:?}", e);
                    return Err(nfc::HandleError::Nfc(Box::new(e)));
                }
            };
            let cap = match ctx.env.get_direct_buffer_capacity(buffer) {
                Ok(cap) => cap,
                Err(e) => return Err(nfc::HandleError::Nfc(Box::new(e))),
            };

            unsafe { std::slice::from_raw_parts_mut(ptr, cap) }
        } else {
            return Err(nfc::HandleError::Nfc(Box::new("failed")));
        };

        info!("APDU Response Received: {:?}", buf);

        let len = buf.len();
        if response.len() < len {
            return Err(nfc::HandleError::NotEnoughBuffer(len));
        }

        response[..len].copy_from_slice(buf);

        Ok(len)
    }
}

impl JniNfcCard {
    pub fn new(delegate: GlobalRef) -> Self {
        Self { delegate }
    }
}

unsafe fn unwrap<T, E>(result: Result<T, E>) -> T
where
    T: Default,
    E: std::error::Error,
{
    match result {
        Ok(value) => value,
        Err(err) => {
            LAST_ERROR = Some(err.to_string());
            T::default()
        }
    }
}

unsafe fn unwrap_or_default<T, E>(result: Result<T, E>, default: T) -> T
where
    E: std::error::Error,
{
    match result {
        Ok(value) => value,
        Err(err) => {
            LAST_ERROR = Some(err.to_string());
            default
        }
    }
}

macro_rules! wrap {
    (jobject, $inner: expr) => {
        unwrap_or_default((|| -> Result<jobject, Error> { $inner })(), NULL)
    };

    (jobject, $e: ty, $inner: expr) => {
        unwrap_or_default((|| -> Result<jobject, $e> { $inner })(), NULL)
    };

    ($t: ty, $inner: expr) => {
        unwrap((|| -> Result<$t, Error> { $inner })())
    };

    ($t: ty, $e: ty, $inner: expr) => {
        unwrap((|| -> Result<$t, $e> { $inner })())
    };
}

#[no_mangle]
pub extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_init() {
    android_log::init("JPKI.FFI").unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_lastError(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    match LAST_ERROR.clone() {
        Some(message) => env.new_string(message).unwrap().into_raw(),
        None => 0 as jstring,
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_newNfcCard(
    env: JNIEnv,
    _class: JClass,
    delegate: JObject,
) -> jlong {
    wrap!(jlong, {
        let global_ref = env.new_global_ref(delegate).map_err(Error::Jni)?;
        let card = JniNfcCard::new(global_ref);

        Ok(Box::into_raw(Box::new(card)) as jlong)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_newCard(
    _env: JNIEnv,
    _class: JClass,
    delegate: jlong,
) -> jlong {
    let nfc_card = Box::from_raw(delegate as *mut JniNfcCard);
    let card = Card::new(nfc_card);

    Box::into_raw(Box::new(card)) as jlong
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_newCryptoAp(
    env: JNIEnv,
    _class: JClass,
    delegate: jlong,
) -> jlong {
    wrap!(jlong, {
        let ctx = JniContext { env };
        let card = Rc::from_raw(delegate as *mut Card<JniNfcCard, JniContext>);
        let ap = CryptoAp::open(ctx, card)?;

        Ok(Box::into_raw(Box::new(ap)) as jlong)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_cryptoApReadCertificateSign(
    env: JNIEnv,
    _class: JClass,
    crypto_ap: jlong,
    pin: jstring,
    ca: jboolean,
) -> jobject {
    wrap!(jobject, {
        let ctx = JniContext { env };
        let pin = jstring_to_bytes_vec(env, pin)?;
        let ty = match ca {
            JNI_TRUE => CertType::SignCA,
            _ => CertType::Sign,
        };

        let ap = &mut *(crypto_ap as *mut CryptoAp<JniNfcCard, JniContext>);
        let certificate = ap.read_certificate(ctx, ty, pin)?.leak();
        let buffer = env
            .new_direct_byte_buffer(certificate.as_mut_ptr(), certificate.len())
            .map_err(Error::Jni)?;

        Ok(buffer.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_cryptoApReadCertificateAuth(
    env: JNIEnv,
    _class: JClass,
    crypto_ap: jlong,
    ca: jboolean,
) -> jobject {
    wrap!(jobject, {
        let ctx = JniContext { env };
        let pin = vec![];
        let ty = match ca {
            JNI_TRUE => CertType::AuthCA,
            _ => CertType::Auth,
        };

        let ap = &mut *(crypto_ap as *mut CryptoAp<JniNfcCard, JniContext>);
        let certificate = ap.read_certificate(ctx, ty, pin)?.leak();
        let buffer = env
            .new_direct_byte_buffer(certificate.as_mut_ptr(), certificate.len())
            .map_err(Error::Jni)?;

        Ok(buffer.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_cryptoApAuth(
    env: JNIEnv,
    _class: JClass,
    crypto_ap: jlong,
    pin: jstring,
    digest: jbyteArray,
) -> jobject {
    wrap!(jobject, {
        let ctx = JniContext { env };
        let pin = jstring_to_bytes_vec(env, pin)?;
        let digest = env.convert_byte_array(digest).map_err(Error::Jni)?;

        let ap = &mut *(crypto_ap as *mut CryptoAp<JniNfcCard, JniContext>);
        let signature = ap.auth(ctx, pin, digest)?.leak();
        let buffer = env
            .new_direct_byte_buffer(signature.as_mut_ptr(), signature.len())
            .map_err(Error::Jni)?;

        Ok(buffer.into_raw())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_cryptoApClose(
    _env: JNIEnv,
    _class: JClass,
    crypto_ap: jlong,
) {
    let _ = Box::from_raw(crypto_ap as *mut CryptoAp<JniNfcCard, JniContext>);
}

fn jstring_to_bytes_vec(env: JNIEnv, str: jstring) -> Result<Vec<u8>, Error> {
    Ok(env
        .get_string(unsafe { JString::from_raw(str) })
        .map_err(Error::Jni)?
        .to_bytes()
        .to_vec())
}
