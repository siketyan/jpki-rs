#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate log;
extern crate android_log;

use std::rc::Rc;

use jni::objects::{GlobalRef, JByteBuffer, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jlong, jobject, jstring, JNI_TRUE};
use jni::JNIEnv;

use jpki::ap::jpki::CertType;
use jpki::ap::JpkiAp;
use jpki::{nfc, Card, ClientForAuth};

const NULL: jobject = 0 as jobject;

static mut LAST_ERROR: Option<String> = None;

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("APDU Error: {0}")]
    Apdu(#[from] nfc::Error),

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

impl nfc::Handler<JniContext<'_>> for JniNfcCard {
    fn handle(&self, ctx: JniContext, command: nfc::Command) -> nfc::Response {
        let mut bytes = Vec::from(command);
        let buffer = ctx.env.new_direct_byte_buffer(&mut bytes).unwrap();
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

        if let JValue::Object(obj) = val {
            let buffer = JByteBuffer::from(obj);
            match ctx.env.get_direct_buffer_address(buffer) {
                Ok(bytes) => {
                    info!("APDU Response Received: {:?}", bytes);

                    bytes.to_vec().into()
                }
                Err(e) => {
                    error!("getDirectBufferAddress Error: {:?}", e);

                    nfc::Response::new()
                }
            }
        } else {
            panic!("failed");
        }
    }
}

impl nfc::Card<JniContext<'_>> for JniNfcCard {}

impl<'a> JniNfcCard {
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
        Some(message) => env.new_string(message).unwrap().into_inner(),
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
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_newJpkiAp(
    env: JNIEnv,
    _class: JClass,
    delegate: jlong,
) -> jlong {
    wrap!(jlong, {
        let ctx = JniContext { env };
        let card = Rc::from_raw(delegate as *mut Card<JniNfcCard, JniContext>);
        let ap = JpkiAp::open(ctx, card)?;

        Ok(Box::into_raw(Box::new(ap)) as jlong)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApReadCertificateSign(
    env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
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

        let ap = &mut *(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
        let mut certificate = ap.read_certificate(ctx, ty, pin).map_err(Error::Apdu)?;
        let buffer = env
            .new_direct_byte_buffer(&mut certificate)
            .map_err(Error::Jni)?;

        Ok(buffer.into_inner())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApReadCertificateAuth(
    env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
    ca: jboolean,
) -> jobject {
    wrap!(jobject, {
        let ctx = JniContext { env };
        let pin = vec![];
        let ty = match ca {
            JNI_TRUE => CertType::AuthCA,
            _ => CertType::Auth,
        };

        let ap = &mut *(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
        let mut certificate = ap.read_certificate(ctx, ty, pin).map_err(Error::Apdu)?;
        let buffer = env
            .new_direct_byte_buffer(&mut certificate)
            .map_err(Error::Jni)?;

        Ok(buffer.into_inner())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApAuth(
    env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
    pin: jstring,
    digest: jbyteArray,
) -> jobject {
    wrap!(jobject, {
        let ctx = JniContext { env };
        let pin = jstring_to_bytes_vec(env, pin)?;
        let digest = env.convert_byte_array(digest).map_err(Error::Jni)?;

        let ap = &mut *(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
        let mut signature = ap.auth(ctx, pin, digest).map_err(Error::Apdu)?;
        let buffer = env
            .new_direct_byte_buffer(&mut signature)
            .map_err(Error::Jni)?;

        Ok(buffer.into_inner())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApClose(
    _env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
) {
    let _ = Box::from_raw(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_newClientForAuth(
    env: JNIEnv,
    _class: JClass,
    delegate: jlong,
) -> jlong {
    wrap!(jlong, {
        let ctx = JniContext { env };
        let card = Box::from_raw(delegate as *mut JniNfcCard);
        let client = ClientForAuth::create(ctx, card).map_err(Error::Apdu)?;

        Ok(Box::into_raw(Box::new(client)) as jlong)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_clientForAuthSign(
    env: JNIEnv,
    _class: JClass,
    client: jlong,
    pin: jstring,
    message: jbyteArray,
) -> jobject {
    wrap!(jobject, {
        let ctx = JniContext { env };
        let pin = jstring_to_bytes_vec(env, pin)?;
        let message = env.convert_byte_array(message).map_err(Error::Jni)?;

        let client = &mut *(client as *mut ClientForAuth<JniNfcCard, JniContext>);
        let mut signature = client.sign(ctx, pin, message).map_err(Error::Apdu)?;
        let buffer = env
            .new_direct_byte_buffer(&mut signature)
            .map_err(Error::Jni)?;

        Ok(buffer.into_inner())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_clientForAuthVerify(
    env: JNIEnv,
    _class: JClass,
    client: jlong,
    message: jbyteArray,
    signature: jbyteArray,
) -> jboolean {
    wrap!(jboolean, {
        let ctx = JniContext { env };
        let message = env.convert_byte_array(message).map_err(Error::Jni)?;
        let signature = env.convert_byte_array(signature).map_err(Error::Jni)?;

        let client = &mut *(client as *mut ClientForAuth<JniNfcCard, JniContext>);
        let result = client
            .verify(ctx, message, signature)
            .map_err(Error::Apdu)?;

        Ok(result.into())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_clientForAuthClose(
    _env: JNIEnv,
    _class: JClass,
    client: jlong,
) {
    let _ = Box::from_raw(client as *mut ClientForAuth<JniNfcCard, JniContext>);
}

fn jstring_to_bytes_vec(env: JNIEnv, str: jstring) -> Result<Vec<u8>, Error> {
    Ok(env
        .get_string(JString::from(str))
        .map_err(Error::Jni)?
        .to_bytes()
        .to_vec())
}
