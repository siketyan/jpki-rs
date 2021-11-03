#[macro_use]
extern crate log;
extern crate android_log;

use jni::objects::{GlobalRef, JByteBuffer, JClass, JObject, JString, JValue};
use jni::sys::{jlong, jobject, jstring};
use jni::JNIEnv;

use jpki::ap::jpki::CertType;
use jpki::ap::JpkiAp;
use jpki::{nfc, Card};

struct JniNfcCard {
    delegate: GlobalRef,
}

#[derive(Copy, Clone)]
struct JniContext<'a> {
    env: JNIEnv<'a>,
}

impl nfc::apdu::Handler<JniContext<'_>> for JniNfcCard {
    fn handle(&self, ctx: JniContext, command: nfc::apdu::Command) -> nfc::apdu::Response {
        let mut bytes = command.into_bytes();
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

                    nfc::apdu::Response::from_bytes(bytes.to_vec())
                }
                Err(e) => {
                    error!("getDirectBufferAddress Error: {:?}", e);

                    nfc::apdu::Response::new()
                }
            }
        } else {
            panic!("failed");
        }
    }
}

impl jpki::nfc::Card<JniContext<'_>> for JniNfcCard {}

impl<'a> JniNfcCard {
    pub fn new(delegate: GlobalRef) -> Self {
        Self { delegate }
    }
}

#[no_mangle]
pub extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_newNfcCard(
    env: JNIEnv,
    _class: JClass,
    delegate: JObject,
) -> jlong {
    android_log::init("JPKI.FFI1").unwrap();

    let global_ref = env.new_global_ref(delegate).unwrap();
    let card = JniNfcCard::new(global_ref);

    Box::into_raw(Box::new(card)) as jlong
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
    let ctx = JniContext { env };
    let card = Box::from_raw(delegate as *mut Card<JniNfcCard, JniContext>);
    let ap = JpkiAp::open(ctx, card).unwrap();

    Box::into_raw(Box::new(ap)) as jlong
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApReadCertificate(
    env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
    pin: jstring,
) -> jobject {
    let ctx = JniContext { env };
    let pin = env
        .get_string(JString::from(pin))
        .unwrap()
        .to_bytes()
        .to_vec();

    let ap = &mut *(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
    let mut certificate = ap.read_certificate(ctx, CertType::Sign, pin).unwrap();
    let buffer = env.new_direct_byte_buffer(&mut certificate).unwrap();

    buffer.into_inner()
}
