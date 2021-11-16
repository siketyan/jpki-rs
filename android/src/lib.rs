#[macro_use]
extern crate log;
extern crate android_log;

use jni::objects::{GlobalRef, JByteBuffer, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jlong, jobject, jstring, JNI_TRUE};
use jni::JNIEnv;

use jpki::ap::jpki::CertType;
use jpki::ap::JpkiAp;
use jpki::{nfc, Card, ClientForAuth};

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
pub extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_init() {
    android_log::init("JPKI.FFI").unwrap();
}

#[no_mangle]
pub extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_newNfcCard(
    env: JNIEnv,
    _class: JClass,
    delegate: JObject,
) -> jlong {
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
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApReadCertificateSign(
    env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
    pin: jstring,
    ca: jboolean,
) -> jobject {
    let ctx = JniContext { env };
    let pin = env
        .get_string(JString::from(pin))
        .unwrap()
        .to_bytes()
        .to_vec();

    let ty = match ca {
        JNI_TRUE => CertType::SignCA,
        _ => CertType::Sign,
    };

    let ap = &mut *(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
    let mut certificate = ap.read_certificate(ctx, ty, pin).unwrap();
    let buffer = env.new_direct_byte_buffer(&mut certificate).unwrap();

    buffer.into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApReadCertificateAuth(
    env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
    ca: jboolean,
) -> jobject {
    let ctx = JniContext { env };
    let pin = vec![];
    let ty = match ca {
        JNI_TRUE => CertType::AuthCA,
        _ => CertType::Auth,
    };

    let ap = &mut *(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
    let mut certificate = ap.read_certificate(ctx, ty, pin).unwrap();
    let buffer = env.new_direct_byte_buffer(&mut certificate).unwrap();

    buffer.into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApAuth(
    env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
    pin: jstring,
    digest: jbyteArray,
) -> jobject {
    let ctx = JniContext { env };
    let pin = jstring_to_bytes_vec(env, pin);
    let digest = env.convert_byte_array(digest).unwrap();
    let digest_info = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next()
                    .write_oid(&yasna::models::ObjectIdentifier::from_slice(&[
                        1, 3, 14, 3, 2, 26,
                    ]));
                w.next().write_null();
            });
            w.next().write_bytes(&digest);
        });
    });

    let ap = &mut *(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
    let mut signature = ap.auth(ctx, pin, digest_info).unwrap();
    let buffer = env.new_direct_byte_buffer(&mut signature).unwrap();

    buffer.into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_jpkiApClose(
    _env: JNIEnv,
    _class: JClass,
    jpki_ap: jlong,
) {
    let _ = Box::from_raw(jpki_ap as *mut JpkiAp<JniNfcCard, JniContext>);
}

fn jstring_to_bytes_vec(env: JNIEnv, str: jstring) -> Vec<u8> {
    env.get_string(JString::from(str))
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_newClientForAuth(
    env: JNIEnv,
    _class: JClass,
    delegate: jlong,
) -> jlong {
    let ctx = JniContext { env };
    let card = Box::from_raw(delegate as *mut JniNfcCard);
    let client = ClientForAuth::create(ctx, card).unwrap();

    Box::into_raw(Box::new(client)) as jlong
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_clientForAuthSign(
    env: JNIEnv,
    _class: JClass,
    client: jlong,
    pin: jstring,
    message: jbyteArray,
) -> jobject {
    let ctx = JniContext { env };
    let pin = jstring_to_bytes_vec(env, pin);
    let message = env.convert_byte_array(message).unwrap();

    let client = &mut *(client as *mut ClientForAuth<JniNfcCard, JniContext>);
    let mut signature = client.sign(ctx, pin, message).unwrap();
    let buffer = env.new_direct_byte_buffer(&mut signature).unwrap();

    buffer.into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_clientForAuthVerify(
    env: JNIEnv,
    _class: JClass,
    client: jlong,
    message: jbyteArray,
    signature: jbyteArray,
) -> jboolean {
    let ctx = JniContext { env };
    let message = env.convert_byte_array(message).unwrap();
    let signature = env.convert_byte_array(signature).unwrap();

    let client = &mut *(client as *mut ClientForAuth<JniNfcCard, JniContext>);
    let result = client.verify(ctx, message, signature).unwrap();

    result.into()
}

#[no_mangle]
pub unsafe extern "C" fn Java_jp_s6n_jpki_app_ffi_LibJpki_clientForAuthClose(
    _env: JNIEnv,
    _class: JClass,
    client: jlong,
) {
    let _ = Box::from_raw(client as *mut ClientForAuth<JniNfcCard, JniContext>);
}
