use der::asn1::{Null, ObjectIdentifier, OctetStringRef};
use der::{Encode, Sequence};

#[derive(Sequence)]
struct SignatureMeta {
    oid: ObjectIdentifier,
    null: Null,
}

#[derive(Sequence)]
struct Signature<'a> {
    meta: SignatureMeta,
    bytes: OctetStringRef<'a>,
}

pub fn calculate(message: Vec<u8>) -> Vec<u8> {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &message);
    let signature = Signature {
        meta: SignatureMeta {
            oid: "1.3.14.3.2.26".parse::<ObjectIdentifier>().unwrap(),
            null: Null,
        },
        bytes: OctetStringRef::new(digest.as_ref()).unwrap(),
    };

    let mut vec = Vec::new();
    signature.encode_to_vec(&mut vec).unwrap();
    vec
}

pub fn verify(certificate: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let x509 = x509_certificate::X509Certificate::from_der(certificate).unwrap();
    let public_key = x509.public_key_data();
    let public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        public_key,
    );

    public_key.verify(&message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate() {
        /*
           SEQUENCE
             SEQUENCE
               ObjectIdentifier sha1 (1 3 14 3 2 26)
               NULL
             OCTETSTRING f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0
        */
        assert_eq!(
            [
                48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, 247, 255, 158, 139, 123, 178,
                224, 155, 112, 147, 90, 93, 120, 94, 12, 197, 217, 208, 171, 240,
            ]
            .to_vec(),
            calculate(b"Hello".to_vec()),
        );
    }
}
