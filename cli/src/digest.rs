pub fn calculate(message: Vec<u8>) -> Vec<u8> {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &message);
    let oid = yasna::models::ObjectIdentifier::from_slice(&[1, 3, 14, 3, 2, 26]);

    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid);
                w.next().write_null();
            });
            w.next().write_bytes(digest.as_ref());
        });
    })
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
