#ifndef LIBJPKI_H
#define LIBJPKI_H

struct JpkiByteArrayRef {
    unsigned int len;
    unsigned char* ptr;
};

struct JpkiFfiResult {
    void* ptr;
    unsigned char* ptr_err;
};

struct JpkiNfcCard;
struct JpkiCard;
struct JpkiApJpki;

JpkiNfcCard* jpki_nfc_card_new(JpkiByteArrayRef (*delegate)(JpkiByteArrayRef));
JpkiCard* jpki_card_new(JpkiNfcCard* nfc_card);
JpkiFfiResult jpki_ap_jpki_open(JpkiCard* card);

#endif /* LIBJPKI_H */
