#include <cstdio>
#include <cstring>
#include "jpki.h"

void print_byte_array(ByteArray bytes) {
    for (int i = 0; i < bytes.len; i++) {
        printf("%02x ", bytes.ptr[i]);
    }
}

bool expect(const uint8_t* expected, ByteArray actual) {
    return std::memcmp(expected, actual.ptr, actual.len) == 0;
}

ByteArray byte_array(const uint8_t* src, const size_t len) {
    auto* ptr = static_cast<uint8_t *>(malloc(len));
    std::memcpy(ptr, src, len);

    return ByteArray{
        ptr,
        len,
        len,
    };
}

ByteArray ok() {
    const uint8_t response[] = {0x90, 0x00};
    return byte_array(response, sizeof(response));
}

ByteArray emulate(ByteArray tx) {
    {
        // Opens the AP in the card by selecting the DF.
        const uint8_t expected[] = {0x00, 0xa4, 0x04, 0x0c, 0x0a, 0xd3, 0x92, 0xf0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00,
                                    0x01};
        if (expect(expected, tx)) {
            return ok();
        }
    }

    {
        // Selects an EF that contains a certificate for user authentication.
        const uint8_t expected[] = {0x00, 0xa4, 0x02, 0x0c, 0x02, 0x00, 0x0b};
        if (expect(expected, tx)) {
            return ok();
        }
    }

    {
        // Reads only 7 bytes from head to determine length of entire certificate.
        const uint8_t expected[] = {0x00, 0xb0, 0x00, 0x00, 0x07};
        if (expect(expected, tx)) {
            const uint8_t response[] = {0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00};
            return byte_array(response, sizeof(response));
        }
    }

    {
        // Reads entire certificate.
        const uint8_t expected[] = {0x00, 0xb0, 0x00, 0x00, 0x0a};
        if (expect(expected, tx)) {
            const uint8_t response[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x90, 0x00};
            return byte_array(response, sizeof(response));
        }
    }

    {
        // Selects a EF of PIN verification for signing.
        const uint8_t expected[] = {0x00, 0xa4, 0x02, 0x0c, 0x02, 0x00, 0x1b};
        if (expect(expected, tx)) {
            return ok();
        }
    }

    {
        // Verifies a PIN for signing (AbCdEfG).
        const uint8_t expected[] = {0x00, 0x20, 0x00, 0x80, 0x07, 0x41, 0x62, 0x43, 0x64, 0x45, 0x66, 0x47};
        if (expect(expected, tx)) {
            return ok();
        }
    }

    {
        // Selects a EF of the key-pair for signing.
        const uint8_t expected[] = {0x00, 0xa4, 0x02, 0x0c, 0x02, 0x00, 0x1a};
        if (expect(expected, tx)) {
            return ok();
        }
    }

    {
        // Computes a signature of the digest.
        const uint8_t expected[] = {0x80, 0x2a, 0x00, 0x80, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00};
        if (expect(expected, tx)) {
            const uint8_t response[] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x90, 0x00};
            return byte_array(response, sizeof(response));
        }
    }

    return tx;
}

ByteArray transmit(ByteArray tx) {
    printf("TX: ");
    print_byte_array(tx);
    putchar('\n');

    auto rx = emulate(tx);

    printf("RX: ");
    print_byte_array(rx);
    putchar('\n');

    return rx;
}

bool is_ok() {
    auto err = jpki_last_error();
    if (err == nullptr) {
        return true;
    }

    printf("ERROR: %s\n", err);

    return false;
}

int main() {
    jpki_init();

    auto nfc_card = jpki_new_nfc_card(transmit);
    auto card = jpki_new_card(nfc_card);
    auto jpki_ap = jpki_new_jpki_ap(card);
    if (!is_ok()) {
        return 1;
    }

    auto certificate = jpki_jpki_ap_read_certificate_auth(jpki_ap, true);
    if (!is_ok()) {
        return 1;
    }

    printf("CERTIFICATE: ");
    print_byte_array(certificate);
    putchar('\n');

    free(certificate.ptr);

    const char* pin = "AbCdEfG";
    const uint8_t digest[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    auto signature = jpki_jpki_ap_sign(jpki_ap, pin, byte_array(digest, sizeof(digest)));
    if (!is_ok()) {
        return 1;
    }

    printf("SIGNATURE: ");
    print_byte_array(signature);
    putchar('\n');

    free(signature.ptr);

    jpki_jpki_ap_close(jpki_ap);
    jpki_card_close(card);
    jpki_nfc_card_close(nfc_card);
}
