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

ByteArray emulate(ByteArray tx) {
    // Opens the AP in the card by selecting the DF.
    const uint8_t expected[] = {0x00, 0xa4, 0x04, 0x0c, 0x0a, 0xd3, 0x92, 0xf0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01};
    if (expect(expected, tx)) {
        const uint8_t response[] = {0x90, 0x00};
        return byte_array(response, sizeof(response));
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

int main() {
    jpki_init();

    auto nfc_card = jpki_new_nfc_card(transmit);
    auto card = jpki_new_card(nfc_card);
    auto jpki_ap = jpki_new_jpki_ap(card);

    printf("%p\n", jpki_ap);
}
