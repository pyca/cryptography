// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this
// repository for complete details.

/* Returns the value of the input with the most-significant-bit copied to all
   of the bits. */
static uint16_t Cryptography_DUPLICATE_MSB_TO_ALL(uint16_t a) {
    return (1 - (a >> (sizeof(uint16_t) * 8 - 1))) - 1;
}

/* This returns 0xFFFF if a < b else 0x0000, but does so in a constant time
   fashion */
static uint16_t Cryptography_constant_time_lt(uint16_t a, uint16_t b) {
    a -= b;
    return Cryptography_DUPLICATE_MSB_TO_ALL(a);
}

uint8_t Cryptography_check_pkcs7_padding(const uint8_t *data,
                                         uint16_t block_len) {
    uint16_t i;
    uint16_t pad_size = data[block_len - 1];
    uint16_t mismatch = 0;
    for (i = 0; i < block_len; i++) {
        unsigned int mask = Cryptography_constant_time_lt(i, pad_size);
        uint16_t b = data[block_len - 1 - i];
        mismatch |= (mask & (pad_size ^ b));
    }

    /* Check to make sure the pad_size was within the valid range. */
    mismatch |= ~Cryptography_constant_time_lt(0, pad_size);
    mismatch |= Cryptography_constant_time_lt(block_len, pad_size);

    /* Make sure any bits set are copied to the lowest bit */
    mismatch |= mismatch >> 8;
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;
    /* Now check the low bit to see if it's set */
    return (mismatch & 1) == 0;
}

uint8_t Cryptography_check_ansix923_padding(const uint8_t *data,
                                            uint16_t block_len) {
    uint16_t i;
    uint16_t pad_size = data[block_len - 1];
    uint16_t mismatch = 0;
    /* Skip the first one with the pad size */
    for (i = 1; i < block_len; i++) {
        unsigned int mask = Cryptography_constant_time_lt(i, pad_size);
        uint16_t b = data[block_len - 1 - i];
        mismatch |= (mask & b);
    }

    /* Check to make sure the pad_size was within the valid range. */
    mismatch |= ~Cryptography_constant_time_lt(0, pad_size);
    mismatch |= Cryptography_constant_time_lt(block_len, pad_size);

    /* Make sure any bits set are copied to the lowest bit */
    mismatch |= mismatch >> 8;
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;
    /* Now check the low bit to see if it's set */
    return (mismatch & 1) == 0;
}
