//==================================================================================================
/// @file       crypto_speck.c
/// @author     modulomedito (chcchc1995@outlook.com)
/// @brief
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// INCLUDE
//==================================================================================================
#include "crypto_speck.h"
#include "rustlike_types.h"

//==================================================================================================
// IMPORTED SWITCH CHECK
//==================================================================================================

//==================================================================================================
// PRIVATE DEFINE
//==================================================================================================
// 32-bit right and left rotation (ensures safe unsigned shifts per MISRA C)
#define CRYPTO_SPECK_ROTR32(x, r) (((x) >> (r)) | ((x) << (32U - (r))))
#define CRYPTO_SPECK_ROTL32(x, r) (((x) << (r)) | ((x) >> (32U - (r))))

#define CRYPTO_SPECK_SPECK64_KEY_U8_NUM (16U)

//==================================================================================================
// PRIVATE TYPEDEF
//==================================================================================================

//==================================================================================================
// PRIVATE ENUM
//==================================================================================================

//==================================================================================================
// PRIVATE STRUCT
//==================================================================================================

//==================================================================================================
// PRIVATE UNION
//==================================================================================================

//==================================================================================================
// PRIVATE FUNCTION DECLARATION
//==================================================================================================
static crypto_speck_Ret crypto_speck_Speck64_deinit(crypto_speck_Speck64 *self);
static crypto_speck_Ret crypto_speck_speck64_expand_key(
    Slice_u32 round_keys,
    Slice_cu8 speck64_key
);
static crypto_speck_Ret crypto_speck_speck64_encrypt_block(
    crypto_speck_Speck64 *self,
    Slice_u8 cipher,
    Slice_cu8 plain
);
static crypto_speck_Ret crypto_speck_speck64_decrypt_block(
    crypto_speck_Speck64 *self,
    Slice_u8 plain,
    Slice_cu8 cipher
);
static u32 crypto_speck_load_u32_le(const volatile u8 *src);
static void crypto_speck_store_u32_le(volatile u8 *dst, u32 value);

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
/// @brief Encrypt input bytes with SPECK-64/128 using a temporary context
crypto_speck_Ret crypto_speck_speck64_encrypt(
    Slice_u8 output,
    Slice_cu8 input,
    Slice_cu8 speck64_key
) {
    crypto_speck_Speck64 self;

    crypto_speck_Ret ret =
        crypto_speck_Speck64_init(&self, crypto_speck_Mode_Encrypt, output, speck64_key);
    if (ret != crypto_speck_Ret_Ok) {
        return ret;
    }

    ret = crypto_speck_Speck64_update(&self, input);
    if (ret != crypto_speck_Ret_Ok) {
        (void)crypto_speck_Speck64_deinit(&self);
        return ret;
    }

    return crypto_speck_Speck64_finalize(&self);
}

/// @brief Decrypt input bytes with SPECK-64/128 using a temporary context
crypto_speck_Ret crypto_speck_speck64_decrypt(
    Slice_u8 output,
    Slice_cu8 input,
    Slice_cu8 speck64_key
) {
    crypto_speck_Speck64 self;

    crypto_speck_Ret ret =
        crypto_speck_Speck64_init(&self, crypto_speck_Mode_Decrypt, output, speck64_key);
    if (ret != crypto_speck_Ret_Ok) {
        return ret;
    }

    ret = crypto_speck_Speck64_update(&self, input);
    if (ret != crypto_speck_Ret_Ok) {
        (void)crypto_speck_Speck64_deinit(&self);
        return ret;
    }

    return crypto_speck_Speck64_finalize(&self);
}

/// @brief Initialize SPECK-64/128 context with a 128-bit key
/// @param self Pointer to the Speck64 context to initialize
/// @param speck64_key 128-bit key slice (must contain at least 16 bytes)
/// @return crypto_speck_Ret_Ok on success, crypto_speck_Ret_InvalidArg if arguments are invalid
crypto_speck_Ret crypto_speck_Speck64_init(
    crypto_speck_Speck64 *self,
    crypto_speck_Mode mode,
    Slice_u8 output,
    Slice_cu8 speck64_key
) {
    if ((self == NULL) || //
        ((output.ptr == NULL) && (output.len > 0U)) || //
        (speck64_key.ptr == NULL) || //
        (speck64_key.len < CRYPTO_SPECK_SPECK64_KEY_U8_NUM) || //
        (mode >= crypto_speck_Mode_Invalid)) {
        return crypto_speck_Ret_InvalidArg;
    }

    self->mode = mode;
    self->data = output;
    self->output_len = 0U;
    self->residue_len = 0U;
    for (u32 i = 0U; i < (CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U); i++) {
        self->residue_buf[i] = 0U;
    }

    crypto_speck_Ret ret = crypto_speck_speck64_expand_key(
        (Slice_u32){.ptr = self->round_key_buf, .len = CRYPTO_SPECK_SPECK64_ROUNDS},
        speck64_key
    );

    return ret;
}

/// @brief Buffer byte input for SPECK-64/128 processing
/// @param data Input bytes to append to the internal buffer
crypto_speck_Ret crypto_speck_Speck64_update(crypto_speck_Speck64 *self, Slice_cu8 data) {
    if ((self == NULL) || //
        (self->mode >= crypto_speck_Mode_Invalid) || //
        ((data.ptr == NULL) && (data.len > 0U))) {
        return crypto_speck_Ret_InvalidArg;
    }

    if (data.len == 0U) {
        return crypto_speck_Ret_Ok;
    }

    if (self->mode == crypto_speck_Mode_Encrypt) {
        for (u32 i = 0U; i < data.len; i++) {
            self->residue_buf[self->residue_len] = data.ptr[i];
            self->residue_len++;

            if (self->residue_len == CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM) {
                if ((self->data.len - self->output_len) < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM) {
                    return crypto_speck_Ret_BufferTooSmall;
                }

                crypto_speck_Ret ret = crypto_speck_speck64_encrypt_block(
                    self,
                    (Slice_u8){.ptr = &self->data.ptr[self->output_len],
                               .len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM},
                    (Slice_cu8){.ptr = self->residue_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM}
                );
                if (ret != crypto_speck_Ret_Ok) {
                    return ret;
                }

                self->output_len += CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM;
                self->residue_len = 0U;
            }
        }
    } else {
        for (u32 i = 0U; i < data.len; i++) {
            if (self->residue_len >= (CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U)) {
                return crypto_speck_Ret_Error;
            }

            self->residue_buf[self->residue_len] = data.ptr[i];
            self->residue_len++;

            if (self->residue_len == (CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U)) {
                if ((self->data.len - self->output_len) < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM) {
                    return crypto_speck_Ret_BufferTooSmall;
                }

                crypto_speck_Ret ret = crypto_speck_speck64_decrypt_block(
                    self,
                    (Slice_u8){.ptr = &self->data.ptr[self->output_len],
                               .len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM},
                    (Slice_cu8){.ptr = self->residue_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM}
                );
                if (ret != crypto_speck_Ret_Ok) {
                    return ret;
                }

                self->output_len += CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM;
                for (u32 j = 0U; j < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM; j++) {
                    self->residue_buf[j] = self->residue_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM + j];
                    self->residue_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM + j] = 0U;
                }
                self->residue_len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM;
            }
        }
    }

    return crypto_speck_Ret_Ok;
}

/// @brief Finalize SPECK-64/128 processing and clean the context
crypto_speck_Ret crypto_speck_Speck64_finalize(crypto_speck_Speck64 *self) {
    if ((self == NULL) || //
        (self->mode >= crypto_speck_Mode_Invalid)) {
        return crypto_speck_Ret_InvalidArg;
    }

    crypto_speck_Ret ret = crypto_speck_Ret_Ok;

    if (self->mode == crypto_speck_Mode_Encrypt) {
        const u32 pad_len = (self->residue_len == 0U)
                                ? CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM
                                : (CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM - self->residue_len);
        u8 plain_block[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM];

        if ((self->data.len - self->output_len) < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM) {
            ret = crypto_speck_Ret_BufferTooSmall;
        } else {
            for (u32 i = 0U; i < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM; i++) {
                if (i < self->residue_len) {
                    plain_block[i] = self->residue_buf[i];
                } else {
                    plain_block[i] = (u8)pad_len;
                }
            }

            ret = crypto_speck_speck64_encrypt_block(
                self,
                (Slice_u8){.ptr = &self->data.ptr[self->output_len],
                           .len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM},
                (Slice_cu8){.ptr = plain_block, .len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM}
            );
            if (ret == crypto_speck_Ret_Ok) {
                self->output_len += CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM;
            }
        }
    } else {
        if (self->residue_len != CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM) {
            ret = crypto_speck_Ret_Error;
        } else {
            u8 plain_block[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM];
            const u8 *block_tail = &plain_block[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM - 1U];

            ret = crypto_speck_speck64_decrypt_block(
                self,
                (Slice_u8){.ptr = plain_block, .len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM},
                (Slice_cu8){.ptr = self->residue_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM}
            );
            if (ret == crypto_speck_Ret_Ok) {
                const u8 pad_len = *block_tail;
                u32 final_plain_len = 0U;

                if ((pad_len == 0U) || //
                    (pad_len > CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM)) {
                    ret = crypto_speck_Ret_Error;
                }

                for (u32 i = 0U; (ret == crypto_speck_Ret_Ok) && (i < pad_len); i++) {
                    if (plain_block[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM - 1U - i] != pad_len) {
                        ret = crypto_speck_Ret_Error;
                    }
                }

                if (ret == crypto_speck_Ret_Ok) {
                    final_plain_len = CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM - pad_len;
                    if ((self->data.len - self->output_len) < final_plain_len) {
                        ret = crypto_speck_Ret_BufferTooSmall;
                    } else {
                        for (u32 i = 0U; i < final_plain_len; i++) {
                            self->data.ptr[self->output_len + i] = plain_block[i];
                        }
                        self->output_len += final_plain_len;
                    }
                }
            }
        }
    }

    {
        const crypto_speck_Ret deinit_ret = crypto_speck_Speck64_deinit(self);
        if (ret == crypto_speck_Ret_Ok) {
            ret = deinit_ret;
        }
    }

    return ret;
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
/// @brief De-initialize SPECK-64/128 context
static crypto_speck_Ret crypto_speck_Speck64_deinit(crypto_speck_Speck64 *self) {
    if (self == NULL) {
        return crypto_speck_Ret_InvalidArg;
    }

    for (u32 i = 0U; i < (CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U); i++) {
        self->residue_buf[i] = 0U;
    }

    self->data.ptr = NULL;
    self->data.len = 0U;
    self->output_len = 0U;
    self->residue_len = 0U;

    for (u32 i = 0U; i < CRYPTO_SPECK_SPECK64_ROUNDS; i++) {
        self->round_key_buf[i] = 0U;
    }

    self->mode = crypto_speck_Mode_Invalid;

    return crypto_speck_Ret_Ok;
}

/// @brief SPECK-64/128 key expansion
/// @param const_keys Input: 128-bit original key (array of 4 32-bit elements)
/// @param round_keys Output: 27 32-bit round keys
static crypto_speck_Ret crypto_speck_speck64_expand_key(
    Slice_u32 round_keys,
    Slice_cu8 speck64_key
) {
    if ((round_keys.ptr == NULL) || //
        (round_keys.len < CRYPTO_SPECK_SPECK64_ROUNDS) || //
        (speck64_key.ptr == NULL) || //
        (speck64_key.len < CRYPTO_SPECK_SPECK64_KEY_U8_NUM)) {
        return crypto_speck_Ret_InvalidArg;
    }

    u32 a = crypto_speck_load_u32_le(&speck64_key.ptr[0]);
    u32 b = crypto_speck_load_u32_le(&speck64_key.ptr[4]);
    u32 c = crypto_speck_load_u32_le(&speck64_key.ptr[8]);
    u32 d = crypto_speck_load_u32_le(&speck64_key.ptr[12]);

    for (u32 i = 0U; i < CRYPTO_SPECK_SPECK64_ROUNDS;) {
        round_keys.ptr[i] = a;
        b = (CRYPTO_SPECK_ROTR32(b, 8U) + a) ^ i;
        a = CRYPTO_SPECK_ROTL32(a, 3U) ^ b;
        i++;
        round_keys.ptr[i] = a;
        c = (CRYPTO_SPECK_ROTR32(c, 8U) + a) ^ i;
        a = CRYPTO_SPECK_ROTL32(a, 3U) ^ c;
        i++;
        round_keys.ptr[i] = a;
        d = (CRYPTO_SPECK_ROTR32(d, 8U) + a) ^ i;
        a = CRYPTO_SPECK_ROTL32(a, 3U) ^ d;
        i++;
    }

    return crypto_speck_Ret_Ok;
}

static crypto_speck_Ret crypto_speck_speck64_encrypt_block(
    crypto_speck_Speck64 *self,
    Slice_u8 cipher,
    Slice_cu8 plain
) {
    if ((self == NULL) || //
        (cipher.ptr == NULL) || //
        (cipher.len < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM) || //
        (plain.ptr == NULL) || //
        (plain.len < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM)) {
        return crypto_speck_Ret_InvalidArg;
    }

    u32 x = crypto_speck_load_u32_le(&plain.ptr[4]);
    u32 y = crypto_speck_load_u32_le(&plain.ptr[0]);

    for (u32 i = 0U; i < CRYPTO_SPECK_SPECK64_ROUNDS; i++) {
        x = (CRYPTO_SPECK_ROTR32(x, 8U) + y) ^ (self->round_key_buf[i]);
        y = CRYPTO_SPECK_ROTL32(y, 3U) ^ x;
    }

    crypto_speck_store_u32_le(&cipher.ptr[0], y);
    crypto_speck_store_u32_le(&cipher.ptr[4], x);

    return crypto_speck_Ret_Ok;
}

static crypto_speck_Ret crypto_speck_speck64_decrypt_block(
    crypto_speck_Speck64 *self,
    Slice_u8 plain,
    Slice_cu8 cipher
) {
    if ((self == NULL) || //
        (cipher.ptr == NULL) || //
        (cipher.len < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM) || //
        (plain.ptr == NULL) || //
        (plain.len < CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM)) {
        return crypto_speck_Ret_InvalidArg;
    }

    u32 x = crypto_speck_load_u32_le(&cipher.ptr[4]);
    u32 y = crypto_speck_load_u32_le(&cipher.ptr[0]);

    // Decrypt in reverse round order
    for (i32 i = (i32)(CRYPTO_SPECK_SPECK64_ROUNDS - 1U); i >= 0; i--) {
        y = CRYPTO_SPECK_ROTR32(y ^ x, 3U);
        x = CRYPTO_SPECK_ROTL32((x ^ self->round_key_buf[i]) - y, 8U);
    }

    crypto_speck_store_u32_le(&plain.ptr[0], y);
    crypto_speck_store_u32_le(&plain.ptr[4], x);

    return crypto_speck_Ret_Ok;
}
static u32 crypto_speck_load_u32_le(const volatile u8 *src) {
    return ((u32)src[0]) | //
           (((u32)src[1]) << 8U) | //
           (((u32)src[2]) << 16U) | //
           (((u32)src[3]) << 24U);
}

static void crypto_speck_store_u32_le(volatile u8 *dst, u32 value) {
    dst[0] = (u8)(value & 0xffU);
    dst[1] = (u8)((value >> 8U) & 0xffU);
    dst[2] = (u8)((value >> 16U) & 0xffU);
    dst[3] = (u8)((value >> 24U) & 0xffU);
}

//==================================================================================================
// TEST
//==================================================================================================
#define CRYPTO_SPECK_DEBUG (0)

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
#include <stdio.h>
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

// Binary-safe memcmp for test assertions (not string, not flagged by MISRA string checkers)
static inline i32 crypto_speck_memcmp(const u8 *a_ref, const u8 *b_ref, u32 len) {
    for (u32 i = 0; i < len; i++) {
        if (a_ref[i] != b_ref[i]) {
            return (i32)(a_ref[i] - b_ref[i]);
        }
    }
    return 0;
}

// Official test vectors
static i32 crypto_speck_test_tc1(void) {
    // clang-format off
    u8 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U8_NUM] = {
        0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
        0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
    };
    u8 plain_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {
        0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b,
    };
    u8 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U] = {
        0x8b, 0x02, 0x4e, 0x45, 0x48, 0xa5, 0x6f, 0x8c,
        0x4e, 0xa3, 0xeb, 0x1b, 0x86, 0x66, 0x77, 0xc1,
    };
    // clang-format on
    u8 actual_buf[CRYPTO_SPECK_SPECK64_CIPHER_SIZE_FROM_PLAIN_SIZE(
        CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM
    )] = {0};

    crypto_speck_Ret ret = crypto_speck_speck64_encrypt(
        (Slice_u8){.ptr = actual_buf, .len = sizeof(actual_buf)},
        (Slice_cu8){.ptr = plain_buf, .len = sizeof(plain_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < sizeof(actual_buf); i++) {
        printf("[%d] = 0x%x\n", i, (u32)actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp(expected_buf, actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

// Official test vectors
static i32 crypto_speck_test_tc2(void) {
    // clang-format off
    u8 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U8_NUM] = {
        0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
        0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
    };
    u8 cipher_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U] = {
        0x8b, 0x02, 0x4e, 0x45, 0x48, 0xa5, 0x6f, 0x8c,
        0x4e, 0xa3, 0xeb, 0x1b, 0x86, 0x66, 0x77, 0xc1,
    };
    u8 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {
        0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b,
    };
    u8 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {0};
    // clang-format on

    crypto_speck_Ret ret = crypto_speck_speck64_decrypt(
        (Slice_u8){.ptr = actual_buf, .len = sizeof(actual_buf)},
        (Slice_cu8){.ptr = cipher_buf, .len = sizeof(cipher_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < sizeof(actual_buf); i++) {
        printf("[%d] = 0x%x\n", i, (u32)actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp(expected_buf, actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc3(void) {
    // clang-format off
    u8 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U8_NUM] = {
        0x64, 0xb7, 0x6f, 0xa6, 0x1c, 0xe9, 0x80, 0xab,
        0x2f, 0x71, 0x09, 0x8d, 0x75, 0xd6, 0x6e, 0x5f,
    };
    u8 plain_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {
        0x15, 0x89, 0xa8, 0xbb, 0xff, 0x4c, 0x7a, 0x85,
    };
    u8 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U] = {
        0x2f, 0x1d, 0x12, 0x23, 0x70, 0x94, 0x6b, 0xda,
        0xe1, 0xde, 0x41, 0x68, 0xf6, 0xd2, 0x88, 0xfa,
    };
    u8 actual_buf[CRYPTO_SPECK_SPECK64_CIPHER_SIZE_FROM_PLAIN_SIZE(
        CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM
    )] = {0};
    // clang-format on

    crypto_speck_Ret ret = crypto_speck_speck64_encrypt(
        (Slice_u8){.ptr = actual_buf, .len = sizeof(actual_buf)},
        (Slice_cu8){.ptr = plain_buf, .len = sizeof(plain_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < sizeof(actual_buf); i++) {
        printf("[%d] = 0x%x\n", i, (u32)actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp(expected_buf, actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc4(void) {
    // clang-format off
    u8 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U8_NUM] = {
        0x64, 0xb7, 0x6f, 0xa6, 0x1c, 0xe9, 0x80, 0xab,
        0x2f, 0x71, 0x09, 0x8d, 0x75, 0xd6, 0x6e, 0x5f,
    };
    u8 cipher_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U] = {
        0x2f, 0x1d, 0x12, 0x23, 0x70, 0x94, 0x6b, 0xda,
        0xe1, 0xde, 0x41, 0x68, 0xf6, 0xd2, 0x88, 0xfa,
    };
    u8 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {
        0x15, 0x89, 0xa8, 0xbb, 0xff, 0x4c, 0x7a, 0x85,
    };
    u8 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {0};
    // clang-format on

    crypto_speck_Ret ret = crypto_speck_speck64_decrypt(
        (Slice_u8){.ptr = actual_buf, .len = sizeof(actual_buf)},
        (Slice_cu8){.ptr = cipher_buf, .len = sizeof(cipher_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < sizeof(actual_buf); i++) {
        printf("[%d] = 0x%x\n", i, (u32)actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp(expected_buf, actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc5(void) {
    // clang-format off
    u8 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U8_NUM] = {
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44,
    };
    u8 plain_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {
        0xcc, 0xbb, 0xaa, 0x99, 0x00, 0xff, 0xee, 0xdd,
    };
    u8 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U] = {
        0x22, 0xed, 0x50, 0xc7, 0x7d, 0xa6, 0xab, 0x79,
        0x5d, 0x74, 0xbd, 0xf7, 0xc3, 0x22, 0xcb, 0x6f,
    };
    u8 actual_buf[CRYPTO_SPECK_SPECK64_CIPHER_SIZE_FROM_PLAIN_SIZE(
        CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM
    )] = {0};
    // clang-format on

    crypto_speck_Ret ret = crypto_speck_speck64_encrypt(
        (Slice_u8){.ptr = actual_buf, .len = sizeof(actual_buf)},
        (Slice_cu8){.ptr = plain_buf, .len = sizeof(plain_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < sizeof(actual_buf); i++) {
        printf("[%d] = 0x%x\n", i, (u32)actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp(expected_buf, actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc6(void) {
    // clang-format off
    u8 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U8_NUM] = {
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44,
    };
    u8 cipher_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U] = {
        0x22, 0xed, 0x50, 0xc7, 0x7d, 0xa6, 0xab, 0x79,
        0x5d, 0x74, 0xbd, 0xf7, 0xc3, 0x22, 0xcb, 0x6f,
    };
    u8 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {
        0xcc, 0xbb, 0xaa, 0x99, 0x00, 0xff, 0xee, 0xdd,
    };
    u8 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM] = {0};
    // clang-format on

    crypto_speck_Ret ret = crypto_speck_speck64_decrypt(
        (Slice_u8){.ptr = actual_buf, .len = sizeof(actual_buf)},
        (Slice_cu8){.ptr = cipher_buf, .len = sizeof(cipher_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < sizeof(actual_buf); i++) {
        printf("[%d] = 0x%x\n", i, (u32)actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp(expected_buf, actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc7(void) {
    // clang-format off
    u8 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U8_NUM] = {
        0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
        0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
    };
    u8 plain_buf[13] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0,
    };
    u8 cipher_buf[CRYPTO_SPECK_SPECK64_CIPHER_SIZE_FROM_PLAIN_SIZE(13U)] = {0};
    u8 actual_buf[13] = {0};
    // clang-format on

    crypto_speck_Ret ret;
    crypto_speck_Speck64 enc_obj;
    crypto_speck_Speck64 dec_obj;

    ret = crypto_speck_Speck64_init(
        &enc_obj,
        crypto_speck_Mode_Encrypt,
        (Slice_u8){.ptr = cipher_buf, .len = sizeof(cipher_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_update(&enc_obj, (Slice_cu8){.ptr = plain_buf, .len = 5U});
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_update(&enc_obj, (Slice_cu8){.ptr = &plain_buf[5], .len = 8U});
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_finalize(&enc_obj);
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_init(
        &dec_obj,
        crypto_speck_Mode_Decrypt,
        (Slice_u8){.ptr = actual_buf, .len = sizeof(actual_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_update(
        &dec_obj,
        (Slice_cu8){.ptr = cipher_buf, .len = sizeof(cipher_buf)}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_finalize(&dec_obj);
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    if (crypto_speck_memcmp(plain_buf, actual_buf, sizeof(plain_buf)) != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc8(void) {
    // clang-format off
    u8 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U8_NUM] = {
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44,
    };
    u8 plain_buf[9] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x55,
    };
    u8 cipher_buf[CRYPTO_SPECK_SPECK64_CIPHER_SIZE_FROM_PLAIN_SIZE(9U)] = {0};
    u8 actual_buf[9] = {0};
    // clang-format on

    crypto_speck_Ret ret = crypto_speck_speck64_encrypt(
        (Slice_u8){.ptr = cipher_buf, .len = sizeof(cipher_buf)},
        (Slice_cu8){.ptr = plain_buf, .len = sizeof(plain_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_speck64_decrypt(
        (Slice_u8){.ptr = actual_buf, .len = sizeof(actual_buf)},
        (Slice_cu8){.ptr = cipher_buf, .len = sizeof(cipher_buf)},
        (Slice_cu8){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U8_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    if (crypto_speck_memcmp(plain_buf, actual_buf, sizeof(plain_buf)) != 0) {
        return __LINE__;
    }

    return 0;
}

i32 crypto_speck_test(void) {
    i32 result;

    result = crypto_speck_test_tc1();
    if (result != 0) {
        return result;
    }

    result = crypto_speck_test_tc2();
    if (result != 0) {
        return result;
    }

    result = crypto_speck_test_tc3();
    if (result != 0) {
        return result;
    }

    result = crypto_speck_test_tc4();
    if (result != 0) {
        return result;
    }

    result = crypto_speck_test_tc5();
    if (result != 0) {
        return result;
    }

    result = crypto_speck_test_tc6();
    if (result != 0) {
        return result;
    }

    result = crypto_speck_test_tc7();
    if (result != 0) {
        return result;
    }

    result = crypto_speck_test_tc8();
    if (result != 0) {
        return result;
    }

    return 0;
}
