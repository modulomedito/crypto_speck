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

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================
static crypto_speck_Ret crypto_speck_speck64_expand_key(
    Slice_u32 round_keys,
    Slice_cu32 speck64_key
);

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
/// @brief Initialize SPECK-64/128 context with a 128-bit key
/// @param self Pointer to the Speck64 context to initialize
/// @param speck64_key 128-bit key slice (must contain at least 4 u32 elements)
/// @return crypto_speck_Ret_Ok on success, crypto_speck_Ret_InvalidArg if arguments are invalid
crypto_speck_Ret crypto_speck_Speck64_init(crypto_speck_Speck64 *self, Slice_cu32 speck64_key) {
    if ((self == NULL) || //
        (speck64_key.ptr == NULL) || //
        (speck64_key.len < CRYPTO_SPECK_SPECK64_KEY_U32_NUM)) {
        return crypto_speck_Ret_InvalidArg;
    }

    crypto_speck_Ret ret = crypto_speck_speck64_expand_key(
        (Slice_u32){.ptr = self->round_key_buf, .len = CRYPTO_SPECK_SPECK64_ROUNDS},
        speck64_key
    );

    return ret;
}

/// @brief De-initialize SPECK-64/128 context
crypto_speck_Ret crypto_speck_Speck64_deinit(crypto_speck_Speck64 *self) {
    if (self == NULL) {
        return crypto_speck_Ret_InvalidArg;
    }

    for (u32 i = 0U; i < CRYPTO_SPECK_SPECK64_ROUNDS; i++) {
        self->round_key_buf[i] = 0U;
    }

    return crypto_speck_Ret_Ok;
}

/// @brief SPECK-64/128 single block encryption
/// @param block_data Input/output: 64-bit plaintext
///        ([0] = high 32 bits, [1] = low 32 bits); overwritten with ciphertext
/// @param round_keys Input: 27 pre-generated round keys
crypto_speck_Ret crypto_speck_Speck64_encrypt(
    crypto_speck_Speck64 *self,
    Slice_u32 cipher,
    Slice_cu32 plain
) {
    if ((self == NULL) || //
        (cipher.ptr == NULL) || //
        (cipher.len < CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM) || //
        (plain.ptr == NULL) || //
        (plain.len < CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM)) {
        return crypto_speck_Ret_InvalidArg;
    }

    u32 x = plain.ptr[1];
    u32 y = plain.ptr[0];

    for (u32 i = 0U; i < CRYPTO_SPECK_SPECK64_ROUNDS; i++) {
        x = (CRYPTO_SPECK_ROTR32(x, 8U) + y) ^ (self->round_key_buf[i]);
        y = CRYPTO_SPECK_ROTL32(y, 3U) ^ x;
    }

    cipher.ptr[0] = y;
    cipher.ptr[1] = x;

    return crypto_speck_Ret_Ok;
}

/// @brief SPECK-64/128 single block decryption
/// @param block_data Input/output: 64-bit ciphertext; overwritten with plaintext after decryption
/// @param round_keys Input: 27 pre-generated round keys
crypto_speck_Ret crypto_speck_Speck64_decrypt(
    crypto_speck_Speck64 *self,
    Slice_u32 plain,
    Slice_cu32 cipher
) {
    if ((self == NULL) || //
        (cipher.ptr == NULL) || //
        (cipher.len < CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM) || //
        (plain.ptr == NULL) || //
        (plain.len < CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM)) {
        return crypto_speck_Ret_InvalidArg;
    }

    u32 x = cipher.ptr[1];
    u32 y = cipher.ptr[0];

    /* Decrypt in reverse round order */
    for (i32 i = (i32)(CRYPTO_SPECK_SPECK64_ROUNDS - 1U); i >= 0; i--) {
        y = CRYPTO_SPECK_ROTR32(y ^ x, 3U);
        x = CRYPTO_SPECK_ROTL32((x ^ self->round_key_buf[i]) - y, 8U);
    }

    plain.ptr[0] = y;
    plain.ptr[1] = x;

    return crypto_speck_Ret_Ok;
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
/// @brief SPECK-64/128 key expansion
/// @param const_keys Input: 128-bit original key (array of 4 32-bit elements)
/// @param round_keys Output: 27 32-bit round keys
static crypto_speck_Ret crypto_speck_speck64_expand_key(
    Slice_u32 round_keys,
    Slice_cu32 speck64_key
) {
    if ((round_keys.ptr == NULL) || //
        (round_keys.len < CRYPTO_SPECK_SPECK64_ROUNDS) || //
        (speck64_key.ptr == NULL) || //
        (speck64_key.len < CRYPTO_SPECK_SPECK64_KEY_U32_NUM)) {
        return crypto_speck_Ret_InvalidArg;
    }

    u32 a = speck64_key.ptr[0];
    u32 b = speck64_key.ptr[1];
    u32 c = speck64_key.ptr[2];
    u32 d = speck64_key.ptr[3];

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
    u32 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U32_NUM] = {
        0x03020100,
        0x0b0a0908,
        0x13121110,
        0x1b1a1918,
    };
    u32 plain_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0x7475432d,
        0x3b726574,
    };
    u32 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0x454e028b,
        0x8c6fa548,
    };
    u32 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {0};

    crypto_speck_Ret ret;
    crypto_speck_Speck64 speck64_obj;

    ret = crypto_speck_Speck64_init(
        &speck64_obj,
        (Slice_cu32){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_encrypt(
        &speck64_obj,
        (Slice_u32){.ptr = actual_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM},
        (Slice_cu32){.ptr = plain_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_deinit(&speck64_obj);
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < 2; i++) {
        printf("[%d] = 0x%x\n", i, actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp((u8 *)expected_buf, (u8 *)actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

// Official test vectors
static i32 crypto_speck_test_tc2(void) {
    u32 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U32_NUM] = {
        0x03020100,
        0x0b0a0908,
        0x13121110,
        0x1b1a1918,
    };
    u32 cipher_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0x454e028b,
        0x8c6fa548,
    };
    u32 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0x7475432d,
        0x3b726574,
    };
    u32 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {0};

    crypto_speck_Ret ret;
    crypto_speck_Speck64 speck64_obj;

    ret = crypto_speck_Speck64_init(
        &speck64_obj,
        (Slice_cu32){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_decrypt(
        &speck64_obj,
        (Slice_u32){.ptr = actual_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM},
        (Slice_cu32){.ptr = cipher_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_deinit(&speck64_obj);
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < 2; i++) {
        printf("[%d] = 0x%x\n", i, actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp((u8 *)expected_buf, (u8 *)actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc3(void) {
    u32 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U32_NUM] = {
        0xa66fb764,
        0xab80e91c,
        0x8d09712f,
        0x5f6ed675,
    };
    u32 plain_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0xbba88915,
        0x857a4cff,
    };
    u32 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0x23121d2f,
        0xda6b9470,
    };
    u32 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {0};

    crypto_speck_Ret ret;
    crypto_speck_Speck64 speck64_obj;

    ret = crypto_speck_Speck64_init(
        &speck64_obj,
        (Slice_cu32){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_encrypt(
        &speck64_obj,
        (Slice_u32){.ptr = actual_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM},
        (Slice_cu32){.ptr = plain_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_deinit(&speck64_obj);
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < 2; i++) {
        printf("[%d] = 0x%x\n", i, actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp((u8 *)expected_buf, (u8 *)actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc4(void) {
    u32 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U32_NUM] = {
        0xa66fb764,
        0xab80e91c,
        0x8d09712f,
        0x5f6ed675,
    };
    u32 cipher_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0x23121d2f,
        0xda6b9470,
    };
    u32 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0xbba88915,
        0x857a4cff,
    };
    u32 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {0};

    crypto_speck_Ret ret;
    crypto_speck_Speck64 speck64_obj;

    ret = crypto_speck_Speck64_init(
        &speck64_obj,
        (Slice_cu32){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_decrypt(
        &speck64_obj,
        (Slice_u32){.ptr = actual_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM},
        (Slice_cu32){.ptr = cipher_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_deinit(&speck64_obj);
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < 2; i++) {
        printf("[%d] = 0x%x\n", i, actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp((u8 *)expected_buf, (u8 *)actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc5(void) {
    u32 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U32_NUM] = {
        0x11111111,
        0x22222222,
        0x33333333,
        0x44444444,
    };
    u32 plain_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0x99aabbcc,
        0xddeeff00,
    };
    u32 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0xc750ed22,
        0x79aba67d,
    };
    u32 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {0};

    crypto_speck_Ret ret;
    crypto_speck_Speck64 speck64_obj;

    ret = crypto_speck_Speck64_init(
        &speck64_obj,
        (Slice_cu32){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_encrypt(
        &speck64_obj,
        (Slice_u32){.ptr = actual_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM},
        (Slice_cu32){.ptr = plain_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_deinit(&speck64_obj);
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < 2; i++) {
        printf("[%d] = 0x%x\n", i, actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp((u8 *)expected_buf, (u8 *)actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_speck_test_tc6(void) {
    u32 speck64_key_buf[CRYPTO_SPECK_SPECK64_KEY_U32_NUM] = {
        0x11111111,
        0x22222222,
        0x33333333,
        0x44444444,
    };
    u32 cipher_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0xc750ed22,
        0x79aba67d,
    };
    u32 expected_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {
        0x99aabbcc,
        0xddeeff00,
    };
    u32 actual_buf[CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM] = {0};

    crypto_speck_Ret ret;
    crypto_speck_Speck64 speck64_obj;

    ret = crypto_speck_Speck64_init(
        &speck64_obj,
        (Slice_cu32){.ptr = speck64_key_buf, .len = CRYPTO_SPECK_SPECK64_KEY_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_decrypt(
        &speck64_obj,
        (Slice_u32){.ptr = actual_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM},
        (Slice_cu32){.ptr = cipher_buf, .len = CRYPTO_SPECK_SPECK64_BLOCK_U32_NUM}
    );
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

    ret = crypto_speck_Speck64_deinit(&speck64_obj);
    if (ret != crypto_speck_Ret_Ok) {
        return __LINE__;
    }

#if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)
    for (u32 i = 0; i < 2; i++) {
        printf("[%d] = 0x%x\n", i, actual_buf[i]);
    }
    printf("\n");
#endif // #if defined(CRYPTO_SPECK_DEBUG) && (CRYPTO_SPECK_DEBUG > 0)

    i32 cmp = crypto_speck_memcmp((u8 *)expected_buf, (u8 *)actual_buf, sizeof(expected_buf));
    if (cmp != 0) {
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

    return 0;
}
