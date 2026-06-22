//==================================================================================================
/// @file       crypto_speck.h
/// @author     modulomedito (chcchc1995@outlook.com)
/// @brief
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// GUARD START
//==================================================================================================
#ifndef CRYPTO_SPECK_H
#define CRYPTO_SPECK_H
#ifdef __cplusplus
extern "C" {
#endif

//==================================================================================================
// INCLUDE
//==================================================================================================
#include "rustlike_types.h"

//==================================================================================================
// PUBLIC TYPEDEF
//==================================================================================================

//==================================================================================================
// PUBLIC DEFINE
//==================================================================================================
#define CRYPTO_SPECK_VERSION_MAJOR (0U)
#define CRYPTO_SPECK_VERSION_MINOR (1U)
#define CRYPTO_SPECK_VERSION_PATCH (0U)

#define CRYPTO_SPECK_SPECK64_KEY_U8_NUM (16U)
#define CRYPTO_SPECK_SPECK64_ROUNDS (27U)
#define CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM (8U)
#define CRYPTO_SPECK_SPECK64_CIPHER_SIZE_FROM_PLAIN_SIZE(plain_size)                               \
    (((((u32)(plain_size)) / CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM) + 1U) *                            \
     CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM)

//==================================================================================================
// PUBLIC ENUM
//==================================================================================================
typedef enum {
    crypto_speck_Ret_Ok = 0,
    crypto_speck_Ret_InvalidArg,
    crypto_speck_Ret_BufferTooSmall,
    crypto_speck_Ret_Error,
} crypto_speck_Ret;

typedef enum {
    crypto_speck_Mode_Encrypt = 0,
    crypto_speck_Mode_Decrypt,
    crypto_speck_Mode_Invalid,
} crypto_speck_Mode;

//==================================================================================================
// PUBLIC STRUCT
//==================================================================================================
typedef struct {
    crypto_speck_Mode mode;
    u32 round_key_buf[CRYPTO_SPECK_SPECK64_ROUNDS];
    Slice_u8 data;
    u32 output_len;
    u8 residue_buf[CRYPTO_SPECK_SPECK64_BLOCK_U8_NUM * 2U];
    u32 residue_len;
} crypto_speck_Speck64;

//==================================================================================================
// PUBLIC UNION
//==================================================================================================

//==================================================================================================
// PUBLIC VARIABLE DECLARATION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DECLARATION
//==================================================================================================
extern crypto_speck_Ret crypto_speck_speck64_encrypt(
    Slice_u8 output,
    Slice_cu8 input,
    Slice_cu8 speck64_key
);
extern crypto_speck_Ret crypto_speck_speck64_decrypt(
    Slice_u8 output,
    Slice_cu8 input,
    Slice_cu8 speck64_key
);

extern crypto_speck_Ret crypto_speck_Speck64_init(
    crypto_speck_Speck64 *self,
    crypto_speck_Mode mode,
    Slice_u8 output,
    Slice_cu8 speck64_key
);
extern crypto_speck_Ret crypto_speck_Speck64_update(crypto_speck_Speck64 *self, Slice_cu8 data);
extern crypto_speck_Ret crypto_speck_Speck64_finalize(crypto_speck_Speck64 *self);

//==================================================================================================
// GUARD END
//==================================================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_SPECK_H
