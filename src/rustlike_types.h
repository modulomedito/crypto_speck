//==================================================================================================
/// @file       rustlike_types.h
/// @author     modulomedito (chcchc1995@outlook.com)
/// @brief      Define rust-like types for C language
/// @copyright  Copyright (C) 2026. MIT License.
/// @details    This is a header for defining types like rust. C99 compatible.
///
/// See https://github.com/modulomedito/rustlike_types
//==================================================================================================
//==================================================================================================
// GUARD START
//==================================================================================================
#ifndef RUSTLIKE_TYPES_H
#define RUSTLIKE_TYPES_H
#ifdef __cplusplus
extern "C" {
#endif

//==================================================================================================
// INCLUDE
//==================================================================================================
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

//==================================================================================================
// PUBLIC TYPEDEF
//==================================================================================================
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef float f32;
typedef double f64;
typedef uintptr_t uptr;
typedef intptr_t iptr;
typedef ptrdiff_t isize;
typedef size_t usize;
typedef char ichar;
typedef unsigned char uchar;

//==================================================================================================
// PUBLIC DEFINE
//==================================================================================================
#define RUSTLIKE_TYPES_MAJOR_VERSION (0)
#define RUSTLIKE_TYPES_MINOR_VERSION (3)
#define RUSTLIKE_TYPES_PATCH_VERSION (2)

#ifndef bool
#define bool bool_t
#endif

#ifndef true
#define true (1)
#endif

#ifndef false
#define false (0)
#endif

#ifndef C99_STATIC_ASSERT
#define C99_STATIC_ASSERT(name, condition)                                                         \
    typedef char name##_failed_at_line_##__LINE__[(condition) ? 1 : -1]
#endif

#ifndef RUSTLIKE_TYPES_DEFINE_SLICE
#define RUSTLIKE_TYPES_DEFINE_SLICE(T)                                                             \
    typedef struct {                                                                               \
        volatile T *ptr;                                                                           \
        u32 len;                                                                                   \
    } Slice_##T
#endif

#ifndef RUSTLIKE_TYPES_DEFINE_CONST_SLICE
#define RUSTLIKE_TYPES_DEFINE_CONST_SLICE(T)                                                       \
    typedef struct {                                                                               \
        const volatile T *ptr;                                                                     \
        u32 len;                                                                                   \
    } Slice_c##T
#endif

//==================================================================================================
// PUBLIC ENUM
//==================================================================================================

//==================================================================================================
// PUBLIC STRUCT
//==================================================================================================
RUSTLIKE_TYPES_DEFINE_SLICE(u8);
RUSTLIKE_TYPES_DEFINE_SLICE(u16);
RUSTLIKE_TYPES_DEFINE_SLICE(u32);
RUSTLIKE_TYPES_DEFINE_SLICE(u64);
RUSTLIKE_TYPES_DEFINE_SLICE(i8);
RUSTLIKE_TYPES_DEFINE_SLICE(i16);
RUSTLIKE_TYPES_DEFINE_SLICE(i32);
RUSTLIKE_TYPES_DEFINE_SLICE(i64);
RUSTLIKE_TYPES_DEFINE_SLICE(f32);
RUSTLIKE_TYPES_DEFINE_SLICE(f64);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(u8);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(u16);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(u32);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(u64);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(i8);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(i16);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(i32);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(i64);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(f32);
RUSTLIKE_TYPES_DEFINE_CONST_SLICE(f64);

//==================================================================================================
// PUBLIC UNION
//==================================================================================================

//==================================================================================================
// PUBLIC VARIABLE DECLARATION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DECLARATION
//==================================================================================================

//==================================================================================================
// GUARD END
//==================================================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef RUSTLIKE_TYPES_H
