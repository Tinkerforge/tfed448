#ifndef TF_ED448_PORTABLE_ENDIAN_H
#define TF_ED448_PORTABLE_ENDIAN_H

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <stdint.h>

/* Prevent libdecaf's desktop-only portability header from rejecting newlib. */
#ifndef __PORTABLE_ENDIAN_H__
#define __PORTABLE_ENDIAN_H__

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    !defined(__ORDER_BIG_ENDIAN__)
#error "Compiler does not define target byte order"
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htole64(value) ((uint64_t)(value))
#define le64toh(value) ((uint64_t)(value))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htole64(value) __builtin_bswap64((uint64_t)(value))
#define le64toh(value) __builtin_bswap64((uint64_t)(value))
#else
#error "Unsupported target byte order"
#endif

#endif
#endif
