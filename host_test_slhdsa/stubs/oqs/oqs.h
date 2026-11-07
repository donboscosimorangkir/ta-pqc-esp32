#pragma once
#include <stddef.h>
#include <stdint.h>
#ifndef OQS_API
#define OQS_API
#endif
static inline void OQS_MEM_cleanse(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}
