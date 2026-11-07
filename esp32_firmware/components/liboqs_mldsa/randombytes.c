#include <stdint.h>
#include <stddef.h>
#include "esp_random.h"

void randombytes(uint8_t *out, size_t outlen)
{
    esp_fill_random(out, outlen);
}

void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read)
{
    esp_fill_random(random_array, bytes_to_read);
}
