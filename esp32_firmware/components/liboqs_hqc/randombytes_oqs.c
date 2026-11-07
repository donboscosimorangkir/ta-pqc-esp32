#include <stddef.h>
#include <stdint.h>
#include "esp_random.h"

void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read)
{
    esp_fill_random(random_array, bytes_to_read);
}
