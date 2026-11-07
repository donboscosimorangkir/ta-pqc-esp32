#include <stdio.h>
#include <stdlib.h>
#include "esp_random.h"

void esp_fill_random(void *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, len, f) != len) { perror("urandom"); exit(1); }
    fclose(f);
}
