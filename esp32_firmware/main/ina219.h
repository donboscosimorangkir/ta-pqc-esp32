#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool     valid;            /* true jika minimal 1 sampel terbaca */
    double   energy_mj;        /* energi selama jendela ukur */
    double   avg_current_ma;
    double   peak_current_ma;
    double   avg_voltage_mv;
    uint32_t samples;
    double   duration_ms;
} ina_result_t;

bool   ina219_init(void);                 /* false jika sensor tidak terdeteksi */
bool   ina219_available(void);
void   ina_measure_start(void);
void   ina_measure_stop(ina_result_t *out);
double ina_measure_idle_power_mw(uint32_t window_ms);  /* -1 jika tidak valid */
