#include <string.h>
#include "ina219.h"
#include "driver/i2c_master.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define INA_SDA          21
#define INA_SCL          22
#define INA_ADDR         0x40
#define INA_FREQ_HZ      100000
#define INA_SHUNT_OHM    0.1          /* R100 pada modul */
#define SAMPLE_PERIOD_US 1000
#define REG_CONFIG       0x00
#define REG_SHUNT        0x01
#define REG_BUS          0x02
/* BRNG=16V, PGA=/4 (+-160mV => maks 1,6 A), 12-bit, shunt+bus kontinu */
#define CFG_VALUE        0x119F

static const char *TAG = "INA219";
static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev;
static esp_timer_handle_t s_timer;
static bool s_ok = false;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

static bool     s_active;
static int64_t  s_t_start, s_t_prev;
static double   s_energy_mj, s_sum_i, s_sum_v, s_peak_i;
static uint32_t s_samples;

static esp_err_t rd16(uint8_t reg, uint16_t *val)
{
    uint8_t b[2];
    esp_err_t e = i2c_master_transmit_receive(s_dev, &reg, 1, b, 2, 100);
    if (e == ESP_OK) *val = ((uint16_t)b[0] << 8) | b[1];
    return e;
}

static void sample_cb(void *arg)
{
    uint16_t sh, bus;
    if (rd16(REG_SHUNT, &sh) != ESP_OK || rd16(REG_BUS, &bus) != ESP_OK) return;
    int64_t now = esp_timer_get_time();
    double i_ma = (int16_t)sh * 0.01 / INA_SHUNT_OHM;   /* LSB shunt = 10 uV */
    double v_mv = (bus >> 3) * 4.0;                     /* LSB bus = 4 mV */

    portENTER_CRITICAL(&s_mux);
    if (s_active) {
        double dt_s = (now - s_t_prev) / 1e6;
        s_energy_mj += (v_mv * i_ma) * dt_s / 1000.0;   /* uW * s = uJ -> mJ */
        s_sum_i += i_ma;
        s_sum_v += v_mv;
        if (i_ma > s_peak_i) s_peak_i = i_ma;
        s_samples++;
        s_t_prev = now;
    }
    portEXIT_CRITICAL(&s_mux);
}

bool ina219_init(void)
{
    i2c_master_bus_config_t bc = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .i2c_port = I2C_NUM_0,
        .scl_io_num = INA_SCL,
        .sda_io_num = INA_SDA,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    if (i2c_new_master_bus(&bc, &s_bus) != ESP_OK) { ESP_LOGW(TAG, "Bus I2C gagal"); return false; }
    if (i2c_master_probe(s_bus, INA_ADDR, 50) != ESP_OK) {
        ESP_LOGW(TAG, "INA219 tidak terdeteksi di 0x%02X, energi dinonaktifkan", INA_ADDR);
        return false;
    }
    i2c_device_config_t dc = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = INA_ADDR,
        .scl_speed_hz = INA_FREQ_HZ,
    };
    if (i2c_master_bus_add_device(s_bus, &dc, &s_dev) != ESP_OK) return false;

    uint8_t w[3] = { REG_CONFIG, CFG_VALUE >> 8, CFG_VALUE & 0xFF };
    if (i2c_master_transmit(s_dev, w, 3, 100) != ESP_OK) return false;
    uint16_t back = 0;
    if (rd16(REG_CONFIG, &back) != ESP_OK || back != CFG_VALUE) {
        ESP_LOGW(TAG, "Konfigurasi tidak cocok (0x%04X)", back);
        return false;
    }
    esp_timer_create_args_t ta = { .callback = sample_cb, .name = "ina_sample" };
    if (esp_timer_create(&ta, &s_timer) != ESP_OK) return false;

    s_ok = true;
    ESP_LOGI(TAG, "INA219 siap (0x%02X, shunt %.2f ohm)", INA_ADDR, INA_SHUNT_OHM);
    return true;
}

bool ina219_available(void) { return s_ok; }

void ina_measure_start(void)
{
    if (!s_ok) return;
    portENTER_CRITICAL(&s_mux);
    s_energy_mj = s_sum_i = s_sum_v = s_peak_i = 0;
    s_samples = 0;
    s_t_start = s_t_prev = esp_timer_get_time();
    s_active = true;
    portEXIT_CRITICAL(&s_mux);
    esp_timer_start_periodic(s_timer, SAMPLE_PERIOD_US);
}

void ina_measure_stop(ina_result_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!s_ok) return;
    esp_timer_stop(s_timer);
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_mux);
    s_active = false;
    out->energy_mj = s_energy_mj;
    out->samples = s_samples;
    out->peak_current_ma = s_peak_i;
    if (s_samples > 0) {
        out->avg_current_ma = s_sum_i / s_samples;
        out->avg_voltage_mv = s_sum_v / s_samples;
    }
    out->duration_ms = (now - s_t_start) / 1000.0;
    portEXIT_CRITICAL(&s_mux);
    out->valid = (out->samples > 0);
}

double ina_measure_idle_power_mw(uint32_t window_ms)
{
    ina_result_t r;
    ina_measure_start();
    vTaskDelay(pdMS_TO_TICKS(window_ms));
    ina_measure_stop(&r);
    if (!r.valid || r.duration_ms <= 0) return -1.0;
    return r.energy_mj / (r.duration_ms / 1000.0);   /* mJ/s = mW */
}
