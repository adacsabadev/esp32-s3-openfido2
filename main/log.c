#include "log.h"
#include "usb_composite.h"
#include "nvs.h"
#include <stdarg.h>
#include <stdio.h>

static bool debug_enabled;

void log_init(void) {}

bool log_settings_init(void)
{
    nvs_handle_t handle;
    uint8_t value = 0;
    esp_err_t status = nvs_open("openfido_cfg", NVS_READONLY, &handle);
    if (status == ESP_ERR_NVS_NOT_FOUND) {
        debug_enabled = false;
        return true;
    }
    if (status != ESP_OK) return false;
    status = nvs_get_u8(handle, "debug", &value);
    nvs_close(handle);
    if (status != ESP_OK && status != ESP_ERR_NVS_NOT_FOUND) return false;
    debug_enabled = status == ESP_OK && value != 0;
    return true;
}

bool log_debug_set(bool enabled)
{
    nvs_handle_t handle;
    esp_err_t status = nvs_open("openfido_cfg", NVS_READWRITE, &handle);
    if (status != ESP_OK) return false;
    status = nvs_set_u8(handle, "debug", enabled ? 1u : 0u);
    if (status == ESP_OK) status = nvs_commit(handle);
    nvs_close(handle);
    if (status != ESP_OK) return false;
    debug_enabled = enabled;
    return true;
}

bool log_debug_enabled(void) { return debug_enabled; }
void log_puts(const char *text) { while (*text) usb_cdc_write((const uint8_t *)text++, 1); }
void log_hex(const uint8_t *data, uint32_t length) { usb_cdc_write(data, length); }

void log_debug_printf(const char *format, ...)
{
    if (!debug_enabled) return;
    char line[256];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof line, format, arguments);
    va_end(arguments);
    if (length < 0) return;
    line[sizeof line - 1] = 0;
    log_puts("# DEBUG ");
    log_puts(line);
    log_puts("\r\n");
}
