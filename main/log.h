#pragma once
#include <stdbool.h>
#include <stdint.h>
void log_init(void);
bool log_settings_init(void);
bool log_debug_set(bool enabled);
bool log_debug_enabled(void);
void log_puts(const char *text);
void log_hex(const uint8_t *data, uint32_t length);
void log_debug_printf(const char *format, ...);
