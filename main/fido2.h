#pragma once
#include <stdint.h>
void fido2_init(void);
void fido2_poll(void);
void fido2_hid_rx(const uint8_t *report, uint32_t length);
