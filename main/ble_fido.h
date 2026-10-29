#pragma once

#include <stdbool.h>

void ble_fido_init(void);
void ble_fido_poll(void);
void ble_fido_processing_tick(void);
bool ble_fido_pairing_start(void);
void ble_fido_log_status(void);
