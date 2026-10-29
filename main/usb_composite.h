#pragma once

#include <stdbool.h>
#include <stdint.h>

void usb_composite_init(void);
void usb_composite_poll(void);
void usb_composite_tx_poll(void);
void usb_fido_hid_write(const uint8_t *report, uint32_t length);
void usb_fido_hid_rx(const uint8_t *report, uint32_t length);
void usb_cdc_write(const uint8_t *data, uint32_t length);
void usb_cdc_rx(const uint8_t *data, uint32_t length);
bool usb_cdc_read(uint8_t *byte);
uint32_t usb_cdc_pending(void);
uint32_t usb_cdc_rx_dropped(void);
uint32_t usb_cdc_tx_dropped(void);
