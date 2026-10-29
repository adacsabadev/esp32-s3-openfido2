#pragma once
#include <stdint.h>
#include <stdbool.h>

/* CTAP1 APDU response includes SW1/SW2; zero means insufficient output space. */
uint16_t u2f_dispatch(const uint8_t *request, uint16_t length,
                      uint8_t *response, uint16_t capacity, uint32_t channel);
void u2f_poll(void);
bool u2f_waiting(void);
bool u2f_channel_active(uint32_t channel);
/* Channel zero cancels any outstanding U2F touch. */
void u2f_cancel(uint32_t channel);
