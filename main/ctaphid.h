#pragma once
#include <stdint.h>

#define CTAPHID_REPORT_SIZE 64u
#define CTAPHID_BROADCAST_CID 0xffffffffu

void ctaphid_init(void);
void ctaphid_poll(void);
void ctaphid_processing_tick(void);
void ctaphid_receive(const uint8_t report[CTAPHID_REPORT_SIZE]);
