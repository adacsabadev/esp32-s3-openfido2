#pragma once

#include <stdbool.h>

void indicators_init(void);
void indicators_poll(void);
void indicators_activity(void);
void indicators_wink(void);
void indicators_result(bool success);
void presence_begin(void);
bool presence_take(void);
void presence_cancel(void);
