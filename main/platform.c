#include "platform.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

void platform_init(void)
{
}

uint32_t platform_millis(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

void platform_idle(void)
{
    vTaskDelay(1);
}
