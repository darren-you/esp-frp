// SPDX-License-Identifier: Apache-2.0
#include "sample_resources.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#if !(CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32) || !CONFIG_FREERTOS_USE_TRACE_FACILITY || !CONFIG_ESP_TIMER_PROFILING
#error "FRP lab sample requires esp32c3/esp32, task trace and esp_timer profiling"
#endif
#if CONFIG_IDF_TARGET_ESP32 && !CONFIG_FREERTOS_UNICORE
#error "ESP32 sample task-name snapshots require the single-core lab configuration"
#endif
static TaskStatus_t tasks[32];
static atomic_uint allocation_failures, last_failed_bytes, last_failed_caps;
static void allocation_failed(size_t bytes, uint32_t caps, const char *function)
{
    (void)function;
    atomic_store(&last_failed_bytes, (unsigned)bytes);
    atomic_store(&last_failed_caps, caps);
    atomic_fetch_add(&allocation_failures, 1);
}
void sample_resources_init(void)
{
    ESP_ERROR_CHECK(heap_caps_register_failed_alloc_callback(allocation_failed));
}
static struct { char name[configMAX_TASK_NAME_LEN]; unsigned stack_bytes; } facts[32];
void sample_resources(const char *phase, unsigned cycle)
{
    unsigned sockets=0, socket_errors=0;
    for (int fd=LWIP_SOCKET_OFFSET; fd<LWIP_SOCKET_OFFSET+CONFIG_LWIP_MAX_SOCKETS; ++fd) {
        int kind=0; socklen_t n=sizeof kind;
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &n) == 0) ++sockets;
        else if (errno != EBADF) ++socket_errors;
    }
    /* Both sample targets run one scheduler core. Copy borrowed TCB names
     * before task deletion can invalidate them. */
    vTaskSuspendAll();
    UBaseType_t count=uxTaskGetSystemState(tasks, 32, NULL);
    for (UBaseType_t i=0;i<count;++i) {
        strncpy(facts[i].name, tasks[i].pcTaskName, sizeof facts[i].name-1);
        facts[i].name[sizeof facts[i].name-1]=0;
        facts[i].stack_bytes=(unsigned)tasks[i].usStackHighWaterMark * sizeof(StackType_t);
    }
    (void)xTaskResumeAll();
    printf("EFRP_SAMPLE_RESOURCE phase=%s cycle=%u heap=%" PRIu32 " min_heap=%" PRIu32 " largest=%u tasks=%u sockets=%u socket_errors=%u allocation_failures=%u last_failed_bytes=%u last_failed_caps=%u\n",
        phase, cycle, esp_get_free_heap_size(), esp_get_minimum_free_heap_size(),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT), (unsigned)count, sockets, socket_errors,
        atomic_load(&allocation_failures), atomic_load(&last_failed_bytes), atomic_load(&last_failed_caps));
    for (UBaseType_t i=0;i<count;++i)
        printf("EFRP_SAMPLE_TASK phase=%s cycle=%u name=%s stack_bytes=%u\n", phase, cycle, facts[i].name, facts[i].stack_bytes);
    printf("EFRP_SAMPLE_TIMERS_BEGIN phase=%s cycle=%u\n", phase, cycle);
    esp_err_t error=esp_timer_dump(stdout);
    printf("EFRP_SAMPLE_TIMERS_END phase=%s cycle=%u error=%d\n", phase, cycle, error);
    fflush(stdout);
}
